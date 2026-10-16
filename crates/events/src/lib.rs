#![forbid(unsafe_code)]

//! MCP Events: `events/list`, `events/subscribe`, `events/unsubscribe`, and
//! webhook delivery signed with Standard Webhooks.
//!
//! Follows the draft MCP Events design as implemented by ChatGPT
//! (<https://developers.openai.com/plugins/build/mcp-events>): webhook
//! delivery only, callback verification with a signed challenge, HTTPS
//! callbacks to public addresses (resolved, then pinned for the
//! connection), no redirects, bounded retries, and no replay (`cursor: null`).
//!
//! The only event today is `vpn.state_changed`.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use headless_mcp_wire::JsonRpcError;
use ring::rand::{SecureRandom, SystemRandom};
use ring::{digest, hmac};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const VPN_STATE_EVENT: &str = "vpn.state_changed";
/// `CallbackEndpointError`: the callback URL failed validation or verification.
pub const CALLBACK_ENDPOINT_ERROR: i64 = -32015;

const VPN_STATES: [&str; 3] = ["needs_login", "down", "connected"];
const MIN_TTL_SECS: u64 = 60;
/// Skip re-verifying a callback that passed within this window.
const VERIFICATION_CACHE_SECS: u64 = 24 * 3600;
/// After a secret rotation, also sign with the old secret for this long.
const ROTATION_WINDOW_SECS: u64 = 600;
const DELIVERY_ATTEMPTS: u32 = 3;
const MAX_BODY_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone)]
pub struct EventsConfig {
    /// Where subscriptions are persisted (`None` = memory only).
    pub store_path: Option<PathBuf>,
    pub default_ttl_secs: u64,
    pub max_ttl_secs: u64,
    /// Allow `http://` and private/loopback callbacks. Testing only.
    pub allow_insecure_callbacks: bool,
    /// Put the pending login link in event payloads. Off by default: the
    /// payload ends up in the subscriber's model context.
    pub include_login_url: bool,
}

impl Default for EventsConfig {
    fn default() -> Self {
        Self {
            store_path: None,
            default_ttl_secs: 24 * 3600,
            max_ttl_secs: 7 * 24 * 3600,
            allow_insecure_callbacks: false,
            include_login_url: false,
        }
    }
}

/// A VPN state change to publish.
#[derive(Debug, Clone)]
pub struct VpnStateEvent {
    pub vpn: String,
    pub from: String,
    pub to: String,
    pub login_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Subscription {
    id: String,
    name: String,
    arguments: Value,
    url: String,
    /// Base64 signing key (the part after `whsec_`).
    secret: String,
    #[serde(default)]
    previous_secret: Option<String>,
    #[serde(default)]
    rotated_at_unix: Option<u64>,
    expires_at_unix: u64,
    verified_at_unix: u64,
}

#[derive(Default, Serialize, Deserialize)]
struct Store {
    subscriptions: Vec<Subscription>,
}

pub struct EventHub {
    config: EventsConfig,
    vpn_names: Vec<String>,
    subs: Mutex<HashMap<String, Subscription>>,
}

impl EventHub {
    pub fn new(config: EventsConfig, mut vpn_names: Vec<String>) -> Arc<Self> {
        vpn_names.sort();
        let subs = config
            .store_path
            .as_ref()
            .and_then(|p| std::fs::read(p).ok())
            .and_then(|bytes| serde_json::from_slice::<Store>(&bytes).ok())
            .map(|store| {
                store
                    .subscriptions
                    .into_iter()
                    .filter(|s| s.expires_at_unix > now())
                    .map(|s| (s.id.clone(), s))
                    .collect()
            })
            .unwrap_or_default();
        Arc::new(Self { config, vpn_names, subs: Mutex::new(subs) })
    }

    pub fn subscription_count(&self) -> usize {
        self.subs.lock().unwrap().len()
    }

    /// `events/list` result.
    pub fn list(&self) -> Value {
        serde_json::json!({
            "events": [{
                "name": VPN_STATE_EVENT,
                "description": "A VPN that some tools depend on changed state: it needs an SSO \
                    login (needs_login), is down for another reason (down), or is connected again \
                    (connected). Tools behind a VPN fail until it is connected.",
                "delivery": ["webhook"],
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "vpn": {
                            "type": "string",
                            "enum": self.vpn_names,
                            "description": "Only this VPN. Omit for all.",
                        },
                        "states": {
                            "type": "array",
                            "items": { "type": "string", "enum": VPN_STATES },
                            "description": "Only these new states. Omit for all.",
                        },
                    },
                    "additionalProperties": false,
                },
                "payloadSchema": {
                    "type": "object",
                    "properties": {
                        "vpn": { "type": "string" },
                        "from": { "type": "string" },
                        "to": { "type": "string", "enum": VPN_STATES },
                        "login_url": { "type": "string" },
                    },
                    "required": ["vpn", "from", "to"],
                    "additionalProperties": false,
                },
            }],
        })
    }

    /// `events/subscribe`: validate, verify the callback, store.
    pub async fn subscribe(&self, params: Option<&Value>) -> Result<Value, JsonRpcError> {
        let req = SubscribeParams::parse(params, &self.vpn_names)?;
        let key = decode_secret(&req.secret)?;
        let target = resolve_callback(&req.url, self.config.allow_insecure_callbacks).await?;
        let id = subscription_id(&req.url, &req.name, &req.arguments);

        let ttl = match req.ttl_ms {
            Some(ms) => (ms / 1000).clamp(MIN_TTL_SECS, self.config.max_ttl_secs),
            None => self.config.default_ttl_secs,
        };
        let now = now();

        let previously_verified = self
            .subs
            .lock()
            .unwrap()
            .get(&id)
            .is_some_and(|s| now.saturating_sub(s.verified_at_unix) < VERIFICATION_CACHE_SECS);
        if !previously_verified {
            verify_callback(&target, &req.url, &key, &id).await?;
        }

        let secret_b64 = STANDARD.encode(&key);
        {
            let mut subs = self.subs.lock().unwrap();
            let existing = subs.remove(&id);
            let (previous_secret, rotated_at_unix) = match &existing {
                Some(old) if old.secret != secret_b64 => (Some(old.secret.clone()), Some(now)),
                Some(old) => (old.previous_secret.clone(), old.rotated_at_unix),
                None => (None, None),
            };
            subs.insert(
                id.clone(),
                Subscription {
                    id: id.clone(),
                    name: req.name,
                    arguments: req.arguments,
                    url: req.url,
                    secret: secret_b64,
                    previous_secret,
                    rotated_at_unix,
                    expires_at_unix: now + ttl,
                    verified_at_unix: if previously_verified {
                        existing.map(|s| s.verified_at_unix).unwrap_or(now)
                    } else {
                        now
                    },
                },
            );
        }
        self.persist();
        tracing::info!(%id, ttl, "event subscription active");

        Ok(serde_json::json!({
            "id": id,
            "refreshBefore": iso8601(now + ttl),
            "cursor": Value::Null,
            "truncated": false,
        }))
    }

    /// `events/unsubscribe`: idempotent.
    pub fn unsubscribe(&self, params: Option<&Value>) -> Result<Value, JsonRpcError> {
        let p = params.ok_or_else(|| JsonRpcError::invalid_params("missing params"))?;
        let name = p.get("name").and_then(Value::as_str).unwrap_or(VPN_STATE_EVENT);
        let arguments = normalize_arguments(p.get("arguments"), &self.vpn_names)?;
        let url = p
            .get("delivery")
            .and_then(|d| d.get("url"))
            .and_then(Value::as_str)
            .ok_or_else(|| JsonRpcError::invalid_params("delivery.url is required"))?;
        let id = subscription_id(url, name, &arguments);
        if self.subs.lock().unwrap().remove(&id).is_some() {
            self.persist();
            tracing::info!(%id, "event subscription removed");
        }
        Ok(serde_json::json!({}))
    }

    /// Deliver an event to every matching, unexpired subscription.
    pub fn publish(self: &Arc<Self>, event: VpnStateEvent) {
        let now = now();
        let targets: Vec<Subscription> = {
            let mut subs = self.subs.lock().unwrap();
            subs.retain(|_, s| s.expires_at_unix > now);
            subs.values().filter(|s| matches(s, &event)).cloned().collect()
        };
        if targets.is_empty() {
            return;
        }

        let mut data = serde_json::json!({ "vpn": event.vpn, "from": event.from, "to": event.to });
        if let (true, Some(url)) = (self.config.include_login_url, &event.login_url) {
            data["login_url"] = Value::String(url.clone());
        }

        for sub in targets {
            let hub = Arc::clone(self);
            let body = serde_json::json!({
                "eventId": format!("evt_{}", random_hex(12)),
                "name": VPN_STATE_EVENT,
                "timestamp": iso8601(now),
                "data": data,
                "cursor": Value::Null,
            });
            tokio::spawn(async move { hub.deliver(sub, body).await });
        }
    }

    async fn deliver(&self, sub: Subscription, body: Value) {
        let event_id = body["eventId"].as_str().unwrap_or_default().to_string();
        let bytes = serde_json::to_vec(&body).unwrap_or_default();
        if bytes.len() > MAX_BODY_BYTES {
            tracing::warn!(id = %sub.id, "event payload too large; dropped");
            return;
        }
        for attempt in 1..=DELIVERY_ATTEMPTS {
            let result = async {
                let target = resolve_callback(&sub.url, self.config.allow_insecure_callbacks).await?;
                let signature = sign_all(&sub, &event_id, &bytes);
                send_signed(&target, &sub.url, &sub.id, &event_id, &signature, bytes.clone())
                    .await
                    .map_err(|e| callback_error("http_error", &e))
            }
            .await;
            match result {
                Ok(resp) if resp.status().is_success() => {
                    tracing::info!(id = %sub.id, %event_id, "event delivered");
                    return;
                }
                Ok(resp) if resp.status().as_u16() == 410 => {
                    tracing::info!(id = %sub.id, "subscriber is gone (410); removing subscription");
                    self.subs.lock().unwrap().remove(&sub.id);
                    self.persist();
                    return;
                }
                Ok(resp) if resp.status().as_u16() == 413 => {
                    tracing::warn!(id = %sub.id, "event rejected as too large (413)");
                    return;
                }
                Ok(resp) => {
                    tracing::warn!(id = %sub.id, status = %resp.status(), attempt, "event delivery failed")
                }
                Err(e) => tracing::warn!(id = %sub.id, error = %e.message, attempt, "event delivery failed"),
            }
            if attempt < DELIVERY_ATTEMPTS {
                tokio::time::sleep(Duration::from_secs(1 << (attempt - 1))).await;
            }
        }
    }

    fn persist(&self) {
        let Some(path) = &self.config.store_path else { return };
        let store = Store { subscriptions: self.subs.lock().unwrap().values().cloned().collect() };
        let Ok(bytes) = serde_json::to_vec_pretty(&store) else { return };
        let tmp = path.with_extension("tmp");
        let written = std::fs::write(&tmp, bytes).and_then(|()| {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
            }
            std::fs::rename(&tmp, path)
        });
        if let Err(e) = written {
            tracing::warn!(path = %path.display(), %e, "failed to persist event subscriptions");
        }
    }
}

struct SubscribeParams {
    name: String,
    arguments: Value,
    url: String,
    secret: String,
    /// `None` = server default (also used for `ttlMs: null`; we never grant
    /// subscriptions without expiry).
    ttl_ms: Option<u64>,
}

impl SubscribeParams {
    fn parse(params: Option<&Value>, vpn_names: &[String]) -> Result<Self, JsonRpcError> {
        let p = params.ok_or_else(|| JsonRpcError::invalid_params("missing params"))?;
        let name = p.get("name").and_then(Value::as_str).unwrap_or_default();
        if name != VPN_STATE_EVENT {
            return Err(JsonRpcError::invalid_params(format!("unknown event '{name}'")));
        }
        let arguments = normalize_arguments(p.get("arguments"), vpn_names)?;
        let delivery = p
            .get("delivery")
            .ok_or_else(|| JsonRpcError::invalid_params("delivery is required"))?;
        if delivery.get("mode").and_then(Value::as_str) != Some("webhook") {
            return Err(JsonRpcError::invalid_params("only delivery.mode 'webhook' is supported"));
        }
        let url = delivery
            .get("url")
            .and_then(Value::as_str)
            .ok_or_else(|| JsonRpcError::invalid_params("delivery.url is required"))?
            .to_string();
        let secret = delivery
            .get("secret")
            .and_then(Value::as_str)
            .ok_or_else(|| JsonRpcError::invalid_params("delivery.secret is required"))?
            .to_string();
        Ok(Self { name: name.into(), arguments, url, secret, ttl_ms: p.get("ttlMs").and_then(Value::as_u64) })
    }
}

/// Validate subscription arguments and return them in canonical form.
fn normalize_arguments(arguments: Option<&Value>, vpn_names: &[String]) -> Result<Value, JsonRpcError> {
    let obj = match arguments {
        None | Some(Value::Null) => return Ok(serde_json::json!({})),
        Some(Value::Object(obj)) => obj,
        Some(_) => return Err(JsonRpcError::invalid_params("arguments must be an object")),
    };
    let mut out = serde_json::Map::new();
    for (k, v) in obj {
        match (k.as_str(), v) {
            ("vpn", Value::String(name)) if vpn_names.contains(name) => {
                out.insert(k.clone(), v.clone());
            }
            ("states", Value::Array(states))
                if states.iter().all(|s| s.as_str().is_some_and(|s| VPN_STATES.contains(&s))) =>
            {
                let mut sorted: Vec<&str> = states.iter().filter_map(Value::as_str).collect();
                sorted.sort();
                sorted.dedup();
                out.insert(k.clone(), serde_json::json!(sorted));
            }
            _ => return Err(JsonRpcError::invalid_params(format!("invalid argument '{k}'"))),
        }
    }
    Ok(Value::Object(out))
}

fn matches(sub: &Subscription, event: &VpnStateEvent) -> bool {
    sub.name == VPN_STATE_EVENT
        && sub.arguments.get("vpn").and_then(Value::as_str).is_none_or(|v| v == event.vpn)
        && sub
            .arguments
            .get("states")
            .and_then(Value::as_array)
            .is_none_or(|states| states.iter().any(|s| s.as_str() == Some(event.to.as_str())))
}

/// Deterministic id from callback, event and canonical arguments.
/// (Single principal: the hub has one bearer token.)
fn subscription_id(url: &str, name: &str, arguments: &Value) -> String {
    let canonical = format!("hub\n{url}\n{name}\n{arguments}");
    let hash = digest::digest(&digest::SHA256, canonical.as_bytes());
    format!("sub_{}", hex(&hash.as_ref()[..12]))
}

fn decode_secret(secret: &str) -> Result<Vec<u8>, JsonRpcError> {
    let key = secret
        .strip_prefix("whsec_")
        .and_then(|b64| STANDARD.decode(b64).ok())
        .ok_or_else(|| JsonRpcError::invalid_params("delivery.secret must be whsec_<base64>"))?;
    if !(24..=64).contains(&key.len()) {
        return Err(JsonRpcError::invalid_params("delivery.secret must decode to 24-64 bytes"));
    }
    Ok(key)
}

struct CallbackTarget {
    host: String,
    addr: SocketAddr,
}

fn callback_error(reason: &str, detail: &str) -> JsonRpcError {
    JsonRpcError {
        code: CALLBACK_ENDPOINT_ERROR,
        message: format!("callback endpoint error: {detail}"),
        data: Some(serde_json::json!({ "reason": reason })),
    }
}

/// Parse and resolve a callback URL; every resolved address must be public
/// (unless insecure callbacks are allowed). The connection is later pinned
/// to the returned address.
async fn resolve_callback(url: &str, allow_insecure: bool) -> Result<CallbackTarget, JsonRpcError> {
    let parsed = reqwest::Url::parse(url).map_err(|_| callback_error("invalid_url", "unparseable URL"))?;
    match parsed.scheme() {
        "https" => {}
        "http" if allow_insecure => {}
        _ => return Err(callback_error("invalid_url", "callback must use https")),
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(callback_error("invalid_url", "credentials in callback URL"));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| callback_error("invalid_url", "missing host"))?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    let port = parsed.port_or_known_default().unwrap_or(443);
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(|_| callback_error("dns", "could not resolve callback host"))?
        .collect();
    if addrs.is_empty() {
        return Err(callback_error("dns", "callback host has no addresses"));
    }
    if !allow_insecure && addrs.iter().any(|a| !is_public(a.ip())) {
        return Err(callback_error("blocked_address", "callback resolves to a non-public address"));
    }
    Ok(CallbackTarget { host, addr: addrs[0] })
}

fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
                || o[0] == 0
                || (o[0] == 100 && (64..128).contains(&o[1])) // shared address space
                || o[0] >= 240)
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public(IpAddr::V4(v4));
            }
            let seg = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (seg[0] & 0xfe00) == 0xfc00 // unique local
                || (seg[0] & 0xffc0) == 0xfe80 // link local
                || (seg[0] == 0x2001 && seg[1] == 0x0db8)) // documentation
        }
    }
}

async fn verify_callback(
    target: &CallbackTarget,
    url: &str,
    key: &[u8],
    sub_id: &str,
) -> Result<(), JsonRpcError> {
    let challenge = random_hex(16);
    let msg_id = format!("msg_verification_{}", random_hex(8));
    let body = serde_json::to_vec(&serde_json::json!({ "type": "verification", "challenge": challenge }))
        .unwrap_or_default();
    let timestamp = now();
    let signature = format!("v1,{}", sign(key, &msg_id, timestamp, &body));
    let resp = send_signed_at(target, url, sub_id, &msg_id, timestamp, &signature, body)
        .await
        .map_err(|e| {
            if e.contains("timed out") {
                callback_error("timeout", "verification timed out")
            } else {
                callback_error("http_error", "verification request failed")
            }
        })?;
    if !resp.status().is_success() {
        return Err(callback_error("http_error", &format!("verification returned {}", resp.status())));
    }
    let echoed: Value = resp
        .json()
        .await
        .map_err(|_| callback_error("challenge_failed", "verification response is not JSON"))?;
    let echoed = echoed.get("challenge").and_then(Value::as_str).unwrap_or_default();
    if !constant_time_eq(echoed.as_bytes(), challenge.as_bytes()) {
        return Err(callback_error("challenge_failed", "challenge mismatch"));
    }
    Ok(())
}

/// `v1,<sig>` for the current secret, plus the previous one during rotation.
fn sign_all(sub: &Subscription, msg_id: &str, body: &[u8]) -> (u64, String) {
    let timestamp = now();
    let mut signatures = Vec::new();
    for secret in std::iter::once(&sub.secret).chain(
        sub.previous_secret
            .as_ref()
            .filter(|_| sub.rotated_at_unix.is_some_and(|t| now() - t < ROTATION_WINDOW_SECS)),
    ) {
        if let Ok(key) = STANDARD.decode(secret) {
            signatures.push(format!("v1,{}", sign(&key, msg_id, timestamp, body)));
        }
    }
    (timestamp, signatures.join(" "))
}

/// Standard Webhooks: base64(HMAC-SHA256(key, "{id}.{timestamp}.{body}")).
fn sign(key: &[u8], msg_id: &str, timestamp: u64, body: &[u8]) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let mut ctx = hmac::Context::with_key(&key);
    ctx.update(format!("{msg_id}.{timestamp}.").as_bytes());
    ctx.update(body);
    STANDARD.encode(ctx.sign().as_ref())
}

async fn send_signed(
    target: &CallbackTarget,
    url: &str,
    sub_id: &str,
    msg_id: &str,
    signature: &(u64, String),
    body: Vec<u8>,
) -> Result<reqwest::Response, String> {
    send_signed_at(target, url, sub_id, msg_id, signature.0, &signature.1, body).await
}

async fn send_signed_at(
    target: &CallbackTarget,
    url: &str,
    sub_id: &str,
    msg_id: &str,
    timestamp: u64,
    signature: &str,
    body: Vec<u8>,
) -> Result<reqwest::Response, String> {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .resolve(&target.host, target.addr)
        .build()
        .map_err(|e| e.to_string())?;
    client
        .post(url)
        .header("content-type", "application/json")
        .header("webhook-id", msg_id)
        .header("webhook-timestamp", timestamp.to_string())
        .header("webhook-signature", signature)
        .header("x-mcp-subscription-id", sub_id)
        .body(body)
        .send()
        .await
        .map_err(|e| {
            if e.is_timeout() {
                "timed out".to_string()
            } else {
                e.without_url().to_string()
            }
        })
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    SystemRandom::new().fill(&mut buf).expect("system randomness");
    hex(&buf)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// RFC 3339 / ISO 8601 UTC timestamp, e.g. `2026-10-02T12:00:00Z`.
pub fn iso8601(unix: u64) -> String {
    let days = (unix / 86_400) as i64;
    let secs = unix % 86_400;
    // Civil-from-days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn iso8601_formats_utc() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601(1_790_942_400), "2026-10-02T12:00:00Z");
        assert_eq!(iso8601(951_782_400), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn standard_webhooks_signature_matches_reference() {
        // Reference vector from the Standard Webhooks spec.
        let key = STANDARD.decode("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw").unwrap();
        let body = br#"{"test": 2432232314}"#;
        assert_eq!(
            sign(&key, "msg_p5jXN8AQM9LWM0D4loKWxJek", 1_614_265_330, body),
            "g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE="
        );
    }

    #[test]
    fn public_address_filter() {
        for blocked in ["127.0.0.1", "10.1.2.3", "192.168.1.1", "169.254.169.254", "100.64.0.1", "::1", "fd00::1", "fe80::1", "::ffff:10.0.0.1"] {
            assert!(!is_public(blocked.parse().unwrap()), "{blocked}");
        }
        for ok in ["8.8.8.8", "2606:4700::1111"] {
            assert!(is_public(ok.parse().unwrap()), "{ok}");
        }
    }

    #[test]
    fn arguments_are_validated_and_canonical() {
        let names = vec!["netbird".to_string()];
        let a = normalize_arguments(Some(&serde_json::json!({"states": ["down", "needs_login", "down"], "vpn": "netbird"})), &names).unwrap();
        assert_eq!(a, serde_json::json!({"states": ["down", "needs_login"], "vpn": "netbird"}));
        assert!(normalize_arguments(Some(&serde_json::json!({"vpn": "other"})), &names).is_err());
        assert!(normalize_arguments(Some(&serde_json::json!({"cmd": "x"})), &names).is_err());
    }

    #[tokio::test]
    async fn private_callbacks_are_rejected_by_default() {
        let hub = EventHub::new(EventsConfig::default(), vec!["netbird".into()]);
        let err = hub.subscribe(Some(&subscribe_params("https://127.0.0.1:9/cb"))).await.unwrap_err();
        assert_eq!(err.code, CALLBACK_ENDPOINT_ERROR);
        let err = hub.subscribe(Some(&subscribe_params("http://example.com/cb"))).await.unwrap_err();
        assert_eq!(err.code, CALLBACK_ENDPOINT_ERROR);
    }

    fn secret() -> String {
        format!("whsec_{}", STANDARD.encode([7u8; 32]))
    }

    fn subscribe_params(url: &str) -> Value {
        serde_json::json!({
            "name": VPN_STATE_EVENT,
            "arguments": { "vpn": "netbird", "states": ["needs_login"] },
            "delivery": { "mode": "webhook", "url": url, "secret": secret() },
            "cursor": null,
        })
    }

    /// Minimal HTTP server: answers verification challenges, records events.
    async fn receiver() -> (String, tokio::sync::mpsc::UnboundedReceiver<(String, Value)>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/cb", listener.local_addr().unwrap());
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = listener.accept().await.unwrap();
                let mut buf = vec![0u8; 8192];
                let mut n = 0;
                loop {
                    n += sock.read(&mut buf[n..]).await.unwrap();
                    let text = String::from_utf8_lossy(&buf[..n]);
                    if let Some((head, body)) = text.split_once("\r\n\r\n") {
                        let len = head
                            .lines()
                            .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length: ").map(|v| v.trim().parse::<usize>().unwrap()))
                            .unwrap_or(0);
                        if body.len() >= len {
                            break;
                        }
                    }
                }
                let text = String::from_utf8_lossy(&buf[..n]).into_owned();
                let (head, body) = text.split_once("\r\n\r\n").unwrap();
                let body: Value = serde_json::from_str(body).unwrap();
                let reply = if body["type"] == "verification" {
                    serde_json::json!({ "challenge": body["challenge"] }).to_string()
                } else {
                    String::new()
                };
                let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{reply}", reply.len());
                sock.write_all(resp.as_bytes()).await.unwrap();
                tx.send((head.to_string(), body)).unwrap();
            }
        });
        (url, rx)
    }

    #[tokio::test]
    async fn subscribe_verifies_then_delivers_signed_events() {
        let dir = std::env::temp_dir().join(format!("hmcp-events-{}", random_hex(4)));
        std::fs::create_dir_all(&dir).unwrap();
        let config = EventsConfig {
            store_path: Some(dir.join("events.json")),
            allow_insecure_callbacks: true,
            include_login_url: true,
            ..EventsConfig::default()
        };
        let hub = EventHub::new(config.clone(), vec!["netbird".into()]);
        let (url, mut received) = receiver().await;

        let result = hub.subscribe(Some(&subscribe_params(&url))).await.unwrap();
        let id = result["id"].as_str().unwrap().to_string();
        assert!(id.starts_with("sub_"));
        assert!(result["refreshBefore"].as_str().unwrap().ends_with('Z'));
        let (_, verification) = received.recv().await.unwrap();
        assert_eq!(verification["type"], "verification");

        // Same identity again: idempotent, no second verification.
        let again = hub.subscribe(Some(&subscribe_params(&url))).await.unwrap();
        assert_eq!(again["id"], id.as_str());
        assert_eq!(hub.subscription_count(), 1);

        // Filtered out: state not subscribed.
        hub.publish(VpnStateEvent { vpn: "netbird".into(), from: "needs_login".into(), to: "connected".into(), login_url: None });
        hub.publish(VpnStateEvent {
            vpn: "netbird".into(),
            from: "connected".into(),
            to: "needs_login".into(),
            login_url: Some("https://idp.example/device".into()),
        });
        let (head, event) = tokio::time::timeout(Duration::from_secs(5), received.recv()).await.unwrap().unwrap();
        assert_eq!(event["name"], VPN_STATE_EVENT);
        assert_eq!(event["data"]["to"], "needs_login");
        assert_eq!(event["data"]["login_url"], "https://idp.example/device");

        // Signature verifies with the subscriber's secret.
        let header = |name: &str| {
            head.lines()
                .find_map(|l| l.to_ascii_lowercase().starts_with(name).then(|| l.split_once(": ").unwrap().1.to_string()))
                .unwrap()
        };
        let body = serde_json::to_vec(&event).unwrap();
        let ts: u64 = header("webhook-timestamp").parse().unwrap();
        let expected = format!("v1,{}", sign(&[7u8; 32], &header("webhook-id"), ts, &body));
        assert_eq!(header("webhook-signature"), expected);
        assert_eq!(header("x-mcp-subscription-id"), id);
        assert_eq!(header("webhook-id"), event["eventId"].as_str().unwrap());

        // Persisted, then removed by unsubscribe.
        assert_eq!(EventHub::new(config.clone(), vec!["netbird".into()]).subscription_count(), 1);
        hub.unsubscribe(Some(&subscribe_params(&url))).unwrap();
        assert_eq!(EventHub::new(config, vec!["netbird".into()]).subscription_count(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
