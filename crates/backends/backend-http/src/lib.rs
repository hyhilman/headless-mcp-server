#![forbid(unsafe_code)]

//! HTTP-based MCP backend: connect to remote MCP servers over HTTP.
//!
//! Supports:
//! - Static bearer tokens (env vars, secrets)
//! - OAuth2 auto-discovery (RFC 9728 + RFC 8414)
//! - OAuth2 client_credentials + authorization_code + PKCE grants
//! - Dynamic client registration (RFC 7591)
//! - Token persistence (encrypted at rest, survives restarts)

mod oauth2;
pub mod token_store;

use async_trait::async_trait;
use headless_mcp_core::{
    BackendDef, BackendError, BackendErrorKind, BackendResult, BackendTransport, InitializeResult,
    McpBackend, ToolDescriptor,
};
use headless_mcp_secrets::{EncryptedFileSecretStore, SecretStore};
use headless_mcp_wire::{
    decode_message, JsonRpcId, JsonRpcMessage, JsonRpcNotification, JsonRpcRequest, SseDecoder,
};
use oauth2::{OAuth2TokenManager, parse_resource_metadata_url};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use serde_json::Value;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const APPLICATION_JSON: &str = "application/json";
const SSE_CONTENT_TYPE: &str = "text/event-stream";

/// An HTTP-connected MCP backend with optional OAuth2 support.
pub struct HttpBackend {
    def: BackendDef,
    url: String,
    client: Mutex<reqwest::Client>,
    oauth2: Option<OAuth2TokenManager>,
    /// Encrypted token store for persisting OAuth2 tokens across restarts.
    token_store: Option<Arc<EncryptedFileSecretStore>>,
    initialize_result: Mutex<Option<InitializeResult>>,
    connected: AtomicBool,
    request_counter: AtomicU64,
    default_timeout: Duration,
    /// If true, don't block on interactive OAuth2 flows (daemon mode).
    daemon_mode: bool,
    /// Mcp-Session-Id from initialize response (required by some servers like Atlassian).
    session_id: Mutex<Option<String>>,
}

impl HttpBackend {
    pub fn new(def: BackendDef) -> Self {
        Self::with_store(def, None, false)
    }

    /// Create with a token store for persistence and optional daemon mode.
    pub fn with_store(
        def: BackendDef,
        token_store: Option<Arc<EncryptedFileSecretStore>>,
        daemon_mode: bool,
    ) -> Self {
        let (url, static_token, oauth2_config) = match &def.transport {
            BackendTransport::Http {
                url,
                bearer_token,
                oauth2,
            } => (url.clone(), bearer_token.clone(), oauth2.clone()),
            _ => panic!("HttpBackend requires an HTTP transport"),
        };

        let default_timeout = Duration::from_secs(def.call_timeout_secs);
        let client = Self::build_client(static_token.as_deref(), default_timeout);
        let oauth2 = oauth2_config.map(OAuth2TokenManager::new);

        Self {
            def,
            url,
            client: Mutex::new(client),
            oauth2,
            token_store,
            initialize_result: Mutex::new(None),
            connected: AtomicBool::new(false),
            request_counter: AtomicU64::new(0),
            default_timeout,
            daemon_mode,
            session_id: Mutex::new(None),
        }
    }

    pub fn set_daemon_mode(&mut self, daemon: bool) {
        self.daemon_mode = daemon;
    }

    fn build_client(bearer_token: Option<&str>, timeout: Duration) -> reqwest::Client {
        let mut builder = reqwest::Client::builder()
            .timeout(timeout)
            .http1_title_case_headers();

        if let Some(token) = bearer_token {
            if !token.is_empty() {
                let mut headers = reqwest::header::HeaderMap::new();
                if let Ok(value) =
                    reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
                {
                    headers.insert(AUTHORIZATION, value);
                }
                builder = builder.default_headers(headers);
            }
        }

        builder.build().expect("reqwest client should build")
    }

    fn rebuild_client_with_token(&self, token: &str) {
        let mut client = self.client.lock().unwrap();
        *client = Self::build_client(Some(token), self.default_timeout);
    }

    async fn persist_token(&self, access_token: &str, refresh_token: Option<&str>, expires_in: u64) {
        if let Some(ref store) = self.token_store {
            let client_id = self.oauth2.as_ref().and_then(|o| o.current_client_id());
            token_store::save_token(store, &self.def.id, access_token, refresh_token, expires_in, client_id.as_deref()).await;
            tracing::debug!(backend_id = %self.def.id, "OAuth2 token persisted");
        }
    }

    /// Adopt a token another instance of this same backend may have written since we last looked.
    ///
    /// WHY THIS EXISTS. `build_expose_registry` constructs one `HttpBackend` PER EXPOSE BLOCK, so a
    /// backend named in two blocks is two objects with two independent `OAuth2Manager`s — and they
    /// share exactly one persisted entry, `oauth2:<id>:token`, which each reads once in `connect()`.
    ///
    /// That is survivable until the provider ROTATES refresh tokens, which Slack does: a refresh
    /// returns a new refresh token and retires the one presented. The instance that refreshes first
    /// updates its own memory and the store; the other still holds the retired token forever and
    /// every later refresh returns 400. Observed on a two-profile Slack setup: the read profile
    /// (called hourly) kept winning, and the write profile served exactly one access-token lifetime
    /// of traffic — 23 sends over 11.5h — then failed permanently.
    ///
    /// So: re-read before spending our copy. A still-valid access token is adopted with its
    /// REMAINING life (not expired-on-arrival, or we would spend a rotated refresh token to replace
    /// a token that is fine); an expired one is adopted anyway, because its refresh token is
    /// strictly fresher than ours.
    async fn adopt_persisted_token(&self, oauth2: &OAuth2TokenManager) {
        let Some(ref store) = self.token_store else { return };
        let Some(persisted) = token_store::load_token(store, &self.def.id).await else { return };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let remaining = persisted.expires_at_unix.saturating_sub(now);
        if let Some(cid) = persisted.client_id.as_deref() {
            oauth2.set_dynamic_client_id(cid);
        }
        oauth2.set_cached_token_valid_for(
            &persisted.access_token,
            persisted.refresh_token(),
            Duration::from_secs(remaining),
        );
    }

    async fn post_json(&self, body: &[u8]) -> Result<(Vec<u8>, reqwest::StatusCode, reqwest::header::HeaderMap), BackendError> {
        let client = { self.client.lock().unwrap().clone() };

        let mut req = client
            .post(&self.url)
            .header(CONTENT_TYPE, APPLICATION_JSON)
            .header(ACCEPT, format!("{APPLICATION_JSON}, {SSE_CONTENT_TYPE}"));

        if let Some(ref sid) = *self.session_id.lock().unwrap() {
            req = req.header("Mcp-Session-Id", sid);
        }

        let response = req
            .body(body.to_vec())
            .send()
            .await
            .map_err(|e| {
                BackendError::new(
                    BackendErrorKind::Connection,
                    format!("HTTP request to '{}' failed: {e}", self.def.id),
                )
            })?;

        let status = response.status();

        // Check for OAuth2 metadata on 401
        if status == reqwest::StatusCode::UNAUTHORIZED {
            if let Some(ref oauth2_mgr) = self.oauth2 {
                let metadata_url = response
                    .headers()
                    .get("www-authenticate")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| parse_resource_metadata_url(s));

                let discovery_url = metadata_url.unwrap_or_else(|| {
                    match reqwest::Url::parse(&self.url) {
                        Ok(parsed) => format!(
                            "{}://{}/.well-known/oauth-authorization-server",
                            parsed.scheme(),
                            parsed.authority()
                        ),
                        Err(_) => format!("{}/.well-known/oauth-authorization-server", self.url),
                    }
                });

                tracing::info!(%discovery_url, backend_id = %self.def.id, "OAuth2 discovery");

                if let Err(e) = oauth2_mgr.discover(&discovery_url, &self.def.id).await {
                    tracing::warn!(%e, "OAuth2 discovery failed");
                }
            }
        }

        let headers = response.headers().clone();
        let response_bytes = response.bytes().await.map_err(|e| {
            BackendError::new(
                BackendErrorKind::Protocol,
                format!("failed to read response from '{}': {e}", self.def.id),
            )
        })?;

        Ok((response_bytes.to_vec(), status, headers))
    }

    async fn send_request(
        &self,
        method: &str,
        params: Option<Value>,
        retry: bool,
    ) -> Result<Value, BackendError> {
        let id = self.request_counter.fetch_add(1, Ordering::SeqCst) as i64;
        let request =
            JsonRpcMessage::Request(JsonRpcRequest::new(JsonRpcId::Number(id), method, params));

        let body = serde_json::to_vec(&request).map_err(|e| {
            BackendError::new(BackendErrorKind::Protocol, format!("serialize: {e}"))
        })?;

        let (response_bytes, status, headers) = self.post_json(&body).await?;

        // Capture session ID from response (Atlassian MCP sends Mcp-Session-Id)
        if let Some(sid) = headers.get("mcp-session-id") {
            if let Ok(val) = sid.to_str() {
                tracing::debug!(backend_id = %self.def.id, %val, "captured session id");
                *self.session_id.lock().unwrap() = Some(val.to_string());
            }
        }

        if status == reqwest::StatusCode::UNAUTHORIZED && retry {
            if let Some(ref oauth2_mgr) = self.oauth2 {
                // Deliberately NOT gated on daemon_mode. A refresh_token grant needs no
                // browser, and returning here meant the daemon never spent the refresh
                // token connect() had just loaded — every restart demanded a consent.
                // get_token() blocks the interactive grants in daemon mode itself.
                // A sibling instance of this backend (another expose block) may have refreshed
                // and rotated the shared refresh token since we last read it. See
                // `adopt_persisted_token` — without this, the losing instance 400s forever.
                self.adopt_persisted_token(oauth2_mgr).await;

                tracing::info!(backend_id = %self.def.id, "attempting OAuth2 token acquisition");

                match oauth2_mgr.get_token(&self.def.id, self.daemon_mode).await {
                    Ok(token) => {
                        self.rebuild_client_with_token(&token);

                        // Persist the token. Unconditional: a backend without a refresh
                        // token still needs its access token to survive a restart, and
                        // gating on one meant those writes were silently skipped.
                        //
                        // The lifetime is the token's OWN, not a flat hour. Slack issues 12h
                        // tokens; recording them as 1h had every instance re-refreshing 11 times
                        // more often than needed, and each refresh is a rotation another instance
                        // can lose — the hardcoded 3600 was what made the race constant rather
                        // than rare.
                        let refresh = oauth2_mgr.current_refresh_token();
                        let expires_in = oauth2_mgr.current_expires_in().unwrap_or(3600);
                        self.persist_token(&token, refresh.as_deref(), expires_in).await;

                        // Retry
                        let (retry_bytes, retry_status, retry_headers) = self.post_json(&body).await?;
                        if let Some(sid) = retry_headers.get("mcp-session-id") {
                            if let Ok(val) = sid.to_str() {
                                *self.session_id.lock().unwrap() = Some(val.to_string());
                            }
                        }
                        if retry_status.is_success() {
                            return Self::parse_response(&retry_bytes, &self.def.id);
                        }
                        let body_str = String::from_utf8_lossy(&retry_bytes);
                        return Err(BackendError::new(
                            BackendErrorKind::Auth,
                            format!("HTTP {} after OAuth2: {}", retry_status.as_u16(), body_str),
                        ));
                    }
                    Err(e) => {
                        tracing::warn!(%e, "OAuth2 token acquisition failed");
                    }
                }
            }
        }

        if !status.is_success() {
            let body_str = String::from_utf8_lossy(&response_bytes);
            return Err(BackendError::new(
                BackendErrorKind::Protocol,
                format!("HTTP {} from '{}': {}", status.as_u16(), self.def.id, body_str),
            ));
        }

        Self::parse_response(&response_bytes, &self.def.id)
    }

    fn parse_response(response_bytes: &[u8], backend_id: &str) -> Result<Value, BackendError> {
        let body_str = String::from_utf8_lossy(response_bytes);
        tracing::debug!(%backend_id, %body_str, "raw response");

        // Handle SSE-wrapped responses (e.g. Atlassian MCP)
        let json_bytes: Vec<u8> = if body_str.starts_with("event:") || body_str.starts_with("data:") {
            let mut decoder = SseDecoder::new();
            let events = decoder.feed(&body_str);
            if let Some(event) = events.first() {
                tracing::debug!(%backend_id, data = %event.data, "parsed SSE event");
                event.data.as_bytes().to_vec()
            } else {
                return Err(BackendError::new(
                    BackendErrorKind::Protocol,
                    format!("empty SSE response from '{backend_id}'"),
                ));
            }
        } else {
            response_bytes.to_vec()
        };

        let message = decode_message(&json_bytes).map_err(|e| {
            BackendError::new(
                BackendErrorKind::Protocol,
                format!("failed to decode response from '{backend_id}': {e}"),
            )
        })?;

        match message {
            JsonRpcMessage::SuccessResponse(resp) => Ok(resp.result),
            JsonRpcMessage::ErrorResponse(resp) => Err(BackendError::new(
                BackendErrorKind::Protocol,
                format!(
                    "backend '{backend_id}' returned error (code {}): {}",
                    resp.error.code, resp.error.message
                ),
            )),
            _ => Err(BackendError::new(
                BackendErrorKind::Protocol,
                "unexpected response type",
            )),
        }
    }

    async fn send_notification(&self, method: &str, params: Option<Value>) -> Result<(), BackendError> {
        let notification = JsonRpcMessage::Notification(JsonRpcNotification::new(method, params));
        let body = serde_json::to_vec(&notification).map_err(|e| {
            BackendError::new(BackendErrorKind::Protocol, format!("serialize: {e}"))
        })?;

        let client = { self.client.lock().unwrap().clone() };
        let response = client
            .post(&self.url)
            .header(CONTENT_TYPE, APPLICATION_JSON)
            .body(body)
            .send()
            .await
            .map_err(|e| {
                BackendError::new(
                    BackendErrorKind::Connection,
                    format!("HTTP notification to '{}' failed: {e}", self.def.id),
                )
            })?;

        let status = response.status();
        if !status.is_success() && status.as_u16() != 202 {
            return Err(BackendError::new(
                BackendErrorKind::Protocol,
                format!("notification to '{}' returned HTTP {}", self.def.id, status.as_u16()),
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl McpBackend for HttpBackend {
    fn backend_id(&self) -> &str { &self.def.id }
    fn label(&self) -> &str { self.def.label.as_deref().unwrap_or(&self.def.id) }

    async fn connect(&self) -> BackendResult<InitializeResult> {
        if self.connected.load(Ordering::SeqCst) {
            return self.initialize_result.lock().unwrap().clone()
                .ok_or_else(|| BackendError::new(BackendErrorKind::Internal, "no cached init result"));
        }

        // Load persisted OAuth2 token if available (async, safe inside runtime)
        if let (Some(ref store), Some(ref oauth2)) = (&self.token_store, &self.oauth2) {
            if let Some(persisted) = token_store::load_token(store, &self.def.id).await {
                // Restore dynamic client_id for refresh support
                if let Some(ref cid) = persisted.client_id {
                    oauth2.set_dynamic_client_id(cid);
                }
                if persisted.is_valid() {
                    tracing::info!(backend_id = %self.def.id, "loaded valid persisted token");
                    self.rebuild_client_with_token(&persisted.access_token);
                    oauth2.set_cached_token(&persisted.access_token, persisted.refresh_token());
                } else if persisted.refresh_token().is_some() {
                    tracing::info!(backend_id = %self.def.id, "loaded expired token, will refresh");
                    oauth2.set_cached_token(&persisted.access_token, persisted.refresh_token());
                }
            }
        }

        let result = self
            .send_request("initialize", Some(serde_json::json!({
                "protocolVersion": "2024-11-05",
                "clientInfo": { "name": "headless-mcp", "version": env!("CARGO_PKG_VERSION") },
                "capabilities": {},
            })), true)
            .await?;

        let init_result: InitializeResult = serde_json::from_value(result).map_err(|e| {
            BackendError::new(BackendErrorKind::Protocol, format!("bad init result: {e}"))
        })?;

        // Some servers (e.g. Atlassian) reject standalone notifications; ignore.
        let _ = self.send_notification("notifications/initialized", None).await;

        *self.initialize_result.lock().unwrap() = Some(init_result.clone());
        self.connected.store(true, Ordering::SeqCst);

        tracing::info!(backend_id = %self.def.id, server = %init_result.server_info.name, "http backend connected");
        Ok(init_result)
    }

    async fn list_tools(&self) -> BackendResult<Vec<ToolDescriptor>> {
        self.check_connected()?;
        // retry:true — a long-lived daemon connection outlives the access token; only
        // `initialize` used to refresh it, so every call after that silently 401'd forever.
        let result = self.send_request("tools/list", None, true).await?;
        let tools_list = result.get("tools").and_then(|v| v.as_array()).ok_or_else(|| {
            BackendError::new(BackendErrorKind::Protocol, "no 'tools' array in response")
        })?;
        tools_list.iter().map(|t| serde_json::from_value(t.clone()).map_err(|e| {
            BackendError::new(BackendErrorKind::Protocol, format!("invalid tool descriptor: {e}"))
        })).collect()
    }

    async fn call_tool(&self, name: &str, arguments: Option<Value>, _timeout: Duration) -> BackendResult<Value> {
        self.check_connected()?;
        let params = serde_json::json!({ "name": name, "arguments": arguments.unwrap_or(Value::Object(serde_json::Map::new())) });
        // retry:true — same reasoning as list_tools: this is every actual tool invocation
        // (e.g. slack.slack_send_message), so it's the path that most needs to self-heal.
        self.send_request("tools/call", Some(params), true).await
    }

    async fn request(&self, method: &str, params: Option<Value>, _timeout: Duration) -> BackendResult<Value> {
        self.check_connected()?;
        self.send_request(method, params, true).await
    }

    async fn disconnect(&self) -> BackendResult<()> {
        self.connected.store(false, Ordering::SeqCst);
        tracing::info!(backend_id = %self.def.id, "http backend disconnected");
        Ok(())
    }

    async fn health_check(&self) -> BackendResult<()> {
        self.check_connected()?;
        // retry:true — same bug as list_tools/call_tool: a probe hitting an expired
        // token would otherwise report unhealthy forever instead of self-healing.
        self.send_request("tools/list", None, true).await?;
        Ok(())
    }

    fn protocol_version(&self) -> Option<&str> { None }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};

    /// Reads one HTTP/1.1 request off `stream` (request line + headers + any
    /// Content-Length body) and returns its method.
    async fn read_request_method(stream: &mut TcpStream) -> String {
        let mut reader = BufReader::new(stream);
        let mut request_line = String::new();
        reader.read_line(&mut request_line).await.unwrap();
        let method = request_line.split_whitespace().next().unwrap_or("").to_string();

        let mut content_length = 0usize;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            if line == "\r\n" || line.is_empty() {
                break;
            }
            if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                content_length = v.trim().parse().unwrap_or(0);
            }
        }
        if content_length > 0 {
            let mut body = vec![0u8; content_length];
            reader.read_exact(&mut body).await.unwrap();
        }
        method
    }

    async fn write_response(stream: &mut TcpStream, status: u16, status_text: &str, body: &str) {
        let resp = format!(
            "HTTP/1.1 {status} {status_text}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(resp.as_bytes()).await.unwrap();
        stream.shutdown().await.ok();
    }

    /// A downstream MCP backend that 401s the first `tools/call` POST — simulating an
    /// access token that expired mid-session — then succeeds the retried one. The
    /// interleaved discovery GET (unconditional on any 401, see `post_json`) gets a
    /// plain 404, which is harmless: `discover()` failing is only ever logged.
    async fn spawn_flaky_backend() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut post_count = 0;
            while let Ok((mut stream, _)) = listener.accept().await {
                let method = read_request_method(&mut stream).await;
                if method == "POST" {
                    post_count += 1;
                    if post_count == 1 {
                        write_response(&mut stream, 401, "Unauthorized", "{}").await;
                    } else {
                        let body = serde_json::json!({
                            "jsonrpc": "2.0", "id": 0, "result": { "ok": true },
                        })
                        .to_string();
                        write_response(&mut stream, 200, "OK", &body).await;
                        break;
                    }
                } else {
                    write_response(&mut stream, 404, "Not Found", "{}").await;
                }
            }
        });
        format!("http://{addr}")
    }

    /// The OAuth2 token endpoint: answers one client_credentials grant.
    async fn spawn_token_server() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let _ = read_request_method(&mut stream).await;
                let body = serde_json::json!({
                    "access_token": "test-access-token",
                    "token_type": "bearer",
                    "expires_in": 3600,
                })
                .to_string();
                write_response(&mut stream, 200, "OK", &body).await;
            }
        });
        format!("http://{addr}")
    }

    /// Regression test for the `retry:false` bug: `call_tool` hitting a 401 on an
    /// otherwise-connected backend must refresh via OAuth2 and retry, not fail
    /// straight through. Before this fix `call_tool`/`list_tools`/`health_check` all
    /// passed `retry:false` to `send_request`, so the 401 branch that calls
    /// `get_token()` and retries never ran — every call failed until a full backend
    /// reconnect. This is what silently broke Slack sends for hours in production
    /// (the token refreshed once at connect-time `initialize`, which alone uses
    /// `retry:true`, and never again).
    #[tokio::test]
    async fn call_tool_recovers_from_an_expired_token() {
        let backend_url = spawn_flaky_backend().await;
        let token_url = spawn_token_server().await;

        let def: BackendDef = serde_json::from_value(serde_json::json!({
            "id": "test-backend",
            "transport": "http",
            "url": backend_url,
            "oauth2": {
                "token_endpoint": token_url,
                "client_id": "test-client",
                "client_secret": "test-secret",
            },
        }))
        .unwrap();

        let backend = HttpBackend::with_store(def, None, true);
        backend.connected.store(true, Ordering::SeqCst);

        let result = backend.call_tool("some.tool", None, Duration::from_secs(5)).await;
        assert!(result.is_ok(), "call_tool should recover after refreshing the token: {result:?}");
    }

    /// A token endpoint that ROTATES: it accepts exactly one refresh token, hands back the next
    /// one, and answers 400 to any other — which is what Slack does, and what turns two instances
    /// of one backend into a permanent outage for whichever refreshes second.
    async fn spawn_rotating_token_server(accepts: &'static str, issues: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut reader = BufReader::new(&mut stream);
                let mut line = String::new();
                reader.read_line(&mut line).await.unwrap();
                let mut len = 0usize;
                loop {
                    let mut h = String::new();
                    reader.read_line(&mut h).await.unwrap();
                    if h == "\r\n" || h.is_empty() {
                        break;
                    }
                    if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap_or(0);
                    }
                }
                let mut body = vec![0u8; len];
                reader.read_exact(&mut body).await.unwrap();
                let form = String::from_utf8_lossy(&body).to_string();

                if form.contains(&format!("refresh_token={accepts}")) {
                    let ok = serde_json::json!({
                        "access_token": "rotated-access",
                        "refresh_token": issues,
                        "token_type": "bearer",
                        "expires_in": 3600,
                    })
                    .to_string();
                    write_response(&mut stream, 200, "OK", &ok).await;
                } else {
                    write_response(&mut stream, 400, "Bad Request", "{\"error\":\"invalid_grant\"}").await;
                }
            }
        });
        format!("http://{addr}")
    }

    /// Regression test for the two-instance rotation race.
    ///
    /// `build_expose_registry` builds one `HttpBackend` per expose block, so a backend named in two
    /// blocks is two objects with two token caches over ONE persisted entry. Here instance B holds
    /// the pre-rotation refresh token in memory while the store already carries the rotated one —
    /// exactly the state the read profile leaves the write profile in. B must adopt the stored
    /// token before spending its own; presenting the retired one gets 400 forever, which is what
    /// took Slack sends down for 15 hours.
    #[tokio::test]
    async fn a_second_instance_adopts_a_rotated_token_instead_of_spending_a_retired_one() {
        let backend_url = spawn_flaky_backend().await;
        // Accepts ONLY the rotated token the store holds; the stale in-memory one is refused.
        let token_url = spawn_rotating_token_server("stored-refresh", "next-refresh").await;

        let dir = std::env::temp_dir().join(format!("hmcp-rot-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = Arc::new(
            EncryptedFileSecretStore::with_master_key_hex(
                dir.join("secrets.json"),
                &"ab".repeat(32),
            )
            .unwrap(),
        );

        // What instance A left behind after IT refreshed and rotated: an expired access token and
        // the only refresh token the provider will still honour.
        token_store::save_token(&store, "rot-backend", "old-access", Some("stored-refresh"), 0, Some("test-client")).await;

        let def: BackendDef = serde_json::from_value(serde_json::json!({
            "id": "rot-backend",
            "transport": "http",
            "url": backend_url,
            "oauth2": {
                "token_endpoint": token_url,
                "client_id": "test-client",
                "client_secret": "test-secret",
            },
        }))
        .unwrap();

        let backend = HttpBackend::with_store(def, Some(store.clone()), true);
        backend.connected.store(true, Ordering::SeqCst);
        // Instance B's stale view: the refresh token that was valid before A rotated it.
        if let Some(ref o) = backend.oauth2 {
            o.set_cached_token("old-access", Some("retired-refresh"));
        }

        let result = backend.call_tool("some.tool", None, Duration::from_secs(5)).await;
        assert!(
            result.is_ok(),
            "a second instance must adopt the stored (rotated) refresh token, not spend its retired one: {result:?}"
        );

        // And it must write the rotation forward, so the next instance to look finds the live one.
        let after = token_store::load_token(&store, "rot-backend").await.unwrap();
        assert_eq!(
            after.refresh_token(),
            Some("next-refresh"),
            "the rotated refresh token must be persisted for the sibling instance"
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}

impl HttpBackend {
    fn check_connected(&self) -> BackendResult<()> {
        if !self.connected.load(Ordering::SeqCst) {
            Err(BackendError::new(BackendErrorKind::Connection, format!("backend '{}' not connected", self.def.id)))
        } else {
            Ok(())
        }
    }
}
