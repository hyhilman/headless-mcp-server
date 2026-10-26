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
use base64::Engine;
use headless_mcp_core::{
    BackendDef, BackendError, BackendErrorKind, BackendResult, BackendTransport, InitializeResult,
    McpBackend, ToolDescriptor,
};
use headless_mcp_secrets::{EncryptedFileSecretStore, SecretStore};
use headless_mcp_wire::{
    decode_message, JsonRpcId, JsonRpcMessage, JsonRpcNotification, JsonRpcRequest, SseDecoder,
};
use oauth2::parse_resource_metadata_url;
pub use oauth2::OAuth2TokenManager;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const APPLICATION_JSON: &str = "application/json";
const SSE_CONTENT_TYPE: &str = "text/event-stream";
const META_PROTOCOL_VERSION: &str = "io.modelcontextprotocol/protocolVersion";

/// Where a tool argument lives in the call and the `Mcp-Param-*` header it is mirrored into.
type ParamHeaders = Vec<(Vec<String>, String)>;

/// An HTTP-connected MCP backend with optional OAuth2 support.
pub struct HttpBackend {
    def: BackendDef,
    url: String,
    client: Mutex<reqwest::Client>,
    /// Shared by every `HttpBackend` of this backend id (see `oauth2_manager`).
    oauth2: Option<Arc<OAuth2TokenManager>>,
    initialize_result: Mutex<Option<InitializeResult>>,
    connected: AtomicBool,
    request_counter: AtomicU64,
    default_timeout: Duration,
    /// If true, don't block on interactive OAuth2 flows (daemon mode).
    daemon_mode: bool,
    /// Mcp-Session-Id from initialize response (required by some servers like Atlassian).
    session_id: Mutex<Option<String>>,
    /// `x-mcp-header` annotations per downstream tool, from `tools/list`.
    param_headers: Mutex<HashMap<String, ParamHeaders>>,
    /// Serialises re-initialisation so one lost session costs one handshake, not one per caller.
    reinit_lock: tokio::sync::Mutex<()>,
    /// Bumped after every re-initialisation attempt; lets waiters see that someone else already ran one.
    session_epoch: AtomicU64,
    /// Set by a successful re-initialisation; the registry re-lists tools when it takes this.
    tools_refresh: AtomicBool,
}

/// A failed request, and why the backend's session is thought lost (if it is).
struct Failure {
    error: BackendError,
    session_lost: Option<&'static str>,
}

impl From<BackendError> for Failure {
    fn from(error: BackendError) -> Self {
        Self {
            error,
            session_lost: None,
        }
    }
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
        let oauth2 = Self::oauth2_manager(&def, token_store.clone());
        Self::with_shared_oauth2(def, daemon_mode, oauth2)
    }

    /// The token manager for `def`, or `None` if it has no OAuth2 config.
    ///
    /// Build it once per backend id and pass it to every `with_shared_oauth2`: two managers over
    /// one stored token each refresh it, and the provider retires the refresh token the loser used.
    pub fn oauth2_manager(
        def: &BackendDef,
        token_store: Option<Arc<EncryptedFileSecretStore>>,
    ) -> Option<Arc<OAuth2TokenManager>> {
        match &def.transport {
            BackendTransport::Http {
                oauth2: Some(config),
                ..
            } => Some(Arc::new(OAuth2TokenManager::with_store(
                config.clone(),
                token_store,
            ))),
            _ => None,
        }
    }

    /// Like `with_store`, but uses the given token manager instead of creating one.
    pub fn with_shared_oauth2(
        def: BackendDef,
        daemon_mode: bool,
        oauth2: Option<Arc<OAuth2TokenManager>>,
    ) -> Self {
        let (url, static_token) = match &def.transport {
            BackendTransport::Http {
                url,
                bearer_token,
                ..
            } => (url.clone(), bearer_token.clone()),
            _ => panic!("HttpBackend requires an HTTP transport"),
        };

        let default_timeout = Duration::from_secs(def.call_timeout_secs);
        let client = Self::build_client(static_token.as_deref(), default_timeout);

        Self {
            def,
            url,
            client: Mutex::new(client),
            oauth2,
            initialize_result: Mutex::new(None),
            connected: AtomicBool::new(false),
            request_counter: AtomicU64::new(0),
            default_timeout,
            daemon_mode,
            session_id: Mutex::new(None),
            param_headers: Mutex::new(HashMap::new()),
            reinit_lock: tokio::sync::Mutex::new(()),
            session_epoch: AtomicU64::new(0),
            tools_refresh: AtomicBool::new(false),
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

    async fn post_json(
        &self,
        body: &[u8],
        extra_headers: &HeaderMap,
        session_id: Option<&str>,
    ) -> Result<(Vec<u8>, reqwest::StatusCode, HeaderMap), BackendError> {
        let client = { self.client.lock().unwrap().clone() };

        let mut req = client
            .post(&self.url)
            .header(CONTENT_TYPE, APPLICATION_JSON)
            .header(ACCEPT, format!("{APPLICATION_JSON}, {SSE_CONTENT_TYPE}"))
            .headers(extra_headers.clone());

        if let Some(sid) = session_id {
            req = req.header("Mcp-Session-Id", sid);
        }

        let response = req
            .body(body.to_vec())
            .send()
            .await
            .map_err(|e| {
                let kind = if e.is_timeout() {
                    BackendErrorKind::Timeout
                } else {
                    BackendErrorKind::Connection
                };
                BackendError::new(kind, format!("HTTP request to '{}' failed: {e}", self.def.id))
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

    /// Sends a request; if a legacy request finds the backend's session gone (it restarted),
    /// runs the handshake again and sends the request once more.
    async fn send_request(
        &self,
        method: &str,
        params: Option<Value>,
        retry: bool,
    ) -> Result<Value, BackendError> {
        let epoch = self.session_epoch.load(Ordering::SeqCst);
        let first = self.send_request_inner(method, params.clone(), retry).await;
        let Err(Failure {
            error,
            session_lost: Some(reason),
        }) = first
        else {
            return first.map_err(|f| f.error);
        };
        // Modern calls are sessionless, and `initialize` is the handshake itself.
        if method == "initialize" || modern_version(params.as_ref()).is_some() {
            return Err(error);
        }
        if let Err(e) = self.reinitialize(epoch, reason).await {
            tracing::warn!(backend_id = %self.def.id, %e, "re-initialize failed");
            return Err(error);
        }
        self.send_request_inner(method, params, retry)
            .await
            .map_err(|f| f.error)
    }

    /// Redoes the handshake after the backend lost our session, unless another caller already did.
    async fn reinitialize(&self, seen_epoch: u64, reason: &str) -> BackendResult<()> {
        let _guard = self.reinit_lock.lock().await;
        if self.session_epoch.load(Ordering::SeqCst) != seen_epoch {
            return Ok(());
        }
        let stale = self.session_id.lock().unwrap().take();
        let outcome = self.handshake().await;
        self.session_epoch.fetch_add(1, Ordering::SeqCst);
        match outcome {
            Ok(init) => {
                *self.initialize_result.lock().unwrap() = Some(init);
                self.tools_refresh.store(true, Ordering::SeqCst);
                tracing::info!(backend_id = %self.def.id, %reason, "http backend re-initialized");
                Ok(())
            }
            Err(e) => {
                // Keep the old id so a later 404 is still recognised as a lost session.
                let mut sid = self.session_id.lock().unwrap();
                if sid.is_none() {
                    *sid = stale;
                }
                Err(e)
            }
        }
    }

    /// `initialize` + `notifications/initialized`; no session id is sent with the first.
    async fn handshake(&self) -> BackendResult<InitializeResult> {
        let result = self
            .send_request_inner(
                "initialize",
                Some(serde_json::json!({
                    "protocolVersion": "2024-11-05",
                    "clientInfo": { "name": "headless-mcp", "version": env!("CARGO_PKG_VERSION") },
                    "capabilities": {},
                })),
                true,
            )
            .await
            .map_err(|f| f.error)?;

        let init_result: InitializeResult = serde_json::from_value(result).map_err(|e| {
            BackendError::new(BackendErrorKind::Protocol, format!("bad init result: {e}"))
        })?;

        // Some servers (e.g. Atlassian) reject standalone notifications; ignore.
        let _ = self
            .send_notification("notifications/initialized", None)
            .await;
        Ok(init_result)
    }

    async fn send_request_inner(
        &self,
        method: &str,
        params: Option<Value>,
        retry: bool,
    ) -> Result<Value, Failure> {
        let id = self.request_counter.fetch_add(1, Ordering::SeqCst) as i64;
        let extra_headers = self.modern_headers(method, params.as_ref());
        let request =
            JsonRpcMessage::Request(JsonRpcRequest::new(JsonRpcId::Number(id), method, params));

        let body = serde_json::to_vec(&request).map_err(|e| {
            BackendError::new(BackendErrorKind::Protocol, format!("serialize: {e}"))
        })?;

        let sent_session = self.session_id.lock().unwrap().clone();
        let (response_bytes, status, headers) = self
            .post_json(&body, &extra_headers, sent_session.as_deref())
            .await?;

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
                tracing::info!(backend_id = %self.def.id, "attempting OAuth2 token acquisition");

                match oauth2_mgr.get_token(&self.def.id, self.daemon_mode).await {
                    Ok(token) => {
                        self.rebuild_client_with_token(&token);

                        // Retry
                        let (retry_bytes, retry_status, retry_headers) = self
                            .post_json(&body, &extra_headers, sent_session.as_deref())
                            .await?;
                        if let Some(sid) = retry_headers.get("mcp-session-id") {
                            if let Ok(val) = sid.to_str() {
                                *self.session_id.lock().unwrap() = Some(val.to_string());
                            }
                        }
                        if retry_status.is_success() {
                            return Ok(Self::parse_response(&retry_bytes, &self.def.id)?);
                        }
                        let body_str = String::from_utf8_lossy(&retry_bytes);
                        return Err(BackendError::new(
                            BackendErrorKind::Auth,
                            format!("HTTP {} after OAuth2: {}", retry_status.as_u16(), body_str),
                        )
                        .into());
                    }
                    Err(e) => {
                        tracing::warn!(%e, "OAuth2 token acquisition failed");
                    }
                }
            }
        }

        if !status.is_success() {
            let body_str = String::from_utf8_lossy(&response_bytes);
            // A 5xx means the backend (or the proxy in front of it) is down; a 4xx came from a live server.
            let kind = if status.is_server_error() {
                BackendErrorKind::Connection
            } else {
                BackendErrorKind::Protocol
            };
            let session_lost = if status == reqwest::StatusCode::NOT_FOUND && sent_session.is_some()
            {
                Some("HTTP 404 for the session")
            } else {
                session_not_initialized(&response_bytes)
            };
            let error = BackendError::new(
                kind,
                format!("HTTP {} from '{}': {}", status.as_u16(), self.def.id, body_str),
            );
            return Err(Failure {
                error,
                session_lost,
            });
        }

        Self::parse_response(&response_bytes, &self.def.id).map_err(|error| Failure {
            session_lost: session_not_initialized(&response_bytes),
            error,
        })
    }

    /// Headers a 2026-07-28 request must carry; empty for legacy requests.
    ///
    /// Built from the body so they cannot disagree with it.
    fn modern_headers(&self, method: &str, params: Option<&Value>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        let (Some(params), Some(version)) = (params, modern_version(params)) else {
            return headers;
        };
        let mut put = |name: HeaderName, value: &str| {
            if let Ok(value) = HeaderValue::from_str(value) {
                headers.insert(name, value);
            }
        };
        put(HeaderName::from_static("mcp-protocol-version"), version);
        put(HeaderName::from_static("mcp-method"), method);

        let name_field = match method {
            "tools/call" | "prompts/get" => Some("name"),
            "resources/read" => Some("uri"),
            _ => None,
        };
        let source = name_field.and_then(|f| params.get(f)).and_then(Value::as_str);
        if let Some(source) = source {
            put(HeaderName::from_static("mcp-name"), &encode_header_value(source));
        }

        if method == "tools/call" {
            let tool_headers = self.param_headers.lock().unwrap();
            let annotated = source.and_then(|tool| tool_headers.get(tool));
            for (path, suffix) in annotated.into_iter().flatten() {
                let value = params
                    .get("arguments")
                    .and_then(|args| path.iter().try_fold(args, |v, key| v.get(key.as_str())))
                    .and_then(header_text);
                let name = HeaderName::from_bytes(format!("Mcp-Param-{suffix}").as_bytes());
                if let (Some(value), Ok(name)) = (value, name) {
                    put(name, &encode_header_value(&value));
                }
            }
        }
        headers
    }

    fn parse_response(response_bytes: &[u8], backend_id: &str) -> Result<Value, BackendError> {
        let body_str = String::from_utf8_lossy(response_bytes);
        tracing::debug!(%backend_id, %body_str, "raw response");

        let json_bytes = json_payload(response_bytes).ok_or_else(|| {
            BackendError::new(
                BackendErrorKind::Protocol,
                format!("empty SSE response from '{backend_id}'"),
            )
        })?;

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

    fn session_header(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        let sid = self.session_id.lock().unwrap().clone();
        if let Some(value) = sid.and_then(|sid| HeaderValue::from_str(&sid).ok()) {
            headers.insert(HeaderName::from_static("mcp-session-id"), value);
        }
        headers
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
            .headers(self.session_header())
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

        if let Some(ref oauth2) = self.oauth2 {
            if let Some(access_token) = oauth2.adopt_persisted(&self.def.id).await {
                tracing::info!(backend_id = %self.def.id, "loaded valid persisted token");
                self.rebuild_client_with_token(&access_token);
            }
        }

        let init_result = self.handshake().await?;

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
        let tools: Vec<ToolDescriptor> = tools_list.iter().map(|t| serde_json::from_value(t.clone()).map_err(|e| {
            BackendError::new(BackendErrorKind::Protocol, format!("invalid tool descriptor: {e}"))
        })).collect::<Result<_, _>>()?;
        *self.param_headers.lock().unwrap() = tools
            .iter()
            .map(|t| (t.name.clone(), param_header_paths(&t.input_schema)))
            .filter(|(_, paths)| !paths.is_empty())
            .collect();
        Ok(tools)
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

    fn take_tools_refresh(&self) -> bool {
        self.tools_refresh.swap(false, Ordering::SeqCst)
    }
}

/// The `_meta` protocol version of a 2026-07-28 request; `None` for legacy requests.
fn modern_version(params: Option<&Value>) -> Option<&str> {
    params?.get("_meta")?.get(META_PROTOCOL_VERSION)?.as_str()
}

/// The JSON of a response body, unwrapping an SSE frame (e.g. Atlassian MCP); `None` for an empty one.
fn json_payload(response_bytes: &[u8]) -> Option<Vec<u8>> {
    let body = String::from_utf8_lossy(response_bytes);
    if !(body.starts_with("event:") || body.starts_with("data:")) {
        return Some(response_bytes.to_vec());
    }
    let events = SseDecoder::new().feed(&body);
    let event = events.first()?;
    tracing::debug!(data = %event.data, "parsed SSE event");
    Some(event.data.as_bytes().to_vec())
}

/// A JSON-RPC error saying the session was never initialized, which is what a restarted backend answers.
///
/// Kept narrow (invalid-request or server-error code AND that wording) so ordinary errors are not retried.
fn session_not_initialized(response_bytes: &[u8]) -> Option<&'static str> {
    let JsonRpcMessage::ErrorResponse(resp) =
        decode_message(&json_payload(response_bytes)?).ok()?
    else {
        return None;
    };
    let code = resp.error.code;
    let lost = (code == -32600 || (-32099..=-32000).contains(&code))
        && resp
            .error
            .message
            .to_ascii_lowercase()
            .contains("not initialized");
    lost.then_some("session is not initialized")
}

/// `x-mcp-header` annotations reachable through `properties` keys only.
fn param_header_paths(schema: &Value) -> ParamHeaders {
    fn walk(schema: &Value, path: &mut Vec<String>, out: &mut ParamHeaders) {
        let Some(props) = schema.get("properties").and_then(Value::as_object) else { return };
        for (key, prop) in props {
            path.push(key.clone());
            let primitive = matches!(
                prop.get("type").and_then(Value::as_str),
                Some("string" | "integer" | "boolean")
            );
            if let (Some(name), true) = (prop.get("x-mcp-header").and_then(Value::as_str), primitive) {
                out.push((path.clone(), name.to_string()));
            }
            walk(prop, path, out);
            path.pop();
        }
    }
    let mut out = Vec::new();
    walk(schema, &mut Vec::new(), &mut out);
    out
}

/// A string, integer or boolean argument as header text; `None` for null and other types.
fn header_text(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Number(n) if n.is_i64() || n.is_u64() => Some(n.to_string()),
        _ => None,
    }
}

/// Plain ASCII as is; anything else, or anything that looks like the sentinel, as `=?base64?...?=`.
fn encode_header_value(value: &str) -> String {
    let plain = value.chars().all(|c| (' '..='~').contains(&c))
        && !value.starts_with(' ')
        && !value.ends_with(' ')
        && !(value.starts_with("=?base64?") && value.ends_with("?="));
    if plain {
        value.to_string()
    } else {
        format!("=?base64?{}?=", base64::engine::general_purpose::STANDARD.encode(value))
    }
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

    /// Serves `replies` (status, body) in order, repeating the last; returns the URL and the raw
    /// request head (lower-cased) of every POST it saw.
    async fn spawn_recording_backend(
        replies: Vec<(u16, String)>,
    ) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        tokio::spawn(async move {
            let mut n = 0;
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut reader = BufReader::new(&mut stream);
                let mut head = String::new();
                let mut len = 0usize;
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).await.unwrap();
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap_or(0);
                    }
                    head.push_str(&line.to_ascii_lowercase());
                }
                let mut body = vec![0u8; len];
                reader.read_exact(&mut body).await.unwrap();
                log.lock().unwrap().push(head);
                let (status, reply) = &replies[n.min(replies.len() - 1)];
                n += 1;
                write_response(&mut stream, *status, "Reply", reply).await;
            }
        });
        (format!("http://{addr}"), seen)
    }

    fn ok_reply(result: Value) -> (u16, String) {
        (200, serde_json::json!({ "jsonrpc": "2.0", "id": 0, "result": result }).to_string())
    }

    fn connected_backend(url: String) -> HttpBackend {
        let def: BackendDef = serde_json::from_value(serde_json::json!({
            "id": "mock", "transport": "http", "url": url,
        }))
        .unwrap();
        let backend = HttpBackend::new(def);
        backend.connected.store(true, Ordering::SeqCst);
        backend
    }

    fn modern_call(name: &str, arguments: Value) -> Value {
        serde_json::json!({
            "name": name,
            "arguments": arguments,
            "_meta": { "io.modelcontextprotocol/protocolVersion": "2026-07-28" },
        })
    }

    #[tokio::test]
    async fn a_modern_tools_call_carries_the_matching_request_headers() {
        let (url, seen) = spawn_recording_backend(vec![ok_reply(serde_json::json!({}))]).await;
        let backend = connected_backend(url);
        let params = modern_call("peers", serde_json::json!({}));
        backend.request("tools/call", Some(params), Duration::from_secs(5)).await.unwrap();

        let head = seen.lock().unwrap()[0].clone();
        assert!(head.contains("mcp-protocol-version: 2026-07-28\r\n"), "{head}");
        assert!(head.contains("mcp-method: tools/call\r\n"), "{head}");
        assert!(head.contains("mcp-name: peers\r\n"), "{head}");
    }

    #[tokio::test]
    async fn a_modern_resources_read_names_the_uri() {
        let (url, seen) = spawn_recording_backend(vec![ok_reply(serde_json::json!({}))]).await;
        let backend = connected_backend(url);
        let params = serde_json::json!({
            "uri": "cli://netbird/state",
            "_meta": { "io.modelcontextprotocol/protocolVersion": "2026-07-28" },
        });
        backend.request("resources/read", Some(params), Duration::from_secs(5)).await.unwrap();

        let head = seen.lock().unwrap()[0].clone();
        assert!(head.contains("mcp-method: resources/read\r\n"), "{head}");
        assert!(head.contains("mcp-name: cli://netbird/state\r\n"), "{head}");
    }

    #[tokio::test]
    async fn legacy_requests_keep_their_headers() {
        let (url, seen) = spawn_recording_backend(vec![ok_reply(serde_json::json!({}))]).await;
        let backend = connected_backend(url);
        let params = serde_json::json!({ "name": "peers", "arguments": {} });
        backend.request("tools/call", Some(params), Duration::from_secs(5)).await.unwrap();
        backend.request("tools/list", None, Duration::from_secs(5)).await.unwrap();

        for head in seen.lock().unwrap().iter() {
            assert!(!head.contains("mcp-protocol-version"), "{head}");
            assert!(!head.contains("mcp-method"), "{head}");
            assert!(!head.contains("mcp-name"), "{head}");
            assert!(head.contains("accept: application/json, text/event-stream"), "{head}");
        }
    }

    #[tokio::test]
    async fn annotated_arguments_are_mirrored_into_param_headers() {
        let tools = ok_reply(serde_json::json!({ "tools": [{
            "name": "execute_sql",
            "description": "sql",
            "inputSchema": { "type": "object", "properties": {
                "region": { "type": "string", "x-mcp-header": "Region" },
                "greeting": { "type": "string", "x-mcp-header": "Greeting" },
                "limit": { "type": "integer", "x-mcp-header": "Limit" },
                "skipped": { "type": "string", "x-mcp-header": "Skipped" },
                "query": { "type": "string" },
            } },
        }] }));
        let (url, seen) = spawn_recording_backend(vec![tools, ok_reply(serde_json::json!({}))]).await;
        let backend = connected_backend(url);
        backend.list_tools().await.unwrap();
        let args = serde_json::json!({
            "region": "us-west1", "greeting": "Hello, 世界", "limit": 7,
            "skipped": null, "query": "SELECT 1",
        });
        backend
            .request("tools/call", Some(modern_call("execute_sql", args)), Duration::from_secs(5))
            .await
            .unwrap();

        let head = seen.lock().unwrap()[1].clone();
        assert!(head.contains("mcp-param-region: us-west1\r\n"), "{head}");
        // The mock lower-cases the whole head.
        assert!(head.contains("mcp-param-greeting: =?base64?sgvsbg8sios4luevja==?=\r\n"), "{head}");
        assert!(head.contains("mcp-param-limit: 7\r\n"), "{head}");
        assert!(!head.contains("mcp-param-skipped"), "{head}");
        assert!(!head.contains("mcp-param-query"), "{head}");
    }

    #[test]
    fn header_values_that_are_not_plain_ascii_are_base64_encoded() {
        assert_eq!(encode_header_value("us-west1"), "us-west1");
        assert_eq!(encode_header_value(" padded "), "=?base64?IHBhZGRlZCA=?=");
        assert_eq!(encode_header_value("line1\nline2"), "=?base64?bGluZTEKbGluZTI=?=");
        assert_eq!(encode_header_value("=?base64?literal?="), "=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?=");
    }

    #[tokio::test]
    async fn a_4xx_is_a_protocol_error_but_a_5xx_or_refused_connection_is_unreachable() {
        let mismatch = (
            400,
            serde_json::json!({ "code": -32020, "message": "Header mismatch" }).to_string(),
        );
        let (url, _) = spawn_recording_backend(vec![mismatch]).await;
        let e = connected_backend(url).request("tools/list", None, Duration::from_secs(5)).await.unwrap_err();
        assert_eq!(e.kind, BackendErrorKind::Protocol, "{e}");

        let (url, _) = spawn_recording_backend(vec![(503, "{}".into())]).await;
        let e = connected_backend(url).request("tools/list", None, Duration::from_secs(5)).await.unwrap_err();
        assert_eq!(e.kind, BackendErrorKind::Connection, "{e}");

        let closed = {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            format!("http://{}", listener.local_addr().unwrap())
        };
        let e = connected_backend(closed).request("tools/list", None, Duration::from_secs(5)).await.unwrap_err();
        assert_eq!(e.kind, BackendErrorKind::Connection, "{e}");
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

    /// An instance holds the pre-rotation refresh token in memory while the store already carries
    /// the rotated one. The provider rejects the retired token; the hub must fall back to the
    /// stored one instead of failing every later call with 400.
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

    /// What the rotating token endpoint saw and holds.
    struct Issuer {
        hits: std::sync::atomic::AtomicUsize,
        /// The only refresh token the provider honours right now.
        live: Mutex<String>,
    }

    /// Another process (`headless-mcp auth`) that re-authorises while a refresh is in flight.
    struct OtherWriter {
        store: Arc<EncryptedFileSecretStore>,
        backend_id: &'static str,
        refresh_token: &'static str,
    }

    fn form_value(form: &str, key: &str) -> Option<String> {
        form.split('&')
            .find_map(|kv| kv.strip_prefix(&format!("{key}=")).map(str::to_string))
    }

    /// A token endpoint that ROTATES like Notion and Slack: it honours only the live refresh token,
    /// retires it on use, issues `access-N` / `rt-N`, and answers 400 to anything else. The delay
    /// keeps concurrent refreshes in flight together. `other_writer` runs just before a rejection.
    async fn spawn_rotating_issuer(
        live: &str,
        delay: Duration,
        other_writer: Option<OtherWriter>,
    ) -> (String, Arc<Issuer>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let issuer = Arc::new(Issuer {
            hits: std::sync::atomic::AtomicUsize::new(0),
            live: Mutex::new(live.to_string()),
        });
        let state = issuer.clone();
        let other_writer = Arc::new(other_writer);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let (state, other_writer) = (state.clone(), other_writer.clone());
                tokio::spawn(async move {
                    let mut reader = BufReader::new(&mut stream);
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
                    let presented = form_value(&String::from_utf8_lossy(&body), "refresh_token");

                    let n = state.hits.fetch_add(1, Ordering::SeqCst) + 1;
                    let accepted = {
                        let mut live = state.live.lock().unwrap();
                        let ok = presented.as_deref() == Some(live.as_str());
                        if ok {
                            *live = format!("rt-{n}");
                        }
                        ok
                    };
                    tokio::time::sleep(delay).await;
                    if accepted {
                        let ok = serde_json::json!({
                            "access_token": format!("access-{n}"),
                            "refresh_token": format!("rt-{n}"),
                            "token_type": "bearer",
                            "expires_in": 3600,
                        })
                        .to_string();
                        write_response(&mut stream, 200, "OK", &ok).await;
                    } else {
                        if let Some(w) = other_writer.as_ref() {
                            token_store::save_token(
                                &w.store,
                                w.backend_id,
                                "auth-access",
                                Some(w.refresh_token),
                                0,
                                Some("test-client"),
                            )
                            .await;
                        }
                        write_response(
                            &mut stream,
                            400,
                            "Bad Request",
                            "{\"error\":\"invalid_grant\"}",
                        )
                        .await;
                    }
                });
            }
        });
        (format!("http://{addr}"), issuer)
    }

    /// A protected MCP backend: 401 until the request carries an `access-N` token.
    async fn spawn_protected_backend() -> (String, Arc<Mutex<Vec<(String, String)>>>) {
        spawn_scripted_backend(|method, head| match method {
            "" => Reply::new(404, "{}".into()),
            _ if head.contains("authorization: bearer access-") => ok_call(),
            _ => Reply::new(401, "{}".into()),
        })
        .await
    }

    fn oauth_def(id: &str, backend_url: &str, token_url: &str) -> BackendDef {
        serde_json::from_value(serde_json::json!({
            "id": id,
            "transport": "http",
            "url": backend_url,
            "oauth2": {
                "token_endpoint": token_url,
                "client_id": "test-client",
                "client_secret": "test-secret",
            },
        }))
        .unwrap()
    }

    fn temp_store(name: &str) -> (Arc<EncryptedFileSecretStore>, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("hmcp-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = EncryptedFileSecretStore::with_master_key_hex(
            dir.join("secrets.json"),
            &"ab".repeat(32),
        )
        .unwrap();
        (Arc::new(store), dir)
    }

    /// Two expose blocks naming one backend, wired as `build_expose_registry` does: one shared
    /// token manager, loaded from the store as `connect()` does.
    async fn expose_pair(
        def: &BackendDef,
        store: &Arc<EncryptedFileSecretStore>,
    ) -> (HttpBackend, HttpBackend) {
        let oauth2 = HttpBackend::oauth2_manager(def, Some(store.clone()));
        oauth2.as_ref().unwrap().adopt_persisted(&def.id).await;
        let pair =
            [(); 2].map(|_| HttpBackend::with_shared_oauth2(def.clone(), true, oauth2.clone()));
        let [a, b] = pair;
        a.connected.store(true, Ordering::SeqCst);
        b.connected.store(true, Ordering::SeqCst);
        (a, b)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_expose_blocks_of_one_backend_refresh_once_and_agree_on_the_token() {
        let (backend_url, seen) = spawn_protected_backend().await;
        let (token_url, issuer) =
            spawn_rotating_issuer("rt-0", Duration::from_millis(150), None).await;
        let (store, dir) = temp_store("shared-refresh");
        token_store::save_token(
            &store,
            "shared",
            "old-access",
            Some("rt-0"),
            0,
            Some("test-client"),
        )
        .await;
        let (a, b) = expose_pair(&oauth_def("shared", &backend_url, &token_url), &store).await;

        let (ra, rb) = tokio::join!(
            a.call_tool("some.tool", None, Duration::from_secs(5)),
            b.call_tool("some.tool", None, Duration::from_secs(5)),
        );

        assert!(
            ra.is_ok() && rb.is_ok(),
            "both callers must succeed: {ra:?} / {rb:?}"
        );
        assert_eq!(
            issuer.hits.load(Ordering::SeqCst),
            1,
            "the token endpoint must be hit exactly once"
        );
        let tokens: std::collections::HashSet<String> = seen
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(_, head)| {
                head.lines()
                    .find_map(|l| l.strip_prefix("authorization: bearer "))
            })
            .map(str::to_string)
            .collect();
        assert_eq!(
            tokens,
            ["access-1".to_string()].into(),
            "both callers must use the same access token"
        );
        let stored = token_store::load_token(&store, "shared").await.unwrap();
        assert_eq!(
            stored.refresh_token(),
            Some(issuer.live.lock().unwrap().as_str()),
            "the store must hold the last refresh token the provider issued"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// `headless-mcp auth` re-authorises (new refresh token in the store) while this backend still
    /// holds the old one: the provider rejects the old token, and the hub must re-read the store.
    #[tokio::test]
    async fn a_rejected_refresh_adopts_the_token_another_writer_stored() {
        let (backend_url, _seen) = spawn_protected_backend().await;
        let (store, dir) = temp_store("rejected-refresh");
        let (token_url, issuer) = spawn_rotating_issuer(
            "rt-fresh",
            Duration::ZERO,
            Some(OtherWriter {
                store: store.clone(),
                backend_id: "authed",
                refresh_token: "rt-fresh",
            }),
        )
        .await;
        token_store::save_token(
            &store,
            "authed",
            "old-access",
            Some("rt-old"),
            0,
            Some("test-client"),
        )
        .await;
        let backend = HttpBackend::with_store(
            oauth_def("authed", &backend_url, &token_url),
            Some(store.clone()),
            true,
        );
        backend.connected.store(true, Ordering::SeqCst);
        backend
            .oauth2
            .as_ref()
            .unwrap()
            .set_cached_token("old-access", Some("rt-old"));

        let result = backend
            .call_tool("some.tool", None, Duration::from_secs(5))
            .await;

        assert!(
            result.is_ok(),
            "a rejected refresh must retry with the stored token: {result:?}"
        );
        assert_eq!(
            issuer.hits.load(Ordering::SeqCst),
            2,
            "one rejected refresh, one accepted"
        );
        let stored = token_store::load_token(&store, "authed").await.unwrap();
        assert_eq!(stored.refresh_token(), Some("rt-2"));

        std::fs::remove_dir_all(&dir).ok();
    }

    struct Reply {
        status: u16,
        body: String,
        headers: Vec<(&'static str, String)>,
        delay: Duration,
    }

    impl Reply {
        fn new(status: u16, body: String) -> Self {
            Self {
                status,
                body,
                headers: vec![],
                delay: Duration::ZERO,
            }
        }
    }

    /// Answers each request with `respond(rpc method, lower-cased head)`; returns the URL and every
    /// (rpc method, head) seen, in arrival order. One task per connection.
    async fn spawn_scripted_backend(
        respond: impl Fn(&str, &str) -> Reply + Send + Sync + 'static,
    ) -> (String, Arc<Mutex<Vec<(String, String)>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let respond = Arc::new(respond);
        let log = seen.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let (respond, log) = (respond.clone(), log.clone());
                tokio::spawn(async move {
                    let mut reader = BufReader::new(&mut stream);
                    let mut head = String::new();
                    let mut len = 0usize;
                    loop {
                        let mut line = String::new();
                        reader.read_line(&mut line).await.unwrap();
                        if line == "\r\n" || line.is_empty() {
                            break;
                        }
                        if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                            len = v.trim().parse().unwrap_or(0);
                        }
                        head.push_str(&line.to_ascii_lowercase());
                    }
                    let mut body = vec![0u8; len];
                    reader.read_exact(&mut body).await.unwrap();
                    let rpc: Value = serde_json::from_slice(&body).unwrap_or_default();
                    let method = rpc["method"].as_str().unwrap_or("").to_string();
                    log.lock().unwrap().push((method.clone(), head.clone()));
                    let reply = respond(&method, &head);
                    tokio::time::sleep(reply.delay).await;
                    let extra: String = reply
                        .headers
                        .iter()
                        .map(|(k, v)| format!("{k}: {v}\r\n"))
                        .collect();
                    let resp = format!(
                        "HTTP/1.1 {} Reply\r\nContent-Type: application/json\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                        reply.status,
                        reply.body.len(),
                        reply.body
                    );
                    stream.write_all(resp.as_bytes()).await.unwrap();
                    stream.shutdown().await.ok();
                });
            }
        });
        (format!("http://{addr}"), seen)
    }

    fn init_reply() -> Reply {
        Reply::new(
            200,
            serde_json::json!({ "jsonrpc": "2.0", "id": 0, "result": {
            "protocolVersion": "2024-11-05",
            "serverInfo": { "name": "mock", "version": "1" },
            "capabilities": {},
        } })
            .to_string(),
        )
    }

    fn rpc_error(code: i64, message: &str) -> Reply {
        Reply::new(
            200,
            serde_json::json!({
                "jsonrpc": "2.0", "id": 0, "error": { "code": code, "message": message },
            })
            .to_string(),
        )
    }

    fn ok_call() -> Reply {
        Reply::new(200, ok_reply(serde_json::json!({ "ok": true })).1)
    }

    const NOT_INITIALIZED: &str = "session is not initialized; call \"initialize\" first";

    fn count(seen: &Arc<Mutex<Vec<(String, String)>>>, method: &str) -> usize {
        seen.lock()
            .unwrap()
            .iter()
            .filter(|(m, _)| m == method)
            .count()
    }

    fn real_backend(url: String) -> HttpBackend {
        let def: BackendDef = serde_json::from_value(serde_json::json!({
            "id": "mock", "transport": "http", "url": url,
        }))
        .unwrap();
        HttpBackend::new(def)
    }

    /// A backend that forgets its session when `lost` flips to true and only knows it again
    /// after the next `initialize`.
    fn restartable(lost: Arc<AtomicBool>) -> impl Fn(&str, &str) -> Reply + Send + Sync + 'static {
        move |method, _head| match method {
            "initialize" => {
                lost.store(false, Ordering::SeqCst);
                init_reply()
            }
            "notifications/initialized" => Reply::new(202, String::new()),
            _ if lost.load(Ordering::SeqCst) => rpc_error(-32600, NOT_INITIALIZED),
            _ => ok_call(),
        }
    }

    #[tokio::test]
    async fn a_restarted_backend_is_initialized_again_and_the_call_retried_once() {
        let lost = Arc::new(AtomicBool::new(false));
        let (url, seen) = spawn_scripted_backend(restartable(lost.clone())).await;
        let backend = real_backend(url);
        backend.connect().await.unwrap();
        lost.store(true, Ordering::SeqCst);

        let result = backend
            .call_tool("peers", None, Duration::from_secs(5))
            .await
            .unwrap();

        assert_eq!(result["ok"], true);
        assert_eq!(count(&seen, "initialize"), 2);
        assert_eq!(count(&seen, "notifications/initialized"), 2);
        assert_eq!(count(&seen, "tools/call"), 2);
        assert!(backend.take_tools_refresh());
        assert!(!backend.take_tools_refresh());
    }

    #[tokio::test]
    async fn a_404_for_a_known_session_starts_a_new_session() {
        let (url, seen) = spawn_scripted_backend(|method, head| match method {
            "initialize" => {
                let mut reply = init_reply();
                reply.headers.push(("Mcp-Session-Id", "s2".into()));
                reply
            }
            "notifications/initialized" => Reply::new(202, String::new()),
            _ if head.contains("mcp-session-id: s2\r\n") => ok_call(),
            _ => Reply::new(404, "{}".into()),
        })
        .await;
        let backend = real_backend(url);
        backend.connected.store(true, Ordering::SeqCst);
        *backend.session_id.lock().unwrap() = Some("s1".into());

        backend
            .call_tool("peers", None, Duration::from_secs(5))
            .await
            .unwrap();

        let log = seen.lock().unwrap().clone();
        let methods: Vec<&str> = log.iter().map(|(m, _)| m.as_str()).collect();
        assert_eq!(
            methods,
            [
                "tools/call",
                "initialize",
                "notifications/initialized",
                "tools/call"
            ]
        );
        assert!(
            !log[1].1.contains("mcp-session-id"),
            "initialize must start a new session: {}",
            log[1].1
        );
        assert!(log[2].1.contains("mcp-session-id: s2\r\n"), "{}", log[2].1);
        assert!(log[3].1.contains("mcp-session-id: s2\r\n"), "{}", log[3].1);
    }

    #[tokio::test]
    async fn a_404_without_a_session_is_not_retried() {
        let (url, seen) = spawn_scripted_backend(|_, _| Reply::new(404, "{}".into())).await;
        let backend = connected_backend(url);

        let e = backend
            .call_tool("peers", None, Duration::from_secs(5))
            .await
            .unwrap_err();

        assert!(e.to_string().contains("404"), "{e}");
        assert_eq!(seen.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn other_invalid_request_errors_are_not_retried() {
        let (url, seen) =
            spawn_scripted_backend(|_, _| rpc_error(-32600, "params must be an object")).await;
        let backend = connected_backend(url);

        let e = backend
            .call_tool("peers", None, Duration::from_secs(5))
            .await
            .unwrap_err();

        assert!(e.to_string().contains("params must be an object"), "{e}");
        assert_eq!(seen.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_failed_re_initialize_returns_the_original_error_without_looping() {
        let (url, seen) = spawn_scripted_backend(|method, _| match method {
            "initialize" => Reply::new(500, "down".into()),
            _ => rpc_error(-32600, NOT_INITIALIZED),
        })
        .await;
        let backend = connected_backend(url);

        let e = backend
            .call_tool("peers", None, Duration::from_secs(5))
            .await
            .unwrap_err();

        assert!(e.to_string().contains(NOT_INITIALIZED), "{e}");
        let methods: Vec<String> = seen
            .lock()
            .unwrap()
            .iter()
            .map(|(m, _)| m.clone())
            .collect();
        assert_eq!(methods, ["tools/call", "initialize"]);
        assert!(!backend.take_tools_refresh());
    }

    #[tokio::test]
    async fn a_call_that_still_fails_after_re_initialize_is_not_retried_again() {
        let (url, seen) = spawn_scripted_backend(|method, _| match method {
            "initialize" => init_reply(),
            "notifications/initialized" => Reply::new(202, String::new()),
            _ => rpc_error(-32600, NOT_INITIALIZED),
        })
        .await;
        let backend = connected_backend(url);

        let e = backend
            .call_tool("peers", None, Duration::from_secs(5))
            .await
            .unwrap_err();

        assert!(e.to_string().contains(NOT_INITIALIZED), "{e}");
        assert_eq!(count(&seen, "initialize"), 1);
        assert_eq!(count(&seen, "tools/call"), 2);
    }

    #[tokio::test]
    async fn a_modern_call_is_never_re_initialized() {
        let (url, seen) = spawn_scripted_backend(|_, _| rpc_error(-32600, NOT_INITIALIZED)).await;
        let backend = connected_backend(url);
        let params = modern_call("peers", serde_json::json!({}));

        backend
            .request("tools/call", Some(params), Duration::from_secs(5))
            .await
            .unwrap_err();

        assert_eq!(seen.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn concurrent_calls_on_a_lost_session_share_one_re_initialize() {
        let lost = Arc::new(AtomicBool::new(false));
        let respond = restartable(lost.clone());
        // The error is slow, so every caller has hit the dead session before the first re-initialize ends.
        let (url, seen) = spawn_scripted_backend(move |method, head| {
            let mut reply = respond(method, head);
            if method == "tools/call" {
                reply.delay = Duration::from_millis(150);
            }
            reply
        })
        .await;
        let backend = Arc::new(real_backend(url));
        backend.connect().await.unwrap();
        lost.store(true, Ordering::SeqCst);

        let calls: Vec<_> = (0..8)
            .map(|_| {
                let backend = backend.clone();
                tokio::spawn(async move {
                    backend
                        .call_tool("peers", None, Duration::from_secs(5))
                        .await
                })
            })
            .collect();
        for call in calls {
            assert_eq!(call.await.unwrap().unwrap()["ok"], true);
        }

        assert_eq!(count(&seen, "initialize"), 2);
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
