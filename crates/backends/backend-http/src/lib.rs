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
use headless_mcp_secrets::EncryptedFileSecretStore;
use headless_mcp_wire::{
    decode_message, JsonRpcId, JsonRpcMessage, JsonRpcNotification, JsonRpcRequest,
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

        // Try loading a persisted token for this backend
        let oauth2 = oauth2_config.map(|config| {
            let mut mgr = OAuth2TokenManager::new(config);
            if let Some(ref store) = token_store {
                if let Some(persisted) = token_store::load_token(store, &def.id) {
                    if persisted.is_valid() {
                        tracing::info!(backend_id = %def.id, "loaded valid persisted OAuth2 token");
                        mgr.set_cached_token(
                            &persisted.access_token,
                            persisted.refresh_token(),
                        );
                    } else if persisted.refresh_token().is_some() {
                        tracing::info!(backend_id = %def.id, "loaded expired token with refresh_token");
                        mgr.set_cached_token(
                            &persisted.access_token,
                            persisted.refresh_token(),
                        );
                    }
                }
            }
            mgr
        });

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

    fn persist_token(&self, access_token: &str, refresh_token: Option<&str>, expires_in: u64) {
        if let Some(ref store) = self.token_store {
            token_store::save_token(store, &self.def.id, access_token, refresh_token, expires_in);
            tracing::debug!(backend_id = %self.def.id, "OAuth2 token persisted");
        }
    }

    async fn post_json(&self, body: &[u8]) -> Result<(Vec<u8>, reqwest::StatusCode), BackendError> {
        let client = { self.client.lock().unwrap().clone() };

        let response = client
            .post(&self.url)
            .header(CONTENT_TYPE, APPLICATION_JSON)
            .header(ACCEPT, format!("{APPLICATION_JSON}, {SSE_CONTENT_TYPE}"))
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

        let response_bytes = response.bytes().await.map_err(|e| {
            BackendError::new(
                BackendErrorKind::Protocol,
                format!("failed to read response from '{}': {e}", self.def.id),
            )
        })?;

        Ok((response_bytes.to_vec(), status))
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

        let (response_bytes, status) = self.post_json(&body).await?;

        if status == reqwest::StatusCode::UNAUTHORIZED && retry {
            if let Some(ref oauth2_mgr) = self.oauth2 {
                if self.daemon_mode {
                    tracing::warn!(
                        backend_id = %self.def.id,
                        "OAuth2 re-authorization needed but running in daemon mode — backend marked unhealthy"
                    );
                    return Err(BackendError::new(
                        BackendErrorKind::Auth,
                        "OAuth2 re-authorization required (daemon mode — run 'headless-mcp --dry-run' to re-authenticate)",
                    ));
                }

                tracing::info!(backend_id = %self.def.id, "attempting OAuth2 token acquisition");

                match oauth2_mgr.get_token(&self.def.id, self.daemon_mode).await {
                    Ok(token) => {
                        self.rebuild_client_with_token(&token);

                        // Persist the token
                        if let Some(refresh) = oauth2_mgr.current_refresh_token() {
                            self.persist_token(&token, Some(&refresh), 3600);
                        }

                        // Retry
                        let (retry_bytes, retry_status) = self.post_json(&body).await?;
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
        let message = decode_message(response_bytes).map_err(|e| {
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

        self.send_notification("notifications/initialized", None).await?;

        *self.initialize_result.lock().unwrap() = Some(init_result.clone());
        self.connected.store(true, Ordering::SeqCst);

        tracing::info!(backend_id = %self.def.id, server = %init_result.server_info.name, "http backend connected");
        Ok(init_result)
    }

    async fn list_tools(&self) -> BackendResult<Vec<ToolDescriptor>> {
        self.check_connected()?;
        let result = self.send_request("tools/list", None, false).await?;
        let tools_list = result.get("tools").and_then(|v| v.as_array()).ok_or_else(|| {
            BackendError::new(BackendErrorKind::Protocol, "no 'tools' array in response")
        })?;
        tools_list.iter().map(|t| serde_json::from_value(t.clone()).map_err(|e| {
            BackendError::new(BackendErrorKind::Protocol, format!("invalid tool descriptor: {e}"))
        })).collect()
    }

    async fn call_tool(&self, name: &str, arguments: Option<Value>, _timeout: Duration) -> BackendResult<Value> {
        self.check_connected()?;
        let params = serde_json::json!({ "name": name, "arguments": arguments.unwrap_or(Value::Null) });
        self.send_request("tools/call", Some(params), false).await
    }

    async fn disconnect(&self) -> BackendResult<()> {
        self.connected.store(false, Ordering::SeqCst);
        tracing::info!(backend_id = %self.def.id, "http backend disconnected");
        Ok(())
    }

    async fn health_check(&self) -> BackendResult<()> {
        self.check_connected()?;
        self.send_request("tools/list", None, false).await?;
        Ok(())
    }

    fn protocol_version(&self) -> Option<&str> { None }
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
