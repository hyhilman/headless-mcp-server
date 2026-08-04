#![forbid(unsafe_code)]

//! HTTP-based MCP backend: connect to remote MCP servers over HTTP.
//!
//! Supports both static bearer tokens and OAuth2 client credentials flow.
//! Handles MCP OAuth2 discovery from 401 WWW-Authenticate headers.

mod oauth2;

use async_trait::async_trait;
use headless_mcp_core::{
    BackendDef, BackendError, BackendErrorKind, BackendResult, BackendTransport, InitializeResult,
    McpBackend, OAuth2Config, ToolDescriptor,
};
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

/// Builder for HttpBackend that supports dynamic token updates.
struct ClientBuilder {
    user_agent: &'static str,
    default_timeout: Duration,
}

/// An HTTP-connected MCP backend with optional OAuth2 support.
pub struct HttpBackend {
    def: BackendDef,
    url: String,
    /// Current HTTP client (might be rebuilt with new tokens).
    client: Mutex<reqwest::Client>,
    /// OAuth2 token manager, if configured.
    oauth2: Option<OAuth2TokenManager>,
    /// Static bearer token, if configured.
    static_token: Option<String>,
    initialize_result: Mutex<Option<InitializeResult>>,
    connected: AtomicBool,
    request_counter: AtomicU64,
    default_timeout: Duration,
}

impl HttpBackend {
    /// Creates a new [`HttpBackend`] from its definition.
    pub fn new(def: BackendDef) -> Self {
        let (url, static_token, oauth2_config) = match &def.transport {
            BackendTransport::Http {
                url,
                bearer_token,
                oauth2,
            } => (
                url.clone(),
                bearer_token.clone(),
                oauth2.clone(),
            ),
            _ => panic!("HttpBackend requires an HTTP transport"),
        };

        let default_timeout = Duration::from_secs(def.call_timeout_secs);

        let oauth2 = oauth2_config.map(OAuth2TokenManager::new);

        let client = Self::build_client(&url, static_token.as_deref(), default_timeout);

        Self {
            def,
            url,
            client: Mutex::new(client),
            oauth2,
            static_token,
            initialize_result: Mutex::new(None),
            connected: AtomicBool::new(false),
            request_counter: AtomicU64::new(0),
            default_timeout,
        }
    }

    fn build_client(url: &str, bearer_token: Option<&str>, timeout: Duration) -> reqwest::Client {
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

    /// Rebuild the HTTP client with a new bearer token.
    fn rebuild_client_with_token(&self, token: &str) {
        let mut client = self.client.lock().unwrap();
        *client = Self::build_client(&self.url, Some(token), self.default_timeout);
    }

    async fn post_json(&self, body: &[u8]) -> Result<(Vec<u8>, reqwest::StatusCode), BackendError> {
        // Clone the client inside the lock scope so the guard is dropped before await.
        let client = {
            let guard = self.client.lock().unwrap();
            guard.clone()
        };

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
                if let Some(www_auth) = response.headers().get("www-authenticate") {
                    if let Ok(header_value) = www_auth.to_str() {
                        if let Some(metadata_url) = parse_resource_metadata_url(header_value) {
                            tracing::info!(
                                backend_id = %self.def.id,
                                %metadata_url,
                                "OAuth2 resource metadata discovered; running auto-discovery"
                            );
                            // Run discovery asynchronously (best effort)
                            if let Err(e) = oauth2_mgr.discover(&metadata_url, &self.def.id).await {
                                tracing::warn!(%e, "OAuth2 discovery failed");
                            }
                        }
                    }
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
            // Try OAuth2 token acquisition and retry
            if let Some(ref oauth2_mgr) = self.oauth2 {
                tracing::info!(backend_id = %self.def.id, "attempting OAuth2 token acquisition after 401");
                match oauth2_mgr.get_token(&self.def.id).await {
                    Ok(token) => {
                        self.rebuild_client_with_token(&token);
                        // Retry the request with the new token
                        let (retry_bytes, retry_status) = self.post_json(&body).await?;
                        if retry_status.is_success() {
                            return Self::parse_response(&retry_bytes, &self.def.id);
                        }
                        let body_str = String::from_utf8_lossy(&retry_bytes);
                        return Err(BackendError::new(
                            BackendErrorKind::Auth,
                            format!(
                                "HTTP {} from '{}' after OAuth2: {}",
                                retry_status.as_u16(),
                                self.def.id,
                                body_str
                            ),
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
                format!(
                    "HTTP {} from '{}': {}",
                    status.as_u16(),
                    self.def.id,
                    body_str
                ),
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
            other => Err(BackendError::new(
                BackendErrorKind::Protocol,
                format!(
                    "unexpected response type from '{backend_id}': {:?}",
                    std::mem::discriminant(&other)
                ),
            )),
        }
    }

    async fn send_notification(
        &self,
        method: &str,
        params: Option<Value>,
    ) -> Result<(), BackendError> {
        let notification = JsonRpcMessage::Notification(JsonRpcNotification::new(method, params));

        let body = serde_json::to_vec(&notification).map_err(|e| {
            BackendError::new(BackendErrorKind::Protocol, format!("serialize: {e}"))
        })?;

        let response = {
            let client = self.client.lock().unwrap().clone();
            client
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
                })?
        };

        let status = response.status();
        if !status.is_success() && status.as_u16() != 202 {
            return Err(BackendError::new(
                BackendErrorKind::Protocol,
                format!(
                    "notification to '{}' returned HTTP {}",
                    self.def.id,
                    status.as_u16()
                ),
            ));
        }

        Ok(())
    }
}

#[async_trait]
impl McpBackend for HttpBackend {
    fn backend_id(&self) -> &str {
        &self.def.id
    }

    fn label(&self) -> &str {
        self.def.label.as_deref().unwrap_or(&self.def.id)
    }

    async fn connect(&self) -> BackendResult<InitializeResult> {
        if self.connected.load(Ordering::SeqCst) {
            return self
                .initialize_result
                .lock()
                .unwrap()
                .clone()
                .ok_or_else(|| {
                    BackendError::new(
                        BackendErrorKind::Internal,
                        "connected but no initialize result cached",
                    )
                });
        }

        // Full MCP handshake. `retry: true` enables OAuth2 flow on 401.
        let result = self
            .send_request(
                "initialize",
                Some(serde_json::json!({
                    "protocolVersion": "2024-11-05",
                    "clientInfo": {
                        "name": "headless-mcp",
                        "version": env!("CARGO_PKG_VERSION"),
                    },
                    "capabilities": {},
                })),
                true, // enable OAuth2 retry
            )
            .await?;

        let init_result: InitializeResult = serde_json::from_value(result).map_err(|e| {
            BackendError::new(
                BackendErrorKind::Protocol,
                format!(
                    "failed to parse initialize result from backend '{}': {e}",
                    self.def.id
                ),
            )
        })?;

        self.send_notification("notifications/initialized", None)
            .await?;

        *self.initialize_result.lock().unwrap() = Some(init_result.clone());
        self.connected.store(true, Ordering::SeqCst);

        tracing::info!(
            backend_id = %self.def.id,
            protocol_version = %init_result.protocol_version,
            server_name = %init_result.server_info.name,
            "http backend connected"
        );

        Ok(init_result)
    }

    async fn list_tools(&self) -> BackendResult<Vec<ToolDescriptor>> {
        if !self.connected.load(Ordering::SeqCst) {
            return Err(BackendError::new(
                BackendErrorKind::Connection,
                format!("backend '{}' is not connected", self.def.id),
            ));
        }

        let result = self.send_request("tools/list", None, false).await?;

        let tools_list = result
            .get("tools")
            .and_then(|v| v.as_array())
            .ok_or_else(|| {
                BackendError::new(
                    BackendErrorKind::Protocol,
                    format!(
                        "backend '{}' returned a 'tools/list' response without a 'tools' array",
                        self.def.id
                    ),
                )
            })?;

        tools_list
            .iter()
            .map(|t| {
                serde_json::from_value::<ToolDescriptor>(t.clone()).map_err(|e| {
                    BackendError::new(
                        BackendErrorKind::Protocol,
                        format!(
                            "backend '{}' returned an invalid tool descriptor: {e}",
                            self.def.id
                        ),
                    )
                })
            })
            .collect()
    }

    async fn call_tool(
        &self,
        name: &str,
        arguments: Option<Value>,
        _timeout: Duration,
    ) -> BackendResult<Value> {
        if !self.connected.load(Ordering::SeqCst) {
            return Err(BackendError::new(
                BackendErrorKind::Connection,
                format!("backend '{}' is not connected", self.def.id),
            ));
        }

        let params = serde_json::json!({
            "name": name,
            "arguments": arguments.unwrap_or(Value::Null),
        });

        self.send_request("tools/call", Some(params), false).await
    }

    async fn disconnect(&self) -> BackendResult<()> {
        self.connected.store(false, Ordering::SeqCst);
        tracing::info!(backend_id = %self.def.id, "http backend disconnected");
        Ok(())
    }

    async fn health_check(&self) -> BackendResult<()> {
        if !self.connected.load(Ordering::SeqCst) {
            return Err(BackendError::new(
                BackendErrorKind::Connection,
                format!("backend '{}' is not connected", self.def.id),
            ));
        }

        self.send_request("tools/list", None, false).await?;
        Ok(())
    }

    fn protocol_version(&self) -> Option<&str> {
        None
    }
}
