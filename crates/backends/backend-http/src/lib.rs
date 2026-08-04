#![forbid(unsafe_code)]

//! HTTP-based MCP backend: connect to remote MCP servers over HTTP.
//!
//! This implements [`headless_mcp_core::McpBackend`] for downstream MCP
//! servers that speak the Streamable HTTP transport. It sends JSON-RPC
//! messages via POST and reads JSON-RPC responses.

use async_trait::async_trait;
use headless_mcp_core::{
    BackendDef, BackendError, BackendErrorKind, BackendResult, InitializeResult, McpBackend,
    ToolDescriptor,
};
use headless_mcp_wire::{
    decode_message, JsonRpcId, JsonRpcMessage, JsonRpcNotification, JsonRpcRequest,
};
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use serde_json::Value;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

const APPLICATION_JSON: &str = "application/json";
const SSE_CONTENT_TYPE: &str = "text/event-stream";

/// An HTTP-connected MCP backend.
pub struct HttpBackend {
    def: BackendDef,
    client: reqwest::Client,
    initialize_result: Mutex<Option<InitializeResult>>,
    connected: AtomicBool,
    request_counter: AtomicU64,
}

impl HttpBackend {
    /// Creates a new [`HttpBackend`] from its definition.
    pub fn new(def: BackendDef) -> Self {
        let mut client_builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(def.call_timeout_secs))
            .http1_title_case_headers();

        // Add bearer token if configured
        if let headless_mcp_core::BackendTransport::Http {
            bearer_token, ..
        } = &def.transport
        {
            if let Some(token) = bearer_token {
                let mut headers = reqwest::header::HeaderMap::new();
                if let Ok(value) = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
                {
                    headers.insert(reqwest::header::AUTHORIZATION, value);
                }
                client_builder = client_builder.default_headers(headers);
            }
        }

        Self {
            def,
            client: client_builder.build().expect("reqwest client should build"),
            initialize_result: Mutex::new(None),
            connected: AtomicBool::new(false),
            request_counter: AtomicU64::new(0),
        }
    }

    fn url(&self) -> Result<&str, BackendError> {
        match &self.def.transport {
            headless_mcp_core::BackendTransport::Http { url, .. } => Ok(url.as_str()),
            _ => Err(BackendError::new(
                BackendErrorKind::Connection,
                "HttpBackend requires an HTTP transport",
            )),
        }
    }

    async fn post_json(&self, body: &[u8]) -> Result<Vec<u8>, BackendError> {
        let url = self.url()?;

        let response = self
            .client
            .post(url)
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
        let response_bytes = response.bytes().await.map_err(|e| {
            BackendError::new(
                BackendErrorKind::Protocol,
                format!("failed to read response from '{}': {e}", self.def.id),
            )
        })?;

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

        Ok(response_bytes.to_vec())
    }

    async fn send_request(
        &self,
        method: &str,
        params: Option<Value>,
    ) -> Result<Value, BackendError> {
        let id = self.request_counter.fetch_add(1, Ordering::SeqCst) as i64;
        let request =
            JsonRpcMessage::Request(JsonRpcRequest::new(JsonRpcId::Number(id), method, params));

        let body = serde_json::to_vec(&request).map_err(|e| {
            BackendError::new(BackendErrorKind::Protocol, format!("serialize: {e}"))
        })?;

        let response_bytes = self.post_json(&body).await?;

        // Parse the response
        let message = decode_message(&response_bytes).map_err(|e| {
            BackendError::new(
                BackendErrorKind::Protocol,
                format!("failed to decode response from '{}': {e}", self.def.id),
            )
        })?;

        match message {
            JsonRpcMessage::SuccessResponse(resp) => Ok(resp.result),
            JsonRpcMessage::ErrorResponse(resp) => Err(BackendError::new(
                BackendErrorKind::Protocol,
                format!(
                    "backend '{}' returned error (code {}): {}",
                    self.def.id, resp.error.code, resp.error.message
                ),
            )),
            other => Err(BackendError::new(
                BackendErrorKind::Protocol,
                format!(
                    "unexpected response type from '{}': expected success or error, got {:?}",
                    self.def.id,
                    std::mem::discriminant(&other)
                ),
            )),
        }
    }

    async fn send_notification(&self, method: &str, params: Option<Value>) -> Result<(), BackendError> {
        let notification =
            JsonRpcMessage::Notification(JsonRpcNotification::new(method, params));

        let body = serde_json::to_vec(&notification).map_err(|e| {
            BackendError::new(BackendErrorKind::Protocol, format!("serialize: {e}"))
        })?;

        // For notifications, we don't expect a response body
        // Just check the POST succeeds
        let url = self.url()?;
        let response = self
            .client
            .post(url)
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
        // 202 Accepted is the expected response for notifications
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

        // Full MCP handshake
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
            )
            .await?;

        // Parse InitializeResult
        let init_result: InitializeResult = serde_json::from_value(result).map_err(|e| {
            BackendError::new(
                BackendErrorKind::Protocol,
                format!(
                    "failed to parse initialize result from backend '{}': {e}",
                    self.def.id
                ),
            )
        })?;

        // Send notifications/initialized
        self.send_notification("notifications/initialized", None)
            .await?;

        // Store results
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

        let result = self.send_request("tools/list", None).await?;

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

        self.send_request("tools/call", Some(params)).await
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

        // Health check: send a lightweight tools/list
        self.send_request("tools/list", None).await?;
        Ok(())
    }

    fn protocol_version(&self) -> Option<&str> {
        None
    }
}
