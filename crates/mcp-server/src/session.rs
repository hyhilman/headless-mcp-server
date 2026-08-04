use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use headless_mcp_registry::BackendRegistry;
use headless_mcp_wire::{
    JsonRpcError, JsonRpcErrorResponse, JsonRpcMessage, JsonRpcNotification, JsonRpcRequest,
    JsonRpcSuccessResponse,
};
use serde::Deserialize;
use serde_json::Value;

use crate::audit::{AuditEvent, AuditLogger, AuditOutcome};

/// A placeholder protocol version string.
pub const PROTOCOL_VERSION: &str = "2025-06-18";

/// Default timeout for tools/call routed to a backend.
const DEFAULT_CALL_TIMEOUT_SECS: u64 = 30;

/// Transport-agnostic MCP request/notification dispatch.
///
/// Owns no socket, no auth, no rate limiting — those are transport
/// concerns. This type's only job is: given one decoded
/// [`JsonRpcMessage`], decide what happens and what (if anything) to
/// send back.
pub struct McpSession {
    registry: Arc<BackendRegistry>,
    audit: Arc<dyn AuditLogger>,
    initialized: AtomicBool,
}

impl McpSession {
    pub fn new(registry: Arc<BackendRegistry>, audit: Arc<dyn AuditLogger>) -> Self {
        Self {
            registry,
            audit,
            initialized: AtomicBool::new(false),
        }
    }

    /// Handles one incoming message. Returns `Some` for a request (always
    /// reply, success or error) and `None` for a notification or response.
    pub async fn handle(&self, message: JsonRpcMessage) -> Option<JsonRpcMessage> {
        match message {
            JsonRpcMessage::Request(request) => Some(self.handle_request(request).await),
            JsonRpcMessage::Notification(notification) => {
                self.handle_notification(notification);
                None
            }
            JsonRpcMessage::SuccessResponse(_) | JsonRpcMessage::ErrorResponse(_) => {
                tracing::debug!("ignoring unexpected response-shaped message from client");
                None
            }
        }
    }

    async fn handle_request(&self, request: JsonRpcRequest) -> JsonRpcMessage {
        let method = request.method.clone();
        let (result, tool_name, outcome) = self.dispatch_request(&request).await;

        self.audit
            .record(AuditEvent {
                method,
                tool_name,
                outcome,
            })
            .await;

        match result {
            Ok(value) => {
                JsonRpcMessage::SuccessResponse(JsonRpcSuccessResponse::new(request.id, value))
            }
            Err(error) => {
                JsonRpcMessage::ErrorResponse(JsonRpcErrorResponse::new(Some(request.id), error))
            }
        }
    }

    async fn dispatch_request(
        &self,
        request: &JsonRpcRequest,
    ) -> (Result<Value, JsonRpcError>, Option<String>, AuditOutcome) {
        match request.method.as_str() {
            "initialize" => {
                let result = self.handle_initialize();
                let outcome = AuditOutcome::from_result(&result);
                (result, None, outcome)
            }
            "tools/list" => {
                let result = self.handle_tools_list();
                let outcome = AuditOutcome::from_result(&result);
                (result, None, outcome)
            }
            "tools/call" => self.handle_tools_call(request.params.clone()).await,
            other => {
                let result = Err(JsonRpcError::method_not_found(format!(
                    "unknown method: {other}"
                )));
                let outcome = AuditOutcome::from_result(&result);
                (result, None, outcome)
            }
        }
    }

    fn handle_initialize(&self) -> Result<Value, JsonRpcError> {
        self.initialized.store(true, Ordering::SeqCst);
        Ok(serde_json::json!({
            "protocolVersion": PROTOCOL_VERSION,
            "serverInfo": {
                "name": "headless-mcp",
                "version": env!("CARGO_PKG_VERSION"),
            },
            "capabilities": { "tools": {} },
        }))
    }

    fn require_initialized(&self) -> Result<(), JsonRpcError> {
        if self.initialized.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(JsonRpcError::invalid_request(
                "session is not initialized; call \"initialize\" first",
            ))
        }
    }

    fn handle_tools_list(&self) -> Result<Value, JsonRpcError> {
        self.require_initialized()?;
        let tools = self.registry.aggregated_tools();
        Ok(serde_json::json!({ "tools": tools }))
    }

    async fn handle_tools_call(
        &self,
        params: Option<Value>,
    ) -> (Result<Value, JsonRpcError>, Option<String>, AuditOutcome) {
        if let Err(err) = self.require_initialized() {
            let outcome = AuditOutcome::Error { code: err.code };
            return (Err(err), None, outcome);
        }

        let params = match params.map(serde_json::from_value::<ToolCallParams>) {
            Some(Ok(params)) => params,
            Some(Err(err)) => {
                let error =
                    JsonRpcError::invalid_params(format!("invalid \"tools/call\" params: {err}"));
                let outcome = AuditOutcome::Error { code: error.code };
                return (Err(error), None, outcome);
            }
            None => {
                let error = JsonRpcError::invalid_params("\"tools/call\" requires params");
                let outcome = AuditOutcome::Error { code: error.code };
                return (Err(error), None, outcome);
            }
        };

        let tool_name = params.name.clone();
        let timeout = Duration::from_secs(DEFAULT_CALL_TIMEOUT_SECS);

        match self
            .registry
            .route_call(&params.name, params.arguments, timeout)
            .await
        {
            Ok(value) => {
                let result = make_success_result(value);
                (Ok(result), Some(tool_name), AuditOutcome::Ok)
            }
            Err(err) => {
                let result = make_error_result(err.to_string());
                (Ok(result), Some(tool_name), AuditOutcome::Error { code: -32603 })
            }
        }
    }

    fn handle_notification(&self, notification: JsonRpcNotification) {
        match notification.method.as_str() {
            "notifications/initialized" => {
                tracing::debug!("client acknowledged initialization");
            }
            other => {
                tracing::debug!(method = other, "ignoring unrecognized notification");
            }
        }
    }
}

#[derive(Debug, Deserialize)]
struct ToolCallParams {
    name: String,
    #[serde(default)]
    arguments: Option<Value>,
}

fn make_success_result(value: Value) -> Value {
    let text = serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string());
    serde_json::json!({
        "content": [
            { "type": "text", "text": text }
        ],
        "isError": false,
        "structuredContent": value,
    })
}

fn make_error_result(message: String) -> Value {
    serde_json::json!({
        "content": [
            { "type": "text", "text": message }
        ],
        "isError": true,
    })
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use crate::audit::TracingAuditLogger;
    use headless_mcp_wire::{JsonRpcId, JsonRpcNotification as WireNotification};
    use std::sync::Mutex as StdMutex;

    use super::*;

    #[derive(Default)]
    struct RecordingAudit {
        events: StdMutex<Vec<AuditEvent>>,
    }

    #[async_trait]
    impl AuditLogger for RecordingAudit {
        async fn record(&self, event: AuditEvent) {
            self.events.lock().unwrap().push(event);
        }
    }

    fn request(id: i64, method: &str, params: Option<Value>) -> JsonRpcRequest {
        JsonRpcRequest::new(JsonRpcId::Number(id), method, params)
    }

    #[tokio::test]
    async fn tools_call_before_initialize_is_rejected() {
        let registry = Arc::new(BackendRegistry::new());
        let audit = Arc::new(RecordingAudit::default());
        let session = McpSession::new(registry, audit);

        let reply = session
            .handle(JsonRpcMessage::Request(request(1, "tools/list", None)))
            .await
            .expect("requests always get a reply");

        match reply {
            JsonRpcMessage::ErrorResponse(err) => {
                assert_eq!(err.error.code, JsonRpcError::INVALID_REQUEST);
            }
            other => panic!("expected an error response, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn initialize_then_tools_list_returns_empty_tools() {
        let registry = Arc::new(BackendRegistry::new());
        let audit = Arc::new(TracingAuditLogger);
        let session = McpSession::new(registry, audit);

        session
            .handle(JsonRpcMessage::Request(request(1, "initialize", None)))
            .await;

        let reply = session
            .handle(JsonRpcMessage::Request(request(2, "tools/list", None)))
            .await
            .expect("reply");

        let JsonRpcMessage::SuccessResponse(success) = reply else {
            panic!("expected success response");
        };
        let tools = success.result["tools"].as_array().expect("tools array");
        assert!(tools.is_empty());
    }

    #[tokio::test]
    async fn unknown_method_is_method_not_found() {
        let registry = Arc::new(BackendRegistry::new());
        let audit = Arc::new(TracingAuditLogger);
        let session = McpSession::new(registry, audit);

        session
            .handle(JsonRpcMessage::Request(request(1, "initialize", None)))
            .await;

        let reply = session
            .handle(JsonRpcMessage::Request(request(
                2,
                "nonexistent/method",
                None,
            )))
            .await
            .expect("reply");

        let JsonRpcMessage::ErrorResponse(err) = reply else {
            panic!("expected error response");
        };
        assert_eq!(err.error.code, JsonRpcError::METHOD_NOT_FOUND);
    }

    #[tokio::test]
    async fn notification_never_produces_a_reply() {
        let registry = Arc::new(BackendRegistry::new());
        let audit = Arc::new(TracingAuditLogger);
        let session = McpSession::new(registry, audit);

        let reply = session
            .handle(JsonRpcMessage::Notification(WireNotification::new(
                "notifications/initialized",
                None,
            )))
            .await;
        assert!(reply.is_none());
    }
}
