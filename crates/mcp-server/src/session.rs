use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use headless_mcp_registry::BackendRegistry;
use headless_mcp_wire::{
    JsonRpcError, JsonRpcErrorResponse, JsonRpcMessage, JsonRpcNotification, JsonRpcRequest,
    JsonRpcSuccessResponse,
};
use serde::Deserialize;
use serde_json::Value;

use crate::audit::{AuditEvent, AuditLogger, AuditOutcome};
use crate::protocol::{
    mark_complete, RequestCtx, LEGACY_PROTOCOL_VERSION, META_SERVER_INFO,
    MODERN_PROTOCOL_VERSIONS,
};

/// Version reported to legacy (`initialize`-based) clients.
pub const PROTOCOL_VERSION: &str = LEGACY_PROTOCOL_VERSION;

/// Default timeout for tools/call routed to a backend.
const DEFAULT_CALL_TIMEOUT_SECS: u64 = 30;
/// Timeout for forwarded resources/* and events/* requests.
const FORWARD_TIMEOUT_SECS: u64 = 15;

/// A change that `subscriptions/listen` streams can be told about.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Change {
    ToolsListChanged,
}

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
    pub(crate) changes: tokio::sync::broadcast::Sender<Change>,
    /// Backend serving each resource URI, from the last `resources/list`.
    resource_owners: Mutex<HashMap<String, String>>,
}

impl McpSession {
    pub fn new(registry: Arc<BackendRegistry>, audit: Arc<dyn AuditLogger>) -> Self {
        Self {
            registry,
            audit,
            initialized: AtomicBool::new(false),
            changes: tokio::sync::broadcast::channel(64).0,
            resource_owners: Mutex::new(HashMap::new()),
        }
    }

    /// Tell `subscriptions/listen` streams that the tool list changed
    /// (e.g. a backend reconnected).
    pub fn notify_tools_list_changed(&self) {
        let _ = self.changes.send(Change::ToolsListChanged);
    }

    /// Handles one incoming message. Returns `Some` for a request (always
    /// reply, success or error) and `None` for a notification or response.
    ///
    /// `subscriptions/listen` needs a streaming transport; use
    /// [`McpSession::handle_streaming`] for that.
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

    pub(crate) async fn handle_request(&self, request: JsonRpcRequest) -> JsonRpcMessage {
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
        let ctx = RequestCtx::from_params(request.params.as_ref());
        if let Err(err) = ctx.check_version() {
            let outcome = AuditOutcome::Error { code: err.code };
            return (Err(err), None, outcome);
        }
        let params = request.params.as_ref();

        let (mut result, tool_name, outcome) = match request.method.as_str() {
            "server/discover" => self.simple(Ok(self.handle_discover())),
            "initialize" if !ctx.is_modern() => self.simple(self.handle_initialize()),
            "tools/list" => self.simple(self.handle_tools_list(&ctx)),
            "tools/call" => self.handle_tools_call(request.params.clone(), &ctx).await,
            "resources/list" => self.simple(self.handle_resources_list(&ctx).await),
            "resources/read" => self.simple(self.handle_resources_read(params, &ctx).await),
            "events/list" => self.simple(self.handle_events_list(&ctx).await),
            "events/subscribe" | "events/unsubscribe" => {
                self.simple(self.forward_event_request(&request.method, params, &ctx).await)
            }
            "subscriptions/listen" => self.simple(Err(JsonRpcError::invalid_request(
                "subscriptions/listen needs a streaming transport",
            ))),
            other => self.simple(Err(JsonRpcError::method_not_found(format!(
                "unknown method: {other}"
            )))),
        };
        if ctx.is_modern() {
            if let Ok(value) = &mut result {
                mark_complete(value);
            }
        }
        (result, tool_name, outcome)
    }

    fn simple(
        &self,
        result: Result<Value, JsonRpcError>,
    ) -> (Result<Value, JsonRpcError>, Option<String>, AuditOutcome) {
        let outcome = AuditOutcome::from_result(&result);
        (result, None, outcome)
    }

    fn capabilities(&self) -> Value {
        let mut caps = serde_json::json!({ "tools": { "listChanged": true } });
        if !self.registry.backends_with("resources").is_empty() {
            caps["resources"] = serde_json::json!({ "subscribe": false, "listChanged": false });
        }
        if !self.registry.backends_with("events").is_empty() {
            caps["events"] = serde_json::json!({});
        }
        caps
    }

    fn handle_discover(&self) -> Value {
        serde_json::json!({
            "supportedVersions": MODERN_PROTOCOL_VERSIONS,
            "capabilities": self.capabilities(),
            "_meta": {
                META_SERVER_INFO: {
                    "name": "headless-mcp",
                    "version": env!("CARGO_PKG_VERSION"),
                },
            },
        })
    }

    fn handle_initialize(&self) -> Result<Value, JsonRpcError> {
        self.initialized.store(true, Ordering::SeqCst);
        Ok(serde_json::json!({
            "protocolVersion": PROTOCOL_VERSION,
            "serverInfo": {
                "name": "headless-mcp",
                "version": env!("CARGO_PKG_VERSION"),
            },
            "capabilities": self.capabilities(),
        }))
    }

    /// Legacy requests need `initialize` first; modern requests are stateless.
    pub(crate) fn require_initialized(&self, ctx: &RequestCtx) -> Result<(), JsonRpcError> {
        if ctx.is_modern() || self.initialized.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(JsonRpcError::invalid_request(
                "session is not initialized; call \"initialize\" first",
            ))
        }
    }

    fn handle_tools_list(&self, ctx: &RequestCtx) -> Result<Value, JsonRpcError> {
        self.require_initialized(ctx)?;
        let tools = serde_json::to_value(self.registry.aggregated_tools())
            .unwrap_or_else(|_| Value::Array(Vec::new()));
        Ok(serde_json::json!({ "tools": tools }))
    }

    async fn handle_tools_call(
        &self,
        params: Option<Value>,
        ctx: &RequestCtx,
    ) -> (Result<Value, JsonRpcError>, Option<String>, AuditOutcome) {
        if let Err(err) = self.require_initialized(ctx) {
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
        let backend = self.registry.backend_of_tool(&params.name);

        // A backend that was unreachable (e.g. behind a VPN that needed a
        // login) has no indexed tools: try to bring it back first.
        if let Some(id) = backend.as_deref() {
            if !self.registry.has_tool(&params.name) && !self.registry.is_healthy(id) {
                match self.registry.reconnect_backend(id).await {
                    Ok(()) => {
                        tracing::info!(backend = %id, "backend reconnected on call");
                        self.notify_tools_list_changed();
                    }
                    Err(e) => tracing::debug!(backend = %id, %e, "reconnect on call failed"),
                }
            }
        }

        let mut extra = serde_json::Map::new();
        let forward_meta = backend
            .as_deref()
            .is_some_and(|id| self.registry.forwards_request_meta(id));
        if ctx.is_modern() && forward_meta {
            for (key, value) in [
                ("_meta", params.meta),
                ("requestState", params.request_state.map(Value::String)),
                ("inputResponses", params.input_responses),
            ] {
                if let Some(value) = value {
                    extra.insert(key.into(), value);
                }
            }
        }

        match self
            .registry
            .route_call_with(&params.name, params.arguments, extra, timeout)
            .await
        {
            Ok(value) => {
                let outcome = if value.get("isError") == Some(&Value::Bool(true)) {
                    AuditOutcome::Error { code: -32603 }
                } else {
                    AuditOutcome::Ok
                };
                (Ok(tool_result(value)), Some(tool_name), outcome)
            }
            Err(err) => {
                let mut message = err.to_string();
                let hint = backend
                    .as_deref()
                    .and_then(|id| self.registry.unavailable_hint(id));
                if let Some(hint) = hint {
                    message.push('\n');
                    message.push_str(&hint);
                }
                let result = make_error_result(message);
                (Ok(result), Some(tool_name), AuditOutcome::Error { code: -32603 })
            }
        }
    }

    // ── resources (forwarded) ──────────────────────────────────────────

    async fn handle_resources_list(&self, ctx: &RequestCtx) -> Result<Value, JsonRpcError> {
        self.require_initialized(ctx)?;
        let timeout = Duration::from_secs(FORWARD_TIMEOUT_SECS);
        let mut all = Vec::new();
        let mut owners = HashMap::new();
        for id in self.registry.backends_with("resources") {
            match self
                .registry
                .backend_request(&id, "resources/list", None, timeout)
                .await
            {
                Ok(result) => {
                    let resources = result.get("resources").and_then(Value::as_array);
                    for resource in resources.into_iter().flatten() {
                        if let Some(uri) = resource.get("uri").and_then(Value::as_str) {
                            owners.entry(uri.to_string()).or_insert_with(|| id.clone());
                            all.push(resource.clone());
                        }
                    }
                }
                Err(e) => tracing::warn!(backend = %id, %e, "resources/list failed"),
            }
        }
        *self.resource_owners.lock().unwrap() = owners;
        Ok(serde_json::json!({ "resources": all }))
    }

    async fn handle_resources_read(
        &self,
        params: Option<&Value>,
        ctx: &RequestCtx,
    ) -> Result<Value, JsonRpcError> {
        self.require_initialized(ctx)?;
        let uri = params
            .and_then(|p| p.get("uri"))
            .and_then(Value::as_str)
            .ok_or_else(|| JsonRpcError::invalid_params("resources/read requires 'uri'"))?;
        let mut owner = self.resource_owners.lock().unwrap().get(uri).cloned();
        if owner.is_none() {
            self.handle_resources_list(ctx).await?;
            owner = self.resource_owners.lock().unwrap().get(uri).cloned();
        }
        let owner = owner
            .ok_or_else(|| JsonRpcError::invalid_params(format!("resource not found: {uri}")))?;
        self.registry
            .backend_request(
                &owner,
                "resources/read",
                Some(serde_json::json!({ "uri": uri })),
                Duration::from_secs(FORWARD_TIMEOUT_SECS),
            )
            .await
            .map_err(|e| JsonRpcError::internal_error(e.to_string()))
    }

    // ── events (forwarded) ─────────────────────────────────────────────

    /// `events/list` from every backend with events; names get the
    /// backend's namespace prefix (`<namespace>.<event>`).
    async fn handle_events_list(&self, ctx: &RequestCtx) -> Result<Value, JsonRpcError> {
        self.require_initialized(ctx)?;
        let timeout = Duration::from_secs(FORWARD_TIMEOUT_SECS);
        let mut all = Vec::new();
        for id in self.registry.backends_with("events") {
            match self
                .registry
                .backend_request(&id, "events/list", None, timeout)
                .await
            {
                Ok(result) => {
                    let events = result.get("events").and_then(Value::as_array);
                    for event in events.into_iter().flatten() {
                        let mut event = event.clone();
                        if let Some(name) = event.get("name").and_then(Value::as_str) {
                            event["name"] = Value::String(self.exposed_event_name(&id, name));
                        }
                        all.push(event);
                    }
                }
                Err(e) => tracing::warn!(backend = %id, %e, "events/list failed"),
            }
        }
        Ok(serde_json::json!({ "events": all }))
    }

    fn exposed_event_name(&self, backend: &str, name: &str) -> String {
        match self.registry.namespace(backend) {
            Some(ns) => format!("{ns}.{name}"),
            None => name.to_string(),
        }
    }

    /// Route `events/subscribe` / `events/unsubscribe` to the backend that
    /// owns the event. The backend delivers webhooks to the subscriber
    /// directly.
    async fn forward_event_request(
        &self,
        method: &str,
        params: Option<&Value>,
        ctx: &RequestCtx,
    ) -> Result<Value, JsonRpcError> {
        self.require_initialized(ctx)?;
        let mut params = params
            .cloned()
            .ok_or_else(|| JsonRpcError::invalid_params("missing params"))?;
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| JsonRpcError::invalid_params("'name' is required"))?
            .to_string();
        let (backend, original) = self
            .registry
            .backends_with("events")
            .into_iter()
            .find_map(|id| {
                let original = match self.registry.namespace(&id) {
                    Some(ns) => name.strip_prefix(&format!("{ns}."))?.to_string(),
                    None => name.clone(),
                };
                Some((id, original))
            })
            .ok_or_else(|| JsonRpcError::invalid_params(format!("unknown event '{name}'")))?;
        params["name"] = Value::String(original);
        self.registry
            .backend_request(
                &backend,
                method,
                Some(params),
                Duration::from_secs(FORWARD_TIMEOUT_SECS),
            )
            .await
            .map_err(|e| JsonRpcError::internal_error(e.to_string()))
    }

    pub(crate) fn handle_notification(&self, notification: JsonRpcNotification) {
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
    #[serde(default, rename = "_meta")]
    meta: Option<Value>,
    /// Multi round-trip retry: echoed `requestState`.
    #[serde(default, rename = "requestState")]
    request_state: Option<String>,
    /// Multi round-trip retry: answers to the backend's `inputRequests`.
    #[serde(default, rename = "inputResponses")]
    input_responses: Option<Value>,
}

/// A backend's `CallToolResult` (or `input_required`) is passed through as
/// is; anything else is wrapped as text + structured content.
fn tool_result(value: Value) -> Value {
    let is_call_result = value.get("content").is_some_and(Value::is_array)
        || value.get("resultType").and_then(Value::as_str) == Some("input_required");
    if is_call_result {
        return value;
    }
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
    use headless_mcp_core::{
        BackendDef, BackendResult, BackendTransport, ConnectionMode, InitializeResult, McpBackend,
        ResourcesCapability, ServerCapabilities, ServerInfo, StderrMode, ToolDescriptor,
    };
    use headless_mcp_wire::{JsonRpcId, JsonRpcNotification as WireNotification};

    use super::*;

    fn request(id: i64, method: &str, params: Option<Value>) -> JsonRpcMessage {
        JsonRpcMessage::Request(JsonRpcRequest::new(JsonRpcId::Number(id), method, params))
    }

    fn empty_session() -> McpSession {
        McpSession::new(Arc::new(BackendRegistry::new()), Arc::new(TracingAuditLogger))
    }

    async fn ok(session: &McpSession, message: JsonRpcMessage) -> Value {
        match session.handle(message).await {
            Some(JsonRpcMessage::SuccessResponse(r)) => r.result,
            other => panic!("expected success, got {other:?}"),
        }
    }

    async fn err(session: &McpSession, message: JsonRpcMessage) -> JsonRpcError {
        match session.handle(message).await {
            Some(JsonRpcMessage::ErrorResponse(r)) => r.error,
            other => panic!("expected error, got {other:?}"),
        }
    }

    fn modern(extra: Value) -> Value {
        let mut params = serde_json::json!({
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": { "elicitation": { "url": {} } }
            }
        });
        if let (Value::Object(p), Value::Object(e)) = (&mut params, extra) {
            p.extend(e);
        }
        params
    }

    #[tokio::test]
    async fn legacy_requests_need_initialize() {
        let session = empty_session();
        let e = err(&session, request(1, "tools/list", None)).await;
        assert_eq!(e.code, JsonRpcError::INVALID_REQUEST);
        ok(&session, request(2, "initialize", None)).await;
        let r = ok(&session, request(3, "tools/list", None)).await;
        assert!(r["tools"].as_array().unwrap().is_empty());
        let e = err(&session, request(4, "nonexistent/method", None)).await;
        assert_eq!(e.code, JsonRpcError::METHOD_NOT_FOUND);
    }

    #[tokio::test]
    async fn discover_and_stateless_modern_requests() {
        let session = empty_session();
        let r = ok(&session, request(1, "server/discover", Some(modern(serde_json::json!({}))))).await;
        assert_eq!(r["supportedVersions"], serde_json::json!(["2026-07-28"]));
        assert_eq!(r["resultType"], "complete");
        assert!(r["_meta"]["io.modelcontextprotocol/serverInfo"]["name"].is_string());

        let r = ok(&session, request(2, "tools/list", Some(modern(serde_json::json!({}))))).await;
        assert_eq!(r["resultType"], "complete");

        let params = serde_json::json!({ "_meta": { "io.modelcontextprotocol/protocolVersion": "1900-01-01" } });
        let e = err(&session, request(3, "tools/list", Some(params))).await;
        assert_eq!(e.code, crate::protocol::UNSUPPORTED_PROTOCOL_VERSION);
        assert_eq!(e.data.unwrap()["supported"], serde_json::json!(["2026-07-28"]));
    }

    #[tokio::test]
    async fn notification_never_produces_a_reply() {
        let session = empty_session();
        let n = JsonRpcMessage::Notification(WireNotification::new("notifications/initialized", None));
        assert!(session.handle(n).await.is_none());
    }

    // ── forwarding ─────────────────────────────────────────────────────

    /// A backend with one tool, one resource and one event. `tools/call`
    /// with `_meta` answers `input_required` unless `requestState` is set.
    struct FakeBackend;

    #[async_trait]
    impl McpBackend for FakeBackend {
        fn backend_id(&self) -> &str { "cli" }
        fn label(&self) -> &str { "cli" }
        async fn connect(&self) -> BackendResult<InitializeResult> {
            Ok(InitializeResult {
                protocol_version: "2025-06-18".into(),
                server_info: ServerInfo { name: "mcp-cli".into(), version: "1".into() },
                capabilities: ServerCapabilities {
                    tools: None,
                    resources: Some(ResourcesCapability { subscribe: true, list_changed: false }),
                    prompts: None,
                    events: Some(serde_json::json!({})),
                },
            })
        }
        async fn list_tools(&self) -> BackendResult<Vec<ToolDescriptor>> {
            Ok(vec![ToolDescriptor {
                name: "peers".into(),
                description: "peers".into(),
                input_schema: serde_json::json!({ "type": "object" }),
            }])
        }
        async fn call_tool(&self, _: &str, _: Option<Value>, _: Duration) -> BackendResult<Value> {
            Ok(serde_json::json!({ "content": [{ "type": "text", "text": "LOGIN_REQUIRED" }], "isError": true }))
        }
        async fn request(&self, method: &str, params: Option<Value>, _: Duration) -> BackendResult<Value> {
            let params = params.unwrap_or_default();
            Ok(match method {
                "tools/call" if params.get("requestState").is_some() => {
                    serde_json::json!({ "content": [{ "type": "text", "text": "peer-a" }], "isError": false })
                }
                "tools/call" => serde_json::json!({
                    "resultType": "input_required",
                    "inputRequests": { "login": { "method": "elicitation/create",
                        "params": { "mode": "url", "url": "https://idp.example/d", "message": "sign in" } } },
                    "requestState": "opaque",
                    "echo": params,
                }),
                "resources/list" => serde_json::json!({ "resources": [{ "uri": "cli://netbird/state", "name": "netbird" }] }),
                "resources/read" => serde_json::json!({ "contents": [{ "uri": params["uri"], "text": "ready" }] }),
                "events/list" => serde_json::json!({ "events": [{ "name": "cli.state_changed" }] }),
                "events/subscribe" => serde_json::json!({ "id": "sub_1", "name": params["name"] }),
                other => serde_json::json!({ "unexpected": other }),
            })
        }
        async fn disconnect(&self) -> BackendResult<()> { Ok(()) }
        async fn health_check(&self) -> BackendResult<()> { Ok(()) }
    }

    async fn forwarding_session(forward_request_meta: bool) -> McpSession {
        let registry = Arc::new(BackendRegistry::new());
        let def = BackendDef {
            id: "cli".into(),
            label: None,
            transport: BackendTransport::Stdio {
                command: "unused".into(),
                args: vec![],
                env: std::collections::HashMap::new(),
                cwd: None,
            },
            namespace: Some("vpn".into()),
            connection_mode: ConnectionMode::Eager,
            connect_timeout_secs: 5,
            call_timeout_secs: 5,
            stderr_mode: StderrMode::Silent,
            tools_allow: vec![],
            tools_deny: vec![],
            unavailable_hint: None,
            forward_request_meta,
            pin_args: serde_json::Map::new(),
            deny_args: vec![],
        };
        registry.register(def, Arc::new(FakeBackend)).await.unwrap();
        registry.connect_all().await;
        let session = McpSession::new(registry, Arc::new(TracingAuditLogger));
        ok(&session, request(1, "initialize", None)).await;
        session
    }

    #[tokio::test]
    async fn backend_call_results_pass_through() {
        let session = forwarding_session(false).await;
        let params = serde_json::json!({ "name": "vpn.peers" });
        let r = ok(&session, request(2, "tools/call", Some(params))).await;
        assert_eq!(r["isError"], true, "{r}");
        assert_eq!(r["content"][0]["text"], "LOGIN_REQUIRED");
    }

    #[tokio::test]
    async fn login_prompt_round_trips_through_backend() {
        let session = forwarding_session(true).await;
        let first = ok(&session, request(2, "tools/call", Some(modern(serde_json::json!({ "name": "vpn.peers" }))))).await;
        assert_eq!(first["resultType"], "input_required", "{first}");
        assert_eq!(first["inputRequests"]["login"]["params"]["url"], "https://idp.example/d");
        // The backend saw the client's protocol metadata and the downstream tool name.
        assert_eq!(first["echo"]["name"], "peers");
        assert_eq!(first["echo"]["_meta"]["io.modelcontextprotocol/protocolVersion"], "2026-07-28");

        let retry = modern(serde_json::json!({
            "name": "vpn.peers", "requestState": "opaque",
            "inputResponses": { "login": { "action": "accept" } }
        }));
        let done = ok(&session, request(3, "tools/call", Some(retry))).await;
        assert_eq!(done["content"][0]["text"], "peer-a", "{done}");
        assert_eq!(done["resultType"], "complete");

        // Legacy clients never get `input_required`.
        let legacy = ok(&session, request(4, "tools/call", Some(serde_json::json!({ "name": "vpn.peers" })))).await;
        assert_eq!(legacy["content"][0]["text"], "LOGIN_REQUIRED");
    }

    #[tokio::test]
    async fn resources_are_forwarded() {
        let session = forwarding_session(false).await;
        let r = ok(&session, request(2, "initialize", None)).await;
        assert!(r["capabilities"]["resources"].is_object());
        let r = ok(&session, request(3, "resources/list", None)).await;
        assert_eq!(r["resources"][0]["uri"], "cli://netbird/state");
        let r = ok(&session, request(4, "resources/read", Some(serde_json::json!({ "uri": "cli://netbird/state" })))).await;
        assert_eq!(r["contents"][0]["text"], "ready");
        let e = err(&session, request(5, "resources/read", Some(serde_json::json!({ "uri": "cli://other" })))).await;
        assert_eq!(e.code, JsonRpcError::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn events_are_namespaced_and_routed() {
        let session = forwarding_session(false).await;
        let r = ok(&session, request(2, "events/list", None)).await;
        assert_eq!(r["events"][0]["name"], "vpn.cli.state_changed");
        let params = serde_json::json!({ "name": "vpn.cli.state_changed", "delivery": { "mode": "webhook" } });
        let r = ok(&session, request(3, "events/subscribe", Some(params))).await;
        assert_eq!(r["id"], "sub_1");
        assert_eq!(r["name"], "cli.state_changed");
        let params = serde_json::json!({ "name": "other.event" });
        let e = err(&session, request(4, "events/subscribe", Some(params))).await;
        assert_eq!(e.code, JsonRpcError::INVALID_PARAMS);
    }
}
