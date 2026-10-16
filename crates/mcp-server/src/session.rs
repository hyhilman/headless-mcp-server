use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use headless_mcp_registry::BackendRegistry;
use headless_mcp_vpn::VpnManager;
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

/// Guidance for the model, sent in `initialize` / `server/discover`.
const INSTRUCTIONS: &str = "headless-mcp aggregates several MCP servers; tool names are \
prefixed with their backend namespace. Some backends need a VPN or SSO login. If a tool \
returns VPN_REQUIRED, do not retry blindly: follow the instructions in the error (get the \
login link with hub.vpn_login, show it to the user, wait until hub.vpn_status reports \
'connected', then retry). Never open, fetch, or forward login links yourself.";

/// Default timeout for tools/call routed to a backend.
const DEFAULT_CALL_TIMEOUT_SECS: u64 = 30;

/// A change that `subscriptions/listen` streams can be told about.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Change {
    ToolsListChanged,
    ResourceUpdated(String),
}

/// Transport-agnostic MCP request/notification dispatch.
///
/// Owns no socket, no auth, no rate limiting — those are transport
/// concerns. This type's only job is: given one decoded
/// [`JsonRpcMessage`], decide what happens and what (if anything) to
/// send back.
pub struct McpSession {
    pub(crate) registry: Arc<BackendRegistry>,
    audit: Arc<dyn AuditLogger>,
    initialized: AtomicBool,
    pub(crate) vpn: Option<Arc<VpnManager>>,
    /// VPN names this session exposes through the `hub.vpn_*` tools.
    pub(crate) vpn_tools: Vec<String>,
    pub(crate) changes: tokio::sync::broadcast::Sender<Change>,
    pub(crate) state_signer: crate::request_state::StateSigner,
    /// How long a retried call waits for a VPN login to finish.
    pub(crate) login_wait: Duration,
    events: Option<Arc<headless_mcp_events::EventHub>>,
}

impl McpSession {
    pub fn new(registry: Arc<BackendRegistry>, audit: Arc<dyn AuditLogger>) -> Self {
        Self {
            registry,
            audit,
            initialized: AtomicBool::new(false),
            vpn: None,
            vpn_tools: Vec::new(),
            changes: tokio::sync::broadcast::channel(64).0,
            state_signer: crate::request_state::StateSigner::new(),
            login_wait: Duration::from_secs(20),
            events: None,
        }
    }

    /// Serve MCP Events (`events/list`, `events/subscribe`, `events/unsubscribe`).
    pub fn with_events(mut self, hub: Arc<headless_mcp_events::EventHub>) -> Self {
        self.events = Some(hub);
        self
    }

    /// How long a retried call waits for a pending VPN login to finish.
    pub fn with_login_wait(mut self, wait: Duration) -> Self {
        self.login_wait = wait;
        self
    }

    /// VPN names exposed through this session's `hub.vpn_*` tools.
    pub fn exposed_vpns(&self) -> &[String] {
        &self.vpn_tools
    }

    /// Tell `subscriptions/listen` streams that the tool list changed
    /// (e.g. a backend reconnected).
    pub fn notify_tools_list_changed(&self) {
        let _ = self.changes.send(Change::ToolsListChanged);
    }

    /// Attach the VPN manager. Calls to backends that require a VPN are
    /// gated on its state; `exposed` lists the VPNs this session may check
    /// and log in to via `hub.vpn_status` / `hub.vpn_login`.
    pub fn with_vpn(mut self, manager: Arc<VpnManager>, exposed: Vec<String>) -> Self {
        self.vpn_tools = exposed
            .into_iter()
            .filter(|name| manager.status(name).is_some())
            .collect();
        self.vpn_tools.sort();
        self.forward_vpn_changes(&manager);
        self.vpn = Some(manager);
        self
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

        let (mut result, tool_name, outcome) = match request.method.as_str() {
            "server/discover" => self.simple(Ok(self.handle_discover())),
            "initialize" if !ctx.is_modern() => self.simple(self.handle_initialize()),
            "tools/list" => self.simple(self.handle_tools_list(&ctx)),
            "tools/call" => self.handle_tools_call(request.params.clone(), &ctx).await,
            "resources/list" => self.simple(self.handle_resources_list(&ctx)),
            "resources/read" => self.simple(self.handle_resources_read(request.params.as_ref(), &ctx)),
            "events/list" | "events/subscribe" | "events/unsubscribe" if self.events.is_some() => {
                self.simple(self.handle_events(&request.method, request.params.as_ref(), &ctx).await)
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
        if !self.vpn_tools.is_empty() {
            caps["resources"] = serde_json::json!({ "subscribe": true, "listChanged": false });
        }
        if self.events.is_some() {
            caps["events"] = serde_json::json!({});
        }
        caps
    }

    async fn handle_events(
        &self,
        method: &str,
        params: Option<&Value>,
        ctx: &RequestCtx,
    ) -> Result<Value, JsonRpcError> {
        self.require_initialized(ctx)?;
        let hub = self.events.as_ref().ok_or_else(|| JsonRpcError::method_not_found(method))?;
        match method {
            "events/list" => Ok(hub.list()),
            "events/subscribe" => hub.subscribe(params).await,
            _ => hub.unsubscribe(params),
        }
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
            "instructions": INSTRUCTIONS,
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
            "instructions": INSTRUCTIONS,
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
        let mut tools = serde_json::to_value(self.registry.aggregated_tools())
            .unwrap_or_else(|_| Value::Array(Vec::new()));
        if let Value::Array(list) = &mut tools {
            list.extend(self.hub_tool_descriptors());
        }
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

        if let Some(result) = self.call_hub_tool(&params).await {
            let outcome = match &result {
                Ok(_) => AuditOutcome::Ok,
                Err(_) => AuditOutcome::Error { code: -32603 },
            };
            let value = result.unwrap_or_else(make_error_result);
            return (Ok(value), Some(tool_name), outcome);
        }

        if let Some(block) = self.vpn_block(&params.name) {
            if let Some(result) = self.vpn_login_round_trip(&params, &block, ctx).await {
                return (Ok(result), Some(tool_name), AuditOutcome::Error { code: -32603 });
            }
        }

        let known = self.registry.has_tool(&params.name);
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
                let mut message = err.to_string();
                if !known {
                    if let Some(hint) = self.vpn_hint() {
                        message.push_str("\n");
                        message.push_str(&hint);
                    }
                }
                let result = make_error_result(message);
                (Ok(result), Some(tool_name), AuditOutcome::Error { code: -32603 })
            }
        }
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
pub(crate) struct ToolCallParams {
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) arguments: Option<Value>,
    /// Multi round-trip retry: echoed `requestState`.
    #[serde(default, rename = "requestState")]
    pub(crate) request_state: Option<String>,
    /// Multi round-trip retry: answers to our `inputRequests`.
    #[serde(default, rename = "inputResponses")]
    pub(crate) input_responses: Option<Value>,
}

pub(crate) fn make_success_result(value: Value) -> Value {
    let text = serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string());
    serde_json::json!({
        "content": [
            { "type": "text", "text": text }
        ],
        "isError": false,
        "structuredContent": value,
    })
}

pub(crate) fn make_text_result(text: String, structured: Value) -> Value {
    serde_json::json!({
        "content": [
            { "type": "text", "text": text }
        ],
        "isError": false,
        "structuredContent": structured,
    })
}

pub(crate) fn make_error_result(message: String) -> Value {
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

    // ── 2026-07-28 protocol ────────────────────────────────────────────

    fn modern_params(extra: Value) -> Value {
        let mut params = serde_json::json!({
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {}
            }
        });
        if let (Value::Object(p), Value::Object(e)) = (&mut params, extra) {
            p.extend(e);
        }
        params
    }

    #[tokio::test]
    async fn discover_lists_modern_version() {
        let session = McpSession::new(Arc::new(BackendRegistry::new()), Arc::new(TracingAuditLogger));
        let reply = session
            .handle(JsonRpcMessage::Request(request(1, "server/discover", Some(modern_params(serde_json::json!({}))))))
            .await
            .unwrap();
        let JsonRpcMessage::SuccessResponse(ok) = reply else { panic!("{reply:?}") };
        assert_eq!(ok.result["supportedVersions"], serde_json::json!(["2026-07-28"]));
        assert_eq!(ok.result["resultType"], "complete");
        assert!(ok.result["_meta"]["io.modelcontextprotocol/serverInfo"]["name"].is_string());
    }

    #[tokio::test]
    async fn modern_requests_need_no_initialize() {
        let session = McpSession::new(Arc::new(BackendRegistry::new()), Arc::new(TracingAuditLogger));
        let reply = session
            .handle(JsonRpcMessage::Request(request(1, "tools/list", Some(modern_params(serde_json::json!({}))))))
            .await
            .unwrap();
        let JsonRpcMessage::SuccessResponse(ok) = reply else { panic!("{reply:?}") };
        assert_eq!(ok.result["resultType"], "complete");
    }

    #[tokio::test]
    async fn unknown_modern_version_is_rejected_with_supported_list() {
        let session = McpSession::new(Arc::new(BackendRegistry::new()), Arc::new(TracingAuditLogger));
        let params = serde_json::json!({ "_meta": { "io.modelcontextprotocol/protocolVersion": "1900-01-01" } });
        let reply = session
            .handle(JsonRpcMessage::Request(request(1, "tools/list", Some(params))))
            .await
            .unwrap();
        let JsonRpcMessage::ErrorResponse(err) = reply else { panic!("{reply:?}") };
        assert_eq!(err.error.code, crate::protocol::UNSUPPORTED_PROTOCOL_VERSION);
        assert_eq!(err.error.data.unwrap()["supported"], serde_json::json!(["2026-07-28"]));
    }

    // ── VPN ────────────────────────────────────────────────────────────

    use headless_mcp_core::{
        BackendDef, BackendResult, BackendTransport, ConnectionMode, InitializeResult,
        McpBackend, ServerCapabilities, ServerInfo, StderrMode, ToolDescriptor,
    };
    use crate::vpn_tools::{VPN_LOGIN_TOOL, VPN_STATUS_TOOL};
    use headless_mcp_vpn::VpnDef;
    use std::collections::HashMap;

    struct EchoBackend;

    #[async_trait]
    impl McpBackend for EchoBackend {
        fn backend_id(&self) -> &str { "internal" }
        fn label(&self) -> &str { "internal" }
        async fn connect(&self) -> BackendResult<InitializeResult> {
            Ok(InitializeResult {
                protocol_version: "2025-06-18".into(),
                server_info: ServerInfo { name: "internal".into(), version: "1".into() },
                capabilities: ServerCapabilities { tools: None, resources: None, prompts: None },
            })
        }
        async fn list_tools(&self) -> BackendResult<Vec<ToolDescriptor>> {
            Ok(vec![ToolDescriptor {
                name: "query".into(),
                description: "query".into(),
                input_schema: serde_json::json!({"type": "object"}),
            }])
        }
        async fn call_tool(&self, _: &str, _: Option<Value>, _: Duration) -> BackendResult<Value> {
            Ok(serde_json::json!({"ok": true}))
        }
        async fn disconnect(&self) -> BackendResult<()> { Ok(()) }
        async fn health_check(&self) -> BackendResult<()> { Ok(()) }
    }

    fn vpn_def(health: &str) -> VpnDef {
        VpnDef {
            name: "netbird".into(),
            health: vec!["sh".into(), "-c".into(), health.into()],
            healthy_if: vec![],
            needs_login_if: vec!["NeedsLogin".into()],
            expiry: None,
            login: vec!["true".into()],
            url_prefixes: vec!["https://".into()],
            check_interval_secs: 60,
            command_timeout_secs: 5,
            url_wait_secs: 5,
            login_timeout_secs: 5,
            callback_ports: vec![],
        }
    }

    async fn vpn_session(health: &str, expose: bool) -> (McpSession, Arc<VpnManager>) {
        vpn_session_with(vpn_def(health), expose).await
    }

    async fn vpn_session_with(vpn_def: VpnDef, expose: bool) -> (McpSession, Arc<VpnManager>) {
        let registry = Arc::new(BackendRegistry::new());
        let def = BackendDef {
            id: "internal".into(),
            label: None,
            transport: BackendTransport::Stdio {
                command: "unused".into(),
                args: vec![],
                env: HashMap::new(),
                cwd: None,
            },
            namespace: Some("internal".into()),
            connection_mode: ConnectionMode::Eager,
            connect_timeout_secs: 5,
            call_timeout_secs: 5,
            stderr_mode: StderrMode::Silent,
            tools_allow: vec![],
            tools_deny: vec![],
            requires_vpn: vec!["netbird".into()],
            pin_args: serde_json::Map::new(),
            deny_args: vec![],
        };
        registry.register(def, Arc::new(EchoBackend)).await.unwrap();
        registry.connect_all().await;

        let vpn = VpnManager::new(vec![vpn_def]);
        let exposed = if expose { vpn.names() } else { vec![] };
        let session = McpSession::new(registry, Arc::new(TracingAuditLogger))
            .with_vpn(vpn.clone(), exposed)
            .with_login_wait(Duration::from_secs(5));
        session
            .handle(JsonRpcMessage::Request(request(1, "initialize", None)))
            .await;
        (session, vpn)
    }

    async fn call(session: &McpSession, name: &str, args: Value) -> Value {
        let params = serde_json::json!({ "name": name, "arguments": args });
        let reply = session
            .handle(JsonRpcMessage::Request(request(9, "tools/call", Some(params))))
            .await
            .expect("reply");
        let JsonRpcMessage::SuccessResponse(success) = reply else {
            panic!("expected success response");
        };
        success.result
    }

    #[tokio::test]
    async fn vpn_tools_listed_only_when_exposed() {
        for (expose, expected) in [(true, true), (false, false)] {
            let (session, _) = vpn_session("true", expose).await;
            let reply = session
                .handle(JsonRpcMessage::Request(request(2, "tools/list", None)))
                .await
                .unwrap();
            let JsonRpcMessage::SuccessResponse(success) = reply else { panic!() };
            let names: Vec<String> = success.result["tools"]
                .as_array()
                .unwrap()
                .iter()
                .map(|t| t["name"].as_str().unwrap().to_string())
                .collect();
            assert_eq!(names.contains(&VPN_LOGIN_TOOL.to_string()), expected);
            assert!(names.contains(&"internal.query".to_string()));
        }
    }

    #[tokio::test]
    async fn call_is_blocked_while_vpn_needs_login() {
        let (session, vpn) = vpn_session("echo NeedsLogin", true).await;
        vpn.refresh("netbird").await.unwrap();

        let result = call(&session, "internal.query", serde_json::json!({})).await;
        assert_eq!(result["isError"], true);
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.starts_with("VPN_REQUIRED"), "{text}");
        assert!(text.contains(VPN_LOGIN_TOOL), "{text}");
    }

    #[tokio::test]
    async fn call_passes_when_vpn_connected() {
        let (session, vpn) = vpn_session("echo ok", true).await;
        vpn.refresh("netbird").await.unwrap();

        let result = call(&session, "internal.query", serde_json::json!({})).await;
        assert_eq!(result["isError"], false);
    }

    #[tokio::test]
    async fn vpn_tools_reject_extra_or_unknown_arguments() {
        let (session, _) = vpn_session("echo ok", true).await;

        let result = call(
            &session,
            VPN_LOGIN_TOOL,
            serde_json::json!({ "vpn": "netbird", "command": "rm -rf /" }),
        )
        .await;
        assert_eq!(result["isError"], true);

        let result = call(&session, VPN_LOGIN_TOOL, serde_json::json!({ "vpn": "other" })).await;
        assert_eq!(result["isError"], true);

        let result = call(&session, VPN_STATUS_TOOL, serde_json::json!({})).await;
        assert_eq!(result["isError"], false);
        assert_eq!(result["structuredContent"]["vpns"][0]["state"], "connected");
    }

    #[tokio::test]
    async fn vpn_tools_unavailable_when_not_exposed() {
        let (session, _) = vpn_session("echo ok", false).await;
        let result = call(&session, VPN_LOGIN_TOOL, serde_json::json!({})).await;
        assert_eq!(result["isError"], true);
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("no such tool"), "{text}");
    }

    #[tokio::test]
    async fn vpn_status_is_readable_as_resource() {
        let (session, vpn) = vpn_session("echo NeedsLogin", true).await;
        vpn.refresh("netbird").await.unwrap();

        let reply = session
            .handle(JsonRpcMessage::Request(request(3, "resources/list", None)))
            .await
            .unwrap();
        let JsonRpcMessage::SuccessResponse(ok) = reply else { panic!("{reply:?}") };
        assert_eq!(ok.result["resources"][0]["uri"], "hub://vpn/netbird");

        let params = serde_json::json!({ "uri": "hub://vpn/netbird" });
        let reply = session
            .handle(JsonRpcMessage::Request(request(4, "resources/read", Some(params))))
            .await
            .unwrap();
        let JsonRpcMessage::SuccessResponse(ok) = reply else { panic!("{reply:?}") };
        let text = ok.result["contents"][0]["text"].as_str().unwrap();
        assert!(text.contains("needs_login"), "{text}");

        let params = serde_json::json!({ "uri": "hub://vpn/other" });
        let reply = session
            .handle(JsonRpcMessage::Request(request(5, "resources/read", Some(params))))
            .await
            .unwrap();
        assert!(matches!(reply, JsonRpcMessage::ErrorResponse(_)));
    }

    async fn call_modern(session: &McpSession, params: Value) -> Value {
        let mut params = params;
        params["_meta"] = serde_json::json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": { "elicitation": { "url": {} } }
        });
        let reply = session
            .handle(JsonRpcMessage::Request(request(20, "tools/call", Some(params))))
            .await
            .unwrap();
        let JsonRpcMessage::SuccessResponse(ok) = reply else { panic!("{reply:?}") };
        ok.result
    }

    #[tokio::test]
    async fn blocked_call_round_trips_through_url_elicitation() {
        let dir = std::env::temp_dir().join(format!("hmcp-mrtr-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let flag = dir.join("ok");
        let _ = std::fs::remove_file(&flag);
        let flag = flag.display().to_string();
        let mut def = vpn_def(&format!("test -f {flag} && echo ok || echo NeedsLogin"));
        def.login = vec![
            "sh".into(),
            "-c".into(),
            format!("echo 'login: https://idp.example/device'; echo 'Code: WXYZ'; sleep 1; touch {flag}"),
        ];
        let (session, vpn) = vpn_session_with(def, true).await;
        vpn.refresh("netbird").await.unwrap();

        let first = call_modern(&session, serde_json::json!({ "name": "internal.query" })).await;
        assert_eq!(first["resultType"], "input_required", "{first}");
        let elicit = &first["inputRequests"]["vpn_login"];
        assert_eq!(elicit["method"], "elicitation/create");
        assert_eq!(elicit["params"]["mode"], "url");
        assert_eq!(elicit["params"]["url"], "https://idp.example/device");
        assert!(elicit["params"]["message"].as_str().unwrap().contains("Code: WXYZ"));
        let state = first["requestState"].as_str().unwrap().to_string();

        // Tampered state is rejected.
        let bad = call_modern(&session, serde_json::json!({
            "name": "internal.query", "requestState": format!("{state}x"),
            "inputResponses": { "vpn_login": { "action": "accept" } }
        })).await;
        assert_eq!(bad["isError"], true);

        // Accepted: the retry waits for the login, then runs the tool.
        let done = call_modern(&session, serde_json::json!({
            "name": "internal.query", "requestState": state,
            "inputResponses": { "vpn_login": { "action": "accept" } }
        })).await;
        assert_eq!(done["isError"], false, "{done}");
        assert_eq!(done["resultType"], "complete");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn declined_login_returns_error() {
        let mut def = vpn_def("echo NeedsLogin");
        def.login = vec!["sh".into(), "-c".into(), "echo https://idp.example/x; sleep 5".into()];
        let (session, vpn) = vpn_session_with(def, true).await;
        vpn.refresh("netbird").await.unwrap();

        let first = call_modern(&session, serde_json::json!({ "name": "internal.query" })).await;
        let state = first["requestState"].as_str().unwrap();
        let declined = call_modern(&session, serde_json::json!({
            "name": "internal.query", "requestState": state,
            "inputResponses": { "vpn_login": { "action": "decline" } }
        })).await;
        assert_eq!(declined["isError"], true);
        assert!(declined["content"][0]["text"].as_str().unwrap().contains("declined"));
    }

    #[tokio::test]
    async fn events_methods_only_when_enabled() {
        let (session, _) = vpn_session("echo ok", true).await;
        let params = modern_params(serde_json::json!({}));
        let reply = session
            .handle(JsonRpcMessage::Request(request(1, "events/list", Some(params.clone()))))
            .await
            .unwrap();
        assert!(matches!(reply, JsonRpcMessage::ErrorResponse(_)));

        let hub = headless_mcp_events::EventHub::new(Default::default(), vec!["netbird".into()]);
        let session = session.with_events(hub);
        let reply = session
            .handle(JsonRpcMessage::Request(request(2, "events/list", Some(params.clone()))))
            .await
            .unwrap();
        let JsonRpcMessage::SuccessResponse(ok) = reply else { panic!("{reply:?}") };
        assert_eq!(ok.result["events"][0]["name"], "vpn.state_changed");

        let reply = session
            .handle(JsonRpcMessage::Request(request(3, "server/discover", Some(params))))
            .await
            .unwrap();
        let JsonRpcMessage::SuccessResponse(ok) = reply else { panic!("{reply:?}") };
        assert!(ok.result["capabilities"]["events"].is_object());
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
