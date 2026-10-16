use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use headless_mcp_registry::BackendRegistry;
use headless_mcp_vpn::{LoginOutcome, VpnManager, VpnState};
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

/// Hub-owned tools. The `hub.` namespace is reserved for these.
const VPN_STATUS_TOOL: &str = "hub.vpn_status";
const VPN_LOGIN_TOOL: &str = "hub.vpn_login";
const VPN_LOGIN_COMPLETE_TOOL: &str = "hub.vpn_login_complete";

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
    vpn: Option<Arc<VpnManager>>,
    /// VPN names this session exposes through the `hub.vpn_*` tools.
    vpn_tools: Vec<String>,
}

impl McpSession {
    pub fn new(registry: Arc<BackendRegistry>, audit: Arc<dyn AuditLogger>) -> Self {
        Self {
            registry,
            audit,
            initialized: AtomicBool::new(false),
            vpn: None,
            vpn_tools: Vec::new(),
        }
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
        self.vpn = Some(manager);
        self
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

        if let Some(result) = self.call_hub_tool(&params).await {
            let outcome = match &result {
                Ok(_) => AuditOutcome::Ok,
                Err(_) => AuditOutcome::Error { code: -32603 },
            };
            let value = result.unwrap_or_else(make_error_result);
            return (Ok(value), Some(tool_name), outcome);
        }

        if let Some(message) = self.vpn_gate(&params.name) {
            let result = make_error_result(message);
            return (Ok(result), Some(tool_name), AuditOutcome::Error { code: -32603 });
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

    // ── hub VPN tools ──────────────────────────────────────────────────

    fn hub_tool_descriptors(&self) -> Vec<Value> {
        if self.vpn_tools.is_empty() {
            return Vec::new();
        }
        let vpn_property = serde_json::json!({
            "type": "string",
            "enum": self.vpn_tools,
            "description": "Which VPN. Optional when only one is configured.",
        });
        let schema = serde_json::json!({
            "type": "object",
            "properties": { "vpn": vpn_property },
            "additionalProperties": false,
        });
        let paste_back: Vec<&String> = self
            .vpn_tools
            .iter()
            .filter(|n| self.vpn.as_ref().is_some_and(|m| m.supports_paste_back(n)))
            .collect();
        let mut tools = vec![
            serde_json::json!({
                "name": VPN_STATUS_TOOL,
                "description": "Check VPN connection state (connected / needs_login / down), \
                    login expiry, and any login waiting for the user. Some backends only work \
                    while their VPN is connected.",
                "inputSchema": schema,
            }),
            serde_json::json!({
                "name": VPN_LOGIN_TOOL,
                "description": "Start the VPN's SSO login and return the login link. Show the \
                    link to the user and ask them to sign in; do not open, fetch, or share it \
                    anywhere else. Then poll hub.vpn_status until the state is 'connected'.",
                "inputSchema": schema,
            }),
        ];
        if !paste_back.is_empty() {
            tools.push(serde_json::json!({
                "name": VPN_LOGIN_COMPLETE_TOOL,
                "description": "Finish a VPN login whose browser redirect ended on a \
                    http://localhost:<port>/... page that failed to load. Pass the full address \
                    the user copied from their browser's address bar. Only works while a login \
                    started by hub.vpn_login is waiting.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "vpn": {
                            "type": "string",
                            "enum": paste_back,
                            "description": "Which VPN. Optional when only one is configured.",
                        },
                        "callback_url": {
                            "type": "string",
                            "description": "The full http://localhost:<port>/... address.",
                        },
                    },
                    "required": ["callback_url"],
                    "additionalProperties": false,
                },
            }));
        }
        tools
    }

    /// Handles `hub.*` tools. `None` = not a hub tool on this session.
    async fn call_hub_tool(&self, params: &ToolCallParams) -> Option<Result<Value, String>> {
        let is_status = params.name == VPN_STATUS_TOOL;
        let is_login = params.name == VPN_LOGIN_TOOL;
        let is_complete = params.name == VPN_LOGIN_COMPLETE_TOOL;
        if !(is_status || is_login || is_complete) || self.vpn_tools.is_empty() {
            return None;
        }
        let manager = self.vpn.as_ref()?;

        if is_complete {
            return Some(self.complete_login(manager, params.arguments.as_ref()).await);
        }

        let requested = match self.parse_vpn_arg(params.arguments.as_ref()) {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };

        if is_status {
            let names = match requested {
                Some(name) => vec![name],
                None => self.vpn_tools.clone(),
            };
            let mut statuses = Vec::new();
            for name in names {
                match manager.refresh(&name).await {
                    Ok(status) => statuses.push(status),
                    Err(e) => return Some(Err(e.to_string())),
                }
            }
            let value = serde_json::json!({ "vpns": statuses });
            return Some(Ok(make_success_result(value)));
        }

        let name = match requested {
            Some(name) => name,
            None => {
                return Some(Err(format!(
                    "argument 'vpn' is required; one of: {}",
                    self.vpn_tools.join(", ")
                )))
            }
        };
        Some(match manager.start_login(&name).await {
            Ok(LoginOutcome::AlreadyConnected { status }) => Ok(make_text_result(
                format!("VPN '{name}' is already connected. Retry the original tool."),
                serde_json::json!({ "result": "already_connected", "status": status }),
            )),
            Ok(LoginOutcome::Pending { login }) => {
                let mut text = format!(
                    "Login link for VPN '{name}': {url}\n\n{message}\n\n\
                     Show this link to the user and ask them to sign in. Do not open or share it \
                     anywhere else. The login stays open for {mins} minutes. Afterwards call \
                     {VPN_STATUS_TOOL} until the state is 'connected', then retry the original tool.",
                    url = login.url,
                    message = login.message,
                    mins = login.timeout_at_unix.saturating_sub(login.started_at_unix) / 60,
                );
                if manager.supports_paste_back(&name) {
                    text.push_str(&format!(
                        " If the browser ends on a http://localhost:... page that does not load, \
                         ask the user to copy that full address and pass it to \
                         {VPN_LOGIN_COMPLETE_TOOL}."
                    ));
                }
                Ok(make_text_result(
                    text,
                    serde_json::json!({ "result": "pending", "login": login }),
                ))
            }
            Err(e) => Err(e.to_string()),
        })
    }

    async fn complete_login(
        &self,
        manager: &Arc<VpnManager>,
        arguments: Option<&Value>,
    ) -> Result<Value, String> {
        let Some(Value::Object(obj)) = arguments else {
            return Err("arguments must include 'callback_url'".into());
        };
        if let Some(extra) = obj.keys().find(|k| !matches!(k.as_str(), "vpn" | "callback_url")) {
            return Err(format!("unexpected argument '{extra}'"));
        }
        let callback_url = obj
            .get("callback_url")
            .and_then(Value::as_str)
            .ok_or("argument 'callback_url' must be a string")?;
        let mut vpn_only = obj.clone();
        vpn_only.remove("callback_url");
        let name = self
            .parse_vpn_arg(Some(&Value::Object(vpn_only)))?
            .ok_or_else(|| format!("argument 'vpn' is required; one of: {}", self.vpn_tools.join(", ")))?;
        let status = manager
            .complete_login(&name, callback_url)
            .await
            .map_err(|e| e.to_string())?;
        Ok(make_text_result(
            format!(
                "Callback delivered to the '{name}' login ({status}). Poll {VPN_STATUS_TOOL} \
                 until the state is 'connected', then retry the original tool."
            ),
            serde_json::json!({ "result": "delivered", "http_status": status }),
        ))
    }

    /// Accepts only `{}` or `{"vpn": "<exposed name>"}`; nothing else.
    fn parse_vpn_arg(&self, arguments: Option<&Value>) -> Result<Option<String>, String> {
        let obj = match arguments {
            None | Some(Value::Null) => return Ok(self.default_vpn()),
            Some(Value::Object(obj)) => obj,
            Some(_) => return Err("arguments must be an object".into()),
        };
        if let Some(extra) = obj.keys().find(|k| k.as_str() != "vpn") {
            return Err(format!("unexpected argument '{extra}'; only 'vpn' is accepted"));
        }
        match obj.get("vpn") {
            None | Some(Value::Null) => Ok(self.default_vpn()),
            Some(Value::String(name)) if self.vpn_tools.contains(name) => Ok(Some(name.clone())),
            Some(_) => Err(format!(
                "unknown VPN; expected one of: {}",
                self.vpn_tools.join(", ")
            )),
        }
    }

    fn default_vpn(&self) -> Option<String> {
        match self.vpn_tools.as_slice() {
            [only] => Some(only.clone()),
            _ => None,
        }
    }

    /// Returns an actionable error if the tool's backend needs a VPN that
    /// is known to be down. `Unknown` (not checked yet) is let through.
    fn vpn_gate(&self, tool: &str) -> Option<String> {
        let manager = self.vpn.as_ref()?;
        let (backend_id, required) = self.registry.tool_requirements(tool)?;
        for name in required {
            let status = manager.status(&name)?;
            if matches!(status.state, VpnState::Connected | VpnState::Unknown) {
                continue;
            }
            let mut message = format!(
                "VPN_REQUIRED: backend '{backend_id}' needs VPN '{name}', which is {state}.",
                state = status.state,
            );
            message.push(' ');
            message.push_str(&self.login_instructions(&name, status.login.is_some()));
            return Some(message);
        }
        None
    }

    /// Hint for "no such tool": tools behind a down VPN are not listed.
    fn vpn_hint(&self) -> Option<String> {
        let manager = self.vpn.as_ref()?;
        let down: Vec<String> = manager
            .names()
            .into_iter()
            .filter_map(|n| manager.status(&n))
            .filter(|s| matches!(s.state, VpnState::NeedsLogin | VpnState::Down))
            .map(|s| format!("'{}' ({})", s.name, s.state))
            .collect();
        if down.is_empty() {
            return None;
        }
        Some(format!(
            "Note: VPN {} is not connected; tools behind it are unavailable until it reconnects.",
            down.join(", ")
        ))
    }

    fn login_instructions(&self, vpn: &str, pending: bool) -> String {
        if !self.vpn_tools.iter().any(|n| n == vpn) {
            return format!("Ask the user to log in to VPN '{vpn}' on the hub host, then retry.");
        }
        if pending {
            format!(
                "A login is already waiting for the user: call {VPN_LOGIN_TOOL} {{\"vpn\":\"{vpn}\"}} \
                 to get the link again, then poll {VPN_STATUS_TOOL} and retry once connected."
            )
        } else {
            format!(
                "Call {VPN_LOGIN_TOOL} {{\"vpn\":\"{vpn}\"}}, show the returned link to the user, \
                 poll {VPN_STATUS_TOOL} until the state is 'connected', then retry this tool."
            )
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

fn make_text_result(text: String, structured: Value) -> Value {
    serde_json::json!({
        "content": [
            { "type": "text", "text": text }
        ],
        "isError": false,
        "structuredContent": structured,
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

    // ── VPN ────────────────────────────────────────────────────────────

    use headless_mcp_core::{
        BackendDef, BackendResult, BackendTransport, ConnectionMode, InitializeResult,
        McpBackend, ServerCapabilities, ServerInfo, StderrMode, ToolDescriptor,
    };
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

        let vpn = VpnManager::new(vec![vpn_def(health)]);
        let exposed = if expose { vpn.names() } else { vec![] };
        let session = McpSession::new(registry, Arc::new(TracingAuditLogger))
            .with_vpn(vpn.clone(), exposed);
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
