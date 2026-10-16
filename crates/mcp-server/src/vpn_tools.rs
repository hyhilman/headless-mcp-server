//! Hub-owned VPN tools (`hub.vpn_status`, `hub.vpn_login`,
//! `hub.vpn_login_complete`) and the `requires_vpn` call gate.

use std::sync::Arc;
use std::time::{Duration, Instant};

use headless_mcp_vpn::{LoginOutcome, VpnManager, VpnState};
use serde_json::Value;

use crate::protocol::RequestCtx;
use crate::session::{
    make_error_result, make_success_result, make_text_result, McpSession, ToolCallParams,
};

/// `inputRequests` key for the VPN login elicitation.
const LOGIN_INPUT_KEY: &str = "vpn_login";
/// How long a `requestState` for a VPN login stays valid.
const LOGIN_STATE_TTL_SECS: u64 = 900;

/// A tool call blocked by a VPN that is not connected.
pub(crate) struct VpnBlock {
    pub vpn: String,
    pub backend: String,
    pub state: VpnState,
    pub pending: bool,
}

/// Hub-owned tools. The `hub.` namespace is reserved for these.
pub(crate) const VPN_STATUS_TOOL: &str = "hub.vpn_status";
pub(crate) const VPN_LOGIN_TOOL: &str = "hub.vpn_login";
pub(crate) const VPN_LOGIN_COMPLETE_TOOL: &str = "hub.vpn_login_complete";

impl McpSession {
    pub(crate) fn hub_tool_descriptors(&self) -> Vec<Value> {
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
    pub(crate) async fn call_hub_tool(&self, params: &ToolCallParams) -> Option<Result<Value, String>> {
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
    pub(crate) fn vpn_block(&self, tool: &str) -> Option<VpnBlock> {
        let manager = self.vpn.as_ref()?;
        let (backend, required) = self.registry.tool_requirements(tool)?;
        required.into_iter().find_map(|vpn| {
            let status = manager.status(&vpn)?;
            if matches!(status.state, VpnState::Connected | VpnState::Unknown) {
                return None;
            }
            Some(VpnBlock {
                vpn,
                backend: backend.clone(),
                state: status.state,
                pending: status.login.is_some(),
            })
        })
    }

    /// Text-only "VPN_REQUIRED" result for clients without URL elicitation.
    pub(crate) fn vpn_required_result(&self, block: &VpnBlock) -> Value {
        make_error_result(format!(
            "VPN_REQUIRED: backend '{}' needs VPN '{}', which is {}. {}",
            block.backend,
            block.vpn,
            block.state,
            self.login_instructions(&block.vpn, block.pending),
        ))
    }

    /// Multi round-trip login (2026-07-28 + URL elicitation): instead of an
    /// error, ask the client to show the login link to the user, then let the
    /// retried call through once the VPN is connected.
    ///
    /// Returns `None` when the call may proceed (VPN connected meanwhile),
    /// otherwise the result to send back.
    pub(crate) async fn vpn_login_round_trip(
        &self,
        params: &ToolCallParams,
        block: &VpnBlock,
        ctx: &RequestCtx,
    ) -> Option<Value> {
        let usable = ctx.is_modern()
            && ctx.supports_url_elicitation()
            && self.vpn_tools.iter().any(|n| n == &block.vpn);
        let Some(manager) = self.vpn.as_ref().filter(|_| usable) else {
            return Some(self.vpn_required_result(block));
        };

        // A retry: the user has seen the link (or declined it).
        if let Some(token) = &params.request_state {
            if !self.state_signer.verify(token, &block.vpn, &params.name) {
                return Some(make_error_result(
                    "requestState is invalid or expired; call the tool again without it".into(),
                ));
            }
            let action = params
                .input_responses
                .as_ref()
                .and_then(|r| r.get(LOGIN_INPUT_KEY))
                .and_then(|r| r.get("action"))
                .and_then(Value::as_str);
            if matches!(action, Some("decline") | Some("cancel")) {
                return Some(make_error_result(format!(
                    "The user declined to sign in to VPN '{}'; '{}' cannot run without it.",
                    block.vpn, params.name
                )));
            }
            if self.wait_for_vpn(manager, &block.vpn).await {
                return None;
            }
        }

        match manager.start_login(&block.vpn).await {
            Ok(LoginOutcome::AlreadyConnected { .. }) => None,
            Ok(LoginOutcome::Pending { login }) => {
                let mut message = format!(
                    "Sign in to VPN '{}' so '{}' can run. The login stays open for {} minutes.",
                    block.vpn,
                    params.name,
                    login.timeout_at_unix.saturating_sub(login.started_at_unix) / 60,
                );
                // Keep device codes etc., but no other links in the message.
                let extra: Vec<&str> = login
                    .message
                    .lines()
                    .filter(|l| !l.contains("://"))
                    .collect();
                if !extra.is_empty() {
                    message.push_str("\n");
                    message.push_str(&extra.join("\n"));
                }
                Some(serde_json::json!({
                    "resultType": "input_required",
                    "inputRequests": {
                        LOGIN_INPUT_KEY: {
                            "method": "elicitation/create",
                            "params": { "mode": "url", "url": login.url, "message": message },
                        },
                    },
                    "requestState": self.state_signer.issue(&block.vpn, &params.name, LOGIN_STATE_TTL_SECS),
                }))
            }
            Err(e) => Some(make_error_result(format!(
                "VPN_REQUIRED: backend '{}' needs VPN '{}', and starting the login failed: {e}",
                block.backend, block.vpn
            ))),
        }
    }

    /// Wait (bounded) for the VPN to report connected.
    async fn wait_for_vpn(&self, manager: &Arc<VpnManager>, vpn: &str) -> bool {
        let deadline = Instant::now() + self.login_wait;
        loop {
            if manager.status(vpn).is_some_and(|s| s.state == VpnState::Connected) {
                return true;
            }
            if Instant::now() >= deadline {
                return manager
                    .refresh(vpn)
                    .await
                    .is_ok_and(|s| s.state == VpnState::Connected);
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    /// Hint for "no such tool": tools behind a down VPN are not listed.
    pub(crate) fn vpn_hint(&self) -> Option<String> {
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

    pub(crate) fn login_instructions(&self, vpn: &str, pending: bool) -> String {
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

}
