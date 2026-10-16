//! `subscriptions/listen` streams and the `hub://vpn/<name>` resources they
//! can watch.

use headless_mcp_wire::{JsonRpcError, JsonRpcId, JsonRpcMessage, JsonRpcNotification};
use serde_json::Value;
use tokio::sync::{broadcast, mpsc};

use crate::protocol::{RequestCtx, META_SUBSCRIPTION_ID};
use crate::session::{Change, McpSession};
use headless_mcp_vpn::{VpnEvent, VpnManager};

const VPN_RESOURCE_PREFIX: &str = "hub://vpn/";

/// What a transport should send back for one incoming message.
pub enum SessionReply {
    /// A single response.
    Message(JsonRpcMessage),
    /// A long-lived stream (`subscriptions/listen`): forward every message
    /// until the receiver ends, or drop the receiver to cancel.
    Stream {
        id: JsonRpcId,
        messages: mpsc::UnboundedReceiver<JsonRpcMessage>,
    },
}

impl McpSession {
    /// Like [`McpSession::handle`], but `subscriptions/listen` returns a
    /// [`SessionReply::Stream`] instead of an error.
    pub async fn handle_streaming(&self, message: JsonRpcMessage) -> Option<SessionReply> {
        match message {
            JsonRpcMessage::Request(request) if request.method == "subscriptions/listen" => {
                let ctx = RequestCtx::from_params(request.params.as_ref());
                match self.listen(&request.id, request.params.as_ref(), &ctx) {
                    Ok(messages) => Some(SessionReply::Stream { id: request.id, messages }),
                    Err(error) => Some(SessionReply::Message(JsonRpcMessage::ErrorResponse(
                        headless_mcp_wire::JsonRpcErrorResponse::new(Some(request.id), error),
                    ))),
                }
            }
            JsonRpcMessage::Request(request) => {
                Some(SessionReply::Message(self.handle_request(request).await))
            }
            JsonRpcMessage::Notification(notification) => {
                self.handle_notification(notification);
                None
            }
            JsonRpcMessage::SuccessResponse(_) | JsonRpcMessage::ErrorResponse(_) => None,
        }
    }

    fn listen(
        &self,
        id: &JsonRpcId,
        params: Option<&Value>,
        ctx: &RequestCtx,
    ) -> Result<mpsc::UnboundedReceiver<JsonRpcMessage>, JsonRpcError> {
        ctx.check_version()?;
        if !ctx.is_modern() {
            return Err(JsonRpcError::invalid_request(
                "subscriptions/listen requires protocol version 2026-07-28",
            ));
        }
        let wanted = params
            .and_then(|p| p.get("notifications"))
            .cloned()
            .unwrap_or(Value::Null);
        let tools = wanted.get("toolsListChanged").and_then(Value::as_bool) == Some(true);
        let uris: Vec<String> = wanted
            .get("resourceSubscriptions")
            .and_then(Value::as_array)
            .map(|list| {
                list.iter()
                    .filter_map(Value::as_str)
                    .filter(|uri| self.vpn_resource_name(uri).is_some())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();

        // Acknowledge only what we will actually send.
        let mut agreed = serde_json::Map::new();
        if tools {
            agreed.insert("toolsListChanged".into(), Value::Bool(true));
        }
        if !uris.is_empty() {
            agreed.insert("resourceSubscriptions".into(), serde_json::json!(uris));
        }

        let sub_id = serde_json::to_value(id).unwrap_or(Value::Null);
        let (tx, rx) = mpsc::unbounded_channel();
        let _ = tx.send(notification(
            "notifications/subscriptions/acknowledged",
            &sub_id,
            serde_json::json!({ "notifications": agreed }),
        ));

        let mut changes = self.changes.subscribe();
        tokio::spawn(async move {
            loop {
                let change = match changes.recv().await {
                    Ok(change) => change,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                };
                let message = match change {
                    Change::ToolsListChanged if tools => notification(
                        "notifications/tools/list_changed",
                        &sub_id,
                        serde_json::json!({}),
                    ),
                    Change::ResourceUpdated(uri) if uris.contains(&uri) => notification(
                        "notifications/resources/updated",
                        &sub_id,
                        serde_json::json!({ "uri": uri }),
                    ),
                    _ => continue,
                };
                if tx.send(message).is_err() {
                    break; // client went away
                }
            }
        });
        Ok(rx)
    }

    pub(crate) fn handle_resources_list(&self, ctx: &RequestCtx) -> Result<Value, JsonRpcError> {
        self.require_initialized(ctx)?;
        let resources: Vec<Value> = self
            .vpn_tools
            .iter()
            .map(|name| {
                serde_json::json!({
                    "uri": format!("{VPN_RESOURCE_PREFIX}{name}"),
                    "name": format!("vpn-{name}"),
                    "title": format!("VPN '{name}' status"),
                    "description": "Connection state, login expiry, and any login waiting for the user.",
                    "mimeType": "application/json",
                })
            })
            .collect();
        Ok(serde_json::json!({ "resources": resources }))
    }

    pub(crate) fn handle_resources_read(
        &self,
        params: Option<&Value>,
        ctx: &RequestCtx,
    ) -> Result<Value, JsonRpcError> {
        self.require_initialized(ctx)?;
        let uri = params
            .and_then(|p| p.get("uri"))
            .and_then(Value::as_str)
            .ok_or_else(|| JsonRpcError::invalid_params("resources/read requires 'uri'"))?;
        let status = self
            .vpn_resource_name(uri)
            .and_then(|name| self.vpn.as_ref()?.status(name))
            .ok_or_else(|| JsonRpcError::invalid_params(format!("resource not found: {uri}")))?;
        let text = serde_json::to_string_pretty(&status).unwrap_or_default();
        Ok(serde_json::json!({
            "contents": [{ "uri": uri, "mimeType": "application/json", "text": text }],
        }))
    }

    /// VPN name for an exposed `hub://vpn/<name>` URI.
    fn vpn_resource_name<'a>(&self, uri: &'a str) -> Option<&'a str> {
        let name = uri.strip_prefix(VPN_RESOURCE_PREFIX)?;
        self.vpn_tools.iter().any(|n| n == name).then_some(name)
    }

    /// Turn VPN state changes into `hub://vpn/<name>` resource updates.
    pub(crate) fn forward_vpn_changes(&self, manager: &VpnManager) {
        if self.vpn_tools.is_empty() {
            return;
        }
        let exposed = self.vpn_tools.clone();
        let changes = self.changes.clone();
        let mut events = manager.subscribe();
        tokio::spawn(async move {
            loop {
                match events.recv().await {
                    Ok(VpnEvent::StateChanged { name, .. }) if exposed.contains(&name) => {
                        let _ = changes.send(Change::ResourceUpdated(format!("{VPN_RESOURCE_PREFIX}{name}")));
                    }
                    Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    }
}

fn notification(method: &str, sub_id: &Value, params: Value) -> JsonRpcMessage {
    let mut params = params;
    params["_meta"] = serde_json::json!({ META_SUBSCRIPTION_ID: sub_id });
    JsonRpcMessage::Notification(JsonRpcNotification::new(method, Some(params)))
}
