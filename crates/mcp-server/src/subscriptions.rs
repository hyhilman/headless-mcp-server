//! `subscriptions/listen` streams (tool list changes).

use headless_mcp_wire::{JsonRpcError, JsonRpcId, JsonRpcMessage, JsonRpcNotification};
use serde_json::Value;
use tokio::sync::{broadcast, mpsc};

use crate::protocol::{RequestCtx, META_SUBSCRIPTION_ID};
use crate::session::{Change, McpSession};

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

        // Acknowledge only what we will actually send. Resource updates
        // from backends are not forwarded (yet).
        let mut agreed = serde_json::Map::new();
        if tools {
            agreed.insert("toolsListChanged".into(), Value::Bool(true));
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
                let Change::ToolsListChanged = change;
                if !tools {
                    continue;
                }
                let message = notification(
                    "notifications/tools/list_changed",
                    &sub_id,
                    serde_json::json!({}),
                );
                if tx.send(message).is_err() {
                    break; // client went away
                }
            }
        });
        Ok(rx)
    }
}

fn notification(method: &str, sub_id: &Value, params: Value) -> JsonRpcMessage {
    let mut params = params;
    params["_meta"] = serde_json::json!({ META_SUBSCRIPTION_ID: sub_id });
    JsonRpcMessage::Notification(JsonRpcNotification::new(method, Some(params)))
}
