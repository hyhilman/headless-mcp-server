use async_trait::async_trait;
use headless_mcp_wire::JsonRpcError;

/// The outcome of one JSON-RPC request handled by [`crate::McpSession`].
#[derive(Debug, Clone)]
pub enum AuditOutcome {
    Ok,
    Error { code: i64 },
}

impl AuditOutcome {
    pub fn from_result<T>(result: &Result<T, JsonRpcError>) -> Self {
        match result {
            Ok(_) => Self::Ok,
            Err(err) => Self::Error { code: err.code },
        }
    }
}

/// One audit record. Deliberately excludes tool call arguments and results.
#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub method: String,
    pub tool_name: Option<String>,
    pub outcome: AuditOutcome,
}

/// Records one [`AuditEvent`] per handled request.
#[async_trait]
pub trait AuditLogger: Send + Sync {
    async fn record(&self, event: AuditEvent);
}

/// Emits audit events as structured `tracing` events.
#[derive(Debug, Default)]
pub struct TracingAuditLogger;

#[async_trait]
impl AuditLogger for TracingAuditLogger {
    async fn record(&self, event: AuditEvent) {
        match event.outcome {
            AuditOutcome::Ok => {
                tracing::info!(method = %event.method, tool = ?event.tool_name, "mcp call ok");
            }
            AuditOutcome::Error { code } => {
                tracing::warn!(method = %event.method, tool = ?event.tool_name, code, "mcp call failed");
            }
        }
    }
}
