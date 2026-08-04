#![forbid(unsafe_code)]

//! Transport-agnostic MCP session logic: tool registry, `initialize`/
//! `tools/list`/`tools/call` dispatch, audit logging.
//!
//! Deliberately has no socket, no HTTP, no stdio here — [`McpSession`]
//! takes one decoded [`headless_mcp_wire::JsonRpcMessage`] in and
//! produces zero or one out. Transports (stdio, HTTP+SSE) wrap this and
//! own the concerns that differ between them.

mod audit;
mod session;

pub use audit::{AuditEvent, AuditLogger, AuditOutcome, TracingAuditLogger};
pub use session::{McpSession, PROTOCOL_VERSION};
