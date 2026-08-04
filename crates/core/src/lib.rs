#![forbid(unsafe_code)]

//! Core backend contract and config types for the headless MCP hub.
//!
//! This crate defines [`McpBackend`] — the seam between the hub and a
//! specific MCP backend — plus [`BackendDef`] for configuring them, and
//! the shared error types.

mod error;
pub mod types;

pub use error::{BackendError, BackendErrorKind, BackendResult};
pub use types::{
    BackendDef, BackendTransport, CallToolResult, ConnectionMode, ContentBlock, InitializeResult,
    ServerCapabilities, ServerInfo, StderrMode, ToolDescriptor,
};

use async_trait::async_trait;
use serde_json::Value;
use std::time::Duration;

/// A connected downstream MCP server. This is the seam between the hub
/// and a specific MCP backend.
///
/// Lifecycle: connect → [list_tools | call_tool | health_check]* → disconnect
///
/// `connect()` does the full MCP handshake in one call: spawn/open transport,
/// send `initialize`, await response, send `notifications/initialized`.
/// There is no valid state where a backend is "connected but not initialized" —
/// if the handshake fails, connect returns an error and the backend is dead.
#[async_trait]
pub trait McpBackend: Send + Sync {
    /// Unique id for this backend (e.g. "slack", "linear", "postgres").
    fn backend_id(&self) -> &str;

    /// Human label for logs/dashboards.
    fn label(&self) -> &str;

    /// Full MCP handshake: open transport → initialize request → await
    /// InitializeResult → send notifications/initialized.
    /// Must be idempotent — if already connected, returns cached result.
    async fn connect(&self) -> BackendResult<InitializeResult>;

    /// tools/list from the downstream. Backend must be connected.
    async fn list_tools(&self) -> BackendResult<Vec<ToolDescriptor>>;

    /// tools/call forwarded to the downstream. Backend must be connected.
    async fn call_tool(
        &self,
        name: &str,
        arguments: Option<Value>,
        timeout: Duration,
    ) -> BackendResult<Value>;

    /// Disconnect / tear down. Must be safe to call even if not connected.
    async fn disconnect(&self) -> BackendResult<()>;

    /// Health check — is the downstream reachable and responding?
    async fn health_check(&self) -> BackendResult<()>;

    /// The MCP protocol version this backend speaks, learned during connect().
    fn protocol_version(&self) -> Option<&str> {
        None
    }
}
