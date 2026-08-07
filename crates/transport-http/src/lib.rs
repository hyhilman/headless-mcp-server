#![forbid(unsafe_code)]

//! HTTP+SSE MCP transport.
//!
//! Wraps `headless_mcp_server::McpSession` behind an authenticated
//! network listener. Every request passes a per-IP rate limit and a
//! constant-time bearer-token check before reaching the session.

mod auth;
mod handlers;
mod rate_limit;
mod router;
mod state;

use std::net::SocketAddr;
use std::sync::Arc;

use headless_mcp_server::McpSession;

/// Configuration for [`run_http`].
pub struct HttpTransportConfig {
    pub bind_addr: SocketAddr,
    pub bearer_token: String,
    pub rate_limit_per_minute: u32,
}

impl std::fmt::Debug for HttpTransportConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpTransportConfig")
            .field("bind_addr", &self.bind_addr)
            .field("bearer_token", &"<redacted>")
            .field("rate_limit_per_minute", &self.rate_limit_per_minute)
            .finish()
    }
}

/// Runs the HTTP+SSE MCP transport until the listener exits.
pub async fn run_http(
    session: Arc<McpSession>,
    config: HttpTransportConfig,
) -> Result<(), std::io::Error> {
    // Refuse to serve without a token. The check compares raw bytes, so an empty
    // expected token matches an empty presented one — `Authorization: Bearer `
    // would authenticate, exposing every backend credential behind this listener
    // to anything that can open the port.
    if config.bearer_token.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "refusing to start: no bearer token configured (set [auth] hub_token or HEADLESS_MCP_TOKEN)",
        ));
    }

    // An unresolved placeholder means the variable behind hub_token was never set.
    // The literal "{{unresolved:NAME}}" would otherwise become the accepted token —
    // non-empty, so the check above passes, but derivable by anyone who can read
    // the config.
    if config.bearer_token.contains("{{unresolved:") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "refusing to start: bearer token still contains an unresolved placeholder ({}); \
                 the referenced variable is not set",
                config.bearer_token
            ),
        ));
    }

    if !config.bind_addr.ip().is_loopback() {
        tracing::warn!(
            addr = %config.bind_addr,
            "http transport bound to a non-loopback address; the MCP server is reachable beyond localhost"
        );
    }

    tracing::info!(addr = %config.bind_addr, "http transport listening");

    let app = router::build_router(session, &config);

    let listener = tokio::net::TcpListener::bind(config.bind_addr).await?;

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
}
