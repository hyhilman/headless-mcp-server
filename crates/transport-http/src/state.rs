use std::net::IpAddr;
use std::sync::Arc;

use headless_mcp_server::McpSession;
use governor::DefaultKeyedRateLimiter;

/// Shared state for all axum handlers and middleware.
#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) session: Arc<McpSession>,
    pub(crate) bearer_token: Arc<str>,
    pub(crate) limiter: Arc<DefaultKeyedRateLimiter<IpAddr>>,
}
