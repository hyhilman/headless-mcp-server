use std::sync::Arc;

use axum::middleware;
use axum::routing::post;
use axum::Router;
use headless_mcp_server::McpSession;

use crate::auth::require_bearer_token;
use crate::handlers::handle_mcp;
use crate::rate_limit::{build_limiter, enforce_rate_limit};
use crate::state::AppState;
use crate::HttpTransportConfig;

/// Build the full router: POST /mcp behind bearer auth and rate limit.
pub(crate) fn build_router(session: Arc<McpSession>, config: &HttpTransportConfig) -> Router {
    let state = AppState {
        session,
        bearer_token: Arc::from(config.bearer_token.as_str()),
        limiter: build_limiter(config.rate_limit_per_minute),
    };

    let authenticated_mcp =
        Router::new()
            .route("/mcp", post(handle_mcp))
            .route_layer(middleware::from_fn_with_state(
                state.clone(),
                require_bearer_token,
            ));

    Router::new()
        .merge(authenticated_mcp)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            enforce_rate_limit,
        ))
        .with_state(state)
}
