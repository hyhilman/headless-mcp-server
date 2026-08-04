use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::Arc;

use axum::extract::{ConnectInfo, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};

use crate::state::AppState;

/// Build a per-IP rate limiter.
pub(crate) fn build_limiter(requests_per_minute: u32) -> Arc<DefaultKeyedRateLimiter<IpAddr>> {
    let burst = NonZeroU32::new(requests_per_minute).unwrap_or(NonZeroU32::MIN);
    Arc::new(RateLimiter::keyed(Quota::per_minute(burst)))
}

/// Middleware: return 429 if the source IP is over its budget.
pub(crate) async fn enforce_rate_limit(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    match state.limiter.check_key(&addr.ip()) {
        Ok(()) => next.run(request).await,
        Err(_) => {
            tracing::debug!(client_ip = %addr.ip(), "http transport: rate limit exceeded");
            (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response()
        }
    }
}
