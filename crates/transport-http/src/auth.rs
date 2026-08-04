use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use subtle::ConstantTimeEq;

use crate::state::AppState;

const BEARER_PREFIX: &str = "Bearer ";

fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    raw.strip_prefix(BEARER_PREFIX)
}

fn tokens_match(provided: &str, expected: &str) -> bool {
    provided.as_bytes().ct_eq(expected.as_bytes()).into()
}

/// Middleware: reject with 401 before the session ever runs, unless the
/// request carries a matching bearer token.
pub(crate) async fn require_bearer_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Response {
    match extract_bearer_token(&headers) {
        Some(token) if tokens_match(token, &state.bearer_token) => next.run(request).await,
        _ => {
            tracing::warn!("http transport: rejected request with missing/invalid bearer token");
            (StatusCode::UNAUTHORIZED, "unauthorized").into_response()
        }
    }
}
