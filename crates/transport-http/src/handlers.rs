use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use headless_mcp_wire::{decode_message, JsonRpcErrorResponse};
use serde::Serialize;

use crate::state::AppState;

pub(crate) async fn handle_mcp(State(state): State<AppState>, body: Bytes) -> Response {
    match decode_message(&body) {
        Ok(message) => match state.session.handle(message).await {
            Some(reply) => json_response(StatusCode::OK, &reply),
            None => StatusCode::ACCEPTED.into_response(),
        },
        Err(error) => json_response(StatusCode::OK, &JsonRpcErrorResponse::new(None, error)),
    }
}

fn json_response<T: Serialize>(status: StatusCode, body: &T) -> Response {
    match serde_json::to_vec(body) {
        Ok(bytes) => (status, [(header::CONTENT_TYPE, "application/json")], bytes).into_response(),
        Err(error) => {
            tracing::error!(%error, "http transport: failed to serialize JSON-RPC response");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
