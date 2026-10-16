use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use headless_mcp_server::protocol::{
    request_protocol_version, HEADER_MISMATCH, UNSUPPORTED_PROTOCOL_VERSION,
};
use headless_mcp_wire::{decode_message, JsonRpcError, JsonRpcErrorResponse, JsonRpcMessage};
use serde::Serialize;

use crate::state::AppState;

const PROTOCOL_VERSION_HEADER: &str = "mcp-protocol-version";

pub(crate) async fn handle_mcp(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let message = match decode_message(&body) {
        Ok(message) => message,
        Err(error) => {
            return json_response(StatusCode::OK, &JsonRpcErrorResponse::new(None, error))
        }
    };

    // Modern (2026-07-28) requests declare their version in `_meta`; the
    // header must agree so intermediaries and the server see the same thing.
    let modern = match &message {
        JsonRpcMessage::Request(request) => {
            request_protocol_version(request.params.as_ref()).map(|v| (v, request.id.clone()))
        }
        _ => None,
    };
    if let Some((version, id)) = &modern {
        let header = headers
            .get(PROTOCOL_VERSION_HEADER)
            .and_then(|v| v.to_str().ok());
        if header != Some(version.as_str()) {
            let error = JsonRpcError {
                code: HEADER_MISMATCH,
                message: format!(
                    "Header mismatch: MCP-Protocol-Version {:?} does not match body version '{version}'",
                    header.unwrap_or("<missing>")
                ),
                data: None,
            };
            return json_response(
                StatusCode::BAD_REQUEST,
                &JsonRpcErrorResponse::new(Some(id.clone()), error),
            );
        }
    }

    match state.session.handle(message).await {
        Some(reply) => {
            let status = if modern.is_some() { modern_status(&reply) } else { StatusCode::OK };
            json_response(status, &reply)
        }
        None => StatusCode::ACCEPTED.into_response(),
    }
}

/// HTTP status for a modern reply, per the 2026-07-28 Streamable HTTP rules.
fn modern_status(reply: &JsonRpcMessage) -> StatusCode {
    match reply {
        JsonRpcMessage::ErrorResponse(err) => match err.error.code {
            UNSUPPORTED_PROTOCOL_VERSION => StatusCode::BAD_REQUEST,
            JsonRpcError::METHOD_NOT_FOUND => StatusCode::NOT_FOUND,
            _ => StatusCode::OK,
        },
        _ => StatusCode::OK,
    }
}

pub(crate) fn json_response<T: Serialize>(status: StatusCode, body: &T) -> Response {
    match serde_json::to_vec(body) {
        Ok(bytes) => (status, [(header::CONTENT_TYPE, "application/json")], bytes).into_response(),
        Err(error) => {
            tracing::error!(%error, "http transport: failed to serialize JSON-RPC response");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
