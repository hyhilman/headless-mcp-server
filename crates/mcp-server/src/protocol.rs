//! Protocol-version handling for both MCP eras.
//!
//! - **Legacy** (`2024-11-05` … `2025-11-25`): `initialize` handshake, then
//!   requests without per-request metadata.
//! - **Modern** (`2026-07-28`): no handshake; every request carries its
//!   protocol version and client capabilities in `params._meta`, and every
//!   result carries `resultType`.

use headless_mcp_wire::JsonRpcError;
use serde_json::Value;

/// Version reported to legacy clients in the `initialize` result.
pub const LEGACY_PROTOCOL_VERSION: &str = "2025-06-18";

/// Modern versions this server implements.
pub const MODERN_PROTOCOL_VERSIONS: &[&str] = &["2026-07-28"];

pub const META_PROTOCOL_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
pub const META_CLIENT_CAPABILITIES: &str = "io.modelcontextprotocol/clientCapabilities";
pub const META_SERVER_INFO: &str = "io.modelcontextprotocol/serverInfo";
pub const META_SUBSCRIPTION_ID: &str = "io.modelcontextprotocol/subscriptionId";

/// JSON-RPC error codes defined by the 2026-07-28 revision.
pub const HEADER_MISMATCH: i64 = -32020;
pub const UNSUPPORTED_PROTOCOL_VERSION: i64 = -32022;

/// The protocol version a request declares in `params._meta`, if any.
/// A present version marks the request as modern.
pub fn request_protocol_version(params: Option<&Value>) -> Option<String> {
    params?
        .get("_meta")?
        .get(META_PROTOCOL_VERSION)?
        .as_str()
        .map(str::to_string)
}

/// Per-request protocol context.
#[derive(Debug, Clone, Default)]
pub(crate) struct RequestCtx {
    /// `Some(version)` for modern requests.
    pub modern: Option<String>,
}

impl RequestCtx {
    pub fn from_params(params: Option<&Value>) -> Self {
        Self {
            modern: request_protocol_version(params),
        }
    }

    pub fn is_modern(&self) -> bool {
        self.modern.is_some()
    }

    /// `Err` with `UnsupportedProtocolVersionError` for unknown modern versions.
    pub fn check_version(&self) -> Result<(), JsonRpcError> {
        match &self.modern {
            Some(v) if !MODERN_PROTOCOL_VERSIONS.contains(&v.as_str()) => Err(JsonRpcError {
                code: UNSUPPORTED_PROTOCOL_VERSION,
                message: "Unsupported protocol version".into(),
                data: Some(serde_json::json!({
                    "supported": MODERN_PROTOCOL_VERSIONS,
                    "requested": v,
                })),
            }),
            _ => Ok(()),
        }
    }
}

/// Add `resultType: "complete"` to a modern result object if missing.
pub(crate) fn mark_complete(value: &mut Value) {
    if let Value::Object(obj) = value {
        obj.entry("resultType")
            .or_insert_with(|| Value::String("complete".into()));
    }
}
