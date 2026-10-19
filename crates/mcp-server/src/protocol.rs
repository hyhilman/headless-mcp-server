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

/// Freshness hint for list and discover results; backends can reconnect, and
/// `list_changed` already invalidates the cache sooner.
const LIST_TTL_MS: u64 = 60_000;

/// `ttlMs` and `cacheScope` the 2026-07-28 revision requires on these results.
fn cache_ttl_ms(method: &str) -> Option<u64> {
    match method {
        "server/discover"
        | "tools/list"
        | "resources/list"
        | "resources/templates/list"
        | "prompts/list" => Some(LIST_TTL_MS),
        // Resource contents are live state, so they are always stale.
        "resources/read" => Some(0),
        _ => None,
    }
}

/// Add `ttlMs` and `cacheScope` to a modern result of a cacheable method.
pub(crate) fn mark_cacheable(method: &str, value: &mut Value) {
    let Some(ttl_ms) = cache_ttl_ms(method) else {
        return;
    };
    let Value::Object(obj) = value else {
        return;
    };
    // Interim `input_required` results carry no caching hints.
    if obj.get("resultType").and_then(Value::as_str) != Some("complete") {
        return;
    }
    if !obj.get("ttlMs").is_some_and(Value::is_u64) {
        obj.insert("ttlMs".into(), Value::from(ttl_ms));
    }
    // Each expose port has its own token and tool set, so a shared cache could leak it.
    obj.insert("cacheScope".into(), Value::String("private".into()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_hints_skip_input_required_and_other_methods() {
        let mut interim = serde_json::json!({ "resultType": "input_required" });
        mark_cacheable("resources/read", &mut interim);
        assert_eq!(
            interim,
            serde_json::json!({ "resultType": "input_required" })
        );

        let mut call = serde_json::json!({ "resultType": "complete", "content": [] });
        mark_cacheable("tools/call", &mut call);
        assert!(call.get("ttlMs").is_none() && call.get("cacheScope").is_none());
    }

    #[test]
    fn backend_cache_scope_never_widens() {
        let mut read = serde_json::json!({
            "resultType": "complete", "ttlMs": 5000, "cacheScope": "public", "contents": []
        });
        mark_cacheable("resources/read", &mut read);
        assert_eq!(read["ttlMs"], 5000);
        assert_eq!(read["cacheScope"], "private");
    }
}
