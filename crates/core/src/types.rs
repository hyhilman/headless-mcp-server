use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// How a backend is defined before it's connected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendDef {
    pub id: String,

    #[serde(default)]
    pub label: Option<String>,

    /// How to connect to this backend.
    #[serde(flatten)]
    pub transport: BackendTransport,

    /// Prefix applied to every tool from this backend.
    /// "slack" → tools exposed as "slack.send_message", etc.
    /// null → tools exposed bare (no prefix). Use with caution.
    #[serde(default)]
    pub namespace: Option<String>,

    /// Connection strategy.
    #[serde(default)]
    pub connection_mode: ConnectionMode,

    /// Maximum time for the connect handshake.
    /// Default: 10 seconds.
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_secs: u64,

    /// Maximum time for a tools/call to this backend.
    /// Default: 30 seconds.
    #[serde(default = "default_call_timeout")]
    pub call_timeout_secs: u64,

    /// What to do with the backend's stderr output.
    #[serde(default)]
    pub stderr_mode: StderrMode,

    /// Only expose these tools (by downstream name, before namespace prefix).
    /// Empty = expose all.
    #[serde(default)]
    pub tools_allow: Vec<String>,

    /// Hide these tools from the aggregated list.
    /// Applied after tools_allow.
    #[serde(default)]
    pub tools_deny: Vec<String>,
}

fn default_connect_timeout() -> u64 {
    10
}

fn default_call_timeout() -> u64 {
    30
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "transport", rename_all = "lowercase")]
pub enum BackendTransport {
    Stdio {
        command: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        env: HashMap<String, String>,
        /// Working directory for the child process.
        cwd: Option<String>,
    },
    Http {
        url: String,
        /// Bearer token for the downstream MCP (static token).
        bearer_token: Option<String>,
        /// OAuth2 client credentials for automatic token acquisition.
        #[serde(default)]
        oauth2: Option<OAuth2Config>,
    },
}

/// OAuth2 configuration for a backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2Config {
    /// OAuth2 token endpoint URL.
    pub token_endpoint: Option<String>,
    /// Client ID for the OAuth2 application.
    pub client_id: Option<String>,
    /// Client secret for the OAuth2 application.
    pub client_secret: Option<String>,
    /// Space-separated list of scopes to request.
    #[serde(default)]
    pub scopes: Option<String>,
    /// Grant type: "client_credentials" (default) or "authorization_code".
    #[serde(default = "default_grant_type")]
    pub grant_type: String,
    /// Callback port for the local OAuth2 redirect server (default: 9798).
    #[serde(default = "default_callback_port")]
    pub callback_port: u16,
}

fn default_callback_port() -> u16 {
    9798
}

fn default_grant_type() -> String {
    "client_credentials".to_string()
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConnectionMode {
    /// Connect at hub startup, keep alive, reconnect on failure.
    #[default]
    Eager,
    /// Connect on first tools/call, keep alive thereafter.
    Lazy,
    /// Connect, call, disconnect — stateless, no keepalive.
    PerCall,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StderrMode {
    /// Capture stderr, only log it if the backend returns an error or crashes.
    #[default]
    LogOnError,
    /// Capture stderr, discard entirely (even on errors).
    Silent,
    /// Forward stderr to the hub's stderr in real time.
    Passthrough,
    /// Capture stderr, log it all at trace level regardless of success/failure.
    LogAlways,
}

/// Result of a successful MCP initialize handshake with a backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeResult {
    pub protocol_version: String,
    pub server_info: ServerInfo,
    pub capabilities: ServerCapabilities,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerCapabilities {
    #[serde(default)]
    pub tools: Option<ToolsCapability>,
    #[serde(default)]
    pub resources: Option<ResourcesCapability>,
    #[serde(default)]
    pub prompts: Option<PromptsCapability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolsCapability {
    #[serde(default = "default_true")]
    pub list_changed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourcesCapability {
    #[serde(default = "default_true")]
    pub subscribe: bool,
    #[serde(default = "default_true")]
    pub list_changed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PromptsCapability {
    #[serde(default = "default_true")]
    pub list_changed: bool,
}

fn default_true() -> bool {
    true
}

/// Describes a tool for the `tools/list` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolDescriptor {
    pub name: String,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
}

/// One block of a `tools/call` result's `content` array.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentBlock {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

/// The MCP spec's `tools/call` result shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallToolResult {
    pub content: Vec<ContentBlock>,
    #[serde(rename = "isError", default)]
    pub is_error: bool,
}
