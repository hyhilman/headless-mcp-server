use headless_mcp_core::{BackendDef, BackendTransport, ConnectionMode, StderrMode};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

/// Raw deserialized config from the TOML file.
#[derive(Debug, Deserialize)]
struct RawConfig {
    #[serde(default)]
    pub auth: Option<RawAuthConfig>,
    #[serde(default)]
    pub backends: HashMap<String, RawBackendConfig>,
    #[serde(default)]
    pub expose: Vec<RawExposeBlock>,
}

#[derive(Debug, Deserialize)]
pub struct RawExposeBlock {
    pub port: u16,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub backends: HashMap<String, RawExposeBackend>,
}

#[derive(Debug, Deserialize)]
pub struct RawExposeBackend {
    #[serde(default)]
    pub tools_allow: Vec<String>,
    #[serde(default)]
    pub tools_deny: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawAuthConfig {
    pub hub_token: Option<String>,
    #[serde(default = "default_rate_limit")]
    pub rate_limit: u32,
}

fn default_rate_limit() -> u32 {
    120
}

#[derive(Debug, Deserialize)]
struct RawBackendConfig {
    pub transport: String,
    pub command: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: HashMap<String, String>,
    pub cwd: Option<String>,
    pub url: Option<String>,
    pub bearer_token: Option<String>,
    /// OAuth2 configuration.
    #[serde(default)]
    pub oauth2: Option<RawOAuth2Config>,
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default)]
    pub connection_mode: String,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_secs: u64,
    #[serde(default = "default_call_timeout")]
    pub call_timeout_secs: u64,
    #[serde(default)]
    pub stderr_mode: String,
    #[serde(default)]
    pub tools_allow: Vec<String>,
    #[serde(default)]
    pub tools_deny: Vec<String>,
}

fn default_connect_timeout() -> u64 {
    10
}
fn default_call_timeout() -> u64 {
    30
}

#[derive(Debug, Deserialize)]
struct RawOAuth2Config {
    pub token_endpoint: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    #[serde(default)]
    pub scopes: Option<String>,
    #[serde(default = "default_grant_type")]
    pub grant_type: String,
    #[serde(default = "default_callback_port")]
    pub callback_port: u16,
}

fn default_callback_port() -> u16 {
    9798
}

fn default_grant_type() -> String {
    "client_credentials".to_string()
}

/// Resolved hub configuration, with backends converted to BackendDef.
#[derive(Debug)]
pub struct HubConfig {
    pub auth: Option<AuthConfig>,
    pub backends: Vec<BackendDef>,
    /// HTTP expose blocks: port → filtered backends.
    /// If empty, serve uses stdio or single HTTP with all backends.
    pub expose: Vec<ExposeBlock>,
}

/// One HTTP listener exposing a subset of backends.
#[derive(Debug)]
pub struct ExposeBlock {
    pub port: u16,
    pub label: Option<String>,
    /// Backend IDs to include, with optional tool filters.
    pub backends: HashMap<String, ExposeBackendConfig>,
}

#[derive(Debug)]
pub struct ExposeBackendConfig {
    pub tools_allow: Vec<String>,
    pub tools_deny: Vec<String>,
}

#[derive(Debug)]
pub struct AuthConfig {
    pub hub_token: Option<String>,
    pub rate_limit: u32,
}

const ENV_PREFIX: &str = "{{env:";
const SECRET_PREFIX: &str = "{{secret:";
/// Backstop for a placeholder whose value expands to another placeholder
/// (`FOO="{{env:FOO}}"` would otherwise spin forever).
const MAX_RESOLVE_PASSES: usize = 16;

/// Resolve `{{env:VAR}}` and `{{secret:NAME}}` placeholders in a string.
///
/// An unset variable resolves to `{{unresolved:NAME}}` rather than an empty
/// string: these values are credentials, and silently substituting "" turns a
/// typo'd or missing variable into an empty client secret and a mystifying 401.
fn resolve_value(raw: &str) -> String {
    let mut result = raw.to_string();

    for _ in 0..MAX_RESOLVE_PASSES {
        let mut changed = false;

        // Try {{env:...}}
        if let Some(start) = result.find(ENV_PREFIX) {
            let end = match result[start..].find("}}") {
                Some(e) => start + e + 2,
                None => break,
            };
            let var_name = &result[start + ENV_PREFIX.len()..end - 2];
            let value = std::env::var(var_name)
                .unwrap_or_else(|_| format!("{{{{unresolved:{var_name}}}}}"));
            result.replace_range(start..end, &value);
            changed = true;
        }

        // Try {{secret:...}}
        if !changed {
            if let Some(start) = result.find(SECRET_PREFIX) {
                let end = match result[start..].find("}}") {
                    Some(e) => start + e + 2,
                    None => break,
                };
                let secret_name = &result[start + SECRET_PREFIX.len()..end - 2];
                let env_key = format!("HEADLESS_MCP_SECRET_{}", secret_name.to_uppercase());
                let value = std::env::var(&env_key).unwrap_or_else(|_| {
                    format!("{{{{unresolved:{secret_name}}}}}")
                });
                result.replace_range(start..end, &value);
                changed = true;
            }
        }

        if !changed {
            break;
        }
    }
    result
}

/// Config file discovery:
/// --config <path>           ← explicit, takes priority
/// ./headless-mcp.toml       ← cwd
/// ~/.config/headless-mcp/config.toml  ← user-level fallback
pub fn find_config_file(explicit: Option<&str>) -> Option<PathBuf> {
    if let Some(path) = explicit {
        let path = PathBuf::from(path);
        if path.exists() {
            return Some(path);
        }
    }

    let cwd_config = PathBuf::from("./headless-mcp.toml");
    if cwd_config.exists() {
        return Some(cwd_config);
    }

    if let Some(home) = dirs() {
        let user_config = home.join(".config").join("headless-mcp").join("config.toml");
        if user_config.exists() {
            return Some(user_config);
        }
    }

    None
}

fn dirs() -> Option<PathBuf> {
    std::env::var("HOME")
        .ok()
        .map(PathBuf::from)
}

/// Load and resolve the hub config.
pub fn load_config(explicit: Option<&str>) -> Result<HubConfig, Box<dyn std::error::Error>> {
    let config_path = find_config_file(explicit).ok_or_else(|| {
        "no config file found. Create one at ./headless-mcp.toml or ~/.config/headless-mcp/config.toml"
    })?;

    let raw = std::fs::read_to_string(&config_path)?;
    let raw_config: RawConfig = toml::from_str(&raw)?;

    // hub_token goes through resolve_value like every other credential. It was the
    // one field that did not, while docs/mcp.md documents
    // `hub_token = "{{env:HEADLESS_MCP_TOKEN}}"` as the way to set it — so the
    // placeholder was stored verbatim and became the expected bearer token.
    let auth = raw_config.auth.map(|a| AuthConfig {
        hub_token: a.hub_token.as_deref().map(resolve_value),
        rate_limit: a.rate_limit,
    });

    let mut backends = Vec::new();
    for (id, bc) in &raw_config.backends {
        let transport = match bc.transport.as_str() {
            "stdio" => {
                let command = bc
                    .command
                    .clone()
                    .ok_or_else(|| format!("backend '{id}': missing 'command' for stdio transport"))?;
                BackendTransport::Stdio {
                    command,
                    args: bc.args.clone(),
                    env: bc
                        .env
                        .iter()
                        .map(|(k, v)| (k.clone(), resolve_value(v)))
                        .collect(),
                    cwd: bc.cwd.clone(),
                }
            }
            "http" => {
                let url = bc
                    .url
                    .clone()
                    .ok_or_else(|| format!("backend '{id}': missing 'url' for http transport"))?;
                let oauth2 = bc.oauth2.as_ref().map(|o| headless_mcp_core::OAuth2Config {
                    token_endpoint: o.token_endpoint.clone(),
                    client_id: o.client_id.as_ref().map(|v| resolve_value(v)),
                    client_secret: o.client_secret.as_ref().map(|v| resolve_value(v)),
                    scopes: o.scopes.clone(),
                    grant_type: o.grant_type.clone(),
                    callback_port: o.callback_port,
                });
                BackendTransport::Http {
                    url,
                    bearer_token: bc.bearer_token.as_ref().map(|t| resolve_value(t)),
                    oauth2,
                }
            }
            other => {
                return Err(format!("backend '{id}': unknown transport '{other}'").into());
            }
        };

        let connection_mode = match bc.connection_mode.as_str() {
            "" | "eager" => ConnectionMode::Eager,
            "lazy" => ConnectionMode::Lazy,
            "per-call" | "per_call" => ConnectionMode::PerCall,
            other => {
                return Err(format!("backend '{id}': unknown connection_mode '{other}'").into());
            }
        };

        let stderr_mode = match bc.stderr_mode.as_str() {
            "" | "log-on-error" | "log_on_error" => StderrMode::LogOnError,
            "silent" => StderrMode::Silent,
            "passthrough" => StderrMode::Passthrough,
            "log-always" | "log_always" => StderrMode::LogAlways,
            other => {
                return Err(format!("backend '{id}': unknown stderr_mode '{other}'").into());
            }
        };

        backends.push(BackendDef {
            id: id.clone(),
            label: None,
            transport,
            namespace: bc.namespace.clone(),
            connection_mode,
            connect_timeout_secs: bc.connect_timeout_secs,
            call_timeout_secs: bc.call_timeout_secs,
            stderr_mode,
            tools_allow: bc.tools_allow.clone(),
            tools_deny: bc.tools_deny.clone(),
        });
    }

    // Resolve expose blocks
    let mut expose = Vec::new();
    for eb in &raw_config.expose {
        let mut eb_backends = HashMap::new();
        for (bid, ebc) in &eb.backends {
            eb_backends.insert(bid.clone(), ExposeBackendConfig {
                tools_allow: ebc.tools_allow.clone(),
                tools_deny: ebc.tools_deny.clone(),
            });
        }
        expose.push(ExposeBlock {
            port: eb.port,
            label: eb.label.clone(),
            backends: eb_backends,
        });
    }

    Ok(HubConfig { auth, backends, expose })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Each test uses a distinct variable name: cargo runs tests in threads that
    // share one process environment.

    #[test]
    fn env_placeholder_resolves() {
        std::env::set_var("HMCP_TEST_PLAIN", "sekrit");
        assert_eq!(resolve_value("{{env:HMCP_TEST_PLAIN}}"), "sekrit");
    }

    /// `{{secret:` is 9 characters; the name was read from offset 10, silently
    /// dropping its first letter, so `{{secret:NOTION}}` looked up
    /// HEADLESS_MCP_SECRET_OTION.
    #[test]
    fn secret_placeholder_keeps_the_first_letter_of_the_name() {
        std::env::set_var("HEADLESS_MCP_SECRET_HMCPNOTION", "notion-secret");
        assert_eq!(resolve_value("{{secret:HmcpNotion}}"), "notion-secret");
    }

    /// An unset variable must stay visible. Resolving to "" turned a typo into an
    /// empty credential and an unexplained 401 rather than a startup complaint.
    #[test]
    fn unset_env_var_is_reported_not_blanked() {
        assert_eq!(
            resolve_value("{{env:HMCP_TEST_DEFINITELY_UNSET}}"),
            "{{unresolved:HMCP_TEST_DEFINITELY_UNSET}}"
        );
    }

    #[test]
    fn placeholder_inside_surrounding_text_is_substituted_in_place() {
        std::env::set_var("HMCP_TEST_MID", "xyz");
        assert_eq!(resolve_value("a-{{env:HMCP_TEST_MID}}-b"), "a-xyz-b");
    }

    /// A variable whose value is its own placeholder must not spin forever.
    #[test]
    fn self_referential_placeholder_terminates() {
        std::env::set_var("HMCP_TEST_LOOP", "{{env:HMCP_TEST_LOOP}}");
        assert_eq!(resolve_value("{{env:HMCP_TEST_LOOP}}"), "{{env:HMCP_TEST_LOOP}}");
    }

    #[test]
    fn a_value_with_no_placeholder_is_untouched() {
        assert_eq!(resolve_value("literal-token"), "literal-token");
    }
}
