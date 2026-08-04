use headless_mcp_core::{BackendDef, BackendTransport, ConnectionMode, StderrMode};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

/// Raw deserialized config from the TOML file.
#[derive(Debug, Deserialize)]
struct RawConfig {
    #[serde(default)]
    pub auth: Option<RawAuthConfig>,
    #[serde(default)]
    pub backends: HashMap<String, RawBackendConfig>,
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
}

fn default_connect_timeout() -> u64 {
    10
}
fn default_call_timeout() -> u64 {
    30
}

/// Resolved hub configuration, with backends converted to BackendDef.
#[derive(Debug)]
pub struct HubConfig {
    pub auth: Option<AuthConfig>,
    pub backends: Vec<BackendDef>,
}

#[derive(Debug)]
pub struct AuthConfig {
    pub hub_token: Option<String>,
    pub rate_limit: u32,
}

/// Resolve `{{env:VAR}}` and `{{secret:NAME}}` placeholders in a string.
fn resolve_value(raw: &str) -> String {
    let mut result = raw.to_string();
    let mut changed = true;
    while changed {
        changed = false;

        // Try {{env:...}}
        if let Some(start) = result.find("{{env:") {
            let end = match result[start..].find("}}") {
                Some(e) => start + e + 2,
                None => break,
            };
            let var_name = &result[start + 6..end - 2];
            let value = std::env::var(var_name).unwrap_or_default();
            result.replace_range(start..end, &value);
            changed = true;
        }

        // Try {{secret:...}}
        if !changed {
            if let Some(start) = result.find("{{secret:") {
                let end = match result[start..].find("}}") {
                    Some(e) => start + e + 2,
                    None => break,
                };
                let secret_name = &result[start + 10..end - 2];
                let env_key = format!("HEADLESS_MCP_SECRET_{}", secret_name.to_uppercase());
                let value = std::env::var(&env_key).unwrap_or_else(|_| {
                    format!("{{{{unresolved:{secret_name}}}}}")
                });
                result.replace_range(start..end, &value);
                changed = true;
            }
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

    let auth = raw_config.auth.map(|a| AuthConfig {
        hub_token: a.hub_token,
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
                BackendTransport::Http {
                    url,
                    bearer_token: bc.bearer_token.as_ref().map(|t| resolve_value(t)),
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
        });
    }

    Ok(HubConfig { auth, backends })
}
