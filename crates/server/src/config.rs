use headless_mcp_core::{BackendDef, BackendTransport, ConnectionMode, StderrMode};
use headless_mcp_vpn::VpnDef;
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
    #[serde(default)]
    pub vpn: HashMap<String, RawVpnConfig>,
}

/// `[vpn.<name>]`: fixed commands only. Nothing here can be supplied by a caller.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawVpnConfig {
    pub health: Vec<String>,
    #[serde(default)]
    pub healthy_if: Vec<String>,
    #[serde(default)]
    pub needs_login_if: Vec<String>,
    #[serde(default)]
    pub expiry: Option<Vec<String>>,
    pub login: Vec<String>,
    #[serde(default = "default_url_prefixes")]
    pub url_prefixes: Vec<String>,
    #[serde(default = "default_vpn_check_interval")]
    pub check_interval_secs: u64,
    #[serde(default = "default_vpn_command_timeout")]
    pub command_timeout_secs: u64,
    #[serde(default = "default_vpn_url_wait")]
    pub url_wait_secs: u64,
    #[serde(default = "default_vpn_login_timeout")]
    pub login_timeout_secs: u64,
    #[serde(default)]
    pub callback_ports: Vec<u16>,
}

fn default_url_prefixes() -> Vec<String> {
    vec!["https://".to_string()]
}
fn default_vpn_check_interval() -> u64 {
    60
}
fn default_vpn_command_timeout() -> u64 {
    15
}
fn default_vpn_url_wait() -> u64 {
    30
}
fn default_vpn_login_timeout() -> u64 {
    600
}

#[derive(Debug, Deserialize)]
pub struct RawExposeBlock {
    pub port: u16,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub backends: HashMap<String, RawExposeBackend>,
    /// VPNs whose `hub.vpn_status` / `hub.vpn_login` tools this port exposes.
    #[serde(default)]
    pub vpn: Vec<String>,
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
    #[serde(default)]
    pub requires_vpn: Vec<String>,
    #[serde(default)]
    pub pin_args: toml::Table,
    #[serde(default)]
    pub deny_args: Vec<String>,
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
    pub vpn: Vec<VpnDef>,
}

/// One HTTP listener exposing a subset of backends.
#[derive(Debug)]
pub struct ExposeBlock {
    pub port: u16,
    pub label: Option<String>,
    /// Backend IDs to include, with optional tool filters.
    pub backends: HashMap<String, ExposeBackendConfig>,
    /// VPN names whose hub tools are exposed on this port.
    pub vpn: Vec<String>,
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

    let mut vpn = Vec::new();
    for (name, vc) in &raw_config.vpn {
        if vc.health.is_empty() || vc.login.is_empty() {
            return Err(format!("vpn '{name}': 'health' and 'login' must be non-empty commands").into());
        }
        if vc.expiry.as_ref().is_some_and(|c| c.is_empty()) {
            return Err(format!("vpn '{name}': 'expiry' must be a non-empty command").into());
        }
        vpn.push(VpnDef {
            name: name.clone(),
            health: vc.health.clone(),
            healthy_if: vc.healthy_if.clone(),
            needs_login_if: vc.needs_login_if.clone(),
            expiry: vc.expiry.clone(),
            login: vc.login.clone(),
            url_prefixes: vc.url_prefixes.clone(),
            check_interval_secs: vc.check_interval_secs,
            command_timeout_secs: vc.command_timeout_secs,
            url_wait_secs: vc.url_wait_secs,
            login_timeout_secs: vc.login_timeout_secs,
            callback_ports: vc.callback_ports.clone(),
        });
    }
    let check_vpn = |owner: String, names: &[String]| -> Result<(), String> {
        match names.iter().find(|n| !raw_config.vpn.contains_key(n.as_str())) {
            Some(n) => Err(format!("{owner}: unknown vpn '{n}' (no [vpn.{n}] section)")),
            None => Ok(()),
        }
    };

    let mut backends = Vec::new();
    for (id, bc) in &raw_config.backends {
        check_vpn(format!("backend '{id}'"), &bc.requires_vpn)?;
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
            requires_vpn: bc.requires_vpn.clone(),
            pin_args: match serde_json::to_value(&bc.pin_args)? {
                serde_json::Value::Object(map) => map,
                _ => serde_json::Map::new(),
            },
            deny_args: bc.deny_args.clone(),
        });
    }

    // Resolve expose blocks
    let mut expose = Vec::new();
    for eb in &raw_config.expose {
        check_vpn(format!("expose port {}", eb.port), &eb.vpn)?;
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
            vpn: eb.vpn.clone(),
        });
    }

    Ok(HubConfig { auth, backends, expose, vpn })
}
