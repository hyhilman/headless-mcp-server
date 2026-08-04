use headless_mcp_core::{BackendDef, BackendTransport, McpBackend};
use serde_json::Value;
use std::time::Duration;

use crate::config::load_config;

/// Run a one-shot tool call: load config, find the backend that owns the
/// tool, connect, call, print, exit.
pub async fn run_one_shot(
    tool_name: &str,
    args: &[String],
    json_args: Option<&str>,
    format: &str,
    config_path: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let hub_config = load_config(config_path)?;

    // Parse a dot-separated tool name to guess the backend
    // e.g. "slack.send_message" → backend could be "slack" if namespace matches
    let (namespace_hint, _downstream_name) = parse_tool_name(tool_name);

    // Parse arguments
    let arguments = if let Some(json_str) = json_args {
        Some(
            serde_json::from_str::<Value>(json_str)
                .map_err(|e| format!("invalid JSON arguments: {e}"))?,
        )
    } else if !args.is_empty() {
        let mut map = serde_json::Map::new();
        for arg in args {
            let (key, value) = arg
                .split_once('=')
                .ok_or_else(|| format!("arguments must be key=value pairs, got: '{arg}'"))?;
            map.insert(key.to_string(), Value::String(value.to_string()));
        }
        Some(Value::Object(map))
    } else {
        None
    };

    // Search all stdio backends for the tool.
    // First, try backends whose namespace matches the tool prefix.
    // Then fall back to trying all backends.
    let mut found_backend: Option<(&BackendDef, String)> = None;

    for def in &hub_config.backends {
        // If the tool has a namespace hint and it matches this backend's
        // namespace, try it first.
        let downstream_name = if let Some(ns) = &def.namespace {
            if let Some(hint) = namespace_hint {
                if hint != ns {
                    // Namespace hint doesn't match — this backend probably
                    // doesn't own this tool, skip for now
                    continue;
                }
            }
            // Strip the namespace prefix to get the downstream tool name
            match tool_name.strip_prefix(&format!("{ns}.")) {
                Some(name) => name.to_string(),
                None => continue,
            }
        } else {
            // No namespace — tool name is bare
            tool_name.to_string()
        };

        // Connect, check if the tool exists, call it
        let backend = connect_stdio_backend(def)?;
        if let Err(e) = backend.connect().await {
            tracing::warn!(backend_id = %def.id, %e, "failed to connect for one-shot; skipping");
            continue;
        }

        // Quick check: list tools and see if ours is there
        match backend.list_tools().await {
            Ok(tools) => {
                if tools.iter().any(|t| t.name == downstream_name) {
                    found_backend = Some((def, downstream_name));
                    // We'll keep this connection and use it below
                    break;
                }
            }
            Err(e) => {
                tracing::warn!(backend_id = %def.id, %e, "failed to list tools; skipping");
            }
        }
        let _ = backend.disconnect().await;
    }

    let (def, downstream_name) = found_backend
        .ok_or_else(|| format!("no backend found that owns tool '{tool_name}'"))?;

    // Connect and call
    let backend = connect_stdio_backend(def)?;
    backend.connect().await?;

    let timeout = Duration::from_secs(def.call_timeout_secs);
    let result = backend
        .call_tool(&downstream_name, arguments, timeout)
        .await
        .map_err(|e| format!("tool call failed: {e}"))?;

    // Print the result
    match format {
        "json" => {
            let json_str =
                serde_json::to_string_pretty(&result).map_err(|e| format!("serialize: {e}"))?;
            println!("{json_str}");
        }
        "table" => {
            print_table(&result)?;
        }
        _ => {
            let json_str =
                serde_json::to_string_pretty(&result).map_err(|e| format!("serialize: {e}"))?;
            println!("{json_str}");
        }
    }

    backend.disconnect().await?;
    Ok(())
}

/// Parse "slack.send_message" → (Some("slack"), "send_message")
/// Parse "bare_tool" → (None, "bare_tool")
fn parse_tool_name(tool_name: &str) -> (Option<&str>, &str) {
    match tool_name.split_once('.') {
        Some((prefix, rest)) => (Some(prefix), rest),
        None => (None, tool_name),
    }
}

fn connect_stdio_backend(def: &BackendDef) -> Result<Box<dyn McpBackend>, Box<dyn std::error::Error>> {
    match &def.transport {
        BackendTransport::Stdio { .. } => {
            Ok(Box::new(headless_mcp_backend_stdio::StdioBackend::new(
                def.clone(),
            )))
        }
        BackendTransport::Http { .. } => {
            Ok(Box::new(headless_mcp_backend_http::HttpBackend::new(
                def.clone(),
            )))
        }
    }
}

fn print_table(value: &Value) -> Result<(), Box<dyn std::error::Error>> {
    match value {
        Value::Array(rows) => {
            if rows.is_empty() {
                println!("(empty)");
                return Ok(());
            }
            if let Some(first) = rows.first() {
                if let Some(obj) = first.as_object() {
                    let keys: Vec<&str> = obj.keys().map(|k| k.as_str()).collect();
                    let header = keys
                        .iter()
                        .map(|k| format!("{:<20}", k))
                        .collect::<Vec<_>>()
                        .join(" | ");
                    println!("{header}");
                    println!("{}", "-".repeat(header.len()));

                    for row in rows {
                        let vals: Vec<String> = keys
                            .iter()
                            .map(|k| {
                                let v = row.get(*k).map(|v| format_value(v)).unwrap_or_default();
                                format!("{:<20}", v)
                            })
                            .collect();
                        println!("{}", vals.join(" | "));
                    }
                } else {
                    println!("{}", serde_json::to_string_pretty(value)?);
                }
            }
        }
        _ => {
            println!("{}", serde_json::to_string_pretty(value)?);
        }
    }
    Ok(())
}

fn format_value(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        Value::Array(arr) => serde_json::to_string(arr).unwrap_or_default(),
        Value::Object(obj) => serde_json::to_string(obj).unwrap_or_default(),
    }
}
