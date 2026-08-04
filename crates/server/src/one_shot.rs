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
) -> Result<(), Box<dyn std::error::Error>> {
    let hub_config = load_config()?;

    // Parse a dot-separated tool name to find the backend
    // e.g. "slack.send_message" → backend "slack", tool "send_message"
    let (backend_id, downstream_name) = parse_tool_name(tool_name);

    // Find the backend definition
    let def = hub_config
        .backends
        .iter()
        .find(|d| d.id == backend_id)
        .ok_or_else(|| format!("no backend configured with id '{backend_id}'"))?;

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

    // Connect to the backend
    let backend = connect_to_backend(def, backend_id.as_str())?;
    backend.connect().await?;

    // Call the tool
    let timeout = Duration::from_secs(def.call_timeout_secs);
    let result = backend
        .call_tool(downstream_name.as_str(), arguments, timeout)
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
            // pretty: same as json for now
            let json_str =
                serde_json::to_string_pretty(&result).map_err(|e| format!("serialize: {e}"))?;
            println!("{json_str}");
        }
    }

    backend.disconnect().await?;
    Ok(())
}

/// Parse "slack.send_message" → ("slack", "send_message")
fn parse_tool_name(tool_name: &str) -> (String, String) {
    match tool_name.split_once('.') {
        Some((backend, tool)) => (backend.to_string(), tool.to_string()),
        None => {
            // No dot: assume the tool name IS the exposed name without namespace
            // This means we need to search all backends.
            // For now, just use the whole string as both
            (tool_name.to_string(), tool_name.to_string())
        }
    }
}

/// A lightweight one-shot stdio backend that connects just for a single call.
/// This uses the same StdioBackend from backend-stdio but wraps it for
/// one-shot use.
fn connect_to_backend(
    def: &BackendDef,
    backend_id: &str,
) -> Result<Box<dyn McpBackend>, Box<dyn std::error::Error>> {
    match &def.transport {
        BackendTransport::Stdio { .. } => {
            Ok(Box::new(headless_mcp_backend_stdio::StdioBackend::new(
                def.clone(),
            )))
        }
        BackendTransport::Http { .. } => Err(
            "HTTP backends are not yet implemented (Phase 2)".into(),
        ),
    }
}

fn print_table(value: &Value) -> Result<(), Box<dyn std::error::Error>> {
    match value {
        Value::Array(rows) => {
            if rows.is_empty() {
                println!("(empty)");
                return Ok(());
            }
            // Extract keys from the first row
            if let Some(first) = rows.first() {
                if let Some(obj) = first.as_object() {
                    let keys: Vec<&str> = obj.keys().map(|k| k.as_str()).collect();
                    // Print header
                    let header = keys
                        .iter()
                        .map(|k| format!("{:<20}", k))
                        .collect::<Vec<_>>()
                        .join(" | ");
                    println!("{header}");
                    println!("{}", "-".repeat(header.len()));

                    // Print rows
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
