//! Binary entry point for `headless-mcp`: the standalone, programmatically-
//! configured MCP hub.
//!
//! Two modes, same binary, same config:
//!
//! - **Hub mode** (`headless-mcp` or `headless-mcp serve --http`): long-lived
//!   MCP aggregator. Agents connect to it. It fronts all backends.
//! - **One-shot mode** (`headless-mcp call <tool> --arg ...`): no daemon,
//!   no agent. Reads config, connects to the backend that owns the tool,
//!   calls it, prints the result, exits.

mod config;
mod one_shot;

use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use headless_mcp_core::BackendTransport;
use headless_mcp_registry::BackendRegistry;
use headless_mcp_server::{McpSession, TracingAuditLogger};

use config::load_config;
use one_shot::run_one_shot;

const DEFAULT_HTTP_BIND: &str = "127.0.0.1:9797";
const DEFAULT_RATE_LIMIT: u32 = 120;

#[derive(Parser)]
#[command(name = "headless-mcp", version, about = "A standalone MCP hub")]
struct Cli {
    /// Config file path
    #[arg(short = 'c', long = "config")]
    config: Option<String>,

    /// Enable verbose logging
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,

    /// Dry-run: load config, connect all eager backends, print tool list, exit
    #[arg(long = "dry-run")]
    dry_run: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the long-lived hub daemon
    Serve {
        /// Expose as HTTP+SSE MCP endpoint
        #[arg(long)]
        http: bool,

        /// HTTP bind address (default: 127.0.0.1:9797)
        #[arg(long)]
        bind: Option<String>,

        /// HTTP port (default: 9797)
        #[arg(long, default_value = "9797")]
        port: u16,
    },
    /// One-shot: call a tool and print the result
    Call {
        /// The tool to call, e.g. "slack.send_message"
        tool: String,

        /// Arguments as key=value pairs
        #[arg(short = 'a', long = "arg")]
        args: Vec<String>,

        /// JSON arguments
        #[arg(long = "json")]
        json: Option<String>,

        /// Output format: pretty, json, table
        #[arg(short = 'f', long = "format", default_value = "pretty")]
        format: String,
    },
    /// One-shot: list all aggregated tools
    Tools {
        /// Only show tools from this server
        #[arg(long)]
        server: Option<String>,
    },
    /// Print the resolved config
    Config,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let config_path = cli.config.as_deref();

    let env_filter = if cli.verbose {
        tracing_subscriber::EnvFilter::new("debug")
    } else {
        tracing_subscriber::EnvFilter::from_default_env()
    };

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .init();

    match cli.command {
        Some(Commands::Serve { http, bind, port }) => {
            let bind_addr = if let Some(bind_str) = bind {
                match bind_str.parse::<SocketAddr>() {
                    Ok(addr) => addr,
                    Err(_) => {
                        format!("{bind_str}:{port}")
                            .parse()
                            .unwrap_or_else(|_| format!("{DEFAULT_HTTP_BIND}").parse().unwrap())
                    }
                }
            } else {
                format!("127.0.0.1:{port}")
                    .parse()
                    .unwrap_or_else(|_| DEFAULT_HTTP_BIND.parse().unwrap())
            };

            if let Err(e) = run_serve(http, config_path, bind_addr).await {
                tracing::error!(%e, "server exited with error");
                return ExitCode::FAILURE;
            }
        }
        Some(Commands::Call {
            tool,
            args,
            json,
            format,
        }) => {
            if let Err(e) = run_one_shot(&tool, &args, json.as_deref(), &format, config_path).await
            {
                tracing::error!(%e, "call failed");
                return ExitCode::FAILURE;
            }
        }
        Some(Commands::Tools { .. }) => {
            if let Err(e) = run_list_tools(config_path).await {
                tracing::error!(%e, "tools list failed");
                return ExitCode::FAILURE;
            }
        }
        Some(Commands::Config) => {
            run_print_config(config_path);
        }
        None if cli.dry_run => {
            if let Err(e) = run_dry_run(config_path).await {
                tracing::error!(%e, "dry-run failed");
                return ExitCode::FAILURE;
            }
        }
        None => {
            // Default: serve via stdio
            if let Err(e) = run_serve(false, config_path, DEFAULT_HTTP_BIND.parse().unwrap()).await
            {
                tracing::error!(%e, "server exited with error");
                return ExitCode::FAILURE;
            }
        }
    }

    ExitCode::SUCCESS
}

async fn run_serve(
    http: bool,
    config_path: Option<&str>,
    bind_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let hub_config = load_config(config_path)?;
    let registry = build_registry(&hub_config).await?;

    // Connect all eager backends
    let results = registry.connect_all().await;
    for (id, result) in &results {
        match result {
            Ok(()) => tracing::info!(backend_id = %id, "connected"),
            Err(e) => tracing::warn!(backend_id = %id, error = %e, "failed to connect eager backend"),
        }
    }

    let session = Arc::new(McpSession::new(
        Arc::new(registry),
        Arc::new(TracingAuditLogger),
    ));

    if http {
        let bearer_token = match &hub_config.auth {
            Some(auth) => auth
                .hub_token
                .clone()
                .unwrap_or_else(|| std::env::var("HEADLESS_MCP_TOKEN").unwrap_or_default()),
            None => std::env::var("HEADLESS_MCP_TOKEN").unwrap_or_else(|_| {
                tracing::warn!("HEADLESS_MCP_TOKEN not set; HTTP mode will accept any token (insecure)");
                String::new()
            }),
        };

        let rate_limit = hub_config
            .auth
            .as_ref()
            .map(|a| a.rate_limit)
            .unwrap_or(DEFAULT_RATE_LIMIT);

        let transport_config = headless_mcp_transport_http::HttpTransportConfig {
            bind_addr,
            bearer_token,
            rate_limit_per_minute: rate_limit,
        };

        tracing::info!("headless-mcp hub starting on HTTP");
        headless_mcp_transport_http::run_http(session, transport_config).await?;
    } else {
        tracing::info!("headless-mcp hub starting on stdio");
        headless_mcp_transport_stdio::run_stdio(session).await?;
    }

    Ok(())
}

async fn run_list_tools(config_path: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let hub_config = load_config(config_path)?;
    let registry = build_registry(&hub_config).await?;

    let results = registry.connect_all().await;
    for (id, result) in &results {
        match result {
            Ok(()) => tracing::info!(backend_id = %id, "connected"),
            Err(e) => tracing::warn!(backend_id = %id, error = %e, "failed to connect"),
        }
    }

    let tools = registry.aggregated_tools();
    if tools.is_empty() {
        println!("No tools available (no backends connected).");
    } else {
        for tool in &tools {
            println!("  {}", tool.name);
            println!("    {}", tool.description);
        }
    }

    Ok(())
}

async fn run_dry_run(config_path: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!("dry-run: loading config and connecting eager backends...");

    let hub_config = load_config(config_path)?;
    tracing::info!("config loaded with {} backends", hub_config.backends.len());

    let registry = build_registry(&hub_config).await?;

    let results = registry.connect_all().await;
    let mut exit_code = 0;
    for (id, result) in &results {
        match result {
            Ok(()) => tracing::info!(backend_id = %id, "connected"),
            Err(e) => {
                tracing::error!(backend_id = %id, error = %e, "failed to connect");
                exit_code = 1;
            }
        }
    }

    let tools = registry.aggregated_tools();
    tracing::info!(tool_count = tools.len(), "aggregated tools:");
    for tool in &tools {
        println!("  {}", tool.name);
    }

    if exit_code != 0 {
        return Err("one or more eager backends failed to connect".into());
    }

    Ok(())
}

fn run_print_config(config_path: Option<&str>) {
    match load_config(config_path) {
        Ok(hub_config) => {
            println!("Backends ({})", hub_config.backends.len());
            for def in &hub_config.backends {
                let transport_str = match &def.transport {
                    BackendTransport::Stdio { command, .. } => {
                        format!("stdio ({command})")
                    }
                    BackendTransport::Http { url, .. } => {
                        format!("http ({url})")
                    }
                };
                let ns = def.namespace.as_deref().unwrap_or("<none>");
                println!(
                    "  {:<20} transport: {:<40} namespace: {:<15} mode: {:?}",
                    def.id, transport_str, ns, def.connection_mode
                );
            }
            if let Some(auth) = &hub_config.auth {
                println!("Auth: token={}, rate_limit={}", 
                    auth.hub_token.as_deref().map(|_| "<set>").unwrap_or("<none>"),
                    auth.rate_limit);
            }
        }
        Err(e) => {
            eprintln!("Failed to load config: {e}");
        }
    }
}

async fn build_registry(
    hub_config: &config::HubConfig,
) -> Result<BackendRegistry, Box<dyn std::error::Error>> {
    let registry = BackendRegistry::new();

    for def in &hub_config.backends {
        let backend: Arc<dyn headless_mcp_core::McpBackend> = match &def.transport {
            BackendTransport::Stdio { .. } => {
                Arc::new(headless_mcp_backend_stdio::StdioBackend::new(def.clone()))
            }
            BackendTransport::Http { .. } => {
                Arc::new(headless_mcp_backend_http::HttpBackend::new(def.clone()))
            }
        };

        registry.register(def.clone(), backend).await?;
    }

    Ok(registry)
}
