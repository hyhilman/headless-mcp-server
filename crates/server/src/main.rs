//! Binary entry point for `headless-mcp`: the standalone, programmatically-
//! configured MCP hub.

mod config;
mod one_shot;

use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use headless_mcp_core::{BackendTransport, McpBackend};
use headless_mcp_registry::BackendRegistry;
use headless_mcp_server::{McpSession, TracingAuditLogger};
use headless_mcp_secrets::EncryptedFileSecretStore;

use config::load_config;
use one_shot::run_one_shot;

const DEFAULT_HTTP_BIND: &str = "127.0.0.1:9797";
const DEFAULT_RATE_LIMIT: u32 = 120;

#[derive(Parser)]
#[command(name = "headless-mcp", version, about = "A standalone MCP hub")]
struct Cli {
    #[arg(short = 'c', long = "config")] config: Option<String>,
    #[arg(short = 'v', long = "verbose")] verbose: bool,
    #[arg(long = "dry-run")] dry_run: bool,
    #[command(subcommand)] command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Serve {
        #[arg(long)] http: bool,
        #[arg(long)] bind: Option<String>,
        #[arg(long, default_value = "9797")] port: u16,
    },
    Call {
        tool: String,
        #[arg(short = 'a', long = "arg")] args: Vec<String>,
        #[arg(long = "json")] json: Option<String>,
        #[arg(short = 'f', long = "format", default_value = "pretty")] format: String,
    },
    Tools { #[arg(long)] server: Option<String> },
    Config,
    Auth { backend: Option<String> },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let config_path = cli.config.as_deref();
    let env_filter = if cli.verbose { tracing_subscriber::EnvFilter::new("debug") } else { tracing_subscriber::EnvFilter::from_default_env() };
    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    let token_store = build_token_store();

    let result = match cli.command {
        Some(Commands::Serve { http, bind, port }) => {
            run_serve(http, config_path, bind_addr(bind, port), token_store).await
        }
        Some(Commands::Call { tool, args, json, format }) => {
            run_one_shot(&tool, &args, json.as_deref(), &format, config_path).await
        }
        Some(Commands::Tools { .. }) => run_list_tools(config_path, token_store).await,
        Some(Commands::Config) => { run_print_config(config_path); Ok(()) }
        Some(Commands::Auth { backend }) => run_auth(config_path, backend, token_store).await,
        None if cli.dry_run => run_dry_run(config_path, token_store).await,
        None => run_serve(false, config_path, bind_addr(None, 9797), token_store).await,
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => { tracing::error!(%e, "failed"); ExitCode::FAILURE }
    }
}

fn bind_addr(bind: Option<String>, port: u16) -> SocketAddr {
    if let Some(b) = bind { if let Ok(a) = b.parse() { return a; } }
    format!("127.0.0.1:{port}").parse().unwrap()
}

fn build_token_store() -> Option<Arc<EncryptedFileSecretStore>> {
    let data_dir = std::env::var("HEADLESS_MCP_DATA_DIR").unwrap_or_else(|_| ".".into());
    let path = std::path::Path::new(&data_dir).join("secrets.json");
    match EncryptedFileSecretStore::from_env(path) {
        Ok(s) => { tracing::debug!("token store ready"); Some(Arc::new(s)) }
        Err(headless_mcp_secrets::SecretError::MissingMasterKey) => { tracing::warn!("HEADLESS_MCP_MASTER_KEY not set"); None }
        Err(e) => { tracing::warn!(%e, "token store init failed"); None }
    }
}

async fn run_serve(http: bool, config_path: Option<&str>, bind_addr: SocketAddr, store: Option<Arc<EncryptedFileSecretStore>>) -> Result<(), Box<dyn std::error::Error>> {
    let cfg = load_config(config_path)?;
    let reg = build_registry(&cfg, store).await?;
    for (id, r) in &reg.connect_all().await {
        if let Err(e) = r { tracing::warn!(%id, %e, "connect failed"); }
    }
    let session = Arc::new(McpSession::new(Arc::new(reg), Arc::new(TracingAuditLogger)));
    if http {
        let token = cfg.auth.as_ref().and_then(|a| a.hub_token.clone()).unwrap_or_else(|| std::env::var("HEADLESS_MCP_TOKEN").unwrap_or_default());
        headless_mcp_transport_http::run_http(session, headless_mcp_transport_http::HttpTransportConfig {
            bind_addr, bearer_token: token, rate_limit_per_minute: DEFAULT_RATE_LIMIT,
        }).await?;
    } else {
        headless_mcp_transport_stdio::run_stdio(session).await?;
    }
    Ok(())
}

async fn run_list_tools(config_path: Option<&str>, store: Option<Arc<EncryptedFileSecretStore>>) -> Result<(), Box<dyn std::error::Error>> {
    let reg = build_registry(&load_config(config_path)?, store).await?;
    for (id, r) in &reg.connect_all().await {
        if let Err(e) = r { tracing::warn!(%id, %e, "connect failed"); }
    }
    let tools = reg.aggregated_tools();
    for t in &tools { println!("  {}\n    {}", t.name, t.description); }
    if tools.is_empty() { println!("No tools available."); }
    Ok(())
}

async fn run_dry_run(config_path: Option<&str>, store: Option<Arc<EncryptedFileSecretStore>>) -> Result<(), Box<dyn std::error::Error>> {
    let reg = build_registry(&load_config(config_path)?, store).await?;
    let mut failed = 0;
    for (id, r) in &reg.connect_all().await {
        match r { Ok(()) => tracing::info!(%id, "connected"), Err(e) => { tracing::error!(%id, %e, "failed"); failed += 1; } }
    }
    for t in &reg.aggregated_tools() { println!("  {}", t.name); }
    if failed > 0 { Err("some backends failed".into()) } else { Ok(()) }
}

fn run_print_config(config_path: Option<&str>) {
    if let Ok(c) = load_config(config_path) {
        for def in &c.backends {
            let ts = match &def.transport { BackendTransport::Stdio{command,..} => format!("stdio({command})"), BackendTransport::Http{url,..} => format!("http({url})") };
            println!("  {:<20} {:<40} ns={}", def.id, ts, def.namespace.as_deref().unwrap_or("<none>"));
        }
    }
}

async fn build_registry(config: &config::HubConfig, store: Option<Arc<EncryptedFileSecretStore>>) -> Result<BackendRegistry, Box<dyn std::error::Error>> {
    let reg = BackendRegistry::new();
    for def in &config.backends {
        let b: Arc<dyn McpBackend> = match &def.transport {
            BackendTransport::Stdio { .. } => Arc::new(headless_mcp_backend_stdio::StdioBackend::new(def.clone())),
            BackendTransport::Http { .. } => Arc::new(headless_mcp_backend_http::HttpBackend::with_store(def.clone(), store.clone(), true)),
        };
        reg.register(def.clone(), b).await?;
    }
    Ok(reg)
}

async fn run_auth(config_path: Option<&str>, target: Option<String>, store: Option<Arc<EncryptedFileSecretStore>>) -> Result<(), Box<dyn std::error::Error>> {
    let cfg = load_config(config_path)?;
    let backends: Vec<_> = cfg.backends.iter().filter(|d| matches!(&d.transport, BackendTransport::Http { oauth2: Some(_), .. })).collect();
    if backends.is_empty() { println!("No OAuth2 backends."); return Ok(()); }
    match target {
        Some(ref t) if t == "--all" => {
            for d in &backends { auth_one(d, store.clone()).await?; }
        }
        Some(id) => {
            let d = backends.iter().find(|d| d.id == id).ok_or_else(|| format!("no such backend: {id}"))?;
            auth_one(d, store).await?;
        }
        None => {
            for (i,d) in backends.iter().enumerate() { println!("  [{}] {}", i+1, d.id); }
            println!("Run 'auth <id>' or 'auth --all'");
        }
    }
    Ok(())
}

async fn auth_one(def: &headless_mcp_core::BackendDef, store: Option<Arc<EncryptedFileSecretStore>>) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n═══ Authenticating '{}' ═══", def.id);
    let b = headless_mcp_backend_http::HttpBackend::with_store(def.clone(), store.clone(), false);
    let b: Arc<dyn McpBackend> = Arc::new(b);
    match b.connect().await {
        Ok(init) => {
            println!("✅ Connected to {} ({})", def.id, init.server_info.name);
            if let Ok(tools) = b.list_tools().await {
                println!("   {} tools:", tools.len());
                for t in &tools { println!("   • {}.{}", def.namespace.as_deref().unwrap_or(""), t.name); }
            }
        }
        Err(e) => { eprintln!("❌ {}: {}", def.id, e); }
    }
    if store.is_some() { println!("   Token persisted."); }
    Ok(())
}
