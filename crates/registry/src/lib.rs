#![forbid(unsafe_code)]

//! Backend registry: tool aggregation, namespacing, route dispatch,
//! health checks, reconnect with exponential backoff, and connection modes.

use headless_mcp_core::{
    BackendDef, BackendError, BackendErrorKind, ConnectionMode, McpBackend, ToolDescriptor,
};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::time::MissedTickBehavior;

const HEALTH_CHECK_INTERVAL_SECS: u64 = 30;
const RECONNECT_BASE_DELAY_MS: u64 = 1000;
const RECONNECT_MAX_DELAY_MS: u64 = 60000;

/// Holds a registered backend and its metadata.
struct BackendHandle {
    def: BackendDef,
    backend: Arc<dyn McpBackend>,
    health: AtomicBool,
    /// For eager/lazy backends: current reconnect attempt count (for backoff)
    reconnect_attempts: std::sync::Mutex<u32>,
}

/// Manages a set of MCP backends, their tools, and route dispatch.
pub struct BackendRegistry {
    backends: RwLock<HashMap<String, BackendHandle>>,
    tool_index: RwLock<HashMap<String, RoutedTool>>,
    health_check_handle: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

#[derive(Debug, Clone)]
pub struct RoutedTool {
    pub backend_id: String,
    pub exposed_name: String,
    pub downstream_name: String,
    pub descriptor: ToolDescriptor,
}

impl BackendRegistry {
    pub fn new() -> Self {
        Self {
            backends: RwLock::new(HashMap::new()),
            tool_index: RwLock::new(HashMap::new()),
            health_check_handle: std::sync::Mutex::new(None),
        }
    }

    /// Register a backend from its definition and a constructed [`McpBackend`].
    pub async fn register(
        &self,
        def: BackendDef,
        backend: Arc<dyn McpBackend>,
    ) -> Result<(), BackendError> {
        let id = def.id.clone();

        let handle = BackendHandle {
            def,
            backend,
            health: AtomicBool::new(false),
            reconnect_attempts: std::sync::Mutex::new(0),
        };

        let mut backends = self.backends.write().unwrap();
        if backends.contains_key(&id) {
            return Err(BackendError::new(
                BackendErrorKind::Internal,
                format!("backend '{id}' is already registered"),
            ));
        }
        backends.insert(id.clone(), handle);

        tracing::info!(%id, "backend registered");
        Ok(())
    }

    /// Remove a backend and all its tools.
    pub async fn unregister(&self, id: &str) -> Result<(), BackendError> {
        let handle = {
            let mut backends = self.backends.write().unwrap();
            backends.remove(id).ok_or_else(|| {
                BackendError::new(
                    BackendErrorKind::Internal,
                    format!("backend '{id}' is not registered"),
                )
            })?
        };

        let mut tool_index = self.tool_index.write().unwrap();
        tool_index.retain(|_, routed| routed.backend_id != id);

        handle.backend.disconnect().await?;

        tracing::info!(%id, "backend unregistered");
        Ok(())
    }

    /// Connect all eager backends. Returns results per backend.
    pub async fn connect_all(&self) -> Vec<(String, Result<(), BackendError>)> {
        let backends = self.backends.read().unwrap();
        let ids: Vec<String> = backends
            .iter()
            .filter(|(_, h)| matches!(h.def.connection_mode, ConnectionMode::Eager))
            .map(|(id, _)| id.clone())
            .collect();
        drop(backends);

        let mut results = Vec::new();
        for id in ids {
            let result = self.connect_backend(&id).await;
            results.push((id, result));
        }
        results
    }

    /// Connect a specific backend and index its tools.
    async fn connect_backend(&self, id: &str) -> Result<(), BackendError> {
        let (backend, namespace, _connection_mode, tools_allow, tools_deny) = {
            let backends = self.backends.read().unwrap();
            let handle = backends.get(id).ok_or_else(|| {
                BackendError::new(
                    BackendErrorKind::Internal,
                    format!("backend '{id}' is not registered"),
                )
            })?;
            (
                handle.backend.clone(),
                handle.def.namespace.clone(),
                handle.def.connection_mode,
                handle.def.tools_allow.clone(),
                handle.def.tools_deny.clone(),
            )
        };

        // Full MCP handshake
        backend.connect().await?;

        // Fetch tools
        let mut tools = backend.list_tools().await?;

        // Apply allow/deny filter from backend config
        if !tools_allow.is_empty() {
            tools.retain(|t| tools_allow.iter().any(|a| a == &t.name));
        }
        if !tools_deny.is_empty() {
            tools.retain(|t| !tools_deny.iter().any(|d| d == &t.name));
        }

        // Index tools with namespace prefix
        let mut tool_index = self.tool_index.write().unwrap();

        // Remove old entries for this backend
        tool_index.retain(|_, routed| routed.backend_id != id);

        for tool in &tools {
            let exposed_name = compute_exposed_name(namespace.as_deref(), &tool.name);

            // Collision detection
            if let Some(existing) = tool_index.get(&exposed_name) {
                return Err(BackendError::new(
                    BackendErrorKind::Internal,
                    format!(
                        "tool name collision: both backend '{}' and backend '{}' expose '{}'. Add a namespace.",
                        existing.backend_id, id, exposed_name
                    ),
                ));
            }

            tool_index.insert(
                exposed_name.clone(),
                RoutedTool {
                    backend_id: id.to_string(),
                    exposed_name: exposed_name.clone(),
                    downstream_name: tool.name.clone(),
                    descriptor: ToolDescriptor {
                        name: exposed_name,
                        description: tool.description.clone(),
                        input_schema: tool.input_schema.clone(),
                    },
                },
            );
        }

        // Mark healthy and reset reconnect attempts
        {
            let backends = self.backends.read().unwrap();
            if let Some(handle) = backends.get(id) {
                handle.health.store(true, Ordering::SeqCst);
                *handle.reconnect_attempts.lock().unwrap() = 0;
            }
        }

        tracing::info!(%id, tool_count = tools.len(), "backend connected");
        Ok(())
    }

    /// Start periodic health checks for all registered backends.
    pub fn start_health_checks(self: &Arc<Self>) {
        let registry = Arc::clone(self);

        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(HEALTH_CHECK_INTERVAL_SECS));
            interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

            loop {
                interval.tick().await;
                registry.run_health_checks().await;
            }
        });

        let mut handle_guard = self.health_check_handle.lock().unwrap();
        *handle_guard = Some(handle);
        tracing::info!("health checks started (interval: {HEALTH_CHECK_INTERVAL_SECS}s)");
    }

    async fn run_health_checks(&self) {
        let ids: Vec<(String, ConnectionMode)> = {
            let backends = self.backends.read().unwrap();
            backends
                .iter()
                .filter(|(_, h)| {
                    // Only check eager and lazy backends; per-call are stateless
                    !matches!(h.def.connection_mode, ConnectionMode::PerCall)
                })
                .map(|(id, h)| (id.clone(), h.def.connection_mode))
                .collect()
        };

        for (id, _mode) in ids {
            let is_healthy = {
                let backends = self.backends.read().unwrap();
                backends
                    .get(&id)
                    .map(|h| h.health.load(Ordering::SeqCst))
                    .unwrap_or(false)
            };

            if !is_healthy {
                // Try to reconnect
                let attempt = {
                    let backends = self.backends.read().unwrap();
                    backends
                        .get(&id)
                        .map(|h| {
                            let mut attempts = h.reconnect_attempts.lock().unwrap();
                            *attempts += 1;
                            *attempts
                        })
                        .unwrap_or(0)
                };

                // Exponential backoff: base * 2^(attempt-1), capped
                let delay_ms = std::cmp::min(
                    RECONNECT_BASE_DELAY_MS * 2u64.pow(attempt.saturating_sub(1)),
                    RECONNECT_MAX_DELAY_MS,
                );
                tracing::info!(
                    %id,
                    attempt,
                    delay_ms,
                    "attempting reconnect with backoff"
                );

                tokio::time::sleep(Duration::from_millis(delay_ms)).await;

                match self.connect_backend(&id).await {
                    Ok(()) => {
                        tracing::info!(%id, attempt, "backend reconnected successfully");
                    }
                    Err(e) => {
                        tracing::warn!(%id, attempt, %e, "reconnect attempt failed");
                    }
                }
                continue;
            }

            // Run health check on healthy backends
            let backend = {
                let backends = self.backends.read().unwrap();
                backends.get(&id).map(|h| h.backend.clone())
            };

            if let Some(backend) = backend {
                match backend.health_check().await {
                    Ok(()) => {
                        // Still healthy
                    }
                    Err(e) => {
                        tracing::warn!(%id, %e, "health check failed; marking unhealthy");
                        if let Some(handle) = self.backends.read().unwrap().get(&id) {
                            handle.health.store(false, Ordering::SeqCst);
                        }
                    }
                }
            }
        }
    }

    /// Build the aggregated tools/list response.
    /// Only includes tools from healthy backends.
    pub fn aggregated_tools(&self) -> Vec<ToolDescriptor> {
        let tool_index = self.tool_index.read().unwrap();
        let backends = self.backends.read().unwrap();

        let mut tools: Vec<ToolDescriptor> = tool_index
            .values()
            .filter(|routed| {
                backends
                    .get(&routed.backend_id)
                    .map(|h| h.health.load(Ordering::SeqCst))
                    .unwrap_or(false)
            })
            .map(|routed| routed.descriptor.clone())
            .collect();

        tools.sort_by(|a, b| a.name.cmp(&b.name));
        tools
    }

    /// Route a `tools/call` to the right backend.
    /// For lazy backends, triggers connection on first call.
    pub async fn route_call(
        &self,
        exposed_name: &str,
        args: Option<Value>,
        timeout: Duration,
    ) -> Result<Value, BackendError> {
        let (backend_id, backend, downstream_name, mode) = {
            let tool_index = self.tool_index.read().unwrap();
            let routed = tool_index
                .get(exposed_name)
                .ok_or_else(|| {
                    BackendError::new(
                        BackendErrorKind::Internal,
                        format!("no such tool: {exposed_name}"),
                    )
                })?;

            let backends = self.backends.read().unwrap();
            let handle = backends.get(&routed.backend_id).ok_or_else(|| {
                BackendError::new(
                    BackendErrorKind::Internal,
                    format!(
                        "backend '{}' for tool '{}' is no longer registered",
                        routed.backend_id, exposed_name
                    ),
                )
            })?;

            (
                routed.backend_id.clone(),
                handle.backend.clone(),
                routed.downstream_name.clone(),
                handle.def.connection_mode,
            )
        };

        // Handle lazy connection: connect on first use
        if matches!(mode, ConnectionMode::Lazy) {
            let is_healthy = {
                let backends = self.backends.read().unwrap();
                backends
                    .get(&backend_id)
                    .map(|h| h.health.load(Ordering::SeqCst))
                    .unwrap_or(false)
            };

            if !is_healthy {
                tracing::info!(%backend_id, "lazy backend: connecting on first call");
                self.connect_backend(&backend_id).await?;
            }
        }

        // Handle per-call: connect, call, disconnect
        if matches!(mode, ConnectionMode::PerCall) {
            backend.connect().await?;
            let result = backend.call_tool(&downstream_name, args, timeout).await;
            backend.disconnect().await?;
            return result;
        }

        backend.call_tool(&downstream_name, args, timeout).await
    }

    /// Refresh tools from all healthy backends.
    pub async fn refresh_tools(&self) -> Result<(), BackendError> {
        let backends = self.backends.read().unwrap();
        let ids: Vec<String> = backends
            .iter()
            .filter(|(_, h)| h.health.load(Ordering::SeqCst))
            .map(|(id, _)| id.clone())
            .collect();
        drop(backends);

        self.tool_index.write().unwrap().clear();

        for id in ids {
            if let Err(e) = self.connect_backend(&id).await {
                tracing::warn!(%id, %e, "failed to refresh tools");
            }
        }

        Ok(())
    }

    /// Returns the registered backend ids.
    pub fn backend_ids(&self) -> Vec<String> {
        self.backends.read().unwrap().keys().cloned().collect()
    }
}

/// Compute the exposed (namespaced) name for a tool.
fn compute_exposed_name(namespace: Option<&str>, tool_name: &str) -> String {
    match namespace {
        Some(ns) => format!("{ns}.{tool_name}"),
        None => tool_name.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use headless_mcp_core::{BackendResult, InitializeResult, ServerCapabilities, ServerInfo};

    struct MockBackend {
        id: String,
        tools: Vec<ToolDescriptor>,
        connected: AtomicBool,
    }

    impl MockBackend {
        fn new(id: &str, tools: Vec<ToolDescriptor>) -> Self {
            Self {
                id: id.to_string(),
                tools,
                connected: AtomicBool::new(false),
            }
        }
    }

    #[async_trait]
    impl McpBackend for MockBackend {
        fn backend_id(&self) -> &str {
            &self.id
        }

        fn label(&self) -> &str {
            &self.id
        }

        async fn connect(&self) -> BackendResult<InitializeResult> {
            self.connected.store(true, Ordering::SeqCst);
            Ok(InitializeResult {
                protocol_version: "2024-11-05".to_string(),
                server_info: ServerInfo {
                    name: self.id.clone(),
                    version: "1.0".to_string(),
                },
                capabilities: ServerCapabilities {
                    tools: None,
                    resources: None,
                    prompts: None,
                },
            })
        }

        async fn list_tools(&self) -> BackendResult<Vec<ToolDescriptor>> {
            Ok(self.tools.clone())
        }

        async fn call_tool(
            &self,
            name: &str,
            _arguments: Option<Value>,
            _timeout: Duration,
        ) -> BackendResult<Value> {
            Ok(serde_json::json!({"called": name, "backend": self.id}))
        }

        async fn disconnect(&self) -> BackendResult<()> {
            self.connected.store(false, Ordering::SeqCst);
            Ok(())
        }

        async fn health_check(&self) -> BackendResult<()> {
            if self.connected.load(Ordering::SeqCst) {
                Ok(())
            } else {
                Err(BackendError::new(
                    BackendErrorKind::Connection,
                    "not connected",
                ))
            }
        }
    }

    fn make_tool(name: &str) -> ToolDescriptor {
        ToolDescriptor {
            name: name.to_string(),
            description: format!("{name} tool"),
            input_schema: serde_json::json!({"type": "object"}),
        }
    }

    fn make_def(id: &str, namespace: Option<&str>) -> BackendDef {
        BackendDef {
            id: id.to_string(),
            label: None,
            transport: headless_mcp_core::BackendTransport::Stdio {
                command: "echo".to_string(),
                args: vec![],
                env: HashMap::new(),
                cwd: None,
            },
            namespace: namespace.map(|s| s.to_string()),
            connection_mode: ConnectionMode::Eager,
            connect_timeout_secs: 10,
            call_timeout_secs: 30,
            stderr_mode: headless_mcp_core::StderrMode::LogOnError,
            tools_allow: vec![],
            tools_deny: vec![],
        }
    }

    #[tokio::test]
    async fn namespacing_prefixes_tools() {
        let registry = BackendRegistry::new();
        let backend = Arc::new(MockBackend::new("slack", vec![make_tool("send_message")]));

        registry
            .register(make_def("slack", Some("slack")), backend)
            .await
            .unwrap();

        registry.connect_backend("slack").await.unwrap();

        let tools = registry.aggregated_tools();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "slack.send_message");
    }

    #[tokio::test]
    async fn route_call_dispatches_to_correct_backend() {
        let registry = BackendRegistry::new();
        let backend = Arc::new(MockBackend::new("slack", vec![make_tool("send_message")]));

        registry
            .register(make_def("slack", Some("slack")), backend)
            .await
            .unwrap();

        registry.connect_backend("slack").await.unwrap();

        let result = registry
            .route_call("slack.send_message", None, Duration::from_secs(5))
            .await
            .unwrap();

        assert_eq!(result["called"], "send_message");
        assert_eq!(result["backend"], "slack");
    }
}
