#![forbid(unsafe_code)]

//! Backend registry: tool aggregation, namespacing, and route dispatch.
//!
//! The [`BackendRegistry`] owns all registered MCP backends, manages their
//! lifecycle (connect, health check, disconnect), aggregates their tools
//! with namespace prefixes, and routes incoming `tools/call` requests to
//! the right backend.

use headless_mcp_core::{
    BackendDef, BackendError, BackendErrorKind, ConnectionMode, McpBackend,
    ToolDescriptor,
};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

/// Holds a registered backend and its metadata.
struct BackendHandle {
    def: BackendDef,
    backend: Arc<dyn McpBackend>,
    health: AtomicBool,
}

/// Maps an exposed tool name to its origin backend and downstream name.
#[derive(Debug, Clone)]
pub struct RoutedTool {
    pub backend_id: String,
    /// The tool name as exposed by the hub (with namespace prefix)
    pub exposed_name: String,
    /// The tool name as the downstream expects it (bare)
    pub downstream_name: String,
    pub descriptor: ToolDescriptor,
}

/// Manages a set of MCP backends, their tools, and route dispatch.
pub struct BackendRegistry {
    backends: RwLock<HashMap<String, BackendHandle>>,
    tool_index: RwLock<HashMap<String, RoutedTool>>,
}

impl BackendRegistry {
    pub fn new() -> Self {
        Self {
            backends: RwLock::new(HashMap::new()),
            tool_index: RwLock::new(HashMap::new()),
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

        // Remove tools from the index
        let mut tool_index = self.tool_index.write().unwrap();
        tool_index.retain(|_, routed| routed.backend_id != id);

        // Disconnect the backend
        handle.backend.disconnect().await?;

        tracing::info!(%id, "backend unregistered");
        Ok(())
    }

    /// Connect all eager backends. Returns results per backend so callers
    /// can log failures without aborting the whole hub.
    pub async fn connect_all(&self) -> Vec<(String, Result<(), BackendError>)> {
        let backends = self.backends.read().unwrap();
        let eager_ids: Vec<String> = backends
            .iter()
            .filter(|(_, h)| matches!(h.def.connection_mode, ConnectionMode::Eager))
            .map(|(id, _)| id.clone())
            .collect();
        drop(backends);

        let mut results = Vec::new();
        for id in eager_ids {
            let result = self.connect_backend(&id).await;
            results.push((id, result));
        }
        results
    }

    /// Connect a specific backend and index its tools.
    async fn connect_backend(&self, id: &str) -> Result<(), BackendError> {
        let (backend, namespace) = {
            let backends = self.backends.read().unwrap();
            let handle = backends.get(id).ok_or_else(|| {
                BackendError::new(
                    BackendErrorKind::Internal,
                    format!("backend '{id}' is not registered"),
                )
            })?;
            (handle.backend.clone(), handle.def.namespace.clone())
        };

        // Full MCP handshake
        let init_result = backend.connect().await?;

        // Fetch tools
        let tools = backend.list_tools().await?;

        // Index tools with namespace prefix
        let mut tool_index = self.tool_index.write().unwrap();
        for tool in &tools {
            let exposed_name = compute_exposed_name(namespace.as_deref(), &tool.name);

            // Collision detection
            if let Some(existing) = tool_index.get(&exposed_name) {
                return Err(BackendError::new(
                    BackendErrorKind::Internal,
                    format!(
                        "tool name collision: both backend '{}' and backend '{}' expose a tool named '{}'. Add a namespace to disambiguate.",
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

        // Mark healthy
        {
            let backends = self.backends.read().unwrap();
            if let Some(handle) = backends.get(id) {
                handle.health.store(true, Ordering::SeqCst);
            }
        }

        tracing::info!(%id, tool_count = tools.len(), protocol_version = %init_result.protocol_version, "backend connected");
        Ok(())
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
    pub async fn route_call(
        &self,
        exposed_name: &str,
        args: Option<Value>,
        timeout: Duration,
    ) -> Result<Value, BackendError> {
        let (backend, downstream_name) = {
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
                    format!("backend '{}' for tool '{}' is no longer registered", routed.backend_id, exposed_name),
                )
            })?;

            (handle.backend.clone(), routed.downstream_name.clone())
        };

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

        // Clear existing tool index
        self.tool_index.write().unwrap().clear();

        for id in ids {
            let (backend, namespace) = {
                let backends = self.backends.read().unwrap();
                let Some(handle) = backends.get(&id) else {
                    continue;
                };
                (handle.backend.clone(), handle.def.namespace.clone())
            };

            if let Ok(tools) = backend.list_tools().await {
                let mut tool_index = self.tool_index.write().unwrap();
                for tool in &tools {
                    let exposed_name = compute_exposed_name(namespace.as_deref(), &tool.name);
                    tool_index.insert(
                        exposed_name.clone(),
                        RoutedTool {
                            backend_id: id.clone(),
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
                tracing::info!(%id, tool_count = tools.len(), "tools refreshed");
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
    use headless_mcp_core::{InitializeResult, ServerCapabilities, ServerInfo};

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
    async fn no_namespace_exposes_bare_names() {
        let registry = BackendRegistry::new();
        let backend = Arc::new(MockBackend::new("foo", vec![make_tool("bar")]));

        registry
            .register(make_def("foo", None), backend)
            .await
            .unwrap();

        registry.connect_backend("foo").await.unwrap();

        let tools = registry.aggregated_tools();
        assert_eq!(tools[0].name, "bar");
    }

    #[tokio::test]
    async fn collision_detection_rejects_overlapping_names() {
        let registry = BackendRegistry::new();
        let backend_a = Arc::new(MockBackend::new("a", vec![make_tool("query")]));
        let backend_b = Arc::new(MockBackend::new("b", vec![make_tool("query")]));

        registry
            .register(make_def("a", None), backend_a)
            .await
            .unwrap();
        registry
            .register(make_def("b", None), backend_b)
            .await
            .unwrap();

        registry.connect_backend("a").await.unwrap();
        let result = registry.connect_backend("b").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("name collision"));
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
