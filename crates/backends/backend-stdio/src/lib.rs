#![forbid(unsafe_code)]

//! Stdio-based MCP backend: spawn child process, JSON-RPC over stdin/stdout.
//!
//! This is the reference implementation of [`headless_mcp_core::McpBackend`]
//! for downstream MCP servers that speak newline-delimited JSON-RPC over
//! standard input/output.

mod stderr_capture;

use async_trait::async_trait;
use headless_mcp_core::{
    BackendDef, BackendError, BackendErrorKind, BackendResult, InitializeResult, McpBackend,
    ToolDescriptor,
};
use headless_mcp_wire::{
    decode_message, JsonRpcId, JsonRpcMessage, JsonRpcNotification, JsonRpcRequest,
};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{ChildStdin, ChildStdout, Command};
use tokio::sync::{Mutex, oneshot};

use stderr_capture::StderrCapture;

/// Shared state between the StdioBackend and the reader task.
struct SharedState {
    stdin: Mutex<Option<ChildStdin>>,
    pending: Mutex<HashMap<i64, oneshot::Sender<Result<Value, BackendError>>>>,
    connected: AtomicBool,
    initialize_result: Mutex<Option<InitializeResult>>,
}

/// A connected MCP backend communicating over a child process's stdio.
pub struct StdioBackend {
    def: BackendDef,
    state: Arc<SharedState>,
    write_guard: Mutex<()>,
    request_counter: AtomicU64,
}

impl StdioBackend {
    /// Creates a new [`StdioBackend`] from its definition.
    /// The actual process is not spawned until `connect()` is called.
    pub fn new(def: BackendDef) -> Self {
        Self {
            def,
            state: Arc::new(SharedState {
                stdin: Mutex::new(None),
                pending: Mutex::new(HashMap::new()),
                connected: AtomicBool::new(false),
                initialize_result: Mutex::new(None),
            }),
            write_guard: Mutex::new(()),
            request_counter: AtomicU64::new(0),
        }
    }

    fn command(&self) -> Result<Command, BackendError> {
        let transport = match &self.def.transport {
            headless_mcp_core::BackendTransport::Stdio {
                command,
                args,
                env,
                cwd,
            } => (command, args, env, cwd),
            _ => {
                return Err(BackendError::new(
                    BackendErrorKind::Connection,
                    "StdioBackend requires a stdio transport",
                ))
            }
        };

        let mut cmd = Command::new(transport.0);
        cmd.args(transport.1);
        cmd.stdin(std::process::Stdio::piped());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        cmd.kill_on_drop(true);

        for (k, v) in transport.2 {
            cmd.env(k, v);
        }

        if let Some(cwd) = transport.3 {
            cmd.current_dir(cwd);
        }

        Ok(cmd)
    }

    async fn send_message(&self, message: &JsonRpcMessage) -> Result<(), BackendError> {
        let mut serialized = serde_json::to_vec(message).map_err(|e| {
            BackendError::new(BackendErrorKind::Protocol, format!("serialize: {e}"))
        })?;
        serialized.push(b'\n');

        let _guard = self.write_guard.lock().await;
        let mut stdin_guard = self.state.stdin.lock().await;
        let stdin = stdin_guard
            .as_mut()
            .ok_or_else(|| BackendError::new(BackendErrorKind::Connection, "stdin not available"))?;

        stdin.write_all(&serialized).await.map_err(|e| {
            BackendError::new(BackendErrorKind::Connection, format!("write to stdin: {e}"))
        })?;
        stdin.flush().await.map_err(|e| {
            BackendError::new(BackendErrorKind::Connection, format!("flush stdin: {e}"))
        })?;

        Ok(())
    }

    async fn send_request(
        &self,
        method: &str,
        params: Option<Value>,
        timeout: Duration,
    ) -> Result<Value, BackendError> {
        let id = self.request_counter.fetch_add(1, Ordering::SeqCst) as i64;
        let request =
            JsonRpcMessage::Request(JsonRpcRequest::new(JsonRpcId::Number(id), method, params));

        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.state.pending.lock().await;
            pending.insert(id, tx);
        }

        self.send_message(&request).await?;

        tokio::time::timeout(timeout, rx)
            .await
            .map_err(|_| {
                // Best effort cleanup — if the lock is held we just let
                // the response reader task clean up when the backend disconnects.
                if let Ok(mut pending) = self.state.pending.try_lock() {
                    pending.remove(&id);
                }
                BackendError::new(
                    BackendErrorKind::Timeout,
                    format!(
                        "request '{}' to backend '{}' timed out after {:.0}s",
                        method,
                        self.def.id,
                        timeout.as_secs_f64()
                    ),
                )
            })?
            .map_err(|_| {
                BackendError::new(
                    BackendErrorKind::Connection,
                    format!(
                        "backend '{}' disconnected while waiting for '{}' response",
                        self.def.id, method
                    ),
                )
            })?
    }
}

#[async_trait]
impl McpBackend for StdioBackend {
    fn backend_id(&self) -> &str {
        &self.def.id
    }

    fn label(&self) -> &str {
        self.def.label.as_deref().unwrap_or(&self.def.id)
    }

    async fn connect(&self) -> BackendResult<InitializeResult> {
        if self.state.connected.load(Ordering::SeqCst) {
            return self
                .state
                .initialize_result
                .lock()
                .await
                .clone()
                .ok_or_else(|| {
                    BackendError::new(
                        BackendErrorKind::Internal,
                        "connected but no initialize result cached",
                    )
                });
        }

        let mut cmd = self.command()?;
        let mut child = cmd.spawn().map_err(|e| {
            BackendError::new(
                BackendErrorKind::Connection,
                format!("failed to spawn backend '{}': {e}", self.def.id),
            )
        })?;

        let stdin = child.stdin.take().ok_or_else(|| {
            BackendError::new(
                BackendErrorKind::Connection,
                format!("failed to capture stdin of backend '{}'", self.def.id),
            )
        })?;

        let stdout = child.stdout.take().ok_or_else(|| {
            BackendError::new(
                BackendErrorKind::Connection,
                format!("failed to capture stdout of backend '{}'", self.def.id),
            )
        })?;

        let stderr = child.stderr.take();

        // Store stdin
        {
            let mut stdin_guard = self.state.stdin.lock().await;
            *stdin_guard = Some(stdin);
        }

        // Spawn the response reader task
        let state = self.state.clone();
        let backend_id = self.def.id.clone();
        let connect_timeout = Duration::from_secs(self.def.connect_timeout_secs);

        tokio::spawn(async move {
            read_responses(stdout, state.clone(), backend_id.clone()).await;
            // Mark as disconnected when the reader exits
            state.connected.store(false, Ordering::SeqCst);
            // Notify all pending callers
            let mut pending = state.pending.lock().await;
            for (_, tx) in pending.drain() {
                let _ = tx.send(Err(BackendError::new(
                    BackendErrorKind::Connection,
                    format!("backend '{backend_id}' disconnected"),
                )));
            }
        });

        // Spawn stderr capture
        if let Some(stderr) = stderr {
            let stderr_mode = self.def.stderr_mode;
            let backend_id = self.def.id.clone();
            tokio::spawn(async move {
                let capture = StderrCapture::new(stderr, backend_id, stderr_mode);
                capture.run().await;
            });
        }

        // Full MCP handshake
        let result = self
            .send_request(
                "initialize",
                Some(serde_json::json!({
                    "protocolVersion": "2024-11-05",
                    "clientInfo": {
                        "name": "headless-mcp",
                        "version": env!("CARGO_PKG_VERSION"),
                    },
                    "capabilities": {},
                })),
                connect_timeout,
            )
            .await?;

        // Parse InitializeResult
        let init_result: InitializeResult = serde_json::from_value(result).map_err(|e| {
            BackendError::new(
                BackendErrorKind::Protocol,
                format!(
                    "failed to parse initialize result from backend '{}': {e}",
                    self.def.id
                ),
            )
        })?;

        // Send notifications/initialized
        let notification = JsonRpcMessage::Notification(JsonRpcNotification::new(
            "notifications/initialized",
            None,
        ));
        self.send_message(&notification).await?;

        // Store results
        *self.state.initialize_result.lock().await = Some(init_result.clone());
        self.state.connected.store(true, Ordering::SeqCst);

        tracing::info!(
            backend_id = %self.def.id,
            protocol_version = %init_result.protocol_version,
            server_name = %init_result.server_info.name,
            "stdio backend connected"
        );

        Ok(init_result)
    }

    async fn list_tools(&self) -> BackendResult<Vec<ToolDescriptor>> {
        if !self.state.connected.load(Ordering::SeqCst) {
            return Err(BackendError::new(
                BackendErrorKind::Connection,
                format!("backend '{}' is not connected", self.def.id),
            ));
        }

        let call_timeout = Duration::from_secs(self.def.call_timeout_secs);
        let result = self
            .send_request("tools/list", None, call_timeout)
            .await?;

        let tools_list = result
            .get("tools")
            .and_then(|v| v.as_array())
            .ok_or_else(|| {
                BackendError::new(
                    BackendErrorKind::Protocol,
                    format!(
                        "backend '{}' returned a 'tools/list' response without a 'tools' array",
                        self.def.id
                    ),
                )
            })?;

        tools_list
            .iter()
            .map(|t| {
                serde_json::from_value::<ToolDescriptor>(t.clone()).map_err(|e| {
                    BackendError::new(
                        BackendErrorKind::Protocol,
                        format!(
                            "backend '{}' returned an invalid tool descriptor: {e}",
                            self.def.id
                        ),
                    )
                })
            })
            .collect()
    }

    async fn call_tool(
        &self,
        name: &str,
        arguments: Option<Value>,
        timeout: Duration,
    ) -> BackendResult<Value> {
        if !self.state.connected.load(Ordering::SeqCst) {
            return Err(BackendError::new(
                BackendErrorKind::Connection,
                format!("backend '{}' is not connected", self.def.id),
            ));
        }

        let params = serde_json::json!({
            "name": name,
            "arguments": arguments.unwrap_or(Value::Object(serde_json::Map::new())),
        });

        self.send_request("tools/call", Some(params), timeout)
            .await
    }

    async fn disconnect(&self) -> BackendResult<()> {
        self.state.connected.store(false, Ordering::SeqCst);
        // Drop stdin to signal EOF to the child
        {
            let mut stdin_guard = self.state.stdin.lock().await;
            *stdin_guard = None;
        }
        tracing::info!(backend_id = %self.def.id, "stdio backend disconnected");
        Ok(())
    }

    async fn health_check(&self) -> BackendResult<()> {
        if !self.state.connected.load(Ordering::SeqCst) {
            return Err(BackendError::new(
                BackendErrorKind::Connection,
                format!("backend '{}' is not connected", self.def.id),
            ));
        }

        // Health check: send a lightweight tools/list with a short timeout
        let short_timeout = Duration::from_secs(5);
        self.send_request("tools/list", None, short_timeout).await?;
        Ok(())
    }

    fn protocol_version(&self) -> Option<&str> {
        None
    }
}

async fn read_responses(
    stdout: ChildStdout,
    state: Arc<SharedState>,
    backend_id: String,
) {
    let mut lines = BufReader::new(stdout).lines();

    loop {
        let line = match lines.next_line().await {
            Ok(Some(line)) => line,
            Ok(None) => {
                tracing::info!(%backend_id, "backend stdout closed");
                break;
            }
            Err(e) => {
                tracing::warn!(%backend_id, %e, "error reading backend stdout");
                break;
            }
        };

        if line.trim().is_empty() {
            continue;
        }

        let message = match decode_message(line.as_bytes()) {
            Ok(msg) => msg,
            Err(e) => {
                tracing::warn!(%backend_id, %e, "failed to decode message from backend");
                continue;
            }
        };

        match message {
            JsonRpcMessage::SuccessResponse(resp) => {
                let id = match &resp.id {
                    JsonRpcId::Number(n) => *n,
                    _ => continue,
                };
                let mut pending = state.pending.lock().await;
                if let Some(tx) = pending.remove(&id) {
                    let _ = tx.send(Ok(resp.result));
                }
            }
            JsonRpcMessage::ErrorResponse(resp) => {
                let id = match &resp.id {
                    Some(JsonRpcId::Number(n)) => *n,
                    _ => continue,
                };
                let mut pending = state.pending.lock().await;
                if let Some(tx) = pending.remove(&id) {
                    let _ = tx.send(Err(BackendError::new(
                        BackendErrorKind::Protocol,
                        format!(
                            "backend '{}' returned error: {}",
                            backend_id, resp.error.message
                        ),
                    )));
                }
            }
            _ => {}
        }
    }
}
