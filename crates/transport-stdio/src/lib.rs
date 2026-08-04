#![forbid(unsafe_code)]

//! Newline-delimited JSON-RPC over stdio.
//!
//! One JSON-RPC message per line, both directions. This is the transport
//! a locally-spawned MCP client (an editor, a CLI harness) talks: stdin is
//! implicitly trusted the way any process the user launched is.

use std::io;
use std::sync::Arc;

use headless_mcp_server::McpSession;
use headless_mcp_wire::{decode_message, JsonRpcErrorResponse, JsonRpcMessage};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

/// Runs the stdio transport to completion: reads newline-delimited
/// JSON-RPC messages from stdin, dispatches each through `session`, and
/// writes replies to stdout, until stdin reaches EOF.
///
/// A single malformed line never stops the loop: a line that fails to
/// decode gets a JSON-RPC error reply (`id: null`) and reading continues.
pub async fn run_stdio(session: Arc<McpSession>) -> io::Result<()> {
    run(session, tokio::io::stdin(), tokio::io::stdout()).await
}

/// The testable core of [`run_stdio`], generic over the input/output streams.
async fn run<R, W>(session: Arc<McpSession>, reader: R, mut writer: W) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut lines = BufReader::new(reader).lines();

    loop {
        let line = match lines.next_line().await {
            Ok(Some(line)) => line,
            Ok(None) => return Ok(()),
            Err(error) => {
                tracing::warn!(%error, "failed to read a line from stdin; skipping it");
                continue;
            }
        };

        if line.trim().is_empty() {
            continue;
        }

        tracing::trace!(%line, "received stdio line");

        let reply = match decode_message(line.as_bytes()) {
            Ok(message) => session.handle(message).await,
            Err(error) => Some(JsonRpcMessage::ErrorResponse(JsonRpcErrorResponse::new(
                None, error,
            ))),
        };

        let Some(reply) = reply else {
            continue;
        };

        write_reply(&mut writer, &reply).await?;
    }
}

async fn write_reply<W>(writer: &mut W, reply: &JsonRpcMessage) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut serialized = match serde_json::to_vec(reply) {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::warn!(%error, "failed to serialize a JSON-RPC reply; dropping it");
            return Ok(());
        }
    };
    serialized.push(b'\n');

    writer.write_all(&serialized).await?;
    writer.flush().await
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use headless_mcp_registry::BackendRegistry;
    use headless_mcp_server::{McpSession, TracingAuditLogger};
    use serde_json::{json, Value};
    use tokio::io::AsyncReadExt;

    use super::*;

    fn test_session() -> Arc<McpSession> {
        let registry = Arc::new(BackendRegistry::new());
        Arc::new(McpSession::new(registry, Arc::new(TracingAuditLogger)))
    }

    fn initialize_line(id: i64) -> String {
        json!({"jsonrpc": "2.0", "id": id, "method": "initialize"}).to_string()
    }

    async fn drive(session: Arc<McpSession>, input: &str) -> String {
        let (mut input_tx, input_rx) = tokio::io::duplex(64 * 1024);
        let (output_tx, mut output_rx) = tokio::io::duplex(64 * 1024);

        let handle = tokio::spawn(async move { run(session, input_rx, output_tx).await });

        input_tx.write_all(input.as_bytes()).await.unwrap();
        drop(input_tx);

        handle.await.unwrap().unwrap();

        let mut collected = String::new();
        output_rx.read_to_string(&mut collected).await.unwrap();
        collected
    }

    fn parse_lines(output: &str) -> Vec<Value> {
        output
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).expect("each output line is valid JSON"))
            .collect()
    }

    #[tokio::test]
    async fn valid_initialize_request_produces_a_success_response() {
        let output = drive(test_session(), &format!("{}\n", initialize_line(1))).await;

        let replies = parse_lines(&output);
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0]["result"]["serverInfo"]["name"], "headless-mcp");
        assert!(replies[0].get("error").is_none());
    }

    #[tokio::test]
    async fn garbage_line_gets_a_null_id_error_and_the_transport_keeps_running() {
        let input = format!("not json at all {{{{\n{}\n", initialize_line(1));
        let output = drive(test_session(), &input).await;

        let replies = parse_lines(&output);
        assert_eq!(replies.len(), 2);

        assert_eq!(replies[0]["id"], Value::Null);
        assert!(replies[0]["error"].is_object());

        assert_eq!(replies[1]["id"], 1);
        assert!(replies[1].get("result").is_some());
    }

    #[tokio::test]
    async fn notification_produces_no_output_line() {
        let notification =
            json!({"jsonrpc": "2.0", "method": "notifications/initialized"}).to_string();
        let output = drive(test_session(), &format!("{notification}\n")).await;

        assert!(output.is_empty(), "expected no output, got: {output:?}");
    }

    #[tokio::test]
    async fn eof_on_empty_input_returns_ok_cleanly() {
        let output = drive(test_session(), "").await;
        assert!(output.is_empty());
    }

    #[tokio::test]
    async fn messages_sent_across_separate_writes_are_each_handled_in_order() {
        let (mut input_tx, input_rx) = tokio::io::duplex(64 * 1024);
        let (output_tx, mut output_rx) = tokio::io::duplex(64 * 1024);

        let session = test_session();
        let handle = tokio::spawn(async move { run(session, input_rx, output_tx).await });

        input_tx
            .write_all(format!("{}\n", initialize_line(1)).as_bytes())
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;

        input_tx
            .write_all(format!("{}\n", initialize_line(2)).as_bytes())
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;

        drop(input_tx);
        handle.await.unwrap().unwrap();

        let mut collected = String::new();
        output_rx.read_to_string(&mut collected).await.unwrap();

        let replies = parse_lines(&collected);
        assert_eq!(replies.len(), 2);
        assert_eq!(replies[0]["id"], 1);
        assert_eq!(replies[1]["id"], 2);
    }
}
