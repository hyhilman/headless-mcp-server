use headless_mcp_core::StderrMode;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::ChildStderr;

/// Captures and processes stderr output from a backend child process
/// according to the configured [`StderrMode`].
pub struct StderrCapture {
    reader: BufReader<ChildStderr>,
    backend_id: String,
    mode: StderrMode,
    /// Buffer for `LogOnError` mode: holds captured output until we know
    /// whether to log it.
    buffer: Vec<String>,
}

impl StderrCapture {
    pub fn new(stderr: ChildStderr, backend_id: String, mode: StderrMode) -> Self {
        Self {
            reader: BufReader::new(stderr),
            backend_id,
            mode,
            buffer: Vec::new(),
        }
    }

    pub async fn run(mut self) {
        let mut lines = self.reader.lines();

        loop {
            let line = match lines.next_line().await {
                Ok(Some(line)) => line,
                Ok(None) => return,
                Err(_) => return,
            };

            match self.mode {
                StderrMode::Passthrough => {
                    eprintln!("[backend {}] {}", self.backend_id, line);
                }
                StderrMode::LogAlways => {
                    tracing::trace!(
                        backend_id = %self.backend_id,
                        "{}",
                        line
                    );
                }
                StderrMode::LogOnError => {
                    self.buffer.push(line);
                }
                StderrMode::Silent => {
                    // discard
                }
            }
        }
    }

    /// Returns the buffered content for `LogOnError` mode
    /// and consumes the capture.
    pub fn into_buffer(self) -> Vec<String> {
        self.buffer
    }
}
