use thiserror::Error;

/// Coarse classification of a backend error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendErrorKind {
    Connection,
    Auth,
    Timeout,
    Protocol,
    Internal,
}

/// Uniform error surface across every backend.
///
/// `message` must never contain a credential. Backends that wrap an
/// underlying client library's error must strip credentials from the
/// message before constructing this.
#[derive(Debug, Clone, Error)]
#[error("{message}")]
pub struct BackendError {
    pub kind: BackendErrorKind,
    pub message: String,
    pub detail: Option<String>,
}

impl BackendError {
    pub fn new(kind: BackendErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            detail: None,
        }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

pub type BackendResult<T> = Result<T, BackendError>;
