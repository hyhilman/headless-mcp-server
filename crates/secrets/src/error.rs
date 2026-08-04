use thiserror::Error;

pub const MASTER_KEY_ENV_VAR: &str = "HEADLESS_MCP_MASTER_KEY";

#[derive(Debug, Error)]
pub enum SecretError {
    #[error("secret store I/O failure: {0}")]
    Io(#[from] std::io::Error),

    #[error("missing master key: set the {MASTER_KEY_ENV_VAR} environment variable to 64 hex characters (32 bytes)")]
    MissingMasterKey,

    #[error("invalid master key: {reason}")]
    InvalidMasterKey { reason: String },

    #[error("secret key must not be empty")]
    EmptyKey,

    #[error("encryption failed for key '{key}'")]
    EncryptionFailed { key: String },

    #[error("decryption failed for key '{key}'")]
    DecryptionFailed { key: String },

    #[error("secret store file is corrupted: {reason}")]
    Corrupted { reason: String },
}
