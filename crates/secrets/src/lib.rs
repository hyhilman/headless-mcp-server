#![forbid(unsafe_code)]

//! Encrypted-at-rest credential storage for `headless-mcp`.
//!
//! [`EncryptedFileSecretStore`] is the only backend today: a single JSON
//! file, AES-256-GCM per entry, master key from the
//! `HEADLESS_MCP_MASTER_KEY` environment variable.

mod error;
mod file_store;
mod master_key;
mod store;

pub use error::SecretError;
pub use file_store::EncryptedFileSecretStore;
pub use store::SecretStore;
