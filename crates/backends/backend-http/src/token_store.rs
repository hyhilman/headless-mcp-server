//! OAuth2 token persistence: store encrypted tokens so the hub
//! survives restarts without re-authorizing.
//!
//! Uses the encrypted file secret store (AES-256-GCM) keyed by
//! `"oauth2:<backend_id>:token"`.

use headless_mcp_secrets::{EncryptedFileSecretStore, SecretError, SecretStore};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Persisted OAuth2 token state for one backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedToken {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at_unix: u64,
}

impl PersistedToken {
    /// Returns true if the access token hasn't expired yet (with 30s buffer).
    pub fn is_valid(&self) -> bool {
        let expires_at = Instant::now()
            .checked_add(Duration::from_secs(
                self.expires_at_unix.saturating_sub(now_unix()),
            ))
            .unwrap_or(Instant::now());
        expires_at > Instant::now() + Duration::from_secs(30)
    }

    /// Returns the refresh token if present.
    pub fn refresh_token(&self) -> Option<&str> {
        self.refresh_token.as_deref()
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Loads a persisted token for a backend.
pub fn load_token(store: &EncryptedFileSecretStore, backend_id: &str) -> Option<PersistedToken> {
    let key = format!("oauth2:{backend_id}:token");
    let secret = store.get_blocking(&key).ok()??;
    serde_json::from_str(secret.expose_secret()).ok()
}

/// Saves a token for a backend.
pub fn save_token(
    store: &EncryptedFileSecretStore,
    backend_id: &str,
    access_token: &str,
    refresh_token: Option<&str>,
    expires_in_secs: u64,
) {
    let key = format!("oauth2:{backend_id}:token");
    let token = PersistedToken {
        access_token: access_token.to_string(),
        refresh_token: refresh_token.map(|s| s.to_string()),
        expires_at_unix: now_unix() + expires_in_secs,
    };
    if let Ok(json) = serde_json::to_string(&token) {
        let _ = store.set_blocking(&key, SecretString::from(json));
    }
}

/// Clears the persisted token for a backend.
pub fn clear_token(store: &EncryptedFileSecretStore, backend_id: &str) {
    let key = format!("oauth2:{backend_id}:token");
    let _ = store.delete_blocking(&key);
}

// ── Blocking wrappers for EncryptedFileSecretStore ──

trait SecretStoreBlocking {
    fn get_blocking(&self, key: &str) -> Result<Option<SecretString>, SecretError>;
    fn set_blocking(&self, key: &str, value: SecretString) -> Result<(), SecretError>;
    fn delete_blocking(&self, key: &str) -> Result<(), SecretError>;
}

impl SecretStoreBlocking for EncryptedFileSecretStore {
    fn get_blocking(&self, key: &str) -> Result<Option<SecretString>, SecretError> {
        tokio::runtime::Handle::try_current()
            .map(|rt| rt.block_on(self.get(key)))
            .unwrap_or_else(|_| futures_executor(self.get(key)))
    }

    fn set_blocking(&self, key: &str, value: SecretString) -> Result<(), SecretError> {
        tokio::runtime::Handle::try_current()
            .map(|rt| rt.block_on(self.set(key, value.clone())))
            .unwrap_or_else(|_| futures_executor(self.set(key, value)))
    }

    fn delete_blocking(&self, key: &str) -> Result<(), SecretError> {
        tokio::runtime::Handle::try_current()
            .map(|rt| rt.block_on(self.delete(key)))
            .unwrap_or_else(|_| futures_executor(self.delete(key)))
    }
}

fn futures_executor<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(f)
}
