//! OAuth2 token persistence: store encrypted tokens via async secret store.
//! All methods are async — call them from within a tokio runtime.

use headless_mcp_secrets::{EncryptedFileSecretStore, SecretStore};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

/// Persisted OAuth2 token state for one backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedToken {
    pub access_token: String,
    pub refresh_token: Option<String>,
    /// Dynamic client_id (for refresh to work after restart).
    pub client_id: Option<String>,
    pub expires_at_unix: u64,
}

impl PersistedToken {
    pub fn is_valid(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.expires_at_unix > now + 30
    }

    pub fn refresh_token(&self) -> Option<&str> {
        self.refresh_token.as_deref()
    }
}

/// Load a persisted token for a backend.
pub async fn load_token(
    store: &EncryptedFileSecretStore,
    backend_id: &str,
) -> Option<PersistedToken> {
    let key = format!("oauth2:{backend_id}:token");
    let secret = store.get(&key).await.ok()??;
    serde_json::from_str(secret.expose_secret()).ok()
}

/// Save a token for a backend.
pub async fn save_token(
    store: &EncryptedFileSecretStore,
    backend_id: &str,
    access_token: &str,
    refresh_token: Option<&str>,
    expires_in_secs: u64,
    client_id: Option<&str>,
) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let token = PersistedToken {
        access_token: access_token.to_string(),
        refresh_token: refresh_token.map(|s| s.to_string()),
        client_id: client_id.map(|s| s.to_string()),
        expires_at_unix: now + expires_in_secs,
    };

    let key = format!("oauth2:{backend_id}:token");
    if let Ok(json) = serde_json::to_string(&token) {
        let _ = store.set(&key, SecretString::from(json)).await;
    }
}

/// Clear a persisted token.
pub async fn clear_token(store: &EncryptedFileSecretStore, backend_id: &str) {
    let key = format!("oauth2:{backend_id}:token");
    let _ = store.delete(&key).await;
}
