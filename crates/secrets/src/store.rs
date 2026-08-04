use secrecy::SecretString;

use crate::error::SecretError;

/// Credential storage, keyed by an opaque string.
#[async_trait::async_trait]
pub trait SecretStore: Send + Sync {
    async fn get(&self, key: &str) -> Result<Option<SecretString>, SecretError>;
    async fn set(&self, key: &str, value: SecretString) -> Result<(), SecretError>;
    async fn delete(&self, key: &str) -> Result<(), SecretError>;
}
