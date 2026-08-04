use crate::error::SecretError;

const KEY_LEN_BYTES: usize = 32;

/// A validated 32-byte AES-256-GCM key.
pub(crate) struct MasterKey {
    bytes: zeroize::Zeroizing<[u8; KEY_LEN_BYTES]>,
}

impl MasterKey {
    pub(crate) fn from_hex(hex_str: &str) -> Result<Self, SecretError> {
        let decoded = hex::decode(hex_str.trim()).map_err(|_| SecretError::InvalidMasterKey {
            reason: "master key must be valid hex".to_string(),
        })?;

        let bytes: [u8; KEY_LEN_BYTES] =
            decoded
                .as_slice()
                .try_into()
                .map_err(|_| SecretError::InvalidMasterKey {
                    reason: format!(
                        "master key must decode to {KEY_LEN_BYTES} bytes, got {}",
                        decoded.len()
                    ),
                })?;

        Ok(Self {
            bytes: zeroize::Zeroizing::new(bytes),
        })
    }

    pub(crate) fn from_env() -> Result<Self, SecretError> {
        let raw =
            std::env::var(crate::error::MASTER_KEY_ENV_VAR).map_err(|_| SecretError::MissingMasterKey)?;
        Self::from_hex(&raw)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; KEY_LEN_BYTES] {
        &self.bytes
    }
}
