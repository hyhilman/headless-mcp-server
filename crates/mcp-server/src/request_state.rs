//! Integrity-protected `requestState` for multi round-trip requests.
//!
//! The token binds a retry to the VPN and tool it was issued for and
//! expires quickly. It passes through the client, so it is HMAC-SHA256
//! signed with a per-process random key and rejected if altered.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) struct StateSigner {
    key: hmac::Key,
}

impl StateSigner {
    pub fn new() -> Self {
        let mut bytes = [0u8; 32];
        SystemRandom::new()
            .fill(&mut bytes)
            .expect("system randomness");
        Self { key: hmac::Key::new(hmac::HMAC_SHA256, &bytes) }
    }

    /// Token for `(vpn, tool)` valid for `ttl_secs`.
    pub fn issue(&self, vpn: &str, tool: &str, ttl_secs: u64) -> String {
        let payload = format!("{vpn}\n{tool}\n{}", now() + ttl_secs);
        let tag = hmac::sign(&self.key, payload.as_bytes());
        format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(payload),
            URL_SAFE_NO_PAD.encode(tag.as_ref())
        )
    }

    /// True if `token` was issued here for `(vpn, tool)` and has not expired.
    pub fn verify(&self, token: &str, vpn: &str, tool: &str) -> bool {
        let Some((payload_b64, tag_b64)) = token.split_once('.') else { return false };
        let (Ok(payload), Ok(tag)) = (
            URL_SAFE_NO_PAD.decode(payload_b64),
            URL_SAFE_NO_PAD.decode(tag_b64),
        ) else {
            return false;
        };
        if hmac::verify(&self.key, &payload, &tag).is_err() {
            return false;
        }
        let Ok(payload) = String::from_utf8(payload) else { return false };
        let mut parts = payload.split('\n');
        match (parts.next(), parts.next(), parts.next().and_then(|e| e.parse::<u64>().ok())) {
            (Some(v), Some(t), Some(exp)) => v == vpn && t == tool && exp > now(),
            _ => false,
        }
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_bound_and_tamper_proof() {
        let signer = StateSigner::new();
        let token = signer.issue("netbird", "db.query", 60);
        assert!(signer.verify(&token, "netbird", "db.query"));
        assert!(!signer.verify(&token, "netbird", "db.drop"));
        assert!(!signer.verify(&token, "other", "db.query"));
        assert!(!StateSigner::new().verify(&token, "netbird", "db.query"));

        let (payload, tag) = token.split_once('.').unwrap();
        let forged = URL_SAFE_NO_PAD.encode("netbird\ndb.drop\n99999999999");
        assert!(!signer.verify(&format!("{forged}.{tag}"), "netbird", "db.drop"));
        assert!(!signer.verify(payload, "netbird", "db.query"));

        let expired = signer.issue("netbird", "db.query", 0);
        assert!(!signer.verify(&expired, "netbird", "db.query"));
    }
}
