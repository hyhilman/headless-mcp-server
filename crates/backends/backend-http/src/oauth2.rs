//! OAuth2 token management for HTTP backends.
//!
//! Supports:
//! - Client credentials grant (machine-to-machine)
//! - MCP OAuth2 discovery from 401 WWW-Authenticate headers
//! - Automatic token refresh

use headless_mcp_core::{OAuth2Config, BackendError, BackendErrorKind};
use serde::Deserialize;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tracing;

/// OAuth2 discovery metadata from the MCP server's WWW-Authenticate header.
#[derive(Debug, Clone, Deserialize)]
pub struct OAuth2Metadata {
    pub issuer: Option<String>,
    pub token_endpoint: String,
    pub authorization_endpoint: Option<String>,
    pub registration_endpoint: Option<String>,
    pub scopes_supported: Option<Vec<String>>,
    pub grant_types_supported: Option<Vec<String>>,
}

/// A cached OAuth2 access token with expiry.
#[derive(Debug, Clone)]
struct TokenCache {
    access_token: String,
    expires_at: Instant,
}

/// Manages OAuth2 token lifecycle for an HTTP backend.
pub struct OAuth2TokenManager {
    config: OAuth2Config,
    /// Cached token, if we've already obtained one.
    token_cache: Mutex<Option<TokenCache>>,
    /// Metadata discovered from 401 responses.
    metadata: Mutex<Option<OAuth2Metadata>>,
    /// HTTP client for token requests.
    client: reqwest::Client,
}

impl OAuth2TokenManager {
    /// Create a new token manager from OAuth2 config.
    pub fn new(config: OAuth2Config) -> Self {
        Self {
            config,
            token_cache: Mutex::new(None),
            metadata: Mutex::new(None),
            client: reqwest::Client::new(),
        }
    }

    /// Store discovered OAuth2 metadata from a WWW-Authenticate header.
    pub fn set_metadata(&self, metadata: OAuth2Metadata) {
        tracing::info!(
            token_endpoint = %metadata.token_endpoint,
            "OAuth2 metadata discovered"
        );
        *self.metadata.lock().unwrap() = Some(metadata);
    }

    /// Get a valid access token. If we have a cached non-expired token, return it.
    /// Otherwise, run the token acquisition flow.
    pub async fn get_token(&self, backend_id: &str) -> Result<String, BackendError> {
        // Check cache first
        {
            let cache = self.token_cache.lock().unwrap();
            if let Some(cached) = cache.as_ref() {
                if cached.expires_at > Instant::now() + Duration::from_secs(30) {
                    tracing::debug!(%backend_id, "using cached OAuth2 token");
                    return Ok(cached.access_token.clone());
                }
            }
        }

        // Need a new token
        tracing::info!(%backend_id, grant_type = %self.config.grant_type, "acquiring OAuth2 token");

        let token_endpoint = self.resolve_token_endpoint()?;

        match self.config.grant_type.as_str() {
            "client_credentials" => self.do_client_credentials(&token_endpoint, backend_id).await,
            "authorization_code" => {
                Err(BackendError::new(
                    BackendErrorKind::Auth,
                    "authorization_code grant requires interactive flow; use client_credentials for headless operation",
                ))
            }
            other => Err(BackendError::new(
                BackendErrorKind::Auth,
                format!("unsupported OAuth2 grant type: {other}"),
            )),
        }
    }

    fn resolve_token_endpoint(&self) -> Result<String, BackendError> {
        // Prefer configured token endpoint
        if let Some(ref endpoint) = self.config.token_endpoint {
            if !endpoint.is_empty() {
                return Ok(endpoint.clone());
            }
        }

        // Fall back to discovered metadata
        let metadata = self.metadata.lock().unwrap();
        if let Some(ref meta) = *metadata {
            return Ok(meta.token_endpoint.clone());
        }

        Err(BackendError::new(
            BackendErrorKind::Auth,
            "no OAuth2 token endpoint configured or discovered",
        ))
    }

    async fn do_client_credentials(
        &self,
        token_endpoint: &str,
        backend_id: &str,
    ) -> Result<String, BackendError> {
        let client_id = self.config.client_id.as_deref().ok_or_else(|| {
            BackendError::new(BackendErrorKind::Auth, "OAuth2 client_id not configured")
        })?;

        let client_secret = self.config.client_secret.as_deref().ok_or_else(|| {
            BackendError::new(BackendErrorKind::Auth, "OAuth2 client_secret not configured")
        })?;

        let scopes = self.config.scopes.as_deref().unwrap_or("mcp");

        tracing::debug!(%backend_id, %token_endpoint, %client_id, %scopes, "running client_credentials grant");

        let response = self
            .client
            .post(token_endpoint)
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", client_id),
                ("client_secret", client_secret),
                ("scope", scopes),
            ])
            .send()
            .await
            .map_err(|e| {
                BackendError::new(
                    BackendErrorKind::Auth,
                    format!("OAuth2 token request failed: {e}"),
                )
            })?;

        let status = response.status();
        let body: serde_json::Value = response.json().await.map_err(|e| {
            BackendError::new(
                BackendErrorKind::Auth,
                format!("failed to parse OAuth2 token response: {e}"),
            )
        })?;

        if !status.is_success() {
            let error_desc = body
                .get("error_description")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error");
            return Err(BackendError::new(
                BackendErrorKind::Auth,
                format!("OAuth2 token endpoint returned {status}: {error_desc}"),
            ));
        }

        let access_token = body
            .get("access_token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                BackendError::new(
                    BackendErrorKind::Auth,
                    "OAuth2 token response missing 'access_token'",
                )
            })?;

        let expires_in = body
            .get("expires_in")
            .and_then(|v| v.as_u64())
            .unwrap_or(3600); // default 1 hour

        // Cache the token
        let expires_at = Instant::now() + Duration::from_secs(expires_in);
        *self.token_cache.lock().unwrap() = Some(TokenCache {
            access_token: access_token.to_string(),
            expires_at,
        });

        tracing::info!(%backend_id, expires_in, "OAuth2 token acquired");

        Ok(access_token.to_string())
    }
}

/// Parse OAuth2 metadata from a WWW-Authenticate header.
/// Per MCP spec: `WWW-Authenticate: Bearer resource_metadata="<url>"`
pub fn parse_oauth2_metadata(header_value: &str) -> Option<OAuth2Metadata> {
    // Check for Bearer auth scheme with resource_metadata
    if !header_value.starts_with("Bearer ") {
        return None;
    }

    // Extract resource_metadata URL
    let rest = &header_value[7..]; // after "Bearer "
    let metadata_url = rest
        .split(',')
        .find_map(|part| {
            let part = part.trim();
            if part.starts_with("resource_metadata=\"") {
                let url = &part[20..]; // after 'resource_metadata="'
                url.strip_suffix('"')
            } else {
                None
            }
        })?;

    // We can't fetch the metadata here (needs async). Return a placeholder
    // that the caller can fetch.
    Some(OAuth2Metadata {
        issuer: None,
        token_endpoint: metadata_url.to_string(),
        authorization_endpoint: None,
        registration_endpoint: None,
        scopes_supported: None,
        grant_types_supported: None,
    })
}
