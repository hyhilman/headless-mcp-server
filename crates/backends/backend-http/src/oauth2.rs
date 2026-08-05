//! OAuth2 token management for HTTP backends.
//!
//! Supports:
//! - MCP OAuth2 automated discovery from 401 WWW-Authenticate headers
//! - Client credentials grant (machine-to-machine)
//! - Authorization code + PKCE grant (interactive, with local callback server)
//! - Automatic token refresh

use headless_mcp_core::{BackendError, BackendErrorKind, OAuth2Config};
use serde::Deserialize;
use std::sync::Mutex as StdMutex;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// OAuth2 protected resource metadata (RFC 9728 / MCP spec).
#[derive(Debug, Clone, Deserialize)]
pub struct ResourceMetadata {
    pub resource: String,
    pub authorization_servers: Option<Vec<String>>,
    pub scopes_supported: Option<Vec<String>>,
    pub bearer_methods_supported: Option<Vec<String>>,
    pub resource_name: Option<String>,
}

/// OAuth2 authorization server metadata (RFC 8414).
#[derive(Debug, Clone, Deserialize)]
pub struct AuthServerMetadata {
    pub issuer: String,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: String,
    pub registration_endpoint: Option<String>,
    pub scopes_supported: Option<Vec<String>>,
    pub response_types_supported: Option<Vec<String>>,
    pub grant_types_supported: Option<Vec<String>>,
    pub code_challenge_methods_supported: Option<Vec<String>>,
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
}

/// The fully discovered OAuth2 metadata for a backend.
#[derive(Debug, Clone)]
pub struct DiscoveredOAuth2 {
    pub resource_metadata: ResourceMetadata,
    pub auth_server_metadata: AuthServerMetadata,
}

/// A cached OAuth2 access token with refresh capability.
#[derive(Debug, Clone)]
struct TokenCache {
    access_token: String,
    refresh_token: Option<String>,
    expires_at: Instant,
}

/// Manages OAuth2 token lifecycle for an HTTP backend.
pub struct OAuth2TokenManager {
    config: OAuth2Config,
    /// Cached token.
    token_cache: Mutex<Option<TokenCache>>,
    /// Discovered metadata from 401 responses.
    discovered: StdMutex<Option<DiscoveredOAuth2>>,
    /// HTTP client for token requests.
    client: reqwest::Client,
}

impl OAuth2TokenManager {
    pub fn new(config: OAuth2Config) -> Self {
        Self {
            config,
            token_cache: Mutex::new(None),
            discovered: StdMutex::new(None),
            client: reqwest::Client::new(),
        }
    }

    /// Load a cached token (from persistence layer).
    pub fn set_cached_token(&self, access_token: &str, refresh_token: Option<&str>) {
        let cache = TokenCache {
            access_token: access_token.to_string(),
            refresh_token: refresh_token.map(|s| s.to_string()),
            expires_at: Instant::now(),
        };
        *self.token_cache.try_lock().expect("token_cache") = Some(cache);
    }

    /// Return current refresh token for persistence.
    pub fn current_refresh_token(&self) -> Option<String> {
        self.token_cache.try_lock().ok()?.as_ref()?.refresh_token.clone()
    }

    /// Get a valid access token.
    ///
    /// If the URL is an RFC 9728 resource metadata URL (contains
    /// "oauth-protected-resource"), we fetch it first to discover the
    /// authorization server, then fetch RFC 8414 auth server metadata.
    ///
    /// If the URL is already an RFC 8414 auth server URL (contains
    /// "oauth-authorization-server"), we fetch it directly.
    pub async fn discover(
        &self,
        discovery_url: &str,
        backend_id: &str,
    ) -> Result<DiscoveredOAuth2, BackendError> {
        let auth_server_url = if discovery_url.contains("oauth-protected-resource") {
            // Step 1: fetch RFC 9728 resource metadata
            tracing::info!(%backend_id, %discovery_url, "fetching OAuth2 resource metadata");

            let resource_metadata: ResourceMetadata = self
                .client
                .get(discovery_url)
                .send()
                .await
                .map_err(|e| BackendError::new(
                    BackendErrorKind::Auth,
                    format!("failed to fetch resource metadata: {e}"),
                ))?
                .json()
                .await
                .map_err(|e| BackendError::new(
                    BackendErrorKind::Auth,
                    format!("failed to parse resource metadata: {e}"),
                ))?;

            tracing::info!(
                %backend_id,
                resource = %resource_metadata.resource,
                "resource metadata fetched"
            );

            // Step 2: determine authorization server URL
            resource_metadata
                .authorization_servers
                .as_ref()
                .and_then(|servers| servers.first())
                .map(|url| format!("{url}/.well-known/oauth-authorization-server"))
                .ok_or_else(|| BackendError::new(
                    BackendErrorKind::Auth,
                    "resource metadata has no authorization_servers",
                ))?
        } else {
            // Already an RFC 8414 auth server URL (standard well-known fallback)
            discovery_url.to_string()
        };

        // Step 3: fetch RFC 8414 authorization server metadata
        tracing::info!(%backend_id, %auth_server_url, "fetching authorization server metadata");

        let auth_server_metadata: AuthServerMetadata = self
            .client
            .get(&auth_server_url)
            .send()
            .await
            .map_err(|e| BackendError::new(
                BackendErrorKind::Auth,
                format!("failed to fetch auth server metadata: {e}"),
            ))?
            .json()
            .await
            .map_err(|e| BackendError::new(
                BackendErrorKind::Auth,
                format!("failed to parse auth server metadata: {e}"),
            ))?;

        tracing::info!(
            %backend_id,
            issuer = %auth_server_metadata.issuer,
            token_endpoint = %auth_server_metadata.token_endpoint,
            grants = ?auth_server_metadata.grant_types_supported,
            "authorization server metadata fetched"
        );

        let discovered = DiscoveredOAuth2 {
            resource_metadata: ResourceMetadata {
                resource: String::new(),
                authorization_servers: None,
                scopes_supported: auth_server_metadata.scopes_supported.clone(),
                bearer_methods_supported: None,
                resource_name: None,
            },
            auth_server_metadata,
        };
        *self.discovered.lock().unwrap() = Some(discovered.clone());
        Ok(discovered)
    }

    /// Get a valid access token. Runs discovery, acquires token, caches it.
    pub async fn get_token(&self, backend_id: &str, daemon_mode: bool) -> Result<String, BackendError> {
        // Check cache first
        {
            let cache = self.token_cache.lock().await;
            if let Some(cached) = cache.as_ref() {
                if cached.expires_at > Instant::now() + Duration::from_secs(30) {
                    tracing::debug!(%backend_id, "using cached OAuth2 token");
                    return Ok(cached.access_token.clone());
                }

                // Try refresh if we have a refresh token
                if let Some(refresh_token) = &cached.refresh_token {
                    tracing::debug!(%backend_id, "attempting token refresh");
                    match self.do_refresh(refresh_token, backend_id).await {
                        Ok(new_token) => return Ok(new_token),
                        Err(e) => tracing::warn!(%e, "token refresh failed, will re-acquire"),
                    }
                }
            }
        }

        // Need a new token
        let token_endpoint = self.resolve_token_endpoint()?;
        let grant_type = self.resolve_grant_type()?;

        tracing::info!(%backend_id, %grant_type, %token_endpoint, "acquiring OAuth2 token");

        match grant_type.as_str() {
            "client_credentials" => {
                self.do_client_credentials(&token_endpoint, backend_id).await
            }
            "authorization_code" => {
                if daemon_mode {
                    return Err(BackendError::new(
                        BackendErrorKind::Auth,
                        "authorization_code grant requires interactive consent; run 'headless-mcp --dry-run' to authenticate",
                    ));
                }
                self.do_authorization_code(&token_endpoint, backend_id).await
            }
            "urn:ietf:params:oauth:grant-type:jwt-bearer" => {
                Err(BackendError::new(
                    BackendErrorKind::Auth,
                    "JWT bearer grant is not yet supported by headless-mcp",
                ))
            }
            other => Err(BackendError::new(
                BackendErrorKind::Auth,
                format!("unsupported OAuth2 grant type: {other}"),
            )),
        }
    }

    fn resolve_token_endpoint(&self) -> Result<String, BackendError> {
        if let Some(ref endpoint) = self.config.token_endpoint {
            if !endpoint.is_empty() {
                return Ok(endpoint.clone());
            }
        }
        if let Some(ref disc) = *self.discovered.lock().unwrap() {
            return Ok(disc.auth_server_metadata.token_endpoint.clone());
        }
        Err(BackendError::new(
            BackendErrorKind::Auth,
            "no OAuth2 token endpoint configured or discovered",
        ))
    }

    fn resolve_grant_type(&self) -> Result<String, BackendError> {
        if !self.config.grant_type.is_empty()
            && self.config.grant_type != "client_credentials"
        {
            return Ok(self.config.grant_type.clone());
        }
        Ok("client_credentials".to_string())
    }

    /// Dynamically register a client at the registration endpoint (RFC 7591).
    async fn register_client(&self, backend_id: &str) -> Result<(String, Option<String>), BackendError> {
        let registration_endpoint = {
            let discovered = self.discovered.lock().unwrap();
            discovered
                .as_ref()
                .and_then(|d| d.auth_server_metadata.registration_endpoint.clone())
        };

        let registration_endpoint = match registration_endpoint {
            Some(url) => url,
            None => return Ok((String::new(), None)),
        };

        tracing::info!(%backend_id, %registration_endpoint, "registering OAuth2 client");

        let redirect_uri = format!("http://localhost:{}/callback", self.config.callback_port);
        let body = serde_json::json!({
            "client_name": "headless-mcp",
            "redirect_uris": [redirect_uri],
            "grant_types": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_method": "none"
        });

        let response = self
            .client
            .post(&registration_endpoint)
            .json(&body)
            .send()
            .await
            .map_err(|e| BackendError::new(
                BackendErrorKind::Auth,
                format!("dynamic client registration failed: {e}"),
            ))?;

        let status = response.status();
        let reg: serde_json::Value = response.json().await.map_err(|e| {
            BackendError::new(
                BackendErrorKind::Auth,
                format!("failed to parse registration response: {e}"),
            )
        })?;

        if !status.is_success() {
            return Err(BackendError::new(
                BackendErrorKind::Auth,
                format!("registration failed ({status}): {reg}"),
            ));
        }

        let client_id = reg
            .get("client_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| BackendError::new(
                BackendErrorKind::Auth,
                "registration response missing client_id",
            ))?;

        let client_secret = reg.get("client_secret").and_then(|v| v.as_str()).map(|s| s.to_string());

        tracing::info!(%backend_id, %client_id, "OAuth2 client registered");
        Ok((client_id.to_string(), client_secret))
    }

    async fn do_client_credentials(
        &self,
        token_endpoint: &str,
        backend_id: &str,
    ) -> Result<String, BackendError> {
        let (client_id, client_secret) = if let (Some(cid), Some(cs)) = (&self.config.client_id, &self.config.client_secret) {
            (cid.clone(), cs.clone())
        } else if let Some(ref cid) = self.config.client_id {
            // client_id but no secret — try without secret (some providers allow "none" auth)
            (cid.clone(), String::new())
        } else {
            // Try dynamic registration
            let reg_endpoint = {
                let discovered = self.discovered.lock().unwrap();
                discovered.as_ref().and_then(|d| d.auth_server_metadata.registration_endpoint.clone())
            };
            if let Some(ep) = reg_endpoint {
                let (cid, cs) = self.register_client(backend_id).await?;
                (cid, cs.unwrap_or_default())
            } else {
                return Err(BackendError::new(
                    BackendErrorKind::Auth,
                    "OAuth2 client_id not configured and no registration endpoint",
                ));
            }
        };

        let scopes = self.config.scopes.as_deref().unwrap_or("mcp");

        tracing::debug!(%backend_id, %token_endpoint, %client_id, "running client_credentials grant");

        let response = self
            .client
            .post(token_endpoint)
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", &*client_id),
                ("client_secret", &*client_secret),
                ("scope", scopes),
            ])
            .send()
            .await
            .map_err(|e| BackendError::new(
                BackendErrorKind::Auth,
                format!("OAuth2 token request failed: {e}"),
            ))?;

        let status = response.status();
        let body: serde_json::Value = response.json().await.map_err(|e| {
            BackendError::new(
                BackendErrorKind::Auth,
                format!("failed to parse token response: {e}"),
            )
        })?;

        if !status.is_success() {
            let error_desc = body
                .get("error_description")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error");
            return Err(BackendError::new(
                BackendErrorKind::Auth,
                format!("token endpoint returned {status}: {error_desc}"),
            ));
        }

        self.cache_token_response(&body, backend_id).await
    }

    async fn do_authorization_code(
        &self,
        token_endpoint: &str,
        backend_id: &str,
    ) -> Result<String, BackendError> {
        // Clone the auth endpoint out of the lock scope before awaiting
        let auth_endpoint = {
            let discovered = self.discovered.lock().unwrap();
            discovered
                .as_ref()
                .and_then(|d| d.auth_server_metadata.authorization_endpoint.clone())
                .unwrap_or_else(|| token_endpoint.to_string())
        };

        let pkce_methods = {
            let discovered = self.discovered.lock().unwrap();
            discovered
                .as_ref()
                .and_then(|d| d.auth_server_metadata.code_challenge_methods_supported.clone())
                .unwrap_or_default()
        };

        // Try dynamic registration if no client_id configured
        let client_id = if let Some(cid) = &self.config.client_id {
            cid.clone()
        } else {
            let reg_endpoint = {
                let discovered = self.discovered.lock().unwrap();
                discovered
                    .as_ref()
                    .and_then(|d| d.auth_server_metadata.registration_endpoint.clone())
            };
            match reg_endpoint {
                Some(ep) => {
                    tracing::info!(%backend_id, %ep, "no client_id, attempting dynamic registration");
                    self.register_client(backend_id).await?.0
                }
                None => {
                    return Err(BackendError::new(
                        BackendErrorKind::Auth,
                        "OAuth2 client_id not configured and no registration endpoint discovered",
                    ));
                }
            }
        };

        // Generate PKCE code verifier and challenge
        let (code_verifier, code_challenge) = if pkce_methods.iter().any(|m| m == "S256") {
            generate_pkce_s256()
        } else {
            generate_pkce_plain()
        };

        let redirect_port = self.config.callback_port;
        let redirect_uri = format!("http://localhost:{redirect_port}/callback");

        // Use configured scopes, or fall back to discovered scopes from metadata
        let scopes = if let Some(ref s) = self.config.scopes {
            s.clone()
        } else {
            let discovered = self.discovered.lock().unwrap();
            discovered
                .as_ref()
                .and_then(|d| d.auth_server_metadata.scopes_supported.clone())
                .map(|s| s.join(" "))
                .unwrap_or_default()
        };

        // Build auth URL — only include scope if configured
        let mut auth_url = format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&code_challenge={}&code_challenge_method=S256",
            auth_endpoint, client_id, redirect_uri, code_challenge
        );
        if !scopes.is_empty() {
            auth_url.push_str(&format!("&scope={scopes}"));
        }

        tracing::info!(%backend_id, %auth_url, "opening browser for OAuth2 authorization");

        println!("\n═══ Opening browser for {backend_id} authorization ═══");

        // Auto-open the browser
        if let Err(_) = open::that(&auth_url) {
            // Fallback: print the URL
            eprintln!("\n╔══════════════════════════════════════════════════════════╗");
            eprintln!("║  OAuth2 Authorization Required                           ║");
            eprintln!("║                                                          ║");
            eprintln!("║  Open this URL in a browser to authorize headless-mcp:   ║");
            eprintln!("║  {auth_url}");
            eprintln!("║                                                          ║");
            eprintln!("╚══════════════════════════════════════════════════════════╝\n");
        }

        // Step 2: Start local callback server
        let code = receive_callback(redirect_port).await?;

        // Step 3: Exchange code for token
        let response = self
            .client
            .post(token_endpoint)
            .form(&[
                ("grant_type", "authorization_code"),
                ("client_id", client_id.as_str()),
                ("code", &code),
                ("redirect_uri", &redirect_uri),
                ("code_verifier", &code_verifier),
            ])
            .send()
            .await
            .map_err(|e| BackendError::new(
                BackendErrorKind::Auth,
                format!("token request failed: {e}"),
            ))?;

        let status = response.status();
        let body: serde_json::Value = response.json().await.map_err(|e| {
            BackendError::new(
                BackendErrorKind::Auth,
                format!("failed to parse token response: {e}"),
            )
        })?;

        if !status.is_success() {
            let error_desc = body
                .get("error_description")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error");
            return Err(BackendError::new(
                BackendErrorKind::Auth,
                format!("token endpoint returned {status}: {error_desc}"),
            ));
        }

        self.cache_token_response(&body, backend_id).await
    }

    async fn do_refresh(
        &self,
        refresh_token: &str,
        backend_id: &str,
    ) -> Result<String, BackendError> {
        let token_endpoint = self.resolve_token_endpoint()?;
        let client_id = self.config.client_id.as_deref().unwrap_or("");
        let client_secret = self.config.client_secret.as_deref().unwrap_or("");

        tracing::debug!(%backend_id, "refreshing OAuth2 token");

        let response = self
            .client
            .post(&token_endpoint)
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
                ("client_id", client_id),
                ("client_secret", client_secret),
            ])
            .send()
            .await
            .map_err(|e| BackendError::new(
                BackendErrorKind::Auth,
                format!("token refresh failed: {e}"),
            ))?;

        let status = response.status();
        let body: serde_json::Value = response.json().await.map_err(|e| {
            BackendError::new(
                BackendErrorKind::Auth,
                format!("failed to parse refresh response: {e}"),
            )
        })?;

        if !status.is_success() {
            let error_desc = body
                .get("error_description")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error");
            return Err(BackendError::new(
                BackendErrorKind::Auth,
                format!("refresh failed ({status}): {error_desc}"),
            ));
        }

        self.cache_token_response(&body, backend_id).await
    }

    async fn cache_token_response(
        &self,
        body: &serde_json::Value,
        backend_id: &str,
    ) -> Result<String, BackendError> {
        let access_token = body
            .get("access_token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                BackendError::new(BackendErrorKind::Auth, "response missing 'access_token'")
            })?;

        let refresh_token = body.get("refresh_token").and_then(|v| v.as_str()).map(|s| s.to_string());
        let expires_in = body.get("expires_in").and_then(|v| v.as_u64()).unwrap_or(3600);
        let expires_at = Instant::now() + Duration::from_secs(expires_in);

        *self.token_cache.lock().await = Some(TokenCache {
            access_token: access_token.to_string(),
            refresh_token,
            expires_at,
        });

        tracing::info!(%backend_id, expires_in, "OAuth2 token cached");
        Ok(access_token.to_string())
    }
}

/// Parse OAuth2 metadata URL from a WWW-Authenticate header.
/// Per MCP spec: `WWW-Authenticate: Bearer resource_metadata="<url>"`
pub fn parse_resource_metadata_url(header_value: &str) -> Option<String> {
    if !header_value.starts_with("Bearer ") {
        return None;
    }

    let rest = &header_value[7..]; // after "Bearer "
    rest.split(',')
        .find_map(|part| {
            let part = part.trim();
            if part.starts_with("resource_metadata=\"") {
                let url = &part[19..];
                url.strip_suffix('"').map(|s| s.to_string())
            } else {
                None
            }
        })
}

// ── PKCE utilities ──

fn generate_pkce_s256() -> (String, String) {
    use rand::RngCore;
    use sha2::{Digest, Sha256};

    let mut verifier_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut verifier_bytes);
    let verifier = base64_url_no_pad(&verifier_bytes);

    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let challenge = base64_url_no_pad(&hasher.finalize());

    (verifier, challenge)
}

fn generate_pkce_plain() -> (String, String) {
    use rand::RngCore;
    let mut verifier_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut verifier_bytes);
    let verifier = base64_url_no_pad(&verifier_bytes);
    (verifier.clone(), verifier)
}

fn base64_url_no_pad(bytes: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(bytes)
}

// ── Local callback server for authorization_code flow ──

use std::net::SocketAddr;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

async fn receive_callback(port: u16) -> Result<String, BackendError> {
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let listener = TcpListener::bind(addr).await.map_err(|e| {
        BackendError::new(
            BackendErrorKind::Auth,
            format!("failed to bind callback server: {e}"),
        )
    })?;

    tracing::info!("waiting for OAuth2 callback on http://127.0.0.1:{port}/callback");

    // Accept one connection
    let (mut stream, peer) = listener.accept().await.map_err(|e| {
        BackendError::new(
            BackendErrorKind::Auth,
            format!("callback server accept failed: {e}"),
        )
    })?;

    let mut reader = BufReader::new(&mut stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line).await.map_err(|e| {
        BackendError::new(BackendErrorKind::Auth, format!("read request failed: {e}"))
    })?;

    // Parse the code from the URL
    let code = request_line
        .split_whitespace()
        .nth(1)
        .and_then(|path| {
            path.split('?')
                .nth(1)
                .and_then(|query| {
                    query.split('&').find_map(|param| {
                        let (k, v) = param.split_once('=')?;
                        if k == "code" {
                            Some(percent_decode(v))
                        } else { None }
                    })
                })
        })
        .ok_or_else(|| {
            BackendError::new(BackendErrorKind::Auth, "no authorization code in callback")
        })?;

    // Send a response to the browser
    let response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n\
        <html><body><h1>Authorization Complete</h1><p>You can close this window.</p></body></html>";
    stream.write_all(response.as_bytes()).await.map_err(|e| {
        BackendError::new(BackendErrorKind::Auth, format!("write response failed: {e}"))
    })?;
    stream.shutdown().await.ok();

    tracing::info!("OAuth2 authorization code received");
    Ok(code)
}

/// Simple percent-decoding for URL-encoded query parameters.
fn percent_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '%' {
            let h = chars.next().and_then(|c| c.to_digit(16));
            let l = chars.next().and_then(|c| c.to_digit(16));
            if let (Some(h), Some(l)) = (h, l) {
                out.push(char::from_u32((h << 4) | l).unwrap_or('?'));
            }
        } else if c == '+' {
            out.push(' ');
        } else {
            out.push(c);
        }
    }
    out
}
