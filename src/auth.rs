//! Authentication gates for HTTP and gRPC endpoints.
//!
//! Supports disabled mode, shared token introspection, and OIDC JWT validation.

use crate::config::{AuthConfig, OidcAuthConfig, TokenAuthConfig};
use axum::http::{HeaderMap, StatusCode};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthMode {
    Off,
    Token,
    Oidc,
}

impl AuthMode {
    fn parse(raw: &str) -> Self {
        match raw.trim().to_lowercase().as_str() {
            "token" => AuthMode::Token,
            "oidc" => AuthMode::Oidc,
            _ => AuthMode::Off,
        }
    }
}

#[derive(Clone)]
pub struct AuthSystem {
    mode: AuthMode,
    token_validator: Option<Arc<TokenValidator>>,
    oidc_validator: Option<Arc<OidcValidator>>,
    protect_status: bool,
    protect_otlp_http: bool,
    protect_otlp_grpc: bool,
}

impl AuthSystem {
    /// Builds auth system from runtime config.
    pub fn from_config(cfg: &AuthConfig) -> Self {
        let mode = AuthMode::parse(&cfg.mode);
        let token_validator = if mode == AuthMode::Token && cfg.token.enabled() {
            Some(Arc::new(TokenValidator::new(cfg.token.clone())))
        } else {
            None
        };
        let oidc_validator = if mode == AuthMode::Oidc && cfg.oidc.enabled() {
            Some(Arc::new(OidcValidator::new(cfg.oidc.clone())))
        } else {
            None
        };
        Self {
            mode,
            token_validator,
            oidc_validator,
            protect_status: cfg.protect_status,
            protect_otlp_http: cfg.protect_otlp_http,
            protect_otlp_grpc: cfg.protect_otlp_grpc,
        }
    }

    /// Gate for status endpoints.
    pub fn status_gate(&self) -> AuthGate {
        AuthGate::new(
            self.mode,
            self.protect_status,
            self.token_validator.clone(),
            self.oidc_validator.clone(),
        )
    }

    /// Gate for OTLP/HTTP ingest endpoint.
    pub fn otlp_http_gate(&self) -> AuthGate {
        AuthGate::new(
            self.mode,
            self.protect_otlp_http,
            self.token_validator.clone(),
            self.oidc_validator.clone(),
        )
    }

    /// Gate for OTLP/gRPC ingest endpoint.
    pub fn otlp_grpc_gate(&self) -> AuthGate {
        AuthGate::new(
            self.mode,
            self.protect_otlp_grpc,
            self.token_validator.clone(),
            self.oidc_validator.clone(),
        )
    }
}

#[derive(Clone)]
pub struct AuthGate {
    mode: AuthMode,
    enabled: bool,
    token_validator: Option<Arc<TokenValidator>>,
    oidc_validator: Option<Arc<OidcValidator>>,
}

impl AuthGate {
    fn new(
        mode: AuthMode,
        enabled: bool,
        token_validator: Option<Arc<TokenValidator>>,
        oidc_validator: Option<Arc<OidcValidator>>,
    ) -> Self {
        Self {
            mode,
            enabled,
            token_validator,
            oidc_validator,
        }
    }

    pub async fn authorize_http(&self, headers: &HeaderMap) -> Result<(), StatusCode> {
        if !self.enabled || self.mode == AuthMode::Off {
            return Ok(());
        }
        let token = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(extract_bearer);
        match self.mode {
            AuthMode::Off => Ok(()),
            AuthMode::Token => match token {
                Some(token) => self
                    .token_validator
                    .as_ref()
                    .ok_or(StatusCode::SERVICE_UNAVAILABLE)?
                    .validate(token)
                    .await
                    .map_err(|err| err.to_status_code()),
                None => Err(StatusCode::UNAUTHORIZED),
            },
            AuthMode::Oidc => match token {
                Some(token) => self
                    .oidc_validator
                    .as_ref()
                    .ok_or(StatusCode::SERVICE_UNAVAILABLE)?
                    .validate(token)
                    .await
                    .map_err(|err| err.to_status_code()),
                None => Err(StatusCode::UNAUTHORIZED),
            },
        }
    }

    pub async fn authorize_grpc(
        &self,
        metadata: &tonic::metadata::MetadataMap,
    ) -> Result<(), tonic::Status> {
        if !self.enabled || self.mode == AuthMode::Off {
            return Ok(());
        }
        let token = metadata
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(extract_bearer);
        match self.mode {
            AuthMode::Off => Ok(()),
            AuthMode::Token => {
                let validator = self
                    .token_validator
                    .as_ref()
                    .ok_or_else(|| tonic::Status::unavailable("token auth not configured"))?;
                match token {
                    Some(token) => validator
                        .validate(token)
                        .await
                        .map_err(|err| err.to_tonic_status()),
                    None => Err(tonic::Status::unauthenticated("missing authorization")),
                }
            }
            AuthMode::Oidc => {
                let validator = self
                    .oidc_validator
                    .as_ref()
                    .ok_or_else(|| tonic::Status::unavailable("oidc not configured"))?;
                match token {
                    Some(token) => validator
                        .validate(token)
                        .await
                        .map_err(|err| err.to_tonic_status()),
                    None => Err(tonic::Status::unauthenticated("missing authorization")),
                }
            }
        }
    }
}

fn extract_bearer(raw: &str) -> Option<&str> {
    let raw = raw.trim();
    if let Some(value) = raw.strip_prefix("Bearer ") {
        return Some(value.trim());
    }
    if let Some(value) = raw.strip_prefix("bearer ") {
        return Some(value.trim());
    }
    None
}

#[derive(Debug)]
pub struct TokenValidator {
    cfg: TokenAuthConfig,
    client: reqwest::Client,
    cache: RwLock<HashMap<String, TokenCacheEntry>>,
}

#[derive(Debug, Clone)]
struct TokenCacheEntry {
    authenticated: bool,
    expires_at: Instant,
}

#[derive(Debug, Deserialize)]
struct TokenSessionResponse {
    authenticated: bool,
    user: Option<String>,
}

#[derive(Debug)]
pub enum TokenError {
    MissingToken,
    MissingConfig,
    ServiceUnavailable,
    InvalidToken,
}

impl TokenError {
    fn to_status_code(&self) -> StatusCode {
        match self {
            TokenError::MissingToken | TokenError::InvalidToken => StatusCode::UNAUTHORIZED,
            TokenError::MissingConfig | TokenError::ServiceUnavailable => {
                StatusCode::SERVICE_UNAVAILABLE
            }
        }
    }

    fn to_tonic_status(&self) -> tonic::Status {
        match self {
            TokenError::MissingToken => tonic::Status::unauthenticated("missing token"),
            TokenError::InvalidToken => tonic::Status::unauthenticated("invalid token"),
            TokenError::MissingConfig => tonic::Status::unavailable("token auth not configured"),
            TokenError::ServiceUnavailable => {
                tonic::Status::unavailable("central token validation unavailable")
            }
        }
    }
}

impl TokenValidator {
    /// Creates a token validator with a bounded TTL cache for Refiner session lookups.
    pub fn new(cfg: TokenAuthConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(cfg.http_timeout_ms))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            cfg,
            client,
            cache: RwLock::new(HashMap::new()),
        }
    }

    /// Validates a bearer token via the central session endpoint, with static-token fallback.
    pub async fn validate(&self, token: &str) -> Result<(), TokenError> {
        let token = token.trim();
        if token.is_empty() {
            return Err(TokenError::MissingToken);
        }
        if !self.cfg.enabled() {
            return Err(TokenError::MissingConfig);
        }

        if let Some(entry) = self.cached(token).await {
            return if entry.authenticated {
                Ok(())
            } else {
                Err(TokenError::InvalidToken)
            };
        }

        match self.validate_central_session(token).await {
            Ok(Some(true)) => {
                self.cache_result(token, true, self.cfg.cache_ttl_ms).await;
                Ok(())
            }
            Ok(Some(false)) | Ok(None) => {
                if self.matches_static_token(token) {
                    self.cache_result(token, true, self.cfg.cache_ttl_ms).await;
                    Ok(())
                } else {
                    self.cache_result(token, false, self.negative_cache_ttl_ms())
                        .await;
                    Err(TokenError::InvalidToken)
                }
            }
            Err(err) => {
                if self.matches_static_token(token) {
                    self.cache_result(token, true, self.cfg.cache_ttl_ms).await;
                    Ok(())
                } else {
                    self.cache_result(token, false, self.negative_cache_ttl_ms())
                        .await;
                    Err(err)
                }
            }
        }
    }

    async fn validate_central_session(&self, token: &str) -> Result<Option<bool>, TokenError> {
        let Some(session_url) = self
            .cfg
            .session_url
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            return Ok(None);
        };

        let response = self
            .client
            .get(session_url)
            .header("Accept", "application/json")
            .bearer_auth(token)
            .send()
            .await
            .map_err(|_| TokenError::ServiceUnavailable)?;

        let status = response.status();
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN
        {
            return Ok(Some(false));
        }
        if status.is_server_error() || !status.is_success() {
            return Err(TokenError::ServiceUnavailable);
        }

        let payload = response
            .json::<TokenSessionResponse>()
            .await
            .map_err(|_| TokenError::ServiceUnavailable)?;
        Ok(Some(
            payload.authenticated
                && payload
                    .user
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .is_some(),
        ))
    }

    fn matches_static_token(&self, token: &str) -> bool {
        self.cfg
            .static_token
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            == Some(token)
    }

    fn negative_cache_ttl_ms(&self) -> u64 {
        self.cfg.cache_ttl_ms.min(2_000).max(250)
    }

    async fn cached(&self, token: &str) -> Option<TokenCacheEntry> {
        let now = Instant::now();
        {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.get(token) {
                if entry.expires_at > now {
                    return Some(entry.clone());
                }
            }
        }
        let mut cache = self.cache.write().await;
        if let Some(entry) = cache.get(token) {
            if entry.expires_at > now {
                return Some(entry.clone());
            }
        }
        cache.remove(token)
    }

    async fn cache_result(&self, token: &str, authenticated: bool, ttl_ms: u64) {
        const MAX_CACHE_ENTRIES: usize = 1024;

        let now = Instant::now();
        let mut cache = self.cache.write().await;
        cache.retain(|_, entry| entry.expires_at > now);
        if cache.len() >= MAX_CACHE_ENTRIES {
            cache.clear();
        }
        cache.insert(
            token.to_string(),
            TokenCacheEntry {
                authenticated,
                expires_at: now + Duration::from_millis(ttl_ms.max(1)),
            },
        );
    }
}

#[derive(Debug)]
pub struct OidcValidator {
    cfg: OidcAuthConfig,
    client: reqwest::Client,
    cache: RwLock<OidcCache>,
}

#[derive(Debug)]
struct OidcCache {
    jwks: Option<JwkSet>,
    jwks_expires_at: Instant,
    discovery: Option<OidcDiscovery>,
    discovery_expires_at: Instant,
}

#[derive(Debug, Clone)]
struct OidcDiscovery {
    jwks_uri: String,
}

#[derive(Debug)]
pub enum OidcError {
    MissingToken,
    MissingConfig,
    DiscoveryFailed,
    JwksFailed,
    KeyNotFound,
    UnsupportedAlg,
    InvalidToken,
    ScopeMismatch,
}

impl OidcError {
    fn to_status_code(&self) -> StatusCode {
        match self {
            OidcError::MissingToken => StatusCode::UNAUTHORIZED,
            OidcError::ScopeMismatch => StatusCode::FORBIDDEN,
            OidcError::MissingConfig => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::UNAUTHORIZED,
        }
    }

    fn to_tonic_status(&self) -> tonic::Status {
        match self {
            OidcError::MissingToken => tonic::Status::unauthenticated("missing token"),
            OidcError::ScopeMismatch => tonic::Status::permission_denied("scope mismatch"),
            OidcError::MissingConfig => tonic::Status::unavailable("oidc not configured"),
            _ => tonic::Status::unauthenticated("invalid token"),
        }
    }
}

impl OidcValidator {
    /// Creates an OIDC validator with TTL-cached discovery and JWKS fetches.
    pub fn new(cfg: OidcAuthConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(cfg.http_timeout_ms))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            cfg,
            client,
            cache: RwLock::new(OidcCache {
                jwks: None,
                jwks_expires_at: Instant::now(),
                discovery: None,
                discovery_expires_at: Instant::now(),
            }),
        }
    }

    /// Validates a JWT against configured issuer/JWKS/audience/scope rules.
    pub async fn validate(&self, token: &str) -> Result<(), OidcError> {
        if token.trim().is_empty() {
            return Err(OidcError::MissingToken);
        }
        if !self.cfg.enabled() {
            return Err(OidcError::MissingConfig);
        }

        let header = decode_header(token).map_err(|_| OidcError::InvalidToken)?;
        let kid = header.kid.ok_or(OidcError::KeyNotFound)?;
        let alg = header.alg;
        if !is_supported_alg(alg) {
            return Err(OidcError::UnsupportedAlg);
        }

        let jwks = self.jwks().await?;
        let jwk = jwks
            .keys
            .iter()
            .find(|key| key.common.key_id.as_deref() == Some(kid.as_str()))
            .ok_or(OidcError::KeyNotFound)?;
        let decoding_key = DecodingKey::from_jwk(jwk).map_err(|_| OidcError::InvalidToken)?;

        let mut validation = Validation::new(alg);
        validation.validate_exp = true;
        validation.leeway = self.cfg.leeway_sec as u64;
        if !self.cfg.issuer.is_empty() {
            validation.set_issuer(&[self.cfg.issuer.clone()]);
        }
        let mut audiences = self.cfg.audiences.clone();
        if audiences.is_empty() {
            if let Some(client_id) = self.cfg.client_id.as_ref() {
                audiences.push(client_id.clone());
            }
        }
        if !audiences.is_empty() {
            validation.set_audience(&audiences);
        }

        let data = decode::<Value>(token, &decoding_key, &validation)
            .map_err(|_| OidcError::InvalidToken)?;
        if !self.cfg.required_scopes.is_empty() {
            let scopes = extract_scopes(&data.claims);
            if !has_required_scopes(&scopes, &self.cfg.required_scopes) {
                return Err(OidcError::ScopeMismatch);
            }
        }
        Ok(())
    }

    async fn jwks(&self) -> Result<JwkSet, OidcError> {
        let now = Instant::now();
        {
            let cache = self.cache.read().await;
            if let Some(jwks) = cache.jwks.as_ref() {
                if now < cache.jwks_expires_at {
                    return Ok(jwks.clone());
                }
            }
        }

        let mut cache = self.cache.write().await;
        if let Some(jwks) = cache.jwks.as_ref() {
            if now < cache.jwks_expires_at {
                return Ok(jwks.clone());
            }
        }

        let jwks_url = if let Some(jwks_url) = self.cfg.jwks_url.as_ref() {
            jwks_url.clone()
        } else {
            let discovery = self.discovery(&mut cache).await?;
            discovery.jwks_uri
        };

        let resp = self
            .client
            .get(jwks_url)
            .send()
            .await
            .map_err(|_| OidcError::JwksFailed)?;
        if !resp.status().is_success() {
            return Err(OidcError::JwksFailed);
        }
        let jwks = resp
            .json::<JwkSet>()
            .await
            .map_err(|_| OidcError::JwksFailed)?;
        cache.jwks = Some(jwks.clone());
        cache.jwks_expires_at = now + Duration::from_millis(self.cfg.cache_ttl_ms);
        Ok(jwks)
    }

    async fn discovery(&self, cache: &mut OidcCache) -> Result<OidcDiscovery, OidcError> {
        let now = Instant::now();
        if let Some(discovery) = cache.discovery.as_ref() {
            if now < cache.discovery_expires_at {
                return Ok(discovery.clone());
            }
        }

        if self.cfg.issuer.is_empty() {
            return Err(OidcError::MissingConfig);
        }
        let url = format!(
            "{}/.well-known/openid-configuration",
            self.cfg.issuer.trim_end_matches('/')
        );
        let resp = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|_| OidcError::DiscoveryFailed)?;
        if !resp.status().is_success() {
            return Err(OidcError::DiscoveryFailed);
        }
        let payload = resp
            .json::<Value>()
            .await
            .map_err(|_| OidcError::DiscoveryFailed)?;
        let jwks_uri = payload
            .get("jwks_uri")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        if jwks_uri.is_empty() {
            return Err(OidcError::DiscoveryFailed);
        }
        let discovery = OidcDiscovery { jwks_uri };
        cache.discovery = Some(discovery.clone());
        cache.discovery_expires_at = now + Duration::from_millis(self.cfg.cache_ttl_ms);
        Ok(discovery)
    }
}

fn extract_scopes(claims: &Value) -> HashSet<String> {
    let mut scopes = HashSet::new();
    if let Some(scope) = claims.get("scope").and_then(|v| v.as_str()) {
        for item in scope.split_whitespace() {
            scopes.insert(item.to_string());
        }
    }
    if let Some(scope) = claims.get("scp").and_then(|v| v.as_str()) {
        for item in scope.split_whitespace() {
            scopes.insert(item.to_string());
        }
    }
    scopes
}

fn has_required_scopes(scopes: &HashSet<String>, required: &[String]) -> bool {
    required.iter().all(|s| scopes.contains(s))
}

fn is_supported_alg(alg: Algorithm) -> bool {
    matches!(
        alg,
        Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::ES256
            | Algorithm::ES384
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512
            | Algorithm::EdDSA
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, Router, routing::get};
    use serde_json::json;

    #[test]
    fn auth_mode_parse_defaults_to_off() {
        assert_eq!(AuthMode::parse("oidc"), AuthMode::Oidc);
        assert_eq!(AuthMode::parse("OIDC"), AuthMode::Oidc);
        assert_eq!(AuthMode::parse("off"), AuthMode::Off);
        assert_eq!(AuthMode::parse("unknown"), AuthMode::Off);
    }

    #[test]
    fn extract_bearer_accepts_common_cases() {
        assert_eq!(extract_bearer("Bearer abc"), Some("abc"));
        assert_eq!(extract_bearer("bearer xyz"), Some("xyz"));
        assert_eq!(extract_bearer("Token nope"), None);
    }

    #[test]
    fn required_scope_check_is_all_of() {
        let scopes = HashSet::from_iter(["read".to_string(), "write".to_string()]);
        assert!(has_required_scopes(&scopes, &["read".to_string()]));
        assert!(has_required_scopes(
            &scopes,
            &["read".to_string(), "write".to_string()]
        ));
        assert!(!has_required_scopes(
            &scopes,
            &["read".to_string(), "admin".to_string()]
        ));
    }

    #[test]
    fn supported_alg_filter_blocks_none() {
        assert!(is_supported_alg(Algorithm::RS256));
        assert!(is_supported_alg(Algorithm::EdDSA));
        assert!(!is_supported_alg(Algorithm::HS256));
    }

    #[tokio::test]
    async fn token_validator_accepts_static_token_without_central_auth() {
        let validator = TokenValidator::new(TokenAuthConfig {
            session_url: None,
            static_token: Some("static-secret".to_string()),
            cache_ttl_ms: 15_000,
            http_timeout_ms: 1_000,
        });
        assert!(validator.validate("static-secret").await.is_ok());
        assert!(matches!(
            validator.validate("wrong-token").await,
            Err(TokenError::InvalidToken)
        ));
    }

    #[tokio::test]
    async fn token_validator_uses_central_session_endpoint() {
        let (base_url, handle) = spawn_session_server(
            axum::http::StatusCode::OK,
            json!({"authenticated": true, "user": "pbisaacs"}),
        )
        .await;
        let validator = TokenValidator::new(TokenAuthConfig {
            session_url: Some(format!("{}/api/session", base_url)),
            static_token: None,
            cache_ttl_ms: 15_000,
            http_timeout_ms: 1_000,
        });

        assert!(validator.validate("central-token").await.is_ok());
        handle.abort();
    }

    #[tokio::test]
    async fn token_validator_falls_back_to_static_token_when_central_auth_fails() {
        let (base_url, handle) =
            spawn_session_server(axum::http::StatusCode::INTERNAL_SERVER_ERROR, json!({})).await;
        let validator = TokenValidator::new(TokenAuthConfig {
            session_url: Some(format!("{}/api/session", base_url)),
            static_token: Some("fallback-token".to_string()),
            cache_ttl_ms: 15_000,
            http_timeout_ms: 1_000,
        });

        assert!(validator.validate("fallback-token").await.is_ok());
        handle.abort();
    }

    async fn spawn_session_server(
        status: axum::http::StatusCode,
        payload: Value,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock session server");
        let addr = listener.local_addr().expect("mock session server addr");
        let app = Router::new().route(
            "/api/session",
            get(move || {
                let payload = payload.clone();
                async move { (status, Json(payload)) }
            }),
        );
        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("run mock session server");
        });
        (format!("http://{}", addr), handle)
    }
}
