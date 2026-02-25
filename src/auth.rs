use crate::config::{AuthConfig, OidcAuthConfig};
use axum::http::{HeaderMap, StatusCode};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde_json::Value;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthMode {
    Off,
    Oidc,
}

impl AuthMode {
    fn parse(raw: &str) -> Self {
        match raw.trim().to_lowercase().as_str() {
            "oidc" => AuthMode::Oidc,
            _ => AuthMode::Off,
        }
    }
}

#[derive(Clone)]
pub struct AuthSystem {
    mode: AuthMode,
    validator: Option<Arc<OidcValidator>>,
    protect_status: bool,
    protect_otlp_http: bool,
    protect_otlp_grpc: bool,
}

impl AuthSystem {
    pub fn from_config(cfg: &AuthConfig) -> Self {
        let mode = AuthMode::parse(&cfg.mode);
        let validator = if mode == AuthMode::Oidc && cfg.oidc.enabled() {
            Some(Arc::new(OidcValidator::new(cfg.oidc.clone())))
        } else {
            None
        };
        Self {
            mode,
            validator,
            protect_status: cfg.protect_status,
            protect_otlp_http: cfg.protect_otlp_http,
            protect_otlp_grpc: cfg.protect_otlp_grpc,
        }
    }

    pub fn status_gate(&self) -> AuthGate {
        AuthGate::new(self.mode, self.protect_status, self.validator.clone())
    }

    pub fn otlp_http_gate(&self) -> AuthGate {
        AuthGate::new(self.mode, self.protect_otlp_http, self.validator.clone())
    }

    pub fn otlp_grpc_gate(&self) -> AuthGate {
        AuthGate::new(self.mode, self.protect_otlp_grpc, self.validator.clone())
    }
}

#[derive(Clone)]
pub struct AuthGate {
    mode: AuthMode,
    enabled: bool,
    validator: Option<Arc<OidcValidator>>,
}

impl AuthGate {
    fn new(mode: AuthMode, enabled: bool, validator: Option<Arc<OidcValidator>>) -> Self {
        Self { mode, enabled, validator }
    }

    pub async fn authorize_http(&self, headers: &HeaderMap) -> Result<(), StatusCode> {
        if !self.enabled || self.mode == AuthMode::Off {
            return Ok(());
        }
        let token = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(extract_bearer);
        match token {
            Some(token) => self
                .validator
                .as_ref()
                .ok_or(StatusCode::SERVICE_UNAVAILABLE)?
                .validate(token)
                .await
                .map_err(|err| err.to_status_code()),
            None => Err(StatusCode::UNAUTHORIZED),
        }
    }

    pub async fn authorize_grpc(&self, metadata: &tonic::metadata::MetadataMap) -> Result<(), tonic::Status> {
        if !self.enabled || self.mode == AuthMode::Off {
            return Ok(());
        }
        let token = metadata
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(extract_bearer);
        let validator = self
            .validator
            .as_ref()
            .ok_or_else(|| tonic::Status::unavailable("oidc not configured"))?;
        match token {
            Some(token) => validator.validate(token).await.map_err(|err| err.to_tonic_status()),
            None => Err(tonic::Status::unauthenticated("missing authorization")),
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

        let data = decode::<Value>(token, &decoding_key, &validation).map_err(|_| OidcError::InvalidToken)?;
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
        let jwks = resp.json::<JwkSet>().await.map_err(|_| OidcError::JwksFailed)?;
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
        let payload = resp.json::<Value>().await.map_err(|_| OidcError::DiscoveryFailed)?;
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
