//! Authentication gates for HTTP and gRPC endpoints.
//!
//! Supports disabled mode, shared token introspection, and OIDC JWT validation.

use crate::config::{AuthConfig, OidcAuthConfig, TokenAuthConfig};
use axum::http::{HeaderMap, StatusCode};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
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

const SERVICE_ACCESS_NONE: &str = "none";
const SERVICE_ACCESS_REQUEST: &str = "request";
const SERVICE_ACCESS_OBSERVE: &str = "observe";
const SERVICE_ACCESS_USE: &str = "use";
const SERVICE_ACCESS_CONTROL: &str = "control";

fn normalize_service_access_level(value: &str, fallback: &str) -> String {
    let cleaned = value.trim().to_lowercase();
    match cleaned.as_str() {
        SERVICE_ACCESS_NONE
        | SERVICE_ACCESS_REQUEST
        | SERVICE_ACCESS_OBSERVE
        | SERVICE_ACCESS_USE
        | SERVICE_ACCESS_CONTROL => cleaned,
        _ => fallback.to_string(),
    }
}

fn access_at_least(current: &str, required: &str) -> bool {
    let rank =
        |value: &str| match normalize_service_access_level(value, SERVICE_ACCESS_NONE).as_str() {
            SERVICE_ACCESS_REQUEST => 1,
            SERVICE_ACCESS_OBSERVE => 2,
            SERVICE_ACCESS_USE => 3,
            SERVICE_ACCESS_CONTROL => 4,
            _ => 0,
        };
    rank(current) >= rank(required)
}

fn max_access_level(left: &str, right: &str) -> String {
    if access_at_least(left, right) {
        normalize_service_access_level(left, SERVICE_ACCESS_NONE)
    } else {
        normalize_service_access_level(right, SERVICE_ACCESS_NONE)
    }
}

fn json_bool(value: Option<&Value>, fallback: bool) -> bool {
    match value {
        Some(Value::Bool(inner)) => *inner,
        Some(Value::Number(inner)) => inner.as_i64().unwrap_or_default() != 0,
        Some(Value::String(inner)) => matches!(
            inner.trim().to_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        _ => fallback,
    }
}

fn coerce_groups(value: Option<&Value>) -> Vec<String> {
    let mut groups = Vec::new();
    let mut seen = HashSet::new();
    let mut push_group = |candidate: &str| {
        let cleaned = candidate.trim().to_lowercase();
        if cleaned.is_empty() || seen.contains(&cleaned) {
            return;
        }
        seen.insert(cleaned.clone());
        groups.push(cleaned);
    };

    match value {
        Some(Value::String(inner)) => {
            for item in inner.split(',') {
                push_group(item);
            }
        }
        Some(Value::Array(items)) => {
            for item in items {
                if let Some(group) = item.as_str() {
                    push_group(group);
                }
            }
        }
        _ => {}
    }

    groups
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ResolvedServiceAccess {
    access_level: String,
    public_access_level: String,
    visible_access_level: String,
    visible: bool,
    can_request: bool,
    can_observe: bool,
    can_use: bool,
    can_control: bool,
}

impl ResolvedServiceAccess {
    fn from_value(raw: Option<&Value>, default_public: &str, default_access: &str) -> Self {
        let entry = raw.and_then(Value::as_object);
        let direct_access = raw.and_then(Value::as_str);
        let access_level = normalize_service_access_level(
            entry
                .and_then(|item| item.get("access_level").or_else(|| item.get("level")))
                .and_then(Value::as_str)
                .or(direct_access)
                .unwrap_or(default_access),
            default_access,
        );
        let public_access_level = normalize_service_access_level(
            entry
                .and_then(|item| item.get("public_access_level"))
                .and_then(Value::as_str)
                .unwrap_or(default_public),
            default_public,
        );
        let visible_access_level = normalize_service_access_level(
            entry
                .and_then(|item| item.get("visible_access_level"))
                .and_then(Value::as_str)
                .unwrap_or(&max_access_level(&access_level, &public_access_level)),
            &max_access_level(&access_level, &public_access_level),
        );
        Self {
            access_level: access_level.clone(),
            public_access_level: public_access_level.clone(),
            visible_access_level: visible_access_level.clone(),
            visible: entry
                .and_then(|item| item.get("visible"))
                .map(|value| json_bool(Some(value), visible_access_level != SERVICE_ACCESS_NONE))
                .unwrap_or(visible_access_level != SERVICE_ACCESS_NONE),
            can_request: entry
                .and_then(|item| item.get("can_request"))
                .map(|value| {
                    json_bool(
                        Some(value),
                        access_at_least(&visible_access_level, SERVICE_ACCESS_REQUEST),
                    )
                })
                .unwrap_or(access_at_least(
                    &visible_access_level,
                    SERVICE_ACCESS_REQUEST,
                )),
            can_observe: entry
                .and_then(|item| item.get("can_observe"))
                .map(|value| {
                    json_bool(
                        Some(value),
                        access_at_least(&visible_access_level, SERVICE_ACCESS_OBSERVE),
                    )
                })
                .unwrap_or(access_at_least(
                    &visible_access_level,
                    SERVICE_ACCESS_OBSERVE,
                )),
            can_use: entry
                .and_then(|item| item.get("can_use"))
                .map(|value| {
                    json_bool(
                        Some(value),
                        access_at_least(&access_level, SERVICE_ACCESS_USE),
                    )
                })
                .unwrap_or(access_at_least(&access_level, SERVICE_ACCESS_USE)),
            can_control: entry
                .and_then(|item| item.get("can_control"))
                .map(|value| {
                    json_bool(
                        Some(value),
                        access_at_least(&access_level, SERVICE_ACCESS_CONTROL),
                    )
                })
                .unwrap_or(access_at_least(&access_level, SERVICE_ACCESS_CONTROL)),
        }
    }
}

fn default_service_access(
    authenticated: bool,
    role: &str,
    groups: &[String],
) -> HashMap<String, ResolvedServiceAccess> {
    let is_admin = role == "admin" || groups.iter().any(|group| group == "admin");
    let access_level = if is_admin {
        SERVICE_ACCESS_CONTROL
    } else if authenticated {
        SERVICE_ACCESS_NONE
    } else {
        SERVICE_ACCESS_NONE
    };
    HashMap::from([(
        "tracey".to_string(),
        ResolvedServiceAccess::from_value(None, SERVICE_ACCESS_OBSERVE, access_level),
    )])
}

fn resolve_service_access(
    payload: &Value,
    authenticated: bool,
    role: &str,
    groups: &[String],
) -> HashMap<String, ResolvedServiceAccess> {
    let mut resolved = default_service_access(authenticated, role, groups);
    let raw_service_access = payload.get("service_access");
    let mut apply_entry = |service_key: &str, raw_entry: Option<&Value>| {
        let cleaned_service_key = service_key.trim().to_lowercase();
        if cleaned_service_key.is_empty() {
            return;
        }
        let default_entry = resolved.get(&cleaned_service_key);
        let normalized = ResolvedServiceAccess::from_value(
            raw_entry,
            default_entry
                .map(|entry| entry.public_access_level.as_str())
                .unwrap_or(SERVICE_ACCESS_NONE),
            default_entry
                .map(|entry| entry.access_level.as_str())
                .unwrap_or(SERVICE_ACCESS_NONE),
        );
        resolved.insert(cleaned_service_key, normalized);
    };

    match raw_service_access {
        Some(Value::Object(entries)) => {
            for (service_key, raw_entry) in entries {
                apply_entry(service_key, Some(raw_entry));
            }
        }
        Some(Value::Array(entries)) => {
            for raw_entry in entries {
                let Some(service_key) = raw_entry
                    .get("service_key")
                    .or_else(|| raw_entry.get("key"))
                    .and_then(Value::as_str)
                else {
                    continue;
                };
                apply_entry(service_key, Some(raw_entry));
            }
        }
        _ => {}
    }

    resolved
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ResolvedIdentity {
    authenticated: bool,
    user: String,
    role: String,
    groups: Vec<String>,
    service_access: HashMap<String, ResolvedServiceAccess>,
}

impl ResolvedIdentity {
    fn can_access(&self, requirement: AccessRequirement) -> bool {
        if !self.authenticated {
            return false;
        }
        if requirement.service_key.is_empty() {
            return true;
        }
        let Some(entry) = self.service_access.get(requirement.service_key) else {
            return false;
        };
        match requirement.access_level {
            SERVICE_ACCESS_REQUEST => entry.can_request,
            SERVICE_ACCESS_OBSERVE => entry.can_observe,
            SERVICE_ACCESS_USE => entry.can_use,
            SERVICE_ACCESS_CONTROL => entry.can_control,
            _ => false,
        }
    }
}

fn resolve_identity(payload: &Value, default_authenticated: bool) -> Option<ResolvedIdentity> {
    let authenticated = payload
        .get("authenticated")
        .map(|value| json_bool(Some(value), default_authenticated))
        .or_else(|| {
            payload
                .get("active")
                .map(|value| json_bool(Some(value), default_authenticated))
        })
        .unwrap_or(default_authenticated);
    let user = payload
        .get("user")
        .or_else(|| payload.get("preferred_username"))
        .or_else(|| payload.get("username"))
        .or_else(|| payload.get("email"))
        .or_else(|| payload.get("sub"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())?
        .to_string();
    let identity_type = payload
        .get("identity_type")
        .and_then(Value::as_str)
        .map(|value| value.trim().to_lowercase())
        .filter(|value| !value.is_empty());
    let role = payload
        .get("role")
        .and_then(Value::as_str)
        .map(|value| value.trim().to_lowercase())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| match identity_type.as_deref() {
            Some("service_account") => "service_account".to_string(),
            _ => "user".to_string(),
        });
    let mut groups = coerce_groups(payload.get("groups"));
    if role != "service_account" && !groups.iter().any(|group| group == &role) {
        groups.insert(0, role.clone());
    }
    let service_access = resolve_service_access(payload, authenticated, &role, &groups);
    Some(ResolvedIdentity {
        authenticated: authenticated && !user.is_empty(),
        user,
        role,
        groups,
        service_access,
    })
}

fn static_token_identity() -> ResolvedIdentity {
    resolve_identity(
        &serde_json::json!({
            "authenticated": true,
            "user": "service-token",
            "role": "admin",
            "groups": ["admin"]
        }),
        true,
    )
    .expect("static token identity should always resolve")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccessRequirement {
    pub service_key: &'static str,
    pub access_level: &'static str,
}

impl AccessRequirement {
    pub const fn new(service_key: &'static str, access_level: &'static str) -> Self {
        Self {
            service_key,
            access_level,
        }
    }

    pub const fn tracey_observe() -> Self {
        Self::new("tracey", SERVICE_ACCESS_OBSERVE)
    }

    pub const fn tracey_use() -> Self {
        Self::new("tracey", SERVICE_ACCESS_USE)
    }

    pub const fn tracey_control() -> Self {
        Self::new("tracey", SERVICE_ACCESS_CONTROL)
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

    pub async fn authorize_http(
        &self,
        headers: &HeaderMap,
        requirement: AccessRequirement,
    ) -> Result<(), StatusCode> {
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
                Some(token) => {
                    let identity = self
                        .token_validator
                        .as_ref()
                        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?
                        .validate(token)
                        .await
                        .map_err(|err| err.to_status_code())?;
                    if identity.can_access(requirement) {
                        Ok(())
                    } else {
                        Err(StatusCode::FORBIDDEN)
                    }
                }
                None => Err(StatusCode::UNAUTHORIZED),
            },
            AuthMode::Oidc => match token {
                Some(token) => {
                    let identity = self
                        .oidc_validator
                        .as_ref()
                        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?
                        .validate(token)
                        .await
                        .map_err(|err| err.to_status_code())?;
                    if identity.can_access(requirement) {
                        Ok(())
                    } else {
                        Err(StatusCode::FORBIDDEN)
                    }
                }
                None => Err(StatusCode::UNAUTHORIZED),
            },
        }
    }

    pub async fn authorize_grpc(
        &self,
        metadata: &tonic::metadata::MetadataMap,
        requirement: AccessRequirement,
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
                    Some(token) => {
                        let identity = validator
                            .validate(token)
                            .await
                            .map_err(|err| err.to_tonic_status())?;
                        if identity.can_access(requirement) {
                            Ok(())
                        } else {
                            Err(tonic::Status::permission_denied(
                                "insufficient service access",
                            ))
                        }
                    }
                    None => Err(tonic::Status::unauthenticated("missing authorization")),
                }
            }
            AuthMode::Oidc => {
                let validator = self
                    .oidc_validator
                    .as_ref()
                    .ok_or_else(|| tonic::Status::unavailable("oidc not configured"))?;
                match token {
                    Some(token) => {
                        let identity = validator
                            .validate(token)
                            .await
                            .map_err(|err| err.to_tonic_status())?;
                        if identity.can_access(requirement) {
                            Ok(())
                        } else {
                            Err(tonic::Status::permission_denied(
                                "insufficient service access",
                            ))
                        }
                    }
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
    identity: Option<ResolvedIdentity>,
    expires_at: Instant,
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
    async fn validate(&self, token: &str) -> Result<ResolvedIdentity, TokenError> {
        let token = token.trim();
        if token.is_empty() {
            return Err(TokenError::MissingToken);
        }
        if !self.cfg.enabled() {
            return Err(TokenError::MissingConfig);
        }

        if let Some(entry) = self.cached(token).await {
            return entry.identity.ok_or(TokenError::InvalidToken);
        }

        match self.validate_central_session(token).await {
            Ok(Some(identity)) => {
                self.cache_result(token, Some(identity.clone()), self.cfg.cache_ttl_ms)
                    .await;
                Ok(identity)
            }
            Ok(None) => {
                if self.matches_static_token(token) {
                    let identity = static_token_identity();
                    self.cache_result(token, Some(identity.clone()), self.cfg.cache_ttl_ms)
                        .await;
                    Ok(identity)
                } else {
                    self.cache_result(token, None, self.negative_cache_ttl_ms())
                        .await;
                    Err(TokenError::InvalidToken)
                }
            }
            Err(err) => {
                if self.matches_static_token(token) {
                    let identity = static_token_identity();
                    self.cache_result(token, Some(identity.clone()), self.cfg.cache_ttl_ms)
                        .await;
                    Ok(identity)
                } else {
                    self.cache_result(token, None, self.negative_cache_ttl_ms())
                        .await;
                    Err(err)
                }
            }
        }
    }

    async fn validate_central_session(
        &self,
        token: &str,
    ) -> Result<Option<ResolvedIdentity>, TokenError> {
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
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            return Ok(None);
        }
        if status.is_server_error() || !status.is_success() {
            return Err(TokenError::ServiceUnavailable);
        }

        let payload = response
            .json::<Value>()
            .await
            .map_err(|_| TokenError::ServiceUnavailable)?;
        Ok(resolve_identity(&payload, true).filter(|identity| identity.authenticated))
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

    async fn cache_result(&self, token: &str, identity: Option<ResolvedIdentity>, ttl_ms: u64) {
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
                identity,
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
    async fn validate(&self, token: &str) -> Result<ResolvedIdentity, OidcError> {
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
        resolve_identity(&data.claims, true)
            .filter(|identity| identity.authenticated)
            .ok_or(OidcError::InvalidToken)
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

    #[test]
    fn resolve_identity_defaults_to_public_tracey_observe_for_authenticated_users() {
        let identity = resolve_identity(
            &json!({
                "authenticated": true,
                "user": "pbisaacs",
                "role": "user",
                "groups": ["user"]
            }),
            true,
        )
        .expect("identity should resolve");

        assert!(identity.can_access(AccessRequirement::tracey_observe()));
        assert!(!identity.can_access(AccessRequirement::tracey_use()));
        assert!(!identity.can_access(AccessRequirement::tracey_control()));
    }

    #[test]
    fn resolve_identity_preserves_explicit_service_account_groups() {
        let identity = resolve_identity(
            &json!({
                "authenticated": true,
                "identity_type": "service_account",
                "user": "tracey-sync",
                "role": "service_account",
                "groups": ["ops"]
            }),
            true,
        )
        .expect("identity should resolve");

        assert_eq!(identity.role, "service_account");
        assert_eq!(identity.groups, vec!["ops".to_string()]);
        assert!(identity.can_access(AccessRequirement::tracey_observe()));
        assert!(!identity.can_access(AccessRequirement::tracey_use()));
    }

    #[tokio::test]
    async fn token_validator_resolves_service_access_from_central_session() {
        let (base_url, handle) = spawn_session_server(
            axum::http::StatusCode::OK,
            json!({
                "authenticated": true,
                "user": "pbisaacs",
                "role": "user",
                "groups": ["user"],
                "service_access": {
                    "tracey": {
                        "service_key": "tracey",
                        "access_level": "use",
                        "public_access_level": "observe"
                    }
                }
            }),
        )
        .await;
        let validator = TokenValidator::new(TokenAuthConfig {
            session_url: Some(format!("{}/api/session", base_url)),
            static_token: None,
            cache_ttl_ms: 15_000,
            http_timeout_ms: 1_000,
        });

        let identity = validator
            .validate("central-token")
            .await
            .expect("central token should resolve");
        assert!(identity.can_access(AccessRequirement::tracey_observe()));
        assert!(identity.can_access(AccessRequirement::tracey_use()));
        assert!(!identity.can_access(AccessRequirement::tracey_control()));
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
