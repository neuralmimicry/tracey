//! OTA update staging, signature verification, and supervised handoff.
//!
//! Update bundles are verified with keyed BLAKE3 signatures before activation.

use crate::event::now_ms;
use crate::peer_compat::{self, SchemaField};
use crate::shutdown::{Shutdown, ShutdownListener};
use crate::storage::Storage;
use crate::supervisor;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;
use tokio::fs;
use tokio::process::Command;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum UpdateChannel {
    Production,
    Development,
}

impl UpdateChannel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Production => "production",
            Self::Development => "development",
        }
    }

    pub fn distributable(&self) -> bool {
        matches!(self, Self::Production)
    }
}

impl Default for UpdateChannel {
    fn default() -> Self {
        Self::Production
    }
}

impl fmt::Display for UpdateChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for UpdateChannel {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "production" | "prod" => Ok(Self::Production),
            "development" | "dev" => Ok(Self::Development),
            other => Err(format!("unsupported update channel: {}", other)),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct UpdateRemoteConfig {
    pub enabled: bool,
    pub base_url: String,
    pub metadata_path: String,
    pub bundle_path: String,
    pub signature_path: String,
    pub ca_cert_path: Option<PathBuf>,
    pub client_identity_path: Option<PathBuf>,
    pub timeout_ms: u64,
}

impl Default for UpdateRemoteConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            base_url: "https://updates.example.com/tracey".to_string(),
            metadata_path: "tracey.update.meta.json".to_string(),
            bundle_path: "tracey.update".to_string(),
            signature_path: "tracey.update.sig".to_string(),
            ca_cert_path: None,
            client_identity_path: None,
            timeout_ms: 8000,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct UpdateConfig {
    pub enabled: bool,
    pub update_dir: PathBuf,
    pub bundle_name: String,
    pub signature_name: String,
    pub metadata_name: String,
    pub local_channel: UpdateChannel,
    pub shared_key: String,
    pub poll_interval_ms: u64,
    pub handoff_timeout_ms: u64,
    pub remote: UpdateRemoteConfig,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            update_dir: PathBuf::from("updates"),
            bundle_name: "tracey.update".to_string(),
            signature_name: "tracey.update.sig".to_string(),
            metadata_name: "tracey.update.meta.json".to_string(),
            local_channel: UpdateChannel::Production,
            shared_key: "tracey-dev-key-change-me".to_string(),
            poll_interval_ms: 5000,
            handoff_timeout_ms: 10_000,
            remote: UpdateRemoteConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpdateMetadata {
    pub version: String,
    pub os: String,
    pub arch: String,
    pub blake3: String,
    #[serde(default)]
    pub channel: UpdateChannel,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpdateRecord {
    pub ts_ms: u64,
    pub status: String,
    pub detail: String,
    pub version: Option<String>,
    pub os: Option<String>,
    pub arch: Option<String>,
}

pub struct UpdateManager {
    config: UpdateConfig,
    shutdown: Shutdown,
    storage: Storage,
    shutdown_listener: ShutdownListener,
    governance_state: std::sync::Arc<tokio::sync::RwLock<crate::governance::GovernanceState>>,
}

impl UpdateManager {
    /// Creates an update manager bound to governance and shutdown channels.
    pub fn new(
        config: UpdateConfig,
        shutdown: Shutdown,
        storage: Storage,
        shutdown_listener: ShutdownListener,
        governance_state: std::sync::Arc<tokio::sync::RwLock<crate::governance::GovernanceState>>,
    ) -> Self {
        Self {
            config,
            shutdown,
            storage,
            shutdown_listener,
            governance_state,
        }
    }

    /// Runs periodic local/remote update checks until shutdown.
    pub async fn run(mut self) {
        if !self.config.enabled {
            tracing::info!("update manager disabled");
            return;
        }

        if self.config.shared_key == "tracey-dev-key-change-me" {
            tracing::warn!(
                "update shared_key is using the default value; rotate it before production"
            );
        }

        let mut ticker = tokio::time::interval(Duration::from_millis(self.config.poll_interval_ms));
        loop {
            tokio::select! {
                _ = self.shutdown_listener.wait() => {
                    break;
                }
                _ = ticker.tick() => {
                    if !self.is_update_enabled().await {
                        continue;
                    }
                    if let Err(err) = self.check_once().await {
                        tracing::warn!("update check failed: {}", err);
                    }
                }
            }
        }
    }

    async fn is_update_enabled(&self) -> bool {
        let state = self.governance_state.read().await;
        state.update_enabled
    }

    async fn check_once(&mut self) -> Result<(), UpdateError> {
        let update_dir = &self.config.update_dir;
        fs::create_dir_all(update_dir)
            .await
            .map_err(UpdateError::Io)?;

        if self.config.remote.enabled {
            self.fetch_remote().await?;
        }

        let bundle_path = update_dir.join(&self.config.bundle_name);
        let signature_path = update_dir.join(&self.config.signature_name);
        let metadata_path = update_dir.join(&self.config.metadata_name);

        if !bundle_path.exists() {
            return Ok(());
        }

        let metadata_bytes = fs::read(&metadata_path).await.map_err(UpdateError::Io)?;
        let signature = fs::read_to_string(&signature_path)
            .await
            .map_err(UpdateError::Io)?;
        let bundle_bytes = fs::read(&bundle_path).await.map_err(UpdateError::Io)?;
        let metadata = verify_signed_artifacts(
            &metadata_bytes,
            &bundle_bytes,
            signature.trim(),
            &self.config.shared_key,
        )?;

        if metadata.os != std::env::consts::OS || metadata.arch != std::env::consts::ARCH {
            self.record(UpdateRecord {
                ts_ms: now_ms(),
                status: "rejected".to_string(),
                detail: "os/arch mismatch".to_string(),
                version: Some(metadata.version),
                os: Some(metadata.os),
                arch: Some(metadata.arch),
            })
            .await;
            return Err(UpdateError::Metadata("os/arch mismatch".to_string()));
        }

        if metadata.channel != self.config.local_channel {
            self.record(UpdateRecord {
                ts_ms: now_ms(),
                status: "ignored".to_string(),
                detail: format!(
                    "channel mismatch: local={} incoming={}",
                    self.config.local_channel, metadata.channel
                ),
                version: Some(metadata.version),
                os: Some(metadata.os),
                arch: Some(metadata.arch),
            })
            .await;
            return Ok(());
        }

        let binary_path = stage_binary(update_dir, &bundle_path).await?;

        if std::env::var("TRACEY_SUPERVISED").is_ok() {
            supervisor::write_update_request(update_dir, &binary_path, &metadata, signature.trim())
                .await
                .map_err(UpdateError::Io)?;

            archive_update(update_dir, &bundle_path, &signature_path, &metadata_path).await;
            self.record(UpdateRecord {
                ts_ms: now_ms(),
                status: "staged".to_string(),
                detail: "supervisor handoff requested".to_string(),
                version: Some(metadata.version),
                os: Some(metadata.os),
                arch: Some(metadata.arch),
            })
            .await;
            return Ok(());
        }

        let handoff_path = update_dir.join(format!("handoff-{}.ready", std::process::id()));
        let token = generate_token();
        spawn_new_process(&binary_path, &handoff_path, &token).await?;

        let ready = wait_for_handoff(&handoff_path, &token, self.config.handoff_timeout_ms).await;
        if ready {
            archive_update(update_dir, &bundle_path, &signature_path, &metadata_path).await;
            self.record(UpdateRecord {
                ts_ms: now_ms(),
                status: "applied".to_string(),
                detail: "handoff completed".to_string(),
                version: Some(metadata.version),
                os: Some(metadata.os),
                arch: Some(metadata.arch),
            })
            .await;
            self.shutdown.trigger();
        } else {
            self.record(UpdateRecord {
                ts_ms: now_ms(),
                status: "failed".to_string(),
                detail: "handoff timeout".to_string(),
                version: Some(metadata.version),
                os: Some(metadata.os),
                arch: Some(metadata.arch),
            })
            .await;
        }

        Ok(())
    }

    async fn record(&self, record: UpdateRecord) {
        self.storage.record_update(record).await;
    }

    async fn fetch_remote(&self) -> Result<(), UpdateError> {
        let remote = &self.config.remote;
        if !remote.enabled {
            return Ok(());
        }

        if remote.base_url.trim().is_empty() {
            return Err(UpdateError::Metadata("remote base_url missing".to_string()));
        }

        let ca_path = remote
            .ca_cert_path
            .as_ref()
            .ok_or_else(|| UpdateError::Metadata("remote ca_cert_path missing".to_string()))?;
        let identity_path = remote.client_identity_path.as_ref().ok_or_else(|| {
            UpdateError::Metadata("remote client_identity_path missing".to_string())
        })?;

        let ca_bytes = fs::read(ca_path).await.map_err(UpdateError::Io)?;
        let identity_bytes = fs::read(identity_path).await.map_err(UpdateError::Io)?;

        let ca_cert = reqwest::Certificate::from_pem(&ca_bytes).map_err(UpdateError::Http)?;
        let identity = reqwest::Identity::from_pem(&identity_bytes).map_err(UpdateError::Http)?;

        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(remote.timeout_ms))
            .add_root_certificate(ca_cert)
            .identity(identity)
            .build()
            .map_err(UpdateError::Http)?;

        let metadata_url = join_url(&remote.base_url, &remote.metadata_path);
        let bundle_url = join_url(&remote.base_url, &remote.bundle_path);
        let signature_url = join_url(&remote.base_url, &remote.signature_path);

        let metadata_bytes = client
            .get(metadata_url)
            .send()
            .await
            .map_err(UpdateError::Http)?
            .bytes()
            .await
            .map_err(UpdateError::Http)?;

        let bundle_bytes = client
            .get(bundle_url)
            .send()
            .await
            .map_err(UpdateError::Http)?
            .bytes()
            .await
            .map_err(UpdateError::Http)?;

        let signature_bytes = client
            .get(signature_url)
            .send()
            .await
            .map_err(UpdateError::Http)?
            .bytes()
            .await
            .map_err(UpdateError::Http)?;

        let update_dir = &self.config.update_dir;
        let metadata_path = update_dir.join(&self.config.metadata_name);
        let bundle_path = update_dir.join(&self.config.bundle_name);
        let signature_path = update_dir.join(&self.config.signature_name);

        write_atomic(&metadata_path, &metadata_bytes)
            .await
            .map_err(UpdateError::Io)?;
        write_atomic(&bundle_path, &bundle_bytes)
            .await
            .map_err(UpdateError::Io)?;
        write_atomic(&signature_path, &signature_bytes)
            .await
            .map_err(UpdateError::Io)?;

        Ok(())
    }
}

pub(crate) fn build_metadata(
    version: impl Into<String>,
    os: impl Into<String>,
    arch: impl Into<String>,
    bundle: &[u8],
    channel: UpdateChannel,
) -> UpdateMetadata {
    let hash = blake3::hash(bundle);
    UpdateMetadata {
        version: version.into(),
        os: os.into(),
        arch: arch.into(),
        blake3: to_hex(hash.as_bytes()),
        channel,
    }
}

pub(crate) fn serialize_metadata(metadata: &UpdateMetadata) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(metadata)
}

pub(crate) fn sign_metadata_bytes(metadata: &[u8], bundle: &[u8], shared_key: &str) -> String {
    let key = derive_key(shared_key);
    sign_payload(metadata, bundle, &key)
}

pub(crate) fn verify_signed_artifacts(
    metadata_bytes: &[u8],
    bundle_bytes: &[u8],
    signature: &str,
    shared_key: &str,
) -> Result<UpdateMetadata, UpdateError> {
    let metadata = match serde_json::from_slice::<UpdateMetadata>(metadata_bytes) {
        Ok(metadata) => metadata,
        Err(err) => match parse_update_metadata_lossy(metadata_bytes) {
            Ok((metadata, affinity)) => {
                tracing::info!(affinity, version = %metadata.version, "update metadata recovered with fuzzy parser");
                metadata
            }
            Err(reason) => {
                return Err(if matches!(
                    peer_compat::parse_bytes(metadata_bytes),
                    Ok(serde_json::Value::Object(_))
                ) {
                    UpdateError::Metadata(reason)
                } else {
                    UpdateError::Serde(err)
                });
            }
        },
    };
    let computed_hash = blake3::hash(bundle_bytes);
    if metadata.blake3 != to_hex(computed_hash.as_bytes()) {
        return Err(UpdateError::Metadata("bundle hash mismatch".to_string()));
    }
    let expected_sig = sign_metadata_bytes(metadata_bytes, bundle_bytes, shared_key);
    if !constant_time_eq(signature.trim(), &expected_sig) {
        return Err(UpdateError::Signature("invalid signature".to_string()));
    }
    Ok(metadata)
}

fn parse_update_metadata_lossy(metadata_bytes: &[u8]) -> Result<(UpdateMetadata, f64), String> {
    let root = peer_compat::parse_bytes(metadata_bytes).map_err(|err| err.to_string())?;
    let fields = [
        SchemaField {
            aliases: &["version", "agent_version", "build_version", "release_version"],
            required: true,
            weight: 2.0,
        },
        SchemaField {
            aliases: &["os", "platform", "target_os"],
            required: true,
            weight: 1.5,
        },
        SchemaField {
            aliases: &["arch", "architecture", "target_arch"],
            required: true,
            weight: 1.5,
        },
        SchemaField {
            aliases: &["blake3", "digest", "hash", "checksum"],
            required: true,
            weight: 2.0,
        },
        SchemaField {
            aliases: &["channel", "release_channel", "track"],
            required: false,
            weight: 0.8,
        },
    ];
    let matched = peer_compat::best_object(&root, &fields, 3.0, 3)
        .ok_or_else(|| "payload did not resemble update metadata".to_string())?;
    let map = matched.map;
    let version = peer_compat::value_for(
        map,
        &["version", "agent_version", "build_version", "release_version"],
    )
    .and_then(peer_compat::coerce_string)
    .ok_or_else(|| "missing version".to_string())?;
    let os = peer_compat::value_for(map, &["os", "platform", "target_os"])
        .and_then(peer_compat::coerce_string)
        .ok_or_else(|| "missing os".to_string())?;
    let arch = peer_compat::value_for(map, &["arch", "architecture", "target_arch"])
        .and_then(peer_compat::coerce_string)
        .ok_or_else(|| "missing arch".to_string())?;
    let blake3 = peer_compat::value_for(map, &["blake3", "digest", "hash", "checksum"])
        .and_then(peer_compat::coerce_string)
        .ok_or_else(|| "missing blake3 digest".to_string())?;
    let channel = peer_compat::value_for(map, &["channel", "release_channel", "track"])
        .and_then(peer_compat::coerce_string)
        .map(|value| UpdateChannel::from_str(&value).unwrap_or_default())
        .unwrap_or_default();

    Ok((
        UpdateMetadata {
            version,
            os,
            arch,
            blake3,
            channel,
        },
        matched.score,
    ))
}

/// Writes readiness token for zero-downtime handoff when requested by parent.
pub async fn signal_handoff_ready() {
    let path = std::env::var("TRACEY_HANDOFF_PATH").ok();
    let token = std::env::var("TRACEY_HANDOFF_TOKEN").ok();
    let Some(path) = path else {
        return;
    };
    let Some(token) = token else {
        return;
    };

    if let Err(err) = fs::write(&path, token.as_bytes()).await {
        tracing::warn!("handoff readiness write failed: {}", err);
    }
}

/// CLI helper: signs an update bundle and writes metadata/signature artifacts.
pub fn run_sign_update(args: &[String]) -> Result<(), String> {
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        return Err(sign_usage());
    }

    let mut bundle = None;
    let mut version = None;
    let mut os = None;
    let mut arch = None;
    let mut out_dir = None;
    let mut key = None;
    let mut channel = None;

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--bundle" => bundle = iter.next().cloned(),
            "--version" => version = iter.next().cloned(),
            "--os" => os = iter.next().cloned(),
            "--arch" => arch = iter.next().cloned(),
            "--out" => out_dir = iter.next().cloned(),
            "--key" => key = iter.next().cloned(),
            "--channel" => channel = iter.next().cloned(),
            _ => {}
        }
    }

    let bundle = bundle.ok_or_else(|| "missing --bundle".to_string())?;
    let version = version.ok_or_else(|| "missing --version".to_string())?;
    let os = os.unwrap_or_else(|| std::env::consts::OS.to_string());
    let arch = arch.unwrap_or_else(|| std::env::consts::ARCH.to_string());
    let out_dir = out_dir.unwrap_or_else(|| "updates".to_string());
    let key = key
        .or_else(|| std::env::var("TRACEY_UPDATE_KEY").ok())
        .ok_or_else(|| "missing --key or TRACEY_UPDATE_KEY".to_string())?;
    let channel = channel
        .map(|value| UpdateChannel::from_str(&value))
        .transpose()?
        .unwrap_or(UpdateChannel::Production);

    let bundle_path = PathBuf::from(bundle);
    let out_dir = PathBuf::from(out_dir);
    std::fs::create_dir_all(&out_dir).map_err(|err| err.to_string())?;

    let bundle_bytes = std::fs::read(&bundle_path).map_err(|err| err.to_string())?;
    let metadata = build_metadata(version, os, arch, &bundle_bytes, channel);
    let metadata_bytes = serialize_metadata(&metadata).map_err(|err| err.to_string())?;

    let metadata_path = out_dir.join("tracey.update.meta.json");
    let signature_path = out_dir.join("tracey.update.sig");
    let bundle_out = out_dir.join("tracey.update");

    std::fs::write(&metadata_path, &metadata_bytes).map_err(|err| err.to_string())?;
    let signature = sign_metadata_bytes(&metadata_bytes, &bundle_bytes, &key);
    std::fs::write(&signature_path, signature.as_bytes()).map_err(|err| err.to_string())?;
    std::fs::copy(&bundle_path, &bundle_out).map_err(|err| err.to_string())?;

    println!("Wrote {}", metadata_path.display());
    println!("Wrote {}", signature_path.display());
    println!("Wrote {}", bundle_out.display());

    Ok(())
}

async fn spawn_new_process(
    binary_path: &Path,
    handoff_path: &Path,
    token: &str,
) -> Result<(), UpdateError> {
    let mut command = Command::new(binary_path);
    command
        .env("TRACEY_HANDOFF_PATH", handoff_path)
        .env("TRACEY_HANDOFF_TOKEN", token)
        .env("TRACEY_UPDATED_FROM", "ota");

    command.spawn().map_err(UpdateError::Io)?;
    Ok(())
}

async fn wait_for_handoff(path: &Path, token: &str, timeout_ms: u64) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        if let Ok(contents) = fs::read_to_string(path).await {
            if contents.trim() == token {
                let _ = fs::remove_file(path).await;
                return true;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

pub(crate) async fn stage_binary(
    update_dir: &Path,
    bundle_path: &Path,
) -> Result<PathBuf, UpdateError> {
    let staged = update_dir.join("tracey.next");
    fs::copy(bundle_path, &staged)
        .await
        .map_err(UpdateError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&staged)
            .await
            .map_err(UpdateError::Io)?
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&staged, perms)
            .await
            .map_err(UpdateError::Io)?;
    }
    Ok(staged)
}

async fn archive_update(
    update_dir: &Path,
    bundle_path: &Path,
    signature_path: &Path,
    metadata_path: &Path,
) {
    let stamp = now_ms();
    let _ = fs::rename(
        bundle_path,
        update_dir.join(format!("tracey.applied.{}", stamp)),
    )
    .await;
    let _ = fs::rename(
        signature_path,
        update_dir.join(format!("tracey.applied.{}.sig", stamp)),
    )
    .await;
    let _ = fs::rename(
        metadata_path,
        update_dir.join(format!("tracey.applied.{}.meta.json", stamp)),
    )
    .await;
}

pub(crate) fn sign_payload(metadata: &[u8], bundle: &[u8], key: &[u8; 32]) -> String {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(metadata);
    hasher.update(bundle);
    to_hex(hasher.finalize().as_bytes())
}

pub(crate) fn derive_key(shared: &str) -> [u8; 32] {
    let hash = blake3::hash(shared.as_bytes());
    *hash.as_bytes()
}

pub(crate) fn to_hex(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(LUT[(b >> 4) as usize] as char);
        out.push(LUT[(b & 0x0f) as usize] as char);
    }
    out
}

pub(crate) fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (ca, cb) in a.as_bytes().iter().zip(b.as_bytes().iter()) {
        diff |= ca ^ cb;
    }
    diff == 0
}

fn generate_token() -> String {
    let seed = format!(
        "{}:{}:{:?}",
        now_ms(),
        std::process::id(),
        std::thread::current().id()
    );
    let hash = blake3::hash(seed.as_bytes());
    to_hex(hash.as_bytes())
}

fn sign_usage() -> String {
    [
        "Usage:",
        "  tracey sign-update --bundle <path> --version <v> [--os <os>] [--arch <arch>] [--channel production|development] [--out <dir>] [--key <key>]",
        "",
        "Notes:",
        "  --key can be omitted if TRACEY_UPDATE_KEY is set.",
        "  Output files default to updates/tracey.update(.meta.json/.sig).",
    ]
    .join("\n")
}

fn join_url(base: &str, path: &str) -> String {
    let base = base.trim_end_matches('/');
    let path = path.trim_start_matches('/');
    format!("{}/{}", base, path)
}

pub(crate) async fn write_atomic(path: &Path, payload: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).await?;
    }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, payload).await?;
    fs::rename(tmp, path).await
}

#[derive(Debug)]
pub enum UpdateError {
    Io(std::io::Error),
    Serde(serde_json::Error),
    Http(reqwest::Error),
    Signature(String),
    Metadata(String),
}

impl std::fmt::Display for UpdateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpdateError::Io(err) => write!(f, "io: {}", err),
            UpdateError::Serde(err) => write!(f, "serde: {}", err),
            UpdateError::Http(err) => write!(f, "http: {}", err),
            UpdateError::Signature(msg) => write!(f, "signature: {}", msg),
            UpdateError::Metadata(msg) => write!(f, "metadata: {}", msg),
        }
    }
}

impl std::error::Error for UpdateError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "tracey-update-test-{}-{}-{}",
            name,
            std::process::id(),
            now_ms()
        ))
    }

    #[test]
    fn constant_time_eq_requires_identical_inputs() {
        assert!(constant_time_eq("abcd", "abcd"));
        assert!(!constant_time_eq("abcd", "abce"));
        assert!(!constant_time_eq("abcd", "abc"));
    }

    #[test]
    fn join_url_normalizes_slashes() {
        assert_eq!(
            join_url("https://updates.example.com/base/", "/tracey.update"),
            "https://updates.example.com/base/tracey.update"
        );
    }

    #[test]
    fn sign_payload_is_deterministic_for_same_inputs() {
        let key = derive_key("shared");
        let a = sign_payload(b"meta", b"bundle", &key);
        let b = sign_payload(b"meta", b"bundle", &key);
        let c = sign_payload(b"meta2", b"bundle", &key);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn run_sign_update_writes_expected_files() {
        let dir = test_dir("sign");
        std::fs::create_dir_all(&dir).expect("create test dir");
        let bundle = dir.join("tracey.bin");
        std::fs::write(&bundle, b"binary-payload").expect("write bundle");

        let args = vec![
            "--bundle".to_string(),
            bundle.display().to_string(),
            "--version".to_string(),
            "1.2.3".to_string(),
            "--out".to_string(),
            dir.display().to_string(),
            "--key".to_string(),
            "test-shared-key".to_string(),
        ];

        run_sign_update(&args).expect("sign-update should succeed");

        let metadata = dir.join("tracey.update.meta.json");
        let signature = dir.join("tracey.update.sig");
        let copied_bundle = dir.join("tracey.update");
        assert!(metadata.exists());
        assert!(signature.exists());
        assert!(copied_bundle.exists());

        let meta_bytes = std::fs::read(&metadata).expect("read metadata");
        let meta: UpdateMetadata =
            serde_json::from_slice(&meta_bytes).expect("metadata should parse");
        assert_eq!(meta.version, "1.2.3");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_signed_artifacts_accepts_fuzzy_metadata_schema() {
        let bundle = b"tracey-bundle";
        let digest = to_hex(blake3::hash(bundle).as_bytes());
        let metadata_bytes = serde_json::json!({
            "payload": {
                "buildVersion": "2.4.6",
                "platform": std::env::consts::OS,
                "architecture": std::env::consts::ARCH,
                "digest": digest,
                "release_channel": "prod"
            }
        })
        .to_string()
        .into_bytes();
        let signature = sign_metadata_bytes(&metadata_bytes, bundle, "shared-key");

        let metadata =
            verify_signed_artifacts(&metadata_bytes, bundle, &signature, "shared-key").unwrap();

        assert_eq!(metadata.version, "2.4.6");
        assert_eq!(metadata.channel, UpdateChannel::Production);
        assert_eq!(metadata.blake3, digest);
    }
}
