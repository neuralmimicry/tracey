use crate::config::{Config, LoaderConfig};
use crate::event::now_ms;
use crate::loader_threat::{self, LocalThreatIncident};
use crate::peer_compat::{self, SchemaField};
use crate::shutdown::{Shutdown, ShutdownListener};
use crate::supervisor::{self, ManagedChild, SupervisorRequest};
use crate::update::{self, UpdateChannel, UpdateMetadata};
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::error::Error;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::fs;
use tokio::net::UdpSocket;
use tokio::process::Command;
use tokio::sync::RwLock;

const LOADER_CURRENT_BINARY: &str = "current/tracey-core";
const LOADER_CURRENT_METADATA: &str = "current/tracey-core.meta.json";
const LOADER_CURRENT_SIGNATURE: &str = "current/tracey-core.sig";
const LOADER_ROLLBACK_BINARY: &str = "rollback/tracey-core.previous";
const LOADER_ROLLBACK_METADATA: &str = "rollback/tracey-core.previous.meta.json";
const LOADER_ROLLBACK_SIGNATURE: &str = "rollback/tracey-core.previous.sig";
const LOADER_ROLLBACK_STATE: &str = "tracey-loader.rollback.json";
const LOADER_STAGING_DIR: &str = "staging";
const LOADER_MANIFEST: &str = "tracey-loader.manifest.json";
const LOADER_HEALTH_ROUTE: &str = "/health";
const LOADER_STATUS_ROUTE: &str = "/loader/status";
const LOADER_METADATA_ROUTE: &str = "/loader/core/metadata";
const LOADER_SIGNATURE_ROUTE: &str = "/loader/core/signature";
const LOADER_BUNDLE_ROUTE: &str = "/loader/core/bundle";
const LOADER_REQUEST_POLL_MS: u64 = 500;
const MAX_FUTURE_SKEW_MS: u64 = 30_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LoaderIntegrityManifest {
    loader_path: String,
    blake3: String,
    version: String,
    verified_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LoaderAnnouncement {
    agent_id: String,
    ts_ms: u64,
    os: String,
    arch: String,
    version: String,
    blake3: String,
    channel: UpdateChannel,
    distributable: bool,
    transfer_addr: Option<String>,
    signature: String,
}

#[derive(Debug, Clone)]
struct PeerPresence {
    announcement: LoaderAnnouncement,
    source_addr: SocketAddr,
}

#[derive(Debug, Clone)]
struct ActiveCore {
    binary_path: PathBuf,
    metadata: UpdateMetadata,
    metadata_bytes: Vec<u8>,
    signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RollbackMarker {
    activated_ms: u64,
    failed_version: String,
    failed_blake3: String,
    previous_version: String,
    previous_blake3: String,
    #[serde(default)]
    source_kind: Option<String>,
    #[serde(default)]
    source_peer_agent_id: Option<String>,
    #[serde(default)]
    source_peer_addr: Option<String>,
}

#[derive(Debug, Clone)]
struct PendingRollback {
    previous: ActiveCore,
    marker: RollbackMarker,
}

#[derive(Clone)]
struct LoaderSharedState {
    agent_id: String,
    policy_channel: UpdateChannel,
    transfer_advertise_addr: String,
    current: Arc<RwLock<Option<ActiveCore>>>,
    rollback: Arc<RwLock<Option<PendingRollback>>>,
    threats: loader_threat::LoaderThreatHub,
}

impl LoaderSharedState {
    async fn distributable_core(&self) -> Option<ActiveCore> {
        if !self.policy_channel.distributable() {
            return None;
        }
        if self.rollback.read().await.is_some() {
            return None;
        }
        let current = self.current.read().await;
        let active = current.clone()?;
        if !active.metadata.channel.distributable() {
            return None;
        }
        Some(active)
    }

    async fn rollback_pending(&self) -> bool {
        self.rollback.read().await.is_some()
    }
}

#[derive(Debug, Serialize)]
struct LoaderStatusSnapshot {
    ts_ms: u64,
    agent_id: String,
    version: Option<String>,
    channel: Option<String>,
    distributable: bool,
    transfer_addr: Option<String>,
    pending_rollback: bool,
    rollback_previous_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    loader_threats: Option<loader_threat::LoaderThreatSnapshot>,
}

#[derive(Debug)]
struct FetchedCore {
    staged_path: PathBuf,
    metadata: UpdateMetadata,
    metadata_bytes: Vec<u8>,
    signature: String,
}

#[derive(Debug)]
enum PeerFetchError {
    Transport(String),
    Verification(String),
}

impl std::fmt::Display for PeerFetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(detail) => write!(f, "{detail}"),
            Self::Verification(detail) => write!(f, "{detail}"),
        }
    }
}

impl std::error::Error for PeerFetchError {}

impl PeerFetchError {
    fn suspicious(&self) -> bool {
        matches!(self, Self::Verification(_))
    }
}

#[derive(Debug, Clone)]
struct UpdateProvenance {
    source_kind: String,
    peer_agent_id: Option<String>,
    peer_addr: Option<String>,
}

pub async fn run_loader(args: Vec<String>) -> Result<(), Box<dyn Error>> {
    if args.iter().any(|arg| arg == "--version" || arg == "-V") {
        println!("{}", crate::package_version());
        return Ok(());
    }

    let config = Config::load();
    if !config.loader.enabled {
        return Err(std::io::Error::other("loader disabled in config").into());
    }

    let keys = loader_keys(&config)?;
    let loader_root = resolve_loader_root(&config.loader)?;
    let current_binary = current_binary_path(&loader_root);
    let current_metadata = current_metadata_path(&loader_root);
    let current_signature = current_signature_path(&loader_root);
    let rollback_binary = rollback_binary_path(&loader_root);
    let staging_dir = staging_dir_path(&loader_root);
    fs::create_dir_all(current_binary.parent().unwrap_or(&loader_root)).await?;
    fs::create_dir_all(rollback_binary.parent().unwrap_or(&loader_root)).await?;
    fs::create_dir_all(&staging_dir).await?;

    verify_loader_integrity(&config.loader, &loader_root).await?;

    let initial_core = load_or_seed_active_core(
        &config,
        &keys.artifact_key,
        &current_binary,
        &current_metadata,
        &current_signature,
    )
    .await?
    .ok_or_else(|| {
        std::io::Error::other(format!(
            "no Tracey core found at {}",
            current_binary.display()
        ))
    })?;

    let transfer_advertise_addr = config
        .loader
        .transfer_public_addr
        .clone()
        .or_else(|| config.loader.advertise_addr.clone())
        .or_else(|| Some(config.loader.transfer_listen_addr.clone()))
        .ok_or_else(|| std::io::Error::other("loader transfer address missing"))?;

    let pending_rollback = load_pending_rollback(
        &loader_root,
        &keys.artifact_key,
        &initial_core,
        config.loader.rollback_window_ms,
    )
    .await?;
    let threat_hub = loader_threat::LoaderThreatHub::from_config(&config.loader).await?;

    let shared_state = LoaderSharedState {
        agent_id: config.agent_id.clone(),
        policy_channel: config.update.local_channel.clone(),
        transfer_advertise_addr,
        current: Arc::new(RwLock::new(Some(initial_core.clone()))),
        rollback: Arc::new(RwLock::new(pending_rollback.clone())),
        threats: threat_hub.clone(),
    };
    let shared_state = Arc::new(shared_state);

    let (shutdown, shutdown_listener) = Shutdown::new();
    let transfer_listen_addr = config.loader.transfer_listen_addr.parse::<SocketAddr>()?;
    tokio::spawn(spawn_transfer_server(
        shared_state.clone(),
        transfer_listen_addr,
        shutdown_listener.clone(),
    ));

    let gossip_socket = UdpSocket::bind(&config.loader.discovery_bind_addr).await?;
    gossip_socket.set_broadcast(true)?;

    let update_dir = resolve_update_dir(&config.update.update_dir)?;
    fs::create_dir_all(&update_dir).await?;

    let mut peers: HashMap<String, PeerPresence> = HashMap::new();
    let mut child = spawn_core_child(&initial_core, &update_dir).await?;
    let mut announce_tick =
        tokio::time::interval(Duration::from_millis(config.loader.announce_interval_ms));
    let mut sync_tick =
        tokio::time::interval(Duration::from_millis(config.loader.sync_interval_ms));
    let mut request_tick = tokio::time::interval(Duration::from_millis(LOADER_REQUEST_POLL_MS));
    let mut integrity_tick = tokio::time::interval(Duration::from_millis(
        config.loader.integrity_check_interval_ms,
    ));
    let mut stability_tick = tokio::time::interval(Duration::from_millis(1000));
    let mut buf = vec![0u8; 4096];
    let mut backoff = Duration::from_millis(500);
    let mut last_sync_attempt: Option<(String, u64)> = None;

    tracing::info!(
        transfer = %config.loader.transfer_listen_addr,
        discovery = %config.loader.discovery_bind_addr,
        current = %initial_core.binary_path.display(),
        version = %initial_core.metadata.version,
        channel = %initial_core.metadata.channel,
        "tracey loader started"
    );
    if let Some(pending) = pending_rollback {
        tracing::warn!(
            failed_version = %pending.marker.failed_version,
            previous_version = %pending.marker.previous_version,
            activated_ms = pending.marker.activated_ms,
            "tracey core is in rollback probation window"
        );
    }

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("loader ctrl-c received; shutting down");
                shutdown.trigger();
                shutdown_child(&mut child).await;
                break;
            }
            status = child.child.wait() => {
                tracing::warn!(code = ?status.ok().and_then(|s| s.code()), "tracey core exited");

                if let Some(restored) = rollback_after_crash(
                    &loader_root,
                    &keys.artifact_key,
                    shared_state.clone(),
                    config.loader.rollback_window_ms,
                )
                .await? {
                    tracing::warn!(
                        restored_version = %restored.metadata.version,
                        "loader reverted to previous stable core after crash"
                    );
                    child = spawn_core_child(&restored, &update_dir).await?;
                    backoff = Duration::from_millis(250);
                    continue;
                }

                if let Some(request) = supervisor::read_update_request(&update_dir).await {
                    if let Err(err) = apply_supervisor_request(
                        &config,
                        &keys.artifact_key,
                        &loader_root,
                        &update_dir,
                        shared_state.clone(),
                        &mut child,
                        request,
                    ).await {
                        tracing::warn!(error = %err, "loader failed applying staged core update");
                    } else {
                        backoff = Duration::from_millis(250);
                        continue;
                    }
                }

                if backoff > Duration::from_millis(0) {
                    tokio::time::sleep(backoff).await;
                }
                let active = shared_state
                    .current
                    .read()
                    .await
                    .clone()
                    .ok_or_else(|| std::io::Error::other("loader lost active core state"))?;
                child = spawn_core_child(&active, &update_dir).await?;
                if backoff < Duration::from_secs(10) {
                    backoff = (backoff * 2).min(Duration::from_secs(10));
                }
            }
            _ = announce_tick.tick() => {
                stabilize_rollout_if_ready(
                    &loader_root,
                    shared_state.clone(),
                    config.loader.rollback_window_ms,
                )
                .await;
                let announcement = build_loader_announcement(shared_state.clone(), &keys.gossip_key).await;
                match serde_json::to_vec(&announcement) {
                    Ok(payload) => {
                        if let Err(err) = gossip_socket.send_to(&payload, &config.loader.discovery_broadcast_addr).await {
                            tracing::warn!(target = %config.loader.discovery_broadcast_addr, error = %err, "loader announcement broadcast failed");
                        }
                    }
                    Err(err) => {
                        tracing::warn!(error = %err, "loader announcement serialization failed");
                    }
                }
                if let Some(threat_announcement) = threat_hub
                    .build_announcement(&config.agent_id, &keys.gossip_key, 8)
                    .await
                {
                    match serde_json::to_vec(&threat_announcement) {
                        Ok(payload) => {
                            if let Err(err) = gossip_socket
                                .send_to(&payload, &config.loader.discovery_broadcast_addr)
                                .await
                            {
                                tracing::warn!(
                                    target = %config.loader.discovery_broadcast_addr,
                                    error = %err,
                                    "loader threat announcement broadcast failed"
                                );
                            }
                        }
                        Err(err) => {
                            tracing::warn!(
                                error = %err,
                                "loader threat announcement serialization failed"
                            );
                        }
                    }
                }
            }
            recv = gossip_socket.recv_from(&mut buf) => {
                match recv {
                    Ok((size, peer_addr)) => {
                        let loader_announcement =
                            match serde_json::from_slice::<LoaderAnnouncement>(&buf[..size]) {
                                Ok(announcement) => Some(announcement),
                                Err(_) => match parse_loader_announcement_lossy(&buf[..size]) {
                                    Ok((announcement, affinity)) => {
                                        tracing::info!(
                                            peer = %peer_addr,
                                            affinity,
                                            "loader announcement recovered with fuzzy parser"
                                        );
                                        Some(announcement)
                                    }
                                    Err(_) => None,
                                },
                            };
                        if let Some(announcement) = loader_announcement {
                            if announcement.agent_id != config.agent_id
                                && validate_loader_announcement(
                                    &announcement,
                                    &keys.gossip_key,
                                    config.loader.ttl_ms,
                                )
                                .is_ok()
                            {
                                peers.insert(
                                    announcement.agent_id.clone(),
                                    PeerPresence {
                                        announcement,
                                        source_addr: peer_addr,
                                    },
                                );
                            }
                            continue;
                        }

                        let threat_announcement = match serde_json::from_slice::<
                            loader_threat::LoaderThreatAnnouncement,
                        >(&buf[..size]) {
                            Ok(announcement) => Some(announcement),
                            Err(_) => {
                                match loader_threat::parse_loader_threat_announcement_lossy(
                                    &buf[..size],
                                ) {
                                    Ok((announcement, affinity)) => {
                                        tracing::info!(
                                            peer = %peer_addr,
                                            affinity,
                                            "loader threat announcement recovered with fuzzy parser"
                                        );
                                        Some(announcement)
                                    }
                                    Err(reason) => {
                                        tracing::warn!(
                                            peer = %peer_addr,
                                            reason = %reason,
                                            "invalid loader gossip payload"
                                        );
                                        None
                                    }
                                }
                            }
                        };
                        if let Some(announcement) = threat_announcement
                            && announcement.agent_id != config.agent_id
                        {
                            if loader_threat::validate_loader_threat_announcement(
                                &announcement,
                                &keys.gossip_key,
                                config.loader.ttl_ms,
                            )
                            .is_ok()
                            {
                                threat_hub.ingest_remote(announcement).await;
                            }
                        }
                    }
                    Err(err) => {
                        tracing::warn!(error = %err, "loader discovery receive failed");
                    }
                }
            }
            _ = request_tick.tick() => {
                if shared_state.rollback_pending().await {
                    continue;
                }
                if let Some(request) = supervisor::read_update_request(&update_dir).await {
                    match apply_supervisor_request(
                        &config,
                        &keys.artifact_key,
                        &loader_root,
                        &update_dir,
                        shared_state.clone(),
                        &mut child,
                        request,
                    ).await {
                        Ok(()) => {
                            backoff = Duration::from_millis(250);
                        }
                        Err(err) => {
                            tracing::warn!(error = %err, "loader could not activate staged core update");
                        }
                    }
                }
            }
            _ = sync_tick.tick() => {
                stabilize_rollout_if_ready(
                    &loader_root,
                    shared_state.clone(),
                    config.loader.rollback_window_ms,
                )
                .await;
                if should_attempt_peer_sync(&config, shared_state.clone(), &last_sync_attempt).await {
                    if let Some(candidate) = choose_best_peer(
                        &peers,
                        shared_state.clone(),
                        threat_hub.clone(),
                        config.loader.ttl_ms,
                    )
                    .await {
                        last_sync_attempt = Some((candidate.announcement.version.clone(), now_ms()));
                        match sync_from_peer(
                            &config,
                            &keys.artifact_key,
                            &loader_root,
                            &update_dir,
                            shared_state.clone(),
                            threat_hub.clone(),
                            &mut child,
                            &candidate,
                        ).await {
                            Ok(true) => {
                                backoff = Duration::from_millis(250);
                            }
                            Ok(false) => {}
                            Err(err) => {
                                tracing::warn!(
                                    peer = %candidate.announcement.agent_id,
                                    version = %candidate.announcement.version,
                                    error = %err,
                                    "loader peer sync failed"
                                );
                            }
                        }
                    }
                }
            }
            _ = integrity_tick.tick() => {
                verify_loader_integrity(&config.loader, &loader_root).await?;
            }
            _ = stability_tick.tick() => {
                stabilize_rollout_if_ready(
                    &loader_root,
                    shared_state.clone(),
                    config.loader.rollback_window_ms,
                )
                .await;
            }
        }
    }

    Ok(())
}

fn loader_keys(config: &Config) -> Result<LoaderKeys, std::io::Error> {
    let artifact_key = if !config.update.shared_key.trim().is_empty() {
        config.update.shared_key.clone()
    } else if !config.discovery.shared_key.trim().is_empty() {
        config.discovery.shared_key.clone()
    } else {
        return Err(std::io::Error::other(
            "loader requires update.shared_key or discovery.shared_key",
        ));
    };

    let gossip_key = if !config.discovery.shared_key.trim().is_empty() {
        config.discovery.shared_key.clone()
    } else {
        artifact_key.clone()
    };

    Ok(LoaderKeys {
        artifact_key,
        gossip_key,
    })
}

struct LoaderKeys {
    artifact_key: String,
    gossip_key: String,
}

fn resolve_loader_root(config: &LoaderConfig) -> Result<PathBuf, std::io::Error> {
    if config.state_dir.is_absolute() {
        return Ok(config.state_dir.clone());
    }
    Ok(std::env::current_dir()?.join(&config.state_dir))
}

fn resolve_update_dir(update_dir: &Path) -> Result<PathBuf, std::io::Error> {
    if update_dir.is_absolute() {
        Ok(update_dir.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(update_dir))
    }
}

fn current_binary_path(root: &Path) -> PathBuf {
    root.join(LOADER_CURRENT_BINARY)
}

fn current_metadata_path(root: &Path) -> PathBuf {
    root.join(LOADER_CURRENT_METADATA)
}

fn current_signature_path(root: &Path) -> PathBuf {
    root.join(LOADER_CURRENT_SIGNATURE)
}

fn rollback_binary_path(root: &Path) -> PathBuf {
    root.join(LOADER_ROLLBACK_BINARY)
}

fn rollback_metadata_path(root: &Path) -> PathBuf {
    root.join(LOADER_ROLLBACK_METADATA)
}

fn rollback_signature_path(root: &Path) -> PathBuf {
    root.join(LOADER_ROLLBACK_SIGNATURE)
}

fn rollback_state_path(root: &Path) -> PathBuf {
    root.join(LOADER_ROLLBACK_STATE)
}

fn staging_dir_path(root: &Path) -> PathBuf {
    root.join(LOADER_STAGING_DIR)
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join(LOADER_MANIFEST)
}

async fn verify_loader_integrity(config: &LoaderConfig, root: &Path) -> Result<(), Box<dyn Error>> {
    let loader_path = std::env::current_exe()?;
    let loader_bytes = fs::read(&loader_path).await?;
    let digest = update::to_hex(blake3::hash(&loader_bytes).as_bytes());
    let manifest_path = manifest_path(root);
    let now = now_ms();

    let mut manifest = if manifest_path.exists() {
        let raw = fs::read(&manifest_path).await?;
        serde_json::from_slice::<LoaderIntegrityManifest>(&raw)?
    } else {
        LoaderIntegrityManifest {
            loader_path: loader_path.display().to_string(),
            blake3: digest.clone(),
            version: crate::package_version().to_string(),
            verified_ms: now,
        }
    };

    if manifest.blake3 != digest {
        return Err(std::io::Error::other(format!(
            "loader integrity check failed for {}",
            loader_path.display()
        ))
        .into());
    }

    let mut changed = false;
    let loader_path_str = loader_path.display().to_string();
    if manifest.loader_path != loader_path_str {
        manifest.loader_path = loader_path_str;
        changed = true;
    }
    if manifest.version != crate::package_version() {
        manifest.version = crate::package_version().to_string();
        changed = true;
    }
    if manifest.verified_ms + config.integrity_check_interval_ms <= now || !manifest_path.exists() {
        manifest.verified_ms = now;
        changed = true;
    }

    if changed {
        let payload = serde_json::to_vec_pretty(&manifest)?;
        update::write_atomic(&manifest_path, &payload).await?;
    }

    Ok(())
}

async fn load_pending_rollback(
    loader_root: &Path,
    artifact_key: &str,
    current: &ActiveCore,
    rollback_window_ms: u64,
) -> Result<Option<PendingRollback>, Box<dyn Error>> {
    let state_path = rollback_state_path(loader_root);
    if !state_path.exists() {
        return Ok(None);
    }

    let raw = fs::read(&state_path).await?;
    let marker: RollbackMarker = serde_json::from_slice(&raw)?;
    if rollback_marker_expired(&marker, rollback_window_ms, now_ms()) {
        clear_rollback_marker_file(loader_root).await?;
        return Ok(None);
    }
    if current.metadata.version != marker.failed_version
        || current.metadata.blake3 != marker.failed_blake3
    {
        clear_rollback_marker_file(loader_root).await?;
        return Ok(None);
    }

    let previous = load_active_core_from_paths(
        &rollback_binary_path(loader_root),
        &rollback_metadata_path(loader_root),
        &rollback_signature_path(loader_root),
        artifact_key,
    )
    .await?;
    if previous.metadata.version != marker.previous_version
        || previous.metadata.blake3 != marker.previous_blake3
    {
        clear_rollback_marker_file(loader_root).await?;
        return Ok(None);
    }

    Ok(Some(PendingRollback { previous, marker }))
}

async fn load_active_core_from_paths(
    binary_path: &Path,
    metadata_path: &Path,
    signature_path: &Path,
    artifact_key: &str,
) -> Result<ActiveCore, Box<dyn Error>> {
    let bundle_bytes = fs::read(binary_path).await?;
    let metadata_bytes = fs::read(metadata_path).await?;
    let signature = fs::read_to_string(signature_path).await?;
    let metadata = update::verify_signed_artifacts(
        &metadata_bytes,
        &bundle_bytes,
        signature.trim(),
        artifact_key,
    )?;
    validate_local_metadata(&metadata)?;
    ensure_executable(binary_path).await?;

    Ok(ActiveCore {
        binary_path: binary_path.to_path_buf(),
        metadata,
        metadata_bytes,
        signature: signature.trim().to_string(),
    })
}

async fn snapshot_current_for_rollback(
    loader_root: &Path,
    active: &ActiveCore,
) -> Result<ActiveCore, Box<dyn Error>> {
    let rollback_binary = rollback_binary_path(loader_root);
    let rollback_metadata = rollback_metadata_path(loader_root);
    let rollback_signature = rollback_signature_path(loader_root);
    let bundle_bytes = fs::read(&active.binary_path).await?;
    update::write_atomic(&rollback_binary, &bundle_bytes).await?;
    ensure_executable(&rollback_binary).await?;
    update::write_atomic(&rollback_metadata, &active.metadata_bytes).await?;
    update::write_atomic(&rollback_signature, active.signature.as_bytes()).await?;

    Ok(ActiveCore {
        binary_path: rollback_binary,
        metadata: active.metadata.clone(),
        metadata_bytes: active.metadata_bytes.clone(),
        signature: active.signature.clone(),
    })
}

async fn write_rollback_marker(
    loader_root: &Path,
    marker: &RollbackMarker,
) -> Result<(), Box<dyn Error>> {
    let payload = serde_json::to_vec_pretty(marker)?;
    update::write_atomic(&rollback_state_path(loader_root), &payload).await?;
    Ok(())
}

async fn clear_rollback_marker_file(loader_root: &Path) -> Result<(), Box<dyn Error>> {
    let path = rollback_state_path(loader_root);
    if path.exists() {
        let _ = fs::remove_file(path).await;
    }
    Ok(())
}

async fn clear_pending_rollback(
    loader_root: &Path,
    shared: Arc<LoaderSharedState>,
) -> Result<(), Box<dyn Error>> {
    clear_rollback_marker_file(loader_root).await?;
    *shared.rollback.write().await = None;
    Ok(())
}

async fn stabilize_rollout_if_ready(
    loader_root: &Path,
    shared: Arc<LoaderSharedState>,
    rollback_window_ms: u64,
) {
    let pending = { shared.rollback.read().await.clone() };
    let Some(pending) = pending else {
        return;
    };
    if !rollback_marker_expired(&pending.marker, rollback_window_ms, now_ms()) {
        return;
    }
    match clear_pending_rollback(loader_root, shared.clone()).await {
        Ok(()) => {
            tracing::info!(
                version = %pending.marker.failed_version,
                previous = %pending.marker.previous_version,
                "tracey core cleared rollback probation window"
            );
        }
        Err(err) => {
            tracing::warn!(error = %err, "failed to clear loader rollback marker");
        }
    }
}

async fn rollback_after_crash(
    loader_root: &Path,
    artifact_key: &str,
    shared: Arc<LoaderSharedState>,
    rollback_window_ms: u64,
) -> Result<Option<ActiveCore>, Box<dyn Error>> {
    let pending = { shared.rollback.read().await.clone() };
    let Some(pending) = pending else {
        return Ok(None);
    };
    if rollback_marker_expired(&pending.marker, rollback_window_ms, now_ms()) {
        clear_pending_rollback(loader_root, shared).await?;
        return Ok(None);
    }

    let current = shared
        .current
        .read()
        .await
        .clone()
        .ok_or_else(|| std::io::Error::other("loader lost active core state"))?;
    if current.metadata.version != pending.marker.failed_version
        || current.metadata.blake3 != pending.marker.failed_blake3
    {
        return Ok(None);
    }

    if let Err(err) = archive_failed_core(loader_root, &current).await {
        tracing::warn!(
            version = %current.metadata.version,
            error = %err,
            "failed to archive crashing core before rollback"
        );
    }
    shared
        .threats
        .record_incident(LocalThreatIncident {
            provider_agent_id: pending.marker.source_peer_agent_id.clone(),
            source_addr: pending.marker.source_peer_addr.clone(),
            artifact_version: Some(current.metadata.version.clone()),
            artifact_blake3: Some(current.metadata.blake3.clone()),
            classification: "crashing_update".to_string(),
            reason: format!(
                "activated core crashed during rollback probation window via {}",
                pending
                    .marker
                    .source_kind
                    .clone()
                    .unwrap_or_else(|| "unknown source".to_string())
            ),
            provider_risk: if pending.marker.source_peer_agent_id.is_some() {
                1.0
            } else {
                0.0
            },
            artifact_risk: 1.0,
        })
        .await;
    let restored = restore_previous_core(loader_root, artifact_key, &pending.previous).await?;
    *shared.current.write().await = Some(restored.clone());
    clear_pending_rollback(loader_root, shared).await?;
    Ok(Some(restored))
}

async fn archive_failed_core(
    loader_root: &Path,
    failed: &ActiveCore,
) -> Result<(), Box<dyn Error>> {
    let archive_root = staging_dir_path(loader_root);
    fs::create_dir_all(&archive_root).await?;
    let stem = format!(
        "failed-{}-{}",
        failed.metadata.version.replace('/', "_"),
        failed.metadata.blake3
    );
    let failed_binary = archive_root.join(&stem);
    let failed_metadata = archive_root.join(format!("{}.meta.json", stem));
    let failed_signature = archive_root.join(format!("{}.sig", stem));

    if failed.binary_path.exists() {
        let bytes = fs::read(&failed.binary_path).await?;
        update::write_atomic(&failed_binary, &bytes).await?;
        ensure_executable(&failed_binary).await?;
    }
    update::write_atomic(&failed_metadata, &failed.metadata_bytes).await?;
    update::write_atomic(&failed_signature, failed.signature.as_bytes()).await?;
    Ok(())
}

async fn restore_previous_core(
    loader_root: &Path,
    artifact_key: &str,
    previous: &ActiveCore,
) -> Result<ActiveCore, Box<dyn Error>> {
    let bundle_bytes = fs::read(&previous.binary_path).await?;
    let current_binary = current_binary_path(loader_root);
    let current_metadata = current_metadata_path(loader_root);
    let current_signature = current_signature_path(loader_root);

    update::write_atomic(&current_binary, &bundle_bytes).await?;
    ensure_executable(&current_binary).await?;
    update::write_atomic(&current_metadata, &previous.metadata_bytes).await?;
    update::write_atomic(&current_signature, previous.signature.as_bytes()).await?;

    let reloaded = load_active_core_from_paths(
        &current_binary,
        &current_metadata,
        &current_signature,
        artifact_key,
    )
    .await?;
    Ok(reloaded)
}

async fn cleanup_staged_core(path: PathBuf) {
    if path.exists() {
        let _ = fs::remove_file(path).await;
    }
}

fn rollback_marker_expired(marker: &RollbackMarker, rollback_window_ms: u64, now: u64) -> bool {
    now.saturating_sub(marker.activated_ms) > rollback_window_ms
}

async fn load_or_seed_active_core(
    config: &Config,
    artifact_key: &str,
    binary_path: &Path,
    metadata_path: &Path,
    signature_path: &Path,
) -> Result<Option<ActiveCore>, Box<dyn Error>> {
    if !binary_path.exists() {
        return Ok(None);
    }

    let bundle_bytes = fs::read(binary_path).await?;
    ensure_executable(binary_path).await?;

    if metadata_path.exists() && signature_path.exists() {
        let metadata_bytes = fs::read(metadata_path).await?;
        let signature = fs::read_to_string(signature_path).await?;
        let metadata = update::verify_signed_artifacts(
            &metadata_bytes,
            &bundle_bytes,
            signature.trim(),
            artifact_key,
        )?;
        validate_local_metadata(&metadata)?;
        return Ok(Some(ActiveCore {
            binary_path: binary_path.to_path_buf(),
            metadata,
            metadata_bytes,
            signature: signature.trim().to_string(),
        }));
    }

    let version = match read_core_version(binary_path).await {
        Some(version) => version,
        None => config
            .loader
            .bootstrap_version
            .clone()
            .unwrap_or_else(|| crate::package_version().to_string()),
    };
    let metadata = update::build_metadata(
        version,
        std::env::consts::OS,
        std::env::consts::ARCH,
        &bundle_bytes,
        config.update.local_channel.clone(),
    );
    let metadata_bytes = update::serialize_metadata(&metadata)?;
    let signature = update::sign_metadata_bytes(&metadata_bytes, &bundle_bytes, artifact_key);
    update::write_atomic(metadata_path, &metadata_bytes).await?;
    update::write_atomic(signature_path, signature.as_bytes()).await?;

    Ok(Some(ActiveCore {
        binary_path: binary_path.to_path_buf(),
        metadata,
        metadata_bytes,
        signature,
    }))
}

fn validate_local_metadata(metadata: &UpdateMetadata) -> Result<(), Box<dyn Error>> {
    if metadata.os != std::env::consts::OS || metadata.arch != std::env::consts::ARCH {
        return Err(std::io::Error::other("local core metadata os/arch mismatch").into());
    }
    Ok(())
}

async fn read_core_version(binary_path: &Path) -> Option<String> {
    let output = tokio::time::timeout(
        Duration::from_secs(2),
        Command::new(binary_path).arg("--version").output(),
    )
    .await
    .ok()?
    .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let version = stdout.lines().next()?.trim();
    if version.is_empty() {
        None
    } else {
        Some(version.to_string())
    }
}

async fn spawn_core_child(
    active: &ActiveCore,
    update_dir: &Path,
) -> Result<ManagedChild, Box<dyn Error>> {
    let extra_env = vec![
        (
            "TRACEY_ACTIVE_CORE_VERSION".to_string(),
            active.metadata.version.clone(),
        ),
        (
            "TRACEY_ACTIVE_CORE_CHANNEL".to_string(),
            active.metadata.channel.to_string(),
        ),
    ];
    Ok(supervisor::spawn_child_with_env(
        &active.binary_path,
        &[],
        update_dir,
        None,
        &extra_env,
        None,
        "loader",
    )
    .await?)
}

async fn shutdown_child(child: &mut ManagedChild) {
    supervisor::request_shutdown(&child.shutdown_path, &child.shutdown_token).await;
    if tokio::time::timeout(Duration::from_secs(5), child.child.wait())
        .await
        .is_err()
    {
        let _ = child.child.kill().await;
    }
}

async fn spawn_transfer_server(
    shared: Arc<LoaderSharedState>,
    listen_addr: SocketAddr,
    mut shutdown: ShutdownListener,
) {
    let app = Router::new()
        .route(LOADER_HEALTH_ROUTE, get(loader_health_handler))
        .route(LOADER_STATUS_ROUTE, get(loader_status_handler))
        .route(LOADER_METADATA_ROUTE, get(loader_metadata_handler))
        .route(LOADER_SIGNATURE_ROUTE, get(loader_signature_handler))
        .route(LOADER_BUNDLE_ROUTE, get(loader_bundle_handler))
        .with_state(shared);

    let listener = match tokio::net::TcpListener::bind(listen_addr).await {
        Ok(listener) => listener,
        Err(err) => {
            tracing::warn!(addr = %listen_addr, error = %err, "loader transfer bind failed");
            return;
        }
    };

    if let Err(err) = axum::serve(listener, app)
        .with_graceful_shutdown(async move { shutdown.wait().await })
        .await
    {
        tracing::warn!(error = %err, "loader transfer server failed");
    }
}

async fn loader_health_handler(State(shared): State<Arc<LoaderSharedState>>) -> StatusCode {
    if shared.current.read().await.is_some() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

async fn loader_status_handler(
    State(shared): State<Arc<LoaderSharedState>>,
) -> Json<LoaderStatusSnapshot> {
    let current = shared.current.read().await.clone();
    let pending = shared.rollback.read().await.clone();
    let distributable = shared.distributable_core().await.is_some();
    let loader_threats = Some(shared.threats.snapshot(8).await);
    Json(LoaderStatusSnapshot {
        ts_ms: now_ms(),
        agent_id: shared.agent_id.clone(),
        version: current
            .as_ref()
            .map(|active| active.metadata.version.clone()),
        channel: current
            .as_ref()
            .map(|active| active.metadata.channel.to_string()),
        distributable,
        transfer_addr: if distributable {
            Some(shared.transfer_advertise_addr.clone())
        } else {
            None
        },
        pending_rollback: pending.is_some(),
        rollback_previous_version: pending.map(|state| state.marker.previous_version),
        loader_threats,
    })
}

async fn loader_metadata_handler(
    State(shared): State<Arc<LoaderSharedState>>,
) -> Result<impl axum::response::IntoResponse, StatusCode> {
    let Some(active) = shared.distributable_core().await else {
        return Err(StatusCode::NOT_FOUND);
    };
    Ok((
        [(header::CONTENT_TYPE, "application/json")],
        active.metadata_bytes,
    ))
}

async fn loader_signature_handler(
    State(shared): State<Arc<LoaderSharedState>>,
) -> Result<impl axum::response::IntoResponse, StatusCode> {
    let Some(active) = shared.distributable_core().await else {
        return Err(StatusCode::NOT_FOUND);
    };
    Ok((
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        active.signature,
    ))
}

async fn loader_bundle_handler(
    State(shared): State<Arc<LoaderSharedState>>,
) -> Result<impl axum::response::IntoResponse, StatusCode> {
    let Some(active) = shared.distributable_core().await else {
        return Err(StatusCode::NOT_FOUND);
    };
    let bytes = fs::read(&active.binary_path)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(([(header::CONTENT_TYPE, "application/octet-stream")], bytes))
}

async fn build_loader_announcement(
    shared: Arc<LoaderSharedState>,
    gossip_key: &str,
) -> LoaderAnnouncement {
    let current = shared.current.read().await.clone();
    let rollback_pending = shared.rollback_pending().await;
    let (version, blake3, channel, distributable) = if let Some(active) = current {
        let distributable = !rollback_pending
            && shared.policy_channel.distributable()
            && active.metadata.channel.distributable();
        (
            active.metadata.version,
            active.metadata.blake3,
            active.metadata.channel,
            distributable,
        )
    } else {
        (
            String::new(),
            String::new(),
            shared.policy_channel.clone(),
            false,
        )
    };

    let mut announcement = LoaderAnnouncement {
        agent_id: shared.agent_id.clone(),
        ts_ms: now_ms(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        version,
        blake3,
        channel,
        distributable,
        transfer_addr: if distributable {
            Some(shared.transfer_advertise_addr.clone())
        } else {
            None
        },
        signature: String::new(),
    };
    announcement.signature = sign_loader_announcement(&announcement, gossip_key);
    announcement
}

fn validate_loader_announcement(
    announcement: &LoaderAnnouncement,
    gossip_key: &str,
    ttl_ms: u64,
) -> Result<(), Box<dyn Error>> {
    if announcement.agent_id.trim().is_empty() {
        return Err(std::io::Error::other("loader announcement missing agent_id").into());
    }
    if !verify_loader_announcement_signature(announcement, gossip_key) {
        return Err(std::io::Error::other("loader announcement signature mismatch").into());
    }
    let now = now_ms();
    if announcement.ts_ms > now.saturating_add(MAX_FUTURE_SKEW_MS) {
        return Err(
            std::io::Error::other("loader announcement timestamp too far in future").into(),
        );
    }
    if now.saturating_sub(announcement.ts_ms) > ttl_ms {
        return Err(std::io::Error::other("loader announcement expired").into());
    }
    if announcement.os != std::env::consts::OS || announcement.arch != std::env::consts::ARCH {
        return Err(std::io::Error::other("loader announcement os/arch mismatch").into());
    }
    Ok(())
}

fn parse_loader_announcement_lossy(payload: &[u8]) -> Result<(LoaderAnnouncement, f64), String> {
    let root = peer_compat::parse_bytes(payload).map_err(|err| err.to_string())?;
    let fields = [
        SchemaField {
            aliases: &["agent_id", "agentId", "node_id", "nodeId", "id"],
            required: true,
            weight: 2.0,
        },
        SchemaField {
            aliases: &["ts_ms", "timestamp_ms", "timestamp", "updated_ms"],
            required: true,
            weight: 1.5,
        },
        SchemaField {
            aliases: &["version", "agent_version", "build_version"],
            required: true,
            weight: 1.5,
        },
        SchemaField {
            aliases: &["blake3", "digest", "hash", "checksum"],
            required: true,
            weight: 2.0,
        },
        SchemaField {
            aliases: &["signature", "sig", "mac"],
            required: true,
            weight: 2.0,
        },
    ];
    let matched = peer_compat::best_object(&root, &fields, 3.0, 4)
        .ok_or_else(|| "payload did not resemble a loader announcement".to_string())?;
    let map = matched.map;
    let channel = peer_compat::value_for(map, &["channel", "release_channel", "track"])
        .and_then(parse_update_channel_lossy)
        .unwrap_or(UpdateChannel::Production);
    let distributable = peer_compat::value_for(
        map,
        &[
            "distributable",
            "can_distribute",
            "shareable",
            "production_ready",
        ],
    )
    .and_then(peer_compat::coerce_bool)
    .unwrap_or_else(|| channel.distributable());

    Ok((
        LoaderAnnouncement {
            agent_id: peer_compat::value_for(
                map,
                &["agent_id", "agentId", "node_id", "nodeId", "id"],
            )
            .and_then(peer_compat::coerce_string)
            .ok_or_else(|| "missing agent identifier".to_string())?,
            ts_ms: peer_compat::value_for(
                map,
                &["ts_ms", "timestamp_ms", "timestamp", "updated_ms"],
            )
            .and_then(peer_compat::coerce_u64)
            .ok_or_else(|| "missing timestamp".to_string())?,
            os: peer_compat::value_for(map, &["os", "platform", "target_os"])
                .and_then(peer_compat::coerce_string)
                .ok_or_else(|| "missing os".to_string())?,
            arch: peer_compat::value_for(map, &["arch", "architecture", "target_arch"])
                .and_then(peer_compat::coerce_string)
                .ok_or_else(|| "missing arch".to_string())?,
            version: peer_compat::value_for(map, &["version", "agent_version", "build_version"])
                .and_then(peer_compat::coerce_string)
                .ok_or_else(|| "missing version".to_string())?,
            blake3: peer_compat::value_for(map, &["blake3", "digest", "hash", "checksum"])
                .and_then(peer_compat::coerce_string)
                .ok_or_else(|| "missing digest".to_string())?,
            channel,
            distributable,
            transfer_addr: peer_compat::value_for(
                map,
                &["transfer_addr", "transferAddr", "addr", "url", "bundle_url"],
            )
            .and_then(peer_compat::coerce_string),
            signature: peer_compat::value_for(map, &["signature", "sig", "mac"])
                .and_then(peer_compat::coerce_string)
                .ok_or_else(|| "missing signature".to_string())?,
        },
        matched.score,
    ))
}

fn sign_loader_announcement(announcement: &LoaderAnnouncement, gossip_key: &str) -> String {
    let key = update::derive_key(gossip_key);
    let payload = serde_json::to_vec(&(
        &announcement.agent_id,
        announcement.ts_ms,
        &announcement.os,
        &announcement.arch,
        &announcement.version,
        &announcement.blake3,
        announcement.channel.as_str(),
        announcement.distributable,
        announcement.transfer_addr.as_deref().unwrap_or(""),
    ))
    .unwrap_or_default();
    let mut hasher = blake3::Hasher::new_keyed(&key);
    hasher.update(&payload);
    update::to_hex(hasher.finalize().as_bytes())
}

fn verify_loader_announcement_signature(
    announcement: &LoaderAnnouncement,
    gossip_key: &str,
) -> bool {
    let expected = sign_loader_announcement(announcement, gossip_key);
    if update::constant_time_eq(&announcement.signature, &expected) {
        return true;
    }
    let legacy_without_transfer = sign_loader_announcement_legacy(announcement, gossip_key, true);
    if update::constant_time_eq(&announcement.signature, &legacy_without_transfer) {
        return true;
    }
    let legacy_without_distributable =
        sign_loader_announcement_legacy(announcement, gossip_key, false);
    update::constant_time_eq(&announcement.signature, &legacy_without_distributable)
}

fn sign_loader_announcement_legacy(
    announcement: &LoaderAnnouncement,
    gossip_key: &str,
    include_distributable: bool,
) -> String {
    let key = update::derive_key(gossip_key);
    let payload = if include_distributable {
        serde_json::to_vec(&(
            &announcement.agent_id,
            announcement.ts_ms,
            &announcement.os,
            &announcement.arch,
            &announcement.version,
            &announcement.blake3,
            announcement.channel.as_str(),
            announcement.distributable,
        ))
        .unwrap_or_default()
    } else {
        serde_json::to_vec(&(
            &announcement.agent_id,
            announcement.ts_ms,
            &announcement.os,
            &announcement.arch,
            &announcement.version,
            &announcement.blake3,
            announcement.channel.as_str(),
        ))
        .unwrap_or_default()
    };
    let mut hasher = blake3::Hasher::new_keyed(&key);
    hasher.update(&payload);
    update::to_hex(hasher.finalize().as_bytes())
}

fn parse_update_channel_lossy(value: &Value) -> Option<UpdateChannel> {
    peer_compat::coerce_string(value)
        .and_then(|value| value.parse::<UpdateChannel>().ok())
        .or_else(|| {
            peer_compat::coerce_u64(value).map(|value| {
                if value == 0 {
                    UpdateChannel::Production
                } else {
                    UpdateChannel::Development
                }
            })
        })
}

async fn should_attempt_peer_sync(
    config: &Config,
    shared: Arc<LoaderSharedState>,
    last_sync_attempt: &Option<(String, u64)>,
) -> bool {
    if shared.rollback_pending().await {
        return false;
    }
    if !config.update.local_channel.distributable() {
        return false;
    }
    let Some(active) = shared.current.read().await.clone() else {
        return false;
    };
    if !active.metadata.channel.distributable() {
        return false;
    }
    if let Some((_, ts_ms)) = last_sync_attempt
        && now_ms().saturating_sub(*ts_ms) < config.loader.sync_interval_ms / 2
    {
        return false;
    }
    true
}

async fn choose_best_peer(
    peers: &HashMap<String, PeerPresence>,
    shared: Arc<LoaderSharedState>,
    threats: loader_threat::LoaderThreatHub,
    ttl_ms: u64,
) -> Option<PeerPresence> {
    let local = shared.current.read().await.clone()?;
    let now = now_ms();
    let mut best: Option<PeerPresence> = None;

    for peer in peers.values() {
        if now.saturating_sub(peer.announcement.ts_ms) > ttl_ms
            || !peer.announcement.distributable
            || !peer.announcement.channel.distributable()
            || peer.announcement.version.trim().is_empty()
            || compare_versions(&peer.announcement.version, &local.metadata.version)
                != Ordering::Greater
        {
            continue;
        }

        let provider_assessment = threats
            .provider_assessment(&peer.announcement.agent_id)
            .await;
        if provider_assessment.recommended_block {
            tracing::debug!(
                peer = %peer.announcement.agent_id,
                local_risk = provider_assessment.local_risk,
                remote_risk = provider_assessment.remote_risk,
                remote_reporters = provider_assessment.remote_reporters,
                "skipping loader peer because provider is blocklisted"
            );
            continue;
        }

        let artifact_assessment = threats
            .artifact_assessment(&peer.announcement.version, &peer.announcement.blake3)
            .await;
        if artifact_assessment.recommended_block {
            tracing::debug!(
                peer = %peer.announcement.agent_id,
                version = %peer.announcement.version,
                blake3 = %peer.announcement.blake3,
                local_risk = artifact_assessment.local_risk,
                remote_risk = artifact_assessment.remote_risk,
                remote_reporters = artifact_assessment.remote_reporters,
                "skipping loader peer because artifact is blocklisted"
            );
            continue;
        }

        let replace = best.as_ref().is_none_or(|current| {
            compare_versions(&peer.announcement.version, &current.announcement.version)
                .then_with(|| peer.announcement.ts_ms.cmp(&current.announcement.ts_ms))
                == Ordering::Greater
        });
        if replace {
            best = Some(peer.clone());
        }
    }

    best
}

async fn sync_from_peer(
    config: &Config,
    artifact_key: &str,
    loader_root: &Path,
    update_dir: &Path,
    shared: Arc<LoaderSharedState>,
    threats: loader_threat::LoaderThreatHub,
    child: &mut ManagedChild,
    peer: &PeerPresence,
) -> Result<bool, Box<dyn Error>> {
    let Some(base_addr) = normalize_peer_transfer_addr(
        peer.announcement.transfer_addr.as_deref(),
        peer.source_addr.ip(),
    ) else {
        return Ok(false);
    };

    let fetched = match fetch_peer_core(
        &base_addr,
        artifact_key,
        config.loader.request_timeout_ms,
        &staging_dir_path(loader_root),
    )
    .await
    {
        Ok(fetched) => fetched,
        Err(err) => {
            if err.suspicious() {
                threats
                    .record_incident(LocalThreatIncident {
                        provider_agent_id: Some(peer.announcement.agent_id.clone()),
                        source_addr: Some(peer.source_addr.to_string()),
                        artifact_version: Some(peer.announcement.version.clone()),
                        artifact_blake3: Some(peer.announcement.blake3.clone()),
                        classification: "malformed_update".to_string(),
                        reason: format!("peer served malformed or unverifiable artifact: {err}"),
                        provider_risk: 0.60,
                        artifact_risk: 0.60,
                    })
                    .await;
            }
            return Err(std::io::Error::other(err.to_string()).into());
        }
    };

    if fetched.metadata.channel != UpdateChannel::Production {
        let _ = fs::remove_file(&fetched.staged_path).await;
        threats
            .record_incident(LocalThreatIncident {
                provider_agent_id: Some(peer.announcement.agent_id.clone()),
                source_addr: Some(peer.source_addr.to_string()),
                artifact_version: Some(fetched.metadata.version.clone()),
                artifact_blake3: Some(fetched.metadata.blake3.clone()),
                classification: "announcement_mismatch".to_string(),
                reason: format!(
                    "peer announced distributable production artifact but served {:?} channel",
                    fetched.metadata.channel
                ),
                provider_risk: 0.60,
                artifact_risk: 0.60,
            })
            .await;
        return Ok(false);
    }
    if compare_versions(
        &fetched.metadata.version,
        &shared
            .current
            .read()
            .await
            .as_ref()
            .map(|active| active.metadata.version.clone())
            .unwrap_or_default(),
    ) != Ordering::Greater
    {
        let _ = fs::remove_file(&fetched.staged_path).await;
        return Ok(false);
    }
    if fetched.metadata.version != peer.announcement.version
        || fetched.metadata.blake3 != peer.announcement.blake3
    {
        let _ = fs::remove_file(&fetched.staged_path).await;
        threats
            .record_incident(LocalThreatIncident {
                provider_agent_id: Some(peer.announcement.agent_id.clone()),
                source_addr: Some(peer.source_addr.to_string()),
                artifact_version: Some(fetched.metadata.version.clone()),
                artifact_blake3: Some(fetched.metadata.blake3.clone()),
                classification: "announcement_mismatch".to_string(),
                reason: format!(
                    "peer announcement {} / {} did not match fetched artifact {} / {}",
                    peer.announcement.version,
                    peer.announcement.blake3,
                    fetched.metadata.version,
                    fetched.metadata.blake3
                ),
                provider_risk: 0.75,
                artifact_risk: 0.75,
            })
            .await;
        return Err(
            std::io::Error::other("peer announcement did not match fetched core metadata").into(),
        );
    }

    apply_fetched_core(
        artifact_key,
        loader_root,
        update_dir,
        shared,
        threats,
        child,
        fetched,
        UpdateProvenance {
            source_kind: "loader-peer".to_string(),
            peer_agent_id: Some(peer.announcement.agent_id.clone()),
            peer_addr: Some(peer.source_addr.to_string()),
        },
        config.loader.handoff_timeout_ms,
    )
    .await?;
    Ok(true)
}

fn normalize_peer_transfer_addr(raw: Option<&str>, source_ip: IpAddr) -> Option<String> {
    let raw = raw?.trim();
    if raw.is_empty() {
        return None;
    }
    if raw.starts_with("http://") || raw.starts_with("https://") {
        return Some(raw.to_string());
    }
    if let Ok(addr) = raw.parse::<SocketAddr>() {
        let ip = if addr.ip().is_unspecified() {
            source_ip
        } else {
            addr.ip()
        };
        return Some(format!("http://{}", SocketAddr::new(ip, addr.port())));
    }
    Some(format!("http://{}", raw))
}

async fn fetch_peer_core(
    base_addr: &str,
    artifact_key: &str,
    timeout_ms: u64,
    staging_dir: &Path,
) -> Result<FetchedCore, PeerFetchError> {
    fs::create_dir_all(staging_dir)
        .await
        .map_err(|err| PeerFetchError::Transport(err.to_string()))?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        .build()
        .map_err(|err| PeerFetchError::Transport(err.to_string()))?;

    let metadata_url = join_loader_url(base_addr, LOADER_METADATA_ROUTE);
    let signature_url = join_loader_url(base_addr, LOADER_SIGNATURE_ROUTE);
    let bundle_url = join_loader_url(base_addr, LOADER_BUNDLE_ROUTE);

    let metadata_request = async {
        let response = client
            .get(&metadata_url)
            .send()
            .await
            .map_err(|err| PeerFetchError::Transport(err.to_string()))?;
        if !response.status().is_success() {
            return Err(PeerFetchError::Transport(format!(
                "metadata fetch failed with {}",
                response.status()
            )));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|err| PeerFetchError::Transport(err.to_string()))?;
        Ok::<Vec<u8>, PeerFetchError>(bytes.to_vec())
    };
    let signature_request = async {
        let response = client
            .get(&signature_url)
            .send()
            .await
            .map_err(|err| PeerFetchError::Transport(err.to_string()))?;
        if !response.status().is_success() {
            return Err(PeerFetchError::Transport(format!(
                "signature fetch failed with {}",
                response.status()
            )));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|err| PeerFetchError::Transport(err.to_string()))?;
        String::from_utf8(bytes.to_vec()).map_err(|err| {
            PeerFetchError::Verification(format!("signature body was not utf-8: {err}"))
        })
    };
    let bundle_request = async {
        let response = client
            .get(&bundle_url)
            .send()
            .await
            .map_err(|err| PeerFetchError::Transport(err.to_string()))?;
        if !response.status().is_success() {
            return Err(PeerFetchError::Transport(format!(
                "bundle fetch failed with {}",
                response.status()
            )));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|err| PeerFetchError::Transport(err.to_string()))?;
        Ok::<Vec<u8>, PeerFetchError>(bytes.to_vec())
    };

    let (metadata_bytes, signature, bundle_bytes) =
        tokio::try_join!(metadata_request, signature_request, bundle_request)?;
    let metadata = update::verify_signed_artifacts(
        &metadata_bytes,
        &bundle_bytes,
        signature.trim(),
        artifact_key,
    )
    .map_err(|err| PeerFetchError::Verification(err.to_string()))?;
    validate_local_metadata(&metadata)
        .map_err(|err| PeerFetchError::Verification(err.to_string()))?;

    let staged_path = staging_dir.join(format!(
        "tracey-core-{}-{}",
        metadata.version.replace('/', "_"),
        metadata.blake3,
    ));
    update::write_atomic(&staged_path, &bundle_bytes)
        .await
        .map_err(|err| PeerFetchError::Transport(err.to_string()))?;
    ensure_executable(&staged_path)
        .await
        .map_err(|err| PeerFetchError::Transport(err.to_string()))?;

    Ok(FetchedCore {
        staged_path,
        metadata,
        metadata_bytes,
        signature: signature.trim().to_string(),
    })
}

fn join_loader_url(base: &str, path: &str) -> String {
    let base = base.trim_end_matches('/');
    let path = path.trim_start_matches('/');
    format!("{}/{}", base, path)
}

async fn apply_supervisor_request(
    config: &Config,
    artifact_key: &str,
    loader_root: &Path,
    update_dir: &Path,
    shared: Arc<LoaderSharedState>,
    child: &mut ManagedChild,
    request: SupervisorRequest,
) -> Result<(), Box<dyn Error>> {
    let metadata = request
        .metadata()
        .ok_or_else(|| std::io::Error::other("supervisor request missing metadata"))?;
    if metadata.channel != config.update.local_channel {
        return Err(std::io::Error::other("supervisor request channel mismatch").into());
    }

    let bundle_path = PathBuf::from(&request.binary_path);
    let bundle_bytes = fs::read(&bundle_path).await?;
    let metadata_bytes = update::serialize_metadata(&metadata)?;
    let signature = if request.signature.trim().is_empty() {
        update::sign_metadata_bytes(&metadata_bytes, &bundle_bytes, artifact_key)
    } else {
        request.signature.trim().to_string()
    };
    update::verify_signed_artifacts(&metadata_bytes, &bundle_bytes, &signature, artifact_key)?;

    let fetched = FetchedCore {
        staged_path: bundle_path,
        metadata,
        metadata_bytes,
        signature,
    };
    let threats = shared.threats.clone();

    apply_fetched_core(
        artifact_key,
        loader_root,
        update_dir,
        shared,
        threats,
        child,
        fetched,
        UpdateProvenance {
            source_kind: "loader-handoff".to_string(),
            peer_agent_id: None,
            peer_addr: None,
        },
        config.loader.handoff_timeout_ms,
    )
    .await
}

async fn apply_fetched_core(
    artifact_key: &str,
    loader_root: &Path,
    update_dir: &Path,
    shared: Arc<LoaderSharedState>,
    threats: loader_threat::LoaderThreatHub,
    child: &mut ManagedChild,
    fetched: FetchedCore,
    provenance: UpdateProvenance,
    handoff_timeout_ms: u64,
) -> Result<(), Box<dyn Error>> {
    if shared.rollback_pending().await {
        return Err(
            std::io::Error::other("current core is still in rollback probation window").into(),
        );
    }
    let current_active = shared
        .current
        .read()
        .await
        .clone()
        .ok_or_else(|| std::io::Error::other("loader lost active core state"))?;
    let previous_backup = snapshot_current_for_rollback(loader_root, &current_active).await?;
    let staged_path = fetched.staged_path.clone();
    let staged_cleanup_path = staged_path.clone();
    let staged_version = fetched.metadata.version.clone();
    let staged_blake3 = fetched.metadata.blake3.clone();
    let staged_channel = fetched.metadata.channel.clone();
    let extra_env = vec![
        (
            "TRACEY_ACTIVE_CORE_VERSION".to_string(),
            fetched.metadata.version.clone(),
        ),
        (
            "TRACEY_ACTIVE_CORE_CHANNEL".to_string(),
            fetched.metadata.channel.to_string(),
        ),
    ];
    let mut new_child = match supervisor::perform_handoff_with_env(
        child,
        &fetched.staged_path,
        &[],
        update_dir,
        Duration::from_millis(handoff_timeout_ms),
        &extra_env,
        None,
        &provenance.source_kind,
    )
    .await
    {
        Ok(child) => child,
        Err(err) => {
            tokio::spawn(cleanup_staged_core(staged_cleanup_path.clone()));
            threats
                .record_incident(LocalThreatIncident {
                    provider_agent_id: provenance.peer_agent_id.clone(),
                    source_addr: provenance.peer_addr.clone(),
                    artifact_version: Some(staged_version.clone()),
                    artifact_blake3: Some(staged_blake3.clone()),
                    classification: "handoff_failure".to_string(),
                    reason: format!("activated core never became ready: {err}"),
                    provider_risk: if provenance.peer_agent_id.is_some() {
                        0.75
                    } else {
                        0.0
                    },
                    artifact_risk: 0.75,
                })
                .await;
            return Err(err.into());
        }
    };

    let promoted = match promote_fetched_core(loader_root, fetched).await {
        Ok(promoted) => promoted,
        Err(err) => {
            tracing::warn!(
                version = %staged_version,
                channel = %staged_channel,
                error = %err,
                "loader promotion failed after handoff; restoring previous stable core"
            );
            shutdown_child(&mut new_child).await;
            tokio::spawn(cleanup_staged_core(staged_path));
            let restored_active =
                restore_previous_core(loader_root, artifact_key, &previous_backup).await?;
            *shared.current.write().await = Some(restored_active.clone());
            *child = spawn_core_child(&restored_active, update_dir).await?;
            return Err(err.into());
        }
    };
    let promoted_bytes = fs::read(&promoted.binary_path).await?;
    update::verify_signed_artifacts(
        &promoted.metadata_bytes,
        &promoted_bytes,
        &promoted.signature,
        artifact_key,
    )?;

    let pending = PendingRollback {
        previous: previous_backup,
        marker: RollbackMarker {
            activated_ms: now_ms(),
            failed_version: promoted.metadata.version.clone(),
            failed_blake3: promoted.metadata.blake3.clone(),
            previous_version: current_active.metadata.version.clone(),
            previous_blake3: current_active.metadata.blake3.clone(),
            source_kind: Some(provenance.source_kind),
            source_peer_agent_id: provenance.peer_agent_id,
            source_peer_addr: provenance.peer_addr,
        },
    };
    if let Err(err) = write_rollback_marker(loader_root, &pending.marker).await {
        tracing::warn!(
            version = %promoted.metadata.version,
            error = %err,
            "failed to persist rollback marker; rollback will remain in-memory only"
        );
    }

    *shared.current.write().await = Some(promoted.clone());
    *shared.rollback.write().await = Some(pending);
    *child = new_child;
    tracing::info!(
        version = %promoted.metadata.version,
        channel = %promoted.metadata.channel,
        path = %promoted.binary_path.display(),
        "loader activated new tracey core"
    );
    Ok(())
}

async fn promote_fetched_core(
    loader_root: &Path,
    fetched: FetchedCore,
) -> Result<ActiveCore, Box<dyn Error>> {
    let current_binary = current_binary_path(loader_root);
    let current_metadata = current_metadata_path(loader_root);
    let current_signature = current_signature_path(loader_root);
    if let Some(parent) = current_binary.parent() {
        fs::create_dir_all(parent).await?;
    }

    if current_binary.exists() {
        let _ = fs::remove_file(&current_binary).await;
    }
    match fs::rename(&fetched.staged_path, &current_binary).await {
        Ok(()) => {}
        Err(_) => {
            fs::copy(&fetched.staged_path, &current_binary).await?;
            let _ = fs::remove_file(&fetched.staged_path).await;
        }
    }
    ensure_executable(&current_binary).await?;
    update::write_atomic(&current_metadata, &fetched.metadata_bytes).await?;
    update::write_atomic(&current_signature, fetched.signature.as_bytes()).await?;

    Ok(ActiveCore {
        binary_path: current_binary,
        metadata: fetched.metadata,
        metadata_bytes: fetched.metadata_bytes,
        signature: fetched.signature,
    })
}

fn compare_versions(left: &str, right: &str) -> Ordering {
    let left_nums = version_numbers(left);
    let right_nums = version_numbers(right);
    if !left_nums.is_empty() || !right_nums.is_empty() {
        for idx in 0..left_nums.len().max(right_nums.len()) {
            let left_part = left_nums.get(idx).copied().unwrap_or(0);
            let right_part = right_nums.get(idx).copied().unwrap_or(0);
            match left_part.cmp(&right_part) {
                Ordering::Equal => {}
                other => return other,
            }
        }
    }
    left.cmp(right)
}

fn version_numbers(value: &str) -> Vec<u64> {
    let mut parts = Vec::new();
    let mut current = String::new();
    for ch in value.chars() {
        if ch.is_ascii_digit() {
            current.push(ch);
        } else if !current.is_empty() {
            if let Ok(number) = current.parse::<u64>() {
                parts.push(number);
            }
            current.clear();
        }
    }
    if !current.is_empty() {
        if let Ok(number) = current.parse::<u64>() {
            parts.push(number);
        }
    }
    parts
}

#[cfg(unix)]
async fn ensure_executable(path: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = fs::metadata(path).await?.permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).await
}

#[cfg(not(unix))]
async fn ensure_executable(_path: &Path) -> Result<(), std::io::Error> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::update;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::sync::RwLock;

    #[test]
    fn compare_versions_prefers_numeric_segments() {
        assert_eq!(compare_versions("1.10.0", "1.2.0"), Ordering::Greater);
        assert_eq!(compare_versions("2.0.0", "2.0.0"), Ordering::Equal);
        assert_eq!(compare_versions("0.9.9", "1.0.0"), Ordering::Less);
    }

    #[test]
    fn normalize_peer_transfer_addr_replaces_unspecified_host() {
        let addr =
            normalize_peer_transfer_addr(Some("0.0.0.0:47988"), "192.0.2.10".parse().unwrap())
                .expect("addr should normalize");
        assert_eq!(addr, "http://192.0.2.10:47988");
    }

    #[test]
    fn rollback_marker_expiry_uses_window_boundary() {
        let marker = RollbackMarker {
            activated_ms: 1_000,
            failed_version: "2.0.0".to_string(),
            failed_blake3: "deadbeef".to_string(),
            previous_version: "1.9.0".to_string(),
            previous_blake3: "feedface".to_string(),
            source_kind: None,
            source_peer_agent_id: None,
            source_peer_addr: None,
        };

        assert!(!rollback_marker_expired(&marker, 5_000, 6_000));
        assert!(rollback_marker_expired(&marker, 5_000, 6_001));
    }

    #[tokio::test]
    async fn load_pending_rollback_restores_persisted_previous_core() {
        let loader_root = unique_test_dir("persisted-rollback");
        let _ = fs::remove_dir_all(&loader_root).await;
        fs::create_dir_all(current_binary_path(&loader_root).parent().unwrap())
            .await
            .expect("current dir should exist");
        fs::create_dir_all(rollback_binary_path(&loader_root).parent().unwrap())
            .await
            .expect("rollback dir should exist");

        let key = "loader-test-key";
        let current = write_signed_core(
            &current_binary_path(&loader_root),
            &current_metadata_path(&loader_root),
            &current_signature_path(&loader_root),
            "2.0.0",
            key,
        )
        .await;
        let previous = write_signed_core(
            &rollback_binary_path(&loader_root),
            &rollback_metadata_path(&loader_root),
            &rollback_signature_path(&loader_root),
            "1.9.0",
            key,
        )
        .await;
        let marker = RollbackMarker {
            activated_ms: now_ms(),
            failed_version: current.metadata.version.clone(),
            failed_blake3: current.metadata.blake3.clone(),
            previous_version: previous.metadata.version.clone(),
            previous_blake3: previous.metadata.blake3.clone(),
            source_kind: None,
            source_peer_agent_id: None,
            source_peer_addr: None,
        };
        write_rollback_marker(&loader_root, &marker)
            .await
            .expect("rollback marker should persist");

        let pending = load_pending_rollback(&loader_root, key, &current, 60_000)
            .await
            .expect("rollback state should load")
            .expect("rollback state should be present");

        assert_eq!(pending.marker.failed_version, "2.0.0");
        assert_eq!(pending.previous.metadata.version, "1.9.0");

        let _ = fs::remove_dir_all(&loader_root).await;
    }

    #[tokio::test]
    async fn rollback_after_crash_restores_previous_core_and_clears_marker() {
        let loader_root = unique_test_dir("crash-rollback");
        let _ = fs::remove_dir_all(&loader_root).await;
        fs::create_dir_all(current_binary_path(&loader_root).parent().unwrap())
            .await
            .expect("current dir should exist");
        fs::create_dir_all(rollback_binary_path(&loader_root).parent().unwrap())
            .await
            .expect("rollback dir should exist");

        let key = "loader-test-key";
        let current = write_signed_core(
            &current_binary_path(&loader_root),
            &current_metadata_path(&loader_root),
            &current_signature_path(&loader_root),
            "3.0.0",
            key,
        )
        .await;
        let previous = write_signed_core(
            &rollback_binary_path(&loader_root),
            &rollback_metadata_path(&loader_root),
            &rollback_signature_path(&loader_root),
            "2.9.0",
            key,
        )
        .await;
        let failed_bytes = fs::read(&current.binary_path)
            .await
            .expect("failed bundle should be readable");
        let marker = RollbackMarker {
            activated_ms: now_ms(),
            failed_version: current.metadata.version.clone(),
            failed_blake3: current.metadata.blake3.clone(),
            previous_version: previous.metadata.version.clone(),
            previous_blake3: previous.metadata.blake3.clone(),
            source_kind: None,
            source_peer_agent_id: None,
            source_peer_addr: None,
        };
        write_rollback_marker(&loader_root, &marker)
            .await
            .expect("rollback marker should persist");

        let shared = Arc::new(LoaderSharedState {
            agent_id: "agent-a".to_string(),
            policy_channel: update::UpdateChannel::Production,
            transfer_advertise_addr: "http://127.0.0.1:47988".to_string(),
            current: Arc::new(RwLock::new(Some(current.clone()))),
            rollback: Arc::new(RwLock::new(Some(PendingRollback {
                previous: previous.clone(),
                marker: marker.clone(),
            }))),
            threats: loader_threat::LoaderThreatHub::from_config(&LoaderConfig {
                state_dir: loader_root.clone(),
                ..LoaderConfig::default()
            })
            .await
            .expect("loader threat hub should initialize"),
        });

        let restored = rollback_after_crash(&loader_root, key, shared.clone(), 60_000)
            .await
            .expect("rollback should succeed")
            .expect("rollback should restore previous core");

        assert_eq!(restored.metadata.version, "2.9.0");
        assert!(shared.rollback.read().await.is_none());
        assert!(!rollback_state_path(&loader_root).exists());

        let current_reloaded = load_active_core_from_paths(
            &current_binary_path(&loader_root),
            &current_metadata_path(&loader_root),
            &current_signature_path(&loader_root),
            key,
        )
        .await
        .expect("restored core should verify");
        assert_eq!(current_reloaded.metadata.version, "2.9.0");

        let active = shared
            .current
            .read()
            .await
            .clone()
            .expect("shared state should retain active core");
        assert_eq!(active.metadata.version, "2.9.0");

        let archive_stem = format!(
            "failed-{}-{}",
            current.metadata.version.replace('/', "_"),
            current.metadata.blake3
        );
        let archived = fs::read(staging_dir_path(&loader_root).join(&archive_stem))
            .await
            .expect("failed core archive should exist");
        assert_eq!(archived, failed_bytes);

        let _ = fs::remove_dir_all(&loader_root).await;
    }

    #[tokio::test]
    async fn rollback_after_crash_marks_peer_source_as_blocked() {
        let loader_root = unique_test_dir("crash-rollback-threats");
        let _ = fs::remove_dir_all(&loader_root).await;
        fs::create_dir_all(current_binary_path(&loader_root).parent().unwrap())
            .await
            .expect("current dir should exist");
        fs::create_dir_all(rollback_binary_path(&loader_root).parent().unwrap())
            .await
            .expect("rollback dir should exist");

        let key = "loader-test-key";
        let current = write_signed_core(
            &current_binary_path(&loader_root),
            &current_metadata_path(&loader_root),
            &current_signature_path(&loader_root),
            "4.0.0",
            key,
        )
        .await;
        let previous = write_signed_core(
            &rollback_binary_path(&loader_root),
            &rollback_metadata_path(&loader_root),
            &rollback_signature_path(&loader_root),
            "3.9.0",
            key,
        )
        .await;
        let marker = RollbackMarker {
            activated_ms: now_ms(),
            failed_version: current.metadata.version.clone(),
            failed_blake3: current.metadata.blake3.clone(),
            previous_version: previous.metadata.version.clone(),
            previous_blake3: previous.metadata.blake3.clone(),
            source_kind: Some("loader-peer".to_string()),
            source_peer_agent_id: Some("peer-malicious".to_string()),
            source_peer_addr: Some("10.0.0.7:47988".to_string()),
        };
        write_rollback_marker(&loader_root, &marker)
            .await
            .expect("rollback marker should persist");

        let threats = loader_threat::LoaderThreatHub::from_config(&LoaderConfig {
            state_dir: loader_root.clone(),
            ..LoaderConfig::default()
        })
        .await
        .expect("loader threat hub should initialize");
        let shared = Arc::new(LoaderSharedState {
            agent_id: "agent-a".to_string(),
            policy_channel: update::UpdateChannel::Production,
            transfer_advertise_addr: "http://127.0.0.1:47988".to_string(),
            current: Arc::new(RwLock::new(Some(current.clone()))),
            rollback: Arc::new(RwLock::new(Some(PendingRollback {
                previous: previous.clone(),
                marker: marker.clone(),
            }))),
            threats: threats.clone(),
        });

        let restored = rollback_after_crash(&loader_root, key, shared.clone(), 60_000)
            .await
            .expect("rollback should succeed")
            .expect("rollback should restore previous core");

        assert_eq!(restored.metadata.version, "3.9.0");
        let provider = threats.provider_assessment("peer-malicious").await;
        let artifact = threats
            .artifact_assessment(&current.metadata.version, &current.metadata.blake3)
            .await;
        assert!(provider.recommended_block);
        assert!(artifact.recommended_block);

        let _ = fs::remove_dir_all(&loader_root).await;
    }

    #[tokio::test]
    async fn choose_best_peer_skips_blocklisted_provider() {
        let loader_root = unique_test_dir("choose-peer-threats");
        let _ = fs::remove_dir_all(&loader_root).await;
        fs::create_dir_all(current_binary_path(&loader_root).parent().unwrap())
            .await
            .expect("current dir should exist");

        let key = "loader-test-key";
        let current = write_signed_core(
            &current_binary_path(&loader_root),
            &current_metadata_path(&loader_root),
            &current_signature_path(&loader_root),
            "1.0.0",
            key,
        )
        .await;
        let threats = loader_threat::LoaderThreatHub::from_config(&LoaderConfig {
            state_dir: loader_root.clone(),
            ..LoaderConfig::default()
        })
        .await
        .expect("loader threat hub should initialize");
        threats
            .record_incident(LocalThreatIncident {
                provider_agent_id: Some("peer-bad".to_string()),
                source_addr: Some("10.0.0.9:47988".to_string()),
                artifact_version: Some("3.0.0".to_string()),
                artifact_blake3: Some("bb".repeat(32)),
                classification: "malformed_update".to_string(),
                reason: "served malformed artifact".to_string(),
                provider_risk: 1.0,
                artifact_risk: 1.0,
            })
            .await;

        let shared = Arc::new(LoaderSharedState {
            agent_id: "agent-a".to_string(),
            policy_channel: update::UpdateChannel::Production,
            transfer_advertise_addr: "http://127.0.0.1:47988".to_string(),
            current: Arc::new(RwLock::new(Some(current.clone()))),
            rollback: Arc::new(RwLock::new(None)),
            threats: threats.clone(),
        });

        let mut peers = HashMap::new();
        peers.insert(
            "peer-bad".to_string(),
            PeerPresence {
                announcement: LoaderAnnouncement {
                    agent_id: "peer-bad".to_string(),
                    ts_ms: now_ms(),
                    os: std::env::consts::OS.to_string(),
                    arch: std::env::consts::ARCH.to_string(),
                    version: "3.0.0".to_string(),
                    blake3: "bb".repeat(32),
                    channel: UpdateChannel::Production,
                    distributable: true,
                    transfer_addr: Some("http://10.0.0.9:47988".to_string()),
                    signature: String::new(),
                },
                source_addr: "10.0.0.9:47989".parse().expect("source addr should parse"),
            },
        );
        peers.insert(
            "peer-good".to_string(),
            PeerPresence {
                announcement: LoaderAnnouncement {
                    agent_id: "peer-good".to_string(),
                    ts_ms: now_ms(),
                    os: std::env::consts::OS.to_string(),
                    arch: std::env::consts::ARCH.to_string(),
                    version: "2.0.0".to_string(),
                    blake3: "cc".repeat(32),
                    channel: UpdateChannel::Production,
                    distributable: true,
                    transfer_addr: Some("http://10.0.0.10:47988".to_string()),
                    signature: String::new(),
                },
                source_addr: "10.0.0.10:47989".parse().expect("source addr should parse"),
            },
        );

        let selected = choose_best_peer(&peers, shared, threats, 60_000)
            .await
            .expect("a safe peer should be selected");
        assert_eq!(selected.announcement.agent_id, "peer-good");

        let _ = fs::remove_dir_all(&loader_root).await;
    }

    #[test]
    fn fuzzy_loader_parser_recovers_wrapped_payload() {
        let announcement = LoaderAnnouncement {
            agent_id: "peer-loader".to_string(),
            ts_ms: 77,
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            version: "2.4.6".to_string(),
            blake3: "ab".repeat(32),
            channel: UpdateChannel::Production,
            distributable: true,
            transfer_addr: Some("http://10.0.0.42:47988".to_string()),
            signature: String::new(),
        };
        let signature = sign_loader_announcement(&announcement, "shared-key");
        let payload = serde_json::json!({
            "wrapper": {
                "announcement": {
                    "agentId": "peer-loader",
                    "timestamp_ms": "77",
                    "platform": std::env::consts::OS,
                    "architecture": std::env::consts::ARCH,
                    "buildVersion": "2.4.6",
                    "digest": "ab".repeat(32),
                    "release_channel": "prod",
                    "production_ready": "true",
                    "transferAddr": "http://10.0.0.42:47988",
                    "sig": signature
                }
            }
        })
        .to_string();

        let (parsed, affinity) =
            parse_loader_announcement_lossy(payload.as_bytes()).expect("payload should recover");

        assert!(affinity >= 3.0);
        assert_eq!(parsed.agent_id, "peer-loader");
        assert_eq!(parsed.version, "2.4.6");
        assert!(parsed.distributable);
        assert_eq!(
            parsed.transfer_addr.as_deref(),
            Some("http://10.0.0.42:47988")
        );
        assert!(verify_loader_announcement_signature(&parsed, "shared-key"));
    }

    #[test]
    fn loader_signature_accepts_legacy_formats() {
        let mut announcement = LoaderAnnouncement {
            agent_id: "peer-loader".to_string(),
            ts_ms: 77,
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            version: "2.4.6".to_string(),
            blake3: "ab".repeat(32),
            channel: UpdateChannel::Production,
            distributable: true,
            transfer_addr: Some("http://10.0.0.42:47988".to_string()),
            signature: String::new(),
        };
        announcement.signature = sign_loader_announcement_legacy(&announcement, "shared-key", true);
        assert!(verify_loader_announcement_signature(
            &announcement,
            "shared-key"
        ));

        announcement.signature =
            sign_loader_announcement_legacy(&announcement, "shared-key", false);
        assert!(verify_loader_announcement_signature(
            &announcement,
            "shared-key"
        ));
    }

    fn unique_test_dir(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "tracey-loader-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    async fn write_signed_core(
        binary_path: &Path,
        metadata_path: &Path,
        signature_path: &Path,
        version: &str,
        key: &str,
    ) -> ActiveCore {
        let bundle_bytes = format!("#!/bin/sh\n# tracey {version}\nexit 0\n").into_bytes();
        if let Some(parent) = binary_path.parent() {
            fs::create_dir_all(parent)
                .await
                .expect("binary parent dir should exist");
        }
        update::write_atomic(binary_path, &bundle_bytes)
            .await
            .expect("binary should persist");
        ensure_executable(binary_path)
            .await
            .expect("binary should be executable");
        let metadata = update::build_metadata(
            version,
            std::env::consts::OS,
            std::env::consts::ARCH,
            &bundle_bytes,
            update::UpdateChannel::Production,
        );
        let metadata_bytes =
            update::serialize_metadata(&metadata).expect("metadata should serialize");
        let signature = update::sign_metadata_bytes(&metadata_bytes, &bundle_bytes, key);
        update::write_atomic(metadata_path, &metadata_bytes)
            .await
            .expect("metadata should persist");
        update::write_atomic(signature_path, signature.as_bytes())
            .await
            .expect("signature should persist");

        ActiveCore {
            binary_path: binary_path.to_path_buf(),
            metadata,
            metadata_bytes,
            signature,
        }
    }
}
