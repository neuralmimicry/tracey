use crate::config::LoaderConfig;
use crate::event::now_ms;
use crate::peer_compat::{self, SchemaField};
use crate::update;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tokio::sync::RwLock;

const LOADER_THREAT_STATE: &str = "tracey-loader.threats.state.json";
const LOADER_THREAT_SNAPSHOT: &str = "tracey-loader.threats.snapshot.json";
const MAX_FUTURE_SKEW_MS: u64 = 30_000;
const PROVIDER_BLOCK_THRESHOLD: f64 = 0.60;
const ARTIFACT_BLOCK_THRESHOLD: f64 = 0.60;
const REMOTE_BLOCK_THRESHOLD: f64 = 0.60;
const REMOTE_REPORTER_BLOCK_QUORUM: usize = 2;
const SNAPSHOT_ENTRY_LIMIT: usize = 8;
const MAX_REASON_LEN: usize = 160;
const MAX_CLASSIFICATION_LEN: usize = 64;
const MAX_ID_LEN: usize = 128;
const MAX_ADDR_LEN: usize = 256;
const MAX_VERSION_LEN: usize = 96;
const MAX_DIGEST_LEN: usize = 128;
const MAX_PERSISTED_LOCAL_ENTRIES: usize = 64;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct LoaderThreatProviderEntry {
    pub provider_agent_id: String,
    #[serde(default)]
    pub last_source_addr: Option<String>,
    pub risk: f64,
    pub evidence_count: u64,
    pub last_event_ms: u64,
    pub last_reason: String,
    #[serde(default)]
    pub last_classification: String,
    #[serde(default)]
    pub related_version: Option<String>,
    #[serde(default)]
    pub related_blake3: Option<String>,
    #[serde(default)]
    pub reporter_count: usize,
    #[serde(default)]
    pub recommended_block: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct LoaderThreatArtifactEntry {
    pub version: String,
    pub blake3: String,
    pub risk: f64,
    pub evidence_count: u64,
    pub last_event_ms: u64,
    pub last_reason: String,
    #[serde(default)]
    pub last_classification: String,
    #[serde(default)]
    pub source_provider_agent_id: Option<String>,
    #[serde(default)]
    pub reporter_count: usize,
    #[serde(default)]
    pub recommended_block: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct LoaderThreatSummary {
    pub local_provider_count: usize,
    pub local_artifact_count: usize,
    pub remote_provider_count: usize,
    pub remote_artifact_count: usize,
    pub remote_reporters: usize,
    pub blocked_provider_count: usize,
    pub blocked_artifact_count: usize,
    pub highest_provider_risk: f64,
    pub highest_artifact_risk: f64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct LoaderThreatSnapshot {
    pub ts_ms: u64,
    pub summary: LoaderThreatSummary,
    #[serde(default)]
    pub local_providers: Vec<LoaderThreatProviderEntry>,
    #[serde(default)]
    pub local_artifacts: Vec<LoaderThreatArtifactEntry>,
    #[serde(default)]
    pub remote_providers: Vec<LoaderThreatProviderEntry>,
    #[serde(default)]
    pub remote_artifacts: Vec<LoaderThreatArtifactEntry>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct LoaderThreatAnnouncement {
    pub agent_id: String,
    pub ts_ms: u64,
    pub epoch: u64,
    #[serde(default)]
    pub providers: Vec<LoaderThreatProviderEntry>,
    #[serde(default)]
    pub artifacts: Vec<LoaderThreatArtifactEntry>,
    pub signature: String,
}

#[derive(Clone, Debug, Default)]
pub struct LoaderThreatAssessment {
    pub local_risk: f64,
    pub remote_risk: f64,
    pub remote_reporters: usize,
    pub recommended_block: bool,
}

#[derive(Clone, Debug, Default)]
pub struct LocalThreatIncident {
    pub provider_agent_id: Option<String>,
    pub source_addr: Option<String>,
    pub artifact_version: Option<String>,
    pub artifact_blake3: Option<String>,
    pub classification: String,
    pub reason: String,
    pub provider_risk: f64,
    pub artifact_risk: f64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct PersistedLoaderThreatState {
    version: u8,
    epoch: u64,
    #[serde(default)]
    providers: Vec<LoaderThreatProviderEntry>,
    #[serde(default)]
    artifacts: Vec<LoaderThreatArtifactEntry>,
}

#[derive(Clone, Debug)]
struct RemoteThreatRecord {
    ts_ms: u64,
    providers: Vec<LoaderThreatProviderEntry>,
    artifacts: Vec<LoaderThreatArtifactEntry>,
}

#[derive(Default)]
struct LoaderThreatState {
    epoch: u64,
    local_providers: HashMap<String, LoaderThreatProviderEntry>,
    local_artifacts: HashMap<String, LoaderThreatArtifactEntry>,
    remote: HashMap<String, RemoteThreatRecord>,
    remote_ttl_ms: u64,
}

#[derive(Clone)]
pub struct LoaderThreatHub {
    state: Arc<RwLock<LoaderThreatState>>,
    state_path: PathBuf,
    snapshot_path: PathBuf,
}

#[derive(Clone)]
pub struct LoaderThreatStatusHandle {
    snapshot_path: PathBuf,
}

impl LoaderThreatStatusHandle {
    pub fn from_config(config: &LoaderConfig) -> Result<Self, std::io::Error> {
        let root = resolve_loader_root(config)?;
        Ok(Self {
            snapshot_path: threat_snapshot_path(&root),
        })
    }

    pub async fn snapshot(&self) -> Option<LoaderThreatSnapshot> {
        if !self.snapshot_path.exists() {
            return None;
        }
        let raw = fs::read(&self.snapshot_path).await.ok()?;
        match serde_json::from_slice::<LoaderThreatSnapshot>(&raw) {
            Ok(snapshot) => Some(snapshot),
            Err(err) => {
                tracing::warn!(
                    path = %self.snapshot_path.display(),
                    error = %err,
                    "loader threat snapshot was malformed; ignoring"
                );
                None
            }
        }
    }
}

impl LoaderThreatHub {
    pub async fn from_config(config: &LoaderConfig) -> Result<Self, Box<dyn Error>> {
        let root = resolve_loader_root(config)?;
        let state_path = threat_state_path(&root);
        let snapshot_path = threat_snapshot_path(&root);
        let persisted = load_persisted_state(&state_path).await;
        let mut state = LoaderThreatState {
            epoch: persisted.as_ref().map(|state| state.epoch).unwrap_or(0),
            local_providers: HashMap::new(),
            local_artifacts: HashMap::new(),
            remote: HashMap::new(),
            remote_ttl_ms: config.ttl_ms.max(1_000),
        };

        if let Some(persisted) = persisted {
            for entry in persisted
                .providers
                .into_iter()
                .filter_map(sanitize_provider_entry)
            {
                state
                    .local_providers
                    .insert(entry.provider_agent_id.clone(), entry);
            }
            for entry in persisted
                .artifacts
                .into_iter()
                .filter_map(sanitize_artifact_entry)
            {
                state
                    .local_artifacts
                    .insert(make_artifact_key(&entry.version, &entry.blake3), entry);
            }
        }

        let hub = Self {
            state: Arc::new(RwLock::new(state)),
            state_path,
            snapshot_path,
        };
        hub.persist().await;
        Ok(hub)
    }

    pub fn status_handle(&self) -> LoaderThreatStatusHandle {
        LoaderThreatStatusHandle {
            snapshot_path: self.snapshot_path.clone(),
        }
    }

    pub async fn record_incident(&self, incident: LocalThreatIncident) {
        let (persisted, snapshot) = {
            let mut state = self.state.write().await;
            cleanup_state(&mut state, now_ms());

            let classification = sanitize_text(&incident.classification, MAX_CLASSIFICATION_LEN)
                .unwrap_or_else(|| "malformed_update".to_string());
            let reason = sanitize_text(&incident.reason, MAX_REASON_LEN)
                .unwrap_or_else(|| "suspicious loader update detected".to_string());
            let provider_risk = incident.provider_risk.clamp(0.0, 1.0);
            let artifact_risk = incident.artifact_risk.clamp(0.0, 1.0);
            let provider_agent_id = sanitize_text_option(incident.provider_agent_id, MAX_ID_LEN);
            let artifact_version = sanitize_text_option(incident.artifact_version, MAX_VERSION_LEN);
            let artifact_blake3 = sanitize_text_option(incident.artifact_blake3, MAX_DIGEST_LEN);
            let source_addr = sanitize_text_option(incident.source_addr, MAX_ADDR_LEN);
            let event_ms = now_ms();

            if let Some(provider_agent_id) = provider_agent_id.clone()
                && provider_risk > 0.0
            {
                state.epoch = state.epoch.saturating_add(1);
                let entry = state
                    .local_providers
                    .entry(provider_agent_id.clone())
                    .or_insert_with(|| LoaderThreatProviderEntry {
                        provider_agent_id,
                        reporter_count: 1,
                        ..LoaderThreatProviderEntry::default()
                    });
                entry.risk = (entry.risk + provider_risk).clamp(0.0, 1.0);
                entry.evidence_count = entry.evidence_count.saturating_add(1);
                entry.last_event_ms = event_ms;
                entry.last_reason = reason.clone();
                entry.last_classification = classification.clone();
                entry.last_source_addr = source_addr.clone();
                entry.related_version = artifact_version.clone();
                entry.related_blake3 = artifact_blake3.clone();
                entry.reporter_count = 1;
                entry.recommended_block = entry.risk >= PROVIDER_BLOCK_THRESHOLD;
            }

            if let (Some(version), Some(blake3)) =
                (artifact_version.clone(), artifact_blake3.clone())
                && artifact_risk > 0.0
            {
                let key = make_artifact_key(&version, &blake3);
                state.epoch = state.epoch.saturating_add(1);
                let entry =
                    state
                        .local_artifacts
                        .entry(key)
                        .or_insert_with(|| LoaderThreatArtifactEntry {
                            version,
                            blake3,
                            reporter_count: 1,
                            ..LoaderThreatArtifactEntry::default()
                        });
                entry.risk = (entry.risk + artifact_risk).clamp(0.0, 1.0);
                entry.evidence_count = entry.evidence_count.saturating_add(1);
                entry.last_event_ms = event_ms;
                entry.last_reason = reason;
                entry.last_classification = classification;
                entry.reporter_count = 1;
                entry.source_provider_agent_id = provider_agent_id;
                entry.recommended_block = entry.risk >= ARTIFACT_BLOCK_THRESHOLD;
            }

            let persisted = persisted_from_state(&state);
            let snapshot = snapshot_from_state(&state, SNAPSHOT_ENTRY_LIMIT, now_ms());
            (persisted, snapshot)
        };
        persist_payloads(&self.state_path, &self.snapshot_path, &persisted, &snapshot).await;
    }

    pub async fn provider_assessment(&self, provider_agent_id: &str) -> LoaderThreatAssessment {
        let mut state = self.state.write().await;
        cleanup_state(&mut state, now_ms());
        provider_assessment_locked(&state, provider_agent_id)
    }

    pub async fn artifact_assessment(&self, version: &str, blake3: &str) -> LoaderThreatAssessment {
        let mut state = self.state.write().await;
        cleanup_state(&mut state, now_ms());
        artifact_assessment_locked(&state, version, blake3)
    }

    pub async fn build_announcement(
        &self,
        agent_id: &str,
        gossip_key: &str,
        max_entries: usize,
    ) -> Option<LoaderThreatAnnouncement> {
        let max_entries = max_entries.max(1);
        let mut state = self.state.write().await;
        cleanup_state(&mut state, now_ms());
        if state.epoch == 0
            || (state.local_providers.is_empty() && state.local_artifacts.is_empty())
        {
            return None;
        }

        let mut providers: Vec<_> = state.local_providers.values().cloned().collect();
        providers.sort_by(|left, right| {
            right
                .risk
                .partial_cmp(&left.risk)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| right.last_event_ms.cmp(&left.last_event_ms))
        });
        if providers.len() > max_entries {
            providers.truncate(max_entries);
        }

        let mut artifacts: Vec<_> = state.local_artifacts.values().cloned().collect();
        artifacts.sort_by(|left, right| {
            right
                .risk
                .partial_cmp(&left.risk)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| right.last_event_ms.cmp(&left.last_event_ms))
        });
        if artifacts.len() > max_entries {
            artifacts.truncate(max_entries);
        }

        let mut announcement = LoaderThreatAnnouncement {
            agent_id: agent_id.to_string(),
            ts_ms: now_ms(),
            epoch: state.epoch,
            providers,
            artifacts,
            signature: String::new(),
        };
        announcement.signature = sign_loader_threat_announcement(&announcement, gossip_key);
        Some(announcement)
    }

    pub async fn ingest_remote(&self, announcement: LoaderThreatAnnouncement) {
        let (persisted, snapshot) = {
            let mut state = self.state.write().await;
            cleanup_state(&mut state, now_ms());
            let providers = announcement
                .providers
                .into_iter()
                .filter_map(sanitize_provider_entry)
                .collect::<Vec<_>>();
            let artifacts = announcement
                .artifacts
                .into_iter()
                .filter_map(sanitize_artifact_entry)
                .collect::<Vec<_>>();
            state.remote.insert(
                announcement.agent_id,
                RemoteThreatRecord {
                    ts_ms: announcement.ts_ms,
                    providers,
                    artifacts,
                },
            );
            let persisted = persisted_from_state(&state);
            let snapshot = snapshot_from_state(&state, SNAPSHOT_ENTRY_LIMIT, now_ms());
            (persisted, snapshot)
        };
        persist_payloads(&self.state_path, &self.snapshot_path, &persisted, &snapshot).await;
    }

    pub async fn snapshot(&self, max_entries: usize) -> LoaderThreatSnapshot {
        let mut state = self.state.write().await;
        cleanup_state(&mut state, now_ms());
        snapshot_from_state(&state, max_entries.max(1), now_ms())
    }

    pub async fn persist(&self) {
        let (persisted, snapshot) = {
            let mut state = self.state.write().await;
            cleanup_state(&mut state, now_ms());
            let persisted = persisted_from_state(&state);
            let snapshot = snapshot_from_state(&state, SNAPSHOT_ENTRY_LIMIT, now_ms());
            (persisted, snapshot)
        };
        persist_payloads(&self.state_path, &self.snapshot_path, &persisted, &snapshot).await;
    }
}

pub fn validate_loader_threat_announcement(
    announcement: &LoaderThreatAnnouncement,
    gossip_key: &str,
    ttl_ms: u64,
) -> Result<(), Box<dyn Error>> {
    if announcement.agent_id.trim().is_empty() {
        return Err(std::io::Error::other("loader threat announcement missing agent_id").into());
    }
    if !verify_loader_threat_announcement_signature(announcement, gossip_key) {
        return Err(std::io::Error::other("loader threat announcement signature mismatch").into());
    }
    let now = now_ms();
    if announcement.ts_ms > now.saturating_add(MAX_FUTURE_SKEW_MS) {
        return Err(std::io::Error::other(
            "loader threat announcement timestamp too far in future",
        )
        .into());
    }
    if now.saturating_sub(announcement.ts_ms) > ttl_ms {
        return Err(std::io::Error::other("loader threat announcement expired").into());
    }
    Ok(())
}

pub fn parse_loader_threat_announcement_lossy(
    payload: &[u8],
) -> Result<(LoaderThreatAnnouncement, f64), String> {
    let root = peer_compat::parse_bytes(payload).map_err(|err| err.to_string())?;
    let fields = [
        SchemaField {
            aliases: &["agent_id", "agentId", "reporter", "node_id", "nodeId"],
            required: true,
            weight: 2.0,
        },
        SchemaField {
            aliases: &["ts_ms", "timestamp_ms", "timestamp", "updated_ms"],
            required: true,
            weight: 1.5,
        },
        SchemaField {
            aliases: &["signature", "sig", "mac"],
            required: true,
            weight: 2.0,
        },
        SchemaField {
            aliases: &["providers", "provider_reports", "provider_intel"],
            required: false,
            weight: 1.0,
        },
        SchemaField {
            aliases: &["artifacts", "artifact_reports", "artifact_intel"],
            required: false,
            weight: 1.0,
        },
    ];
    let matched = peer_compat::best_object(&root, &fields, 3.0, 3)
        .ok_or_else(|| "payload did not resemble a loader threat announcement".to_string())?;
    let map = matched.map;
    let providers =
        peer_compat::array_for(map, &["providers", "provider_reports", "provider_intel"])
            .map(|items| {
                items
                    .into_iter()
                    .filter_map(|item| parse_provider_entry_lossy(&item))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
    let artifacts =
        peer_compat::array_for(map, &["artifacts", "artifact_reports", "artifact_intel"])
            .map(|items| {
                items
                    .into_iter()
                    .filter_map(|item| parse_artifact_entry_lossy(&item))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
    if providers.is_empty() && artifacts.is_empty() {
        return Err("loader threat announcement did not contain threat entries".to_string());
    }

    Ok((
        LoaderThreatAnnouncement {
            agent_id: peer_compat::value_for(
                map,
                &["agent_id", "agentId", "reporter", "node_id", "nodeId"],
            )
            .and_then(peer_compat::coerce_string)
            .ok_or_else(|| "missing agent identifier".to_string())?,
            ts_ms: peer_compat::value_for(
                map,
                &["ts_ms", "timestamp_ms", "timestamp", "updated_ms"],
            )
            .and_then(peer_compat::coerce_u64)
            .ok_or_else(|| "missing timestamp".to_string())?,
            epoch: peer_compat::value_for(map, &["epoch", "version", "generation"])
                .and_then(peer_compat::coerce_u64)
                .unwrap_or(0),
            providers,
            artifacts,
            signature: peer_compat::value_for(map, &["signature", "sig", "mac"])
                .and_then(peer_compat::coerce_string)
                .ok_or_else(|| "missing signature".to_string())?,
        },
        matched.score,
    ))
}

pub fn sign_loader_threat_announcement(
    announcement: &LoaderThreatAnnouncement,
    gossip_key: &str,
) -> String {
    let key = update::derive_key(gossip_key);
    let provider_digest = serde_json::to_vec(&announcement.providers)
        .ok()
        .map(|payload| blake3::hash(&payload).to_hex().to_string())
        .unwrap_or_default();
    let artifact_digest = serde_json::to_vec(&announcement.artifacts)
        .ok()
        .map(|payload| blake3::hash(&payload).to_hex().to_string())
        .unwrap_or_default();
    let payload = serde_json::to_vec(&(
        &announcement.agent_id,
        announcement.ts_ms,
        announcement.epoch,
        provider_digest,
        artifact_digest,
    ))
    .unwrap_or_default();
    let mut hasher = blake3::Hasher::new_keyed(&key);
    hasher.update(&payload);
    update::to_hex(hasher.finalize().as_bytes())
}

pub fn verify_loader_threat_announcement_signature(
    announcement: &LoaderThreatAnnouncement,
    gossip_key: &str,
) -> bool {
    let expected = sign_loader_threat_announcement(announcement, gossip_key);
    update::constant_time_eq(&announcement.signature, &expected)
}

fn resolve_loader_root(config: &LoaderConfig) -> Result<PathBuf, std::io::Error> {
    if config.state_dir.is_absolute() {
        return Ok(config.state_dir.clone());
    }
    Ok(std::env::current_dir()?.join(&config.state_dir))
}

fn threat_state_path(root: &Path) -> PathBuf {
    root.join(LOADER_THREAT_STATE)
}

fn threat_snapshot_path(root: &Path) -> PathBuf {
    root.join(LOADER_THREAT_SNAPSHOT)
}

async fn load_persisted_state(path: &Path) -> Option<PersistedLoaderThreatState> {
    if !path.exists() {
        return None;
    }
    let raw = match fs::read(path).await {
        Ok(raw) => raw,
        Err(err) => {
            tracing::warn!(path = %path.display(), error = %err, "failed reading loader threat state");
            return None;
        }
    };
    match serde_json::from_slice::<PersistedLoaderThreatState>(&raw) {
        Ok(state) => Some(state),
        Err(err) => {
            tracing::warn!(path = %path.display(), error = %err, "loader threat state was malformed; resetting");
            None
        }
    }
}

async fn persist_payloads(
    state_path: &Path,
    snapshot_path: &Path,
    persisted: &PersistedLoaderThreatState,
    snapshot: &LoaderThreatSnapshot,
) {
    match serde_json::to_vec_pretty(persisted) {
        Ok(payload) => {
            if let Err(err) = update::write_atomic(state_path, &payload).await {
                tracing::warn!(path = %state_path.display(), error = %err, "failed persisting loader threat state");
            }
        }
        Err(err) => {
            tracing::warn!(error = %err, "failed serializing loader threat state");
        }
    }
    match serde_json::to_vec_pretty(snapshot) {
        Ok(payload) => {
            if let Err(err) = update::write_atomic(snapshot_path, &payload).await {
                tracing::warn!(path = %snapshot_path.display(), error = %err, "failed persisting loader threat snapshot");
            }
        }
        Err(err) => {
            tracing::warn!(error = %err, "failed serializing loader threat snapshot");
        }
    }
}

fn cleanup_state(state: &mut LoaderThreatState, now: u64) {
    state
        .remote
        .retain(|_, record| now.saturating_sub(record.ts_ms) <= state.remote_ttl_ms);
}

fn persisted_from_state(state: &LoaderThreatState) -> PersistedLoaderThreatState {
    let mut providers: Vec<_> = state.local_providers.values().cloned().collect();
    providers.sort_by(|left, right| {
        right
            .risk
            .partial_cmp(&left.risk)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| right.last_event_ms.cmp(&left.last_event_ms))
    });
    if providers.len() > MAX_PERSISTED_LOCAL_ENTRIES {
        providers.truncate(MAX_PERSISTED_LOCAL_ENTRIES);
    }

    let mut artifacts: Vec<_> = state.local_artifacts.values().cloned().collect();
    artifacts.sort_by(|left, right| {
        right
            .risk
            .partial_cmp(&left.risk)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| right.last_event_ms.cmp(&left.last_event_ms))
    });
    if artifacts.len() > MAX_PERSISTED_LOCAL_ENTRIES {
        artifacts.truncate(MAX_PERSISTED_LOCAL_ENTRIES);
    }

    PersistedLoaderThreatState {
        version: 1,
        epoch: state.epoch,
        providers,
        artifacts,
    }
}

fn snapshot_from_state(
    state: &LoaderThreatState,
    max_entries: usize,
    now: u64,
) -> LoaderThreatSnapshot {
    let mut local_providers: Vec<_> = state.local_providers.values().cloned().collect();
    local_providers.sort_by(|left, right| {
        right
            .risk
            .partial_cmp(&left.risk)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| right.last_event_ms.cmp(&left.last_event_ms))
    });
    if local_providers.len() > max_entries {
        local_providers.truncate(max_entries);
    }

    let mut local_artifacts: Vec<_> = state.local_artifacts.values().cloned().collect();
    local_artifacts.sort_by(|left, right| {
        right
            .risk
            .partial_cmp(&left.risk)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| right.last_event_ms.cmp(&left.last_event_ms))
    });
    if local_artifacts.len() > max_entries {
        local_artifacts.truncate(max_entries);
    }

    let remote_provider_map = aggregate_remote_providers(state);
    let remote_artifact_map = aggregate_remote_artifacts(state);
    let mut remote_providers: Vec<_> = remote_provider_map.into_values().collect();
    remote_providers.sort_by(|left, right| {
        right
            .risk
            .partial_cmp(&left.risk)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| right.last_event_ms.cmp(&left.last_event_ms))
    });
    if remote_providers.len() > max_entries {
        remote_providers.truncate(max_entries);
    }

    let mut remote_artifacts: Vec<_> = remote_artifact_map.into_values().collect();
    remote_artifacts.sort_by(|left, right| {
        right
            .risk
            .partial_cmp(&left.risk)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| right.last_event_ms.cmp(&left.last_event_ms))
    });
    if remote_artifacts.len() > max_entries {
        remote_artifacts.truncate(max_entries);
    }

    let blocked_provider_count = state
        .local_providers
        .keys()
        .filter(|provider_agent_id| {
            provider_assessment_locked(state, provider_agent_id).recommended_block
        })
        .count()
        + remote_providers
            .iter()
            .filter(|entry| {
                !state.local_providers.contains_key(&entry.provider_agent_id)
                    && provider_assessment_locked(state, &entry.provider_agent_id).recommended_block
            })
            .count();
    let blocked_artifact_count = state
        .local_artifacts
        .values()
        .filter(|entry| {
            artifact_assessment_locked(state, &entry.version, &entry.blake3).recommended_block
        })
        .count()
        + remote_artifacts
            .iter()
            .filter(|entry| {
                !state
                    .local_artifacts
                    .contains_key(&make_artifact_key(&entry.version, &entry.blake3))
                    && artifact_assessment_locked(state, &entry.version, &entry.blake3)
                        .recommended_block
            })
            .count();

    let highest_provider_risk = local_providers
        .iter()
        .map(|entry| provider_assessment_locked(state, &entry.provider_agent_id))
        .chain(
            remote_providers
                .iter()
                .map(|entry| provider_assessment_locked(state, &entry.provider_agent_id)),
        )
        .map(|assessment| assessment.local_risk.max(assessment.remote_risk))
        .fold(0.0_f64, f64::max);
    let highest_artifact_risk = local_artifacts
        .iter()
        .map(|entry| artifact_assessment_locked(state, &entry.version, &entry.blake3))
        .chain(
            remote_artifacts
                .iter()
                .map(|entry| artifact_assessment_locked(state, &entry.version, &entry.blake3)),
        )
        .map(|assessment| assessment.local_risk.max(assessment.remote_risk))
        .fold(0.0_f64, f64::max);

    LoaderThreatSnapshot {
        ts_ms: now,
        summary: LoaderThreatSummary {
            local_provider_count: state.local_providers.len(),
            local_artifact_count: state.local_artifacts.len(),
            remote_provider_count: remote_providers.len(),
            remote_artifact_count: remote_artifacts.len(),
            remote_reporters: state.remote.len(),
            blocked_provider_count,
            blocked_artifact_count,
            highest_provider_risk,
            highest_artifact_risk,
        },
        local_providers,
        local_artifacts,
        remote_providers,
        remote_artifacts,
    }
}

fn provider_assessment_locked(
    state: &LoaderThreatState,
    provider_agent_id: &str,
) -> LoaderThreatAssessment {
    let provider_agent_id = provider_agent_id.trim();
    if provider_agent_id.is_empty() {
        return LoaderThreatAssessment::default();
    }

    let local_risk = state
        .local_providers
        .get(provider_agent_id)
        .map(|entry| entry.risk)
        .unwrap_or(0.0);
    let mut remote_risk: f64 = 0.0;
    let mut remote_reporters = 0;
    let mut remote_block_votes = 0;
    for record in state.remote.values() {
        if let Some(entry) = record
            .providers
            .iter()
            .find(|entry| entry.provider_agent_id == provider_agent_id)
        {
            remote_reporters += 1;
            remote_risk = remote_risk.max(entry.risk);
            if entry.recommended_block || entry.risk >= REMOTE_BLOCK_THRESHOLD {
                remote_block_votes += 1;
            }
        }
    }

    LoaderThreatAssessment {
        local_risk,
        remote_risk,
        remote_reporters,
        recommended_block: local_risk >= PROVIDER_BLOCK_THRESHOLD
            || (remote_block_votes >= REMOTE_REPORTER_BLOCK_QUORUM
                && remote_risk >= REMOTE_BLOCK_THRESHOLD),
    }
}

fn artifact_assessment_locked(
    state: &LoaderThreatState,
    version: &str,
    blake3: &str,
) -> LoaderThreatAssessment {
    let key = make_artifact_key(version, blake3);
    if key.is_empty() {
        return LoaderThreatAssessment::default();
    }

    let local_risk = state
        .local_artifacts
        .get(&key)
        .map(|entry| entry.risk)
        .unwrap_or(0.0);
    let mut remote_risk: f64 = 0.0;
    let mut remote_reporters = 0;
    let mut remote_block_votes = 0;
    for record in state.remote.values() {
        if let Some(entry) = record
            .artifacts
            .iter()
            .find(|entry| make_artifact_key(&entry.version, &entry.blake3) == key)
        {
            remote_reporters += 1;
            remote_risk = remote_risk.max(entry.risk);
            if entry.recommended_block || entry.risk >= REMOTE_BLOCK_THRESHOLD {
                remote_block_votes += 1;
            }
        }
    }

    LoaderThreatAssessment {
        local_risk,
        remote_risk,
        remote_reporters,
        recommended_block: local_risk >= ARTIFACT_BLOCK_THRESHOLD
            || (remote_block_votes >= REMOTE_REPORTER_BLOCK_QUORUM
                && remote_risk >= REMOTE_BLOCK_THRESHOLD),
    }
}

fn aggregate_remote_providers(
    state: &LoaderThreatState,
) -> HashMap<String, LoaderThreatProviderEntry> {
    let mut aggregated = HashMap::new();
    for record in state.remote.values() {
        for entry in &record.providers {
            let aggregate = aggregated
                .entry(entry.provider_agent_id.clone())
                .or_insert_with(|| LoaderThreatProviderEntry {
                    provider_agent_id: entry.provider_agent_id.clone(),
                    ..LoaderThreatProviderEntry::default()
                });
            aggregate.risk = aggregate.risk.max(entry.risk);
            aggregate.evidence_count = aggregate.evidence_count.max(entry.evidence_count);
            aggregate.last_event_ms = aggregate.last_event_ms.max(entry.last_event_ms);
            if aggregate.last_event_ms == entry.last_event_ms {
                aggregate.last_reason = entry.last_reason.clone();
                aggregate.last_classification = entry.last_classification.clone();
                aggregate.last_source_addr = entry.last_source_addr.clone();
                aggregate.related_version = entry.related_version.clone();
                aggregate.related_blake3 = entry.related_blake3.clone();
            }
            aggregate.reporter_count = aggregate.reporter_count.saturating_add(1);
            aggregate.recommended_block = aggregate.recommended_block || entry.recommended_block;
        }
    }
    aggregated
}

fn aggregate_remote_artifacts(
    state: &LoaderThreatState,
) -> HashMap<String, LoaderThreatArtifactEntry> {
    let mut aggregated = HashMap::new();
    for record in state.remote.values() {
        for entry in &record.artifacts {
            let key = make_artifact_key(&entry.version, &entry.blake3);
            let aggregate = aggregated
                .entry(key)
                .or_insert_with(|| LoaderThreatArtifactEntry {
                    version: entry.version.clone(),
                    blake3: entry.blake3.clone(),
                    ..LoaderThreatArtifactEntry::default()
                });
            aggregate.risk = aggregate.risk.max(entry.risk);
            aggregate.evidence_count = aggregate.evidence_count.max(entry.evidence_count);
            aggregate.last_event_ms = aggregate.last_event_ms.max(entry.last_event_ms);
            if aggregate.last_event_ms == entry.last_event_ms {
                aggregate.last_reason = entry.last_reason.clone();
                aggregate.last_classification = entry.last_classification.clone();
                aggregate.source_provider_agent_id = entry.source_provider_agent_id.clone();
            }
            aggregate.reporter_count = aggregate.reporter_count.saturating_add(1);
            aggregate.recommended_block = aggregate.recommended_block || entry.recommended_block;
        }
    }
    aggregated
}

fn sanitize_provider_entry(
    mut entry: LoaderThreatProviderEntry,
) -> Option<LoaderThreatProviderEntry> {
    entry.provider_agent_id = sanitize_text(entry.provider_agent_id, MAX_ID_LEN)?;
    entry.last_source_addr = sanitize_text_option(entry.last_source_addr, MAX_ADDR_LEN);
    entry.last_reason = sanitize_text(entry.last_reason, MAX_REASON_LEN)
        .unwrap_or_else(|| "suspicious loader update detected".to_string());
    entry.last_classification = sanitize_text(entry.last_classification, MAX_CLASSIFICATION_LEN)
        .unwrap_or_else(|| "malformed_update".to_string());
    entry.related_version = sanitize_text_option(entry.related_version, MAX_VERSION_LEN);
    entry.related_blake3 = sanitize_text_option(entry.related_blake3, MAX_DIGEST_LEN);
    entry.risk = entry.risk.clamp(0.0, 1.0);
    entry.reporter_count = entry.reporter_count.max(1);
    entry.recommended_block = entry.recommended_block || entry.risk >= PROVIDER_BLOCK_THRESHOLD;
    Some(entry)
}

fn sanitize_artifact_entry(
    mut entry: LoaderThreatArtifactEntry,
) -> Option<LoaderThreatArtifactEntry> {
    entry.version = sanitize_text(entry.version, MAX_VERSION_LEN)?;
    entry.blake3 = sanitize_text(entry.blake3, MAX_DIGEST_LEN)?;
    entry.last_reason = sanitize_text(entry.last_reason, MAX_REASON_LEN)
        .unwrap_or_else(|| "suspicious loader update detected".to_string());
    entry.last_classification = sanitize_text(entry.last_classification, MAX_CLASSIFICATION_LEN)
        .unwrap_or_else(|| "malformed_update".to_string());
    entry.source_provider_agent_id =
        sanitize_text_option(entry.source_provider_agent_id, MAX_ID_LEN);
    entry.risk = entry.risk.clamp(0.0, 1.0);
    entry.reporter_count = entry.reporter_count.max(1);
    entry.recommended_block = entry.recommended_block || entry.risk >= ARTIFACT_BLOCK_THRESHOLD;
    Some(entry)
}

fn sanitize_text(value: impl Into<String>, max_len: usize) -> Option<String> {
    let value = value.into();
    let mut value = value.trim().to_string();
    if value.is_empty() {
        return None;
    }
    if value.len() > max_len {
        value.truncate(max_len);
    }
    Some(value)
}

fn sanitize_text_option(value: Option<String>, max_len: usize) -> Option<String> {
    value.and_then(|value| sanitize_text(value, max_len))
}

fn make_artifact_key(version: &str, blake3: &str) -> String {
    let version = version.trim();
    let blake3 = blake3.trim();
    if version.is_empty() || blake3.is_empty() {
        return String::new();
    }
    format!("{}::{}", version, blake3)
}

fn parse_provider_entry_lossy(value: &Value) -> Option<LoaderThreatProviderEntry> {
    let object = peer_compat::value_as_object(value)?;
    sanitize_provider_entry(LoaderThreatProviderEntry {
        provider_agent_id: peer_compat::value_for(
            &object,
            &[
                "provider_agent_id",
                "provider",
                "peer_agent_id",
                "peerId",
                "agent_id",
            ],
        )
        .and_then(peer_compat::coerce_string)?,
        last_source_addr: peer_compat::value_for(
            &object,
            &["last_source_addr", "source_addr", "sourceAddr", "addr"],
        )
        .and_then(peer_compat::coerce_string),
        risk: peer_compat::value_for(&object, &["risk", "score"])
            .and_then(peer_compat::coerce_unit_interval)
            .unwrap_or(0.0),
        evidence_count: peer_compat::value_for(&object, &["evidence_count", "count", "hits"])
            .and_then(peer_compat::coerce_u64)
            .unwrap_or(1),
        last_event_ms: peer_compat::value_for(
            &object,
            &["last_event_ms", "updated_ms", "ts_ms", "timestamp_ms"],
        )
        .and_then(peer_compat::coerce_u64)
        .unwrap_or(0),
        last_reason: peer_compat::value_for(&object, &["last_reason", "reason", "detail"])
            .and_then(peer_compat::coerce_string)
            .unwrap_or_else(|| "suspicious loader update detected".to_string()),
        last_classification: peer_compat::value_for(
            &object,
            &["last_classification", "classification", "category", "kind"],
        )
        .and_then(peer_compat::coerce_string)
        .unwrap_or_else(|| "malformed_update".to_string()),
        related_version: peer_compat::value_for(
            &object,
            &["related_version", "version", "artifact_version"],
        )
        .and_then(peer_compat::coerce_string),
        related_blake3: peer_compat::value_for(
            &object,
            &["related_blake3", "blake3", "artifact_blake3", "digest"],
        )
        .and_then(peer_compat::coerce_string),
        reporter_count: 1,
        recommended_block: peer_compat::value_for(
            &object,
            &["recommended_block", "block", "blocked", "quarantine"],
        )
        .and_then(peer_compat::coerce_bool)
        .unwrap_or(false),
    })
}

fn parse_artifact_entry_lossy(value: &Value) -> Option<LoaderThreatArtifactEntry> {
    let object = peer_compat::value_as_object(value)?;
    sanitize_artifact_entry(LoaderThreatArtifactEntry {
        version: peer_compat::value_for(&object, &["version", "artifact_version"])
            .and_then(peer_compat::coerce_string)?,
        blake3: peer_compat::value_for(&object, &["blake3", "digest", "hash", "artifact_blake3"])
            .and_then(peer_compat::coerce_string)?,
        risk: peer_compat::value_for(&object, &["risk", "score"])
            .and_then(peer_compat::coerce_unit_interval)
            .unwrap_or(0.0),
        evidence_count: peer_compat::value_for(&object, &["evidence_count", "count", "hits"])
            .and_then(peer_compat::coerce_u64)
            .unwrap_or(1),
        last_event_ms: peer_compat::value_for(
            &object,
            &["last_event_ms", "updated_ms", "ts_ms", "timestamp_ms"],
        )
        .and_then(peer_compat::coerce_u64)
        .unwrap_or(0),
        last_reason: peer_compat::value_for(&object, &["last_reason", "reason", "detail"])
            .and_then(peer_compat::coerce_string)
            .unwrap_or_else(|| "suspicious loader update detected".to_string()),
        last_classification: peer_compat::value_for(
            &object,
            &["last_classification", "classification", "category", "kind"],
        )
        .and_then(peer_compat::coerce_string)
        .unwrap_or_else(|| "malformed_update".to_string()),
        source_provider_agent_id: peer_compat::value_for(
            &object,
            &[
                "source_provider_agent_id",
                "provider_agent_id",
                "provider",
                "peer_agent_id",
            ],
        )
        .and_then(peer_compat::coerce_string),
        reporter_count: 1,
        recommended_block: peer_compat::value_for(
            &object,
            &["recommended_block", "block", "blocked", "quarantine"],
        )
        .and_then(peer_compat::coerce_bool)
        .unwrap_or(false),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[tokio::test]
    async fn local_incident_blocks_provider_and_artifact() {
        let loader_root = unique_test_dir("loader-threats-local");
        let _ = fs::remove_dir_all(&loader_root).await;
        fs::create_dir_all(&loader_root)
            .await
            .expect("loader root should exist");
        let config = LoaderConfig {
            state_dir: loader_root.clone(),
            ..LoaderConfig::default()
        };
        let hub = LoaderThreatHub::from_config(&config)
            .await
            .expect("hub should initialize");

        hub.record_incident(LocalThreatIncident {
            provider_agent_id: Some("peer-a".to_string()),
            source_addr: Some("10.0.0.1:47988".to_string()),
            artifact_version: Some("2.0.0".to_string()),
            artifact_blake3: Some("ab".repeat(32)),
            classification: "crashing_update".to_string(),
            reason: "rollback after crash".to_string(),
            provider_risk: 1.0,
            artifact_risk: 1.0,
        })
        .await;

        let provider = hub.provider_assessment("peer-a").await;
        let artifact = hub.artifact_assessment("2.0.0", &"ab".repeat(32)).await;
        assert!(provider.recommended_block);
        assert!(artifact.recommended_block);

        let snapshot = hub.snapshot(8).await;
        assert_eq!(snapshot.summary.blocked_provider_count, 1);
        assert_eq!(snapshot.summary.blocked_artifact_count, 1);

        let _ = fs::remove_dir_all(&loader_root).await;
    }

    #[tokio::test]
    async fn remote_reports_require_quorum_for_blocking() {
        let loader_root = unique_test_dir("loader-threats-remote");
        let _ = fs::remove_dir_all(&loader_root).await;
        fs::create_dir_all(&loader_root)
            .await
            .expect("loader root should exist");
        let config = LoaderConfig {
            state_dir: loader_root.clone(),
            ..LoaderConfig::default()
        };
        let hub = LoaderThreatHub::from_config(&config)
            .await
            .expect("hub should initialize");

        let ts_ms = now_ms();
        let remote_entry = LoaderThreatProviderEntry {
            provider_agent_id: "peer-bad".to_string(),
            risk: 1.0,
            evidence_count: 1,
            last_event_ms: ts_ms,
            last_reason: "malformed peer bundle".to_string(),
            last_classification: "malformed_update".to_string(),
            reporter_count: 1,
            recommended_block: true,
            ..LoaderThreatProviderEntry::default()
        };
        let artifact_entry = LoaderThreatArtifactEntry {
            version: "9.9.9".to_string(),
            blake3: "cd".repeat(32),
            risk: 1.0,
            evidence_count: 1,
            last_event_ms: ts_ms,
            last_reason: "malformed peer bundle".to_string(),
            last_classification: "malformed_update".to_string(),
            reporter_count: 1,
            recommended_block: true,
            source_provider_agent_id: Some("peer-bad".to_string()),
        };

        let mut announcement = LoaderThreatAnnouncement {
            agent_id: "observer-1".to_string(),
            ts_ms,
            epoch: 1,
            providers: vec![remote_entry.clone()],
            artifacts: vec![artifact_entry.clone()],
            signature: String::new(),
        };
        announcement.signature = sign_loader_threat_announcement(&announcement, "shared-key");
        hub.ingest_remote(announcement).await;
        assert!(!hub.provider_assessment("peer-bad").await.recommended_block);
        assert!(
            !hub.artifact_assessment("9.9.9", &"cd".repeat(32))
                .await
                .recommended_block
        );

        let mut announcement = LoaderThreatAnnouncement {
            agent_id: "observer-2".to_string(),
            ts_ms: ts_ms.saturating_add(1),
            epoch: 1,
            providers: vec![remote_entry],
            artifacts: vec![artifact_entry],
            signature: String::new(),
        };
        announcement.signature = sign_loader_threat_announcement(&announcement, "shared-key");
        hub.ingest_remote(announcement).await;
        assert!(hub.provider_assessment("peer-bad").await.recommended_block);
        assert!(
            hub.artifact_assessment("9.9.9", &"cd".repeat(32))
                .await
                .recommended_block
        );

        let _ = fs::remove_dir_all(&loader_root).await;
    }

    #[test]
    fn fuzzy_loader_threat_parser_recovers_wrapped_payload() {
        let provider = LoaderThreatProviderEntry {
            provider_agent_id: "peer-loader".to_string(),
            risk: 1.0,
            evidence_count: 2,
            last_event_ms: 55,
            last_reason: "rollback after crash".to_string(),
            last_classification: "crashing_update".to_string(),
            reporter_count: 1,
            recommended_block: true,
            related_version: Some("2.4.6".to_string()),
            related_blake3: Some("ab".repeat(32)),
            ..LoaderThreatProviderEntry::default()
        };
        let artifact = LoaderThreatArtifactEntry {
            version: "2.4.6".to_string(),
            blake3: "ab".repeat(32),
            risk: 1.0,
            evidence_count: 1,
            last_event_ms: 55,
            last_reason: "rollback after crash".to_string(),
            last_classification: "crashing_update".to_string(),
            reporter_count: 1,
            recommended_block: true,
            source_provider_agent_id: Some("peer-loader".to_string()),
        };
        let announcement = LoaderThreatAnnouncement {
            agent_id: "observer".to_string(),
            ts_ms: 77,
            epoch: 3,
            providers: vec![provider],
            artifacts: vec![artifact],
            signature: String::new(),
        };
        let signature = sign_loader_threat_announcement(&announcement, "shared-key");
        let payload = serde_json::json!({
            "wrapper": {
                "threat": {
                    "agentId": "observer",
                    "timestamp_ms": "77",
                    "generation": 3,
                    "provider_intel": [{
                        "provider": "peer-loader",
                        "score": "1.0",
                        "count": "2",
                        "updated_ms": 55,
                        "reason": "rollback after crash",
                        "category": "crashing_update",
                        "artifact_version": "2.4.6",
                        "artifact_blake3": "ab".repeat(32),
                        "blocked": true
                    }],
                    "artifact_reports": [{
                        "artifact_version": "2.4.6",
                        "hash": "ab".repeat(32),
                        "score": "1.0",
                        "count": 1,
                        "updated_ms": 55,
                        "reason": "rollback after crash",
                        "category": "crashing_update",
                        "provider": "peer-loader",
                        "blocked": true
                    }],
                    "sig": signature
                }
            }
        })
        .to_string();

        let (parsed, affinity) = parse_loader_threat_announcement_lossy(payload.as_bytes())
            .expect("payload should recover");

        assert!(affinity >= 3.0);
        assert_eq!(parsed.agent_id, "observer");
        assert_eq!(parsed.providers.len(), 1);
        assert_eq!(parsed.artifacts.len(), 1);
        assert_eq!(parsed.providers, announcement.providers);
        assert_eq!(parsed.artifacts, announcement.artifacts);
        assert!(verify_loader_threat_announcement_signature(
            &parsed,
            "shared-key"
        ));
    }

    fn unique_test_dir(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!("tracey-{label}-{}-{nonce}", std::process::id()))
    }
}
