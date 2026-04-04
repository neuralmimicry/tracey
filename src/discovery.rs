//! Authenticated UDP gossip for peer discovery and distributed intelligence.
//!
//! Announcements include capability data and optional TraceyBan/TraceyGuard
//! advertisements signed with a shared-key digest.

use crate::capabilities::Capabilities;
use crate::config::DiscoveryConfig;
use crate::coordination::{CoordinatorRole, PrometheusProbe};
use crate::event::now_ms;
use crate::governance::GovernanceState;
use crate::inventory::Inventory;
use crate::peer_compat::{self, SchemaField};
use crate::shutdown::ShutdownListener;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Duration;
use tokio::net::UdpSocket;

const MAX_FUTURE_SKEW_MS: u64 = 30_000;
const MAX_AGENT_ID_LEN: usize = 128;
const MAX_ADDR_LEN: usize = 256;
const MAX_VERSION_LEN: usize = 64;
const MAX_TAGS: usize = 64;
const MAX_TAG_LEN: usize = 64;
const DISCOVERY_PREVIEW_BYTES: usize = 160;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentAnnouncement {
    pub agent_id: String,
    #[serde(default)]
    pub agent_version: Option<String>,
    pub ts_ms: u64,
    pub addr: Option<String>,
    pub status_addr: Option<String>,
    pub ban_advertisement: Option<crate::tracey_ban::BanAdvertisement>,
    pub fault_advertisement: Option<crate::tracey_guard::FaultAdvertisement>,
    #[serde(default)]
    pub slurm: Option<crate::slurm::SlurmSnapshot>,
    pub capabilities: Capabilities,
    pub signature: String,
    pub is_coordinator: Option<bool>,
    pub coordinator_epoch: Option<u64>,
    pub score: Option<u64>,
    #[serde(default)]
    pub prometheus_probe: Option<PrometheusProbe>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentPresence {
    pub agent_id: String,
    #[serde(default)]
    pub agent_version: Option<String>,
    pub ts_ms: u64,
    pub addr: Option<String>,
    pub status_addr: Option<String>,
    #[serde(default)]
    pub observed_addr: Option<String>,
    pub ban_advertisement: Option<crate::tracey_ban::BanAdvertisement>,
    pub fault_advertisement: Option<crate::tracey_guard::FaultAdvertisement>,
    #[serde(default)]
    pub slurm: Option<crate::slurm::SlurmSnapshot>,
    pub capabilities: Capabilities,
    pub source: String,
    pub is_coordinator: Option<bool>,
    pub coordinator_epoch: Option<u64>,
    pub score: Option<u64>,
    #[serde(default)]
    pub prometheus_probe: Option<PrometheusProbe>,
}

pub async fn spawn_discovery(
    config: DiscoveryConfig,
    agent_id: String,
    agent_version: String,
    inventory: Inventory,
    mut shutdown: ShutdownListener,
    governance_state: std::sync::Arc<tokio::sync::RwLock<GovernanceState>>,
    coordinator_role: std::sync::Arc<tokio::sync::RwLock<CoordinatorRole>>,
    coordination: crate::coordination::Coordination,
    status_addr: Option<String>,
    capabilities: Capabilities,
    slurm: crate::slurm::SlurmRuntimeHandle,
    ban_intel: Option<crate::tracey_ban::BanIntelHub>,
    max_advertised_ips: usize,
    fault_intel: Option<crate::tracey_guard::FaultIntelHub>,
    max_advertised_faults: usize,
) -> std::io::Result<()> {
    if !config.enabled {
        tracing::info!("discovery disabled");
        return Ok(());
    }

    let socket = UdpSocket::bind(&config.bind_addr).await?;
    socket.set_broadcast(true)?;

    let announce_interval = Duration::from_millis(config.announce_interval_ms);
    let ttl = config.ttl_ms;
    let mut ticker = tokio::time::interval(announce_interval);
    let mut buf = vec![0u8; 4096];
    let shared_key = derive_key(&config.shared_key);
    tracing::info!(
        bind = %config.bind_addr,
        broadcast = %config.broadcast_addr,
        "discovery enabled"
    );

    loop {
        tokio::select! {
            _ = shutdown.wait() => {
                tracing::info!("discovery shutting down");
                break;
            }
            _ = ticker.tick() => {
                let enabled = governance_state.read().await.discovery_enabled;
                if enabled {
                    let role = coordinator_role.read().await.clone();
                    let ban_advertisement = if let Some(intel) = &ban_intel {
                        Some(intel.build_advertisement(max_advertised_ips).await)
                    } else {
                        None
                    };
                    let fault_advertisement = if let Some(intel) = &fault_intel {
                        Some(intel.build_advertisement(max_advertised_faults).await)
                    } else {
                        None
                    };
                    let slurm_snapshot = slurm.snapshot().await;
                    let announcement_capabilities = if let Some(snapshot) = &slurm_snapshot {
                        capabilities.with_extra_tags(snapshot.capability_tags())
                    } else {
                        capabilities.clone()
                    };
                    let announcement = build_announcement(
                        &agent_id,
                        &agent_version,
                        &config,
                        &announcement_capabilities,
                        &shared_key,
                        &role,
                        status_addr.as_deref(),
                        ban_advertisement,
                        fault_advertisement,
                        slurm_snapshot,
                    );
                    match serde_json::to_vec(&announcement) {
                        Ok(payload) => {
                            if let Err(err) = socket.send_to(&payload, &config.broadcast_addr).await {
                                tracing::warn!(
                                    target = %config.broadcast_addr,
                                    error = %err,
                                    "discovery broadcast send failed"
                                );
                            }
                        }
                        Err(err) => {
                            tracing::warn!(error = %err, "discovery announcement serialization failed");
                        }
                    }
                }
            }
            recv = socket.recv_from(&mut buf) => {
                if let Ok((size, peer)) = recv {
                    if !governance_state.read().await.discovery_enabled {
                        continue;
                    }
                    let mut announcement = match serde_json::from_slice::<AgentAnnouncement>(&buf[..size]) {
                        Ok(announcement) => announcement,
                        Err(err) => {
                            match parse_announcement_lossy(&buf[..size]) {
                                Ok((announcement, affinity)) => {
                                    tracing::info!(
                                        peer = %peer,
                                        size,
                                        affinity,
                                        payload_preview = %payload_preview(&buf[..size], DISCOVERY_PREVIEW_BYTES),
                                        "discovery announcement recovered with fuzzy parser"
                                    );
                                    announcement
                                }
                                Err(reason) => {
                                    tracing::warn!(
                                        peer = %peer,
                                        size,
                                        error = %err,
                                        reason = %reason,
                                        payload_preview = %payload_preview(&buf[..size], DISCOVERY_PREVIEW_BYTES),
                                        "invalid discovery announcement format"
                                    );
                                    continue;
                                }
                            }
                        }
                    };
                    if announcement.agent_id == agent_id {
                        continue;
                    }
                    if !valid_signature(&announcement, &shared_key) {
                        tracing::warn!(peer = %peer, agent_id = %announcement.agent_id, "discovery signature mismatch");
                        continue;
                    }
                    let now = now_ms();
                    if let Err(reason) = validate_announcement_semantics(&announcement, ttl, now) {
                        tracing::warn!(
                            peer = %peer,
                            agent_id = %announcement.agent_id,
                            reason = %reason,
                            "invalid discovery announcement semantics"
                        );
                        continue;
                    }
                    sanitize_announcement(&mut announcement, max_advertised_ips, &peer.to_string(), now);
                    sanitize_fault_announcement(
                        &mut announcement,
                        max_advertised_faults,
                        &peer.to_string(),
                    );

                    let presence = AgentPresence {
                        agent_id: announcement.agent_id,
                        agent_version: announcement.agent_version,
                        ts_ms: announcement.ts_ms,
                        addr: announcement.addr,
                        status_addr: announcement.status_addr,
                        observed_addr: Some(peer.to_string()),
                        ban_advertisement: announcement.ban_advertisement.clone(),
                        fault_advertisement: announcement.fault_advertisement.clone(),
                        slurm: announcement.slurm.clone(),
                        capabilities: announcement.capabilities,
                        source: "gossip".to_string(),
                        is_coordinator: announcement.is_coordinator,
                        coordinator_epoch: announcement.coordinator_epoch,
                        score: announcement.score,
                        prometheus_probe: announcement.prometheus_probe,
                    };
                    if let Some(intel) = &ban_intel
                        && let Some(advertisement) = &presence.ban_advertisement
                    {
                        intel.ingest_remote(&presence.agent_id, advertisement.clone()).await;
                    }
                    if let Some(intel) = &fault_intel
                        && let Some(advertisement) = &presence.fault_advertisement
                    {
                        intel.ingest_remote(&presence.agent_id, advertisement.clone()).await;
                    }
                    inventory.record_agent(presence.clone()).await;
                    coordination.record_presence(presence).await;
                } else if let Err(err) = recv {
                    tracing::warn!(error = %err, "discovery receive failed");
                }
            }
        }
    }

    Ok(())
}

fn build_announcement(
    agent_id: &str,
    agent_version: &str,
    config: &DiscoveryConfig,
    capabilities: &Capabilities,
    key: &[u8; 32],
    role: &CoordinatorRole,
    status_addr: Option<&str>,
    ban_advertisement: Option<crate::tracey_ban::BanAdvertisement>,
    fault_advertisement: Option<crate::tracey_guard::FaultAdvertisement>,
    slurm: Option<crate::slurm::SlurmSnapshot>,
) -> AgentAnnouncement {
    let ts_ms = now_ms();
    let addr = config.advertise_addr.clone();
    let signature = sign_payload(
        agent_id,
        agent_version,
        ts_ms,
        addr.as_deref(),
        capabilities,
        role,
        status_addr,
        ban_advertisement.as_ref(),
        fault_advertisement.as_ref(),
        key,
    );
    AgentAnnouncement {
        agent_id: agent_id.to_string(),
        agent_version: Some(agent_version.to_string()),
        ts_ms,
        addr,
        status_addr: status_addr.map(|v| v.to_string()),
        ban_advertisement,
        fault_advertisement,
        slurm,
        capabilities: capabilities.clone(),
        signature,
        is_coordinator: Some(role.is_coordinator),
        coordinator_epoch: Some(role.epoch),
        score: Some(role.score),
        prometheus_probe: role.prometheus_probe.clone(),
    }
}

fn valid_signature(announcement: &AgentAnnouncement, key: &[u8; 32]) -> bool {
    let role = CoordinatorRole {
        agent_id: announcement.agent_id.clone(),
        score: announcement.score.unwrap_or(0),
        is_coordinator: announcement.is_coordinator.unwrap_or(false),
        leader_rank: 0,
        leader_count: 0,
        epoch: announcement.coordinator_epoch.unwrap_or(0),
        last_update_ms: announcement.ts_ms,
        proxy_agent_id: None,
        proxy_latency_ms: None,
        proxy_addr: None,
        is_prometheus_exporter: false,
        prometheus_exporter_agent_id: None,
        prometheus_exporter_addr: None,
        prometheus_exporter_latency_ms: None,
        prometheus_exporter_bandwidth_mbps: None,
        prometheus_probe: announcement.prometheus_probe.clone(),
    };
    if let Some(agent_version) = announcement
        .agent_version
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        let expected = sign_payload(
            &announcement.agent_id,
            agent_version,
            announcement.ts_ms,
            announcement.addr.as_deref(),
            &announcement.capabilities,
            &role,
            announcement.status_addr.as_deref(),
            announcement.ban_advertisement.as_ref(),
            announcement.fault_advertisement.as_ref(),
            key,
        );
        return normalize_eq(&announcement.signature, &expected);
    }

    let legacy = sign_payload_legacy(
        &announcement.agent_id,
        announcement.ts_ms,
        announcement.addr.as_deref(),
        &announcement.capabilities,
        &role,
        announcement.status_addr.as_deref(),
        announcement.ban_advertisement.as_ref(),
        announcement.fault_advertisement.as_ref(),
        key,
    );
    normalize_eq(&announcement.signature, &legacy)
}

fn validate_announcement_semantics(
    announcement: &AgentAnnouncement,
    ttl_ms: u64,
    now: u64,
) -> Result<(), String> {
    let agent_id = announcement.agent_id.trim();
    if agent_id.is_empty() {
        return Err("agent_id is empty".to_string());
    }
    if agent_id.len() > MAX_AGENT_ID_LEN {
        return Err(format!("agent_id too long (>{})", MAX_AGENT_ID_LEN));
    }
    if let Some(agent_version) = &announcement.agent_version {
        validate_text_field("agent_version", agent_version, MAX_VERSION_LEN)?;
    }
    if !is_hex64(&announcement.signature) {
        return Err("signature format invalid".to_string());
    }
    if announcement.ts_ms == 0 {
        return Err("timestamp is zero".to_string());
    }
    if now.saturating_sub(announcement.ts_ms) > ttl_ms {
        return Err("announcement expired".to_string());
    }
    if announcement.ts_ms.saturating_sub(now) > MAX_FUTURE_SKEW_MS {
        return Err(format!(
            "announcement timestamp too far in future (>{}ms)",
            MAX_FUTURE_SKEW_MS
        ));
    }
    if let Some(addr) = &announcement.addr {
        validate_text_field("addr", addr, MAX_ADDR_LEN)?;
    }
    if let Some(status_addr) = &announcement.status_addr {
        validate_text_field("status_addr", status_addr, MAX_ADDR_LEN)?;
    }
    if announcement.capabilities.cpu_cores == 0 {
        return Err("capabilities.cpu_cores must be > 0".to_string());
    }
    if announcement.capabilities.tags.len() > MAX_TAGS {
        return Err(format!("too many capability tags (>{})", MAX_TAGS));
    }
    for tag in &announcement.capabilities.tags {
        validate_text_field("capability_tag", tag, MAX_TAG_LEN)?;
    }
    if let Some(probe) = &announcement.prometheus_probe {
        if !probe.bandwidth_mbps.is_finite() || probe.bandwidth_mbps < 0.0 {
            return Err("prometheus_probe.bandwidth_mbps invalid".to_string());
        }
        if probe.sampled_at_ms > now.saturating_add(MAX_FUTURE_SKEW_MS) {
            return Err("prometheus_probe.sampled_at_ms too far in future".to_string());
        }
    }
    Ok(())
}

fn validate_text_field(name: &str, value: &str, max_len: usize) -> Result<(), String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(format!("{} is empty", name));
    }
    if value.len() > max_len {
        return Err(format!("{} too long (>{})", name, max_len));
    }
    if value.chars().any(|ch| ch.is_control()) {
        return Err(format!("{} contains control characters", name));
    }
    Ok(())
}

fn parse_announcement_lossy(payload: &[u8]) -> Result<(AgentAnnouncement, f64), String> {
    let root = peer_compat::parse_bytes(payload).map_err(|err| err.to_string())?;
    let fields = [
        SchemaField {
            aliases: &[
                "agent_id", "agentId", "peer_id", "peerId", "node_id", "nodeId", "id",
            ],
            required: true,
            weight: 2.0,
        },
        SchemaField {
            aliases: &[
                "ts_ms",
                "timestamp_ms",
                "timestamp",
                "ts",
                "seen_ms",
                "updated_ms",
            ],
            required: true,
            weight: 1.5,
        },
        SchemaField {
            aliases: &["signature", "sig", "mac", "digest"],
            required: true,
            weight: 2.0,
        },
        SchemaField {
            aliases: &["capabilities", "capability", "traits", "os", "platform"],
            required: true,
            weight: 1.8,
        },
        SchemaField {
            aliases: &[
                "status_addr",
                "statusAddr",
                "status_url",
                "statusUrl",
                "api_addr",
            ],
            required: false,
            weight: 0.8,
        },
    ];
    let matched = peer_compat::best_object(&root, &fields, 2.4, 4)
        .ok_or_else(|| "payload did not resemble a discovery announcement".to_string())?;
    let map = matched.map;

    let agent_id = peer_compat::value_for(
        map,
        &[
            "agent_id", "agentId", "peer_id", "peerId", "node_id", "nodeId", "id",
        ],
    )
    .and_then(peer_compat::coerce_string)
    .ok_or_else(|| "missing agent identifier".to_string())?;
    let ts_ms = peer_compat::value_for(
        map,
        &[
            "ts_ms",
            "timestamp_ms",
            "timestamp",
            "ts",
            "seen_ms",
            "updated_ms",
        ],
    )
    .and_then(peer_compat::coerce_u64)
    .ok_or_else(|| "missing timestamp".to_string())?;
    let signature = peer_compat::value_for(map, &["signature", "sig", "mac", "digest"])
        .and_then(peer_compat::coerce_string)
        .ok_or_else(|| "missing signature".to_string())?;
    let capabilities =
        parse_capabilities_lossy(map).ok_or_else(|| "missing capability data".to_string())?;

    let is_coordinator = peer_compat::value_for(
        map,
        &["is_coordinator", "isCoordinator", "leader", "coordinator"],
    )
    .and_then(parse_role_flag);

    Ok((
        AgentAnnouncement {
            agent_id,
            agent_version: peer_compat::value_for(
                map,
                &[
                    "agent_version",
                    "agentVersion",
                    "version",
                    "build_version",
                    "buildVersion",
                ],
            )
            .and_then(peer_compat::coerce_string),
            ts_ms,
            addr: peer_compat::value_for(
                map,
                &[
                    "addr",
                    "advertise_addr",
                    "advertiseAddr",
                    "discovery_addr",
                    "discoveryAddr",
                    "peer_addr",
                    "peerAddr",
                ],
            )
            .and_then(peer_compat::coerce_string),
            status_addr: peer_compat::value_for(
                map,
                &[
                    "status_addr",
                    "statusAddr",
                    "status_url",
                    "statusUrl",
                    "api_addr",
                ],
            )
            .and_then(peer_compat::coerce_string),
            ban_advertisement: peer_compat::value_for(
                map,
                &["ban_advertisement", "banAdvertisement", "ban_ad", "bans"],
            )
            .and_then(parse_ban_advertisement_lossy),
            fault_advertisement: peer_compat::value_for(
                map,
                &[
                    "fault_advertisement",
                    "faultAdvertisement",
                    "fault_ad",
                    "faults",
                ],
            )
            .and_then(parse_fault_advertisement_lossy),
            slurm: peer_compat::value_for(map, &["slurm", "slurm_status", "slurmSnapshot"])
                .and_then(parse_slurm_snapshot_lossy),
            capabilities,
            signature,
            is_coordinator,
            coordinator_epoch: peer_compat::value_for(
                map,
                &[
                    "coordinator_epoch",
                    "coordinatorEpoch",
                    "epoch",
                    "leader_epoch",
                ],
            )
            .and_then(peer_compat::coerce_u64),
            score: peer_compat::value_for(map, &["score", "rank_score", "weight"])
                .and_then(peer_compat::coerce_u64),
            prometheus_probe: peer_compat::value_for(
                map,
                &[
                    "prometheus_probe",
                    "prometheusProbe",
                    "probe",
                    "metrics_probe",
                ],
            )
            .and_then(parse_prometheus_probe_lossy),
        },
        matched.score,
    ))
}

fn parse_capabilities_lossy(map: &Map<String, Value>) -> Option<Capabilities> {
    let source = peer_compat::object_for(
        map,
        &[
            "capabilities",
            "capability",
            "traits",
            "host",
            "system",
            "node",
        ],
    )
    .unwrap_or_else(|| map.clone());

    let os = peer_compat::value_for(&source, &["os", "platform", "operating_system"])
        .and_then(peer_compat::coerce_string)?;
    let arch = peer_compat::value_for(&source, &["arch", "architecture", "cpu_arch"])
        .and_then(peer_compat::coerce_string)?;
    let cpu_cores = peer_compat::value_for(
        &source,
        &[
            "cpu_cores",
            "cpuCores",
            "cores",
            "cpu_count",
            "cpuCount",
            "cpus",
        ],
    )
    .and_then(peer_compat::coerce_usize)
    .unwrap_or(1);

    let mut seen = HashSet::new();
    let mut tags = Vec::new();
    if let Some(value) = peer_compat::value_for(
        &source,
        &[
            "tags",
            "labels",
            "roles",
            "capability_tags",
            "capabilityTags",
        ],
    ) {
        for tag in peer_compat::coerce_string_vec(value) {
            let trimmed = tag.trim();
            if trimmed.is_empty() {
                continue;
            }
            if seen.insert(trimmed.to_string()) {
                tags.push(trimmed.to_string());
            }
        }
    }

    Some(Capabilities {
        os,
        arch,
        cpu_cores,
        tags,
    })
}

fn parse_ban_advertisement_lossy(value: &Value) -> Option<crate::tracey_ban::BanAdvertisement> {
    let object = peer_compat::value_as_object(value)?;
    let ts_ms = peer_compat::value_for(&object, &["ts_ms", "timestamp_ms", "timestamp"])
        .and_then(peer_compat::coerce_u64)
        .unwrap_or(0);
    let epoch = peer_compat::value_for(&object, &["epoch", "version", "generation"])
        .and_then(peer_compat::coerce_u64)
        .unwrap_or(0);
    let entries =
        if let Some(items) = peer_compat::array_for(&object, &["entries", "bans", "items"]) {
            items
                .into_iter()
                .filter_map(|entry| parse_ban_entry_lossy(&entry, ts_ms))
                .collect()
        } else {
            Vec::new()
        };
    Some(crate::tracey_ban::BanAdvertisement {
        ts_ms,
        epoch,
        entries,
    })
}

fn parse_ban_entry_lossy(
    value: &Value,
    advertisement_ts_ms: u64,
) -> Option<crate::tracey_ban::BanAdvertisementEntry> {
    let object = peer_compat::value_as_object(value)?;
    let ip = peer_compat::value_for(&object, &["ip", "address", "addr", "host"])
        .and_then(peer_compat::coerce_string)?;
    let jail = peer_compat::value_for(&object, &["jail", "source", "rule", "name"])
        .and_then(peer_compat::coerce_string)?;
    Some(crate::tracey_ban::BanAdvertisementEntry {
        ip,
        jail,
        expires_ms: peer_compat::value_for(&object, &["expires_ms", "expires", "until_ms"])
            .and_then(peer_compat::coerce_u64),
        ban_count: peer_compat::value_for(&object, &["ban_count", "count", "hits"])
            .and_then(peer_compat::coerce_u32)
            .unwrap_or(1),
        last_ban_ms: peer_compat::value_for(
            &object,
            &["last_ban_ms", "last_seen_ms", "ts_ms", "timestamp_ms"],
        )
        .and_then(peer_compat::coerce_u64)
        .unwrap_or(advertisement_ts_ms),
    })
}

fn parse_fault_advertisement_lossy(
    value: &Value,
) -> Option<crate::tracey_guard::FaultAdvertisement> {
    let object = peer_compat::value_as_object(value)?;
    let ts_ms = peer_compat::value_for(&object, &["ts_ms", "timestamp_ms", "timestamp"])
        .and_then(peer_compat::coerce_u64)
        .unwrap_or(0);
    let epoch = peer_compat::value_for(&object, &["epoch", "version", "generation"])
        .and_then(peer_compat::coerce_u64)
        .unwrap_or(0);
    let entries = if let Some(items) =
        peer_compat::array_for(&object, &["entries", "faults", "items", "recent_faults"])
    {
        items
            .into_iter()
            .filter_map(|entry| parse_fault_entry_lossy(&entry))
            .collect()
    } else {
        Vec::new()
    };
    Some(crate::tracey_guard::FaultAdvertisement {
        ts_ms,
        epoch,
        entries,
    })
}

fn parse_fault_entry_lossy(value: &Value) -> Option<crate::tracey_guard::FaultAdvertisementEntry> {
    let object = peer_compat::value_as_object(value)?;
    let risk_value = peer_compat::value_for(&object, &["risk", "score", "mean_risk"])
        .and_then(peer_compat::coerce_unit_interval)
        .unwrap_or(0.0);
    let confidence_value =
        peer_compat::value_for(&object, &["confidence", "certainty", "mean_confidence"])
            .and_then(peer_compat::coerce_unit_interval)
            .unwrap_or(0.0);
    Some(crate::tracey_guard::FaultAdvertisementEntry {
        key: peer_compat::value_for(&object, &["key", "signature", "fault_key"])
            .and_then(peer_compat::coerce_string)?,
        gpu_id: peer_compat::value_for(&object, &["gpu_id", "gpuId", "device_id", "deviceId"])
            .and_then(peer_compat::coerce_string)?,
        probe_type: peer_compat::value_for(
            &object,
            &[
                "probe_type",
                "probeType",
                "probe",
                "fault_type",
                "faultType",
            ],
        )
        .and_then(peer_compat::coerce_string)?,
        state: peer_compat::value_for(&object, &["state", "status"])
            .and_then(peer_compat::coerce_string)
            .unwrap_or_else(|| "unknown".to_string()),
        severity: peer_compat::value_for(&object, &["severity", "level"])
            .and_then(peer_compat::coerce_string)
            .unwrap_or_else(|| infer_severity_label(risk_value).to_string()),
        risk: risk_value,
        confidence: confidence_value,
        count: peer_compat::value_for(&object, &["count", "hits", "samples"])
            .and_then(peer_compat::coerce_u64)
            .unwrap_or(1),
        first_seen_ms: peer_compat::value_for(
            &object,
            &["first_seen_ms", "firstSeenMs", "started_ms", "ts_ms"],
        )
        .and_then(peer_compat::coerce_u64)
        .unwrap_or(0),
        last_seen_ms: peer_compat::value_for(
            &object,
            &["last_seen_ms", "lastSeenMs", "updated_ms", "ts_ms"],
        )
        .and_then(peer_compat::coerce_u64)
        .unwrap_or(0),
    })
}

fn parse_slurm_snapshot_lossy(value: &Value) -> Option<crate::slurm::SlurmSnapshot> {
    let object = peer_compat::value_as_object(value)?;
    let mut snapshot = crate::slurm::SlurmSnapshot {
        updated_ms: peer_compat::value_for(
            &object,
            &["updated_ms", "timestamp_ms", "sampled_at_ms", "ts_ms"],
        )
        .and_then(peer_compat::coerce_u64)
        .unwrap_or(0),
        mode: peer_compat::value_for(&object, &["mode", "deployment_mode", "slurm_mode"])
            .and_then(peer_compat::coerce_string)
            .unwrap_or_default(),
        cluster_name: peer_compat::value_for(&object, &["cluster_name", "clusterName", "cluster"])
            .and_then(peer_compat::coerce_string),
        roles: peer_compat::value_for(&object, &["roles", "role", "labels"])
            .map(peer_compat::coerce_string_vec)
            .unwrap_or_default(),
        controller_healthy: peer_compat::value_for(
            &object,
            &[
                "controller_healthy",
                "controllerHealthy",
                "healthy",
                "ready",
            ],
        )
        .and_then(peer_compat::coerce_bool)
        .unwrap_or(false),
        nodes_total: peer_compat::value_for(&object, &["nodes_total", "nodesTotal", "nodes"])
            .and_then(peer_compat::coerce_u32)
            .unwrap_or(0),
        nodes_idle: peer_compat::value_for(&object, &["nodes_idle", "nodesIdle"])
            .and_then(peer_compat::coerce_u32)
            .unwrap_or(0),
        nodes_allocated: peer_compat::value_for(
            &object,
            &["nodes_allocated", "nodesAllocated", "nodes_busy"],
        )
        .and_then(peer_compat::coerce_u32)
        .unwrap_or(0),
        nodes_down: peer_compat::value_for(&object, &["nodes_down", "nodesDown"])
            .and_then(peer_compat::coerce_u32)
            .unwrap_or(0),
        nodes_other: peer_compat::value_for(&object, &["nodes_other", "nodesOther"])
            .and_then(peer_compat::coerce_u32)
            .unwrap_or(0),
        jobs_total: peer_compat::value_for(&object, &["jobs_total", "jobsTotal", "jobs"])
            .and_then(peer_compat::coerce_u32)
            .unwrap_or(0),
        jobs_pending: peer_compat::value_for(&object, &["jobs_pending", "jobsPending"])
            .and_then(peer_compat::coerce_u32)
            .unwrap_or(0),
        jobs_running: peer_compat::value_for(&object, &["jobs_running", "jobsRunning"])
            .and_then(peer_compat::coerce_u32)
            .unwrap_or(0),
        jobs_completing: peer_compat::value_for(&object, &["jobs_completing", "jobsCompleting"])
            .and_then(peer_compat::coerce_u32)
            .unwrap_or(0),
        jobs_failed: peer_compat::value_for(&object, &["jobs_failed", "jobsFailed"])
            .and_then(peer_compat::coerce_u32)
            .unwrap_or(0),
        jobs_other: peer_compat::value_for(&object, &["jobs_other", "jobsOther"])
            .and_then(peer_compat::coerce_u32)
            .unwrap_or(0),
    };
    snapshot.sanitize();
    Some(snapshot)
}

fn parse_prometheus_probe_lossy(value: &Value) -> Option<PrometheusProbe> {
    let object = peer_compat::value_as_object(value)?;
    Some(PrometheusProbe {
        ready: peer_compat::value_for(&object, &["ready", "healthy", "up"])
            .and_then(peer_compat::coerce_bool)
            .unwrap_or(false),
        latency_ms: peer_compat::value_for(
            &object,
            &["latency_ms", "latencyMs", "latency", "duration_ms"],
        )
        .and_then(peer_compat::coerce_u64)
        .unwrap_or(0),
        bandwidth_mbps: peer_compat::value_for(
            &object,
            &[
                "bandwidth_mbps",
                "bandwidthMbps",
                "bandwidth",
                "throughput_mbps",
            ],
        )
        .and_then(peer_compat::coerce_f64)
        .unwrap_or(0.0),
        sampled_at_ms: peer_compat::value_for(
            &object,
            &["sampled_at_ms", "sampledAtMs", "updated_ms", "ts_ms"],
        )
        .and_then(peer_compat::coerce_u64)
        .unwrap_or(0),
    })
}

fn parse_role_flag(value: &Value) -> Option<bool> {
    peer_compat::coerce_bool(value).or_else(|| {
        peer_compat::coerce_string(value).map(|text| {
            matches!(
                text.trim().to_ascii_lowercase().as_str(),
                "coordinator" | "leader" | "primary"
            )
        })
    })
}

fn infer_severity_label(risk: f64) -> &'static str {
    if risk >= 0.95 {
        "critical"
    } else if risk >= 0.8 {
        "high"
    } else if risk >= 0.55 {
        "medium"
    } else {
        "low"
    }
}

fn sanitize_announcement(
    announcement: &mut AgentAnnouncement,
    max_advertised_ips: usize,
    peer: &str,
    now: u64,
) {
    if let Some(advertisement) = announcement.ban_advertisement.as_mut() {
        let original_len = advertisement.entries.len();
        let mut dropped = 0usize;
        let mut cleaned = Vec::with_capacity(advertisement.entries.len());
        for mut entry in advertisement.entries.drain(..) {
            if entry.jail.trim().is_empty() || entry.jail.len() > MAX_AGENT_ID_LEN {
                dropped += 1;
                continue;
            }
            let Ok(ip) = entry.ip.parse::<IpAddr>() else {
                dropped += 1;
                continue;
            };
            entry.ip = ip.to_string();
            if entry.expires_ms.is_some_and(|expires| expires <= now) {
                dropped += 1;
                continue;
            }
            cleaned.push(entry);
            if cleaned.len() >= max_advertised_ips {
                break;
            }
        }
        if dropped > 0 {
            tracing::warn!(
                peer = %peer,
                agent_id = %announcement.agent_id,
                dropped_entries = dropped,
                "discovery ban advertisement contained invalid entries"
            );
        }
        if original_len > max_advertised_ips {
            tracing::warn!(
                peer = %peer,
                agent_id = %announcement.agent_id,
                received_entries = original_len,
                max_advertised_ips,
                "discovery ban advertisement exceeded maximum entries and was truncated"
            );
        }
        advertisement.entries = cleaned;
    }

    let drop_slurm = if let Some(snapshot) = announcement.slurm.as_mut() {
        snapshot.sanitize();
        snapshot.mode.is_empty() || snapshot.roles.is_empty()
    } else {
        false
    };
    if drop_slurm {
        tracing::warn!(
            peer = %peer,
            agent_id = %announcement.agent_id,
            "discovery slurm advertisement was invalid and has been dropped"
        );
        announcement.slurm = None;
    }
}

fn sanitize_fault_announcement(
    announcement: &mut AgentAnnouncement,
    max_advertised_faults: usize,
    peer: &str,
) {
    let Some(advertisement) = announcement.fault_advertisement.as_mut() else {
        return;
    };

    let original_len = advertisement.entries.len();
    let mut cleaned = Vec::with_capacity(advertisement.entries.len());
    let mut dropped = 0usize;

    for mut entry in advertisement.entries.drain(..) {
        if entry.key.trim().is_empty() || entry.key.len() > 256 {
            dropped += 1;
            continue;
        }
        if entry.gpu_id.trim().is_empty() || entry.gpu_id.len() > MAX_AGENT_ID_LEN {
            dropped += 1;
            continue;
        }
        if entry.probe_type.trim().is_empty() || entry.probe_type.len() > MAX_TAG_LEN {
            dropped += 1;
            continue;
        }
        entry.key = entry.key.trim().to_string();
        entry.gpu_id = entry.gpu_id.trim().to_string();
        entry.probe_type = entry.probe_type.trim().to_ascii_lowercase();
        entry.state = entry.state.trim().to_ascii_lowercase();
        entry.severity = entry.severity.trim().to_ascii_lowercase();
        entry.risk = entry.risk.clamp(0.0, 1.0);
        entry.confidence = entry.confidence.clamp(0.0, 1.0);
        cleaned.push(entry);
        if cleaned.len() >= max_advertised_faults {
            break;
        }
    }

    if dropped > 0 {
        tracing::warn!(
            peer = %peer,
            agent_id = %announcement.agent_id,
            dropped_entries = dropped,
            "discovery fault advertisement contained invalid entries"
        );
    }
    if original_len > max_advertised_faults {
        tracing::warn!(
            peer = %peer,
            agent_id = %announcement.agent_id,
            received_entries = original_len,
            max_advertised_faults,
            "discovery fault advertisement exceeded maximum entries and was truncated"
        );
    }
    advertisement.entries = cleaned;
}

fn sign_payload(
    agent_id: &str,
    agent_version: &str,
    ts_ms: u64,
    addr: Option<&str>,
    capabilities: &Capabilities,
    role: &CoordinatorRole,
    status_addr: Option<&str>,
    ban_advertisement: Option<&crate::tracey_ban::BanAdvertisement>,
    fault_advertisement: Option<&crate::tracey_guard::FaultAdvertisement>,
    key: &[u8; 32],
) -> String {
    let ban_digest = ban_advertisement
        .and_then(|advertisement| serde_json::to_vec(advertisement).ok())
        .map(|payload| blake3::hash(&payload).to_hex().to_string())
        .unwrap_or_default();
    let fault_digest = fault_advertisement
        .and_then(|advertisement| serde_json::to_vec(advertisement).ok())
        .map(|payload| blake3::hash(&payload).to_hex().to_string())
        .unwrap_or_default();
    let probe_digest = role
        .prometheus_probe
        .as_ref()
        .and_then(|probe| serde_json::to_vec(probe).ok())
        .map(|payload| blake3::hash(&payload).to_hex().to_string())
        .unwrap_or_default();
    let payload = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        agent_id,
        agent_version,
        ts_ms,
        addr.unwrap_or(""),
        status_addr.unwrap_or(""),
        capabilities.os,
        capabilities.arch,
        capabilities.cpu_cores,
        capabilities.tags.join(","),
        role.is_coordinator,
        role.epoch,
        role.score,
        ban_digest,
        fault_digest,
        probe_digest
    );
    let hash = blake3::keyed_hash(key, payload.as_bytes());
    to_hex(hash.as_bytes())
}

fn sign_payload_legacy(
    agent_id: &str,
    ts_ms: u64,
    addr: Option<&str>,
    capabilities: &Capabilities,
    role: &CoordinatorRole,
    status_addr: Option<&str>,
    ban_advertisement: Option<&crate::tracey_ban::BanAdvertisement>,
    fault_advertisement: Option<&crate::tracey_guard::FaultAdvertisement>,
    key: &[u8; 32],
) -> String {
    let ban_digest = ban_advertisement
        .and_then(|advertisement| serde_json::to_vec(advertisement).ok())
        .map(|payload| blake3::hash(&payload).to_hex().to_string())
        .unwrap_or_default();
    let fault_digest = fault_advertisement
        .and_then(|advertisement| serde_json::to_vec(advertisement).ok())
        .map(|payload| blake3::hash(&payload).to_hex().to_string())
        .unwrap_or_default();
    let probe_digest = role
        .prometheus_probe
        .as_ref()
        .and_then(|probe| serde_json::to_vec(probe).ok())
        .map(|payload| blake3::hash(&payload).to_hex().to_string())
        .unwrap_or_default();
    let payload = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        agent_id,
        ts_ms,
        addr.unwrap_or(""),
        status_addr.unwrap_or(""),
        capabilities.os,
        capabilities.arch,
        capabilities.cpu_cores,
        capabilities.tags.join(","),
        role.is_coordinator,
        role.epoch,
        role.score,
        ban_digest,
        fault_digest,
        probe_digest
    );
    let hash = blake3::keyed_hash(key, payload.as_bytes());
    to_hex(hash.as_bytes())
}

fn derive_key(shared: &str) -> [u8; 32] {
    let hash = blake3::hash(shared.as_bytes());
    *hash.as_bytes()
}

fn to_hex(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(LUT[(b >> 4) as usize] as char);
        out.push(LUT[(b & 0x0f) as usize] as char);
    }
    out
}

fn normalize_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (ca, cb) in a.as_bytes().iter().zip(b.as_bytes().iter()) {
        diff |= ca ^ cb;
    }
    diff == 0
}

fn is_hex64(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn payload_preview(payload: &[u8], max: usize) -> String {
    let limit = payload.len().min(max);
    let preview = String::from_utf8_lossy(&payload[..limit]).to_string();
    preview.replace('\n', "\\n").replace('\r', "\\r")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::Capabilities;
    use crate::tracey_ban::{BanAdvertisement, BanAdvertisementEntry};
    use proptest::prelude::*;

    #[test]
    fn sanitize_announcement_drops_invalid_ban_entries() {
        let now = now_ms();
        let mut announcement = AgentAnnouncement {
            agent_id: "peer-1".to_string(),
            agent_version: Some("1.2.3".to_string()),
            ts_ms: now,
            addr: Some("10.0.0.2:47990".to_string()),
            status_addr: Some("10.0.0.2:48000".to_string()),
            ban_advertisement: Some(BanAdvertisement {
                ts_ms: now,
                epoch: 1,
                entries: vec![
                    BanAdvertisementEntry {
                        ip: "10.0.0.1".to_string(),
                        jail: "ssh".to_string(),
                        expires_ms: Some(now + 5_000),
                        ban_count: 1,
                        last_ban_ms: now,
                    },
                    BanAdvertisementEntry {
                        ip: "999.0.0.1".to_string(),
                        jail: "ssh".to_string(),
                        expires_ms: Some(now + 5_000),
                        ban_count: 1,
                        last_ban_ms: now,
                    },
                    BanAdvertisementEntry {
                        ip: "10.0.0.2".to_string(),
                        jail: "".to_string(),
                        expires_ms: Some(now + 5_000),
                        ban_count: 1,
                        last_ban_ms: now,
                    },
                    BanAdvertisementEntry {
                        ip: "10.0.0.3".to_string(),
                        jail: "ssh".to_string(),
                        expires_ms: Some(now.saturating_sub(1)),
                        ban_count: 1,
                        last_ban_ms: now,
                    },
                ],
            }),
            fault_advertisement: None,
            slurm: None,
            capabilities: Capabilities {
                os: "linux".to_string(),
                arch: "x86_64".to_string(),
                cpu_cores: 4,
                tags: vec!["test".to_string()],
            },
            signature: "0".repeat(64),
            is_coordinator: Some(false),
            coordinator_epoch: Some(1),
            score: Some(1),
            prometheus_probe: None,
        };

        sanitize_announcement(&mut announcement, 8, "127.0.0.1:12345", now);
        let entries = announcement
            .ban_advertisement
            .expect("advertisement present")
            .entries;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ip, "10.0.0.1");
    }

    proptest! {
        #[test]
        fn discovery_payload_parsing_is_panic_safe(payload in prop::collection::vec(any::<u8>(), 0..1024)) {
            if let Ok(mut announcement) = serde_json::from_slice::<AgentAnnouncement>(&payload) {
                let now = now_ms();
                let _ = validate_announcement_semantics(&announcement, 10_000, now);
                sanitize_announcement(&mut announcement, 64, "fuzz-peer", now);
                let _ = valid_signature(&announcement, &derive_key("fuzz-key"));
            }
        }

        #[test]
        fn discovery_semantic_validation_is_panic_safe(
            agent_id in ".{0,220}",
            signature in ".{0,120}",
            addr in prop::option::of(".{0,300}"),
            status_addr in prop::option::of(".{0,300}"),
            cpu_cores in 0usize..8usize,
            tags in prop::collection::vec(".{0,96}", 0..96),
            ts in any::<u64>(),
        ) {
            let announcement = AgentAnnouncement {
                agent_id,
                agent_version: None,
                ts_ms: ts,
                addr,
                status_addr,
                ban_advertisement: None,
                fault_advertisement: None,
                slurm: None,
                capabilities: Capabilities {
                    os: "linux".to_string(),
                    arch: "x86_64".to_string(),
                    cpu_cores,
                    tags,
                },
                signature,
                is_coordinator: Some(false),
                coordinator_epoch: Some(0),
                score: Some(0),
                prometheus_probe: None,
            };

            let _ = validate_announcement_semantics(&announcement, 20_000, now_ms());
        }
    }

    #[test]
    fn discovery_signature_binds_agent_version() {
        let key = derive_key("shared-key");
        let role = CoordinatorRole {
            agent_id: "peer-1".to_string(),
            score: 7,
            is_coordinator: true,
            leader_rank: 0,
            leader_count: 1,
            epoch: 3,
            last_update_ms: 1,
            proxy_agent_id: None,
            proxy_latency_ms: None,
            proxy_addr: None,
            is_prometheus_exporter: false,
            prometheus_exporter_agent_id: None,
            prometheus_exporter_addr: None,
            prometheus_exporter_latency_ms: None,
            prometheus_exporter_bandwidth_mbps: None,
            prometheus_probe: None,
        };
        let capabilities = Capabilities {
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            cpu_cores: 8,
            tags: vec!["room:lab".to_string()],
        };
        let ts_ms = 42;
        let signature = sign_payload(
            "peer-1",
            "1.2.3",
            ts_ms,
            Some("10.0.0.2:47990"),
            &capabilities,
            &role,
            Some("https://10.0.0.2:48000/status"),
            None,
            None,
            &key,
        );

        let mut announcement = AgentAnnouncement {
            agent_id: "peer-1".to_string(),
            agent_version: Some("1.2.3".to_string()),
            ts_ms,
            addr: Some("10.0.0.2:47990".to_string()),
            status_addr: Some("https://10.0.0.2:48000/status".to_string()),
            ban_advertisement: None,
            fault_advertisement: None,
            slurm: None,
            capabilities,
            signature,
            is_coordinator: Some(true),
            coordinator_epoch: Some(3),
            score: Some(7),
            prometheus_probe: None,
        };
        assert!(valid_signature(&announcement, &key));

        announcement.agent_version = Some("9.9.9".to_string());
        assert!(!valid_signature(&announcement, &key));
    }

    #[test]
    fn discovery_signature_accepts_legacy_announcements_without_version() {
        let key = derive_key("shared-key");
        let role = CoordinatorRole {
            agent_id: "peer-1".to_string(),
            score: 7,
            is_coordinator: false,
            leader_rank: 0,
            leader_count: 1,
            epoch: 2,
            last_update_ms: 1,
            proxy_agent_id: None,
            proxy_latency_ms: None,
            proxy_addr: None,
            is_prometheus_exporter: false,
            prometheus_exporter_agent_id: None,
            prometheus_exporter_addr: None,
            prometheus_exporter_latency_ms: None,
            prometheus_exporter_bandwidth_mbps: None,
            prometheus_probe: None,
        };
        let capabilities = Capabilities {
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            cpu_cores: 4,
            tags: vec!["test".to_string()],
        };
        let ts_ms = 55;
        let signature = sign_payload_legacy(
            "peer-1",
            ts_ms,
            Some("10.0.0.2:47990"),
            &capabilities,
            &role,
            Some("http://10.0.0.2:48000/status"),
            None,
            None,
            &key,
        );
        let announcement = AgentAnnouncement {
            agent_id: "peer-1".to_string(),
            agent_version: None,
            ts_ms,
            addr: Some("10.0.0.2:47990".to_string()),
            status_addr: Some("http://10.0.0.2:48000/status".to_string()),
            ban_advertisement: None,
            fault_advertisement: None,
            slurm: None,
            capabilities,
            signature,
            is_coordinator: Some(false),
            coordinator_epoch: Some(2),
            score: Some(7),
            prometheus_probe: None,
        };
        assert!(valid_signature(&announcement, &key));
    }

    #[test]
    fn fuzzy_discovery_parser_recovers_wrapped_camel_case_payload() {
        let key = derive_key("shared-key");
        let role = CoordinatorRole {
            agent_id: "peer-42".to_string(),
            score: 9,
            is_coordinator: true,
            leader_rank: 0,
            leader_count: 1,
            epoch: 5,
            last_update_ms: 1,
            proxy_agent_id: None,
            proxy_latency_ms: None,
            proxy_addr: None,
            is_prometheus_exporter: false,
            prometheus_exporter_agent_id: None,
            prometheus_exporter_addr: None,
            prometheus_exporter_latency_ms: None,
            prometheus_exporter_bandwidth_mbps: None,
            prometheus_probe: Some(PrometheusProbe {
                ready: true,
                latency_ms: 12,
                bandwidth_mbps: 37.5,
                sampled_at_ms: 77,
            }),
        };
        let capabilities = Capabilities {
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            cpu_cores: 8,
            tags: vec!["room:lab".to_string(), "jetson".to_string()],
        };
        let signature = sign_payload(
            "peer-42",
            "2.4.6",
            77,
            Some("10.0.0.42:47990"),
            &capabilities,
            &role,
            Some("https://10.0.0.42:48000/status"),
            None,
            None,
            &key,
        );
        let payload = serde_json::json!({
            "wrapper": {
                "announcement": {
                    "agentId": "peer-42",
                    "agentVersion": "2.4.6",
                    "timestamp_ms": "77",
                    "advertiseAddr": "10.0.0.42:47990",
                    "statusUrl": "https://10.0.0.42:48000/status",
                    "traits": {
                        "platform": "linux",
                        "architecture": "x86_64",
                        "cores": "8",
                        "labels": "room:lab, jetson"
                    },
                    "leader": "true",
                    "epoch": "5",
                    "weight": "9",
                    "probe": {
                        "healthy": "true",
                        "latency": "12ms",
                        "bandwidth": "37.5",
                        "updated_ms": "77"
                    },
                    "sig": signature
                }
            }
        })
        .to_string();

        let (announcement, affinity) =
            parse_announcement_lossy(payload.as_bytes()).expect("payload should recover");

        assert!(affinity >= 2.4);
        assert_eq!(announcement.agent_id, "peer-42");
        assert_eq!(announcement.agent_version.as_deref(), Some("2.4.6"));
        assert_eq!(announcement.capabilities.cpu_cores, 8);
        assert_eq!(
            announcement.capabilities.tags,
            vec!["room:lab".to_string(), "jetson".to_string()]
        );
        assert_eq!(announcement.score, Some(9));
        assert!(valid_signature(&announcement, &key));
    }
}
