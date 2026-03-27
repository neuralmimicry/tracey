//! Authenticated UDP gossip for peer discovery and distributed intelligence.
//!
//! Announcements include capability data and optional TraceyBan/TraceyGuard
//! advertisements signed with a shared-key digest.

use crate::capabilities::Capabilities;
use crate::config::DiscoveryConfig;
use crate::coordination::CoordinatorRole;
use crate::event::now_ms;
use crate::governance::GovernanceState;
use crate::inventory::Inventory;
use crate::shutdown::ShutdownListener;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Duration;
use tokio::net::UdpSocket;

const MAX_FUTURE_SKEW_MS: u64 = 30_000;
const MAX_AGENT_ID_LEN: usize = 128;
const MAX_ADDR_LEN: usize = 256;
const MAX_TAGS: usize = 64;
const MAX_TAG_LEN: usize = 64;
const DISCOVERY_PREVIEW_BYTES: usize = 160;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentAnnouncement {
    pub agent_id: String,
    pub ts_ms: u64,
    pub addr: Option<String>,
    pub status_addr: Option<String>,
    pub ban_advertisement: Option<crate::tracey_ban::BanAdvertisement>,
    pub fault_advertisement: Option<crate::tracey_guard::FaultAdvertisement>,
    pub capabilities: Capabilities,
    pub signature: String,
    pub is_coordinator: Option<bool>,
    pub coordinator_epoch: Option<u64>,
    pub score: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentPresence {
    pub agent_id: String,
    pub ts_ms: u64,
    pub addr: Option<String>,
    pub status_addr: Option<String>,
    pub ban_advertisement: Option<crate::tracey_ban::BanAdvertisement>,
    pub fault_advertisement: Option<crate::tracey_guard::FaultAdvertisement>,
    pub capabilities: Capabilities,
    pub source: String,
    pub is_coordinator: Option<bool>,
    pub coordinator_epoch: Option<u64>,
    pub score: Option<u64>,
}

pub async fn spawn_discovery(
    config: DiscoveryConfig,
    agent_id: String,
    inventory: Inventory,
    mut shutdown: ShutdownListener,
    governance_state: std::sync::Arc<tokio::sync::RwLock<GovernanceState>>,
    coordinator_role: std::sync::Arc<tokio::sync::RwLock<CoordinatorRole>>,
    coordination: crate::coordination::Coordination,
    status_addr: Option<String>,
    capabilities: Capabilities,
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
                    let announcement = build_announcement(
                        &agent_id,
                        &config,
                        &capabilities,
                        &shared_key,
                        &role,
                        status_addr.as_deref(),
                        ban_advertisement,
                        fault_advertisement,
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
                            tracing::warn!(
                                peer = %peer,
                                size,
                                error = %err,
                                payload_preview = %payload_preview(&buf[..size], DISCOVERY_PREVIEW_BYTES),
                                "invalid discovery announcement format"
                            );
                            continue;
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
                        ts_ms: announcement.ts_ms,
                        addr: announcement.addr,
                        status_addr: announcement.status_addr,
                        ban_advertisement: announcement.ban_advertisement.clone(),
                        fault_advertisement: announcement.fault_advertisement.clone(),
                        capabilities: announcement.capabilities,
                        source: "gossip".to_string(),
                        is_coordinator: announcement.is_coordinator,
                        coordinator_epoch: announcement.coordinator_epoch,
                        score: announcement.score,
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
    config: &DiscoveryConfig,
    capabilities: &Capabilities,
    key: &[u8; 32],
    role: &CoordinatorRole,
    status_addr: Option<&str>,
    ban_advertisement: Option<crate::tracey_ban::BanAdvertisement>,
    fault_advertisement: Option<crate::tracey_guard::FaultAdvertisement>,
) -> AgentAnnouncement {
    let ts_ms = now_ms();
    let addr = config.advertise_addr.clone();
    let signature = sign_payload(
        agent_id,
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
        ts_ms,
        addr,
        status_addr: status_addr.map(|v| v.to_string()),
        ban_advertisement,
        fault_advertisement,
        capabilities: capabilities.clone(),
        signature,
        is_coordinator: Some(role.is_coordinator),
        coordinator_epoch: Some(role.epoch),
        score: Some(role.score),
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
    };
    let expected = sign_payload(
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
    normalize_eq(&announcement.signature, &expected)
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

fn sanitize_announcement(
    announcement: &mut AgentAnnouncement,
    max_advertised_ips: usize,
    peer: &str,
    now: u64,
) {
    let Some(advertisement) = announcement.ban_advertisement.as_mut() else {
        return;
    };

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
    let payload = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
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
        fault_digest
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
                ts_ms: ts,
                addr,
                status_addr,
                ban_advertisement: None,
                fault_advertisement: None,
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
            };

            let _ = validate_announcement_semantics(&announcement, 20_000, now_ms());
        }
    }
}
