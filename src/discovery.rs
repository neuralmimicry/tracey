use crate::capabilities::Capabilities;
use crate::config::DiscoveryConfig;
use crate::coordination::CoordinatorRole;
use crate::event::now_ms;
use crate::governance::GovernanceState;
use crate::inventory::Inventory;
use crate::shutdown::ShutdownListener;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::net::UdpSocket;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentAnnouncement {
    pub agent_id: String,
    pub ts_ms: u64,
    pub addr: Option<String>,
    pub status_addr: Option<String>,
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
                    let announcement = build_announcement(
                        &agent_id,
                        &config,
                        &capabilities,
                        &shared_key,
                        &role,
                        status_addr.as_deref(),
                    );
                    let payload = serde_json::to_vec(&announcement).unwrap_or_default();
                    let _ = socket.send_to(&payload, &config.broadcast_addr).await;
                }
            }
            recv = socket.recv_from(&mut buf) => {
                if let Ok((size, _peer)) = recv {
                    if !governance_state.read().await.discovery_enabled {
                        continue;
                    }
                    if let Ok(mut announcement) = serde_json::from_slice::<AgentAnnouncement>(&buf[..size]) {
                        if announcement.agent_id == agent_id {
                            continue;
                        }
                        if !valid_signature(&mut announcement, &shared_key) {
                            tracing::warn!("discovery signature mismatch from {}", announcement.agent_id);
                            continue;
                        }
                        if now_ms().saturating_sub(announcement.ts_ms) > ttl {
                            continue;
                        }
                        let presence = AgentPresence {
                            agent_id: announcement.agent_id,
                            ts_ms: announcement.ts_ms,
                            addr: announcement.addr,
                            status_addr: announcement.status_addr,
                            capabilities: announcement.capabilities,
                            source: "gossip".to_string(),
                            is_coordinator: announcement.is_coordinator,
                            coordinator_epoch: announcement.coordinator_epoch,
                            score: announcement.score,
                        };
                        inventory.record_agent(presence.clone()).await;
                        coordination.record_presence(presence).await;
                    }
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
        key,
    );
    AgentAnnouncement {
        agent_id: agent_id.to_string(),
        ts_ms,
        addr,
        status_addr: status_addr.map(|v| v.to_string()),
        capabilities: capabilities.clone(),
        signature,
        is_coordinator: Some(role.is_coordinator),
        coordinator_epoch: Some(role.epoch),
        score: Some(role.score),
    }
}

fn valid_signature(announcement: &mut AgentAnnouncement, key: &[u8; 32]) -> bool {
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
        key,
    );
    normalize_eq(&announcement.signature, &expected)
}

fn sign_payload(
    agent_id: &str,
    ts_ms: u64,
    addr: Option<&str>,
    capabilities: &Capabilities,
    role: &CoordinatorRole,
    status_addr: Option<&str>,
    key: &[u8; 32],
) -> String {
    let payload = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
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
        role.score
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
