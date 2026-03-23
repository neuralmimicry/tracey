use crate::capabilities::Capabilities;
use crate::config::CoordinationConfig;
use crate::discovery::AgentPresence;
use crate::event::now_ms;
use crate::governance::GovernanceState;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoordinatorRole {
    pub agent_id: String,
    pub score: u64,
    pub is_coordinator: bool,
    pub leader_rank: usize,
    pub leader_count: usize,
    pub epoch: u64,
    pub last_update_ms: u64,
    pub proxy_agent_id: Option<String>,
    pub proxy_latency_ms: Option<u64>,
    pub proxy_addr: Option<String>,
}

#[derive(Clone, Debug)]
pub struct PresenceRecord {
    pub agent_id: String,
    pub score: u64,
    pub cpu_cores: usize,
    pub latency_ms: u64,
    pub status_addr: Option<String>,
    pub tags: Vec<String>,
    pub is_coordinator: bool,
    pub epoch: u64,
    pub last_seen_ms: u64,
}

#[derive(Clone)]
pub struct Coordination {
    config: CoordinationConfig,
    role: Arc<RwLock<CoordinatorRole>>,
    presence: Arc<RwLock<HashMap<String, PresenceRecord>>>,
    local_capabilities: Capabilities,
}

impl Coordination {
    pub fn new(
        agent_id: String,
        config: CoordinationConfig,
        shared_key: &str,
        local_capabilities: Capabilities,
    ) -> Self {
        let score = score_agent(&agent_id, shared_key);
        let role = CoordinatorRole {
            agent_id: agent_id.clone(),
            score,
            is_coordinator: false,
            leader_rank: 0,
            leader_count: 0,
            epoch: 0,
            last_update_ms: now_ms(),
            proxy_agent_id: None,
            proxy_latency_ms: None,
            proxy_addr: None,
        };
        Self {
            config,
            role: Arc::new(RwLock::new(role)),
            presence: Arc::new(RwLock::new(HashMap::new())),
            local_capabilities,
        }
    }

    pub fn role_handle(&self) -> Arc<RwLock<CoordinatorRole>> {
        self.role.clone()
    }

    #[allow(dead_code)]
    pub async fn proxy_agent(&self) -> Option<String> {
        self.role.read().await.proxy_agent_id.clone()
    }

    pub async fn record_presence(&self, presence: AgentPresence) {
        let seen = now_ms();
        let latency_ms = seen.saturating_sub(presence.ts_ms);
        let mut map = self.presence.write().await;
        map.insert(
            presence.agent_id.clone(),
            PresenceRecord {
                agent_id: presence.agent_id,
                score: presence.score.unwrap_or(0),
                cpu_cores: presence.capabilities.cpu_cores,
                latency_ms,
                status_addr: presence.status_addr,
                tags: presence.capabilities.tags,
                is_coordinator: presence.is_coordinator.unwrap_or(false),
                epoch: presence.coordinator_epoch.unwrap_or(0),
                last_seen_ms: seen,
            },
        );
    }

    #[allow(dead_code)]
    pub async fn is_coordinator(&self) -> bool {
        self.role.read().await.is_coordinator
    }

    pub async fn spawn_election(self, governance: Arc<RwLock<GovernanceState>>) {
        if !self.config.enabled {
            tracing::info!("coordination disabled");
            return;
        }

        let mut interval =
            tokio::time::interval(Duration::from_millis(self.config.election_interval_ms));
        loop {
            interval.tick().await;
            if !governance.read().await.coordination_enabled {
                continue;
            }
            self.evaluate().await;
        }
    }

    async fn evaluate(&self) {
        let now = now_ms();
        let ttl = self.config.presence_ttl_ms;

        let mut map = self.presence.write().await;
        map.retain(|_, record| now.saturating_sub(record.last_seen_ms) <= ttl);

        let local = self.role.read().await.clone();
        map.entry(local.agent_id.clone()).or_insert(PresenceRecord {
            agent_id: local.agent_id.clone(),
            score: local.score,
            cpu_cores: self.local_capabilities.cpu_cores,
            latency_ms: 0,
            status_addr: None,
            tags: self.local_capabilities.tags.clone(),
            is_coordinator: local.is_coordinator,
            epoch: local.epoch,
            last_seen_ms: now,
        });

        let coordinator_count = map.values().filter(|record| record.is_coordinator).count();
        if coordinator_count == 0 {
            tracing::debug!("no coordinators detected; electing leader");
        } else if coordinator_count > 1 {
            tracing::warn!(
                count = coordinator_count,
                "split-brain detected; reconciling"
            );
        }

        let mut candidates: Vec<(f64, &PresenceRecord)> = map
            .values()
            .map(|record| (weighted_score(record, &self.config), record))
            .collect();
        candidates.sort_by(|a, b| {
            b.0.partial_cmp(&a.0)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.1.agent_id.cmp(&b.1.agent_id))
        });

        let leader_count = self.config.max_coordinators.max(1).min(candidates.len());
        let leaders = &candidates[..leader_count];
        let should_lead = leaders
            .iter()
            .any(|(_, record)| record.agent_id == local.agent_id);
        let leader_rank = leaders
            .iter()
            .position(|(_, record)| record.agent_id == local.agent_id)
            .unwrap_or(usize::MAX);

        let proxy = select_proxy(&candidates, &leaders);

        let mut role = self.role.write().await;
        if role.is_coordinator != should_lead {
            role.is_coordinator = should_lead;
            role.epoch = role.epoch.saturating_add(1);
            role.last_update_ms = now;
            tracing::info!(
                agent_id = %role.agent_id,
                coordinator = role.is_coordinator,
                epoch = role.epoch,
                "coordinator role updated"
            );
        }
        role.leader_rank = leader_rank;
        role.leader_count = leader_count;
        role.proxy_agent_id = proxy.map(|entry| entry.agent_id.clone());
        role.proxy_latency_ms = proxy.map(|entry| entry.latency_ms);
        role.proxy_addr = proxy.and_then(|entry| entry.status_addr.clone());

        if let Some(entry) = map.get_mut(&role.agent_id) {
            entry.is_coordinator = role.is_coordinator;
            entry.epoch = role.epoch;
            entry.last_seen_ms = now;
        }
    }
}

fn score_agent(agent_id: &str, shared_key: &str) -> u64 {
    let seed = format!("{}::{}", shared_key, agent_id);
    let hash = blake3::hash(seed.as_bytes());
    let bytes = hash.as_bytes();
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

fn weighted_score(record: &PresenceRecord, config: &CoordinationConfig) -> f64 {
    let cpu_score = record.cpu_cores as f64;
    let latency_score = 1_000_000f64 / (1.0 + record.latency_ms as f64);
    let hash_score = (record.score as f64) / (u64::MAX as f64);

    cpu_score * config.weight_cpu
        + latency_score * config.weight_latency
        + hash_score * config.weight_hash
        + capability_score(record) * config.weight_capability
}

fn capability_score(record: &PresenceRecord) -> f64 {
    let mut score = 0.0;
    for tag in &record.tags {
        let lower = tag.to_lowercase();
        if let Some(soc) = lower.strip_prefix("soc:") {
            score += soc_weight(soc);
        }
        if lower.starts_with("board:") {
            score += 0.2;
        }
        if lower == "jetson" {
            score += 0.8;
        }
        if lower == "vendor:nvidia" {
            score += 0.4;
        }
    }
    score
}

fn soc_weight(soc: &str) -> f64 {
    if soc.contains("orin") {
        1.2
    } else if soc.contains("xavier") {
        0.9
    } else if soc.contains("tegra") {
        0.6
    } else {
        0.2
    }
}

fn select_proxy<'a>(
    all: &'a [(f64, &'a PresenceRecord)],
    leaders: &'a [(f64, &'a PresenceRecord)],
) -> Option<&'a PresenceRecord> {
    let candidates = if leaders.is_empty() { all } else { leaders };
    candidates
        .iter()
        .min_by(|a, b| a.1.latency_ms.cmp(&b.1.latency_ms))
        .map(|(_, record)| *record)
}
