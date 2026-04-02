//! Distributed coordination and leader election for multi-agent deployments.
//!
//! Election uses weighted scoring from compute capacity, network latency,
//! deterministic hash score, and optional capability tags.

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

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PrometheusProbe {
    pub ready: bool,
    pub latency_ms: u64,
    pub bandwidth_mbps: f64,
    pub sampled_at_ms: u64,
}

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
    #[serde(default)]
    pub is_prometheus_exporter: bool,
    #[serde(default)]
    pub prometheus_exporter_agent_id: Option<String>,
    #[serde(default)]
    pub prometheus_exporter_addr: Option<String>,
    #[serde(default)]
    pub prometheus_exporter_latency_ms: Option<u64>,
    #[serde(default)]
    pub prometheus_exporter_bandwidth_mbps: Option<f64>,
    #[serde(default)]
    pub prometheus_probe: Option<PrometheusProbe>,
}

#[derive(Clone, Debug)]
pub struct PresenceRecord {
    pub agent_id: String,
    pub agent_version: Option<String>,
    pub score: u64,
    pub cpu_cores: usize,
    pub os: String,
    pub arch: String,
    pub latency_ms: u64,
    pub advertise_addr: Option<String>,
    pub status_addr: Option<String>,
    pub observed_addr: Option<String>,
    pub tags: Vec<String>,
    pub is_coordinator: bool,
    pub epoch: u64,
    pub last_seen_ms: u64,
    pub prometheus_probe: Option<PrometheusProbe>,
}

#[derive(Clone)]
pub struct Coordination {
    config: CoordinationConfig,
    role: Arc<RwLock<CoordinatorRole>>,
    presence: Arc<RwLock<HashMap<String, PresenceRecord>>>,
    local_capabilities: Capabilities,
    local_version: String,
    local_prometheus_probe: Arc<RwLock<Option<PrometheusProbe>>>,
}

impl Coordination {
    /// Creates a coordination state for the local agent.
    pub fn new(
        agent_id: String,
        config: CoordinationConfig,
        shared_key: &str,
        local_capabilities: Capabilities,
        local_version: String,
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
            is_prometheus_exporter: false,
            prometheus_exporter_agent_id: None,
            prometheus_exporter_addr: None,
            prometheus_exporter_latency_ms: None,
            prometheus_exporter_bandwidth_mbps: None,
            prometheus_probe: None,
        };
        Self {
            config,
            role: Arc::new(RwLock::new(role)),
            presence: Arc::new(RwLock::new(HashMap::new())),
            local_capabilities,
            local_version,
            local_prometheus_probe: Arc::new(RwLock::new(None)),
        }
    }

    /// Returns a shared role state handle for status/reporting paths.
    pub fn role_handle(&self) -> Arc<RwLock<CoordinatorRole>> {
        self.role.clone()
    }

    #[allow(dead_code)]
    pub async fn proxy_agent(&self) -> Option<String> {
        self.role.read().await.proxy_agent_id.clone()
    }

    pub async fn update_prometheus_probe(&self, probe: Option<PrometheusProbe>) {
        *self.local_prometheus_probe.write().await = probe.clone();
        let now = now_ms();
        let local = self.role.read().await.clone();
        let mut map = self.presence.write().await;
        if let Some(entry) = map.get_mut(&local.agent_id) {
            entry.prometheus_probe = probe;
            entry.last_seen_ms = now;
        }
    }

    /// Updates presence cache with a gossip announcement.
    pub async fn record_presence(&self, presence: AgentPresence) {
        let seen = now_ms();
        let latency_ms = seen.saturating_sub(presence.ts_ms);
        let mut map = self.presence.write().await;
        map.insert(
            presence.agent_id.clone(),
            PresenceRecord {
                agent_id: presence.agent_id,
                agent_version: presence.agent_version,
                score: presence.score.unwrap_or(0),
                cpu_cores: presence.capabilities.cpu_cores,
                os: presence.capabilities.os,
                arch: presence.capabilities.arch,
                latency_ms,
                advertise_addr: presence.addr,
                status_addr: presence.status_addr,
                observed_addr: presence.observed_addr,
                tags: presence.capabilities.tags,
                is_coordinator: presence.is_coordinator.unwrap_or(false),
                epoch: presence.coordinator_epoch.unwrap_or(0),
                last_seen_ms: seen,
                prometheus_probe: presence.prometheus_probe,
            },
        );
    }

    #[allow(dead_code)]
    pub async fn is_coordinator(&self) -> bool {
        self.role.read().await.is_coordinator
    }

    pub async fn presence_snapshot(&self) -> Vec<PresenceRecord> {
        let now = now_ms();
        let local = self.role.read().await.clone();
        let local_probe = self.local_prometheus_probe.read().await.clone();

        let mut records: Vec<PresenceRecord> =
            self.presence.read().await.values().cloned().collect();
        if let Some(local_record) = records
            .iter_mut()
            .find(|record| record.agent_id == local.agent_id)
        {
            local_record.agent_version = Some(self.local_version.clone());
            local_record.score = local.score;
            local_record.cpu_cores = self.local_capabilities.cpu_cores;
            local_record.os = self.local_capabilities.os.clone();
            local_record.arch = self.local_capabilities.arch.clone();
            local_record.latency_ms = 0;
            local_record.tags = self.local_capabilities.tags.clone();
            local_record.is_coordinator = local.is_coordinator;
            local_record.epoch = local.epoch;
            local_record.last_seen_ms = now;
            local_record.prometheus_probe = local_probe.clone();
        } else {
            records.push(PresenceRecord {
                agent_id: local.agent_id.clone(),
                agent_version: Some(self.local_version.clone()),
                score: local.score,
                cpu_cores: self.local_capabilities.cpu_cores,
                os: self.local_capabilities.os.clone(),
                arch: self.local_capabilities.arch.clone(),
                latency_ms: 0,
                advertise_addr: None,
                status_addr: None,
                observed_addr: None,
                tags: self.local_capabilities.tags.clone(),
                is_coordinator: local.is_coordinator,
                epoch: local.epoch,
                last_seen_ms: now,
                prometheus_probe: local_probe,
            });
        }

        records.sort_by(|left, right| {
            left.latency_ms
                .cmp(&right.latency_ms)
                .then_with(|| left.agent_id.cmp(&right.agent_id))
        });
        records
    }

    /// Runs periodic role elections while governance permits coordination.
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
        let local_probe = self.local_prometheus_probe.read().await.clone();
        map.entry(local.agent_id.clone()).or_insert(PresenceRecord {
            agent_id: local.agent_id.clone(),
            agent_version: Some(self.local_version.clone()),
            score: local.score,
            cpu_cores: self.local_capabilities.cpu_cores,
            os: self.local_capabilities.os.clone(),
            arch: self.local_capabilities.arch.clone(),
            latency_ms: 0,
            advertise_addr: None,
            status_addr: None,
            observed_addr: None,
            tags: self.local_capabilities.tags.clone(),
            is_coordinator: local.is_coordinator,
            epoch: local.epoch,
            last_seen_ms: now,
            prometheus_probe: local_probe.clone(),
        });
        if let Some(entry) = map.get_mut(&local.agent_id) {
            entry.agent_version = Some(self.local_version.clone());
            entry.prometheus_probe = local_probe.clone();
            entry.last_seen_ms = now;
        }

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
        let exporter = select_prometheus_exporter(&candidates, &self.config);

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
        role.is_prometheus_exporter = exporter
            .map(|entry| entry.agent_id == role.agent_id)
            .unwrap_or(false);
        role.prometheus_exporter_agent_id = exporter.map(|entry| entry.agent_id.clone());
        role.prometheus_exporter_addr = exporter.and_then(|entry| entry.status_addr.clone());
        role.prometheus_exporter_latency_ms = exporter
            .and_then(|entry| entry.prometheus_probe.as_ref())
            .map(|probe| probe.latency_ms);
        role.prometheus_exporter_bandwidth_mbps = exporter
            .and_then(|entry| entry.prometheus_probe.as_ref())
            .map(|probe| probe.bandwidth_mbps);
        role.prometheus_probe = local_probe;

        if let Some(entry) = map.get_mut(&role.agent_id) {
            entry.is_coordinator = role.is_coordinator;
            entry.epoch = role.epoch;
            entry.last_seen_ms = now;
            entry.prometheus_probe = role.prometheus_probe.clone();
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

fn select_prometheus_exporter<'a>(
    all: &'a [(f64, &'a PresenceRecord)],
    config: &CoordinationConfig,
) -> Option<&'a PresenceRecord> {
    let mut candidates: Vec<(bool, f64, &'a PresenceRecord)> = all
        .iter()
        .map(|(_, record)| {
            let ready = record
                .prometheus_probe
                .as_ref()
                .map(|probe| probe.ready)
                .unwrap_or(false);
            let score = if ready {
                prometheus_export_score(record, config)
            } else {
                weighted_score(record, config)
            };
            (ready, score, *record)
        })
        .collect();
    candidates.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal))
            .then_with(|| a.2.agent_id.cmp(&b.2.agent_id))
    });
    candidates.first().map(|(_, _, record)| *record)
}

fn prometheus_export_score(record: &PresenceRecord, config: &CoordinationConfig) -> f64 {
    let Some(probe) = record.prometheus_probe.as_ref() else {
        return f64::MIN;
    };
    if !probe.ready {
        return f64::MIN;
    }
    let latency_score = 1_000_000f64 / (1.0 + probe.latency_ms as f64);
    let bandwidth_score = (probe.bandwidth_mbps.max(0.0).ln_1p() * 100_000.0).max(0.0);
    latency_score * config.weight_prometheus_latency
        + bandwidth_score * config.weight_prometheus_bandwidth
        + weighted_score(record, config) * 0.05
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

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_record(agent_id: &str, latency_ms: u64, tags: Vec<&str>) -> PresenceRecord {
        PresenceRecord {
            agent_id: agent_id.to_string(),
            agent_version: Some(crate::package_version().to_string()),
            score: 123,
            cpu_cores: 8,
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            latency_ms,
            advertise_addr: Some(format!("{}:48000", agent_id)),
            status_addr: Some(format!("{}:48000", agent_id)),
            observed_addr: Some(format!("{}:47990", agent_id)),
            tags: tags.into_iter().map(|v| v.to_string()).collect(),
            is_coordinator: false,
            epoch: 1,
            last_seen_ms: now_ms(),
            prometheus_probe: None,
        }
    }

    #[test]
    fn score_agent_is_stable_for_same_input() {
        let a = score_agent("agent-1", "shared-key");
        let b = score_agent("agent-1", "shared-key");
        let c = score_agent("agent-2", "shared-key");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn weighted_score_prefers_lower_latency_when_weighted() {
        let cfg = CoordinationConfig {
            weight_cpu: 0.0,
            weight_latency: 1.0,
            weight_hash: 0.0,
            weight_capability: 0.0,
            ..CoordinationConfig::default()
        };
        let fast = mk_record("fast", 5, vec![]);
        let slow = mk_record("slow", 80, vec![]);
        assert!(weighted_score(&fast, &cfg) > weighted_score(&slow, &cfg));
    }

    #[test]
    fn capability_score_rewards_jetson_and_soc_tags() {
        let plain = mk_record("plain", 10, vec!["board:generic"]);
        let jetson = mk_record(
            "jetson",
            10,
            vec!["board:jetson", "jetson", "vendor:nvidia", "soc:orin"],
        );
        assert!(capability_score(&jetson) > capability_score(&plain));
    }

    #[test]
    fn select_proxy_chooses_lowest_latency_candidate() {
        let a = mk_record("a", 40, vec![]);
        let b = mk_record("b", 8, vec![]);
        let all = vec![(0.9, &a), (0.8, &b)];
        let leaders = vec![(0.9, &a), (0.8, &b)];
        let proxy = select_proxy(&all, &leaders).expect("proxy should exist");
        assert_eq!(proxy.agent_id, "b");
    }

    #[test]
    fn prometheus_exporter_prefers_ready_low_latency_high_bandwidth_probe() {
        let mut fast = mk_record("fast", 20, vec![]);
        fast.prometheus_probe = Some(PrometheusProbe {
            ready: true,
            latency_ms: 4,
            bandwidth_mbps: 80.0,
            sampled_at_ms: now_ms(),
        });
        let mut slow = mk_record("slow", 4, vec![]);
        slow.prometheus_probe = Some(PrometheusProbe {
            ready: true,
            latency_ms: 25,
            bandwidth_mbps: 10.0,
            sampled_at_ms: now_ms(),
        });
        let cfg = CoordinationConfig::default();
        let all = vec![(0.6, &slow), (0.4, &fast)];
        let exporter =
            select_prometheus_exporter(&all, &cfg).expect("exporter candidate should exist");
        assert_eq!(exporter.agent_id, "fast");
    }
}
