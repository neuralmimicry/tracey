//! Telemetry-driven Continuum autoscaler for Tracey deployments.

use crate::config::ContinuumAutoscalerConfig;
use crate::coordination::CoordinatorRole;
use crate::event::now_ms;
use crate::shutdown::ShutdownListener;
use crate::slurm::SlurmRuntimeHandle;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::MissedTickBehavior;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ContinuumAutoscalerSnapshot {
    pub enabled: bool,
    pub controller_role: String,
    pub requested_remote_nodes: usize,
    pub active_remote_nodes: usize,
    pub last_action: Option<String>,
    pub pressure_signals: Vec<String>,
    pub local_cpu_usage_pct: Option<f32>,
    pub local_memory_usage_pct: Option<f32>,
    pub coordination_latency_ms: Option<u64>,
    pub prometheus_latency_ms: Option<u64>,
    pub slurm_pending_jobs: Option<u32>,
    pub slurm_allocated_ratio: Option<f32>,
    pub last_evaluated_ms: u64,
}

#[derive(Clone)]
pub struct ContinuumAutoscalerHandle {
    snapshot: Arc<RwLock<ContinuumAutoscalerSnapshot>>,
}

impl ContinuumAutoscalerHandle {
    pub fn disabled() -> Self {
        Self {
            snapshot: Arc::new(RwLock::new(ContinuumAutoscalerSnapshot {
                enabled: false,
                controller_role: "disabled".to_string(),
                last_action: Some("continuum autoscaler disabled".to_string()),
                last_evaluated_ms: now_ms(),
                ..ContinuumAutoscalerSnapshot::default()
            })),
        }
    }

    pub async fn snapshot(&self) -> ContinuumAutoscalerSnapshot {
        self.snapshot.read().await.clone()
    }
}

fn normalize_grpc_name(raw: &str) -> String {
    raw.trim()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_lowercase()
}

async fn recruit_host(
    client: &reqwest::Client,
    config: &ContinuumAutoscalerConfig,
    host: &str,
    agent_id: &str,
) -> anyhow::Result<()> {
    let url = format!("{}/node/recruit", config.base_url.trim_end_matches('/'));
    let mut request = client.post(url).header(CONTENT_TYPE, "application/json");
    if let Some(token) = config.bearer_token.as_deref() {
        request = request.header(AUTHORIZATION, format!("Bearer {}", token));
    }

    let mut body = serde_json::json!({
        "host": host,
        "user": config.recruit_user,
        "node_type": config.node_type,
        "name": format!("{}-{}", normalize_grpc_name(agent_id), normalize_grpc_name(host)),
        "dry_run": config.dry_run,
        "auto_configure": config.auto_configure,
    });
    if let Some(path) = config.ssh_key_path.as_deref() {
        body["ssh_key_path"] = serde_json::Value::String(path.to_string());
    }
    if let Some(region) = config.region.as_deref() {
        body["region"] = serde_json::Value::String(region.to_string());
    }
    if let Some(tenant_id) = config.tenant_id.as_deref() {
        body["tenant_id"] = serde_json::Value::String(tenant_id.to_string());
    }
    if let Some(tenant_name) = config.tenant_name.as_deref() {
        body["tenant_name"] = serde_json::Value::String(tenant_name.to_string());
    }
    if let Some(tenant_environment) = config.tenant_environment.as_deref() {
        body["tenant_environment"] = serde_json::Value::String(tenant_environment.to_string());
    }
    if let Some(recruit_token) = config.recruit_token.as_deref() {
        body["recruit_token"] = serde_json::Value::String(recruit_token.to_string());
    }

    let response = request
        .json(&body)
        .send()
        .await
        .map_err(|err| anyhow::anyhow!("continuum recruit request failed: {}", err))?;
    if !response.status().is_success() {
        let message = response
            .text()
            .await
            .unwrap_or_else(|_| "recruit failed".to_string());
        anyhow::bail!("continuum recruit failed for '{}': {}", host, message);
    }
    Ok(())
}

pub fn spawn_continuum_autoscaler(
    config: ContinuumAutoscalerConfig,
    agent_id: String,
    coordination_role: Arc<RwLock<CoordinatorRole>>,
    slurm: SlurmRuntimeHandle,
    mut shutdown: ShutdownListener,
) -> ContinuumAutoscalerHandle {
    if !config.enabled {
        return ContinuumAutoscalerHandle::disabled();
    }

    let handle = ContinuumAutoscalerHandle {
        snapshot: Arc::new(RwLock::new(ContinuumAutoscalerSnapshot {
            enabled: true,
            controller_role: "standby".to_string(),
            last_evaluated_ms: now_ms(),
            ..ContinuumAutoscalerSnapshot::default()
        })),
    };
    let snapshot = handle.snapshot.clone();
    tokio::spawn(async move {
        let client = reqwest::Client::new();
        let mut interval = tokio::time::interval(Duration::from_millis(config.poll_interval_ms));
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut recruited_hosts = HashSet::new();
        let mut system = sysinfo::System::new();

        loop {
            tokio::select! {
                _ = shutdown.wait() => {
                    break;
                }
                _ = interval.tick() => {}
            }

            system.refresh_cpu_usage();
            system.refresh_memory();
            let local_cpu_usage_pct = system.global_cpu_usage();
            let local_memory_usage_pct = if system.total_memory() > 0 {
                100.0 * (1.0 - (system.available_memory() as f32 / system.total_memory() as f32))
            } else {
                0.0
            };

            let role = coordination_role.read().await.clone();
            let slurm_snapshot = slurm.snapshot().await;
            let coordination_latency_ms = role.proxy_latency_ms;
            let prometheus_latency_ms = role
                .prometheus_exporter_latency_ms
                .or_else(|| role.prometheus_probe.as_ref().map(|probe| probe.latency_ms));
            let slurm_pending_jobs = slurm_snapshot
                .as_ref()
                .map(|snapshot| snapshot.jobs_pending);
            let slurm_allocated_ratio = slurm_snapshot.as_ref().map(|snapshot| {
                if snapshot.nodes_total == 0 {
                    0.0
                } else {
                    snapshot.nodes_allocated as f32 / snapshot.nodes_total as f32
                }
            });

            let mut pressure_signals = Vec::new();
            if local_cpu_usage_pct >= config.local_cpu_usage_pct {
                pressure_signals.push(format!(
                    "local cpu {:.1}% >= {:.1}%",
                    local_cpu_usage_pct, config.local_cpu_usage_pct
                ));
            }
            if local_memory_usage_pct >= config.local_memory_usage_pct {
                pressure_signals.push(format!(
                    "local memory {:.1}% >= {:.1}%",
                    local_memory_usage_pct, config.local_memory_usage_pct
                ));
            }
            if let Some(latency_ms) = coordination_latency_ms {
                if latency_ms >= config.coordination_latency_ms {
                    pressure_signals.push(format!(
                        "coordination latency {}ms >= {}ms",
                        latency_ms, config.coordination_latency_ms
                    ));
                }
            }
            if let Some(latency_ms) = prometheus_latency_ms {
                if latency_ms >= config.prometheus_latency_ms {
                    pressure_signals.push(format!(
                        "prometheus latency {}ms >= {}ms",
                        latency_ms, config.prometheus_latency_ms
                    ));
                }
            }
            if let Some(pending_jobs) = slurm_pending_jobs {
                if pending_jobs >= config.slurm_pending_jobs {
                    pressure_signals.push(format!(
                        "slurm pending jobs {} >= {}",
                        pending_jobs, config.slurm_pending_jobs
                    ));
                }
            }
            if let Some(allocated_ratio) = slurm_allocated_ratio {
                if allocated_ratio >= config.slurm_allocated_ratio {
                    pressure_signals.push(format!(
                        "slurm allocated ratio {:.2} >= {:.2}",
                        allocated_ratio, config.slurm_allocated_ratio
                    ));
                }
            }

            let controller = role.is_coordinator && role.leader_rank == 0;
            let requested_remote_nodes = if pressure_signals.is_empty() {
                0
            } else {
                1 + pressure_signals.len().saturating_sub(1) / 2
            }
            .min(config.recruit_hosts.len());

            let mut last_action = if controller {
                None
            } else {
                Some("standby: another Tracey coordinator owns scaling".to_string())
            };

            if controller {
                let mut recruited_this_tick = 0usize;
                while recruited_hosts.len() < requested_remote_nodes
                    && recruited_this_tick < config.max_recruits_per_tick
                {
                    let Some(next_host) = config
                        .recruit_hosts
                        .iter()
                        .find(|host| !recruited_hosts.contains(*host))
                        .cloned()
                    else {
                        last_action = Some(
                            "no unused Continuum hosts remain for telemetry-driven scale out"
                                .to_string(),
                        );
                        break;
                    };

                    match recruit_host(&client, &config, &next_host, &agent_id).await {
                        Ok(()) => {
                            recruited_hosts.insert(next_host.clone());
                            recruited_this_tick += 1;
                            let reason = if pressure_signals.is_empty() {
                                "telemetry signalled scale-out".to_string()
                            } else {
                                pressure_signals.join(", ")
                            };
                            last_action = Some(format!(
                                "recruited Continuum host '{}' due to {}",
                                next_host, reason
                            ));
                        }
                        Err(err) => {
                            last_action = Some(format!(
                                "failed recruiting Continuum host '{}': {}",
                                next_host, err
                            ));
                            break;
                        }
                    }
                }
            }

            *snapshot.write().await = ContinuumAutoscalerSnapshot {
                enabled: true,
                controller_role: if controller {
                    "controller".to_string()
                } else {
                    "standby".to_string()
                },
                requested_remote_nodes,
                active_remote_nodes: recruited_hosts.len(),
                last_action,
                pressure_signals,
                local_cpu_usage_pct: Some(local_cpu_usage_pct),
                local_memory_usage_pct: Some(local_memory_usage_pct),
                coordination_latency_ms,
                prometheus_latency_ms,
                slurm_pending_jobs,
                slurm_allocated_ratio,
                last_evaluated_ms: now_ms(),
            };
        }
    });

    handle
}
