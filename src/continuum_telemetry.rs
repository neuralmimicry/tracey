//! Bounded host/GPU/action telemetry snapshot for Continuum-facing status APIs.

use crate::event::{Event, EventKind, Severity, now_ms};
use crate::security::Action;
use crate::shutdown::ShutdownListener;
use crate::swarm::Decision;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast};

const MAX_THERMALS: usize = 12;
const MAX_FANS: usize = 12;
const MAX_POWER_SENSORS: usize = 12;
const MAX_DISKS: usize = 8;
const MAX_PROCESSES: usize = 8;
const MAX_GPUS: usize = 32;
const MAX_NETWORK_PROCESSES: usize = 16;
const MAX_NETWORK_FLOWS: usize = 16;
const MAX_NETWORK_LISTENERS: usize = 16;
const MAX_RECENT_ACTIONS: usize = 48;
const MAX_DETAIL_LEN: usize = 160;
const MAX_LABEL_LEN: usize = 64;
const MAX_HOSTNAME_LEN: usize = 96;
const MIN_NETWORK_RETENTION_MS: u64 = 15_000;
const MAX_NETWORK_RETENTION_MS: u64 = 300_000;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ContinuumIdentitySnapshot {
    pub agent_id: String,
    pub host: String,
    pub zone: Option<String>,
    pub rack: Option<String>,
    pub row: Option<String>,
    pub site: Option<String>,
    pub building: Option<String>,
    pub room: Option<String>,
    pub network: Option<String>,
    pub physical: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ContinuumThermalSensor {
    pub name: String,
    pub label: String,
    pub sensor_type: Option<String>,
    pub temp_c: f64,
    pub severity: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ContinuumFanSensor {
    pub name: String,
    pub label: String,
    pub rpm: Option<u64>,
    pub pwm_percent: Option<f64>,
    pub severity: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ContinuumPowerSensor {
    pub name: String,
    pub label: String,
    pub power_w: f64,
    pub severity: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ContinuumEccSnapshot {
    pub corrected_total: u64,
    pub uncorrected_total: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ContinuumProcessSnapshot {
    pub pid: u32,
    pub name: String,
    pub cpu_pct: Option<f64>,
    pub mem_bytes: Option<f64>,
    pub io_bps: Option<f64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ContinuumDiskSnapshot {
    pub mount: String,
    pub used_ratio: Option<f64>,
    pub used_bytes: Option<f64>,
    pub total_bytes: Option<f64>,
    pub read_bps: Option<f64>,
    pub write_bps: Option<f64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ContinuumGpuSnapshot {
    pub gpu_id: String,
    pub name: Option<String>,
    pub vendor: Option<String>,
    pub source: Option<String>,
    pub slot_index: Option<u32>,
    pub util_pct: Option<f64>,
    pub temp_c: Option<f64>,
    pub power_w: Option<f64>,
    pub mem_used_bytes: Option<u64>,
    pub mem_total_bytes: Option<u64>,
    pub mem_used_pct: Option<f64>,
    pub graphics_clock_mhz: Option<u64>,
    pub memory_clock_mhz: Option<u64>,
    pub fan_speed_percent: Option<f64>,
    pub encoder_util_percent: Option<f64>,
    pub decoder_util_percent: Option<f64>,
    pub ecc_error_count: Option<u64>,
    pub guard_state: Option<String>,
    pub reliability_score: Option<f64>,
    pub probe_fail_count: Option<u64>,
    pub probe_error_count: Option<u64>,
    pub consecutive_failures: Option<u32>,
    pub sm_count: Option<u32>,
    pub last_guard_reason: Option<String>,
    pub last_guard_transition_ms: Option<u64>,
    pub last_guard_risk: Option<f64>,
    pub last_guard_confidence: Option<f64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ContinuumActionRecord {
    pub ts_ms: u64,
    pub category: String,
    pub action: String,
    pub detail: String,
    pub source: Option<String>,
    pub tone: String,
    pub score: Option<f64>,
    pub gpu_id: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ContinuumNetworkSummarySnapshot {
    pub window_ms: u64,
    pub updated_ms: u64,
    pub collector_backend: String,
    pub active_flows: usize,
    pub established_flows: usize,
    pub listeners: usize,
    pub owner_misses: usize,
    pub estimated_flows: usize,
    pub remote_endpoints: usize,
    pub cross_network_flows: usize,
    pub lan_flows: usize,
    pub local_host_flows: usize,
    pub unknown_remote_mac_flows: usize,
    pub udp_active_flows: usize,
    pub udp_drop_delta: u64,
    pub attributed_rx_bps: Option<f64>,
    pub attributed_tx_bps: Option<f64>,
    pub attributed_total_bps: Option<f64>,
    pub cross_network_bps: Option<f64>,
    pub udp_estimated_total_bps: Option<f64>,
    pub attribution_confidence: Option<f64>,
    pub latency_pressure: Option<f64>,
    pub queue_pressure: Option<f64>,
    pub queue_bytes: Option<f64>,
    pub rtt_ms_max: Option<f64>,
    pub traffic_growth_pct_per_min: f64,
    pub cross_network_growth_pct_per_min: f64,
    pub flow_growth_pct_per_min: f64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ContinuumNetworkFlowSnapshot {
    pub flow_id: String,
    pub pid: u32,
    pub process: String,
    pub protocol: String,
    pub socket_state: String,
    pub uid: u32,
    pub iface: Option<String>,
    pub local_ip: String,
    pub local_port: u16,
    pub local_mac: Option<String>,
    pub remote_ip: Option<String>,
    pub remote_port: Option<u16>,
    pub remote_mac: Option<String>,
    pub exe_path: Option<String>,
    pub cmdline: Option<String>,
    pub cgroup: Option<String>,
    pub rx_bps: Option<f64>,
    pub tx_bps: Option<f64>,
    pub total_bps: f64,
    pub queue_bytes: Option<f64>,
    pub collector_backend: String,
    pub attribution_confidence: Option<f64>,
    pub udp_drop_delta: Option<u64>,
    pub rtt_ms: Option<f64>,
    pub retransmits: Option<u32>,
    pub cross_network: bool,
    pub same_lan: bool,
    pub local_host: bool,
    pub bytes_estimated: bool,
    pub anomaly: bool,
    pub severity: String,
    pub last_seen_ms: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ContinuumNetworkProcessSnapshot {
    pub pid: u32,
    pub name: String,
    pub exe_path: Option<String>,
    pub cmdline: Option<String>,
    pub cgroup: Option<String>,
    pub flow_count: usize,
    pub listener_count: usize,
    pub cross_network_flows: usize,
    pub rx_bps: Option<f64>,
    pub tx_bps: Option<f64>,
    pub total_bps: f64,
    pub queue_bytes: Option<f64>,
    pub collector_backend: String,
    pub attribution_confidence: Option<f64>,
    pub max_rtt_ms: Option<f64>,
    pub dominant_remote_ip: Option<String>,
    pub local_ports: Vec<u16>,
    pub remote_ports: Vec<u16>,
    pub severity: String,
    pub last_seen_ms: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ContinuumNetworkListenerSnapshot {
    pub listener_id: String,
    pub pid: u32,
    pub process: String,
    pub protocol: String,
    pub socket_state: String,
    pub uid: u32,
    pub iface: Option<String>,
    pub local_ip: String,
    pub local_port: u16,
    pub local_mac: Option<String>,
    pub queue_bytes: Option<f64>,
    pub collector_backend: String,
    pub attribution_confidence: Option<f64>,
    pub severity: String,
    pub last_seen_ms: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ContinuumNetworkSnapshot {
    pub summary: ContinuumNetworkSummarySnapshot,
    pub top_processes: Vec<ContinuumNetworkProcessSnapshot>,
    pub top_flows: Vec<ContinuumNetworkFlowSnapshot>,
    pub top_listeners: Vec<ContinuumNetworkListenerSnapshot>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ContinuumServerSnapshot {
    pub cpu_usage_pct: Option<f64>,
    pub mem_used_pct: Option<f64>,
    pub mem_app_used_pct: Option<f64>,
    pub swap_used_pct: Option<f64>,
    pub net_rx_bps: Option<f64>,
    pub net_tx_bps: Option<f64>,
    pub gpu_utilization_avg_pct: Option<f64>,
    pub gpu_temperature_max_c: Option<f64>,
    pub gpu_power_total_w: Option<f64>,
    pub thermal_alerts: usize,
    pub fan_alerts: usize,
    pub recent_action_count: usize,
    pub autonomy_risk: Option<f64>,
    pub autonomy_action: Option<String>,
    pub ecc: ContinuumEccSnapshot,
    pub network: ContinuumNetworkSnapshot,
    pub thermal_sensors: Vec<ContinuumThermalSensor>,
    pub fan_sensors: Vec<ContinuumFanSensor>,
    pub power_sensors: Vec<ContinuumPowerSensor>,
    pub processes: Vec<ContinuumProcessSnapshot>,
    pub disks: Vec<ContinuumDiskSnapshot>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ContinuumTelemetrySnapshot {
    pub ts_ms: u64,
    pub identity: ContinuumIdentitySnapshot,
    pub server: ContinuumServerSnapshot,
    pub gpus: Vec<ContinuumGpuSnapshot>,
    pub recent_actions: Vec<ContinuumActionRecord>,
}

#[derive(Clone)]
pub struct ContinuumTelemetryHandle {
    snapshot: Arc<RwLock<ContinuumTelemetrySnapshot>>,
}

impl ContinuumTelemetryHandle {
    pub fn disabled(agent_id: impl Into<String>) -> Self {
        Self {
            snapshot: Arc::new(RwLock::new(ContinuumTelemetrySnapshot {
                ts_ms: now_ms(),
                identity: build_identity(&agent_id.into()),
                ..ContinuumTelemetrySnapshot::default()
            })),
        }
    }

    pub async fn snapshot(&self) -> ContinuumTelemetrySnapshot {
        self.snapshot.read().await.clone()
    }
}

pub fn spawn_continuum_telemetry(
    agent_id: String,
    mut event_rx: broadcast::Receiver<Event>,
    mut decision_rx: broadcast::Receiver<Decision>,
    mut shutdown: ShutdownListener,
) -> ContinuumTelemetryHandle {
    let handle = ContinuumTelemetryHandle::disabled(agent_id);
    let snapshot = handle.snapshot.clone();
    tokio::spawn(async move {
        let identity = {
            let read = snapshot.read().await;
            read.identity.clone()
        };
        let mut state = ContinuumTelemetryState {
            identity,
            network_window_ms: 5_000,
            ..ContinuumTelemetryState::default()
        };

        loop {
            tokio::select! {
                _ = shutdown.wait() => {
                    tracing::info!("continuum telemetry snapshot worker shutting down");
                    break;
                }
                message = event_rx.recv() => {
                    match message {
                        Ok(event) => {
                            state.ingest_event(event);
                            *snapshot.write().await = state.build_snapshot();
                        }
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            tracing::warn!(skipped, "continuum telemetry lagged behind event stream");
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
                message = decision_rx.recv() => {
                    match message {
                        Ok(decision) => {
                            state.ingest_decision(decision);
                            *snapshot.write().await = state.build_snapshot();
                        }
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            tracing::warn!(skipped, "continuum telemetry lagged behind decision stream");
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
            }
        }
    });
    handle
}

#[derive(Default)]
struct ContinuumTelemetryState {
    identity: ContinuumIdentitySnapshot,
    cpu_usage_pct: Option<f64>,
    mem_used_pct: Option<f64>,
    mem_app_used_pct: Option<f64>,
    swap_used_pct: Option<f64>,
    net_rx_bps: Option<f64>,
    net_tx_bps: Option<f64>,
    thermals: HashMap<String, ContinuumThermalSensor>,
    fans: HashMap<String, ContinuumFanSensor>,
    powers: HashMap<String, ContinuumPowerSensor>,
    processes: HashMap<u32, ContinuumProcessSnapshot>,
    disks: HashMap<String, ContinuumDiskSnapshot>,
    gpus: HashMap<String, ContinuumGpuSnapshot>,
    network_summary: ContinuumNetworkSummarySnapshot,
    network_processes: HashMap<u32, ContinuumNetworkProcessSnapshot>,
    network_flows: HashMap<String, ContinuumNetworkFlowSnapshot>,
    network_listeners: HashMap<String, ContinuumNetworkListenerSnapshot>,
    network_window_ms: u64,
    recent_actions: VecDeque<ContinuumActionRecord>,
    ecc_corrected_total: u64,
    ecc_uncorrected_total: u64,
    last_decision_risk: Option<f64>,
    last_decision_action: Option<String>,
}

impl ContinuumTelemetryState {
    fn ingest_event(&mut self, event: Event) {
        if event.source == "embedded" {
            self.ingest_embedded_event(&event);
        }

        if should_record_action(&event) {
            self.push_action(action_from_event(&event));
        }
    }

    fn ingest_decision(&mut self, decision: Decision) {
        self.last_decision_risk = Some(decision.mean_risk.clamp(0.0, 1.0));
        self.last_decision_action = Some(format!("{:?}", decision.action).to_ascii_lowercase());
        self.push_action(ContinuumActionRecord {
            ts_ms: decision.ts_ms,
            category: "autonomy".to_string(),
            action: format!("{:?}", decision.action).to_ascii_lowercase(),
            detail: truncate_text(
                &format!("{:?}: {}", decision.kind, decision.reason),
                MAX_DETAIL_LEN,
            ),
            source: Some("swarm".to_string()),
            tone: tone_for_action(decision.action).to_string(),
            score: Some(decision.mean_risk.clamp(0.0, 1.0)),
            gpu_id: None,
        });
    }

    fn ingest_embedded_event(&mut self, event: &Event) {
        let metric = event
            .attributes
            .get("metric")
            .map(String::as_str)
            .unwrap_or("");
        let value = parse_attr_f64(event, "value");
        if metric.starts_with("network_") {
            self.ingest_network_event(event, metric, value);
            return;
        }
        match metric {
            "cpu_usage" => {
                self.cpu_usage_pct = value.or(Some(event.signal.clamp(0.0, 1.0) * 100.0));
            }
            "mem_used" => {
                self.mem_used_pct = Some(event.signal.clamp(0.0, 1.0) * 100.0);
            }
            "mem_app_used" => {
                self.mem_app_used_pct = Some(event.signal.clamp(0.0, 1.0) * 100.0);
            }
            "swap_used" => {
                self.swap_used_pct = Some(event.signal.clamp(0.0, 1.0) * 100.0);
            }
            "net_rx_bps" => {
                self.net_rx_bps = value;
            }
            "net_tx_bps" => {
                self.net_tx_bps = value;
            }
            "thermal_temp" => {
                let name = sensor_name(event, "zone", "thermal");
                let label = sensor_label(event, "zone", "thermal");
                let entry =
                    self.thermals
                        .entry(name.clone())
                        .or_insert_with(|| ContinuumThermalSensor {
                            name,
                            label,
                            ..ContinuumThermalSensor::default()
                        });
                entry.sensor_type = event.attributes.get("type").cloned();
                entry.temp_c = value.unwrap_or_default();
                entry.severity = severity_label(event.severity).to_string();
            }
            "fan_rpm" => {
                let name = sensor_name(event, "fan", "fan");
                let label = sensor_label(event, "label", &name);
                let entry = self
                    .fans
                    .entry(name.clone())
                    .or_insert_with(|| ContinuumFanSensor {
                        name,
                        label,
                        ..ContinuumFanSensor::default()
                    });
                entry.rpm = value.map(|raw| raw.max(0.0).round() as u64);
                entry.severity = severity_label(event.severity).to_string();
            }
            "fan_pwm_percent" => {
                let name = sensor_name(event, "fan", "fan");
                let label = sensor_label(event, "label", &name);
                let entry = self
                    .fans
                    .entry(name.clone())
                    .or_insert_with(|| ContinuumFanSensor {
                        name,
                        label,
                        ..ContinuumFanSensor::default()
                    });
                entry.pwm_percent = value;
                entry.severity = severity_label(event.severity).to_string();
            }
            "sensor_power_w" => {
                let name = sensor_name(event, "sensor", "power");
                let label = sensor_label(event, "label", &name);
                let entry =
                    self.powers
                        .entry(name.clone())
                        .or_insert_with(|| ContinuumPowerSensor {
                            name,
                            label,
                            ..ContinuumPowerSensor::default()
                        });
                entry.power_w = value.unwrap_or_default();
                entry.severity = severity_label(event.severity).to_string();
            }
            "ecc_corrected_total" => {
                self.ecc_corrected_total = value.unwrap_or_default().max(0.0).round() as u64;
            }
            "ecc_uncorrected_total" => {
                self.ecc_uncorrected_total = value.unwrap_or_default().max(0.0).round() as u64;
            }
            "process_cpu_percent" | "process_mem_rss_bytes" | "process_io_bps" => {
                if let Some(pid) = parse_attr_u32(event, "pid") {
                    let name = event
                        .attributes
                        .get("process")
                        .cloned()
                        .unwrap_or_else(|| "unknown".to_string());
                    let entry =
                        self.processes
                            .entry(pid)
                            .or_insert_with(|| ContinuumProcessSnapshot {
                                pid,
                                name: name.clone(),
                                ..ContinuumProcessSnapshot::default()
                            });
                    entry.name = name;
                    match metric {
                        "process_cpu_percent" => entry.cpu_pct = value,
                        "process_mem_rss_bytes" => entry.mem_bytes = value,
                        "process_io_bps" => entry.io_bps = value,
                        _ => {}
                    }
                }
            }
            "disk_used_bytes" | "disk_total_bytes" | "disk_read_bps" | "disk_write_bps" => {
                let mount = event
                    .attributes
                    .get("mount")
                    .cloned()
                    .unwrap_or_else(|| "/".to_string());
                let entry =
                    self.disks
                        .entry(mount.clone())
                        .or_insert_with(|| ContinuumDiskSnapshot {
                            mount: mount.clone(),
                            ..ContinuumDiskSnapshot::default()
                        });
                match metric {
                    "disk_used_bytes" => {
                        entry.used_bytes = value;
                        entry.used_ratio =
                            parse_attr_f64(event, "used_ratio").or(Some(event.signal));
                    }
                    "disk_total_bytes" => entry.total_bytes = value,
                    "disk_read_bps" => entry.read_bps = value,
                    "disk_write_bps" => entry.write_bps = value,
                    _ => {}
                }
            }
            "gpu_util_percent"
            | "gpu_temp_c"
            | "gpu_power_w"
            | "gpu_mem_total_bytes"
            | "gpu_mem_used_bytes"
            | "gpu_clock_graphics_mhz"
            | "gpu_clock_memory_mhz"
            | "gpu_fan_speed_percent"
            | "gpu_encoder_util_percent"
            | "gpu_decoder_util_percent" => {
                self.ingest_gpu_metric(event, metric, value);
            }
            _ => {
                if metric.contains("ecc") {
                    self.ingest_gpu_metric(event, metric, value);
                }
            }
        }
    }

    fn ingest_gpu_metric(&mut self, event: &Event, metric: &str, value: Option<f64>) {
        let gpu_id = event
            .attributes
            .get("gpu_id")
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());
        let entry = self
            .gpus
            .entry(gpu_id.clone())
            .or_insert_with(|| ContinuumGpuSnapshot {
                gpu_id: gpu_id.clone(),
                slot_index: infer_slot_index(&gpu_id),
                ..ContinuumGpuSnapshot::default()
            });

        entry.name = entry
            .name
            .clone()
            .or_else(|| event.attributes.get("gpu_name").cloned());
        entry.vendor = entry
            .vendor
            .clone()
            .or_else(|| event.attributes.get("gpu_vendor").cloned());
        entry.source = entry
            .source
            .clone()
            .or_else(|| event.attributes.get("gpu_source").cloned());
        if entry.slot_index.is_none() {
            entry.slot_index = infer_slot_index(&gpu_id);
        }

        match metric {
            "gpu_util_percent" => entry.util_pct = value,
            "gpu_temp_c" => entry.temp_c = value,
            "gpu_power_w" => entry.power_w = value,
            "gpu_mem_total_bytes" => entry.mem_total_bytes = value.map(|v| v.max(0.0) as u64),
            "gpu_mem_used_bytes" => entry.mem_used_bytes = value.map(|v| v.max(0.0) as u64),
            "gpu_clock_graphics_mhz" => {
                entry.graphics_clock_mhz = value.map(|v| v.max(0.0).round() as u64)
            }
            "gpu_clock_memory_mhz" => {
                entry.memory_clock_mhz = value.map(|v| v.max(0.0).round() as u64)
            }
            "gpu_fan_speed_percent" => entry.fan_speed_percent = value,
            "gpu_encoder_util_percent" => entry.encoder_util_percent = value,
            "gpu_decoder_util_percent" => entry.decoder_util_percent = value,
            _ if metric.contains("ecc") => {
                let next = value.map(|v| v.max(0.0).round() as u64).unwrap_or(1);
                entry.ecc_error_count = Some(entry.ecc_error_count.unwrap_or_default().max(next));
            }
            _ => {}
        }

        if let (Some(used), Some(total)) = (entry.mem_used_bytes, entry.mem_total_bytes) {
            if total > 0 {
                entry.mem_used_pct = Some(((used as f64 / total as f64) * 100.0).clamp(0.0, 100.0));
            }
        }
    }

    fn ingest_network_event(&mut self, event: &Event, metric: &str, value: Option<f64>) {
        let summary = &mut self.network_summary;
        summary.updated_ms = event.ts_ms;
        if let Some(backend) = event.attributes.get("collector_backend") {
            summary.collector_backend = backend.clone();
        }

        match metric {
            "network_active_flows" => {
                summary.active_flows = value.unwrap_or_default().max(0.0).round() as usize;
                if let Some(window_ms) = parse_attr_u64(event, "window_ms") {
                    self.network_window_ms = window_ms.max(1_000);
                    summary.window_ms = self.network_window_ms;
                }
            }
            "network_established_flows" => {
                summary.established_flows = value.unwrap_or_default().max(0.0).round() as usize;
            }
            "network_listeners" => {
                summary.listeners = value.unwrap_or_default().max(0.0).round() as usize;
            }
            "network_owner_misses" => {
                summary.owner_misses = value.unwrap_or_default().max(0.0).round() as usize;
            }
            "network_estimated_flows" => {
                summary.estimated_flows = value.unwrap_or_default().max(0.0).round() as usize;
            }
            "network_remote_endpoints" => {
                summary.remote_endpoints = value.unwrap_or_default().max(0.0).round() as usize;
            }
            "network_cross_network_flows" => {
                summary.cross_network_flows = value.unwrap_or_default().max(0.0).round() as usize;
            }
            "network_lan_flows" => {
                summary.lan_flows = value.unwrap_or_default().max(0.0).round() as usize;
            }
            "network_local_host_flows" => {
                summary.local_host_flows = value.unwrap_or_default().max(0.0).round() as usize;
            }
            "network_unknown_remote_mac_flows" => {
                summary.unknown_remote_mac_flows =
                    value.unwrap_or_default().max(0.0).round() as usize;
            }
            "network_udp_active_flows" => {
                summary.udp_active_flows = value.unwrap_or_default().max(0.0).round() as usize;
            }
            "network_udp_drop_delta" => {
                summary.udp_drop_delta = value.unwrap_or_default().max(0.0).round() as u64;
            }
            "network_attributed_rx_bps" => {
                summary.attributed_rx_bps = value;
            }
            "network_attributed_tx_bps" => {
                summary.attributed_tx_bps = value;
            }
            "network_attributed_total_bps" => {
                summary.attributed_total_bps = value;
            }
            "network_cross_network_bps" => {
                summary.cross_network_bps = value;
            }
            "network_udp_estimated_total_bps" => {
                summary.udp_estimated_total_bps = value;
            }
            "network_attribution_confidence" => {
                summary.attribution_confidence = value.or(Some(event.signal.clamp(0.0, 1.0)));
            }
            "network_latency_pressure" => {
                summary.latency_pressure = value.or(Some(event.signal.clamp(0.0, 1.0)));
                summary.rtt_ms_max = parse_attr_f64(event, "rtt_ms_max");
            }
            "network_queue_pressure" => {
                summary.queue_bytes = value;
                summary.queue_pressure = Some(event.signal.clamp(0.0, 1.0));
            }
            "network_traffic_growth_pct_per_min" => {
                summary.traffic_growth_pct_per_min = value.unwrap_or_default();
            }
            "network_cross_network_growth_pct_per_min" => {
                summary.cross_network_growth_pct_per_min = value.unwrap_or_default();
            }
            "network_flow_growth_pct_per_min" => {
                summary.flow_growth_pct_per_min = value.unwrap_or_default();
            }
            "network_process_flow_bps" => {
                let mut flow = ContinuumNetworkFlowSnapshot {
                    flow_id: event.attributes.get("flow_id").cloned().unwrap_or_default(),
                    pid: parse_attr_u32(event, "pid").unwrap_or_default(),
                    process: event
                        .attributes
                        .get("process")
                        .cloned()
                        .unwrap_or_else(|| "unknown".to_string()),
                    protocol: event
                        .attributes
                        .get("protocol")
                        .cloned()
                        .unwrap_or_else(|| "unknown".to_string()),
                    socket_state: event
                        .attributes
                        .get("socket_state")
                        .cloned()
                        .unwrap_or_else(|| "unknown".to_string()),
                    uid: parse_attr_u32(event, "uid").unwrap_or_default(),
                    iface: event.attributes.get("iface").cloned(),
                    local_ip: event
                        .attributes
                        .get("local_ip")
                        .cloned()
                        .unwrap_or_default(),
                    local_port: parse_attr_u16(event, "local_port").unwrap_or_default(),
                    local_mac: event.attributes.get("local_mac").cloned(),
                    remote_ip: event.attributes.get("remote_ip").cloned(),
                    remote_port: parse_attr_u16(event, "remote_port"),
                    remote_mac: event.attributes.get("remote_mac").cloned(),
                    exe_path: event.attributes.get("exe_path").cloned(),
                    cmdline: event.attributes.get("cmdline").cloned(),
                    cgroup: event.attributes.get("cgroup").cloned(),
                    rx_bps: parse_attr_f64(event, "rx_bps"),
                    tx_bps: parse_attr_f64(event, "tx_bps"),
                    total_bps: value.unwrap_or_default().max(0.0),
                    queue_bytes: parse_attr_f64(event, "queue_bytes"),
                    collector_backend: event
                        .attributes
                        .get("collector_backend")
                        .cloned()
                        .unwrap_or_default(),
                    attribution_confidence: parse_attr_f64(event, "attribution_confidence"),
                    udp_drop_delta: parse_attr_u64(event, "udp_drop_delta"),
                    rtt_ms: parse_attr_f64(event, "rtt_ms"),
                    retransmits: parse_attr_u32(event, "retransmits"),
                    cross_network: parse_attr_bool(event, "cross_network").unwrap_or(false),
                    same_lan: parse_attr_bool(event, "same_lan").unwrap_or(false),
                    local_host: parse_attr_bool(event, "local_host").unwrap_or(false),
                    bytes_estimated: parse_attr_bool(event, "bytes_estimated").unwrap_or(false),
                    anomaly: parse_attr_bool(event, "anomaly").unwrap_or(false),
                    severity: severity_label(event.severity).to_string(),
                    last_seen_ms: event.ts_ms,
                };
                if flow.flow_id.is_empty() {
                    flow.flow_id = format!(
                        "{}:{}:{}:{}:{}",
                        flow.protocol,
                        flow.pid,
                        flow.local_ip,
                        flow.local_port,
                        flow.remote_port.unwrap_or_default()
                    );
                }
                if flow.remote_ip.as_deref() == Some("0.0.0.0")
                    || flow.remote_ip.as_deref() == Some("::")
                {
                    flow.remote_ip = None;
                }
                self.network_flows.insert(flow.flow_id.clone(), flow);
            }
            "network_process_total_bps" => {
                let process = ContinuumNetworkProcessSnapshot {
                    pid: parse_attr_u32(event, "pid").unwrap_or_default(),
                    name: event
                        .attributes
                        .get("process")
                        .cloned()
                        .unwrap_or_else(|| "unknown".to_string()),
                    exe_path: event.attributes.get("exe_path").cloned(),
                    cmdline: event.attributes.get("cmdline").cloned(),
                    cgroup: event.attributes.get("cgroup").cloned(),
                    flow_count: parse_attr_usize(event, "flow_count").unwrap_or_default(),
                    listener_count: parse_attr_usize(event, "listener_count").unwrap_or_default(),
                    cross_network_flows: parse_attr_usize(event, "cross_network_flows")
                        .unwrap_or_default(),
                    rx_bps: parse_attr_f64(event, "rx_bps"),
                    tx_bps: parse_attr_f64(event, "tx_bps"),
                    total_bps: value.unwrap_or_default().max(0.0),
                    queue_bytes: parse_attr_f64(event, "queue_bytes"),
                    collector_backend: event
                        .attributes
                        .get("collector_backend")
                        .cloned()
                        .unwrap_or_default(),
                    attribution_confidence: parse_attr_f64(event, "attribution_confidence"),
                    max_rtt_ms: parse_attr_f64(event, "max_rtt_ms"),
                    dominant_remote_ip: event.attributes.get("dominant_remote_ip").cloned(),
                    local_ports: parse_csv_u16_attr(event, "local_ports"),
                    remote_ports: parse_csv_u16_attr(event, "remote_ports"),
                    severity: severity_label(event.severity).to_string(),
                    last_seen_ms: event.ts_ms,
                };
                self.network_processes.insert(process.pid, process);
            }
            "network_listener_socket" => {
                let mut listener = ContinuumNetworkListenerSnapshot {
                    listener_id: event
                        .attributes
                        .get("listener_id")
                        .cloned()
                        .unwrap_or_default(),
                    pid: parse_attr_u32(event, "pid").unwrap_or_default(),
                    process: event
                        .attributes
                        .get("process")
                        .cloned()
                        .unwrap_or_else(|| "unknown".to_string()),
                    protocol: event
                        .attributes
                        .get("protocol")
                        .cloned()
                        .unwrap_or_else(|| "unknown".to_string()),
                    socket_state: event
                        .attributes
                        .get("socket_state")
                        .cloned()
                        .unwrap_or_else(|| "unknown".to_string()),
                    uid: parse_attr_u32(event, "uid").unwrap_or_default(),
                    iface: event.attributes.get("iface").cloned(),
                    local_ip: event
                        .attributes
                        .get("local_ip")
                        .cloned()
                        .unwrap_or_default(),
                    local_port: parse_attr_u16(event, "local_port").unwrap_or_default(),
                    local_mac: event.attributes.get("local_mac").cloned(),
                    queue_bytes: value,
                    collector_backend: event
                        .attributes
                        .get("collector_backend")
                        .cloned()
                        .unwrap_or_default(),
                    attribution_confidence: parse_attr_f64(event, "attribution_confidence"),
                    severity: severity_label(event.severity).to_string(),
                    last_seen_ms: event.ts_ms,
                };
                if listener.listener_id.is_empty() {
                    listener.listener_id = format!(
                        "{}:{}:{}:{}",
                        listener.protocol, listener.pid, listener.local_ip, listener.local_port
                    );
                }
                self.network_listeners
                    .insert(listener.listener_id.clone(), listener);
            }
            _ => {}
        }
    }

    fn push_action(&mut self, action: ContinuumActionRecord) {
        if action.action.is_empty() && action.detail.is_empty() {
            return;
        }
        if self.recent_actions.front().is_some_and(|existing| {
            existing.ts_ms == action.ts_ms
                && existing.category == action.category
                && existing.action == action.action
                && existing.detail == action.detail
        }) {
            return;
        }
        self.recent_actions.push_front(action);
        while self.recent_actions.len() > MAX_RECENT_ACTIONS {
            self.recent_actions.pop_back();
        }
    }

    fn build_snapshot(&mut self) -> ContinuumTelemetrySnapshot {
        let mut thermals: Vec<_> = self.thermals.values().cloned().collect();
        thermals.sort_by(|left, right| {
            right
                .temp_c
                .partial_cmp(&left.temp_c)
                .unwrap_or(Ordering::Equal)
                .then_with(|| left.name.cmp(&right.name))
        });
        thermals.truncate(MAX_THERMALS);

        let mut fans: Vec<_> = self.fans.values().cloned().collect();
        fans.sort_by(|left, right| {
            cmp_opt_f64_desc(right.rpm.map(|v| v as f64), left.rpm.map(|v| v as f64))
                .then_with(|| left.name.cmp(&right.name))
        });
        fans.truncate(MAX_FANS);

        let mut powers: Vec<_> = self.powers.values().cloned().collect();
        powers.sort_by(|left, right| {
            right
                .power_w
                .partial_cmp(&left.power_w)
                .unwrap_or(Ordering::Equal)
                .then_with(|| left.name.cmp(&right.name))
        });
        powers.truncate(MAX_POWER_SENSORS);

        let mut processes: Vec<_> = self.processes.values().cloned().collect();
        processes.sort_by(|left, right| {
            cmp_opt_f64_desc(right.cpu_pct, left.cpu_pct)
                .then_with(|| cmp_opt_f64_desc(right.mem_bytes, left.mem_bytes))
                .then_with(|| cmp_opt_f64_desc(right.io_bps, left.io_bps))
                .then_with(|| left.name.cmp(&right.name))
        });
        processes.truncate(MAX_PROCESSES);

        let mut disks: Vec<_> = self.disks.values().cloned().collect();
        disks.sort_by(|left, right| {
            cmp_opt_f64_desc(right.used_ratio, left.used_ratio)
                .then_with(|| cmp_opt_f64_desc(right.used_bytes, left.used_bytes))
                .then_with(|| left.mount.cmp(&right.mount))
        });
        disks.truncate(MAX_DISKS);

        let mut gpus: Vec<_> = self.gpus.values().cloned().collect();
        gpus.sort_by(|left, right| {
            cmp_opt_f64_desc(right.util_pct, left.util_pct)
                .then_with(|| cmp_opt_f64_desc(right.temp_c, left.temp_c))
                .then_with(|| left.gpu_id.cmp(&right.gpu_id))
        });
        gpus.truncate(MAX_GPUS);

        let network_retention_ms = network_retention_ms(self.network_window_ms);
        self.prune_network_samples(now_ms(), network_retention_ms);

        let mut network_processes: Vec<_> = self.network_processes.values().cloned().collect();
        network_processes.sort_by(|left, right| {
            right
                .total_bps
                .partial_cmp(&left.total_bps)
                .unwrap_or(Ordering::Equal)
                .then_with(|| cmp_opt_f64_desc(right.max_rtt_ms, left.max_rtt_ms))
                .then_with(|| left.name.cmp(&right.name))
        });
        network_processes.truncate(MAX_NETWORK_PROCESSES);

        let mut network_flows: Vec<_> = self.network_flows.values().cloned().collect();
        network_flows.sort_by(|left, right| {
            right
                .total_bps
                .partial_cmp(&left.total_bps)
                .unwrap_or(Ordering::Equal)
                .then_with(|| cmp_opt_f64_desc(right.rtt_ms, left.rtt_ms))
                .then_with(|| left.flow_id.cmp(&right.flow_id))
        });
        network_flows.truncate(MAX_NETWORK_FLOWS);

        let mut network_listeners: Vec<_> = self.network_listeners.values().cloned().collect();
        network_listeners.sort_by(|left, right| {
            cmp_opt_f64_desc(right.queue_bytes, left.queue_bytes)
                .then_with(|| left.process.cmp(&right.process))
                .then_with(|| left.listener_id.cmp(&right.listener_id))
        });
        network_listeners.truncate(MAX_NETWORK_LISTENERS);

        let mut gpu_util_sum = 0.0;
        let mut gpu_util_count = 0usize;
        let mut gpu_temp_max: Option<f64> = None;
        let mut gpu_power_total = 0.0;
        let mut gpu_power_count = 0usize;
        for gpu in &gpus {
            if let Some(util) = gpu.util_pct {
                gpu_util_sum += util;
                gpu_util_count += 1;
            }
            if let Some(temp) = gpu.temp_c {
                gpu_temp_max = Some(
                    gpu_temp_max
                        .map(|current| current.max(temp))
                        .unwrap_or(temp),
                );
            }
            if let Some(power) = gpu.power_w {
                gpu_power_total += power;
                gpu_power_count += 1;
            }
        }

        ContinuumTelemetrySnapshot {
            ts_ms: now_ms(),
            identity: self.identity.clone(),
            server: ContinuumServerSnapshot {
                cpu_usage_pct: self.cpu_usage_pct,
                mem_used_pct: self.mem_used_pct,
                mem_app_used_pct: self.mem_app_used_pct,
                swap_used_pct: self.swap_used_pct,
                net_rx_bps: self.net_rx_bps,
                net_tx_bps: self.net_tx_bps,
                gpu_utilization_avg_pct: (gpu_util_count > 0)
                    .then_some(gpu_util_sum / gpu_util_count as f64),
                gpu_temperature_max_c: gpu_temp_max,
                gpu_power_total_w: (gpu_power_count > 0).then_some(gpu_power_total),
                thermal_alerts: thermals.iter().filter(|entry| entry.temp_c >= 75.0).count(),
                fan_alerts: fans
                    .iter()
                    .filter(|entry| {
                        entry.rpm == Some(0) || entry.pwm_percent.is_some_and(|value| value >= 95.0)
                    })
                    .count(),
                recent_action_count: self.recent_actions.len(),
                autonomy_risk: self.last_decision_risk,
                autonomy_action: self.last_decision_action.clone(),
                ecc: ContinuumEccSnapshot {
                    corrected_total: self.ecc_corrected_total,
                    uncorrected_total: self.ecc_uncorrected_total,
                },
                network: ContinuumNetworkSnapshot {
                    summary: ContinuumNetworkSummarySnapshot {
                        window_ms: self.network_summary.window_ms.max(self.network_window_ms),
                        ..self.network_summary.clone()
                    },
                    top_processes: network_processes,
                    top_flows: network_flows,
                    top_listeners: network_listeners,
                },
                thermal_sensors: thermals,
                fan_sensors: fans,
                power_sensors: powers,
                processes,
                disks,
            },
            gpus,
            recent_actions: self.recent_actions.iter().cloned().collect(),
        }
    }

    fn prune_network_samples(&mut self, now_ms: u64, retention_ms: u64) {
        self.network_processes
            .retain(|_, process| now_ms.saturating_sub(process.last_seen_ms) <= retention_ms);
        self.network_flows
            .retain(|_, flow| now_ms.saturating_sub(flow.last_seen_ms) <= retention_ms);
        self.network_listeners
            .retain(|_, listener| now_ms.saturating_sub(listener.last_seen_ms) <= retention_ms);
    }
}

fn build_identity(agent_id: &str) -> ContinuumIdentitySnapshot {
    let host = read_hostname()
        .or_else(|| std::env::var("HOSTNAME").ok())
        .map(|value| sanitize_label(&value, MAX_HOSTNAME_LEN))
        .unwrap_or_else(|| sanitize_label(agent_id, MAX_HOSTNAME_LEN));
    let zone = env_hint(&["TRACEY_ZONE", "NM_TRACEY_ZONE", "ZONE"])
        .or_else(|| infer_topology_token(&host, &["zone", "z"]));
    let rack = env_hint(&["TRACEY_RACK", "NM_TRACEY_RACK", "RACK"])
        .or_else(|| infer_topology_token(&host, &["rack", "r"]));
    let row = env_hint(&["TRACEY_ROW", "NM_TRACEY_ROW", "ROW"]);

    ContinuumIdentitySnapshot {
        agent_id: sanitize_label(agent_id, MAX_LABEL_LEN),
        host,
        zone,
        rack,
        row,
        site: env_hint(&["TRACEY_SITE", "NM_TRACEY_SITE", "SITE", "DATACENTER"]),
        building: env_hint(&["TRACEY_BUILDING", "NM_TRACEY_BUILDING", "BUILDING"]),
        room: env_hint(&["TRACEY_ROOM", "NM_TRACEY_ROOM", "ROOM"]),
        network: env_hint(&["TRACEY_NETWORK", "NM_TRACEY_NETWORK", "NETWORK", "VLAN"]),
        physical: env_hint(&["TRACEY_PHYSICAL", "NM_TRACEY_PHYSICAL", "PHYSICAL"]),
    }
}

fn read_hostname() -> Option<String> {
    fs::read_to_string("/etc/hostname")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn env_hint(keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| std::env::var(key).ok())
        .map(|value| sanitize_label(&value, MAX_LABEL_LEN))
        .filter(|value| !value.is_empty())
}

fn infer_topology_token(host: &str, prefixes: &[&str]) -> Option<String> {
    let lower = host.to_ascii_lowercase();
    for token in lower.split(|ch: char| !ch.is_ascii_alphanumeric()) {
        if token.is_empty() {
            continue;
        }
        for prefix in prefixes {
            if let Some(rest) = token.strip_prefix(prefix) {
                if rest.is_empty() {
                    continue;
                }
                return Some(rest_to_topology(prefix, rest));
            }
        }
    }
    None
}

fn rest_to_topology(prefix: &str, rest: &str) -> String {
    let cleaned = sanitize_label(rest, MAX_LABEL_LEN);
    if prefix == "r" || prefix == "rack" {
        if cleaned.chars().all(|ch| ch.is_ascii_digit()) {
            return format!("R{:0>2}", cleaned);
        }
        return format!("R{}", cleaned.to_ascii_uppercase());
    }
    cleaned.to_ascii_uppercase()
}

fn sanitize_label(value: &str, max_len: usize) -> String {
    value
        .trim()
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | ':' | '.'))
        .take(max_len)
        .collect()
}

fn truncate_text(value: &str, max_len: usize) -> String {
    let trimmed = value.trim();
    if trimmed.len() <= max_len {
        return trimmed.to_string();
    }
    let mut out = trimmed
        .chars()
        .take(max_len.saturating_sub(3))
        .collect::<String>();
    out.push_str("...");
    out
}

fn sensor_name(event: &Event, key: &str, fallback: &str) -> String {
    event
        .attributes
        .get(key)
        .cloned()
        .filter(|value| !value.trim().is_empty())
        .map(|value| sanitize_label(&value, MAX_LABEL_LEN))
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| fallback.to_string())
}

fn sensor_label(event: &Event, key: &str, fallback: &str) -> String {
    event
        .attributes
        .get(key)
        .cloned()
        .filter(|value| !value.trim().is_empty())
        .map(|value| truncate_text(&value, MAX_LABEL_LEN))
        .unwrap_or_else(|| truncate_text(fallback, MAX_LABEL_LEN))
}

fn infer_slot_index(gpu_id: &str) -> Option<u32> {
    let tail = gpu_id
        .rsplit(|ch: char| !ch.is_ascii_digit())
        .find(|chunk| !chunk.is_empty())?;
    tail.parse::<u32>().ok()
}

fn parse_attr_f64(event: &Event, key: &str) -> Option<f64> {
    event
        .attributes
        .get(key)
        .and_then(|value| value.parse::<f64>().ok())
}

fn parse_attr_bool(event: &Event, key: &str) -> Option<bool> {
    let value = event.attributes.get(key)?;
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "yes" | "1" => Some(true),
        "false" | "no" | "0" => Some(false),
        _ => None,
    }
}

fn parse_attr_u16(event: &Event, key: &str) -> Option<u16> {
    event
        .attributes
        .get(key)
        .and_then(|value| value.parse::<u16>().ok())
}

fn parse_attr_u32(event: &Event, key: &str) -> Option<u32> {
    event
        .attributes
        .get(key)
        .and_then(|value| value.parse::<u32>().ok())
}

fn parse_attr_u64(event: &Event, key: &str) -> Option<u64> {
    event
        .attributes
        .get(key)
        .and_then(|value| value.parse::<u64>().ok())
}

fn parse_attr_usize(event: &Event, key: &str) -> Option<usize> {
    event
        .attributes
        .get(key)
        .and_then(|value| value.parse::<usize>().ok())
}

fn parse_csv_u16_attr(event: &Event, key: &str) -> Vec<u16> {
    event
        .attributes
        .get(key)
        .map(|raw| {
            raw.split(',')
                .filter_map(|part| part.trim().parse::<u16>().ok())
                .collect()
        })
        .unwrap_or_default()
}

fn network_retention_ms(window_ms: u64) -> u64 {
    (window_ms.saturating_mul(3)).clamp(MIN_NETWORK_RETENTION_MS, MAX_NETWORK_RETENTION_MS)
}

fn cmp_opt_f64_desc(left: Option<f64>, right: Option<f64>) -> Ordering {
    match (left, right) {
        (Some(left), Some(right)) => left.partial_cmp(&right).unwrap_or(Ordering::Equal),
        (Some(_), None) => Ordering::Greater,
        (None, Some(_)) => Ordering::Less,
        (None, None) => Ordering::Equal,
    }
}

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

fn should_record_action(event: &Event) -> bool {
    if matches!(
        event.kind,
        EventKind::AutomationAction | EventKind::UserAction
    ) {
        return true;
    }

    if event.source == "tracey_guard" {
        return true;
    }

    if event.severity == Severity::Critical {
        return true;
    }

    let metric = event
        .attributes
        .get("metric")
        .map(String::as_str)
        .unwrap_or("");
    metric.contains("fault")
        || metric.contains("ecc")
        || metric.contains("quarantine")
        || metric.contains("gpu_temp")
        || metric.contains("loader")
}

fn action_from_event(event: &Event) -> ContinuumActionRecord {
    let metric = event
        .attributes
        .get("metric")
        .cloned()
        .unwrap_or_else(|| event.source.clone());
    let action = event
        .attributes
        .get("action")
        .cloned()
        .or_else(|| event.attributes.get("state").cloned())
        .unwrap_or_else(|| metric.clone());

    let mut detail_parts = Vec::new();
    for key in [
        "reason",
        "state",
        "probe_type",
        "metric",
        "process",
        "mount",
        "iface",
    ] {
        if let Some(value) = event.attributes.get(key) {
            detail_parts.push(format!("{key}={value}"));
        }
    }
    if detail_parts.is_empty() && event.source != metric {
        detail_parts.push(format!("source={}", event.source));
    }

    ContinuumActionRecord {
        ts_ms: event.ts_ms,
        category: event_category(event).to_string(),
        action: truncate_text(&action, 48),
        detail: truncate_text(&detail_parts.join(" "), MAX_DETAIL_LEN),
        source: Some(event.source.clone()),
        tone: severity_label(event.severity).to_string(),
        score: Some(event.signal.clamp(0.0, 1.0)),
        gpu_id: event.attributes.get("gpu_id").cloned(),
    }
}

fn event_category(event: &Event) -> &'static str {
    if event.source == "tracey_guard" {
        return "hardware";
    }
    match event.kind {
        EventKind::AutomationAction => "automation",
        EventKind::UserAction => "operator",
        EventKind::Observability => "observability",
        EventKind::NetworkFlow => "network",
        EventKind::SystemMetric => "system",
    }
}

fn tone_for_action(action: Action) -> &'static str {
    match action {
        Action::Monitor => "neutral",
        Action::Alert => "warn",
        Action::Throttle => "warn",
        Action::Isolate => "bad",
        Action::Shutdown => "bad",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{EventKind, Severity};

    #[test]
    fn rack_inference_prefers_environment_then_hostname() {
        assert_eq!(rest_to_topology("r", "9"), "R09");
        assert_eq!(rest_to_topology("rack", "12"), "R12");
        assert_eq!(
            infer_topology_token("gpu-r07-node", &["rack", "r"]).as_deref(),
            Some("R07")
        );
    }

    #[test]
    fn gpu_slot_inference_extracts_tail_digits() {
        assert_eq!(infer_slot_index("nvidia:3"), Some(3));
        assert_eq!(infer_slot_index("card12"), Some(12));
        assert_eq!(infer_slot_index("gpu"), None);
    }

    #[test]
    fn action_filter_keeps_operationally_relevant_events() {
        let event = Event::new(
            1,
            "tracey_guard",
            EventKind::Observability,
            0.7,
            Severity::High,
        )
        .with_attr("metric", "tracey_guard_fault")
        .with_attr("gpu_id", "nvidia:0");
        assert!(should_record_action(&event));
    }
}
