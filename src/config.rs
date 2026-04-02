//! Runtime configuration model, defaults, env overrides, and sanitization.
//!
//! Config loading follows precedence: defaults < JSON file < env overrides,
//! then a normalization pass clamps invalid/out-of-range values.

use crate::security::ActionPolicy;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StorageConfig {
    pub log_path: PathBuf,
    pub max_bytes: u64,
    pub max_total_bytes: u64,
    pub retain_lines: usize,
    pub compact_interval_ms: u64,
    pub rotate_archives: usize,
    pub summary_top_keys: usize,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            log_path: PathBuf::from("tracey.log.jsonl"),
            max_bytes: 25_000_000,
            max_total_bytes: 100_000_000,
            retain_lines: 5000,
            compact_interval_ms: 30_000,
            rotate_archives: 3,
            summary_top_keys: 25,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DiscoveryConfig {
    pub enabled: bool,
    pub bind_addr: String,
    pub broadcast_addr: String,
    pub advertise_addr: Option<String>,
    pub shared_key: String,
    pub announce_interval_ms: u64,
    pub ttl_ms: u64,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bind_addr: "0.0.0.0:47990".to_string(),
            broadcast_addr: "255.255.255.255:47990".to_string(),
            advertise_addr: None,
            shared_key: "tracey-dev-key-change-me".to_string(),
            announce_interval_ms: 1500,
            ttl_ms: 10_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AssetFeedConfig {
    pub enabled: bool,
    pub path: PathBuf,
    pub poll_interval_ms: u64,
    pub source: String,
}

impl Default for AssetFeedConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: PathBuf::from("asset_feed.jsonl"),
            poll_interval_ms: 3000,
            source: "asset_feed".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct InventoryConfig {
    pub agent_ttl_ms: u64,
    pub host_ttl_ms: u64,
    pub unmanaged_resend_ms: u64,
}

impl Default for InventoryConfig {
    fn default() -> Self {
        Self {
            agent_ttl_ms: 30_000,
            host_ttl_ms: 120_000,
            unmanaged_resend_ms: 30_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RefinerTrackingConfig {
    pub enabled: bool,
    pub source: String,
    pub service_name: String,
    pub health_url: String,
    pub security_feed_path: PathBuf,
    pub poll_interval_ms: u64,
    pub timeout_ms: u64,
}

impl Default for RefinerTrackingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            source: "refiner".to_string(),
            service_name: "refiner".to_string(),
            health_url: "http://127.0.0.1:5001/api/health".to_string(),
            security_feed_path: PathBuf::from("refiner_security_feed.jsonl"),
            poll_interval_ms: 5000,
            timeout_ms: 2500,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TelemetryConfig {
    pub enabled: bool,
    pub prometheus_enabled: bool,
    pub endpoints: Vec<String>,
    pub scrape_interval_ms: u64,
    pub max_samples: usize,
    pub allow_prefixes: Vec<String>,
    pub allow_exact: Vec<String>,
    pub autodiscover_local: bool,
    pub allow_remote: bool,
    pub source: String,
    pub timeout_ms: u64,
    pub prefer_prometheus: bool,
    pub dedup_ttl_ms: u64,
    pub otlp: OtlpReceiverConfig,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            prometheus_enabled: true,
            endpoints: Vec::new(),
            scrape_interval_ms: 5000,
            max_samples: 200,
            allow_prefixes: vec![
                "process_".to_string(),
                "system_".to_string(),
                "node_".to_string(),
                "cpu".to_string(),
                "mem".to_string(),
                "load".to_string(),
                "http_".to_string(),
                "otelcol_".to_string(),
            ],
            allow_exact: Vec::new(),
            autodiscover_local: true,
            allow_remote: false,
            source: "telemetry".to_string(),
            timeout_ms: 2000,
            prefer_prometheus: true,
            dedup_ttl_ms: 30_000,
            otlp: OtlpReceiverConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PrometheusLogExportConfig {
    pub enabled: bool,
    pub server_url: String,
    pub probe_path: String,
    pub probe_interval_ms: u64,
    pub probe_timeout_ms: u64,
    pub forward_interval_ms: u64,
    pub batch_ttl_ms: u64,
    pub max_batch: usize,
    pub max_queue: usize,
    pub min_signal: f64,
    pub min_decision_risk: f64,
    pub series_ttl_ms: u64,
}

impl Default for PrometheusLogExportConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            server_url: "https://prometheus.neuralmimicry.ai".to_string(),
            probe_path: "/-/ready".to_string(),
            probe_interval_ms: 5_000,
            probe_timeout_ms: 1_500,
            forward_interval_ms: 1_000,
            batch_ttl_ms: 30_000,
            max_batch: 64,
            max_queue: 2_048,
            min_signal: 0.70,
            min_decision_risk: 0.70,
            series_ttl_ms: 86_400_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EmbeddedConfig {
    pub enabled: bool,
    pub interval_ms: u64,
    pub jetson_enabled: bool,
    pub max_thermals: usize,
    pub max_disks: usize,
    pub max_interfaces: usize,
    pub process_enabled: bool,
    pub process_top_n: usize,
    pub process_window_ms: u64,
    pub process_max: usize,
    pub gpu_enabled: bool,
    pub gpu_sysfs_enabled: bool,
    pub gpu_nvml_enabled: bool,
    pub gpu_rocm_enabled: bool,
    pub gpu_max_devices: usize,
}

impl Default for EmbeddedConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_ms: 2000,
            jetson_enabled: true,
            max_thermals: 8,
            max_disks: 8,
            max_interfaces: 8,
            process_enabled: true,
            process_top_n: 5,
            process_window_ms: 5000,
            process_max: 2048,
            gpu_enabled: true,
            gpu_sysfs_enabled: true,
            gpu_nvml_enabled: true,
            gpu_rocm_enabled: true,
            gpu_max_devices: 8,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TraceyGuardProbeConfig {
    pub enabled: bool,
    pub period_ms: u64,
    pub sm_coverage: f64,
    pub priority: u8,
    pub timeout_ms: u64,
}

impl Default for TraceyGuardProbeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            period_ms: 60_000,
            sm_coverage: 1.0,
            priority: 1,
            timeout_ms: 1_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TraceyGuardProbeCatalogConfig {
    pub fma: TraceyGuardProbeConfig,
    pub tensor_core: TraceyGuardProbeConfig,
    pub transcendental: TraceyGuardProbeConfig,
    pub aes: TraceyGuardProbeConfig,
    pub memory: TraceyGuardProbeConfig,
    pub register_file: TraceyGuardProbeConfig,
    pub shared_memory: TraceyGuardProbeConfig,
}

impl Default for TraceyGuardProbeCatalogConfig {
    fn default() -> Self {
        Self {
            fma: TraceyGuardProbeConfig {
                period_ms: 60_000,
                sm_coverage: 1.0,
                priority: 1,
                timeout_ms: 500,
                enabled: true,
            },
            tensor_core: TraceyGuardProbeConfig {
                period_ms: 60_000,
                sm_coverage: 1.0,
                priority: 1,
                timeout_ms: 1_000,
                enabled: true,
            },
            transcendental: TraceyGuardProbeConfig {
                period_ms: 120_000,
                sm_coverage: 0.5,
                priority: 2,
                timeout_ms: 500,
                enabled: true,
            },
            aes: TraceyGuardProbeConfig {
                period_ms: 300_000,
                sm_coverage: 0.25,
                priority: 3,
                timeout_ms: 2_000,
                enabled: true,
            },
            memory: TraceyGuardProbeConfig {
                period_ms: 600_000,
                sm_coverage: 1.0,
                priority: 4,
                timeout_ms: 5_000,
                enabled: true,
            },
            register_file: TraceyGuardProbeConfig {
                period_ms: 120_000,
                sm_coverage: 1.0,
                priority: 2,
                timeout_ms: 500,
                enabled: true,
            },
            shared_memory: TraceyGuardProbeConfig {
                period_ms: 300_000,
                sm_coverage: 0.5,
                priority: 3,
                timeout_ms: 1_000,
                enabled: true,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TraceyGuardTmrConfig {
    pub enabled: bool,
    pub interval_ms: u64,
    pub timeout_ms: u64,
    pub triples_per_interval: usize,
}

impl Default for TraceyGuardTmrConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_ms: 600_000,
            timeout_ms: 30_000,
            triples_per_interval: 3,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TraceyGuardCorrelationConfig {
    pub window_ms: u64,
    pub min_confidence: f64,
    pub healthy_to_suspect: f64,
    pub suspect_to_quarantine: f64,
    pub quarantine_to_healthy: f64,
    pub immediate_quarantine_failures: u32,
    pub deep_test_passes: u32,
}

impl Default for TraceyGuardCorrelationConfig {
    fn default() -> Self {
        Self {
            window_ms: 300_000,
            min_confidence: 0.6,
            healthy_to_suspect: 0.95,
            suspect_to_quarantine: 0.80,
            quarantine_to_healthy: 0.98,
            immediate_quarantine_failures: 3,
            deep_test_passes: 128,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TraceyGuardConfig {
    pub enabled: bool,
    pub scheduler_poll_ms: u64,
    pub max_parallel_tasks: usize,
    pub overhead_budget_pct: f64,
    pub max_devices: usize,
    pub synthetic_devices: usize,
    pub default_sm_count: usize,
    pub max_advertised_faults: usize,
    pub remote_fault_ttl_ms: u64,
    pub deep_dive_max_faults: usize,
    pub probes: TraceyGuardProbeCatalogConfig,
    pub tmr: TraceyGuardTmrConfig,
    pub correlation: TraceyGuardCorrelationConfig,
}

impl Default for TraceyGuardConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            scheduler_poll_ms: 200,
            max_parallel_tasks: 32,
            overhead_budget_pct: 2.0,
            max_devices: 32,
            synthetic_devices: 1,
            default_sm_count: 16,
            max_advertised_faults: 64,
            remote_fault_ttl_ms: 120_000,
            deep_dive_max_faults: 256,
            probes: TraceyGuardProbeCatalogConfig::default(),
            tmr: TraceyGuardTmrConfig::default(),
            correlation: TraceyGuardCorrelationConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OtlpReceiverConfig {
    pub enabled: bool,
    pub grpc_addr: String,
    pub http_addr: String,
    pub enable_grpc: bool,
    pub enable_http: bool,
}

impl Default for OtlpReceiverConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            grpc_addr: "127.0.0.1:4317".to_string(),
            http_addr: "127.0.0.1:4318".to_string(),
            enable_grpc: true,
            enable_http: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TraceyBanConfig {
    pub enabled: bool,
    pub state_path: PathBuf,
    pub max_advertised_ips: usize,
    pub remote_ttl_ms: u64,
    pub unban_check_ms: u64,
    pub persist_interval_ms: u64,
    pub agent_id: String,
    pub auto_elevate_root: bool,
    pub sudo_program: String,
    pub sudo_non_interactive: bool,
    pub use_sudo_for_actions: bool,
    pub inherit_global_fuzzy: bool,
    pub min_samples: u64,
    pub fuzzy: FuzzyConfig,
    pub fuzzy_min_risk: f64,
    pub fuzzy_min_confidence: f64,
    pub fuzzy_retry_reduction: f64,
    pub jails: Vec<TraceyBanJailConfig>,
}

impl Default for TraceyBanConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            state_path: PathBuf::from("tracey.tracey_ban.state.json"),
            max_advertised_ips: 64,
            remote_ttl_ms: 15_000,
            unban_check_ms: 1_000,
            persist_interval_ms: 3_000,
            agent_id: String::new(),
            auto_elevate_root: true,
            sudo_program: "sudo".to_string(),
            sudo_non_interactive: true,
            use_sudo_for_actions: true,
            inherit_global_fuzzy: true,
            min_samples: 12,
            fuzzy: FuzzyConfig::default(),
            fuzzy_min_risk: 0.62,
            fuzzy_min_confidence: 0.30,
            fuzzy_retry_reduction: 0.55,
            jails: vec![TraceyBanJailConfig::default()],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TraceyBanJailConfig {
    pub name: String,
    pub enabled: bool,
    pub backend: String,
    pub log_paths: Vec<PathBuf>,
    pub filter_files: Vec<PathBuf>,
    pub fail_regex: Vec<String>,
    pub ignore_regex: Vec<String>,
    pub prefilter_regex: Option<String>,
    pub max_retry: u32,
    pub find_time_ms: u64,
    pub ban_time_ms: i64,
    pub ban_increment: bool,
    pub ban_multiplier: f64,
    pub ban_max_time_ms: u64,
    pub ban_randomize_ms: u64,
    pub ignore_ips: Vec<String>,
    pub poll_interval_ms: u64,
    pub event_ip_keys: Vec<String>,
    pub action_start: Option<String>,
    pub action_stop: Option<String>,
    pub action_ban: Option<String>,
    pub action_unban: Option<String>,
    pub shell: String,
    pub action_timeout_ms: u64,
}

impl Default for TraceyBanJailConfig {
    fn default() -> Self {
        Self {
            name: "tracey-default".to_string(),
            enabled: true,
            backend: "tracey_event".to_string(),
            log_paths: Vec::new(),
            filter_files: Vec::new(),
            fail_regex: vec![
                r"(?i)(failed|invalid|denied|rejected|unauthorized).*?(?P<host>(?:\d{1,3}\.){3}\d{1,3}|(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4})".to_string(),
                r"(?P<host>(?:\d{1,3}\.){3}\d{1,3}|(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4})".to_string(),
            ],
            ignore_regex: Vec::new(),
            prefilter_regex: None,
            max_retry: 3,
            find_time_ms: 600_000,
            ban_time_ms: 600_000,
            ban_increment: true,
            ban_multiplier: 2.0,
            ban_max_time_ms: 7_200_000,
            ban_randomize_ms: 15_000,
            ignore_ips: vec!["127.0.0.1".to_string(), "::1".to_string()],
            poll_interval_ms: 1_000,
            event_ip_keys: vec![
                "ip".to_string(),
                "src_ip".to_string(),
                "source_ip".to_string(),
                "client_ip".to_string(),
                "remote_addr".to_string(),
            ],
            action_start: None,
            action_stop: None,
            action_ban: None,
            action_unban: None,
            shell: "/bin/sh".to_string(),
            action_timeout_ms: 5_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub agent_id: String,
    pub agents: usize,
    pub bus_capacity: usize,
    pub assessment_channel_capacity: usize,
    pub assessment_quorum: usize,
    pub decision_threshold: f64,
    pub decision_ttl_ms: u64,
    pub event_rate_ms: u64,
    pub learning_merge_alpha: f64,
    pub learning_broadcast_ms: u64,
    pub directive_broadcast_ms: u64,
    pub min_samples: u64,
    pub fuzzy: FuzzyConfig,
    pub active_response: bool,
    pub shutdown_enabled: bool,
    pub policy: ActionPolicy,
    pub storage: StorageConfig,
    pub discovery: DiscoveryConfig,
    pub asset_feed: AssetFeedConfig,
    pub inventory: InventoryConfig,
    pub refiner: RefinerTrackingConfig,
    pub tuning: crate::tuning::TuningConfig,
    pub update: crate::update::UpdateConfig,
    pub telemetry: TelemetryConfig,
    pub prometheus_log_export: PrometheusLogExportConfig,
    pub embedded: EmbeddedConfig,
    pub tracey_guard: TraceyGuardConfig,
    pub tracey_ban: TraceyBanConfig,
    pub governance: crate::governance::GovernanceConfig,
    pub coordination: CoordinationConfig,
    pub continuum_autoscaler: ContinuumAutoscalerConfig,
    pub loader: LoaderConfig,
    pub status: StatusConfig,
    pub stimuli: StimuliConfig,
    pub auth: AuthConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            agent_id: default_agent_id(),
            agents: 6,
            bus_capacity: 2048,
            assessment_channel_capacity: 2048,
            assessment_quorum: 4,
            decision_threshold: 0.75,
            decision_ttl_ms: 1500,
            event_rate_ms: 150,
            learning_merge_alpha: 0.15,
            learning_broadcast_ms: 2000,
            directive_broadcast_ms: 2500,
            min_samples: 12,
            fuzzy: FuzzyConfig::default(),
            active_response: false,
            shutdown_enabled: false,
            policy: ActionPolicy::default(),
            storage: StorageConfig::default(),
            discovery: DiscoveryConfig::default(),
            asset_feed: AssetFeedConfig::default(),
            inventory: InventoryConfig::default(),
            refiner: RefinerTrackingConfig::default(),
            tuning: crate::tuning::TuningConfig::default(),
            update: crate::update::UpdateConfig::default(),
            telemetry: TelemetryConfig::default(),
            prometheus_log_export: PrometheusLogExportConfig::default(),
            embedded: EmbeddedConfig::default(),
            tracey_guard: TraceyGuardConfig::default(),
            tracey_ban: TraceyBanConfig::default(),
            governance: crate::governance::GovernanceConfig::default(),
            coordination: CoordinationConfig::default(),
            continuum_autoscaler: ContinuumAutoscalerConfig::default(),
            loader: LoaderConfig::default(),
            status: StatusConfig::default(),
            stimuli: StimuliConfig::default(),
            auth: AuthConfig::default(),
        }
    }
}

impl Config {
    /// Loads configuration from `TRACEY_CONFIG` (if present), applies env
    /// overrides, and sanitizes values to safe operational ranges.
    pub fn load() -> Self {
        let path = std::env::var("TRACEY_CONFIG").ok();
        if let Some(path) = path {
            match std::fs::read_to_string(&path) {
                Ok(raw) => match serde_json::from_str::<Config>(&raw) {
                    Ok(mut cfg) => {
                        cfg.apply_env_overrides();
                        cfg.sanitize();
                        return cfg;
                    }
                    Err(err) => {
                        tracing::warn!("Failed to parse config from {}: {}", path, err);
                    }
                },
                Err(err) => {
                    tracing::warn!("Failed to read config from {}: {}", path, err);
                }
            }
        }
        let mut cfg = Config::default();
        cfg.apply_env_overrides();
        cfg.sanitize();
        cfg
    }

    fn sanitize(&mut self) {
        self.agents = self.agents.clamp(1, 128);
        self.bus_capacity = self.bus_capacity.clamp(128, 65535);
        self.assessment_channel_capacity = self.assessment_channel_capacity.clamp(128, 65535);
        self.assessment_quorum = self.assessment_quorum.clamp(1, self.agents.max(1));
        self.decision_threshold = self.decision_threshold.clamp(0.0, 1.0);
        self.learning_merge_alpha = self.learning_merge_alpha.clamp(0.01, 0.8);
        self.event_rate_ms = self.event_rate_ms.clamp(50, 10_000);
        self.learning_broadcast_ms = self.learning_broadcast_ms.clamp(250, 60_000);
        self.directive_broadcast_ms = self.directive_broadcast_ms.clamp(250, 60_000);
        self.min_samples = self.min_samples.clamp(3, 10_000);
        self.fuzzy.order = self.fuzzy.order.clamp(1, 8);
        self.fuzzy.uncertainty = self.fuzzy.uncertainty.clamp(0.0, 1.0);
        self.fuzzy.edge_bias = self.fuzzy.edge_bias.clamp(0.0, 1.0);
        self.fuzzy.aarnn_weight = self.fuzzy.aarnn_weight.clamp(0.0, 1.0);
        self.fuzzy.security_weight = self.fuzzy.security_weight.clamp(0.0, 1.0);

        self.storage.max_bytes = self.storage.max_bytes.clamp(1_000_000, 1_000_000_000);
        self.storage.max_total_bytes = self
            .storage
            .max_total_bytes
            .clamp(1_000_000, 10_000_000_000);
        self.storage.retain_lines = self.storage.retain_lines.clamp(100, 100_000);
        self.storage.compact_interval_ms = self.storage.compact_interval_ms.clamp(5_000, 600_000);
        self.storage.rotate_archives = self.storage.rotate_archives.clamp(0, 20);
        self.storage.summary_top_keys = self.storage.summary_top_keys.clamp(5, 200);
        if self.storage.max_total_bytes < self.storage.max_bytes {
            self.storage.max_total_bytes = self.storage.max_bytes;
        }

        self.discovery.announce_interval_ms =
            self.discovery.announce_interval_ms.clamp(200, 60_000);
        self.discovery.ttl_ms = self.discovery.ttl_ms.clamp(1000, 120_000);
        if self.discovery.shared_key.trim().is_empty() {
            self.discovery.enabled = false;
        }

        self.asset_feed.poll_interval_ms = self.asset_feed.poll_interval_ms.clamp(500, 60_000);

        self.inventory.agent_ttl_ms = self.inventory.agent_ttl_ms.clamp(5_000, 600_000);
        self.inventory.host_ttl_ms = self.inventory.host_ttl_ms.clamp(10_000, 900_000);
        self.inventory.unmanaged_resend_ms =
            self.inventory.unmanaged_resend_ms.clamp(10_000, 600_000);

        self.refiner.poll_interval_ms = self.refiner.poll_interval_ms.clamp(500, 120_000);
        self.refiner.timeout_ms = self.refiner.timeout_ms.clamp(250, 15_000);
        if self.refiner.health_url.trim().is_empty() {
            self.refiner.enabled = false;
        }

        self.tuning.target_alert_rate = self.tuning.target_alert_rate.clamp(0.01, 0.5);
        self.tuning.adjustment_rate = self.tuning.adjustment_rate.clamp(0.005, 0.25);
        self.tuning.min_threshold = self.tuning.min_threshold.clamp(0.2, 0.9);
        self.tuning.max_threshold = self
            .tuning
            .max_threshold
            .clamp(self.tuning.min_threshold, 0.99);
        self.tuning.window_ms = self.tuning.window_ms.clamp(1000, 120_000);

        self.update.poll_interval_ms = self.update.poll_interval_ms.clamp(1000, 120_000);
        self.update.handoff_timeout_ms = self.update.handoff_timeout_ms.clamp(1000, 60_000);
        if self.update.shared_key.trim().is_empty() {
            self.update.enabled = false;
        }
        self.update.remote.timeout_ms = self.update.remote.timeout_ms.clamp(1000, 30_000);

        self.loader.announce_interval_ms = self.loader.announce_interval_ms.clamp(200, 60_000);
        self.loader.sync_interval_ms = self.loader.sync_interval_ms.clamp(500, 120_000);
        self.loader.ttl_ms = self.loader.ttl_ms.clamp(1000, 120_000);
        self.loader.request_timeout_ms = self.loader.request_timeout_ms.clamp(500, 30_000);
        self.loader.handoff_timeout_ms = self.loader.handoff_timeout_ms.clamp(1000, 60_000);
        self.loader.integrity_check_interval_ms = self
            .loader
            .integrity_check_interval_ms
            .clamp(5_000, 3_600_000);
        self.loader.rollback_window_ms = self.loader.rollback_window_ms.clamp(1_000, 86_400_000);

        self.telemetry.scrape_interval_ms = self.telemetry.scrape_interval_ms.clamp(500, 120_000);
        self.telemetry.max_samples = self.telemetry.max_samples.clamp(10, 10_000);
        self.telemetry.timeout_ms = self.telemetry.timeout_ms.clamp(500, 15_000);
        self.telemetry.dedup_ttl_ms = self.telemetry.dedup_ttl_ms.clamp(1000, 300_000);

        self.prometheus_log_export.probe_interval_ms = self
            .prometheus_log_export
            .probe_interval_ms
            .clamp(500, 300_000);
        self.prometheus_log_export.probe_timeout_ms = self
            .prometheus_log_export
            .probe_timeout_ms
            .clamp(200, 30_000);
        self.prometheus_log_export.forward_interval_ms = self
            .prometheus_log_export
            .forward_interval_ms
            .clamp(200, 60_000);
        self.prometheus_log_export.batch_ttl_ms = self
            .prometheus_log_export
            .batch_ttl_ms
            .clamp(1_000, 300_000);
        self.prometheus_log_export.max_batch = self.prometheus_log_export.max_batch.clamp(1, 1_024);
        self.prometheus_log_export.max_queue =
            self.prometheus_log_export.max_queue.clamp(32, 65_535);
        self.prometheus_log_export.min_signal =
            self.prometheus_log_export.min_signal.clamp(0.0, 1.0);
        self.prometheus_log_export.min_decision_risk =
            self.prometheus_log_export.min_decision_risk.clamp(0.0, 1.0);
        self.prometheus_log_export.series_ttl_ms = self
            .prometheus_log_export
            .series_ttl_ms
            .clamp(60_000, 7 * 86_400_000);
        if self.prometheus_log_export.server_url.trim().is_empty() {
            self.prometheus_log_export.enabled = false;
        }

        self.embedded.interval_ms = self.embedded.interval_ms.clamp(500, 60_000);
        self.embedded.max_thermals = self.embedded.max_thermals.clamp(1, 64);
        self.embedded.max_disks = self.embedded.max_disks.clamp(1, 64);
        self.embedded.max_interfaces = self.embedded.max_interfaces.clamp(1, 64);
        self.embedded.process_top_n = self.embedded.process_top_n.clamp(1, 50);
        self.embedded.process_window_ms = self.embedded.process_window_ms.clamp(1000, 120_000);
        self.embedded.process_max = self.embedded.process_max.clamp(64, 65_535);
        self.embedded.gpu_max_devices = self.embedded.gpu_max_devices.clamp(1, 32);

        self.tracey_guard.scheduler_poll_ms = self.tracey_guard.scheduler_poll_ms.clamp(50, 10_000);
        self.tracey_guard.max_parallel_tasks = self.tracey_guard.max_parallel_tasks.clamp(1, 1024);
        self.tracey_guard.overhead_budget_pct =
            self.tracey_guard.overhead_budget_pct.clamp(0.1, 50.0);
        self.tracey_guard.max_devices = self.tracey_guard.max_devices.clamp(1, 256);
        self.tracey_guard.synthetic_devices = self.tracey_guard.synthetic_devices.clamp(1, 256);
        self.tracey_guard.default_sm_count = self.tracey_guard.default_sm_count.clamp(1, 256);
        self.tracey_guard.max_advertised_faults =
            self.tracey_guard.max_advertised_faults.clamp(1, 4096);
        self.tracey_guard.remote_fault_ttl_ms =
            self.tracey_guard.remote_fault_ttl_ms.clamp(1_000, 600_000);
        self.tracey_guard.deep_dive_max_faults =
            self.tracey_guard.deep_dive_max_faults.clamp(8, 10_000);
        self.tracey_guard.tmr.interval_ms =
            self.tracey_guard.tmr.interval_ms.clamp(5_000, 3_600_000);
        self.tracey_guard.tmr.timeout_ms = self.tracey_guard.tmr.timeout_ms.clamp(500, 120_000);
        self.tracey_guard.tmr.triples_per_interval =
            self.tracey_guard.tmr.triples_per_interval.clamp(1, 128);
        self.tracey_guard.correlation.window_ms = self
            .tracey_guard
            .correlation
            .window_ms
            .clamp(5_000, 3_600_000);
        self.tracey_guard.correlation.min_confidence =
            self.tracey_guard.correlation.min_confidence.clamp(0.0, 1.0);
        self.tracey_guard.correlation.healthy_to_suspect = self
            .tracey_guard
            .correlation
            .healthy_to_suspect
            .clamp(0.50, 0.999);
        self.tracey_guard.correlation.suspect_to_quarantine = self
            .tracey_guard
            .correlation
            .suspect_to_quarantine
            .clamp(0.10, self.tracey_guard.correlation.healthy_to_suspect);
        self.tracey_guard.correlation.quarantine_to_healthy = self
            .tracey_guard
            .correlation
            .quarantine_to_healthy
            .clamp(self.tracey_guard.correlation.healthy_to_suspect, 0.999);
        self.tracey_guard.correlation.immediate_quarantine_failures = self
            .tracey_guard
            .correlation
            .immediate_quarantine_failures
            .clamp(1, 32);
        self.tracey_guard.correlation.deep_test_passes = self
            .tracey_guard
            .correlation
            .deep_test_passes
            .clamp(1, 10_000);
        sanitize_probe_cfg(&mut self.tracey_guard.probes.fma);
        sanitize_probe_cfg(&mut self.tracey_guard.probes.tensor_core);
        sanitize_probe_cfg(&mut self.tracey_guard.probes.transcendental);
        sanitize_probe_cfg(&mut self.tracey_guard.probes.aes);
        sanitize_probe_cfg(&mut self.tracey_guard.probes.memory);
        sanitize_probe_cfg(&mut self.tracey_guard.probes.register_file);
        sanitize_probe_cfg(&mut self.tracey_guard.probes.shared_memory);

        self.tracey_ban.max_advertised_ips = self.tracey_ban.max_advertised_ips.clamp(1, 2048);
        self.tracey_ban.remote_ttl_ms = self.tracey_ban.remote_ttl_ms.clamp(1_000, 300_000);
        self.tracey_ban.unban_check_ms = self.tracey_ban.unban_check_ms.clamp(200, 120_000);
        self.tracey_ban.persist_interval_ms =
            self.tracey_ban.persist_interval_ms.clamp(500, 300_000);
        if self.tracey_ban.sudo_program.trim().is_empty() {
            self.tracey_ban.sudo_program = "sudo".to_string();
        }
        self.tracey_ban.min_samples = self.tracey_ban.min_samples.clamp(3, 10_000);
        self.tracey_ban.fuzzy.order = self.tracey_ban.fuzzy.order.clamp(1, 8);
        self.tracey_ban.fuzzy.uncertainty = self.tracey_ban.fuzzy.uncertainty.clamp(0.0, 1.0);
        self.tracey_ban.fuzzy.edge_bias = self.tracey_ban.fuzzy.edge_bias.clamp(0.0, 1.0);
        self.tracey_ban.fuzzy.aarnn_weight = self.tracey_ban.fuzzy.aarnn_weight.clamp(0.0, 1.0);
        self.tracey_ban.fuzzy.security_weight =
            self.tracey_ban.fuzzy.security_weight.clamp(0.0, 1.0);
        self.tracey_ban.fuzzy_min_risk = self.tracey_ban.fuzzy_min_risk.clamp(0.0, 1.0);
        self.tracey_ban.fuzzy_min_confidence = self.tracey_ban.fuzzy_min_confidence.clamp(0.0, 1.0);
        self.tracey_ban.fuzzy_retry_reduction =
            self.tracey_ban.fuzzy_retry_reduction.clamp(0.0, 0.95);
        if self.tracey_ban.agent_id.trim().is_empty() {
            self.tracey_ban.agent_id = self.agent_id.clone();
        }
        for (idx, jail) in self.tracey_ban.jails.iter_mut().enumerate() {
            if jail.name.trim().is_empty() {
                jail.name = format!("tracey-jail-{}", idx + 1);
            }
            jail.backend = jail.backend.trim().to_ascii_lowercase();
            if jail.backend.is_empty() {
                jail.backend = "tracey_event".to_string();
            }
            jail.max_retry = jail.max_retry.clamp(1, 100);
            jail.find_time_ms = jail.find_time_ms.clamp(1_000, 86_400_000);
            jail.ban_time_ms = jail.ban_time_ms.clamp(-1, 86_400_000);
            jail.ban_multiplier = jail.ban_multiplier.clamp(1.0, 64.0);
            jail.ban_max_time_ms = jail.ban_max_time_ms.clamp(0, 604_800_000);
            jail.ban_randomize_ms = jail.ban_randomize_ms.clamp(0, 300_000);
            jail.poll_interval_ms = jail.poll_interval_ms.clamp(100, 120_000);
            jail.action_timeout_ms = jail.action_timeout_ms.clamp(250, 120_000);
            if jail.shell.trim().is_empty() {
                jail.shell = "/bin/sh".to_string();
            }
            if jail.event_ip_keys.is_empty() {
                jail.event_ip_keys = TraceyBanJailConfig::default().event_ip_keys;
            }
        }

        self.governance.vote_interval_ms = self.governance.vote_interval_ms.clamp(500, 30_000);
        self.governance.vote_ttl_ms = self.governance.vote_ttl_ms.clamp(1000, 60_000);
        self.governance.quorum = self.governance.quorum.clamp(1, self.agents.max(1));
        self.governance.decision_threshold = self.governance.decision_threshold.clamp(0.5, 0.95);
        self.governance.min_confidence = self.governance.min_confidence.clamp(0.1, 0.95);
        self.governance.relaxed_risk = self.governance.relaxed_risk.clamp(0.0, 1.0);
        self.governance.strict_risk = self
            .governance
            .strict_risk
            .clamp(self.governance.relaxed_risk, 1.0);
        self.governance.lockdown_risk = self
            .governance
            .lockdown_risk
            .clamp(self.governance.strict_risk, 1.0);
        self.governance.rebel.probability = self.governance.rebel.probability.clamp(0.0, 0.5);
        self.governance.rebel.max_streak = self.governance.rebel.max_streak.clamp(1, 10);
        self.governance.rebel.cooldown_ms = self.governance.rebel.cooldown_ms.clamp(1000, 120_000);

        self.coordination.election_interval_ms =
            self.coordination.election_interval_ms.clamp(250, 10_000);
        self.coordination.presence_ttl_ms = self.coordination.presence_ttl_ms.clamp(1_000, 120_000);
        self.coordination.max_coordinators = self.coordination.max_coordinators.clamp(1, 16);
        self.coordination.weight_cpu = self.coordination.weight_cpu.clamp(0.0, 10.0);
        self.coordination.weight_latency = self.coordination.weight_latency.clamp(0.0, 10.0);
        self.coordination.weight_hash = self.coordination.weight_hash.clamp(0.0, 10.0);
        self.coordination.weight_capability = self.coordination.weight_capability.clamp(0.0, 10.0);
        self.coordination.weight_prometheus_latency =
            self.coordination.weight_prometheus_latency.clamp(0.0, 10.0);
        self.coordination.weight_prometheus_bandwidth = self
            .coordination
            .weight_prometheus_bandwidth
            .clamp(0.0, 10.0);
        self.continuum_autoscaler.poll_interval_ms = self
            .continuum_autoscaler
            .poll_interval_ms
            .clamp(1_000, 300_000);
        self.continuum_autoscaler.local_cpu_usage_pct = self
            .continuum_autoscaler
            .local_cpu_usage_pct
            .clamp(0.0, 100.0);
        self.continuum_autoscaler.local_memory_usage_pct = self
            .continuum_autoscaler
            .local_memory_usage_pct
            .clamp(0.0, 100.0);
        self.continuum_autoscaler.slurm_allocated_ratio = self
            .continuum_autoscaler
            .slurm_allocated_ratio
            .clamp(0.0, 1.0);
        self.continuum_autoscaler.max_recruits_per_tick =
            self.continuum_autoscaler.max_recruits_per_tick.clamp(1, 16);
        if self.continuum_autoscaler.base_url.trim().is_empty()
            || self.continuum_autoscaler.recruit_hosts.is_empty()
        {
            self.continuum_autoscaler.enabled = false;
        }

        if self.status.listen_addr.trim().is_empty() {
            self.status.enabled = false;
        }
        self.status.proxy_timeout_ms = self.status.proxy_timeout_ms.clamp(200, 10_000);
        if !self.status.enabled {
            self.prometheus_log_export.enabled = false;
        }

        if self.stimuli.listen_addr.trim().is_empty() {
            self.stimuli.enabled = false;
        }
        self.stimuli.flush_interval_ms = self.stimuli.flush_interval_ms.clamp(50, 10_000);
        self.stimuli.posture_interval_ms = self.stimuli.posture_interval_ms.clamp(250, 30_000);
        self.stimuli.max_batch = self.stimuli.max_batch.clamp(1, 4096);
        self.stimuli.max_packet_bytes = self.stimuli.max_packet_bytes.clamp(256, 65_000);

        self.auth.oidc.cache_ttl_ms = self.auth.oidc.cache_ttl_ms.clamp(5_000, 300_000);
        self.auth.oidc.leeway_sec = self.auth.oidc.leeway_sec.clamp(0, 300);
        self.auth.oidc.http_timeout_ms = self.auth.oidc.http_timeout_ms.clamp(500, 15_000);
    }

    /// Applies environment variable overrides for selected runtime settings.
    fn apply_env_overrides(&mut self) {
        if let Some(value) = env_bool_any(&["TRACEY_FUZZY_ENABLED", "NM_FUZZY_ENABLED"]) {
            self.fuzzy.enabled = value;
        }
        if let Some(value) = env_u64_any(&["TRACEY_FUZZY_ORDER", "NM_FUZZY_ORDER"]) {
            self.fuzzy.order = value as u8;
        }
        if let Some(value) = env_f64_any(&["TRACEY_FUZZY_UNCERTAINTY", "NM_FUZZY_UNCERTAINTY"]) {
            self.fuzzy.uncertainty = value;
        }
        if let Some(value) = env_f64_any(&["TRACEY_FUZZY_EDGE_BIAS", "NM_FUZZY_EDGE_BIAS"]) {
            self.fuzzy.edge_bias = value;
        }
        if let Some(value) = env_f64_any(&["TRACEY_FUZZY_AARNN_WEIGHT", "NM_FUZZY_AARNN_WEIGHT"]) {
            self.fuzzy.aarnn_weight = value;
        }
        if let Some(value) =
            env_f64_any(&["TRACEY_FUZZY_SECURITY_WEIGHT", "NM_FUZZY_SECURITY_WEIGHT"])
        {
            self.fuzzy.security_weight = value;
        }

        if let Some(value) = env_any(&["TRACEY_DISCOVERY_SHARED_KEY", "NM_DISCOVERY_SHARED_KEY"]) {
            self.discovery.shared_key = value;
        }
        if let Some(value) = env_any(&["TRACEY_UPDATE_SHARED_KEY", "NM_UPDATE_SHARED_KEY"]) {
            self.update.shared_key = value;
        }
        if let Some(value) = env_any(&["TRACEY_UPDATE_LOCAL_CHANNEL", "NM_UPDATE_LOCAL_CHANNEL"])
            && let Ok(channel) = crate::update::UpdateChannel::from_str(&value)
        {
            self.update.local_channel = channel;
        }
        if let Some(value) = env_u64_any(&[
            "TRACEY_LOADER_ROLLBACK_WINDOW_MS",
            "NM_LOADER_ROLLBACK_WINDOW_MS",
        ]) {
            self.loader.rollback_window_ms = value;
        }

        if let Some(value) = env_bool_any(&["TRACEY_GUARD_ENABLED", "NM_TRACEY_GUARD_ENABLED"]) {
            self.tracey_guard.enabled = value;
        }
        if let Some(value) =
            env_f64_any(&["TRACEY_GUARD_OVERHEAD_PCT", "NM_TRACEY_GUARD_OVERHEAD_PCT"])
        {
            self.tracey_guard.overhead_budget_pct = value;
        }
        if let Some(value) = env_u64_any(&["TRACEY_GUARD_POLL_MS", "NM_TRACEY_GUARD_POLL_MS"]) {
            self.tracey_guard.scheduler_poll_ms = value;
        }
        if let Some(value) = env_u64_any(&[
            "TRACEY_GUARD_REMOTE_TTL_MS",
            "NM_TRACEY_GUARD_REMOTE_TTL_MS",
        ]) {
            self.tracey_guard.remote_fault_ttl_ms = value;
        }

        if let Some(value) = env_bool_any(&["TRACEY_BAN_ENABLED", "NM_TRACEY_BAN_ENABLED"]) {
            self.tracey_ban.enabled = value;
        }
        if let Some(value) = env_bool_any(&[
            "TRACEY_BAN_AUTO_ELEVATE_ROOT",
            "NM_TRACEY_BAN_AUTO_ELEVATE_ROOT",
        ]) {
            self.tracey_ban.auto_elevate_root = value;
        }
        if let Some(value) = env_any(&["TRACEY_BAN_SUDO_PROGRAM", "NM_TRACEY_BAN_SUDO_PROGRAM"]) {
            self.tracey_ban.sudo_program = value;
        }
        if let Some(value) = env_bool_any(&[
            "TRACEY_BAN_SUDO_NON_INTERACTIVE",
            "NM_TRACEY_BAN_SUDO_NON_INTERACTIVE",
        ]) {
            self.tracey_ban.sudo_non_interactive = value;
        }
        if let Some(value) = env_bool_any(&[
            "TRACEY_BAN_USE_SUDO_FOR_ACTIONS",
            "NM_TRACEY_BAN_USE_SUDO_FOR_ACTIONS",
        ]) {
            self.tracey_ban.use_sudo_for_actions = value;
        }
        if let Some(value) = env_bool_any(&[
            "TRACEY_BAN_INHERIT_GLOBAL_FUZZY",
            "NM_TRACEY_BAN_INHERIT_GLOBAL_FUZZY",
        ]) {
            self.tracey_ban.inherit_global_fuzzy = value;
        }
        if let Some(value) = env_any(&["TRACEY_BAN_STATE_PATH", "NM_TRACEY_BAN_STATE_PATH"]) {
            self.tracey_ban.state_path = PathBuf::from(value);
        }
        if let Some(value) = env_u64_any(&[
            "TRACEY_BAN_MAX_ADVERTISED_IPS",
            "NM_TRACEY_BAN_MAX_ADVERTISED_IPS",
        ]) {
            self.tracey_ban.max_advertised_ips = value as usize;
        }
        if let Some(value) =
            env_u64_any(&["TRACEY_BAN_REMOTE_TTL_MS", "NM_TRACEY_BAN_REMOTE_TTL_MS"])
        {
            self.tracey_ban.remote_ttl_ms = value;
        }
        if let Some(value) =
            env_u64_any(&["TRACEY_BAN_UNBAN_CHECK_MS", "NM_TRACEY_BAN_UNBAN_CHECK_MS"])
        {
            self.tracey_ban.unban_check_ms = value;
        }
        if let Some(value) = env_u64_any(&[
            "TRACEY_BAN_PERSIST_INTERVAL_MS",
            "NM_TRACEY_BAN_PERSIST_INTERVAL_MS",
        ]) {
            self.tracey_ban.persist_interval_ms = value;
        }
        if let Some(value) = env_u64_any(&["TRACEY_BAN_MIN_SAMPLES", "NM_TRACEY_BAN_MIN_SAMPLES"]) {
            self.tracey_ban.min_samples = value;
        }
        if let Some(value) =
            env_f64_any(&["TRACEY_BAN_FUZZY_MIN_RISK", "NM_TRACEY_BAN_FUZZY_MIN_RISK"])
        {
            self.tracey_ban.fuzzy_min_risk = value;
        }
        if let Some(value) = env_f64_any(&[
            "TRACEY_BAN_FUZZY_MIN_CONFIDENCE",
            "NM_TRACEY_BAN_FUZZY_MIN_CONFIDENCE",
        ]) {
            self.tracey_ban.fuzzy_min_confidence = value;
        }
        if let Some(value) = env_f64_any(&[
            "TRACEY_BAN_FUZZY_RETRY_REDUCTION",
            "NM_TRACEY_BAN_FUZZY_RETRY_REDUCTION",
        ]) {
            self.tracey_ban.fuzzy_retry_reduction = value;
        }
        if let Some(value) =
            env_bool_any(&["TRACEY_BAN_FUZZY_ENABLED", "NM_TRACEY_BAN_FUZZY_ENABLED"])
        {
            self.tracey_ban.fuzzy.enabled = value;
        }
        if let Some(value) = env_u64_any(&["TRACEY_BAN_FUZZY_ORDER", "NM_TRACEY_BAN_FUZZY_ORDER"]) {
            self.tracey_ban.fuzzy.order = value as u8;
        }
        if let Some(value) = env_f64_any(&[
            "TRACEY_BAN_FUZZY_UNCERTAINTY",
            "NM_TRACEY_BAN_FUZZY_UNCERTAINTY",
        ]) {
            self.tracey_ban.fuzzy.uncertainty = value;
        }
        if let Some(value) = env_f64_any(&[
            "TRACEY_BAN_FUZZY_EDGE_BIAS",
            "NM_TRACEY_BAN_FUZZY_EDGE_BIAS",
        ]) {
            self.tracey_ban.fuzzy.edge_bias = value;
        }
        if let Some(value) = env_f64_any(&[
            "TRACEY_BAN_FUZZY_AARNN_WEIGHT",
            "NM_TRACEY_BAN_FUZZY_AARNN_WEIGHT",
        ]) {
            self.tracey_ban.fuzzy.aarnn_weight = value;
        }
        if let Some(value) = env_f64_any(&[
            "TRACEY_BAN_FUZZY_SECURITY_WEIGHT",
            "NM_TRACEY_BAN_FUZZY_SECURITY_WEIGHT",
        ]) {
            self.tracey_ban.fuzzy.security_weight = value;
        }

        if let Some(mode) = env_any(&["TRACEY_AUTH_MODE", "NM_AUTH_MODE"]) {
            self.auth.mode = mode.to_lowercase();
        }
        if let Some(value) = env_any(&["TRACEY_STORAGE_PATH", "NM_STORAGE_PATH"]) {
            self.storage.log_path = PathBuf::from(value);
        }
        if let Some(value) = env_u64_any(&["TRACEY_STORAGE_MAX_BYTES", "NM_STORAGE_MAX_BYTES"]) {
            self.storage.max_bytes = value;
        }
        if let Some(value) = env_u64_any(&[
            "TRACEY_STORAGE_MAX_TOTAL_BYTES",
            "NM_STORAGE_MAX_TOTAL_BYTES",
        ]) {
            self.storage.max_total_bytes = value;
        }
        if let Some(value) =
            env_u64_any(&["TRACEY_STORAGE_RETAIN_LINES", "NM_STORAGE_RETAIN_LINES"])
        {
            self.storage.retain_lines = value as usize;
        }
        if let Some(value) = env_u64_any(&[
            "TRACEY_STORAGE_COMPACT_INTERVAL_MS",
            "NM_STORAGE_COMPACT_INTERVAL_MS",
        ]) {
            self.storage.compact_interval_ms = value;
        }
        if let Some(value) = env_u64_any(&[
            "TRACEY_STORAGE_ROTATE_ARCHIVES",
            "NM_STORAGE_ROTATE_ARCHIVES",
        ]) {
            self.storage.rotate_archives = value as usize;
        }
        if let Some(value) = env_u64_any(&[
            "TRACEY_STORAGE_SUMMARY_TOP_KEYS",
            "NM_STORAGE_SUMMARY_TOP_KEYS",
        ]) {
            self.storage.summary_top_keys = value as usize;
        }
        if let Some(value) = env_bool_any(&["TRACEY_REFINER_ENABLED", "NM_REFINER_ENABLED"]) {
            self.refiner.enabled = value;
        }
        if let Some(value) = env_bool_any(&[
            "TRACEY_CONTINUUM_AUTOSCALER_ENABLED",
            "NM_TRACEY_CONTINUUM_AUTOSCALER_ENABLED",
        ]) {
            self.continuum_autoscaler.enabled = value;
        }
        if let Some(value) = env_any(&["TRACEY_CONTINUUM_URL", "NM_TRACEY_CONTINUUM_URL"]) {
            self.continuum_autoscaler.base_url = value;
        }
        if let Some(value) = env_any(&["TRACEY_CONTINUUM_TOKEN", "NM_TRACEY_CONTINUUM_TOKEN"]) {
            self.continuum_autoscaler.bearer_token = Some(value);
        }
        let recruit_hosts = env_csv_any(&["TRACEY_CONTINUUM_HOSTS", "NM_TRACEY_CONTINUUM_HOSTS"]);
        if !recruit_hosts.is_empty() {
            self.continuum_autoscaler.recruit_hosts = recruit_hosts;
        }
        if let Some(value) = env_any(&["TRACEY_CONTINUUM_USER", "NM_TRACEY_CONTINUUM_USER"]) {
            self.continuum_autoscaler.recruit_user = value;
        }
        if let Some(value) = env_any(&["TRACEY_CONTINUUM_SSH_KEY", "NM_TRACEY_CONTINUUM_SSH_KEY"]) {
            self.continuum_autoscaler.ssh_key_path = Some(value);
        }
        if let Some(value) = env_any(&[
            "TRACEY_CONTINUUM_NODE_TYPE",
            "NM_TRACEY_CONTINUUM_NODE_TYPE",
        ]) {
            self.continuum_autoscaler.node_type = value;
        }
        if let Some(value) = env_any(&["TRACEY_CONTINUUM_REGION", "NM_TRACEY_CONTINUUM_REGION"]) {
            self.continuum_autoscaler.region = Some(value);
        }
        if let Some(value) = env_any(&[
            "TRACEY_CONTINUUM_TENANT_ID",
            "NM_TRACEY_CONTINUUM_TENANT_ID",
        ]) {
            self.continuum_autoscaler.tenant_id = Some(value);
        }
        if let Some(value) = env_any(&[
            "TRACEY_CONTINUUM_TENANT_NAME",
            "NM_TRACEY_CONTINUUM_TENANT_NAME",
        ]) {
            self.continuum_autoscaler.tenant_name = Some(value);
        }
        if let Some(value) = env_any(&[
            "TRACEY_CONTINUUM_TENANT_ENV",
            "NM_TRACEY_CONTINUUM_TENANT_ENV",
        ]) {
            self.continuum_autoscaler.tenant_environment = Some(value);
        }
        if let Some(value) = env_any(&[
            "TRACEY_CONTINUUM_RECRUIT_TOKEN",
            "NM_TRACEY_CONTINUUM_RECRUIT_TOKEN",
        ]) {
            self.continuum_autoscaler.recruit_token = Some(value);
        }
        if let Some(value) = env_bool_any(&[
            "TRACEY_CONTINUUM_AUTO_CONFIGURE",
            "NM_TRACEY_CONTINUUM_AUTO_CONFIGURE",
        ]) {
            self.continuum_autoscaler.auto_configure = value;
        }
        if let Some(value) =
            env_bool_any(&["TRACEY_CONTINUUM_DRY_RUN", "NM_TRACEY_CONTINUUM_DRY_RUN"])
        {
            self.continuum_autoscaler.dry_run = value;
        }
        if let Some(value) = env_u64_any(&[
            "TRACEY_CONTINUUM_POLL_INTERVAL_MS",
            "NM_TRACEY_CONTINUUM_POLL_INTERVAL_MS",
        ]) {
            self.continuum_autoscaler.poll_interval_ms = value;
        }
        if let Some(value) = env_f64_any(&[
            "TRACEY_CONTINUUM_LOCAL_CPU_PCT",
            "NM_TRACEY_CONTINUUM_LOCAL_CPU_PCT",
        ]) {
            self.continuum_autoscaler.local_cpu_usage_pct = value as f32;
        }
        if let Some(value) = env_f64_any(&[
            "TRACEY_CONTINUUM_LOCAL_MEMORY_PCT",
            "NM_TRACEY_CONTINUUM_LOCAL_MEMORY_PCT",
        ]) {
            self.continuum_autoscaler.local_memory_usage_pct = value as f32;
        }
        if let Some(value) = env_u64_any(&[
            "TRACEY_CONTINUUM_COORDINATION_LATENCY_MS",
            "NM_TRACEY_CONTINUUM_COORDINATION_LATENCY_MS",
        ]) {
            self.continuum_autoscaler.coordination_latency_ms = value;
        }
        if let Some(value) = env_u64_any(&[
            "TRACEY_CONTINUUM_PROMETHEUS_LATENCY_MS",
            "NM_TRACEY_CONTINUUM_PROMETHEUS_LATENCY_MS",
        ]) {
            self.continuum_autoscaler.prometheus_latency_ms = value;
        }
        if let Some(value) = env_u64_any(&[
            "TRACEY_CONTINUUM_SLURM_PENDING_JOBS",
            "NM_TRACEY_CONTINUUM_SLURM_PENDING_JOBS",
        ]) {
            self.continuum_autoscaler.slurm_pending_jobs = value as u32;
        }
        if let Some(value) = env_f64_any(&[
            "TRACEY_CONTINUUM_SLURM_ALLOCATED_RATIO",
            "NM_TRACEY_CONTINUUM_SLURM_ALLOCATED_RATIO",
        ]) {
            self.continuum_autoscaler.slurm_allocated_ratio = value as f32;
        }
        if let Some(value) = env_u64_any(&[
            "TRACEY_CONTINUUM_MAX_RECRUITS_PER_TICK",
            "NM_TRACEY_CONTINUUM_MAX_RECRUITS_PER_TICK",
        ]) {
            self.continuum_autoscaler.max_recruits_per_tick = value as usize;
        }
        if let Some(value) = env_any(&["TRACEY_REFINER_SOURCE", "NM_REFINER_SOURCE"]) {
            self.refiner.source = value;
        }
        if let Some(value) = env_any(&["TRACEY_REFINER_SERVICE", "NM_REFINER_SERVICE"]) {
            self.refiner.service_name = value;
        }
        if let Some(value) = env_any(&["TRACEY_REFINER_HEALTH_URL", "NM_REFINER_HEALTH_URL"]) {
            self.refiner.health_url = value;
        }
        if let Some(value) = env_any(&[
            "TRACEY_REFINER_SECURITY_FEED_PATH",
            "NM_REFINER_SECURITY_FEED_PATH",
        ]) {
            self.refiner.security_feed_path = PathBuf::from(value);
        }
        if let Some(value) = env_u64_any(&[
            "TRACEY_REFINER_POLL_INTERVAL_MS",
            "NM_REFINER_POLL_INTERVAL_MS",
        ]) {
            self.refiner.poll_interval_ms = value;
        }
        if let Some(value) = env_u64_any(&["TRACEY_REFINER_TIMEOUT_MS", "NM_REFINER_TIMEOUT_MS"]) {
            self.refiner.timeout_ms = value;
        }
        if let Some(value) = env_bool_any(&["TRACEY_EMBEDDED_ENABLED", "NM_EMBEDDED_ENABLED"]) {
            self.embedded.enabled = value;
        }
        if let Some(value) =
            env_u64_any(&["TRACEY_EMBEDDED_INTERVAL_MS", "NM_EMBEDDED_INTERVAL_MS"])
        {
            self.embedded.interval_ms = value;
        }
        if let Some(value) = env_bool_any(&[
            "TRACEY_EMBEDDED_JETSON_ENABLED",
            "NM_EMBEDDED_JETSON_ENABLED",
        ]) {
            self.embedded.jetson_enabled = value;
        }
        if let Some(value) =
            env_u64_any(&["TRACEY_EMBEDDED_MAX_THERMALS", "NM_EMBEDDED_MAX_THERMALS"])
        {
            self.embedded.max_thermals = value as usize;
        }
        if let Some(value) = env_u64_any(&["TRACEY_EMBEDDED_MAX_DISKS", "NM_EMBEDDED_MAX_DISKS"]) {
            self.embedded.max_disks = value as usize;
        }
        if let Some(value) = env_u64_any(&[
            "TRACEY_EMBEDDED_MAX_INTERFACES",
            "NM_EMBEDDED_MAX_INTERFACES",
        ]) {
            self.embedded.max_interfaces = value as usize;
        }
        if let Some(value) = env_bool_any(&[
            "TRACEY_EMBEDDED_PROCESS_ENABLED",
            "NM_EMBEDDED_PROCESS_ENABLED",
        ]) {
            self.embedded.process_enabled = value;
        }
        if let Some(value) =
            env_u64_any(&["TRACEY_EMBEDDED_PROCESS_TOP_N", "NM_EMBEDDED_PROCESS_TOP_N"])
        {
            self.embedded.process_top_n = value as usize;
        }
        if let Some(value) = env_u64_any(&[
            "TRACEY_EMBEDDED_PROCESS_WINDOW_MS",
            "NM_EMBEDDED_PROCESS_WINDOW_MS",
        ]) {
            self.embedded.process_window_ms = value;
        }
        if let Some(value) =
            env_u64_any(&["TRACEY_EMBEDDED_PROCESS_MAX", "NM_EMBEDDED_PROCESS_MAX"])
        {
            self.embedded.process_max = value as usize;
        }
        if let Some(value) =
            env_bool_any(&["TRACEY_EMBEDDED_GPU_ENABLED", "NM_EMBEDDED_GPU_ENABLED"])
        {
            self.embedded.gpu_enabled = value;
        }
        if let Some(value) = env_bool_any(&[
            "TRACEY_EMBEDDED_GPU_SYSFS_ENABLED",
            "NM_EMBEDDED_GPU_SYSFS_ENABLED",
        ]) {
            self.embedded.gpu_sysfs_enabled = value;
        }
        if let Some(value) = env_bool_any(&[
            "TRACEY_EMBEDDED_GPU_NVML_ENABLED",
            "NM_EMBEDDED_GPU_NVML_ENABLED",
        ]) {
            self.embedded.gpu_nvml_enabled = value;
        }
        if let Some(value) = env_bool_any(&[
            "TRACEY_EMBEDDED_GPU_ROCM_ENABLED",
            "NM_EMBEDDED_GPU_ROCM_ENABLED",
        ]) {
            self.embedded.gpu_rocm_enabled = value;
        }
        if let Some(value) = env_u64_any(&[
            "TRACEY_EMBEDDED_GPU_MAX_DEVICES",
            "NM_EMBEDDED_GPU_MAX_DEVICES",
        ]) {
            self.embedded.gpu_max_devices = value as usize;
        }
        if let Some(value) = env_bool_any(&[
            "TRACEY_PROMETHEUS_LOG_EXPORT_ENABLED",
            "NM_PROMETHEUS_LOG_EXPORT_ENABLED",
        ]) {
            self.prometheus_log_export.enabled = value;
        }
        if let Some(value) = env_any(&[
            "TRACEY_PROMETHEUS_LOG_EXPORT_URL",
            "NM_PROMETHEUS_LOG_EXPORT_URL",
        ]) {
            self.prometheus_log_export.server_url = value;
        }
        if let Some(value) = env_any(&[
            "TRACEY_PROMETHEUS_LOG_EXPORT_PROBE_PATH",
            "NM_PROMETHEUS_LOG_EXPORT_PROBE_PATH",
        ]) {
            self.prometheus_log_export.probe_path = value;
        }
        if let Some(value) = env_bool_any(&["TRACEY_OIDC_PROTECT_STATUS", "NM_OIDC_PROTECT_STATUS"])
        {
            self.auth.protect_status = value;
        }
        if let Some(value) =
            env_bool_any(&["TRACEY_OIDC_PROTECT_OTLP_HTTP", "NM_OIDC_PROTECT_OTLP_HTTP"])
        {
            self.auth.protect_otlp_http = value;
        }
        if let Some(value) =
            env_bool_any(&["TRACEY_OIDC_PROTECT_OTLP_GRPC", "NM_OIDC_PROTECT_OTLP_GRPC"])
        {
            self.auth.protect_otlp_grpc = value;
        }

        if let Some(issuer) = env_any(&["TRACEY_OIDC_ISSUER", "NM_OIDC_ISSUER"]) {
            self.auth.oidc.issuer = issuer;
        }
        if let Some(jwks) = env_any(&["TRACEY_OIDC_JWKS_URL", "NM_OIDC_JWKS_URL"]) {
            self.auth.oidc.jwks_url = Some(jwks);
        }
        if let Some(client_id) = env_any(&["TRACEY_OIDC_CLIENT_ID", "NM_OIDC_CLIENT_ID"]) {
            self.auth.oidc.client_id = Some(client_id);
        }

        let audiences = env_csv_any(&[
            "TRACEY_OIDC_AUDIENCE",
            "TRACEY_OIDC_ALLOWED_AUDIENCES",
            "TRACEY_OIDC_AUDIENCES",
            "NM_OIDC_AUDIENCE",
            "NM_OIDC_ALLOWED_AUDIENCES",
            "NM_OIDC_AUDIENCES",
        ]);
        if !audiences.is_empty() {
            self.auth.oidc.audiences = audiences;
        }

        let scopes = env_csv_any(&[
            "TRACEY_OIDC_REQUIRED_SCOPE",
            "TRACEY_OIDC_REQUIRED_SCOPES",
            "NM_OIDC_REQUIRED_SCOPE",
            "NM_OIDC_REQUIRED_SCOPES",
        ]);
        if !scopes.is_empty() {
            self.auth.oidc.required_scopes = scopes;
        }

        if let Some(ttl) = env_u64_any(&["TRACEY_OIDC_CACHE_TTL_MS", "NM_OIDC_CACHE_TTL_MS"]) {
            self.auth.oidc.cache_ttl_ms = ttl;
        }
        if let Some(leeway) = env_u64_any(&["TRACEY_OIDC_LEEWAY_SEC", "NM_OIDC_LEEWAY_SEC"]) {
            self.auth.oidc.leeway_sec = leeway;
        }
        if let Some(timeout) =
            env_u64_any(&["TRACEY_OIDC_HTTP_TIMEOUT_MS", "NM_OIDC_HTTP_TIMEOUT_MS"])
        {
            self.auth.oidc.http_timeout_ms = timeout;
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FuzzyConfig {
    pub enabled: bool,
    pub order: u8,
    pub uncertainty: f64,
    pub edge_bias: f64,
    pub aarnn_weight: f64,
    pub security_weight: f64,
}

impl Default for FuzzyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            order: 3,
            uncertainty: 0.55,
            edge_bias: 0.70,
            aarnn_weight: 0.22,
            security_weight: 0.28,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CoordinationConfig {
    pub enabled: bool,
    pub max_coordinators: usize,
    pub election_interval_ms: u64,
    pub presence_ttl_ms: u64,
    pub weight_cpu: f64,
    pub weight_latency: f64,
    pub weight_hash: f64,
    pub weight_capability: f64,
    pub weight_prometheus_latency: f64,
    pub weight_prometheus_bandwidth: f64,
}

impl Default for CoordinationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_coordinators: 2,
            election_interval_ms: 1000,
            presence_ttl_ms: 8000,
            weight_cpu: 1.0,
            weight_latency: 1.5,
            weight_hash: 0.1,
            weight_capability: 0.5,
            weight_prometheus_latency: 2.5,
            weight_prometheus_bandwidth: 1.2,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ContinuumAutoscalerConfig {
    pub enabled: bool,
    pub poll_interval_ms: u64,
    pub base_url: String,
    pub bearer_token: Option<String>,
    pub recruit_hosts: Vec<String>,
    pub recruit_user: String,
    pub ssh_key_path: Option<String>,
    pub node_type: String,
    pub region: Option<String>,
    pub tenant_id: Option<String>,
    pub tenant_name: Option<String>,
    pub tenant_environment: Option<String>,
    pub recruit_token: Option<String>,
    pub auto_configure: bool,
    pub dry_run: bool,
    pub local_cpu_usage_pct: f32,
    pub local_memory_usage_pct: f32,
    pub coordination_latency_ms: u64,
    pub prometheus_latency_ms: u64,
    pub slurm_pending_jobs: u32,
    pub slurm_allocated_ratio: f32,
    pub max_recruits_per_tick: usize,
}

impl Default for ContinuumAutoscalerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            poll_interval_ms: 5_000,
            base_url: String::new(),
            bearer_token: None,
            recruit_hosts: Vec::new(),
            recruit_user: "ubuntu".to_string(),
            ssh_key_path: None,
            node_type: "kubernetes".to_string(),
            region: None,
            tenant_id: None,
            tenant_name: None,
            tenant_environment: None,
            recruit_token: None,
            auto_configure: true,
            dry_run: true,
            local_cpu_usage_pct: 75.0,
            local_memory_usage_pct: 80.0,
            coordination_latency_ms: 40,
            prometheus_latency_ms: 35,
            slurm_pending_jobs: 1,
            slurm_allocated_ratio: 0.80,
            max_recruits_per_tick: 1,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LoaderConfig {
    pub enabled: bool,
    pub state_dir: PathBuf,
    pub discovery_bind_addr: String,
    pub discovery_broadcast_addr: String,
    pub advertise_addr: Option<String>,
    pub transfer_listen_addr: String,
    pub transfer_public_addr: Option<String>,
    pub announce_interval_ms: u64,
    pub sync_interval_ms: u64,
    pub ttl_ms: u64,
    pub request_timeout_ms: u64,
    pub handoff_timeout_ms: u64,
    pub integrity_check_interval_ms: u64,
    pub rollback_window_ms: u64,
    pub bootstrap_version: Option<String>,
}

impl Default for LoaderConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            state_dir: PathBuf::from("loader"),
            discovery_bind_addr: "0.0.0.0:47989".to_string(),
            discovery_broadcast_addr: "255.255.255.255:47989".to_string(),
            advertise_addr: None,
            transfer_listen_addr: "0.0.0.0:47988".to_string(),
            transfer_public_addr: None,
            announce_interval_ms: 1500,
            sync_interval_ms: 5000,
            ttl_ms: 10_000,
            request_timeout_ms: 3000,
            handoff_timeout_ms: 10_000,
            integrity_check_interval_ms: 30_000,
            rollback_window_ms: 120_000,
            bootstrap_version: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StatusConfig {
    pub enabled: bool,
    pub listen_addr: String,
    pub public_addr: Option<String>,
    pub proxy_timeout_ms: u64,
}

impl Default for StatusConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen_addr: "0.0.0.0:48000".to_string(),
            public_addr: None,
            proxy_timeout_ms: 1500,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StimuliConfig {
    pub enabled: bool,
    pub listen_addr: String,
    pub peer_addr: Option<String>,
    pub flush_interval_ms: u64,
    pub posture_interval_ms: u64,
    pub max_batch: usize,
    pub max_packet_bytes: usize,
}

impl Default for StimuliConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_addr: "0.0.0.0:48100".to_string(),
            peer_addr: None,
            flush_interval_ms: 500,
            posture_interval_ms: 2000,
            max_batch: 128,
            max_packet_bytes: 8192,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthConfig {
    pub mode: String,
    pub protect_status: bool,
    pub protect_otlp_http: bool,
    pub protect_otlp_grpc: bool,
    pub oidc: OidcAuthConfig,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            mode: "off".to_string(),
            protect_status: true,
            protect_otlp_http: true,
            protect_otlp_grpc: false,
            oidc: OidcAuthConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OidcAuthConfig {
    pub issuer: String,
    pub jwks_url: Option<String>,
    pub client_id: Option<String>,
    pub audiences: Vec<String>,
    pub required_scopes: Vec<String>,
    pub cache_ttl_ms: u64,
    pub leeway_sec: u64,
    pub http_timeout_ms: u64,
}

impl OidcAuthConfig {
    pub fn enabled(&self) -> bool {
        !self.issuer.trim().is_empty()
            || self.jwks_url.as_deref().map(str::trim).unwrap_or("").len() > 0
    }
}

impl Default for OidcAuthConfig {
    fn default() -> Self {
        Self {
            issuer: String::new(),
            jwks_url: None,
            client_id: None,
            audiences: Vec::new(),
            required_scopes: Vec::new(),
            cache_ttl_ms: 60_000,
            leeway_sec: 60,
            http_timeout_ms: 3000,
        }
    }
}

fn sanitize_probe_cfg(cfg: &mut TraceyGuardProbeConfig) {
    cfg.period_ms = cfg.period_ms.clamp(100, 3_600_000);
    cfg.sm_coverage = cfg.sm_coverage.clamp(0.01, 1.0);
    cfg.priority = cfg.priority.clamp(1, 10);
    cfg.timeout_ms = cfg.timeout_ms.clamp(50, 120_000);
}

fn default_agent_id() -> String {
    let hostname = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "tracey".to_string());
    format!("{}-{}", hostname, std::process::id())
}

fn env_any(names: &[&str]) -> Option<String> {
    for name in names {
        if let Ok(value) = std::env::var(name) {
            let value = value.trim().to_string();
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

fn env_bool_any(names: &[&str]) -> Option<bool> {
    for name in names {
        if let Ok(value) = std::env::var(name) {
            let value = value.trim().to_lowercase();
            if value.is_empty() {
                continue;
            }
            let parsed = matches!(value.as_str(), "1" | "true" | "yes" | "on");
            return Some(parsed);
        }
    }
    None
}

fn env_u64_any(names: &[&str]) -> Option<u64> {
    for name in names {
        if let Ok(value) = std::env::var(name) {
            if let Ok(parsed) = value.trim().parse::<u64>() {
                return Some(parsed);
            }
        }
    }
    None
}

fn env_f64_any(names: &[&str]) -> Option<f64> {
    for name in names {
        if let Ok(value) = std::env::var(name) {
            if let Ok(parsed) = value.trim().parse::<f64>() {
                return Some(parsed);
            }
        }
    }
    None
}

fn env_csv_any(names: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for name in names {
        if let Ok(value) = std::env::var(name) {
            for item in value.split(',') {
                let item = item.trim();
                if item.is_empty() {
                    continue;
                }
                if seen.insert(item.to_string()) {
                    out.push(item.to_string());
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_probe_cfg_clamps_extremes() {
        let mut probe = TraceyGuardProbeConfig {
            enabled: true,
            period_ms: 1,
            sm_coverage: 5.0,
            priority: 99,
            timeout_ms: 1,
        };
        sanitize_probe_cfg(&mut probe);
        assert_eq!(probe.period_ms, 100);
        assert_eq!(probe.sm_coverage, 1.0);
        assert_eq!(probe.priority, 10);
        assert_eq!(probe.timeout_ms, 50);
    }

    #[test]
    fn oidc_config_enabled_when_issuer_or_jwks_present() {
        let mut cfg = OidcAuthConfig::default();
        assert!(!cfg.enabled());
        cfg.issuer = "https://issuer.example.com".to_string();
        assert!(cfg.enabled());
        cfg.issuer.clear();
        cfg.jwks_url = Some("https://issuer.example.com/jwks.json".to_string());
        assert!(cfg.enabled());
    }

    #[test]
    fn config_sanitize_clamps_core_ranges_and_disables_invalid_keys() {
        let mut cfg = Config::default();
        cfg.agents = 0;
        cfg.bus_capacity = 1;
        cfg.assessment_channel_capacity = 1;
        cfg.assessment_quorum = 9999;
        cfg.decision_threshold = 5.0;
        cfg.event_rate_ms = 1;
        cfg.discovery.enabled = true;
        cfg.discovery.shared_key = "   ".to_string();
        cfg.update.enabled = true;
        cfg.update.shared_key = "".to_string();

        cfg.sanitize();

        assert_eq!(cfg.agents, 1);
        assert_eq!(cfg.bus_capacity, 128);
        assert_eq!(cfg.assessment_channel_capacity, 128);
        assert_eq!(cfg.assessment_quorum, 1);
        assert_eq!(cfg.decision_threshold, 1.0);
        assert_eq!(cfg.event_rate_ms, 50);
        assert!(!cfg.discovery.enabled);
        assert!(!cfg.update.enabled);
    }
}
