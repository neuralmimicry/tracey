use crate::security::ActionPolicy;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StorageConfig {
    pub log_path: PathBuf,
    pub max_bytes: u64,
    pub retain_lines: usize,
    pub compact_interval_ms: u64,
    pub summary_top_keys: usize,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            log_path: PathBuf::from("tracey.log.jsonl"),
            max_bytes: 25_000_000,
            retain_lines: 5000,
            compact_interval_ms: 30_000,
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
    pub embedded: EmbeddedConfig,
    pub governance: crate::governance::GovernanceConfig,
    pub coordination: CoordinationConfig,
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
            embedded: EmbeddedConfig::default(),
            governance: crate::governance::GovernanceConfig::default(),
            coordination: CoordinationConfig::default(),
            status: StatusConfig::default(),
            stimuli: StimuliConfig::default(),
            auth: AuthConfig::default(),
        }
    }
}

impl Config {
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
        self.storage.retain_lines = self.storage.retain_lines.clamp(100, 100_000);
        self.storage.compact_interval_ms = self.storage.compact_interval_ms.clamp(5_000, 600_000);
        self.storage.summary_top_keys = self.storage.summary_top_keys.clamp(5, 200);

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

        self.telemetry.scrape_interval_ms = self.telemetry.scrape_interval_ms.clamp(500, 120_000);
        self.telemetry.max_samples = self.telemetry.max_samples.clamp(10, 10_000);
        self.telemetry.timeout_ms = self.telemetry.timeout_ms.clamp(500, 15_000);
        self.telemetry.dedup_ttl_ms = self.telemetry.dedup_ttl_ms.clamp(1000, 300_000);

        self.embedded.interval_ms = self.embedded.interval_ms.clamp(500, 60_000);
        self.embedded.max_thermals = self.embedded.max_thermals.clamp(1, 64);
        self.embedded.max_disks = self.embedded.max_disks.clamp(1, 64);
        self.embedded.max_interfaces = self.embedded.max_interfaces.clamp(1, 64);
        self.embedded.process_top_n = self.embedded.process_top_n.clamp(1, 50);
        self.embedded.process_window_ms = self.embedded.process_window_ms.clamp(1000, 120_000);
        self.embedded.process_max = self.embedded.process_max.clamp(64, 65_535);
        self.embedded.gpu_max_devices = self.embedded.gpu_max_devices.clamp(1, 32);

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

        if self.status.listen_addr.trim().is_empty() {
            self.status.enabled = false;
        }
        self.status.proxy_timeout_ms = self.status.proxy_timeout_ms.clamp(200, 10_000);

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

        if let Some(mode) = env_any(&["TRACEY_AUTH_MODE", "NM_AUTH_MODE"]) {
            self.auth.mode = mode.to_lowercase();
        }
        if let Some(value) = env_any(&["TRACEY_STORAGE_PATH", "NM_STORAGE_PATH"]) {
            self.storage.log_path = PathBuf::from(value);
        }
        if let Some(value) = env_u64_any(&["TRACEY_STORAGE_MAX_BYTES", "NM_STORAGE_MAX_BYTES"]) {
            self.storage.max_bytes = value;
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
            "TRACEY_STORAGE_SUMMARY_TOP_KEYS",
            "NM_STORAGE_SUMMARY_TOP_KEYS",
        ]) {
            self.storage.summary_top_keys = value as usize;
        }
        if let Some(value) = env_bool_any(&["TRACEY_REFINER_ENABLED", "NM_REFINER_ENABLED"]) {
            self.refiner.enabled = value;
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
