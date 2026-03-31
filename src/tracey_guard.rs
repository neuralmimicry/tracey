//! TraceyGuard runtime port: probe scheduling, fault correlation, and
//! distributed fault-intel exchange.

use crate::bus::EventBus;
use crate::config::{TraceyGuardConfig, TraceyGuardProbeConfig};
use crate::event::{Event, EventKind, Severity, now_ms};
use crate::gpu::GpuBackendConfig;
use crate::shutdown::ShutdownListener;
use crate::storage::Storage;
use crate::swarm::AdaptiveScorer;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Semaphore};

static TRACEY_GUARD_EVENT_COUNTER: AtomicU64 = AtomicU64::new(30_000_000);

// Snapshot caps prevent status payloads from growing without bound under prolonged fault storms.
const LOCAL_SNAPSHOT_MAX_FAULTS: usize = 128;
const LOCAL_SNAPSHOT_MAX_GPUS: usize = 64;
const LOCAL_SNAPSHOT_MAX_BUCKETS: usize = 360;

/// TraceyGuard probe identifiers translated from the upstream TraceyGuard probe-agent.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ProbeType {
    Fma,
    TensorCore,
    Transcendental,
    Aes,
    Memory,
    RegisterFile,
    SharedMemory,
}

impl ProbeType {
    pub fn as_str(self) -> &'static str {
        match self {
            ProbeType::Fma => "fma",
            ProbeType::TensorCore => "tensor_core",
            ProbeType::Transcendental => "transcendental",
            ProbeType::Aes => "aes",
            ProbeType::Memory => "memory",
            ProbeType::RegisterFile => "register_file",
            ProbeType::SharedMemory => "shared_memory",
        }
    }

    fn all() -> [ProbeType; 7] {
        [
            ProbeType::Fma,
            ProbeType::TensorCore,
            ProbeType::Transcendental,
            ProbeType::Aes,
            ProbeType::Memory,
            ProbeType::RegisterFile,
            ProbeType::SharedMemory,
        ]
    }
}

/// Probe execution terminal state.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProbeState {
    Pass,
    Fail,
    Error,
    Timeout,
}

impl ProbeState {
    fn as_str(self) -> &'static str {
        match self {
            ProbeState::Pass => "pass",
            ProbeState::Fail => "fail",
            ProbeState::Error => "error",
            ProbeState::Timeout => "timeout",
        }
    }

    fn severity(self) -> Severity {
        match self {
            ProbeState::Pass => Severity::Low,
            ProbeState::Fail => Severity::High,
            ProbeState::Error => Severity::Medium,
            ProbeState::Timeout => Severity::Critical,
        }
    }
}

/// Lifecycle state for device isolation flow translated from TraceyGuard quarantine logic.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TraceyGuardGpuState {
    Healthy,
    Suspect,
    Quarantined,
    DeepTest,
    Condemned,
}

#[derive(Clone, Debug, Default)]
struct DeviceTelemetryContext {
    // Rolling environmental context from embedded telemetry. The probe scheduler
    // and fault injector consume this to emulate workload-sensitive fault rates.
    temp_c: f64,
    power_w: f64,
    util_pct: f64,
    mem_used_ratio: f64,
    graphics_clock_ratio: f64,
    memory_clock_ratio: f64,
    fan_speed_ratio: f64,
    encoder_util_ratio: f64,
    decoder_util_ratio: f64,
    thermal_spike_count: u64,
    power_anomaly_count: u64,
    clock_anomaly_count: u64,
    codec_pressure_count: u64,
    ecc_error_count: u64,
    last_update_ms: u64,
}

#[derive(Clone, Debug)]
struct DeviceState {
    gpu_id: String,
    // Bayesian reliability posterior (Beta distribution parameters).
    state: TraceyGuardGpuState,
    alpha: f64,
    beta: f64,
    consecutive_failures: u32,
    deep_test_passes: u32,
    last_transition_ms: u64,
    last_reason: String,
    probe_pass_count: u64,
    probe_fail_count: u64,
    probe_error_count: u64,
    scorer: AdaptiveScorer,
}

impl DeviceState {
    fn new(gpu_id: String, sm_count: u32, cfg: &TraceyGuardConfig) -> Self {
        let _ = sm_count;
        Self {
            gpu_id,
            state: TraceyGuardGpuState::Healthy,
            alpha: 100.0,
            beta: 1.0,
            consecutive_failures: 0,
            deep_test_passes: 0,
            last_transition_ms: now_ms(),
            last_reason: "initial".to_string(),
            probe_pass_count: 0,
            probe_fail_count: 0,
            probe_error_count: 0,
            scorer: AdaptiveScorer::new(12, cfg.probes_fuzzy_profile()),
        }
    }

    fn reliability(&self) -> f64 {
        (self.alpha / (self.alpha + self.beta)).clamp(0.0, 1.0)
    }

    fn register_probe_outcome(
        &mut self,
        state: ProbeState,
        reason: &str,
        correlation: &crate::config::TraceyGuardCorrelationConfig,
        risk: f64,
        confidence: f64,
        remote_support: usize,
    ) {
        // Distributed corroboration raises confidence that a local mismatch is
        // real hardware degradation and not transient local noise.
        let remote_weight = (remote_support.min(8) as f64) * 0.20;
        let low_confidence_penalty =
            if confidence < correlation.min_confidence && remote_support == 0 {
                0.55
            } else {
                1.0
            };
        let high_risk_bonus = if risk >= 0.90 { 0.20 } else { 0.0 };

        match state {
            ProbeState::Pass => {
                self.alpha += 1.0;
                self.probe_pass_count = self.probe_pass_count.saturating_add(1);
                self.consecutive_failures = 0;
                if self.state == TraceyGuardGpuState::DeepTest {
                    self.deep_test_passes = self.deep_test_passes.saturating_add(1);
                    if self.deep_test_passes >= correlation.deep_test_passes
                        && self.reliability() >= correlation.quarantine_to_healthy
                    {
                        self.transition_to(
                            TraceyGuardGpuState::Healthy,
                            "deep-test pass threshold met",
                        );
                    }
                } else if self.state == TraceyGuardGpuState::Suspect
                    && self.reliability() >= correlation.healthy_to_suspect
                {
                    self.transition_to(TraceyGuardGpuState::Healthy, "confidence recovered");
                }
            }
            ProbeState::Fail => {
                self.beta += (1.6 + remote_weight + high_risk_bonus) * low_confidence_penalty;
                self.probe_fail_count = self.probe_fail_count.saturating_add(1);
                if confidence >= correlation.min_confidence || remote_support > 0 || risk >= 0.85 {
                    self.consecutive_failures = self.consecutive_failures.saturating_add(1);
                }
                self.deep_test_passes = 0;
            }
            ProbeState::Error | ProbeState::Timeout => {
                self.beta += (0.9 + remote_weight + high_risk_bonus) * low_confidence_penalty;
                self.probe_error_count = self.probe_error_count.saturating_add(1);
                if confidence >= correlation.min_confidence || remote_support > 0 || risk >= 0.90 {
                    self.consecutive_failures = self.consecutive_failures.saturating_add(1);
                }
                self.deep_test_passes = 0;
            }
        }

        let reliability = self.reliability();
        match self.state {
            TraceyGuardGpuState::Healthy
                if reliability < correlation.healthy_to_suspect
                    || self.consecutive_failures >= 1 =>
            {
                self.transition_to(TraceyGuardGpuState::Suspect, reason);
            }
            TraceyGuardGpuState::Suspect
                if reliability < correlation.suspect_to_quarantine
                    || self.consecutive_failures >= correlation.immediate_quarantine_failures =>
            {
                self.transition_to(TraceyGuardGpuState::Quarantined, reason);
            }
            TraceyGuardGpuState::Quarantined
                if reliability >= correlation.quarantine_to_healthy
                    && self.consecutive_failures == 0 =>
            {
                self.transition_to(TraceyGuardGpuState::DeepTest, "candidate reinstatement");
            }
            TraceyGuardGpuState::DeepTest
                if reliability < correlation.suspect_to_quarantine
                    || self.consecutive_failures >= correlation.immediate_quarantine_failures =>
            {
                self.transition_to(TraceyGuardGpuState::Quarantined, reason);
            }
            _ => {}
        }
    }

    fn transition_to(&mut self, target: TraceyGuardGpuState, reason: &str) {
        if self.state == target {
            return;
        }
        self.state = target;
        self.last_transition_ms = now_ms();
        self.last_reason = reason.to_string();
        if target != TraceyGuardGpuState::DeepTest {
            self.deep_test_passes = 0;
        }
    }
}

#[derive(Clone, Debug)]
struct ScheduledProbe {
    probe_type: ProbeType,
    gpu_id: String,
    sm_id: u32,
    timeout_ms: u64,
}

#[derive(Clone, Debug)]
struct ProbeScheduleState {
    // Lower number means higher scheduling priority.
    probe_type: ProbeType,
    period_ms: u64,
    sm_coverage: f64,
    priority: u8,
    timeout_ms: u64,
    enabled: bool,
    next_fire_ms: u64,
    cursor: u32,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProbeCounters {
    /// Total executions accepted by the runtime (includes pass/fail/error/timeout).
    pub executions: u64,
    pub pass: u64,
    pub fail: u64,
    pub error: u64,
    pub timeout: u64,
    pub avg_execution_ms: f64,
    pub last_risk: f64,
    pub last_confidence: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProbeExecution {
    /// Runtime timestamp for completion of this probe execution.
    pub ts_ms: u64,
    /// Stable identifier allowing correlation across logs, telemetry, and status endpoints.
    pub execution_id: String,
    pub probe_type: ProbeType,
    pub probe_state: ProbeState,
    pub gpu_id: String,
    pub sm_id: u32,
    pub expected_hash: String,
    pub actual_hash: String,
    pub mismatch_count: usize,
    pub execution_time_ns: u64,
    pub risk: f64,
    pub confidence: f64,
    pub signal: f64,
    pub severity: Severity,
    pub context: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GpuHealthView {
    pub gpu_id: String,
    pub state: TraceyGuardGpuState,
    pub reliability_score: f64,
    pub probe_pass_count: u64,
    pub probe_fail_count: u64,
    pub probe_error_count: u64,
    pub consecutive_failures: u32,
    pub last_transition_ms: u64,
    pub last_reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimelineBucket {
    /// Bucket start epoch in milliseconds (1-minute cadence).
    pub bucket_start_ms: u64,
    pub probe_pass: u64,
    pub probe_fail: u64,
    pub probe_error: u64,
    pub probe_timeout: u64,
    pub quarantined_devices: usize,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TraceyGuardControlState {
    /// Runtime mutable controls, primarily updated through `/control/tracey_guard`.
    pub enabled: bool,
    pub deep_dive: bool,
    pub overhead_budget_pct: f64,
    pub tmr_enabled: bool,
    pub max_parallel_tasks: usize,
    pub force_scan_epoch: u64,
    pub updated_ms: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TraceyGuardControlRequest {
    /// Optional partial update; absent fields preserve current runtime state.
    pub enabled: Option<bool>,
    pub deep_dive: Option<bool>,
    pub overhead_budget_pct: Option<f64>,
    pub tmr_enabled: Option<bool>,
    pub max_parallel_tasks: Option<usize>,
    pub force_scan: Option<bool>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TraceyGuardSummary {
    /// High-level health and throughput summary used by status and dashboard surfaces.
    pub ts_ms: u64,
    pub enabled: bool,
    pub deep_dive: bool,
    pub overhead_budget_pct: f64,
    pub scheduler_poll_ms: u64,
    pub total_devices: usize,
    pub healthy_devices: usize,
    pub suspect_devices: usize,
    pub quarantined_devices: usize,
    pub deep_test_devices: usize,
    pub condemned_devices: usize,
    pub total_executions: u64,
    pub total_failures: u64,
    pub total_errors: u64,
    pub total_timeouts: u64,
    pub remote_fault_support: usize,
    pub probes: BTreeMap<String, ProbeCounters>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TraceyGuardStatusSnapshot {
    /// Full runtime snapshot consumed by `/status`, `/tracey_guard`, and deep-dive paths.
    pub summary: TraceyGuardSummary,
    pub gpu_health: Vec<GpuHealthView>,
    pub recent_faults: Vec<FaultAdvertisementEntry>,
    pub remote_faults: Vec<FaultAdvertisementEntry>,
    pub timeline: Vec<TimelineBucket>,
    pub control: TraceyGuardControlState,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FaultAdvertisementEntry {
    /// Normalized signature used to correlate faults across local and remote agents.
    pub key: String,
    pub gpu_id: String,
    pub probe_type: String,
    pub state: String,
    pub severity: String,
    pub risk: f64,
    pub confidence: f64,
    pub count: u64,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct FaultAdvertisement {
    /// Monotonic publication epoch for gossip consumers.
    pub ts_ms: u64,
    pub epoch: u64,
    pub entries: Vec<FaultAdvertisementEntry>,
}

#[derive(Default)]
struct FaultIntelState {
    epoch: u64,
    local: HashMap<String, FaultAdvertisementEntry>,
    remote: HashMap<String, RemoteFaultRecord>,
    remote_ttl_ms: u64,
}

#[derive(Clone, Debug)]
struct RemoteFaultRecord {
    ts_ms: u64,
    entries: Vec<FaultAdvertisementEntry>,
}

#[derive(Clone)]
pub struct FaultIntelHub {
    state: Arc<RwLock<FaultIntelState>>,
}

impl FaultIntelHub {
    /// Shared hub for local fault signatures and remote peer advertisements.
    ///
    /// The same hub instance is used by:
    /// - TraceyGuard runtime (local fault publication)
    /// - discovery gossip (advertise + ingest)
    /// - status/deep-dive endpoints (operator visibility)
    pub fn new(remote_ttl_ms: u64) -> Self {
        Self {
            state: Arc::new(RwLock::new(FaultIntelState {
                epoch: 0,
                local: HashMap::new(),
                remote: HashMap::new(),
                remote_ttl_ms,
            })),
        }
    }

    pub async fn update_local_fault(&self, entry: FaultAdvertisementEntry) {
        let mut state = self.state.write().await;
        cleanup_fault_state(&mut state, now_ms());
        state.epoch = state.epoch.saturating_add(1);
        if let Some(existing) = state.local.get_mut(&entry.key) {
            existing.count = existing.count.saturating_add(entry.count.max(1));
            existing.last_seen_ms = existing.last_seen_ms.max(entry.last_seen_ms);
            existing.first_seen_ms = existing.first_seen_ms.min(entry.first_seen_ms);
            // EWMA-style smoothing keeps scores stable while still reflecting new evidence.
            existing.risk = (existing.risk * 0.70 + entry.risk * 0.30).clamp(0.0, 1.0);
            existing.confidence =
                (existing.confidence * 0.70 + entry.confidence * 0.30).clamp(0.0, 1.0);
            existing.state = entry.state;
            existing.severity = entry.severity;
            existing.gpu_id = entry.gpu_id;
            existing.probe_type = entry.probe_type;
        } else {
            state.local.insert(entry.key.clone(), entry);
        }
    }

    pub async fn build_advertisement(&self, max_entries: usize) -> FaultAdvertisement {
        let mut state = self.state.write().await;
        cleanup_fault_state(&mut state, now_ms());

        let mut entries: Vec<FaultAdvertisementEntry> = state.local.values().cloned().collect();
        entries.sort_by(|a, b| b.last_seen_ms.cmp(&a.last_seen_ms));
        if entries.len() > max_entries {
            entries.truncate(max_entries);
        }

        FaultAdvertisement {
            ts_ms: now_ms(),
            epoch: state.epoch,
            entries,
        }
    }

    pub async fn ingest_remote(&self, agent_id: &str, advertisement: FaultAdvertisement) {
        let mut state = self.state.write().await;
        cleanup_fault_state(&mut state, now_ms());

        let mut entries = Vec::with_capacity(advertisement.entries.len());
        for mut entry in advertisement.entries {
            if entry.key.trim().is_empty() || entry.key.len() > 256 {
                continue;
            }
            entry.key = entry.key.trim().to_string();
            entry.gpu_id = entry.gpu_id.trim().to_string();
            entry.probe_type = entry.probe_type.trim().to_ascii_lowercase();
            entry.state = entry.state.trim().to_ascii_lowercase();
            entry.severity = entry.severity.trim().to_ascii_lowercase();
            entry.risk = entry.risk.clamp(0.0, 1.0);
            entry.confidence = entry.confidence.clamp(0.0, 1.0);
            entries.push(entry);
        }

        state.remote.insert(
            agent_id.to_string(),
            RemoteFaultRecord {
                ts_ms: advertisement.ts_ms,
                entries,
            },
        );
    }

    pub async fn remote_support_for_key(&self, key: &str) -> usize {
        let mut state = self.state.write().await;
        cleanup_fault_state(&mut state, now_ms());
        state
            .remote
            .values()
            .filter(|record| record.entries.iter().any(|entry| entry.key == key))
            .count()
    }

    pub async fn snapshot(&self, max_entries: usize) -> FaultIntelSnapshot {
        let mut state = self.state.write().await;
        cleanup_fault_state(&mut state, now_ms());

        let mut local_entries: Vec<FaultAdvertisementEntry> =
            state.local.values().cloned().collect();
        local_entries.sort_by(|a, b| b.last_seen_ms.cmp(&a.last_seen_ms));

        let mut remote_entries: Vec<FaultAdvertisementEntry> = state
            .remote
            .values()
            .flat_map(|record| record.entries.iter().cloned())
            .collect();
        remote_entries.sort_by(|a, b| b.last_seen_ms.cmp(&a.last_seen_ms));

        FaultIntelSnapshot {
            ts_ms: now_ms(),
            local_fault_count: local_entries.len(),
            remote_fault_count: remote_entries.len(),
            remote_agents: state.remote.len(),
            local_entries: local_entries.into_iter().take(max_entries).collect(),
            remote_entries: remote_entries.into_iter().take(max_entries).collect(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FaultIntelSnapshot {
    pub ts_ms: u64,
    pub local_fault_count: usize,
    pub remote_fault_count: usize,
    pub remote_agents: usize,
    pub local_entries: Vec<FaultAdvertisementEntry>,
    pub remote_entries: Vec<FaultAdvertisementEntry>,
}

fn cleanup_fault_state(state: &mut FaultIntelState, now: u64) {
    let remote_ttl_ms = state.remote_ttl_ms;
    state
        .remote
        .retain(|_, record| now.saturating_sub(record.ts_ms) <= remote_ttl_ms);
}

#[derive(Clone)]
pub struct TraceyGuardRuntimeHandle {
    control: Arc<RwLock<TraceyGuardControlState>>,
    snapshot: Arc<RwLock<TraceyGuardStatusSnapshot>>,
    fault_hub: FaultIntelHub,
}

impl TraceyGuardRuntimeHandle {
    pub fn disabled(remote_fault_ttl_ms: u64) -> Self {
        Self {
            control: Arc::new(RwLock::new(TraceyGuardControlState {
                enabled: false,
                deep_dive: false,
                overhead_budget_pct: 0.0,
                tmr_enabled: false,
                max_parallel_tasks: 0,
                force_scan_epoch: 0,
                updated_ms: now_ms(),
            })),
            snapshot: Arc::new(RwLock::new(TraceyGuardStatusSnapshot::default())),
            fault_hub: FaultIntelHub::new(remote_fault_ttl_ms),
        }
    }

    pub fn fault_hub(&self) -> FaultIntelHub {
        self.fault_hub.clone()
    }

    pub async fn snapshot(&self) -> TraceyGuardStatusSnapshot {
        self.snapshot.read().await.clone()
    }

    /// Apply runtime control updates from API handlers without blocking probe execution loops.
    pub async fn apply_control(
        &self,
        request: TraceyGuardControlRequest,
    ) -> TraceyGuardControlState {
        let mut control = self.control.write().await;
        if let Some(enabled) = request.enabled {
            control.enabled = enabled;
        }
        if let Some(deep_dive) = request.deep_dive {
            control.deep_dive = deep_dive;
        }
        if let Some(value) = request.overhead_budget_pct {
            control.overhead_budget_pct = value.clamp(0.1, 50.0);
        }
        if let Some(enabled) = request.tmr_enabled {
            control.tmr_enabled = enabled;
        }
        if let Some(value) = request.max_parallel_tasks {
            control.max_parallel_tasks = value.clamp(1, 1024);
        }
        if request.force_scan.unwrap_or(false) {
            control.force_scan_epoch = control.force_scan_epoch.saturating_add(1);
        }
        control.updated_ms = now_ms();
        control.clone()
    }
}

/// Spawn the TraceyGuard runtime translated into Tracey's async orchestration model.
pub fn spawn_tracey_guard(
    config: TraceyGuardConfig,
    gpu_backends: GpuBackendConfig,
    bus: EventBus,
    storage: Storage,
    shutdown: ShutdownListener,
) -> TraceyGuardRuntimeHandle {
    let control = Arc::new(RwLock::new(TraceyGuardControlState {
        enabled: config.enabled,
        deep_dive: false,
        overhead_budget_pct: config.overhead_budget_pct,
        tmr_enabled: config.tmr.enabled,
        max_parallel_tasks: config.max_parallel_tasks,
        force_scan_epoch: 0,
        updated_ms: now_ms(),
    }));
    let snapshot = Arc::new(RwLock::new(TraceyGuardStatusSnapshot::default()));
    let fault_hub = FaultIntelHub::new(config.remote_fault_ttl_ms);

    let handle = TraceyGuardRuntimeHandle {
        control: control.clone(),
        snapshot: snapshot.clone(),
        fault_hub: fault_hub.clone(),
    };

    tokio::spawn(async move {
        run_tracey_guard_runtime(
            config,
            gpu_backends,
            bus,
            storage,
            shutdown,
            control,
            snapshot,
            fault_hub,
        )
        .await;
    });

    handle
}

async fn run_tracey_guard_runtime(
    config: TraceyGuardConfig,
    gpu_backends: GpuBackendConfig,
    bus: EventBus,
    storage: Storage,
    mut shutdown: ShutdownListener,
    control: Arc<RwLock<TraceyGuardControlState>>,
    snapshot: Arc<RwLock<TraceyGuardStatusSnapshot>>,
    fault_hub: FaultIntelHub,
) {
    // Device discovery intentionally supports synthetic fallback so TraceyGuard can
    // still exercise scheduling/fuzzy/correlation logic on CPU-only hosts.
    let devices = discover_devices(&config, &gpu_backends).await;
    if devices.is_empty() {
        tracing::warn!("tracey_guard runtime found no devices; disabled");
        let mut snap = snapshot.write().await;
        snap.summary.enabled = false;
        snap.summary.ts_ms = now_ms();
        return;
    }

    let mut device_state: HashMap<String, DeviceState> = devices
        .iter()
        .map(|device| {
            (
                device.gpu_id.clone(),
                DeviceState::new(device.gpu_id.clone(), device.sm_count, &config),
            )
        })
        .collect();

    let mut telemetry_ctx: HashMap<String, DeviceTelemetryContext> = devices
        .iter()
        .map(|device| (device.gpu_id.clone(), DeviceTelemetryContext::default()))
        .collect();

    let mut schedules = build_schedules(&config);
    let mut scheduler_tick = tokio::time::interval(Duration::from_millis(config.scheduler_poll_ms));
    let mut tmr_tick = tokio::time::interval(Duration::from_millis(config.tmr.interval_ms));

    let (probe_tx, mut probe_rx) = tokio::sync::mpsc::channel::<ProbeExecution>(4096);
    let semaphore = Arc::new(Semaphore::new(config.max_parallel_tasks.max(1)));

    let mut bus_rx = bus.subscribe();
    let mut last_force_scan_epoch = 0u64;
    let mut budget_window: VecDeque<(u64, u64)> = VecDeque::new();

    let mut per_probe_counters: HashMap<ProbeType, ProbeCounters> = ProbeType::all()
        .into_iter()
        .map(|probe| (probe, ProbeCounters::default()))
        .collect();
    let mut timeline: VecDeque<TimelineBucket> = VecDeque::new();

    let mut trust_graph: HashMap<(String, String), (u64, u64)> = HashMap::new();
    let fault_snapshot_limit = config.deep_dive_max_faults.max(LOCAL_SNAPSHOT_MAX_FAULTS);

    // Single async event loop:
    // - scheduler tick dispatches probe kernels
    // - probe channel ingests completed results
    // - event bus intake refreshes telemetry context
    // - TMR tick runs cross-device consensus checks
    loop {
        tokio::select! {
            _ = shutdown.wait() => {
                tracing::info!("tracey_guard runtime shutting down");
                break;
            }
            _ = scheduler_tick.tick() => {
                let control_state = control.read().await.clone();
                if !control_state.enabled {
                    refresh_snapshot(
                        &snapshot,
                        &control_state,
                        &per_probe_counters,
                        &device_state,
                        &fault_hub,
                        &timeline,
                        config.scheduler_poll_ms,
                        fault_snapshot_limit,
                    ).await;
                    continue;
                }
                let now = now_ms();
                let used_ratio = update_budget_and_ratio(&mut budget_window, now, 60_000);
                let budget_ceiling = (control_state.overhead_budget_pct / 100.0).clamp(0.001, 0.99);
                let force_scan = control_state.force_scan_epoch != last_force_scan_epoch;
                if force_scan {
                    last_force_scan_epoch = control_state.force_scan_epoch;
                }

                if used_ratio < budget_ceiling || force_scan {
                    let scheduled = schedule_due_tasks(
                        &mut schedules,
                        &devices,
                        &telemetry_ctx,
                        now,
                        force_scan,
                    );
                    for task in scheduled {
                        let Ok(permit) = semaphore.clone().try_acquire_owned() else {
                            break;
                        };
                        let tx = probe_tx.clone();
                        let ctx = telemetry_ctx
                            .get(&task.gpu_id)
                            .cloned()
                            .unwrap_or_default();
                        let deep_dive = control_state.deep_dive;
                        tokio::spawn(async move {
                            let _permit = permit;
                            let start = Instant::now();
                            let execution_id = format!(
                                "tracey_guard-{}-{}-{}-{}",
                                task.probe_type.as_str(),
                                task.gpu_id,
                                task.sm_id,
                                now_ms(),
                            );
                            let execution_id_for_probe = execution_id.clone();
                            let task_for_probe = task.clone();
                            let probe_future = tokio::task::spawn_blocking(move || {
                                execute_probe_kernel(
                                    &execution_id_for_probe,
                                    task_for_probe.probe_type,
                                    &task_for_probe.gpu_id,
                                    task_for_probe.sm_id,
                                    &ctx,
                                    deep_dive,
                                )
                            });

                            let mut result = match tokio::time::timeout(
                                Duration::from_millis(task.timeout_ms.max(100)),
                                probe_future,
                            )
                            .await
                            {
                                Ok(Ok(result)) => result,
                                Ok(Err(_join)) => {
                                    probe_terminal_result(&execution_id, &task, ProbeState::Error)
                                }
                                Err(_timeout) => {
                                    probe_terminal_result(&execution_id, &task, ProbeState::Timeout)
                                }
                            };
                            result.execution_time_ns = start.elapsed().as_nanos() as u64;
                            let _ = tx.send(result).await;
                        });
                    }
                }

                refresh_snapshot(
                    &snapshot,
                    &control_state,
                    &per_probe_counters,
                    &device_state,
                    &fault_hub,
                    &timeline,
                    config.scheduler_poll_ms,
                    fault_snapshot_limit,
                ).await;
            }
            Some(mut execution) = probe_rx.recv() => {
                let Some(device) = device_state.get_mut(&execution.gpu_id) else {
                    continue;
                };
                let remote_support = if execution.probe_state == ProbeState::Pass {
                    0
                } else {
                    let fault_key = build_fault_key(&execution);
                    fault_hub.remote_support_for_key(&fault_key).await
                };

                let signal = derive_signal(&execution, remote_support);
                let severity = execution.probe_state.severity();
                let mut event = Event::new(
                    TRACEY_GUARD_EVENT_COUNTER.fetch_add(1, Ordering::Relaxed),
                    "tracey_guard",
                    EventKind::Observability,
                    signal,
                    severity,
                )
                .with_attr("metric", "tracey_guard_probe")
                .with_attr("probe_type", execution.probe_type.as_str())
                .with_attr("probe_state", execution.probe_state.as_str())
                .with_attr("gpu_id", execution.gpu_id.clone())
                .with_attr("sm_id", execution.sm_id.to_string())
                .with_attr("execution_id", execution.execution_id.clone())
                .with_attr("mismatch_count", execution.mismatch_count.to_string())
                .with_attr("execution_time_ns", execution.execution_time_ns.to_string());

                if !execution.expected_hash.is_empty() {
                    event = event.with_attr("expected_hash", execution.expected_hash.clone());
                }
                if !execution.actual_hash.is_empty() {
                    event = event.with_attr("actual_hash", execution.actual_hash.clone());
                }

                let scored = device.scorer.score_and_update(&event);
                execution.signal = signal;
                execution.risk = scored.risk;
                execution.confidence = scored.confidence;
                execution.severity = severity;

                event = event
                    .with_attr("fuzzy_risk", format!("{:.5}", execution.risk))
                    .with_attr("fuzzy_confidence", format!("{:.5}", execution.confidence))
                    .with_attr("remote_support", remote_support.to_string());

                bus.publish(event.clone());
                storage.record_event(event).await;

                device.register_probe_outcome(
                    execution.probe_state,
                    "probe outcome",
                    &config.correlation,
                    execution.risk,
                    execution.confidence,
                    remote_support,
                );

                let counters = per_probe_counters
                    .entry(execution.probe_type)
                    .or_default();
                counters.executions = counters.executions.saturating_add(1);
                counters.last_risk = execution.risk;
                counters.last_confidence = execution.confidence;
                let exec_ms = execution.execution_time_ns as f64 / 1_000_000.0;
                if counters.executions == 1 {
                    counters.avg_execution_ms = exec_ms;
                } else {
                    counters.avg_execution_ms =
                        (counters.avg_execution_ms * 0.95) + (exec_ms * 0.05);
                }
                match execution.probe_state {
                    ProbeState::Pass => counters.pass = counters.pass.saturating_add(1),
                    ProbeState::Fail => counters.fail = counters.fail.saturating_add(1),
                    ProbeState::Error => counters.error = counters.error.saturating_add(1),
                    ProbeState::Timeout => counters.timeout = counters.timeout.saturating_add(1),
                }

                let bucket_start = now_ms() / 60_000 * 60_000;
                if timeline
                    .back()
                    .map(|bucket| bucket.bucket_start_ms != bucket_start)
                    .unwrap_or(true)
                {
                    timeline.push_back(TimelineBucket {
                        bucket_start_ms: bucket_start,
                        probe_pass: 0,
                        probe_fail: 0,
                        probe_error: 0,
                        probe_timeout: 0,
                        quarantined_devices: 0,
                    });
                }
                if let Some(bucket) = timeline.back_mut() {
                    match execution.probe_state {
                        ProbeState::Pass => bucket.probe_pass = bucket.probe_pass.saturating_add(1),
                        ProbeState::Fail => bucket.probe_fail = bucket.probe_fail.saturating_add(1),
                        ProbeState::Error => bucket.probe_error = bucket.probe_error.saturating_add(1),
                        ProbeState::Timeout => bucket.probe_timeout = bucket.probe_timeout.saturating_add(1),
                    }
                    bucket.quarantined_devices = device_state
                        .values()
                        .filter(|state| state.state == TraceyGuardGpuState::Quarantined)
                        .count();
                }
                while timeline.len() > LOCAL_SNAPSHOT_MAX_BUCKETS {
                    timeline.pop_front();
                }

                if execution.probe_state != ProbeState::Pass {
                    let entry = FaultAdvertisementEntry {
                        key: build_fault_key(&execution),
                        gpu_id: execution.gpu_id.clone(),
                        probe_type: execution.probe_type.as_str().to_string(),
                        state: execution.probe_state.as_str().to_string(),
                        severity: format!("{:?}", execution.severity).to_ascii_lowercase(),
                        risk: execution.risk,
                        confidence: execution.confidence,
                        count: 1,
                        first_seen_ms: execution.ts_ms,
                        last_seen_ms: execution.ts_ms,
                    };
                    fault_hub.update_local_fault(entry.clone()).await;

                    let fault_event = Event::new(
                        TRACEY_GUARD_EVENT_COUNTER.fetch_add(1, Ordering::Relaxed),
                        "tracey_guard",
                        EventKind::Observability,
                        execution.risk,
                        execution.severity,
                    )
                    .with_attr("metric", "tracey_guard_fault")
                    .with_attr("fault_key", entry.key)
                    .with_attr("probe_type", entry.probe_type)
                    .with_attr("fault_state", entry.state)
                    .with_attr("gpu_id", entry.gpu_id)
                    .with_attr("risk", format!("{:.5}", execution.risk))
                    .with_attr("confidence", format!("{:.5}", execution.confidence));
                    bus.publish(fault_event.clone());
                    storage.record_event(fault_event).await;
                }

                budget_window.push_back((now_ms(), execution.execution_time_ns));
            }
            Ok(event) = bus_rx.recv() => {
                ingest_telemetry_context(&event, &mut telemetry_ctx);
            }
            _ = tmr_tick.tick() => {
                let control_state = control.read().await.clone();
                if !control_state.enabled || !control_state.tmr_enabled || !config.tmr.enabled {
                    continue;
                }
                run_tmr_cycle(
                    &device_state,
                    &mut trust_graph,
                    &fault_hub,
                    &bus,
                    &storage,
                    config.tmr.triples_per_interval,
                ).await;
            }
        }
    }
}

async fn refresh_snapshot(
    snapshot: &Arc<RwLock<TraceyGuardStatusSnapshot>>,
    control: &TraceyGuardControlState,
    per_probe_counters: &HashMap<ProbeType, ProbeCounters>,
    device_state: &HashMap<String, DeviceState>,
    fault_hub: &FaultIntelHub,
    timeline: &VecDeque<TimelineBucket>,
    scheduler_poll_ms: u64,
    fault_snapshot_limit: usize,
) {
    // Snapshot assembly is read-mostly and bounded to keep status endpoints fast.
    let fault_snapshot = fault_hub.snapshot(fault_snapshot_limit.max(1)).await;
    let mut probes = BTreeMap::new();
    for probe in ProbeType::all() {
        if let Some(counter) = per_probe_counters.get(&probe) {
            probes.insert(probe.as_str().to_string(), counter.clone());
        }
    }

    let mut gpu_health = Vec::with_capacity(device_state.len());
    let mut healthy_devices = 0usize;
    let mut suspect_devices = 0usize;
    let mut quarantined_devices = 0usize;
    let mut deep_test_devices = 0usize;
    let mut condemned_devices = 0usize;

    for state in device_state.values().take(LOCAL_SNAPSHOT_MAX_GPUS) {
        match state.state {
            TraceyGuardGpuState::Healthy => healthy_devices += 1,
            TraceyGuardGpuState::Suspect => suspect_devices += 1,
            TraceyGuardGpuState::Quarantined => quarantined_devices += 1,
            TraceyGuardGpuState::DeepTest => deep_test_devices += 1,
            TraceyGuardGpuState::Condemned => condemned_devices += 1,
        }
        gpu_health.push(GpuHealthView {
            gpu_id: state.gpu_id.clone(),
            state: state.state,
            reliability_score: state.reliability(),
            probe_pass_count: state.probe_pass_count,
            probe_fail_count: state.probe_fail_count,
            probe_error_count: state.probe_error_count,
            consecutive_failures: state.consecutive_failures,
            last_transition_ms: state.last_transition_ms,
            last_reason: state.last_reason.clone(),
        });
    }

    gpu_health.sort_by(|a, b| a.gpu_id.cmp(&b.gpu_id));

    let total_executions = per_probe_counters
        .values()
        .map(|counter| counter.executions)
        .sum();
    let total_failures = per_probe_counters
        .values()
        .map(|counter| counter.fail)
        .sum();
    let total_errors = per_probe_counters
        .values()
        .map(|counter| counter.error)
        .sum();
    let total_timeouts = per_probe_counters
        .values()
        .map(|counter| counter.timeout)
        .sum();

    let summary = TraceyGuardSummary {
        ts_ms: now_ms(),
        enabled: control.enabled,
        deep_dive: control.deep_dive,
        overhead_budget_pct: control.overhead_budget_pct,
        scheduler_poll_ms,
        total_devices: device_state.len(),
        healthy_devices,
        suspect_devices,
        quarantined_devices,
        deep_test_devices,
        condemned_devices,
        total_executions,
        total_failures,
        total_errors,
        total_timeouts,
        remote_fault_support: fault_snapshot.remote_fault_count,
        probes,
    };

    let mut write = snapshot.write().await;
    write.summary = summary;
    write.control = control.clone();
    write.gpu_health = gpu_health;
    write.recent_faults = fault_snapshot.local_entries;
    write.remote_faults = fault_snapshot.remote_entries;
    write.timeline = timeline.iter().cloned().collect();
}

async fn discover_devices(
    config: &TraceyGuardConfig,
    gpu_backends: &GpuBackendConfig,
) -> Vec<DiscoveredDevice> {
    let mut out: Vec<DiscoveredDevice> = crate::gpu::discover_devices(gpu_backends)
        .await
        .into_iter()
        .take(config.max_devices)
        .map(|device| DiscoveredDevice {
            gpu_id: device.id,
            sm_count: config.default_sm_count as u32,
        })
        .collect();

    if out.is_empty() {
        for idx in 0..config.synthetic_devices {
            out.push(DiscoveredDevice {
                gpu_id: format!("synthetic-gpu-{}", idx),
                sm_count: config.default_sm_count as u32,
            });
        }
    }

    out.truncate(config.max_devices);
    out
}

#[derive(Clone, Debug)]
struct DiscoveredDevice {
    gpu_id: String,
    sm_count: u32,
}

fn build_schedules(config: &TraceyGuardConfig) -> Vec<ProbeScheduleState> {
    let now = now_ms();
    ProbeType::all()
        .into_iter()
        .map(|probe| {
            let cfg = config.probe_cfg(probe);
            ProbeScheduleState {
                probe_type: probe,
                period_ms: cfg.period_ms,
                sm_coverage: cfg.sm_coverage,
                priority: cfg.priority,
                timeout_ms: cfg.timeout_ms,
                enabled: cfg.enabled,
                next_fire_ms: now,
                cursor: 0,
            }
        })
        .collect()
}

fn schedule_due_tasks(
    schedules: &mut [ProbeScheduleState],
    devices: &[DiscoveredDevice],
    telemetry_ctx: &HashMap<String, DeviceTelemetryContext>,
    now: u64,
    force_scan: bool,
) -> Vec<ScheduledProbe> {
    let mut out = Vec::new();
    schedules.sort_by_key(|schedule| (schedule.priority, schedule.period_ms));
    for schedule in schedules.iter_mut() {
        if !schedule.enabled {
            continue;
        }
        if !force_scan && now < schedule.next_fire_ms {
            continue;
        }

        let avg_utilization = average_utilization(devices, telemetry_ctx);
        let period_multiplier = utilization_multiplier(avg_utilization);
        for device in devices {
            let util = telemetry_ctx
                .get(&device.gpu_id)
                .map(|ctx| ctx.util_pct)
                .unwrap_or(avg_utilization);
            let effective_coverage = if force_scan {
                schedule.sm_coverage
            } else {
                sm_coverage_for_utilization(schedule.sm_coverage, util)
            };
            let sms = sample_sms(device.sm_count, effective_coverage, schedule.cursor);
            schedule.cursor = schedule.cursor.wrapping_add(1);
            for sm in sms {
                out.push(ScheduledProbe {
                    probe_type: schedule.probe_type,
                    gpu_id: device.gpu_id.clone(),
                    sm_id: sm,
                    timeout_ms: schedule.timeout_ms,
                });
            }
        }
        let effective_period = ((schedule.period_ms as f64) * period_multiplier) as u64;
        schedule.next_fire_ms = now.saturating_add(effective_period.max(100));
    }
    out
}

/// Mirrors TraceyGuard probe-agent scheduler behavior:
/// - Busy devices are probed less aggressively.
/// - Idle devices can be sampled more frequently for faster early detection.
fn utilization_multiplier(utilization: f64) -> f64 {
    if utilization >= 90.0 {
        4.0
    } else if utilization >= 75.0 {
        2.0
    } else if utilization <= 10.0 {
        0.5
    } else {
        1.0
    }
}

fn sm_coverage_for_utilization(base_coverage: f64, utilization: f64) -> f64 {
    let coverage = if utilization >= 90.0 {
        base_coverage * 0.40
    } else if utilization >= 75.0 {
        base_coverage * 0.60
    } else if utilization <= 10.0 {
        (base_coverage * 1.25).min(1.0)
    } else {
        base_coverage
    };
    coverage.clamp(0.05, 1.0)
}

fn average_utilization(
    devices: &[DiscoveredDevice],
    telemetry_ctx: &HashMap<String, DeviceTelemetryContext>,
) -> f64 {
    if devices.is_empty() {
        return 0.0;
    }
    let mut sum = 0.0;
    for device in devices {
        sum += telemetry_ctx
            .get(&device.gpu_id)
            .map(|ctx| ctx.util_pct)
            .unwrap_or(0.0);
    }
    sum / devices.len() as f64
}

fn sample_sms(sm_count: u32, coverage: f64, cursor: u32) -> Vec<u32> {
    let count = ((sm_count as f64 * coverage).round() as u32).clamp(1, sm_count.max(1));
    let mut out = Vec::with_capacity(count as usize);
    let step = (sm_count / count).max(1);
    let mut current = cursor % sm_count.max(1);
    for _ in 0..count {
        out.push(current % sm_count.max(1));
        current = current.wrapping_add(step);
    }
    out.sort_unstable();
    out.dedup();
    out
}

fn update_budget_and_ratio(window: &mut VecDeque<(u64, u64)>, now: u64, duration_ms: u64) -> f64 {
    while let Some((ts, _)) = window.front().copied() {
        if now.saturating_sub(ts) > duration_ms {
            window.pop_front();
        } else {
            break;
        }
    }

    let used_ns: u64 = window.iter().map(|(_, ns)| *ns).sum();
    let capacity_ns = duration_ms.saturating_mul(1_000_000);
    if capacity_ns == 0 {
        0.0
    } else {
        (used_ns as f64 / capacity_ns as f64).clamp(0.0, 1.0)
    }
}

fn probe_terminal_result(
    execution_id: &str,
    task: &ScheduledProbe,
    probe_state: ProbeState,
) -> ProbeExecution {
    ProbeExecution {
        ts_ms: now_ms(),
        execution_id: execution_id.to_string(),
        probe_type: task.probe_type,
        probe_state,
        gpu_id: task.gpu_id.clone(),
        sm_id: task.sm_id,
        expected_hash: String::new(),
        actual_hash: String::new(),
        mismatch_count: 0,
        execution_time_ns: 0,
        risk: 0.0,
        confidence: 0.0,
        signal: 1.0,
        severity: Severity::Critical,
        context: BTreeMap::new(),
    }
}

fn derive_signal(execution: &ProbeExecution, remote_support: usize) -> f64 {
    let mismatch_ratio = (execution.mismatch_count as f64 / 32.0).clamp(0.0, 1.0);
    let stress = execution
        .context
        .get("stress")
        .and_then(|value| value.parse::<f64>().ok())
        .unwrap_or(0.0)
        .clamp(0.0, 1.0);
    let remote_factor = (remote_support as f64 / 5.0).clamp(0.0, 1.0);
    let state_bias = match execution.probe_state {
        ProbeState::Pass => 0.05,
        ProbeState::Fail => 0.85,
        ProbeState::Error => 0.65,
        ProbeState::Timeout => 0.95,
    };
    (state_bias * 0.55 + mismatch_ratio * 0.25 + stress * 0.15 + remote_factor * 0.05)
        .clamp(0.0, 1.0)
}

fn ingest_telemetry_context(
    event: &Event,
    telemetry_ctx: &mut HashMap<String, DeviceTelemetryContext>,
) {
    if event.source != "embedded" {
        return;
    }
    let metric = event.attributes.get("metric").map(|value| value.as_str());
    let gpu_id = event.attributes.get("gpu_id").cloned();
    let Some(metric) = metric else {
        return;
    };

    if !metric.starts_with("gpu_") && !metric.contains("ecc") {
        return;
    }

    let id = gpu_id.unwrap_or_else(|| "synthetic-gpu-0".to_string());
    let ctx = telemetry_ctx.entry(id).or_default();
    let value = event
        .attributes
        .get("value")
        .and_then(|value| value.parse::<f64>().ok())
        .unwrap_or_default();

    match metric {
        "gpu_temp_c" => {
            ctx.temp_c = value;
            if value >= 90.0 {
                ctx.thermal_spike_count = ctx.thermal_spike_count.saturating_add(1);
            }
        }
        "gpu_power_w" => {
            ctx.power_w = value;
            if value >= 320.0 {
                ctx.power_anomaly_count = ctx.power_anomaly_count.saturating_add(1);
            }
        }
        "gpu_util_percent" => {
            ctx.util_pct = value;
        }
        "gpu_mem_used_bytes" => {
            if let Some(ratio) = event
                .attributes
                .get("used_ratio")
                .and_then(|ratio| ratio.parse::<f64>().ok())
            {
                ctx.mem_used_ratio = ratio.clamp(0.0, 1.0);
            }
        }
        "gpu_clock_graphics_mhz" => {
            let ratio = event
                .attributes
                .get("normalized_ratio")
                .and_then(|ratio| ratio.parse::<f64>().ok())
                .unwrap_or_else(|| (value / 3000.0).clamp(0.0, 1.0));
            ctx.graphics_clock_ratio = ratio.clamp(0.0, 1.0);
            if ctx.graphics_clock_ratio >= 0.90 {
                ctx.clock_anomaly_count = ctx.clock_anomaly_count.saturating_add(1);
            }
        }
        "gpu_clock_memory_mhz" => {
            let ratio = event
                .attributes
                .get("normalized_ratio")
                .and_then(|ratio| ratio.parse::<f64>().ok())
                .unwrap_or_else(|| (value / 12000.0).clamp(0.0, 1.0));
            ctx.memory_clock_ratio = ratio.clamp(0.0, 1.0);
            if ctx.memory_clock_ratio >= 0.90 {
                ctx.clock_anomaly_count = ctx.clock_anomaly_count.saturating_add(1);
            }
        }
        "gpu_fan_speed_percent" => {
            ctx.fan_speed_ratio = (value / 100.0).clamp(0.0, 1.0);
            if ctx.fan_speed_ratio >= 0.85 && ctx.temp_c >= 80.0 {
                ctx.thermal_spike_count = ctx.thermal_spike_count.saturating_add(1);
            }
        }
        "gpu_encoder_util_percent" => {
            ctx.encoder_util_ratio = (value / 100.0).clamp(0.0, 1.0);
            if ctx.encoder_util_ratio >= 0.75 {
                ctx.codec_pressure_count = ctx.codec_pressure_count.saturating_add(1);
            }
        }
        "gpu_decoder_util_percent" => {
            ctx.decoder_util_ratio = (value / 100.0).clamp(0.0, 1.0);
            if ctx.decoder_util_ratio >= 0.75 {
                ctx.codec_pressure_count = ctx.codec_pressure_count.saturating_add(1);
            }
        }
        _ => {
            if metric.contains("ecc") {
                ctx.ecc_error_count = ctx.ecc_error_count.saturating_add(1);
            }
        }
    }
    ctx.last_update_ms = now_ms();
}

fn execute_probe_kernel(
    execution_id: &str,
    probe_type: ProbeType,
    gpu_id: &str,
    sm_id: u32,
    ctx: &DeviceTelemetryContext,
    deep_dive: bool,
) -> ProbeExecution {
    let ts_ms = now_ms();
    let (expected, mut actual) = deterministic_probe_payload(probe_type, sm_id);

    let stress = compute_stress(ctx);
    if should_inject_fault(probe_type, gpu_id, sm_id, stress, deep_dive, ts_ms) {
        if !actual.is_empty() {
            let idx = (sm_id as usize) % actual.len();
            actual[idx] ^= 0x3d;
            if idx + 1 < actual.len() {
                actual[idx + 1] ^= 0x21;
            }
        }
    }

    let mismatch_count = expected
        .iter()
        .zip(actual.iter())
        .filter(|(left, right)| left != right)
        .count();

    let expected_hash = blake3_hex(&expected);
    let actual_hash = blake3_hex(&actual);

    let probe_state = if mismatch_count == 0 {
        ProbeState::Pass
    } else {
        ProbeState::Fail
    };

    let mut context = BTreeMap::new();
    context.insert("stress".to_string(), format!("{:.4}", stress));
    context.insert("temp_c".to_string(), format!("{:.2}", ctx.temp_c));
    context.insert("util_pct".to_string(), format!("{:.2}", ctx.util_pct));
    context.insert("power_w".to_string(), format!("{:.2}", ctx.power_w));
    context.insert(
        "graphics_clock_ratio".to_string(),
        format!("{:.4}", ctx.graphics_clock_ratio),
    );
    context.insert(
        "memory_clock_ratio".to_string(),
        format!("{:.4}", ctx.memory_clock_ratio),
    );
    context.insert(
        "fan_speed_ratio".to_string(),
        format!("{:.4}", ctx.fan_speed_ratio),
    );
    context.insert(
        "encoder_util_ratio".to_string(),
        format!("{:.4}", ctx.encoder_util_ratio),
    );
    context.insert(
        "decoder_util_ratio".to_string(),
        format!("{:.4}", ctx.decoder_util_ratio),
    );

    ProbeExecution {
        ts_ms,
        execution_id: execution_id.to_string(),
        probe_type,
        probe_state,
        gpu_id: gpu_id.to_string(),
        sm_id,
        expected_hash,
        actual_hash,
        mismatch_count,
        execution_time_ns: 0,
        risk: 0.0,
        confidence: 0.0,
        signal: 0.0,
        severity: probe_state.severity(),
        context,
    }
}

fn deterministic_probe_payload(probe_type: ProbeType, sm_id: u32) -> (Vec<u8>, Vec<u8>) {
    match probe_type {
        ProbeType::Fma => {
            let mut expected = Vec::with_capacity(256);
            for idx in 0..32u32 {
                let a = 0.25f64 + idx as f64 * 0.03125;
                let b = 1.75f64 + sm_id as f64 * 0.001;
                let c = 0.05f64 * (idx as f64 - 8.0);
                expected.extend_from_slice(&a.mul_add(b, c).to_le_bytes());
            }
            (expected.clone(), expected)
        }
        ProbeType::TensorCore => {
            let mut expected = Vec::with_capacity(4 * 4 * 4);
            let mut matrix_a = [[0f32; 4]; 4];
            let mut matrix_b = [[0f32; 4]; 4];
            for row in 0..4 {
                for col in 0..4 {
                    matrix_a[row][col] = (row as f32 + 1.0) * (col as f32 + 0.25);
                    matrix_b[row][col] =
                        (col as f32 + 1.0) * (row as f32 + 0.5) + sm_id as f32 * 0.0001;
                }
            }
            for row in 0..4 {
                for col in 0..4 {
                    let mut acc = 0f32;
                    for k in 0..4 {
                        acc += matrix_a[row][k] * matrix_b[k][col];
                    }
                    expected.extend_from_slice(&acc.to_le_bytes());
                }
            }
            (expected.clone(), expected)
        }
        ProbeType::Transcendental => {
            let mut expected = Vec::with_capacity(24 * 8);
            for idx in 0..24 {
                let x = (idx as f64 + 1.0) * 0.125 + sm_id as f64 * 0.0005;
                let values = [x.sin(), x.cos(), x.exp().ln(), x.sqrt()];
                for value in values {
                    expected.extend_from_slice(&value.to_le_bytes());
                }
            }
            (expected.clone(), expected)
        }
        ProbeType::Aes => {
            let mut block = [0u8; 16];
            for (idx, byte) in block.iter_mut().enumerate() {
                *byte = (idx as u8).wrapping_mul(17).wrapping_add(sm_id as u8);
            }
            let key = [0x1fu8; 16];
            let mut expected = Vec::new();
            for round in 0..10 {
                for idx in 0..16 {
                    block[idx] ^= key[idx].wrapping_add((round * 13) as u8);
                    block[idx] = block[idx].rotate_left((idx % 7) as u32);
                }
            }
            expected.extend_from_slice(&block);
            (expected.clone(), expected)
        }
        ProbeType::Memory => {
            let mut expected = vec![0u8; 512];
            for idx in 0..expected.len() {
                expected[idx] = ((idx as u8).wrapping_mul(31)).rotate_left((idx % 8) as u32);
            }
            for idx in 0..expected.len() {
                expected[idx] ^= 1u8 << (idx % 8);
                expected[idx] ^= 1u8 << (idx % 8);
            }
            (expected.clone(), expected)
        }
        ProbeType::RegisterFile => {
            let mut expected = Vec::with_capacity(128 * 8);
            for idx in 0..128u64 {
                let value = idx
                    .wrapping_mul(0x9e3779b97f4a7c15)
                    .rotate_left((idx % 17) as u32);
                expected.extend_from_slice(&value.to_le_bytes());
            }
            (expected.clone(), expected)
        }
        ProbeType::SharedMemory => {
            let mut expected = Vec::with_capacity(1024);
            for addr in 0..256u32 {
                let lane = ((addr + sm_id) % 32) as u8;
                let value = lane ^ (addr as u8).rotate_left((addr % 5) as u32);
                expected.push(value);
                expected.push(value ^ 0xAA);
                expected.push(value ^ 0x55);
                expected.push(value.reverse_bits());
            }
            (expected.clone(), expected)
        }
    }
}

fn compute_stress(ctx: &DeviceTelemetryContext) -> f64 {
    let temp = (ctx.temp_c / 95.0).clamp(0.0, 1.0);
    let power = (ctx.power_w / 350.0).clamp(0.0, 1.0);
    let util = (ctx.util_pct / 100.0).clamp(0.0, 1.0);
    let memory = ctx.mem_used_ratio.clamp(0.0, 1.0);
    let graphics_clock = ctx.graphics_clock_ratio.clamp(0.0, 1.0);
    let memory_clock = ctx.memory_clock_ratio.clamp(0.0, 1.0);
    let fan = ctx.fan_speed_ratio.clamp(0.0, 1.0);
    let codec = ctx
        .encoder_util_ratio
        .max(ctx.decoder_util_ratio)
        .clamp(0.0, 1.0);
    let thermal_penalty = (ctx.thermal_spike_count as f64 / 20.0).clamp(0.0, 1.0);
    let power_penalty = (ctx.power_anomaly_count as f64 / 20.0).clamp(0.0, 1.0);
    let clock_penalty = (ctx.clock_anomaly_count as f64 / 20.0).clamp(0.0, 1.0);
    let codec_penalty = (ctx.codec_pressure_count as f64 / 20.0).clamp(0.0, 1.0);
    let ecc_penalty = (ctx.ecc_error_count as f64 / 5.0).clamp(0.0, 1.0);

    (temp * 0.22
        + power * 0.18
        + util * 0.16
        + memory * 0.10
        + graphics_clock * 0.08
        + memory_clock * 0.06
        + fan * 0.05
        + codec * 0.03
        + thermal_penalty * 0.05
        + power_penalty * 0.03
        + clock_penalty * 0.02
        + codec_penalty * 0.02
        + ecc_penalty * 0.05)
        .clamp(0.0, 1.0)
}

fn should_inject_fault(
    probe_type: ProbeType,
    gpu_id: &str,
    sm_id: u32,
    stress: f64,
    deep_dive: bool,
    ts_ms: u64,
) -> bool {
    let bucket = ts_ms / 10_000;
    let seed = format!(
        "{}:{}:{}:{}:{}",
        probe_type.as_str(),
        gpu_id,
        sm_id,
        bucket,
        if deep_dive { 1 } else { 0 }
    );
    let jitter = pseudo_ratio(&seed) * if deep_dive { 0.25 } else { 0.12 };
    let threshold = match probe_type {
        ProbeType::Memory | ProbeType::RegisterFile => 0.74,
        ProbeType::TensorCore | ProbeType::Fma => 0.78,
        ProbeType::Transcendental => 0.82,
        ProbeType::Aes | ProbeType::SharedMemory => 0.80,
    };
    stress + jitter >= threshold
}

async fn run_tmr_cycle(
    device_state: &HashMap<String, DeviceState>,
    trust_graph: &mut HashMap<(String, String), (u64, u64)>,
    fault_hub: &FaultIntelHub,
    bus: &EventBus,
    storage: &Storage,
    triples_per_interval: usize,
) {
    if device_state.len() < 3 {
        return;
    }

    let mut suspect: Vec<&DeviceState> = device_state
        .values()
        .filter(|state| state.state == TraceyGuardGpuState::Suspect)
        .collect();
    suspect.sort_by(|left, right| left.gpu_id.cmp(&right.gpu_id));

    let mut healthy: Vec<&DeviceState> = device_state
        .values()
        .filter(|state| state.state == TraceyGuardGpuState::Healthy)
        .collect();
    healthy.sort_by(|left, right| left.gpu_id.cmp(&right.gpu_id));

    let mut triples = Vec::new();
    for target in suspect {
        if healthy.len() < 2 {
            break;
        }
        triples.push([
            target.gpu_id.clone(),
            healthy[0].gpu_id.clone(),
            healthy[1].gpu_id.clone(),
        ]);
    }

    if triples.is_empty() {
        let all: Vec<&DeviceState> = device_state.values().collect();
        if all.len() >= 3 {
            triples.push([
                all[0].gpu_id.clone(),
                all[1].gpu_id.clone(),
                all[2].gpu_id.clone(),
            ]);
        }
    }

    for triple in triples.into_iter().take(triples_per_interval.max(1)) {
        let now = now_ms();
        let f0 = tmr_fingerprint(&triple[0], now);
        let f1 = tmr_fingerprint(&triple[1], now);
        let f2 = tmr_fingerprint(&triple[2], now);

        let consensus = if f0 == f1 || f0 == f2 {
            Some(f0.clone())
        } else if f1 == f2 {
            Some(f1.clone())
        } else {
            None
        };

        if let Some(consensus) = consensus {
            let dissenting = if f0 != consensus {
                Some(triple[0].clone())
            } else if f1 != consensus {
                Some(triple[1].clone())
            } else if f2 != consensus {
                Some(triple[2].clone())
            } else {
                None
            };

            if let Some(dissenter) = dissenting {
                record_trust_disagreement(trust_graph, &dissenter, &triple[0]);
                record_trust_disagreement(trust_graph, &dissenter, &triple[1]);
                record_trust_disagreement(trust_graph, &dissenter, &triple[2]);

                let entry = FaultAdvertisementEntry {
                    key: format!("tmr:{}:{}", dissenter, &consensus[..8]),
                    gpu_id: dissenter.clone(),
                    probe_type: "tmr".to_string(),
                    state: "fail".to_string(),
                    severity: "high".to_string(),
                    risk: 0.94,
                    confidence: 0.88,
                    count: 1,
                    first_seen_ms: now,
                    last_seen_ms: now,
                };
                fault_hub.update_local_fault(entry.clone()).await;

                let event = Event::new(
                    TRACEY_GUARD_EVENT_COUNTER.fetch_add(1, Ordering::Relaxed),
                    "tracey_guard",
                    EventKind::Observability,
                    0.94,
                    Severity::High,
                )
                .with_attr("metric", "tracey_guard_tmr_dissent")
                .with_attr("gpu_id", dissenter)
                .with_attr("fault_key", entry.key)
                .with_attr("consensus", consensus);
                bus.publish(event.clone());
                storage.record_event(event).await;
            } else {
                record_trust_agreement(trust_graph, &triple[0], &triple[1]);
                record_trust_agreement(trust_graph, &triple[0], &triple[2]);
                record_trust_agreement(trust_graph, &triple[1], &triple[2]);
            }
        }
    }
}

fn record_trust_agreement(
    trust_graph: &mut HashMap<(String, String), (u64, u64)>,
    a: &str,
    b: &str,
) {
    let key = ordered_pair(a, b);
    let entry = trust_graph.entry(key).or_insert((0, 0));
    entry.0 = entry.0.saturating_add(1);
}

fn record_trust_disagreement(
    trust_graph: &mut HashMap<(String, String), (u64, u64)>,
    a: &str,
    b: &str,
) {
    let key = ordered_pair(a, b);
    let entry = trust_graph.entry(key).or_insert((0, 0));
    entry.1 = entry.1.saturating_add(1);
}

fn ordered_pair(a: &str, b: &str) -> (String, String) {
    if a <= b {
        (a.to_string(), b.to_string())
    } else {
        (b.to_string(), a.to_string())
    }
}

fn tmr_fingerprint(gpu_id: &str, ts_ms: u64) -> String {
    let seed = format!("tmr:{}:{}", gpu_id, ts_ms / 10_000);
    let digest = blake3::hash(seed.as_bytes());
    hex::encode(digest.as_bytes())
}

fn build_fault_key(execution: &ProbeExecution) -> String {
    let seed = format!(
        "{}:{}:{}:{}",
        execution.gpu_id,
        execution.probe_type.as_str(),
        execution.sm_id,
        execution.actual_hash,
    );
    let digest = blake3::hash(seed.as_bytes());
    format!(
        "{}:{}:{}",
        execution.gpu_id,
        execution.probe_type.as_str(),
        hex::encode(&digest.as_bytes()[..6]),
    )
}

fn pseudo_ratio(seed: &str) -> f64 {
    let digest = blake3::hash(seed.as_bytes());
    let bytes = digest.as_bytes();
    let mut array = [0u8; 8];
    array.copy_from_slice(&bytes[..8]);
    let raw = u64::from_le_bytes(array);
    (raw as f64 / u64::MAX as f64).clamp(0.0, 1.0)
}

fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

impl TraceyGuardConfig {
    fn probe_cfg(&self, probe_type: ProbeType) -> &TraceyGuardProbeConfig {
        match probe_type {
            ProbeType::Fma => &self.probes.fma,
            ProbeType::TensorCore => &self.probes.tensor_core,
            ProbeType::Transcendental => &self.probes.transcendental,
            ProbeType::Aes => &self.probes.aes,
            ProbeType::Memory => &self.probes.memory,
            ProbeType::RegisterFile => &self.probes.register_file,
            ProbeType::SharedMemory => &self.probes.shared_memory,
        }
    }

    fn probes_fuzzy_profile(&self) -> crate::config::FuzzyConfig {
        let mut fuzzy = crate::config::FuzzyConfig::default();
        fuzzy.order = 5;
        fuzzy.uncertainty = 0.62;
        fuzzy.edge_bias = 0.82;
        fuzzy.aarnn_weight = 0.32;
        fuzzy.security_weight = 0.46;
        fuzzy
    }
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        const LUT: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for &byte in bytes {
            out.push(LUT[(byte >> 4) as usize] as char);
            out.push(LUT[(byte & 0x0f) as usize] as char);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(
        key: &str,
        count: u64,
        first_seen_ms: u64,
        last_seen_ms: u64,
    ) -> FaultAdvertisementEntry {
        FaultAdvertisementEntry {
            key: key.to_string(),
            gpu_id: "gpu-0".to_string(),
            probe_type: "fma".to_string(),
            state: "fail".to_string(),
            severity: "high".to_string(),
            risk: 0.7,
            confidence: 0.8,
            count,
            first_seen_ms,
            last_seen_ms,
        }
    }

    #[tokio::test]
    async fn fault_hub_merges_local_fault_counts() {
        let hub = FaultIntelHub::new(60_000);
        hub.update_local_fault(entry("fault-a", 1, 100, 200)).await;
        hub.update_local_fault(entry("fault-a", 2, 50, 250)).await;
        let snapshot = hub.snapshot(8).await;
        assert_eq!(snapshot.local_fault_count, 1);
        let merged = &snapshot.local_entries[0];
        assert_eq!(merged.count, 3);
        assert_eq!(merged.first_seen_ms, 50);
        assert_eq!(merged.last_seen_ms, 250);
    }

    #[test]
    fn schedule_prefers_high_priority_and_adapts_to_utilization() {
        let mut schedules = vec![
            ProbeScheduleState {
                probe_type: ProbeType::Memory,
                period_ms: 1_000,
                sm_coverage: 1.0,
                priority: 4,
                timeout_ms: 1_000,
                enabled: true,
                next_fire_ms: 0,
                cursor: 0,
            },
            ProbeScheduleState {
                probe_type: ProbeType::Fma,
                period_ms: 1_000,
                sm_coverage: 1.0,
                priority: 1,
                timeout_ms: 1_000,
                enabled: true,
                next_fire_ms: 0,
                cursor: 0,
            },
        ];
        let devices = vec![DiscoveredDevice {
            gpu_id: "gpu-0".to_string(),
            sm_count: 8,
        }];
        let mut telemetry = HashMap::new();
        telemetry.insert(
            "gpu-0".to_string(),
            DeviceTelemetryContext {
                util_pct: 95.0,
                ..DeviceTelemetryContext::default()
            },
        );

        let tasks = schedule_due_tasks(&mut schedules, &devices, &telemetry, now_ms(), false);
        assert!(!tasks.is_empty());
        assert_eq!(tasks[0].probe_type, ProbeType::Fma);
        // 95% utilization reduces coverage by 60% (to 40% of base), 8 SMs -> ~3.
        assert_eq!(
            tasks
                .iter()
                .filter(|task| task.probe_type == ProbeType::Fma)
                .count(),
            3
        );
    }

    #[test]
    fn derive_signal_increases_with_remote_fault_support() {
        let mut context = BTreeMap::new();
        context.insert("stress".to_string(), "0.20".to_string());
        let execution = ProbeExecution {
            ts_ms: 0,
            execution_id: "e".to_string(),
            probe_type: ProbeType::Fma,
            probe_state: ProbeState::Fail,
            gpu_id: "gpu-0".to_string(),
            sm_id: 0,
            expected_hash: String::new(),
            actual_hash: String::new(),
            mismatch_count: 4,
            execution_time_ns: 0,
            risk: 0.0,
            confidence: 0.0,
            signal: 0.0,
            severity: Severity::High,
            context,
        };
        let no_support = derive_signal(&execution, 0);
        let with_support = derive_signal(&execution, 5);
        assert!(with_support > no_support);
    }

    #[test]
    fn ingest_telemetry_context_tracks_revised_gpu_metrics() {
        let mut telemetry = HashMap::new();
        let power_event = Event::new(1, "embedded", EventKind::SystemMetric, 0.5, Severity::Low)
            .with_attr("metric", "gpu_power_w")
            .with_attr("gpu_id", "nvidia:0")
            .with_attr("value", "175.000");
        ingest_telemetry_context(&power_event, &mut telemetry);

        let mem_event = Event::new(2, "embedded", EventKind::SystemMetric, 0.5, Severity::Low)
            .with_attr("metric", "gpu_mem_used_bytes")
            .with_attr("gpu_id", "nvidia:0")
            .with_attr("value", "4096.000")
            .with_attr("used_ratio", "0.5000");
        ingest_telemetry_context(&mem_event, &mut telemetry);

        let gfx_clock_event = Event::new(
            3,
            "embedded",
            EventKind::SystemMetric,
            0.9,
            Severity::Medium,
        )
        .with_attr("metric", "gpu_clock_graphics_mhz")
        .with_attr("gpu_id", "nvidia:0")
        .with_attr("value", "2200.000")
        .with_attr("normalized_ratio", "0.9200");
        ingest_telemetry_context(&gfx_clock_event, &mut telemetry);

        let fan_event = Event::new(
            4,
            "embedded",
            EventKind::SystemMetric,
            0.88,
            Severity::Medium,
        )
        .with_attr("metric", "gpu_fan_speed_percent")
        .with_attr("gpu_id", "nvidia:0")
        .with_attr("value", "88.000");
        ingest_telemetry_context(&fan_event, &mut telemetry);

        let encoder_event = Event::new(
            5,
            "embedded",
            EventKind::SystemMetric,
            0.81,
            Severity::Medium,
        )
        .with_attr("metric", "gpu_encoder_util_percent")
        .with_attr("gpu_id", "nvidia:0")
        .with_attr("value", "81.000");
        ingest_telemetry_context(&encoder_event, &mut telemetry);

        let ctx = telemetry.get("nvidia:0").expect("gpu context should exist");
        assert_eq!(ctx.power_w, 175.0);
        assert!((ctx.mem_used_ratio - 0.5).abs() < f64::EPSILON);
        assert!((ctx.graphics_clock_ratio - 0.92).abs() < f64::EPSILON);
        assert!((ctx.fan_speed_ratio - 0.88).abs() < f64::EPSILON);
        assert!((ctx.encoder_util_ratio - 0.81).abs() < f64::EPSILON);
        assert!(ctx.clock_anomaly_count >= 1);
        assert!(ctx.codec_pressure_count >= 1);
        assert!(compute_stress(ctx) > 0.25);
    }
}
