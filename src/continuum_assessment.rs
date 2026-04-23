use crate::bus::EventBus;
use crate::config::{ContinuumAssessmentConfig, FuzzyConfig};
use crate::continuum_telemetry::{ContinuumTelemetryHandle, ContinuumTelemetrySnapshot};
use crate::event::{Event, EventKind, Severity, now_ms};
use crate::loader_threat::{LoaderThreatSnapshot, LoaderThreatStatusHandle};
use crate::security::{Action, ActionPolicy};
use crate::shutdown::ShutdownListener;
use crate::storage::Storage;
use crate::swarm::{AdaptiveScorer, FuzzyTelemetry};
use crate::tracey_guard::{ProbeState, TraceyGuardRuntimeHandle, TraceyGuardStatusSnapshot};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::collections::hash_map::DefaultHasher;
use std::ffi::OsString;
use std::hash::{Hash, Hasher};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
use tokio::process::Command;
use tokio::sync::RwLock;
use tokio::time::MissedTickBehavior;

static CONTINUUM_ASSESSMENT_EVENT_COUNTER: AtomicU64 = AtomicU64::new(1);

const ASSESSMENT_PROTOCOL_VERSION: u64 = 2;
const DEFAULT_TICK_MS: u64 = 5_000;
const MIN_RETRY_BACKOFF_MS: u64 = 15_000;
const MAX_RETRY_BACKOFF_MS: u64 = 5 * 60_000;
const MAX_RECENT_MATCHES: usize = 12;
const MAX_SIGNALS: usize = 10;
const SUSPICIOUS_PROCESS_KEYWORDS: &[&str] = &[
    "xmrig",
    "cryptominer",
    "kdevtmpfsi",
    "kinsing",
    "diamorphine",
    "reptile",
    "rootkit",
    "masscan",
    "chisel",
    "frpc",
];
const SUSPICIOUS_SERVICE_KEYWORDS: &[&str] = &[
    "miner",
    "xmrig",
    "kdevtmpfsi",
    "kinsing",
    "chisel",
    "frpc",
    "backdoor",
];
const SUSPICIOUS_MODULE_KEYWORDS: &[&str] = &[
    "diamorphine",
    "reptile",
    "rootkit",
    "suterusu",
    "phide",
    "kbeast",
];
const SUSPICIOUS_EXEC_PREFIXES: &[&str] =
    &["/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/", "/run/user/"];

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ContinuumAssessmentMirrorSnapshot {
    pub enabled: bool,
    pub repo_url: String,
    pub sync_in_progress: bool,
    pub indexed_records: usize,
    pub head: String,
    pub indexed_head: String,
    pub last_sync_ms: u64,
    pub last_success_ms: u64,
    pub last_success_age_ms: u64,
    pub last_error: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ContinuumAssessmentSliceSnapshot {
    pub slice_index: usize,
    pub start_ms: u64,
    pub end_ms: u64,
    pub completed: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ContinuumAssessmentPlanSnapshot {
    pub protocol_version: u64,
    pub generated_epoch_ms: u64,
    pub agent_id: String,
    pub plan_token: String,
    pub coordination_mode: String,
    pub coordination_epoch_ms: u64,
    pub late_joiner_assignment: bool,
    pub cycle_start_ms: u64,
    pub cycle_deadline_ms: u64,
    pub cycle_duration_ms: u64,
    pub slot_index: usize,
    pub slot_count: usize,
    pub slot_start_ms: u64,
    pub slot_end_ms: u64,
    pub slot_duration_ms: u64,
    pub slice_count: usize,
    pub slice_interval_ms: u64,
    pub completed_slice_count: usize,
    pub slices: Vec<ContinuumAssessmentSliceSnapshot>,
    pub mirror: ContinuumAssessmentMirrorSnapshot,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ContinuumAssessmentProgressSnapshot {
    pub last_plan_ms: u64,
    pub last_report_ms: u64,
    pub last_report_age_ms: u64,
    pub cycle_start_ms: u64,
    pub cycle_deadline_ms: u64,
    pub slot_start_ms: u64,
    pub slot_end_ms: u64,
    pub slot_index: usize,
    pub slot_count: usize,
    pub slice_count: usize,
    pub completed_slices: Vec<usize>,
    pub completed_slice_count: usize,
    pub last_match_count: usize,
    pub critical_matches: usize,
    pub high_matches: usize,
    pub medium_matches: usize,
    pub low_matches: usize,
    pub kev_matches: usize,
    pub highest_cvss: f64,
    pub packages_seen: usize,
    pub modules_seen: usize,
    pub services_seen: usize,
    pub processes_seen: usize,
    pub reports_accepted: usize,
    pub reports_rejected: usize,
    pub duplicate_reports: usize,
    pub stale_plan_reports: usize,
    pub semantic_faults: usize,
    pub protocol_version: u64,
    pub inventory_digest: String,
    pub plan_token: String,
    pub last_disposition: String,
    pub last_request_id: String,
    pub last_success_ms: u64,
    pub last_failure_ms: u64,
    pub last_error: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ContinuumAssessmentInventoryStats {
    pub items: usize,
    pub packages: usize,
    pub modules: usize,
    pub services: usize,
    pub processes: usize,
    pub kernel_release: String,
    pub captured_static_ms: u64,
    pub captured_process_ms: u64,
    pub slice_index: Option<usize>,
    pub inventory_digest: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ContinuumAssessmentCommunicationSnapshot {
    pub protocol_version: u64,
    pub plan_fetch_successes: u64,
    pub plan_fetch_failures: u64,
    pub report_successes: u64,
    pub report_failures: u64,
    pub duplicate_reports: u64,
    pub stale_plan_recoveries: u64,
    pub semantic_failures: u64,
    pub transport_failures: u64,
    pub parse_failures: u64,
    pub auth_failures: u64,
    pub consecutive_failures: u64,
    pub last_http_status: Option<u16>,
    pub last_operation: String,
    pub last_request_id: String,
    pub last_disposition: String,
    pub last_success_ms: u64,
    pub last_failure_ms: u64,
    pub next_retry_ms: u64,
    pub last_error: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CompromiseAssessmentMatch {
    pub cve_id: String,
    pub severity: String,
    pub cvss: f64,
    pub kev: bool,
    pub match_score: f64,
    pub confidence: f64,
    pub product: String,
    pub vendor: String,
    pub inventory_item: String,
    pub inventory_type: String,
    pub installed_version: String,
    pub matched_assets: Vec<String>,
    pub reason: String,
    pub description: String,
    pub updated: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CompromiseAssessmentSignal {
    pub kind: String,
    pub label: String,
    pub risk: f64,
    pub detail: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CompromiseAssessmentSummary {
    pub status: String,
    pub compromise_risk: f64,
    pub compromise_confidence: f64,
    pub recommended_action: String,
    pub cve_matches: usize,
    pub kev_matches: usize,
    pub critical_matches: usize,
    pub high_matches: usize,
    pub medium_matches: usize,
    pub low_matches: usize,
    pub highest_cvss: f64,
    pub inventory_items: usize,
    pub suspicious_processes: usize,
    pub suspicious_services: usize,
    pub suspicious_modules: usize,
    pub cve_signal: f64,
    pub guard_signal: f64,
    pub loader_signal: f64,
    pub telemetry_signal: f64,
    pub local_signal: f64,
    pub fuzzy_risk: f64,
    pub fuzzy_confidence: f64,
    pub fuzzy_order: u8,
    pub cycle_completion_pct: f64,
    pub next_due_slice_ms: u64,
    pub last_error: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ContinuumAssessmentSnapshot {
    pub ts_ms: u64,
    pub agent_id: String,
    pub enabled: bool,
    pub status: String,
    pub plan: Option<ContinuumAssessmentPlanSnapshot>,
    pub progress: Option<ContinuumAssessmentProgressSnapshot>,
    pub mirror: Option<ContinuumAssessmentMirrorSnapshot>,
    pub inventory: ContinuumAssessmentInventoryStats,
    pub communication: ContinuumAssessmentCommunicationSnapshot,
    pub summary: CompromiseAssessmentSummary,
    pub recent_matches: Vec<CompromiseAssessmentMatch>,
    pub evidence: Vec<CompromiseAssessmentSignal>,
}

#[derive(Clone)]
pub struct ContinuumAssessmentHandle {
    snapshot: Arc<RwLock<ContinuumAssessmentSnapshot>>,
}

impl ContinuumAssessmentHandle {
    pub fn disabled(agent_id: impl Into<String>) -> Self {
        let agent_id = agent_id.into();
        Self {
            snapshot: Arc::new(RwLock::new(ContinuumAssessmentSnapshot {
                ts_ms: now_ms(),
                agent_id,
                enabled: false,
                status: "disabled".to_string(),
                communication: ContinuumAssessmentCommunicationSnapshot {
                    protocol_version: ASSESSMENT_PROTOCOL_VERSION,
                    ..ContinuumAssessmentCommunicationSnapshot::default()
                },
                summary: CompromiseAssessmentSummary {
                    status: "disabled".to_string(),
                    recommended_action: action_label(Action::Monitor),
                    ..CompromiseAssessmentSummary::default()
                },
                ..ContinuumAssessmentSnapshot::default()
            })),
        }
    }

    pub async fn snapshot(&self) -> ContinuumAssessmentSnapshot {
        self.snapshot.read().await.clone()
    }
}

#[derive(Clone, Debug, Default, Serialize)]
struct PackageRecord {
    name: String,
    version: String,
    manager: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    package_url: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
struct ModuleRecord {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    size_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    used_by: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    suspicious_reason: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
struct ServiceRecord {
    name: String,
    state: String,
    substate: String,
    description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    suspicious_reason: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
struct ProcessRecord {
    pid: u32,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    exe: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cpu_pct: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mem_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    suspicious_reason: Option<String>,
}

#[derive(Clone, Debug, Default)]
struct InventoryCache {
    static_captured_ms: u64,
    process_captured_ms: u64,
    kernel_release: String,
    packages: Vec<PackageRecord>,
    modules: Vec<ModuleRecord>,
    services: Vec<ServiceRecord>,
    processes: Vec<ProcessRecord>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
struct ApiEnvelope<T>
where
    T: Default,
{
    success: bool,
    message: String,
    data: T,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
struct AssessmentServerInventory {
    items: usize,
    packages: usize,
    modules: usize,
    services: usize,
    processes: usize,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
struct AssessmentServerSummary {
    matches: usize,
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    kev: usize,
    highest_cvss: f64,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
struct AssessmentServerReportData {
    accepted: bool,
    disposition: String,
    reason: String,
    request_id: String,
    protocol_version: u64,
    generated_epoch_ms: u64,
    agent_id: String,
    plan: ContinuumAssessmentPlanSnapshot,
    progress: ContinuumAssessmentProgressSnapshot,
    mirror: ContinuumAssessmentMirrorSnapshot,
    inventory: AssessmentServerInventory,
    summary: AssessmentServerSummary,
    matches: Vec<CompromiseAssessmentMatch>,
}

#[derive(Clone, Debug)]
enum RequestErrorKind {
    Transport,
    Http,
    Parse,
    Semantic,
    Auth,
}

#[derive(Clone, Debug)]
struct RequestError {
    kind: RequestErrorKind,
    status: Option<u16>,
    message: String,
}

impl RequestError {
    fn new(kind: RequestErrorKind, status: Option<u16>, message: impl Into<String>) -> Self {
        Self {
            kind,
            status,
            message: message.into(),
        }
    }

    fn retryable(&self) -> bool {
        if matches!(
            self.kind,
            RequestErrorKind::Transport | RequestErrorKind::Parse
        ) {
            return true;
        }
        matches!(self.status, Some(408 | 429))
            || matches!(self.status, Some(status) if status >= 500)
    }
}

struct AssessmentRuntime {
    config: ContinuumAssessmentConfig,
    agent_id: String,
    client: reqwest::Client,
    token: Option<String>,
    bus: EventBus,
    storage: Storage,
    policy: ActionPolicy,
    telemetry: ContinuumTelemetryHandle,
    tracey_guard: TraceyGuardRuntimeHandle,
    loader_threats: Option<LoaderThreatStatusHandle>,
    scorer: AdaptiveScorer,
    snapshot: Arc<RwLock<ContinuumAssessmentSnapshot>>,
    cache: InventoryCache,
    plan: Option<ContinuumAssessmentPlanSnapshot>,
    progress: Option<ContinuumAssessmentProgressSnapshot>,
    mirror: Option<ContinuumAssessmentMirrorSnapshot>,
    recent_matches: Vec<CompromiseAssessmentMatch>,
    last_report_inventory: ContinuumAssessmentInventoryStats,
    last_summary: CompromiseAssessmentSummary,
    last_signals: Vec<CompromiseAssessmentSignal>,
    last_plan_fetch_ms: u64,
    last_report_attempt_ms: u64,
    next_plan_attempt_ms: u64,
    next_report_attempt_ms: u64,
    plan_failure_streak: u32,
    report_failure_streak: u32,
    request_sequence: u64,
    communication: ContinuumAssessmentCommunicationSnapshot,
    current_slice_index: Option<usize>,
    last_error: String,
}

pub fn spawn_continuum_assessment(
    config: ContinuumAssessmentConfig,
    agent_id: String,
    bus: EventBus,
    storage: Storage,
    policy: ActionPolicy,
    min_samples: u64,
    fuzzy: FuzzyConfig,
    telemetry: ContinuumTelemetryHandle,
    tracey_guard: TraceyGuardRuntimeHandle,
    loader_threats: Option<LoaderThreatStatusHandle>,
    mut shutdown: ShutdownListener,
) -> ContinuumAssessmentHandle {
    let handle = ContinuumAssessmentHandle::disabled(agent_id.clone());
    if !config.enabled {
        return handle;
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(config.request_timeout_ms))
        .build()
        .unwrap_or_else(|err| {
            tracing::warn!(error = %err, "continuum assessment client init failed; using default reqwest client");
            reqwest::Client::new()
        });

    let scorer = AdaptiveScorer::new(min_samples.max(config.min_samples), fuzzy);
    let snapshot = handle.snapshot.clone();
    tokio::spawn(async move {
        let mut runtime = AssessmentRuntime {
            config,
            agent_id,
            client,
            token: None,
            bus,
            storage,
            policy,
            telemetry,
            tracey_guard,
            loader_threats,
            scorer,
            snapshot,
            cache: InventoryCache::default(),
            plan: None,
            progress: None,
            mirror: None,
            recent_matches: Vec::new(),
            last_report_inventory: ContinuumAssessmentInventoryStats::default(),
            last_summary: CompromiseAssessmentSummary {
                status: "scheduled".to_string(),
                recommended_action: action_label(Action::Monitor),
                ..CompromiseAssessmentSummary::default()
            },
            last_signals: Vec::new(),
            last_plan_fetch_ms: 0,
            last_report_attempt_ms: 0,
            next_plan_attempt_ms: 0,
            next_report_attempt_ms: 0,
            plan_failure_streak: 0,
            report_failure_streak: 0,
            request_sequence: 0,
            communication: ContinuumAssessmentCommunicationSnapshot {
                protocol_version: ASSESSMENT_PROTOCOL_VERSION,
                ..ContinuumAssessmentCommunicationSnapshot::default()
            },
            current_slice_index: None,
            last_error: String::new(),
        };
        runtime.token = runtime.config.bearer_token.clone();
        runtime.update_snapshot(None, None, None).await;

        let tick_ms = runtime
            .config
            .plan_poll_interval_ms
            .min(DEFAULT_TICK_MS)
            .max(1_000);
        let mut interval = tokio::time::interval(Duration::from_millis(tick_ms));
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = shutdown.wait() => {
                    tracing::info!(agent_id = %runtime.agent_id, "continuum assessment runtime shutting down");
                    break;
                }
                _ = interval.tick() => {}
            }

            let now = now_ms();
            let plan_refresh_due = runtime.plan.as_ref().is_none_or(|plan| {
                now > plan.cycle_deadline_ms
                    || now.saturating_sub(runtime.last_plan_fetch_ms)
                        >= runtime.config.plan_poll_interval_ms
            });
            if plan_refresh_due && now >= runtime.next_plan_attempt_ms {
                if let Err(err) = runtime.fetch_plan().await {
                    runtime.last_error = err;
                }
            }

            if let Some(slice_index) = runtime.due_slice_index(now) {
                if now >= runtime.next_report_attempt_ms {
                    runtime.last_report_attempt_ms = now;
                    runtime.current_slice_index = Some(slice_index);
                    if let Err(err) = runtime.execute_slice(slice_index).await {
                        runtime.last_error = err.clone();
                        runtime.emit_error_event(&err).await;
                    }
                    runtime.current_slice_index = None;
                }
            }

            runtime.update_snapshot(None, None, None).await;
        }
    });

    handle
}

impl AssessmentRuntime {
    async fn fetch_plan(&mut self) -> Result<(), String> {
        let plan: ContinuumAssessmentPlanSnapshot = match self
            .request_json(
                reqwest::Method::GET,
                &format!("/tracey/agents/{}/assessment/plan", self.agent_id),
                None::<serde_json::Value>,
            )
            .await
        {
            Ok(plan) => plan,
            Err(error) => {
                self.plan_failure_streak = self.plan_failure_streak.saturating_add(1);
                let retry_at_ms = now_ms().saturating_add(self.retry_backoff_ms(
                    "plan_fetch",
                    self.plan_failure_streak,
                    error.retryable(),
                ));
                self.next_plan_attempt_ms = retry_at_ms;
                self.record_failure("plan_fetch", None, &error, retry_at_ms);
                return Err(error.message);
            }
        };
        if let Err(message) = self.validate_plan(&plan) {
            let error = RequestError::new(RequestErrorKind::Semantic, Some(200), message.clone());
            self.plan_failure_streak = self.plan_failure_streak.saturating_add(1);
            let retry_at_ms = now_ms().saturating_add(self.retry_backoff_ms(
                "plan_fetch",
                self.plan_failure_streak,
                false,
            ));
            self.next_plan_attempt_ms = retry_at_ms;
            self.record_failure("plan_fetch", None, &error, retry_at_ms);
            return Err(message);
        }

        self.last_plan_fetch_ms = now_ms();
        self.next_plan_attempt_ms = self
            .last_plan_fetch_ms
            .saturating_add(self.config.plan_poll_interval_ms);
        self.plan_failure_streak = 0;
        self.last_error.clear();
        self.ingest_plan(plan);
        self.record_success("plan_fetch", None, "ok");
        Ok(())
    }

    fn due_slice_index(&self, now: u64) -> Option<usize> {
        let plan = self.plan.as_ref()?;
        if now < plan.slot_start_ms || now > plan.slot_end_ms {
            return None;
        }
        let completed = self.completed_slice_set();
        plan.slices
            .iter()
            .find(|slice| !completed.contains(&slice.slice_index) && now >= slice.start_ms)
            .map(|slice| slice.slice_index)
    }

    async fn execute_slice(&mut self, slice_index: usize) -> Result<(), String> {
        self.refresh_inventory(true).await?;
        let selected = self.select_slice_inventory(slice_index);
        let request_id = self.next_request_id("report");
        let report_body = self.build_report_body(slice_index, &selected, &request_id);
        let response: AssessmentServerReportData = match self
            .request_json(
                reqwest::Method::POST,
                &format!("/tracey/agents/{}/assessment/report", self.agent_id),
                Some(report_body),
            )
            .await
        {
            Ok(response) => response,
            Err(error) => {
                self.report_failure_streak = self.report_failure_streak.saturating_add(1);
                let retry_at_ms = now_ms().saturating_add(self.retry_backoff_ms(
                    "report",
                    self.report_failure_streak,
                    error.retryable(),
                ));
                self.next_report_attempt_ms = retry_at_ms;
                self.record_failure("report", Some(request_id.as_str()), &error, retry_at_ms);
                return Err(error.message);
            }
        };
        if let Err(message) = self.validate_report_response(&response, &request_id) {
            let error = RequestError::new(RequestErrorKind::Semantic, Some(200), message.clone());
            self.report_failure_streak = self.report_failure_streak.saturating_add(1);
            let retry_at_ms = now_ms().saturating_add(self.retry_backoff_ms(
                "report",
                self.report_failure_streak,
                false,
            ));
            self.next_report_attempt_ms = retry_at_ms;
            self.record_failure("report", Some(request_id.as_str()), &error, retry_at_ms);
            return Err(message);
        }

        self.apply_report_state(&response, slice_index);

        if !response.accepted {
            if response.disposition == "stale_plan" {
                self.report_failure_streak = 0;
                self.next_report_attempt_ms = 0;
                self.last_error.clear();
                self.record_stale_plan_recovery(request_id.as_str(), &response.reason);
                self.update_snapshot(None, None, None).await;
                return Ok(());
            }

            let message = if response.reason.trim().is_empty() {
                "continuum assessment report was rejected".to_string()
            } else {
                response.reason.clone()
            };
            let error = RequestError::new(RequestErrorKind::Semantic, Some(200), message.clone());
            self.report_failure_streak = self.report_failure_streak.saturating_add(1);
            let retry_at_ms = now_ms().saturating_add(self.retry_backoff_ms(
                "report",
                self.report_failure_streak,
                false,
            ));
            self.next_report_attempt_ms = retry_at_ms;
            self.record_failure("report", Some(request_id.as_str()), &error, retry_at_ms);
            return Err(message);
        }

        self.report_failure_streak = 0;
        self.next_report_attempt_ms = 0;
        self.last_error.clear();
        self.record_success(
            "report",
            Some(request_id.as_str()),
            if response.disposition.trim().is_empty() {
                "applied"
            } else {
                response.disposition.as_str()
            },
        );
        if response.disposition == "duplicate" {
            self.communication.duplicate_reports =
                self.communication.duplicate_reports.saturating_add(1);
            self.update_snapshot(None, None, None).await;
            return Ok(());
        }
        self.recent_matches = response
            .matches
            .into_iter()
            .take(MAX_RECENT_MATCHES)
            .collect();

        let guard = self.tracey_guard.snapshot().await;
        let telemetry = self.telemetry.snapshot().await;
        let loader = match &self.loader_threats {
            Some(handle) => handle.snapshot().await,
            None => None,
        };
        let (summary, signals, fuzzy) = self.build_summary(
            &response.summary,
            &guard,
            loader.as_ref(),
            &telemetry,
            response.progress.completed_slice_count,
            response.progress.slice_count,
        );
        self.last_summary = summary.clone();
        self.last_signals = signals.clone();
        self.emit_assessment_event(&summary, &signals, &fuzzy).await;
        self.update_snapshot(Some(summary), Some(signals), Some(fuzzy))
            .await;
        Ok(())
    }

    async fn request_json<T, B>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<B>,
    ) -> Result<T, RequestError>
    where
        T: DeserializeOwned + Default,
        B: Serialize,
    {
        let url = join_url(self.config.base_url.as_str(), path);
        let mut request = self.client.request(method, url);
        if let Some(token) = self.token.as_deref() {
            request = request.header(AUTHORIZATION, format!("Bearer {}", token));
        }
        if let Some(body) = body {
            request = request.header(CONTENT_TYPE, "application/json").json(&body);
        }
        let response = request.send().await.map_err(|err| {
            RequestError::new(
                RequestErrorKind::Transport,
                None,
                format!("continuum assessment request failed: {err}"),
            )
        })?;
        let status = response.status();
        let body = response.bytes().await.map_err(|err| {
            RequestError::new(
                RequestErrorKind::Parse,
                Some(status.as_u16()),
                format!("continuum assessment response read failed: {err}"),
            )
        })?;
        let envelope = serde_json::from_slice::<ApiEnvelope<T>>(&body).map_err(|err| {
            let preview = truncate(String::from_utf8_lossy(&body).trim(), 220);
            let detail = if preview.is_empty() {
                format!("continuum assessment response parse failed: {err}")
            } else {
                format!("continuum assessment response parse failed: {err}; body={preview}")
            };
            RequestError::new(RequestErrorKind::Parse, Some(status.as_u16()), detail)
        })?;
        if !status.is_success() || !envelope.success {
            let message = if envelope.message.trim().is_empty() {
                format!("continuum assessment request returned {}", status)
            } else {
                envelope.message
            };
            let kind = if matches!(status.as_u16(), 401 | 403) {
                RequestErrorKind::Auth
            } else if matches!(status.as_u16(), 400 | 404 | 409 | 422) {
                RequestErrorKind::Semantic
            } else {
                RequestErrorKind::Http
            };
            return Err(RequestError::new(kind, Some(status.as_u16()), message));
        }
        Ok(envelope.data)
    }

    fn validate_plan(&self, plan: &ContinuumAssessmentPlanSnapshot) -> Result<(), String> {
        if !plan.agent_id.trim().is_empty() && plan.agent_id != self.agent_id {
            return Err(format!(
                "continuum returned assessment plan for unexpected agent '{}'",
                plan.agent_id
            ));
        }
        if plan.slot_count == 0 || plan.slot_index >= plan.slot_count {
            return Err("continuum returned an invalid slot assignment.".to_string());
        }
        if plan.slice_count == 0 || plan.slices.len() != plan.slice_count {
            return Err("continuum returned an invalid slice manifest.".to_string());
        }
        if plan.completed_slice_count > plan.slice_count {
            return Err("continuum returned inconsistent completed slice counts.".to_string());
        }
        if plan.slot_end_ms <= plan.slot_start_ms || plan.cycle_deadline_ms <= plan.cycle_start_ms {
            return Err("continuum returned an invalid scheduling window.".to_string());
        }
        if plan.protocol_version >= ASSESSMENT_PROTOCOL_VERSION && plan.plan_token.trim().is_empty()
        {
            return Err("continuum omitted the required plan token.".to_string());
        }
        let mut previous_end_ms = plan.slot_start_ms;
        let mut seen = BTreeSet::new();
        for slice in &plan.slices {
            if slice.slice_index >= plan.slice_count {
                return Err(
                    "continuum returned a slice_index outside the declared slice_count."
                        .to_string(),
                );
            }
            if !seen.insert(slice.slice_index) {
                return Err("continuum returned duplicate slice indexes.".to_string());
            }
            if slice.end_ms <= slice.start_ms {
                return Err("continuum returned a slice with a non-positive duration.".to_string());
            }
            if slice.start_ms < plan.slot_start_ms || slice.end_ms > plan.slot_end_ms {
                return Err(
                    "continuum returned a slice outside the assigned slot window.".to_string(),
                );
            }
            if slice.start_ms < previous_end_ms {
                return Err("continuum returned overlapping slice timing.".to_string());
            }
            previous_end_ms = slice.end_ms;
        }
        Ok(())
    }

    fn validate_report_response(
        &self,
        response: &AssessmentServerReportData,
        request_id: &str,
    ) -> Result<(), String> {
        if !response.agent_id.trim().is_empty() && response.agent_id != self.agent_id {
            return Err(format!(
                "continuum responded with assessment data for unexpected agent '{}'",
                response.agent_id
            ));
        }
        if response.protocol_version >= ASSESSMENT_PROTOCOL_VERSION
            && response.request_id != request_id
        {
            return Err("continuum echoed a mismatched assessment request_id.".to_string());
        }
        self.validate_plan(&response.plan)?;
        if response.progress.slice_count > 0
            && response.progress.slice_count != response.plan.slice_count
        {
            return Err("continuum returned mismatched plan/progress slice counts.".to_string());
        }
        if response.progress.slot_count > 0
            && response.progress.slot_count != response.plan.slot_count
        {
            return Err("continuum returned mismatched plan/progress slot counts.".to_string());
        }
        Ok(())
    }

    fn ingest_plan(&mut self, plan: ContinuumAssessmentPlanSnapshot) {
        self.mirror = Some(plan.mirror.clone());
        if self.progress.is_none() {
            self.progress = Some(ContinuumAssessmentProgressSnapshot {
                last_plan_ms: plan.generated_epoch_ms,
                cycle_start_ms: plan.cycle_start_ms,
                cycle_deadline_ms: plan.cycle_deadline_ms,
                slot_start_ms: plan.slot_start_ms,
                slot_end_ms: plan.slot_end_ms,
                slot_index: plan.slot_index,
                slot_count: plan.slot_count,
                slice_count: plan.slice_count,
                completed_slice_count: plan.completed_slice_count,
                completed_slices: plan
                    .slices
                    .iter()
                    .filter(|slice| slice.completed)
                    .map(|slice| slice.slice_index)
                    .collect(),
                protocol_version: plan.protocol_version.max(1),
                plan_token: plan.plan_token.clone(),
                ..ContinuumAssessmentProgressSnapshot::default()
            });
        } else if let Some(progress) = self.progress.as_mut() {
            progress.last_plan_ms = plan.generated_epoch_ms;
            progress.cycle_start_ms = plan.cycle_start_ms;
            progress.cycle_deadline_ms = plan.cycle_deadline_ms;
            progress.slot_start_ms = plan.slot_start_ms;
            progress.slot_end_ms = plan.slot_end_ms;
            progress.slot_index = plan.slot_index;
            progress.slot_count = plan.slot_count;
            progress.slice_count = plan.slice_count;
            progress.protocol_version = plan.protocol_version.max(1);
            progress.plan_token = plan.plan_token.clone();
            let mut completed = plan
                .slices
                .iter()
                .filter(|slice| slice.completed)
                .map(|slice| slice.slice_index)
                .collect::<Vec<_>>();
            for slice in &progress.completed_slices {
                if !completed.contains(slice) {
                    completed.push(*slice);
                }
            }
            completed.sort_unstable();
            completed.dedup();
            progress.completed_slice_count = completed.len();
            progress.completed_slices = completed;
        }
        self.plan = Some(plan);
    }

    fn apply_report_state(&mut self, response: &AssessmentServerReportData, slice_index: usize) {
        self.plan = Some(response.plan.clone());
        self.progress = Some(response.progress.clone());
        self.mirror = Some(response.mirror.clone());
        self.last_report_inventory = ContinuumAssessmentInventoryStats {
            items: response.inventory.items,
            packages: response.inventory.packages,
            modules: response.inventory.modules,
            services: response.inventory.services,
            processes: response.inventory.processes,
            kernel_release: self.cache.kernel_release.clone(),
            captured_static_ms: self.cache.static_captured_ms,
            captured_process_ms: self.cache.process_captured_ms,
            slice_index: Some(slice_index),
            inventory_digest: self
                .progress
                .as_ref()
                .map(|progress| progress.inventory_digest.clone())
                .unwrap_or_default(),
        };
    }

    fn next_request_id(&mut self, phase: &str) -> String {
        self.request_sequence = self.request_sequence.saturating_add(1);
        let seed = format!(
            "{}|{}|{}|{}",
            self.agent_id,
            phase,
            self.request_sequence,
            now_ms()
        );
        let digest = blake3::hash(seed.as_bytes()).to_hex().to_string();
        format!("{phase}-{}", &digest[..16])
    }

    fn retry_backoff_ms(&self, phase: &str, streak: u32, retryable: bool) -> u64 {
        let base = if retryable {
            MIN_RETRY_BACKOFF_MS
        } else {
            MIN_RETRY_BACKOFF_MS.saturating_mul(2)
        };
        let shift = streak.saturating_sub(1).min(5);
        let scaled = base
            .saturating_mul(1_u64 << shift)
            .min(MAX_RETRY_BACKOFF_MS);
        let mut hasher = DefaultHasher::new();
        self.agent_id.hash(&mut hasher);
        phase.hash(&mut hasher);
        streak.hash(&mut hasher);
        let jitter = hasher.finish() % (base / 3).max(1);
        scaled.saturating_add(jitter)
    }

    fn record_success(&mut self, operation: &str, request_id: Option<&str>, disposition: &str) {
        let now = now_ms();
        self.communication.protocol_version = ASSESSMENT_PROTOCOL_VERSION;
        self.communication.last_operation = operation.to_string();
        self.communication.last_request_id = request_id.unwrap_or_default().to_string();
        self.communication.last_disposition = disposition.to_string();
        self.communication.last_success_ms = now;
        self.communication.next_retry_ms = 0;
        self.communication.last_http_status = Some(200);
        self.communication.last_error.clear();
        self.communication.consecutive_failures = 0;
        if operation == "plan_fetch" {
            self.communication.plan_fetch_successes =
                self.communication.plan_fetch_successes.saturating_add(1);
        } else {
            self.communication.report_successes =
                self.communication.report_successes.saturating_add(1);
        }
    }

    fn record_stale_plan_recovery(&mut self, request_id: &str, reason: &str) {
        let now = now_ms();
        self.communication.protocol_version = ASSESSMENT_PROTOCOL_VERSION;
        self.communication.last_operation = "report".to_string();
        self.communication.last_request_id = request_id.to_string();
        self.communication.last_disposition = "stale_plan".to_string();
        self.communication.last_success_ms = now;
        self.communication.next_retry_ms = 0;
        self.communication.last_http_status = Some(200);
        self.communication.last_error = reason.to_string();
        self.communication.stale_plan_recoveries =
            self.communication.stale_plan_recoveries.saturating_add(1);
        self.communication.consecutive_failures = 0;
    }

    fn record_failure(
        &mut self,
        operation: &str,
        request_id: Option<&str>,
        error: &RequestError,
        retry_at_ms: u64,
    ) {
        let now = now_ms();
        self.communication.protocol_version = ASSESSMENT_PROTOCOL_VERSION;
        self.communication.last_operation = operation.to_string();
        self.communication.last_request_id = request_id.unwrap_or_default().to_string();
        self.communication.last_disposition = "error".to_string();
        self.communication.last_failure_ms = now;
        self.communication.next_retry_ms = retry_at_ms;
        self.communication.last_http_status = error.status;
        self.communication.last_error = error.message.clone();
        self.communication.consecutive_failures =
            self.communication.consecutive_failures.saturating_add(1);
        if operation == "plan_fetch" {
            self.communication.plan_fetch_failures =
                self.communication.plan_fetch_failures.saturating_add(1);
        } else {
            self.communication.report_failures =
                self.communication.report_failures.saturating_add(1);
        }
        match error.kind {
            RequestErrorKind::Transport => {
                self.communication.transport_failures =
                    self.communication.transport_failures.saturating_add(1);
            }
            RequestErrorKind::Parse => {
                self.communication.parse_failures =
                    self.communication.parse_failures.saturating_add(1);
            }
            RequestErrorKind::Auth => {
                self.communication.auth_failures =
                    self.communication.auth_failures.saturating_add(1);
            }
            RequestErrorKind::Semantic => {
                self.communication.semantic_failures =
                    self.communication.semantic_failures.saturating_add(1);
            }
            RequestErrorKind::Http => {}
        }
    }

    async fn refresh_inventory(&mut self, force_process: bool) -> Result<(), String> {
        let now = now_ms();
        let static_stale = self.cache.static_captured_ms == 0
            || now.saturating_sub(self.cache.static_captured_ms)
                >= self.config.inventory_cache_ttl_ms;
        let process_stale = self.cache.process_captured_ms == 0
            || now.saturating_sub(self.cache.process_captured_ms)
                >= self.config.process_cache_ttl_ms;

        if static_stale {
            let (kernel_release, packages, modules, services) = tokio::join!(
                collect_kernel_release(),
                collect_packages(self.config.package_max, self.config.request_timeout_ms),
                collect_modules(self.config.module_max),
                collect_services(self.config.service_max, self.config.request_timeout_ms),
            );
            self.cache.kernel_release = kernel_release.unwrap_or_default();
            self.cache.packages = packages;
            self.cache.modules = modules;
            self.cache.services = services;
            self.cache.static_captured_ms = now;
        }

        if force_process || process_stale {
            self.cache.processes = collect_processes(self.config.process_max);
            self.cache.process_captured_ms = now;
        }
        Ok(())
    }

    fn select_slice_inventory(&self, slice_index: usize) -> SelectedInventory {
        let slice_count = self
            .plan
            .as_ref()
            .map(|plan| plan.slice_count)
            .unwrap_or(1)
            .max(1);
        let packages = self
            .cache
            .packages
            .iter()
            .filter(|record| slice_membership("package", &record.name, slice_index, slice_count))
            .cloned()
            .collect::<Vec<_>>();
        let modules = self
            .cache
            .modules
            .iter()
            .filter(|record| slice_membership("module", &record.name, slice_index, slice_count))
            .cloned()
            .collect::<Vec<_>>();
        let services = self
            .cache
            .services
            .iter()
            .filter(|record| slice_membership("service", &record.name, slice_index, slice_count))
            .cloned()
            .collect::<Vec<_>>();
        let processes = self
            .cache
            .processes
            .iter()
            .filter(|record| slice_membership("process", &record.name, slice_index, slice_count))
            .cloned()
            .collect::<Vec<_>>();
        SelectedInventory {
            packages,
            modules,
            services,
            processes,
        }
    }

    fn build_report_body(
        &self,
        slice_index: usize,
        selected: &SelectedInventory,
        request_id: &str,
    ) -> serde_json::Value {
        let protocol_version = self
            .plan
            .as_ref()
            .map(|plan| plan.protocol_version.max(1))
            .unwrap_or(1);
        let plan_token = self
            .plan
            .as_ref()
            .map(|plan| plan.plan_token.clone())
            .unwrap_or_default();
        let inventory = serde_json::json!({
            "packages": &selected.packages,
            "modules": &selected.modules,
            "services": &selected.services,
            "processes": &selected.processes,
            "kernel": {
                "name": "linux-kernel",
                "release": self.cache.kernel_release.clone(),
            }
        });
        serde_json::json!({
            "protocol_version": protocol_version,
            "request_id": request_id,
            "generated_epoch_ms": now_ms(),
            "cycle_start_ms": self.plan.as_ref().map(|plan| plan.cycle_start_ms),
            "slot_index": self.plan.as_ref().map(|plan| plan.slot_index),
            "slot_count": self.plan.as_ref().map(|plan| plan.slot_count),
            "slice_index": slice_index,
            "slice_count": self.plan.as_ref().map(|plan| plan.slice_count),
            "plan_token": if plan_token.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(plan_token) },
            "inventory_digest": blake3::hash(inventory.to_string().as_bytes()).to_hex().to_string(),
            "inventory": inventory
        })
    }

    fn build_summary(
        &mut self,
        server: &AssessmentServerSummary,
        guard: &TraceyGuardStatusSnapshot,
        loader: Option<&LoaderThreatSnapshot>,
        telemetry: &ContinuumTelemetrySnapshot,
        completed_slice_count: usize,
        slice_count: usize,
    ) -> (
        CompromiseAssessmentSummary,
        Vec<CompromiseAssessmentSignal>,
        FuzzyTelemetry,
    ) {
        let suspicious_processes = self
            .cache
            .processes
            .iter()
            .filter(|record| record.suspicious_reason.is_some())
            .count();
        let suspicious_services = self
            .cache
            .services
            .iter()
            .filter(|record| record.suspicious_reason.is_some())
            .count();
        let suspicious_modules = self
            .cache
            .modules
            .iter()
            .filter(|record| record.suspicious_reason.is_some())
            .count();

        let cve_signal = cve_signal(server);
        let guard_signal = derive_guard_signal(guard);
        let loader_signal = derive_loader_signal(loader);
        let telemetry_signal = derive_telemetry_signal(telemetry);
        let local_signal = derive_local_signal(
            suspicious_processes,
            suspicious_services,
            suspicious_modules,
        );

        let mut weights = [
            0.42 + self.config.fuzzy.security_weight * 0.10,
            0.24,
            0.16 + self.config.fuzzy.security_weight * 0.05,
            0.08 + self.config.fuzzy.aarnn_weight * 0.10,
            0.10,
        ];
        let weight_total = weights.iter().sum::<f64>().max(0.001);
        for weight in &mut weights {
            *weight /= weight_total;
        }

        let mut direct_risk = cve_signal * weights[0]
            + guard_signal * weights[1]
            + loader_signal * weights[2]
            + telemetry_signal * weights[3]
            + local_signal * weights[4];
        if server.kev > 0 {
            direct_risk = direct_risk.max(0.84);
        }
        if matches!(
            self.policy.decide(loader_signal.max(guard_signal), 0.65),
            Action::Isolate | Action::Shutdown
        ) {
            direct_risk = direct_risk.max(0.86);
        }
        direct_risk = direct_risk.clamp(0.0, 1.0);

        let evidence_points = server.matches as f64
            + server.kev as f64 * 2.0
            + suspicious_processes as f64 * 1.2
            + suspicious_services as f64 * 0.8
            + suspicious_modules as f64 * 1.1
            + usize::from(loader_signal > 0.0) as f64 * 2.0
            + usize::from(guard_signal > 0.0) as f64 * 2.0;
        let direct_confidence = (evidence_points / self.config.min_samples.max(1) as f64)
            .clamp(0.0, 1.0)
            .max(if server.kev > 0 { 0.62 } else { 0.0 })
            .max(if loader_signal >= 0.70 || guard_signal >= 0.75 {
                0.58
            } else {
                0.0
            });

        let top_match = self.recent_matches.first();
        let mut event = Event::new(
            CONTINUUM_ASSESSMENT_EVENT_COUNTER.fetch_add(1, Ordering::Relaxed),
            "security::continuum_assessment",
            EventKind::Observability,
            direct_risk,
            severity_for_summary(server, direct_risk),
        )
        .with_attr("metric", "compromise_risk")
        .with_attr(
            "anomaly",
            if direct_risk >= self.policy.alert_threshold {
                "true"
            } else {
                "false"
            },
        )
        .with_attr("cve_matches", server.matches.to_string())
        .with_attr("kev_matches", server.kev.to_string())
        .with_attr("cvss", format!("{:.1}", server.highest_cvss))
        .with_attr(
            "finding_severity",
            highest_finding_severity(server).to_string(),
        );
        if let Some(top_match) = top_match {
            event = event.with_attr("cve", top_match.cve_id.clone());
        }

        let score = self.scorer.score_and_update(&event);
        let fuzzy = score.telemetry.clone();
        let compromise_risk = (direct_risk * 0.68 + score.risk * 0.32)
            .max(if server.kev > 0 { 0.84 } else { 0.0 })
            .clamp(0.0, 1.0);
        let compromise_confidence =
            (direct_confidence * 0.62 + score.confidence * 0.38).clamp(0.0, 1.0);
        let recommended_action = self.policy.decide(compromise_risk, compromise_confidence);
        let completion_pct = if slice_count == 0 {
            0.0
        } else {
            completed_slice_count as f64 / slice_count as f64
        };
        let next_due_slice_ms = self
            .plan
            .as_ref()
            .and_then(|plan| {
                let completed = self.completed_slice_set();
                plan.slices
                    .iter()
                    .find(|slice| !completed.contains(&slice.slice_index))
                    .map(|slice| slice.start_ms)
            })
            .unwrap_or_default();

        let mut signals = vec![
            CompromiseAssessmentSignal {
                kind: "cve".to_string(),
                label: format!(
                    "{} matches / {} kev / cvss {:.1}",
                    server.matches, server.kev, server.highest_cvss
                ),
                risk: cve_signal,
                detail: format!(
                    "critical={} high={} medium={} low={}",
                    server.critical, server.high, server.medium, server.low
                ),
            },
            CompromiseAssessmentSignal {
                kind: "tracey_guard".to_string(),
                label: format!(
                    "{} quarantined / {} suspect",
                    guard.summary.quarantined_devices, guard.summary.suspect_devices
                ),
                risk: guard_signal,
                detail: format!(
                    "recent_faults={} remote_faults={} remote_support={}",
                    guard.recent_faults.len(),
                    guard.remote_faults.len(),
                    guard.summary.remote_fault_support
                ),
            },
            CompromiseAssessmentSignal {
                kind: "loader".to_string(),
                label: loader
                    .map(loader_label)
                    .unwrap_or_else(|| "loader intel unavailable".to_string()),
                risk: loader_signal,
                detail: loader
                    .map(loader_detail)
                    .unwrap_or_else(|| "no loader threat snapshot".to_string()),
            },
            CompromiseAssessmentSignal {
                kind: "telemetry".to_string(),
                label: format!(
                    "autonomy {} thermal={} fan={}",
                    format_ratio_pct(telemetry.server.autonomy_risk.unwrap_or_default()),
                    telemetry.server.thermal_alerts,
                    telemetry.server.fan_alerts
                ),
                risk: telemetry_signal,
                detail: format!(
                    "gpu util {} temp {} power {}",
                    format_opt_pct(telemetry.server.gpu_utilization_avg_pct),
                    format_opt_temp(telemetry.server.gpu_temperature_max_c),
                    format_opt_power(telemetry.server.gpu_power_total_w)
                ),
            },
            CompromiseAssessmentSignal {
                kind: "local".to_string(),
                label: format!(
                    "proc={} svc={} mod={}",
                    suspicious_processes, suspicious_services, suspicious_modules
                ),
                risk: local_signal,
                detail: build_local_finding_detail(&self.cache),
            },
        ];
        signals.sort_by(|left, right| {
            right
                .risk
                .partial_cmp(&left.risk)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| left.kind.cmp(&right.kind))
        });
        signals.truncate(MAX_SIGNALS);

        let status = if !self.last_error.trim().is_empty()
            && compromise_risk < self.policy.alert_threshold
        {
            "degraded"
        } else if compromise_risk >= self.policy.isolate_threshold
            && compromise_confidence >= self.policy.min_confidence
        {
            "compromised"
        } else if compromise_risk >= self.policy.alert_threshold {
            "elevated"
        } else if completion_pct >= 1.0 {
            "complete"
        } else if self.current_slice_index.is_some() {
            "assessing"
        } else {
            "scheduled"
        };

        (
            CompromiseAssessmentSummary {
                status: status.to_string(),
                compromise_risk,
                compromise_confidence,
                recommended_action: action_label(recommended_action),
                cve_matches: server.matches,
                kev_matches: server.kev,
                critical_matches: server.critical,
                high_matches: server.high,
                medium_matches: server.medium,
                low_matches: server.low,
                highest_cvss: server.highest_cvss,
                inventory_items: self.cache.packages.len()
                    + self.cache.modules.len()
                    + self.cache.services.len()
                    + self.cache.processes.len()
                    + usize::from(!self.cache.kernel_release.is_empty()),
                suspicious_processes,
                suspicious_services,
                suspicious_modules,
                cve_signal,
                guard_signal,
                loader_signal,
                telemetry_signal,
                local_signal,
                fuzzy_risk: score.risk,
                fuzzy_confidence: score.confidence,
                fuzzy_order: score.telemetry.order,
                cycle_completion_pct: completion_pct,
                next_due_slice_ms,
                last_error: self.last_error.clone(),
            },
            signals,
            fuzzy,
        )
    }

    async fn update_snapshot(
        &self,
        summary_override: Option<CompromiseAssessmentSummary>,
        signals_override: Option<Vec<CompromiseAssessmentSignal>>,
        _fuzzy_override: Option<FuzzyTelemetry>,
    ) {
        let now = now_ms();
        let mut summary = summary_override.unwrap_or_else(|| self.last_summary.clone());
        summary.last_error = self.last_error.clone();
        if self.current_slice_index.is_some() {
            summary.status = "assessing".to_string();
        } else if !self.last_error.trim().is_empty()
            && summary.compromise_risk < self.policy.alert_threshold
        {
            summary.status = "degraded".to_string();
        } else if summary.status.trim().is_empty() {
            summary.status = "scheduled".to_string();
        }
        let signals = signals_override.unwrap_or_else(|| self.last_signals.clone());
        let inventory = if self.last_report_inventory.items > 0
            || self.last_report_inventory.slice_index.is_some()
        {
            self.last_report_inventory.clone()
        } else {
            ContinuumAssessmentInventoryStats {
                items: self.cache.packages.len()
                    + self.cache.modules.len()
                    + self.cache.services.len()
                    + self.cache.processes.len()
                    + usize::from(!self.cache.kernel_release.is_empty()),
                packages: self.cache.packages.len(),
                modules: self.cache.modules.len(),
                services: self.cache.services.len(),
                processes: self.cache.processes.len(),
                kernel_release: self.cache.kernel_release.clone(),
                captured_static_ms: self.cache.static_captured_ms,
                captured_process_ms: self.cache.process_captured_ms,
                inventory_digest: self
                    .progress
                    .as_ref()
                    .map(|progress| progress.inventory_digest.clone())
                    .unwrap_or_default(),
                ..ContinuumAssessmentInventoryStats::default()
            }
        };
        let snapshot = ContinuumAssessmentSnapshot {
            ts_ms: now,
            agent_id: self.agent_id.clone(),
            enabled: self.config.enabled,
            status: summary.status.clone(),
            plan: self.plan.clone(),
            progress: self.progress.clone(),
            mirror: self.mirror.clone(),
            inventory,
            communication: self.communication.clone(),
            summary,
            recent_matches: self.recent_matches.clone(),
            evidence: signals,
        };
        *self.snapshot.write().await = snapshot;
    }

    async fn emit_assessment_event(
        &self,
        summary: &CompromiseAssessmentSummary,
        signals: &[CompromiseAssessmentSignal],
        _fuzzy: &FuzzyTelemetry,
    ) {
        let severity = if summary.compromise_risk >= self.policy.isolate_threshold {
            Severity::Critical
        } else if summary.compromise_risk >= self.policy.alert_threshold {
            Severity::High
        } else if summary.compromise_risk > 0.0 {
            Severity::Medium
        } else {
            Severity::Low
        };
        let mut event = Event::new(
            CONTINUUM_ASSESSMENT_EVENT_COUNTER.fetch_add(1, Ordering::Relaxed),
            "security::continuum_assessment",
            EventKind::Observability,
            summary.compromise_risk,
            severity,
        )
        .with_attr("metric", "compromise_risk")
        .with_attr("assessment_status", summary.status.clone())
        .with_attr("recommended_action", summary.recommended_action.clone())
        .with_attr("cve_matches", summary.cve_matches.to_string())
        .with_attr("kev_matches", summary.kev_matches.to_string())
        .with_attr("cvss", format!("{:.1}", summary.highest_cvss))
        .with_attr(
            "finding_severity",
            highest_finding_severity_from_summary(summary).to_string(),
        )
        .with_attr(
            "anomaly",
            if summary.compromise_risk >= self.policy.alert_threshold {
                "true"
            } else {
                "false"
            },
        );
        if let Some(top_match) = self.recent_matches.first() {
            event = event.with_attr("cve", top_match.cve_id.clone());
        }
        if let Some(top_signal) = signals.first() {
            event = event.with_attr("signal_kind", top_signal.kind.clone());
        }
        self.bus.publish(event.clone());
        self.storage.record_event(event).await;
    }

    async fn emit_error_event(&self, error: &str) {
        let event = Event::new(
            CONTINUUM_ASSESSMENT_EVENT_COUNTER.fetch_add(1, Ordering::Relaxed),
            "security::continuum_assessment",
            EventKind::Observability,
            0.45,
            Severity::Medium,
        )
        .with_attr("metric", "assessment_error")
        .with_attr("reason", truncate(error, 160))
        .with_attr("anomaly", "true");
        self.bus.publish(event.clone());
        self.storage.record_event(event).await;
    }

    fn completed_slice_set(&self) -> BTreeSet<usize> {
        self.progress
            .as_ref()
            .map(|progress| progress.completed_slices.iter().copied().collect())
            .unwrap_or_default()
    }
}

#[derive(Clone, Debug, Default)]
struct SelectedInventory {
    packages: Vec<PackageRecord>,
    modules: Vec<ModuleRecord>,
    services: Vec<ServiceRecord>,
    processes: Vec<ProcessRecord>,
}

async fn collect_kernel_release() -> Option<String> {
    tokio::fs::read_to_string("/proc/sys/kernel/osrelease")
        .await
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

async fn collect_packages(max: usize, timeout_ms: u64) -> Vec<PackageRecord> {
    let commands = [
        (
            "dpkg-query",
            vec!["-W", "-f=${Package}\t${Version}\n"],
            "deb",
        ),
        (
            "rpm",
            vec!["-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"],
            "rpm",
        ),
        ("pacman", vec!["-Q"], "pacman"),
        ("apk", vec!["info", "-v"], "apk"),
    ];
    for (binary, args, manager) in commands {
        let Ok(raw) = run_command(binary, &args, timeout_ms).await else {
            continue;
        };
        let mut packages = Vec::new();
        for line in raw.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let (name, version) = if let Some((name, version)) = line.split_once('\t') {
                (name.trim().to_string(), version.trim().to_string())
            } else if let Some((name, version)) = line.split_once(' ') {
                (name.trim().to_string(), version.trim().to_string())
            } else {
                (line.to_string(), String::new())
            };
            if name.is_empty() {
                continue;
            }
            packages.push(PackageRecord {
                package_url: Some(build_package_url(manager, &name, &version)),
                name,
                version,
                manager: manager.to_string(),
            });
        }
        packages.sort_by(|left, right| left.name.cmp(&right.name));
        packages.dedup_by(|left, right| left.name == right.name && left.version == right.version);
        if packages.len() > max {
            packages.truncate(max);
        }
        if !packages.is_empty() {
            return packages;
        }
    }
    Vec::new()
}

async fn collect_modules(max: usize) -> Vec<ModuleRecord> {
    let Ok(raw) = tokio::fs::read_to_string("/proc/modules").await else {
        return Vec::new();
    };
    let mut modules = Vec::new();
    for line in raw.lines() {
        let parts = line.split_whitespace().collect::<Vec<_>>();
        if parts.len() < 4 {
            continue;
        }
        let name = parts[0].trim().to_string();
        if name.is_empty() {
            continue;
        }
        let used_by = parts[3]
            .split(',')
            .filter(|value| !value.is_empty() && *value != "-")
            .map(|value| value.to_string())
            .collect::<Vec<_>>();
        let suspicious_reason = suspicious_module_reason(&name);
        let version = tokio::fs::read_to_string(format!("/sys/module/{}/version", name))
            .await
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        modules.push(ModuleRecord {
            name,
            version,
            size_bytes: parts[1].parse::<u64>().ok(),
            used_by,
            suspicious_reason,
        });
    }
    modules.sort_by(|left, right| {
        right
            .suspicious_reason
            .is_some()
            .cmp(&left.suspicious_reason.is_some())
            .then_with(|| left.name.cmp(&right.name))
    });
    if modules.len() > max {
        modules.truncate(max);
    }
    modules
}

async fn collect_services(max: usize, timeout_ms: u64) -> Vec<ServiceRecord> {
    let Ok(raw) = run_command(
        "systemctl",
        &[
            "list-units",
            "--type=service",
            "--state=running,failed,activating,reloading,deactivating",
            "--no-legend",
            "--no-pager",
            "--plain",
        ],
        timeout_ms,
    )
    .await
    else {
        return Vec::new();
    };
    let mut services = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parts = line.split_whitespace().collect::<Vec<_>>();
        if parts.len() < 4 {
            continue;
        }
        let description = if parts.len() > 4 {
            parts[4..].join(" ")
        } else {
            String::new()
        };
        let name = parts[0].trim().to_string();
        if name.is_empty() {
            continue;
        }
        let state = parts[2].trim().to_string();
        let substate = parts[3].trim().to_string();
        let suspicious_reason = suspicious_service_reason(&name, &description, &state, &substate);
        services.push(ServiceRecord {
            name,
            state,
            substate,
            description,
            suspicious_reason,
        });
    }
    services.sort_by(|left, right| {
        right
            .suspicious_reason
            .is_some()
            .cmp(&left.suspicious_reason.is_some())
            .then_with(|| left.name.cmp(&right.name))
    });
    if services.len() > max {
        services.truncate(max);
    }
    services
}

fn collect_processes(max: usize) -> Vec<ProcessRecord> {
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing()
            .with_cmd(UpdateKind::OnlyIfNotSet)
            .with_exe(UpdateKind::OnlyIfNotSet),
    );
    let mut processes = system
        .processes()
        .iter()
        .map(|(pid, process)| {
            let exe = process.exe().map(|path| path.to_string_lossy().to_string());
            let command = command_string(process.cmd());
            let suspicious_reason = suspicious_process_reason(
                process.name().to_string_lossy().as_ref(),
                exe.as_deref(),
                command.as_deref(),
            );
            ProcessRecord {
                pid: pid.as_u32(),
                name: process.name().to_string_lossy().to_string(),
                exe,
                command,
                cpu_pct: Some(process.cpu_usage()),
                mem_bytes: Some(process.memory()),
                suspicious_reason,
            }
        })
        .collect::<Vec<_>>();
    processes.sort_by(|left, right| {
        right
            .suspicious_reason
            .is_some()
            .cmp(&left.suspicious_reason.is_some())
            .then_with(|| {
                right
                    .mem_bytes
                    .unwrap_or_default()
                    .cmp(&left.mem_bytes.unwrap_or_default())
            })
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.pid.cmp(&right.pid))
    });
    if processes.len() > max {
        processes.truncate(max);
    }
    processes
}

async fn run_command(binary: &str, args: &[&str], timeout_ms: u64) -> Result<String, String> {
    let mut command = Command::new(binary);
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_millis(timeout_ms.max(500)), command.output())
        .await
        .map_err(|_| format!("{} timed out", binary))?
        .map_err(|err| err.to_string())?;
    if !output.status.success() {
        return Err(format!(
            "{} exited with {}",
            binary,
            output.status.code().unwrap_or(-1)
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn command_string(parts: &[OsString]) -> Option<String> {
    if parts.is_empty() {
        return None;
    }
    Some(
        parts
            .iter()
            .map(|part| part.to_string_lossy().to_string())
            .collect::<Vec<_>>()
            .join(" "),
    )
}

fn build_package_url(manager: &str, name: &str, version: &str) -> String {
    if version.is_empty() {
        format!("pkg:{}/{}", manager, name)
    } else {
        format!("pkg:{}/{}@{}", manager, name, version)
    }
}

fn suspicious_process_reason(
    name: &str,
    exe: Option<&str>,
    command: Option<&str>,
) -> Option<String> {
    let lowered_name = name.to_ascii_lowercase();
    if let Some(keyword) = SUSPICIOUS_PROCESS_KEYWORDS
        .iter()
        .find(|keyword| lowered_name.contains(**keyword))
    {
        return Some(format!("matched suspicious process keyword '{}'", keyword));
    }
    if let Some(exe) = exe {
        let lowered = exe.to_ascii_lowercase();
        if let Some(prefix) = SUSPICIOUS_EXEC_PREFIXES
            .iter()
            .find(|prefix| lowered.starts_with(**prefix))
        {
            return Some(format!(
                "executable launched from writable path '{}'",
                prefix
            ));
        }
        if lowered.contains("(deleted)") || lowered.contains("memfd:") {
            return Some("executable path looks transient or deleted".to_string());
        }
    }
    if let Some(command) = command {
        let lowered = command.to_ascii_lowercase();
        if (lowered.contains("curl") || lowered.contains("wget"))
            && (lowered.contains("| sh")
                || lowered.contains("| bash")
                || lowered.contains("-o /tmp/"))
        {
            return Some("shell downloader pattern detected".to_string());
        }
        if lowered.contains("bash -c") && lowered.contains("/dev/tcp/") {
            return Some("reverse-shell style command detected".to_string());
        }
    }
    None
}

fn suspicious_service_reason(
    name: &str,
    description: &str,
    state: &str,
    substate: &str,
) -> Option<String> {
    let lowered_name = name.to_ascii_lowercase();
    let lowered_description = description.to_ascii_lowercase();
    if let Some(keyword) = SUSPICIOUS_SERVICE_KEYWORDS
        .iter()
        .find(|keyword| lowered_name.contains(**keyword) || lowered_description.contains(**keyword))
    {
        return Some(format!("matched suspicious service keyword '{}'", keyword));
    }
    if state.eq_ignore_ascii_case("failed") && substate.eq_ignore_ascii_case("failed") {
        return Some("service is in a failed state".to_string());
    }
    None
}

fn suspicious_module_reason(name: &str) -> Option<String> {
    let lowered = name.to_ascii_lowercase();
    SUSPICIOUS_MODULE_KEYWORDS
        .iter()
        .find(|keyword| lowered.contains(**keyword))
        .map(|keyword| format!("matched suspicious module keyword '{}'", keyword))
}

fn slice_membership(kind: &str, name: &str, slice_index: usize, slice_count: usize) -> bool {
    if slice_count <= 1 {
        return true;
    }
    let key = format!("{}:{}", kind, name);
    let digest = blake3::hash(key.as_bytes());
    let bucket = u64::from_le_bytes(digest.as_bytes()[0..8].try_into().unwrap_or([0; 8]));
    (bucket as usize % slice_count) == slice_index
}

fn derive_guard_signal(guard: &TraceyGuardStatusSnapshot) -> f64 {
    if guard.summary.total_devices == 0 {
        return 0.0;
    }
    let worst_gpu_risk = guard
        .gpu_health
        .iter()
        .map(|gpu| gpu.last_risk)
        .fold(0.0_f64, f64::max);
    let quarantine_ratio =
        guard.summary.quarantined_devices as f64 / guard.summary.total_devices as f64;
    let suspect_ratio = guard.summary.suspect_devices as f64 / guard.summary.total_devices as f64;
    let recent_failure_ratio = if guard.recent_executions.is_empty() {
        0.0
    } else {
        guard
            .recent_executions
            .iter()
            .filter(|execution| execution.probe_state != ProbeState::Pass)
            .count() as f64
            / guard.recent_executions.len() as f64
    };
    (worst_gpu_risk * 0.40
        + quarantine_ratio * 0.30
        + suspect_ratio * 0.18
        + recent_failure_ratio * 0.12)
        .clamp(0.0, 1.0)
}

fn derive_loader_signal(loader: Option<&LoaderThreatSnapshot>) -> f64 {
    let Some(loader) = loader else {
        return 0.0;
    };
    let summary = &loader.summary;
    let provider = summary.highest_provider_risk.clamp(0.0, 1.0);
    let artifact = summary.highest_artifact_risk.clamp(0.0, 1.0);
    let block_pressure = ((summary.blocked_provider_count + summary.blocked_artifact_count) as f64
        / 4.0)
        .clamp(0.0, 1.0);
    let reporter_pressure = (summary.remote_reporters as f64 / 4.0).clamp(0.0, 1.0);
    (provider * 0.42 + artifact * 0.36 + block_pressure * 0.14 + reporter_pressure * 0.08)
        .clamp(0.0, 1.0)
}

fn derive_telemetry_signal(telemetry: &ContinuumTelemetrySnapshot) -> f64 {
    let autonomy = telemetry
        .server
        .autonomy_risk
        .unwrap_or_default()
        .clamp(0.0, 1.0);
    let thermal = if telemetry.server.thermal_alerts > 0 {
        0.35
    } else {
        0.0
    };
    let fan = if telemetry.server.fan_alerts > 0 {
        0.22
    } else {
        0.0
    };
    autonomy.max((autonomy * 0.7 + thermal + fan).clamp(0.0, 1.0))
}

fn derive_local_signal(
    suspicious_processes: usize,
    suspicious_services: usize,
    suspicious_modules: usize,
) -> f64 {
    ((suspicious_processes as f64 * 0.18)
        + (suspicious_services as f64 * 0.10)
        + (suspicious_modules as f64 * 0.16))
        .clamp(0.0, 1.0)
}

fn cve_signal(server: &AssessmentServerSummary) -> f64 {
    let severity_score = (server.critical as f64 * 0.22)
        + (server.high as f64 * 0.14)
        + (server.medium as f64 * 0.08)
        + (server.low as f64 * 0.03);
    let count_score = (server.matches as f64 / 8.0).clamp(0.0, 1.0);
    let cvss_score = (server.highest_cvss / 10.0).clamp(0.0, 1.0);
    let kev_boost: f64 = if server.kev > 0 { 0.88 } else { 0.0 };
    kev_boost.max((severity_score + count_score * 0.24 + cvss_score * 0.34).clamp(0.0, 1.0))
}

fn highest_finding_severity(server: &AssessmentServerSummary) -> &'static str {
    if server.critical > 0 || server.kev > 0 {
        "critical"
    } else if server.high > 0 {
        "high"
    } else if server.medium > 0 {
        "medium"
    } else if server.low > 0 {
        "low"
    } else {
        "low"
    }
}

fn highest_finding_severity_from_summary(summary: &CompromiseAssessmentSummary) -> &'static str {
    if summary.critical_matches > 0 || summary.kev_matches > 0 {
        "critical"
    } else if summary.high_matches > 0 {
        "high"
    } else if summary.medium_matches > 0 {
        "medium"
    } else if summary.low_matches > 0 {
        "low"
    } else {
        "low"
    }
}

fn severity_for_summary(server: &AssessmentServerSummary, risk: f64) -> Severity {
    if server.critical > 0 || server.kev > 0 || risk >= 0.90 {
        Severity::Critical
    } else if server.high > 0 || risk >= 0.75 {
        Severity::High
    } else if server.medium > 0 || risk >= 0.45 {
        Severity::Medium
    } else {
        Severity::Low
    }
}

fn action_label(action: Action) -> String {
    match action {
        Action::Monitor => "monitor",
        Action::Alert => "alert",
        Action::Throttle => "throttle",
        Action::Isolate => "isolate",
        Action::Shutdown => "shutdown",
    }
    .to_string()
}

fn join_url(base: &str, path: &str) -> String {
    let base = base.trim_end_matches('/');
    let path = path.trim_start_matches('/');
    if base.starts_with("http://") || base.starts_with("https://") {
        format!("{}/{}", base, path)
    } else {
        format!("http://{}/{}", base, path)
    }
}

fn loader_label(loader: &LoaderThreatSnapshot) -> String {
    format!(
        "prov={} art={} remote={}",
        loader.summary.blocked_provider_count,
        loader.summary.blocked_artifact_count,
        loader.summary.remote_reporters
    )
}

fn loader_detail(loader: &LoaderThreatSnapshot) -> String {
    format!(
        "provider_risk={:.2} artifact_risk={:.2}",
        loader.summary.highest_provider_risk, loader.summary.highest_artifact_risk
    )
}

fn build_local_finding_detail(cache: &InventoryCache) -> String {
    let mut details = Vec::new();
    for record in cache
        .processes
        .iter()
        .filter(|record| record.suspicious_reason.is_some())
        .take(2)
    {
        details.push(format!("proc {}", record.name));
    }
    for record in cache
        .services
        .iter()
        .filter(|record| record.suspicious_reason.is_some())
        .take(1)
    {
        details.push(format!("svc {}", record.name));
    }
    for record in cache
        .modules
        .iter()
        .filter(|record| record.suspicious_reason.is_some())
        .take(1)
    {
        details.push(format!("mod {}", record.name));
    }
    if details.is_empty() {
        "no suspicious local process, service, or module names".to_string()
    } else {
        details.join(" | ")
    }
}

fn format_ratio_pct(value: f64) -> String {
    format!("{:.0}%", value.clamp(0.0, 1.0) * 100.0)
}

fn format_opt_pct(value: Option<f64>) -> String {
    value
        .map(|value| format!("{:.0}%", value))
        .unwrap_or_else(|| "n/a".to_string())
}

fn format_opt_temp(value: Option<f64>) -> String {
    value
        .map(|value| format!("{value:.0}C"))
        .unwrap_or_else(|| "n/a".to_string())
}

fn format_opt_power(value: Option<f64>) -> String {
    value
        .map(|value| format!("{value:.0}W"))
        .unwrap_or_else(|| "n/a".to_string())
}

fn truncate(value: &str, max: usize) -> String {
    if value.len() <= max {
        value.to_string()
    } else if max <= 3 {
        value[..max].to_string()
    } else {
        format!("{}...", &value[..max - 3])
    }
}
