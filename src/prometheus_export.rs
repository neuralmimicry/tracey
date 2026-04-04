//! Proximity-aware Prometheus log export with delegated follower forwarding.

use crate::config::PrometheusLogExportConfig;
use crate::coordination::{Coordination, CoordinatorRole, PrometheusProbe};
use crate::event::{Event, EventKind, Severity, now_ms};
use crate::peer_compat::{self, SchemaField};
use crate::security::Action;
use crate::shutdown::ShutdownListener;
use crate::swarm::Decision;
use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, broadcast};

const BATCH_SIG_HEADER: &str = "x-tracey-prometheus-signature";
const MAX_REMOTE_BATCH_BYTES: usize = 512 * 1024;

#[derive(Clone)]
pub struct PrometheusExportHandle {
    agent_id: String,
    config: PrometheusLogExportConfig,
    role: Arc<RwLock<CoordinatorRole>>,
    state: Arc<RwLock<ExporterState>>,
    client: reqwest::Client,
    signing_key: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ForwardBatch {
    agent_id: String,
    batch_id: String,
    ts_ms: u64,
    records: Vec<PertinentLogRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PertinentLogRecord {
    ts_ms: u64,
    source_agent: String,
    category: String,
    source: String,
    kind: String,
    severity: String,
    action: String,
    detail: String,
    signal: f64,
    risk: f64,
    confidence: f64,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct SeriesKey {
    source_agent: String,
    category: String,
    source: String,
    kind: String,
    severity: String,
    action: String,
    detail: String,
}

#[derive(Clone, Debug, Default)]
struct SeriesValue {
    count: u64,
    last_ts_ms: u64,
    last_signal: f64,
    last_risk: f64,
    last_confidence: f64,
}

#[derive(Default)]
struct ExporterState {
    series: HashMap<SeriesKey, SeriesValue>,
    pending: VecDeque<PertinentLogRecord>,
    seen_batches: HashMap<String, u64>,
    local_probe: Option<PrometheusProbe>,
    dropped_records: u64,
    local_records: u64,
    remote_records: u64,
    forwarded_records: u64,
    last_forward_ms: u64,
    was_leader: bool,
}

impl ExporterState {
    fn reconcile_role(&mut self, role: &CoordinatorRole) {
        if self.was_leader && !role.is_prometheus_exporter {
            self.series.clear();
            self.seen_batches.clear();
        }
        self.was_leader = role.is_prometheus_exporter;
    }

    fn enqueue(&mut self, record: PertinentLogRecord, max_queue: usize) {
        if self.pending.len() >= max_queue {
            self.pending.pop_front();
            self.dropped_records = self.dropped_records.saturating_add(1);
        }
        self.pending.push_back(record);
    }

    fn apply_record(&mut self, record: PertinentLogRecord, remote: bool) {
        let key = SeriesKey {
            source_agent: record.source_agent.clone(),
            category: record.category.clone(),
            source: record.source.clone(),
            kind: record.kind.clone(),
            severity: record.severity.clone(),
            action: record.action.clone(),
            detail: record.detail.clone(),
        };
        let entry = self.series.entry(key).or_default();
        entry.count = entry.count.saturating_add(1);
        entry.last_ts_ms = entry.last_ts_ms.max(record.ts_ms);
        entry.last_signal = record.signal.clamp(0.0, 1.0);
        entry.last_risk = record.risk.clamp(0.0, 1.0);
        entry.last_confidence = record.confidence.clamp(0.0, 1.0);
        if remote {
            self.remote_records = self.remote_records.saturating_add(1);
        } else {
            self.local_records = self.local_records.saturating_add(1);
        }
    }

    fn drain_local_to_series(&mut self) {
        while let Some(record) = self.pending.pop_front() {
            self.apply_record(record, false);
        }
    }

    fn peek_batch(&self, max_batch: usize) -> Vec<PertinentLogRecord> {
        self.pending.iter().take(max_batch).cloned().collect()
    }

    fn complete_forward(&mut self, sent: usize, ts_ms: u64) {
        for _ in 0..sent {
            let _ = self.pending.pop_front();
        }
        self.forwarded_records = self.forwarded_records.saturating_add(sent as u64);
        self.last_forward_ms = ts_ms;
    }

    fn apply_remote_batch(&mut self, batch: ForwardBatch, seen_ttl_ms: u64) {
        let now = now_ms();
        self.seen_batches
            .retain(|_, ts_ms| now.saturating_sub(*ts_ms) <= seen_ttl_ms);
        if self.seen_batches.contains_key(&batch.batch_id) {
            return;
        }
        self.seen_batches.insert(batch.batch_id, batch.ts_ms);
        for record in batch.records {
            self.apply_record(normalize_remote_record(&batch.agent_id, record), true);
        }
    }

    fn prune_series(&mut self, series_ttl_ms: u64) {
        let now = now_ms();
        self.series
            .retain(|_, value| now.saturating_sub(value.last_ts_ms) <= series_ttl_ms);
    }
}

impl PertinentLogRecord {
    fn from_event(
        agent_id: &str,
        config: &PrometheusLogExportConfig,
        event: &Event,
    ) -> Option<Self> {
        let signal = event.signal.clamp(0.0, 1.0);
        let metric = event.attributes.get("metric").map(String::as_str);
        let high_severity = matches!(event.severity, Severity::High | Severity::Critical);

        let (category, detail, permitted) = match event.source.as_str() {
            "tracey_guard" => (
                "fault",
                event
                    .attributes
                    .get("probe_type")
                    .or_else(|| event.attributes.get("state"))
                    .cloned()
                    .unwrap_or_else(|| "fault".to_string()),
                high_severity || signal >= config.min_signal,
            ),
            "tracey_ban" => (
                "ban",
                event
                    .attributes
                    .get("jail")
                    .cloned()
                    .unwrap_or_else(|| "ban".to_string()),
                !matches!(event.severity, Severity::Low) || signal >= config.min_signal,
            ),
            "refiner" => (
                "security",
                event
                    .attributes
                    .get("indicator")
                    .or_else(|| event.attributes.get("metric"))
                    .cloned()
                    .unwrap_or_else(|| "security".to_string()),
                !matches!(event.severity, Severity::Low) || signal >= config.min_signal,
            ),
            "embedded" => (
                "anomaly",
                metric
                    .filter(|metric| selected_metric(metric))
                    .unwrap_or("embedded")
                    .to_string(),
                high_severity && metric.is_some_and(selected_metric),
            ),
            _ => (
                "anomaly",
                metric.unwrap_or("event").to_string(),
                high_severity && signal >= config.min_signal,
            ),
        };

        if !permitted {
            return None;
        }

        let risk = event
            .attributes
            .get("risk")
            .or_else(|| event.attributes.get("fuzzy_risk"))
            .and_then(|value| value.parse::<f64>().ok())
            .unwrap_or(signal)
            .clamp(0.0, 1.0);
        let confidence = event
            .attributes
            .get("confidence")
            .or_else(|| event.attributes.get("fuzzy_confidence"))
            .and_then(|value| value.parse::<f64>().ok())
            .unwrap_or(signal)
            .clamp(0.0, 1.0);

        Some(Self {
            ts_ms: event.ts_ms,
            source_agent: agent_id.to_string(),
            category: category.to_string(),
            source: event.source.clone(),
            kind: event_kind_label(event.kind).to_string(),
            severity: severity_label(event.severity).to_string(),
            action: event
                .attributes
                .get("action")
                .cloned()
                .unwrap_or_else(|| "none".to_string()),
            detail,
            signal,
            risk,
            confidence,
        })
    }

    fn from_decision(
        agent_id: &str,
        config: &PrometheusLogExportConfig,
        decision: &Decision,
    ) -> Option<Self> {
        if decision.action == Action::Monitor && decision.mean_risk < config.min_decision_risk {
            return None;
        }

        Some(Self {
            ts_ms: decision.ts_ms,
            source_agent: agent_id.to_string(),
            category: "decision".to_string(),
            source: "swarm".to_string(),
            kind: event_kind_label(decision.kind).to_string(),
            severity: risk_bucket(decision.mean_risk).to_string(),
            action: action_label(decision.action).to_string(),
            detail: if decision.telemetry.mean_metric_context >= 0.25 {
                "metric_enriched".to_string()
            } else {
                "decision".to_string()
            },
            signal: decision.mean_risk.clamp(0.0, 1.0),
            risk: decision.mean_risk.clamp(0.0, 1.0),
            confidence: decision.mean_confidence.clamp(0.0, 1.0),
        })
    }
}

pub fn spawn_prometheus_exporter(
    config: PrometheusLogExportConfig,
    agent_id: String,
    mut events_rx: broadcast::Receiver<Event>,
    mut decisions_rx: broadcast::Receiver<Decision>,
    coordination: Coordination,
    mut shutdown: ShutdownListener,
    shared_key: &str,
) -> Option<PrometheusExportHandle> {
    if !config.enabled {
        return None;
    }

    let role = coordination.role_handle();
    let state = Arc::new(RwLock::new(ExporterState::default()));
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(config.probe_timeout_ms))
        .build()
        .unwrap_or_else(|err| {
            tracing::warn!(error = %err, "prometheus export client init failed; using default client");
            reqwest::Client::new()
        });
    let handle = PrometheusExportHandle {
        agent_id: agent_id.clone(),
        config: config.clone(),
        role,
        state: state.clone(),
        client: client.clone(),
        signing_key: derive_key(shared_key),
    };
    let task_handle = handle.clone();
    tokio::spawn(async move {
        let mut probe_tick = tokio::time::interval(Duration::from_millis(config.probe_interval_ms));
        let mut forward_tick =
            tokio::time::interval(Duration::from_millis(config.forward_interval_ms));

        loop {
            tokio::select! {
                _ = shutdown.wait() => {
                    tracing::info!(agent_id = %agent_id, "prometheus export shutting down");
                    break;
                }
                _ = probe_tick.tick() => {
                    let probe = probe_prometheus(&client, &config).await;
                    coordination.update_prometheus_probe(Some(probe.clone())).await;
                    let mut state = state.write().await;
                    state.local_probe = Some(probe);
                }
                _ = forward_tick.tick() => {
                    task_handle.flush_pending().await;
                }
                message = events_rx.recv() => {
                    match message {
                        Ok(event) => {
                            if let Some(record) = PertinentLogRecord::from_event(&agent_id, &config, &event) {
                                task_handle.process_local_record(record).await;
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            tracing::warn!(agent_id = %agent_id, skipped, "prometheus export lagged on event stream");
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
                message = decisions_rx.recv() => {
                    match message {
                        Ok(decision) => {
                            if let Some(record) = PertinentLogRecord::from_decision(&agent_id, &config, &decision) {
                                task_handle.process_local_record(record).await;
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            tracing::warn!(agent_id = %agent_id, skipped, "prometheus export lagged on decision stream");
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
            }
        }
    });

    Some(handle)
}

impl PrometheusExportHandle {
    pub async fn render_metrics(&self) -> String {
        let role = self.role.read().await.clone();
        let mut state = self.state.write().await;
        state.reconcile_role(&role);
        state.prune_series(self.config.series_ttl_ms);

        let mut out = String::new();
        out.push_str("# HELP tracey_prometheus_exporter_active 1 when this Tracey instance is the elected Prometheus log exporter.\n");
        out.push_str("# TYPE tracey_prometheus_exporter_active gauge\n");
        out.push_str(&format!(
            "tracey_prometheus_exporter_active{{agent_id=\"{}\"}} {}\n",
            escape_label(&self.agent_id),
            if role.is_prometheus_exporter { 1 } else { 0 }
        ));

        out.push_str("# HELP tracey_prometheus_exporter_leader_info Current elected Prometheus log exporter identity and probe outcome.\n");
        out.push_str("# TYPE tracey_prometheus_exporter_leader_info gauge\n");
        if let Some(leader_agent) = role.prometheus_exporter_agent_id.as_deref() {
            out.push_str(&format!(
                "tracey_prometheus_exporter_leader_info{{agent_id=\"{}\",addr=\"{}\"}} 1\n",
                escape_label(leader_agent),
                escape_label(role.prometheus_exporter_addr.as_deref().unwrap_or("")),
            ));
        }

        if let Some(probe) = state.local_probe.clone().or(role.prometheus_probe.clone()) {
            out.push_str("# HELP tracey_prometheus_exporter_target_ready Latest local readiness probe result for the Prometheus tenant.\n");
            out.push_str("# TYPE tracey_prometheus_exporter_target_ready gauge\n");
            out.push_str(&format!(
                "tracey_prometheus_exporter_target_ready{{agent_id=\"{}\"}} {}\n",
                escape_label(&self.agent_id),
                if probe.ready { 1 } else { 0 }
            ));
            out.push_str("# HELP tracey_prometheus_exporter_target_latency_ms Latest local measured latency to the Prometheus tenant.\n");
            out.push_str("# TYPE tracey_prometheus_exporter_target_latency_ms gauge\n");
            out.push_str(&format!(
                "tracey_prometheus_exporter_target_latency_ms{{agent_id=\"{}\"}} {}\n",
                escape_label(&self.agent_id),
                probe.latency_ms
            ));
            out.push_str("# HELP tracey_prometheus_exporter_target_bandwidth_mbps Approximate measured bandwidth to the Prometheus tenant.\n");
            out.push_str("# TYPE tracey_prometheus_exporter_target_bandwidth_mbps gauge\n");
            out.push_str(&format!(
                "tracey_prometheus_exporter_target_bandwidth_mbps{{agent_id=\"{}\"}} {:.6}\n",
                escape_label(&self.agent_id),
                probe.bandwidth_mbps.max(0.0)
            ));
        }

        out.push_str("# HELP tracey_prometheus_exporter_pending_records Pending pertinent records waiting for forwarding.\n");
        out.push_str("# TYPE tracey_prometheus_exporter_pending_records gauge\n");
        out.push_str(&format!(
            "tracey_prometheus_exporter_pending_records{{agent_id=\"{}\"}} {}\n",
            escape_label(&self.agent_id),
            state.pending.len()
        ));
        out.push_str("# HELP tracey_prometheus_exporter_forwarded_records_total Total pertinent records forwarded to elected exporter leaders.\n");
        out.push_str("# TYPE tracey_prometheus_exporter_forwarded_records_total counter\n");
        out.push_str(&format!(
            "tracey_prometheus_exporter_forwarded_records_total{{agent_id=\"{}\"}} {}\n",
            escape_label(&self.agent_id),
            state.forwarded_records
        ));
        out.push_str("# HELP tracey_prometheus_exporter_dropped_records_total Total pertinent records dropped because the local queue was full.\n");
        out.push_str("# TYPE tracey_prometheus_exporter_dropped_records_total counter\n");
        out.push_str(&format!(
            "tracey_prometheus_exporter_dropped_records_total{{agent_id=\"{}\"}} {}\n",
            escape_label(&self.agent_id),
            state.dropped_records
        ));

        if role.is_prometheus_exporter {
            let mut series: Vec<_> = state.series.iter().collect();
            series.sort_by(|a, b| {
                a.0.source_agent
                    .cmp(&b.0.source_agent)
                    .then_with(|| a.0.category.cmp(&b.0.category))
                    .then_with(|| a.0.source.cmp(&b.0.source))
                    .then_with(|| a.0.kind.cmp(&b.0.kind))
                    .then_with(|| a.0.severity.cmp(&b.0.severity))
                    .then_with(|| a.0.action.cmp(&b.0.action))
                    .then_with(|| a.0.detail.cmp(&b.0.detail))
            });
            out.push_str("# HELP tracey_pertinent_logs_total Total pertinent logs accepted by the elected Tracey Prometheus exporter.\n");
            out.push_str("# TYPE tracey_pertinent_logs_total counter\n");
            out.push_str("# HELP tracey_pertinent_log_last_signal Last normalized signal associated with a pertinent log series.\n");
            out.push_str("# TYPE tracey_pertinent_log_last_signal gauge\n");
            out.push_str("# HELP tracey_pertinent_log_last_risk Last risk associated with a pertinent log series.\n");
            out.push_str("# TYPE tracey_pertinent_log_last_risk gauge\n");
            out.push_str("# HELP tracey_pertinent_log_last_confidence Last confidence associated with a pertinent log series.\n");
            out.push_str("# TYPE tracey_pertinent_log_last_confidence gauge\n");
            out.push_str("# HELP tracey_pertinent_log_last_ts_ms Last event timestamp associated with a pertinent log series.\n");
            out.push_str("# TYPE tracey_pertinent_log_last_ts_ms gauge\n");
            for (key, value) in series {
                let labels = format!(
                    "source_agent=\"{}\",category=\"{}\",source=\"{}\",kind=\"{}\",severity=\"{}\",action=\"{}\",detail=\"{}\"",
                    escape_label(&key.source_agent),
                    escape_label(&key.category),
                    escape_label(&key.source),
                    escape_label(&key.kind),
                    escape_label(&key.severity),
                    escape_label(&key.action),
                    escape_label(&key.detail),
                );
                out.push_str(&format!(
                    "tracey_pertinent_logs_total{{{labels}}} {}\n",
                    value.count
                ));
                out.push_str(&format!(
                    "tracey_pertinent_log_last_signal{{{labels}}} {:.6}\n",
                    value.last_signal
                ));
                out.push_str(&format!(
                    "tracey_pertinent_log_last_risk{{{labels}}} {:.6}\n",
                    value.last_risk
                ));
                out.push_str(&format!(
                    "tracey_pertinent_log_last_confidence{{{labels}}} {:.6}\n",
                    value.last_confidence
                ));
                out.push_str(&format!(
                    "tracey_pertinent_log_last_ts_ms{{{labels}}} {}\n",
                    value.last_ts_ms
                ));
            }
        }

        out
    }

    pub async fn ingest_http(&self, headers: &HeaderMap, body: &Bytes) -> Result<(), StatusCode> {
        if body.len() > MAX_REMOTE_BATCH_BYTES {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
        let batch = match serde_json::from_slice::<ForwardBatch>(body) {
            Ok(batch) => batch,
            Err(_) => match parse_forward_batch_lossy(body) {
                Ok((batch, affinity)) => {
                    tracing::info!(agent_id = %self.agent_id, affinity, "prometheus forward batch recovered with fuzzy parser");
                    batch
                }
                Err(_) => return Err(StatusCode::BAD_REQUEST),
            },
        };
        if batch.agent_id.trim().is_empty() {
            return Err(StatusCode::BAD_REQUEST);
        }
        if batch.records.len() > self.config.max_batch {
            return Err(StatusCode::BAD_REQUEST);
        }
        let now = now_ms();
        if now.saturating_sub(batch.ts_ms) > self.config.batch_ttl_ms {
            return Err(StatusCode::REQUEST_TIMEOUT);
        }
        let expected = sign_batch(&batch.agent_id, batch.ts_ms, body, &self.signing_key);
        let Some(provided) = headers
            .get(BATCH_SIG_HEADER)
            .and_then(|value| value.to_str().ok())
        else {
            return Err(StatusCode::UNAUTHORIZED);
        };
        if !normalize_eq(provided, &expected) {
            return Err(StatusCode::UNAUTHORIZED);
        }

        let role = self.role.read().await.clone();
        if !role.is_prometheus_exporter {
            return Err(StatusCode::CONFLICT);
        }

        let mut state = self.state.write().await;
        state.reconcile_role(&role);
        state.prune_series(self.config.series_ttl_ms);
        state.apply_remote_batch(batch, self.config.batch_ttl_ms.saturating_mul(4));
        Ok(())
    }

    async fn process_local_record(&self, record: PertinentLogRecord) {
        let role = self.role.read().await.clone();
        let mut state = self.state.write().await;
        state.reconcile_role(&role);
        state.prune_series(self.config.series_ttl_ms);
        if role.is_prometheus_exporter {
            state.apply_record(record, false);
        } else {
            state.enqueue(record, self.config.max_queue);
        }
    }

    async fn flush_pending(&self) {
        let role = self.role.read().await.clone();
        let records = {
            let mut state = self.state.write().await;
            state.reconcile_role(&role);
            state.prune_series(self.config.series_ttl_ms);
            if role.is_prometheus_exporter {
                state.drain_local_to_series();
                return;
            }
            state.peek_batch(self.config.max_batch)
        };

        if records.is_empty() {
            return;
        }

        let Some(exporter_addr) = role.prometheus_exporter_addr.as_deref() else {
            return;
        };
        if role.prometheus_exporter_agent_id.as_deref() == Some(self.agent_id.as_str()) {
            return;
        }

        let batch = ForwardBatch {
            agent_id: self.agent_id.clone(),
            batch_id: derive_batch_id(&self.agent_id, &records),
            ts_ms: now_ms(),
            records,
        };
        let body = match serde_json::to_vec(&batch) {
            Ok(body) => body,
            Err(err) => {
                tracing::warn!(agent_id = %self.agent_id, error = %err, "prometheus export batch serialization failed");
                return;
            }
        };
        let signature = sign_batch(&batch.agent_id, batch.ts_ms, &body, &self.signing_key);
        let url = normalize_url(exporter_addr, "/prometheus/ingest");

        match self
            .client
            .post(url)
            .header(BATCH_SIG_HEADER, signature)
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => {
                let mut state = self.state.write().await;
                state.complete_forward(batch.records.len(), batch.ts_ms);
            }
            Ok(response) => {
                tracing::debug!(
                    agent_id = %self.agent_id,
                    status = %response.status(),
                    leader = role.prometheus_exporter_agent_id.as_deref().unwrap_or("unknown"),
                    "prometheus export forward was rejected"
                );
            }
            Err(err) => {
                tracing::debug!(
                    agent_id = %self.agent_id,
                    leader = role.prometheus_exporter_agent_id.as_deref().unwrap_or("unknown"),
                    error = %err,
                    "prometheus export forward failed"
                );
            }
        }
    }
}

async fn probe_prometheus(
    client: &reqwest::Client,
    config: &PrometheusLogExportConfig,
) -> PrometheusProbe {
    let url = normalize_url(&config.server_url, &config.probe_path);
    let started = Instant::now();
    let sampled_at_ms = now_ms();
    match client.get(url).send().await {
        Ok(response) => {
            let latency_ms = started.elapsed().as_millis().max(1) as u64;
            let ready = response.status().is_success();
            let body_len = response
                .bytes()
                .await
                .map(|body| body.len().max(32))
                .unwrap_or(32);
            let secs = started.elapsed().as_secs_f64().max(0.001);
            let bandwidth_mbps = (body_len as f64 * 8.0) / secs / 1_000_000.0;
            PrometheusProbe {
                ready,
                latency_ms,
                bandwidth_mbps,
                sampled_at_ms,
            }
        }
        Err(_) => PrometheusProbe {
            ready: false,
            latency_ms: config.probe_timeout_ms,
            bandwidth_mbps: 0.0,
            sampled_at_ms,
        },
    }
}

fn normalize_remote_record(agent_id: &str, mut record: PertinentLogRecord) -> PertinentLogRecord {
    record.source_agent = agent_id.to_string();
    record.signal = record.signal.clamp(0.0, 1.0);
    record.risk = record.risk.clamp(0.0, 1.0);
    record.confidence = record.confidence.clamp(0.0, 1.0);
    record
}

fn parse_forward_batch_lossy(payload: &[u8]) -> Result<(ForwardBatch, f64), String> {
    let root = peer_compat::parse_bytes(payload).map_err(|err| err.to_string())?;
    let fields = [
        SchemaField {
            aliases: &[
                "agent_id",
                "agentId",
                "source_agent",
                "sourceAgent",
                "node_id",
            ],
            required: true,
            weight: 2.0,
        },
        SchemaField {
            aliases: &["ts_ms", "timestamp_ms", "timestamp", "batch_ts_ms"],
            required: true,
            weight: 1.5,
        },
        SchemaField {
            aliases: &["records", "entries", "items", "events", "batch"],
            required: true,
            weight: 2.0,
        },
        SchemaField {
            aliases: &["batch_id", "batchId", "id"],
            required: false,
            weight: 0.8,
        },
    ];
    let matched = peer_compat::best_object(&root, &fields, 2.2, 4)
        .ok_or_else(|| "payload did not resemble a Prometheus forward batch".to_string())?;
    let map = matched.map;
    let agent_id = peer_compat::value_for(
        map,
        &[
            "agent_id",
            "agentId",
            "source_agent",
            "sourceAgent",
            "node_id",
        ],
    )
    .and_then(peer_compat::coerce_string)
    .ok_or_else(|| "missing agent identifier".to_string())?;
    let ts_ms = peer_compat::value_for(map, &["ts_ms", "timestamp_ms", "timestamp", "batch_ts_ms"])
        .and_then(peer_compat::coerce_u64)
        .ok_or_else(|| "missing batch timestamp".to_string())?;
    let records = peer_compat::value_for(map, &["records", "entries", "items", "events", "batch"])
        .and_then(peer_compat::value_as_array)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|value| parse_pertinent_record_lossy(&value, &agent_id, ts_ms))
        .collect::<Vec<_>>();
    let batch_id = peer_compat::value_for(map, &["batch_id", "batchId", "id"])
        .and_then(peer_compat::coerce_string)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| derive_batch_id(&agent_id, &records));

    Ok((
        ForwardBatch {
            agent_id,
            batch_id,
            ts_ms,
            records,
        },
        matched.score,
    ))
}

fn parse_pertinent_record_lossy(
    value: &Value,
    agent_id: &str,
    batch_ts_ms: u64,
) -> Option<PertinentLogRecord> {
    let object = peer_compat::value_as_object(value)?;
    let source = peer_compat::object_for(&object, &["record", "event", "decision", "payload"])
        .unwrap_or_else(|| object.clone());

    let risk = peer_compat::value_for(&source, &["risk", "mean_risk", "score"])
        .and_then(peer_compat::coerce_unit_interval)
        .or_else(|| {
            peer_compat::value_for(&source, &["signal", "value", "normalized_signal"])
                .and_then(peer_compat::coerce_unit_interval)
        })
        .unwrap_or(0.0);
    let signal = peer_compat::value_for(&source, &["signal", "value", "normalized_signal"])
        .and_then(peer_compat::coerce_unit_interval)
        .unwrap_or(risk);
    let confidence =
        peer_compat::value_for(&source, &["confidence", "mean_confidence", "certainty"])
            .and_then(peer_compat::coerce_unit_interval)
            .unwrap_or(0.5);

    let source_name =
        peer_compat::value_for(&source, &["source", "origin", "producer", "component"])
            .and_then(peer_compat::coerce_string)
            .unwrap_or_else(|| "remote".to_string());
    let category = peer_compat::value_for(&source, &["category", "record_type", "recordType"])
        .and_then(peer_compat::coerce_string)
        .unwrap_or_else(|| infer_record_category(&source_name, risk).to_string());
    let detail = peer_compat::value_for(
        &source,
        &[
            "detail",
            "message",
            "metric",
            "name",
            "reason",
            "probe_type",
        ],
    )
    .and_then(peer_compat::coerce_string)
    .unwrap_or_else(|| category.clone());

    Some(PertinentLogRecord {
        ts_ms: peer_compat::value_for(
            &source,
            &[
                "ts_ms",
                "timestamp_ms",
                "timestamp",
                "event_ts_ms",
                "sampled_at_ms",
            ],
        )
        .and_then(peer_compat::coerce_u64)
        .unwrap_or(batch_ts_ms),
        source_agent: peer_compat::value_for(
            &source,
            &["source_agent", "sourceAgent", "agent_id", "agentId"],
        )
        .and_then(peer_compat::coerce_string)
        .unwrap_or_else(|| agent_id.to_string()),
        category,
        source: source_name.clone(),
        kind: peer_compat::value_for(&source, &["kind", "event_kind", "eventKind", "type"])
            .and_then(peer_compat::coerce_string)
            .unwrap_or_else(|| "observability".to_string()),
        severity: peer_compat::value_for(&source, &["severity", "level", "risk_bucket"])
            .and_then(peer_compat::coerce_string)
            .unwrap_or_else(|| infer_severity(risk).to_string()),
        action: peer_compat::value_for(&source, &["action", "decision", "response"])
            .and_then(peer_compat::coerce_string)
            .unwrap_or_else(|| infer_action(risk).to_string()),
        detail,
        signal,
        risk,
        confidence,
    })
}

fn infer_record_category(source: &str, risk: f64) -> &'static str {
    match source {
        "tracey_guard" => "fault",
        "tracey_ban" => "ban",
        "refiner" => "security",
        "swarm" if risk >= 0.55 => "decision",
        _ => "anomaly",
    }
}

fn infer_action(risk: f64) -> &'static str {
    if risk >= 0.8 { "alert" } else { "monitor" }
}

fn infer_severity(risk: f64) -> &'static str {
    if risk >= 0.95 {
        "critical"
    } else if risk >= 0.8 {
        "high"
    } else if risk >= 0.55 {
        "medium"
    } else {
        "low"
    }
}

fn derive_key(shared: &str) -> [u8; 32] {
    let hash = blake3::hash(shared.as_bytes());
    *hash.as_bytes()
}

fn derive_batch_id(agent_id: &str, records: &[PertinentLogRecord]) -> String {
    let payload = serde_json::to_vec(records).unwrap_or_default();
    let digest = blake3::hash(&payload);
    format!("{}-{}", agent_id, digest.to_hex())
}

fn sign_batch(agent_id: &str, ts_ms: u64, body: &[u8], key: &[u8; 32]) -> String {
    let body_hash = blake3::hash(body);
    let payload = format!("{}|{}|{}", agent_id, ts_ms, body_hash.to_hex());
    let hash = blake3::keyed_hash(key, payload.as_bytes());
    hash.to_hex().to_string()
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

fn normalize_url(addr: &str, path: &str) -> String {
    let addr = addr.trim_end_matches('/');
    let path = path.trim_start_matches('/');
    if addr.starts_with("http://") || addr.starts_with("https://") {
        format!("{}/{}", addr, path)
    } else {
        format!("http://{}/{}", addr, path)
    }
}

fn event_kind_label(kind: EventKind) -> &'static str {
    match kind {
        EventKind::SystemMetric => "system_metric",
        EventKind::NetworkFlow => "network_flow",
        EventKind::UserAction => "user_action",
        EventKind::AutomationAction => "automation_action",
        EventKind::Observability => "observability",
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

fn action_label(action: Action) -> &'static str {
    match action {
        Action::Monitor => "monitor",
        Action::Alert => "alert",
        Action::Throttle => "throttle",
        Action::Isolate => "isolate",
        Action::Shutdown => "shutdown",
    }
}

fn risk_bucket(risk: f64) -> &'static str {
    if risk >= 0.95 {
        "critical"
    } else if risk >= 0.80 {
        "high"
    } else if risk >= 0.55 {
        "medium"
    } else {
        "low"
    }
}

fn selected_metric(metric: &str) -> bool {
    matches!(
        metric,
        "gpu_power_w"
            | "gpu_temp_c"
            | "gpu_mem_used_bytes"
            | "gpu_clock_graphics_mhz"
            | "gpu_clock_memory_mhz"
            | "gpu_fan_speed_percent"
            | "gpu_encoder_util_percent"
            | "gpu_decoder_util_percent"
            | "mem_app_used"
            | "mem_bufcache"
            | "swap_used"
    )
}

fn escape_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordination::CoordinatorRole;

    fn cfg() -> PrometheusLogExportConfig {
        PrometheusLogExportConfig::default()
    }

    fn role(is_prometheus_exporter: bool) -> CoordinatorRole {
        CoordinatorRole {
            agent_id: "agent-a".to_string(),
            score: 1,
            is_coordinator: false,
            leader_rank: 0,
            leader_count: 1,
            epoch: 1,
            last_update_ms: now_ms(),
            proxy_agent_id: None,
            proxy_latency_ms: None,
            proxy_addr: None,
            is_prometheus_exporter,
            prometheus_exporter_agent_id: Some(if is_prometheus_exporter {
                "agent-a".to_string()
            } else {
                "agent-b".to_string()
            }),
            prometheus_exporter_addr: Some("127.0.0.1:48000".to_string()),
            prometheus_exporter_latency_ms: Some(3),
            prometheus_exporter_bandwidth_mbps: Some(42.0),
            prometheus_probe: Some(PrometheusProbe {
                ready: true,
                latency_ms: 3,
                bandwidth_mbps: 42.0,
                sampled_at_ms: now_ms(),
            }),
        }
    }

    #[test]
    fn alerting_decision_becomes_pertinent_record() {
        let decision = Decision {
            event_id: 1,
            ts_ms: now_ms(),
            kind: EventKind::Observability,
            action: Action::Alert,
            mean_risk: 0.82,
            mean_confidence: 0.91,
            telemetry: Default::default(),
            quorum: 3,
            agents: 4,
            reason: "test".to_string(),
        };
        let record = PertinentLogRecord::from_decision("agent-a", &cfg(), &decision)
            .expect("alert decision should be exported");
        assert_eq!(record.category, "decision");
        assert_eq!(record.action, "alert");
        assert_eq!(record.severity, "high");
    }

    #[test]
    fn embedded_metric_requires_selected_high_severity_signal() {
        let event = Event::new(1, "embedded", EventKind::SystemMetric, 0.92, Severity::High)
            .with_attr("metric", "gpu_encoder_util_percent");
        let record = PertinentLogRecord::from_event("agent-a", &cfg(), &event)
            .expect("selected high-severity embedded metric should be exported");
        assert_eq!(record.detail, "gpu_encoder_util_percent");

        let low = Event::new(2, "embedded", EventKind::SystemMetric, 0.92, Severity::Low)
            .with_attr("metric", "gpu_encoder_util_percent");
        assert!(PertinentLogRecord::from_event("agent-a", &cfg(), &low).is_none());
    }

    #[tokio::test]
    async fn metrics_hide_series_on_followers() {
        let state = Arc::new(RwLock::new(ExporterState::default()));
        state.write().await.apply_record(
            PertinentLogRecord {
                ts_ms: now_ms(),
                source_agent: "agent-a".to_string(),
                category: "decision".to_string(),
                source: "swarm".to_string(),
                kind: "observability".to_string(),
                severity: "high".to_string(),
                action: "alert".to_string(),
                detail: "decision".to_string(),
                signal: 0.8,
                risk: 0.8,
                confidence: 0.9,
            },
            false,
        );
        let handle = PrometheusExportHandle {
            agent_id: "agent-a".to_string(),
            config: cfg(),
            role: Arc::new(RwLock::new(role(false))),
            state,
            client: reqwest::Client::new(),
            signing_key: derive_key("shared"),
        };
        let rendered = handle.render_metrics().await;
        assert!(!rendered.contains("tracey_pertinent_logs_total{"));
    }

    #[tokio::test]
    async fn ingest_http_accepts_fuzzy_forward_batch() {
        let ts_ms = now_ms();
        let handle = PrometheusExportHandle {
            agent_id: "agent-a".to_string(),
            config: cfg(),
            role: Arc::new(RwLock::new(role(true))),
            state: Arc::new(RwLock::new(ExporterState::default())),
            client: reqwest::Client::new(),
            signing_key: derive_key("shared"),
        };
        let body = serde_json::json!({
            "wrapper": {
                "agentId": "agent-b",
                "timestamp_ms": ts_ms.to_string(),
                "items": [
                    {
                        "decision": {
                            "source": "swarm",
                            "mean_risk": "84%",
                            "mean_confidence": "91%",
                            "action": "alert",
                            "reason": "thermal anomaly"
                        }
                    },
                    {
                        "event": {
                            "source": "tracey_guard",
                            "probeType": "memory",
                            "score": "0.97",
                            "certainty": "88%",
                            "level": "critical",
                            "timestamp_ms": (ts_ms + 1).to_string()
                        }
                    }
                ]
            }
        })
        .to_string();
        let signature = sign_batch("agent-b", ts_ms, body.as_bytes(), &derive_key("shared"));
        let mut headers = HeaderMap::new();
        headers.insert(BATCH_SIG_HEADER, signature.parse().unwrap());

        handle
            .ingest_http(&headers, &Bytes::from(body))
            .await
            .expect("fuzzy batch should be accepted");

        let rendered = handle.render_metrics().await;
        assert!(rendered.contains("source_agent=\"agent-b\",category=\"decision\""));
        assert!(rendered.contains("source_agent=\"agent-b\",category=\"fault\""));
    }

    #[test]
    fn batch_signature_is_stable() {
        let batch = ForwardBatch {
            agent_id: "agent-a".to_string(),
            batch_id: "batch-1".to_string(),
            ts_ms: 42,
            records: Vec::new(),
        };
        let body = serde_json::to_vec(&batch).expect("batch body should serialize");
        let a = sign_batch("agent-a", 42, &body, &derive_key("shared"));
        let b = sign_batch("agent-a", 42, &body, &derive_key("shared"));
        assert_eq!(a, b);
    }
}
