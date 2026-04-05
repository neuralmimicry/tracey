//! HTTP status/control surface for local and proxied cluster state.
//!
//! Includes posture-aware snapshots, TraceyBan summaries, and TraceyGuard
//! status/control endpoints with optional auth gating.

use crate::auth::AuthGate;
use crate::coordination::{Coordination, CoordinatorRole};
use crate::event::now_ms;
use crate::governance::GovernanceState;
use crate::location::AgentLocationSnapshot;
use crate::peer_compat::{self, SchemaField};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

const STATUS_BODY_PREVIEW_BYTES: usize = 256;
const STATUS_MAX_AGENT_ID_LEN: usize = 128;

#[derive(Debug)]
enum ProxySnapshotParseError {
    Syntax(serde_json::Error),
    Semantics(String),
}

#[derive(Clone)]
pub struct StatusService {
    pub agent_id: String,
    pub agent_version: String,
    pub coordination: Coordination,
    pub coordination_role: Arc<tokio::sync::RwLock<CoordinatorRole>>,
    pub governance_state: Arc<tokio::sync::RwLock<GovernanceState>>,
    pub client: reqwest::Client,
    pub status_addr: Option<String>,
    pub auth: AuthGate,
    pub ban_intel: Option<crate::tracey_ban::BanIntelHub>,
    pub tracey_guard: Option<crate::tracey_guard::TraceyGuardRuntimeHandle>,
    pub slurm: crate::slurm::SlurmRuntimeHandle,
    pub prometheus_export: Option<crate::prometheus_export::PrometheusExportHandle>,
    pub continuum_autoscaler: Option<crate::autoscaler::ContinuumAutoscalerHandle>,
    pub continuum_telemetry: Option<crate::continuum_telemetry::ContinuumTelemetryHandle>,
    pub loader_threats: Option<crate::loader_threat::LoaderThreatStatusHandle>,
}

#[derive(Serialize, Deserialize)]
struct StatusSnapshot {
    ts_ms: u64,
    #[serde(default)]
    status: Option<String>,
    agent_id: String,
    #[serde(default)]
    agent_version: Option<String>,
    #[serde(default)]
    status_addr: Option<String>,
    is_coordinator: bool,
    leader_rank: usize,
    leader_count: usize,
    proxy_agent_id: Option<String>,
    proxy_addr: Option<String>,
    proxy_latency_ms: Option<u64>,
    #[serde(default)]
    is_prometheus_exporter: bool,
    #[serde(default)]
    prometheus_exporter_agent_id: Option<String>,
    #[serde(default)]
    prometheus_exporter_addr: Option<String>,
    #[serde(default)]
    prometheus_exporter_latency_ms: Option<u64>,
    #[serde(default)]
    prometheus_exporter_bandwidth_mbps: Option<f64>,
    #[serde(default)]
    local_prometheus_probe_ready: Option<bool>,
    #[serde(default)]
    local_prometheus_latency_ms: Option<u64>,
    #[serde(default)]
    local_prometheus_bandwidth_mbps: Option<f64>,
    posture: String,
    decision_threshold: f64,
    active_response: bool,
    shutdown_enabled: bool,
    update_enabled: bool,
    telemetry_enabled: bool,
    discovery_enabled: bool,
    tracey_ban_local_bans: usize,
    tracey_ban_remote_bans: usize,
    tracey_ban_remote_agents: usize,
    tracey_ban_local_entries: Vec<String>,
    tracey_ban_remote_entries: Vec<String>,
    #[serde(default)]
    tracey_guard: Option<crate::tracey_guard::TraceyGuardStatusSnapshot>,
    #[serde(default)]
    slurm: Option<crate::slurm::SlurmSnapshot>,
    #[serde(default)]
    continuum_autoscaler: Option<crate::autoscaler::ContinuumAutoscalerSnapshot>,
    #[serde(default)]
    continuum_telemetry: Option<crate::continuum_telemetry::ContinuumTelemetrySnapshot>,
    #[serde(default)]
    loader_threats: Option<crate::loader_threat::LoaderThreatSnapshot>,
    #[serde(default)]
    location: AgentLocationSnapshot,
    #[serde(default)]
    peer_locations: Vec<AgentLocationSnapshot>,
}

pub async fn spawn_status(
    service: StatusService,
    listen_addr: SocketAddr,
    mut shutdown: crate::shutdown::ShutdownListener,
) {
    let app = Router::new()
        .route("/status", get(status_handler))
        .route("/health", get(status_handler))
        .route("/ready", get(status_handler))
        .route("/tracey_guard", get(tracey_guard_handler))
        .route("/tracey_guard/deepdive", get(tracey_guard_handler))
        .route("/control/tracey_guard", post(tracey_guard_control_handler))
        .route("/metrics", get(metrics_handler))
        .route("/prometheus/ingest", post(prometheus_ingest_handler))
        .with_state(service);
    let listener = match tokio::net::TcpListener::bind(listen_addr).await {
        Ok(listener) => listener,
        Err(err) => {
            tracing::warn!(addr = %listen_addr, error = %err, "status server bind failed");
            return;
        }
    };
    if let Err(err) = axum::serve(listener, app)
        .with_graceful_shutdown(async move { shutdown.wait().await })
        .await
    {
        tracing::warn!("status server failed: {}", err);
    }
}

async fn status_handler(
    State(service): State<StatusService>,
    headers: HeaderMap,
) -> Result<Json<StatusSnapshot>, StatusCode> {
    service.auth.authorize_http(&headers).await?;
    let hop_raw = headers
        .get("x-tracey-proxy-hop")
        .and_then(|val| val.to_str().ok())
        .unwrap_or("0");
    let hop = match hop_raw.parse::<u8>() {
        Ok(value) => value,
        Err(err) => {
            tracing::warn!(
                hop_raw = %hop_raw,
                error = %err,
                "invalid status proxy hop header"
            );
            0
        }
    };

    let role = service.coordination_role.read().await.clone();
    let is_proxy = role.proxy_agent_id.as_deref() == Some(&service.agent_id);

    if hop == 0 && !is_proxy {
        if let Some(proxy_addr) = &role.proxy_addr {
            let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok());
            if let Some(resp) = forward_to_proxy(&service, proxy_addr, auth_header).await {
                return Ok(Json(resp));
            }
        }
    }

    Ok(Json(local_snapshot(&service, &role).await))
}

async fn tracey_guard_handler(
    State(service): State<StatusService>,
    headers: HeaderMap,
) -> Result<Json<crate::tracey_guard::TraceyGuardStatusSnapshot>, StatusCode> {
    service.auth.authorize_http(&headers).await?;
    let Some(runtime) = &service.tracey_guard else {
        return Err(StatusCode::NOT_FOUND);
    };
    Ok(Json(runtime.snapshot().await))
}

async fn tracey_guard_control_handler(
    State(service): State<StatusService>,
    headers: HeaderMap,
    Json(request): Json<crate::tracey_guard::TraceyGuardControlRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    service.auth.authorize_http(&headers).await?;
    let Some(runtime) = &service.tracey_guard else {
        return Err(StatusCode::NOT_FOUND);
    };
    let control = runtime.apply_control(request).await;
    let snapshot = runtime.snapshot().await;
    Ok(Json(serde_json::json!({
        "control": control,
        "summary": snapshot.summary,
        "updated_ms": now_ms()
    })))
}

async fn metrics_handler(
    State(service): State<StatusService>,
) -> Result<impl IntoResponse, StatusCode> {
    let Some(export) = &service.prometheus_export else {
        return Err(StatusCode::NOT_FOUND);
    };
    let body = export.render_metrics().await;
    Ok((
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    ))
}

async fn prometheus_ingest_handler(
    State(service): State<StatusService>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    let Some(export) = &service.prometheus_export else {
        return StatusCode::NOT_FOUND;
    };
    match export.ingest_http(&headers, &body).await {
        Ok(()) => StatusCode::ACCEPTED,
        Err(code) => code,
    }
}

async fn forward_to_proxy(
    service: &StatusService,
    proxy_addr: &str,
    auth_header: Option<&str>,
) -> Option<StatusSnapshot> {
    let url = normalize_url(proxy_addr, "/status");
    let mut request = service.client.get(url).header("x-tracey-proxy-hop", "1");
    if let Some(auth) = auth_header {
        request = request.header("authorization", auth);
    }

    match request.send().await {
        Ok(resp) => {
            if !resp.status().is_success() {
                tracing::warn!(
                    proxy_addr = %proxy_addr,
                    status = %resp.status(),
                    "proxy status request failed"
                );
                return None;
            }
            let body = match resp.text().await {
                Ok(body) => body,
                Err(err) => {
                    tracing::warn!(
                        proxy_addr = %proxy_addr,
                        error = %err,
                        "failed reading proxy status body"
                    );
                    return None;
                }
            };
            match parse_proxy_snapshot(&body) {
                Ok(snapshot) => Some(snapshot),
                Err(ProxySnapshotParseError::Syntax(err)) => {
                    tracing::warn!(
                        proxy_addr = %proxy_addr,
                        error = %err,
                        body_preview = %body_preview(&body, STATUS_BODY_PREVIEW_BYTES),
                        "invalid proxy status payload"
                    );
                    None
                }
                Err(ProxySnapshotParseError::Semantics(reason)) => {
                    tracing::warn!(
                        proxy_addr = %proxy_addr,
                        reason = %reason,
                        "invalid proxy status semantics"
                    );
                    None
                }
            }
        }
        Err(err) => {
            tracing::warn!(
                proxy_addr = %proxy_addr,
                error = %err,
                "proxy status request transport failed"
            );
            None
        }
    }
}

async fn local_snapshot(service: &StatusService, role: &CoordinatorRole) -> StatusSnapshot {
    let state = service.governance_state.read().await;
    let presence = service.coordination.presence_snapshot().await;
    let ban_snapshot = if let Some(ban_intel) = &service.ban_intel {
        ban_intel.snapshot(16).await
    } else {
        crate::tracey_ban::BanStatusSnapshot::default()
    };

    let tracey_guard = if let Some(tracey_guard) = &service.tracey_guard {
        Some(tracey_guard.snapshot().await)
    } else {
        None
    };
    let slurm = service.slurm.snapshot().await;
    let continuum_autoscaler = if let Some(autoscaler) = &service.continuum_autoscaler {
        Some(autoscaler.snapshot().await)
    } else {
        None
    };
    let mut continuum_telemetry = if let Some(continuum) = &service.continuum_telemetry {
        Some(continuum.snapshot().await)
    } else {
        None
    };
    let loader_threats = if let Some(loader_threats) = &service.loader_threats {
        loader_threats.snapshot().await
    } else {
        None
    };
    let local_probe = role.prometheus_probe.clone();
    let (mut location, peer_locations) = crate::location::infer_cluster_locations(
        &service.agent_id,
        role,
        service.status_addr.as_deref(),
        &presence,
    );
    if location.agent_version.is_none() {
        location.agent_version = Some(service.agent_version.clone());
    }
    if let Some(continuum) = continuum_telemetry.as_mut() {
        merge_continuum_snapshot(continuum, &location, tracey_guard.as_ref());
    }

    StatusSnapshot {
        ts_ms: now_ms(),
        status: Some(status_for_posture(state.posture)),
        agent_id: service.agent_id.clone(),
        agent_version: Some(service.agent_version.clone()),
        status_addr: service.status_addr.clone(),
        is_coordinator: role.is_coordinator,
        leader_rank: role.leader_rank,
        leader_count: role.leader_count,
        proxy_agent_id: role.proxy_agent_id.clone(),
        proxy_addr: role.proxy_addr.clone(),
        proxy_latency_ms: role.proxy_latency_ms,
        is_prometheus_exporter: role.is_prometheus_exporter,
        prometheus_exporter_agent_id: role.prometheus_exporter_agent_id.clone(),
        prometheus_exporter_addr: role.prometheus_exporter_addr.clone(),
        prometheus_exporter_latency_ms: role.prometheus_exporter_latency_ms,
        prometheus_exporter_bandwidth_mbps: role.prometheus_exporter_bandwidth_mbps,
        local_prometheus_probe_ready: local_probe.as_ref().map(|probe| probe.ready),
        local_prometheus_latency_ms: local_probe.as_ref().map(|probe| probe.latency_ms),
        local_prometheus_bandwidth_mbps: local_probe.as_ref().map(|probe| probe.bandwidth_mbps),
        posture: format!("{:?}", state.posture),
        decision_threshold: state.decision_threshold,
        active_response: state.active_response,
        shutdown_enabled: state.shutdown_enabled,
        update_enabled: state.update_enabled,
        telemetry_enabled: state.telemetry_enabled,
        discovery_enabled: state.discovery_enabled,
        tracey_ban_local_bans: ban_snapshot.local_ban_count,
        tracey_ban_remote_bans: ban_snapshot.remote_ban_count,
        tracey_ban_remote_agents: ban_snapshot.remote_agents,
        tracey_ban_local_entries: ban_snapshot
            .local_entries
            .into_iter()
            .map(|entry| format!("{}:{} ({})", entry.jail, entry.ip, entry.ban_count))
            .collect(),
        tracey_ban_remote_entries: ban_snapshot
            .remote_entries
            .into_iter()
            .map(|entry| format!("{}:{} ({})", entry.jail, entry.ip, entry.ban_count))
            .collect(),
        tracey_guard,
        slurm,
        continuum_autoscaler,
        continuum_telemetry,
        loader_threats,
        location,
        peer_locations,
    }
}

fn status_for_posture(posture: crate::governance::Posture) -> String {
    match posture {
        crate::governance::Posture::Relaxed | crate::governance::Posture::Balanced => {
            "healthy".to_string()
        }
        crate::governance::Posture::Strict => "degraded".to_string(),
        crate::governance::Posture::Lockdown => "offline".to_string(),
    }
}

fn merge_continuum_snapshot(
    snapshot: &mut crate::continuum_telemetry::ContinuumTelemetrySnapshot,
    location: &AgentLocationSnapshot,
    tracey_guard: Option<&crate::tracey_guard::TraceyGuardStatusSnapshot>,
) {
    if snapshot.identity.host.trim().is_empty() && !location.host.trim().is_empty() {
        snapshot.identity.host = location.host.clone();
    }
    fill_continuum_location(&mut snapshot.identity.site, location.site.as_ref());
    fill_continuum_location(&mut snapshot.identity.building, location.building.as_ref());
    fill_continuum_location(&mut snapshot.identity.room, location.room.as_ref());
    fill_continuum_location(&mut snapshot.identity.network, location.network.as_ref());
    fill_continuum_location(&mut snapshot.identity.physical, location.physical.as_ref());
    fill_continuum_location(&mut snapshot.identity.zone, location.geo.as_ref());

    let Some(guard) = tracey_guard else {
        return;
    };

    let by_gpu: HashMap<_, _> = guard
        .gpu_health
        .iter()
        .map(|entry| (entry.gpu_id.as_str(), entry))
        .collect();

    for gpu in &mut snapshot.gpus {
        if let Some(view) = by_gpu.get(gpu.gpu_id.as_str()) {
            gpu.guard_state = Some(format!("{:?}", view.state).to_ascii_lowercase());
            gpu.reliability_score = Some(view.reliability_score.clamp(0.0, 1.0));
            gpu.probe_fail_count = Some(view.probe_fail_count);
            gpu.probe_error_count = Some(view.probe_error_count);
            gpu.consecutive_failures = Some(view.consecutive_failures);
            gpu.sm_count = Some(view.sm_count);
            gpu.last_guard_reason = Some(view.last_reason.clone());
            gpu.last_guard_transition_ms = Some(view.last_transition_ms);
            gpu.last_guard_risk = Some(view.last_risk.clamp(0.0, 1.0));
            gpu.last_guard_confidence = Some(view.last_confidence.clamp(0.0, 1.0));
        }
    }
}

fn fill_continuum_location(
    target: &mut Option<String>,
    guess: Option<&crate::location::LocationGuess>,
) {
    if target.is_some() {
        return;
    }
    let Some(guess) = guess else {
        return;
    };
    if guess.label.trim().is_empty() {
        return;
    }
    *target = Some(guess.label.clone());
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

fn validate_proxy_snapshot(snapshot: &StatusSnapshot) -> Result<(), String> {
    if snapshot.agent_id.trim().is_empty() {
        return Err("agent_id is empty".to_string());
    }
    if snapshot.agent_id.len() > STATUS_MAX_AGENT_ID_LEN {
        return Err(format!("agent_id too long (>{})", STATUS_MAX_AGENT_ID_LEN));
    }
    if snapshot.leader_count == 0 {
        return Err("leader_count must be > 0".to_string());
    }
    if snapshot.leader_rank != usize::MAX && snapshot.leader_rank >= snapshot.leader_count {
        return Err("leader_rank must be less than leader_count".to_string());
    }
    if !(0.0..=1.0).contains(&snapshot.decision_threshold) {
        return Err("decision_threshold out of range [0,1]".to_string());
    }
    Ok(())
}

fn parse_proxy_snapshot(body: &str) -> Result<StatusSnapshot, ProxySnapshotParseError> {
    let snapshot = match serde_json::from_str::<StatusSnapshot>(body) {
        Ok(snapshot) => snapshot,
        Err(err) => {
            let (snapshot, affinity) = parse_proxy_snapshot_lossy(body)
                .map_err(|_| ProxySnapshotParseError::Syntax(err))?;
            tracing::info!(affinity, "proxy status payload recovered with fuzzy parser");
            snapshot
        }
    };
    validate_proxy_snapshot(&snapshot).map_err(ProxySnapshotParseError::Semantics)?;
    Ok(snapshot)
}

fn parse_proxy_snapshot_lossy(body: &str) -> Result<(StatusSnapshot, f64), String> {
    let root = peer_compat::parse_str(body).map_err(|err| err.to_string())?;
    let fields = [
        SchemaField {
            aliases: &["agent_id", "agentId", "node_id", "nodeId", "id"],
            required: true,
            weight: 2.0,
        },
        SchemaField {
            aliases: &["posture", "status", "health"],
            required: false,
            weight: 1.0,
        },
        SchemaField {
            aliases: &[
                "decision_threshold",
                "decisionThreshold",
                "threshold",
                "risk_threshold",
            ],
            required: false,
            weight: 1.2,
        },
        SchemaField {
            aliases: &["leader_count", "leaderCount", "leaders"],
            required: false,
            weight: 0.8,
        },
        SchemaField {
            aliases: &["proxy_addr", "proxyAddr", "status_addr", "statusAddr"],
            required: false,
            weight: 0.8,
        },
    ];
    let matched = peer_compat::best_object(&root, &fields, 1.6, 4)
        .ok_or_else(|| "payload did not resemble a Tracey status snapshot".to_string())?;
    let map = matched.map;

    let agent_id = peer_compat::value_for(map, &["agent_id", "agentId", "node_id", "nodeId", "id"])
        .and_then(peer_compat::coerce_string)
        .ok_or_else(|| "missing agent identifier".to_string())?;

    let posture = peer_compat::value_for(map, &["posture", "mode"])
        .and_then(peer_compat::coerce_string)
        .unwrap_or_else(|| "Balanced".to_string());
    let status =
        peer_compat::value_for(map, &["status", "health"]).and_then(peer_compat::coerce_string);
    let decision_threshold = peer_compat::value_for(
        map,
        &[
            "decision_threshold",
            "decisionThreshold",
            "threshold",
            "risk_threshold",
        ],
    )
    .and_then(peer_compat::coerce_unit_interval)
    .unwrap_or(0.75);
    let leader_count = peer_compat::value_for(map, &["leader_count", "leaderCount", "leaders"])
        .and_then(peer_compat::coerce_usize)
        .unwrap_or(1)
        .max(1);

    Ok((
        StatusSnapshot {
            ts_ms: peer_compat::value_for(
                map,
                &["ts_ms", "timestamp_ms", "timestamp", "updated_ms"],
            )
            .and_then(peer_compat::coerce_u64)
            .unwrap_or_else(now_ms),
            status,
            agent_id,
            agent_version: peer_compat::value_for(
                map,
                &["agent_version", "agentVersion", "version", "build_version"],
            )
            .and_then(peer_compat::coerce_string),
            status_addr: peer_compat::value_for(
                map,
                &["status_addr", "statusAddr", "status_url", "statusUrl"],
            )
            .and_then(peer_compat::coerce_string),
            is_coordinator: peer_compat::value_for(
                map,
                &["is_coordinator", "isCoordinator", "leader", "coordinator"],
            )
            .and_then(peer_compat::coerce_bool)
            .unwrap_or(false),
            leader_rank: peer_compat::value_for(map, &["leader_rank", "leaderRank", "rank"])
                .and_then(peer_compat::coerce_usize)
                .unwrap_or(0),
            leader_count,
            proxy_agent_id: peer_compat::value_for(
                map,
                &["proxy_agent_id", "proxyAgentId", "proxy_id", "proxyId"],
            )
            .and_then(peer_compat::coerce_string),
            proxy_addr: peer_compat::value_for(
                map,
                &["proxy_addr", "proxyAddr", "proxy_url", "proxyUrl"],
            )
            .and_then(peer_compat::coerce_string),
            proxy_latency_ms: peer_compat::value_for(
                map,
                &["proxy_latency_ms", "proxyLatencyMs", "proxy_latency"],
            )
            .and_then(peer_compat::coerce_u64),
            is_prometheus_exporter: peer_compat::value_for(
                map,
                &[
                    "is_prometheus_exporter",
                    "isPrometheusExporter",
                    "prometheus_exporter",
                ],
            )
            .and_then(peer_compat::coerce_bool)
            .unwrap_or(false),
            prometheus_exporter_agent_id: peer_compat::value_for(
                map,
                &[
                    "prometheus_exporter_agent_id",
                    "prometheusExporterAgentId",
                    "exporter_agent_id",
                ],
            )
            .and_then(peer_compat::coerce_string),
            prometheus_exporter_addr: peer_compat::value_for(
                map,
                &[
                    "prometheus_exporter_addr",
                    "prometheusExporterAddr",
                    "exporter_addr",
                ],
            )
            .and_then(peer_compat::coerce_string),
            prometheus_exporter_latency_ms: peer_compat::value_for(
                map,
                &[
                    "prometheus_exporter_latency_ms",
                    "prometheusExporterLatencyMs",
                    "exporter_latency_ms",
                ],
            )
            .and_then(peer_compat::coerce_u64),
            prometheus_exporter_bandwidth_mbps: peer_compat::value_for(
                map,
                &[
                    "prometheus_exporter_bandwidth_mbps",
                    "prometheusExporterBandwidthMbps",
                    "exporter_bandwidth_mbps",
                ],
            )
            .and_then(peer_compat::coerce_f64),
            local_prometheus_probe_ready: peer_compat::value_for(
                map,
                &[
                    "local_prometheus_probe_ready",
                    "localPrometheusProbeReady",
                    "probe_ready",
                ],
            )
            .and_then(peer_compat::coerce_bool),
            local_prometheus_latency_ms: peer_compat::value_for(
                map,
                &[
                    "local_prometheus_latency_ms",
                    "localPrometheusLatencyMs",
                    "probe_latency_ms",
                ],
            )
            .and_then(peer_compat::coerce_u64),
            local_prometheus_bandwidth_mbps: peer_compat::value_for(
                map,
                &[
                    "local_prometheus_bandwidth_mbps",
                    "localPrometheusBandwidthMbps",
                    "probe_bandwidth_mbps",
                ],
            )
            .and_then(peer_compat::coerce_f64),
            posture,
            decision_threshold,
            active_response: peer_compat::value_for(
                map,
                &["active_response", "activeResponse", "response_enabled"],
            )
            .and_then(peer_compat::coerce_bool)
            .unwrap_or(false),
            shutdown_enabled: peer_compat::value_for(map, &["shutdown_enabled", "shutdownEnabled"])
                .and_then(peer_compat::coerce_bool)
                .unwrap_or(false),
            update_enabled: peer_compat::value_for(map, &["update_enabled", "updateEnabled"])
                .and_then(peer_compat::coerce_bool)
                .unwrap_or(false),
            telemetry_enabled: peer_compat::value_for(
                map,
                &["telemetry_enabled", "telemetryEnabled"],
            )
            .and_then(peer_compat::coerce_bool)
            .unwrap_or(false),
            discovery_enabled: peer_compat::value_for(
                map,
                &["discovery_enabled", "discoveryEnabled"],
            )
            .and_then(peer_compat::coerce_bool)
            .unwrap_or(false),
            tracey_ban_local_bans: peer_compat::value_for(
                map,
                &["tracey_ban_local_bans", "traceyBanLocalBans", "local_bans"],
            )
            .and_then(peer_compat::coerce_usize)
            .unwrap_or(0),
            tracey_ban_remote_bans: peer_compat::value_for(
                map,
                &[
                    "tracey_ban_remote_bans",
                    "traceyBanRemoteBans",
                    "remote_bans",
                ],
            )
            .and_then(peer_compat::coerce_usize)
            .unwrap_or(0),
            tracey_ban_remote_agents: peer_compat::value_for(
                map,
                &[
                    "tracey_ban_remote_agents",
                    "traceyBanRemoteAgents",
                    "remote_agents",
                ],
            )
            .and_then(peer_compat::coerce_usize)
            .unwrap_or(0),
            tracey_ban_local_entries: peer_compat::value_for(
                map,
                &[
                    "tracey_ban_local_entries",
                    "traceyBanLocalEntries",
                    "local_entries",
                ],
            )
            .map(peer_compat::coerce_string_vec)
            .unwrap_or_default(),
            tracey_ban_remote_entries: peer_compat::value_for(
                map,
                &[
                    "tracey_ban_remote_entries",
                    "traceyBanRemoteEntries",
                    "remote_entries",
                ],
            )
            .map(peer_compat::coerce_string_vec)
            .unwrap_or_default(),
            tracey_guard: parse_object_field(map, &["tracey_guard", "traceyGuard"]),
            slurm: parse_object_field(map, &["slurm", "slurm_status", "slurmSnapshot"]),
            continuum_autoscaler: parse_object_field(
                map,
                &["continuum_autoscaler", "continuumAutoscaler", "autoscaler"],
            ),
            continuum_telemetry: parse_object_field(
                map,
                &["continuum_telemetry", "continuumTelemetry", "continuum"],
            ),
            loader_threats: parse_object_field(
                map,
                &[
                    "loader_threats",
                    "loaderThreats",
                    "loader_security",
                    "loaderSecurity",
                ],
            ),
            location: parse_object_field(map, &["location", "agent_location"]).unwrap_or_default(),
            peer_locations: parse_array_field(map, &["peer_locations", "peerLocations", "peers"]),
        },
        matched.score,
    ))
}

fn parse_object_field<T>(map: &Map<String, Value>, aliases: &[&str]) -> Option<T>
where
    T: DeserializeOwned,
{
    peer_compat::value_for(map, aliases)
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
}

fn parse_array_field<T>(map: &Map<String, Value>, aliases: &[&str]) -> Vec<T>
where
    T: DeserializeOwned,
{
    peer_compat::value_for(map, aliases)
        .and_then(peer_compat::value_as_array)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|value| serde_json::from_value(value).ok())
        .collect()
}

fn body_preview(body: &str, max: usize) -> String {
    let end = body
        .char_indices()
        .nth(max)
        .map(|(idx, _)| idx)
        .unwrap_or(body.len());
    body[..end].replace('\n', "\\n").replace('\r', "\\r")
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn parse_proxy_snapshot_rejects_semantic_violations() {
        let payload = serde_json::json!({
            "ts_ms": 1,
            "agent_id": "peer-a",
            "is_coordinator": false,
            "leader_rank": 0,
            "leader_count": 0,
            "proxy_agent_id": null,
            "proxy_addr": null,
            "proxy_latency_ms": null,
            "posture": "Balanced",
            "decision_threshold": 0.5,
            "active_response": false,
            "shutdown_enabled": false,
            "update_enabled": true,
            "telemetry_enabled": true,
            "discovery_enabled": true,
            "tracey_ban_local_bans": 0,
            "tracey_ban_remote_bans": 0,
            "tracey_ban_remote_agents": 0,
            "tracey_ban_local_entries": [],
            "tracey_ban_remote_entries": []
        })
        .to_string();

        match parse_proxy_snapshot(&payload) {
            Err(ProxySnapshotParseError::Semantics(reason)) => {
                assert!(reason.contains("leader_count"));
            }
            _ => panic!("expected semantic error for invalid leader_count"),
        }
    }

    #[test]
    fn parse_proxy_snapshot_recovers_wrapped_camel_case_payload() {
        let payload = serde_json::json!({
            "response": {
                "statusSnapshot": {
                    "timestamp_ms": "99",
                    "agentId": "peer-a",
                    "agentVersion": "2.3.4",
                    "statusUrl": "https://peer-a.example/status",
                    "leaderCount": "2",
                    "leaderRank": "1",
                    "proxyAddr": "https://leader.example/status",
                    "proxyLatencyMs": "18",
                    "decisionThreshold": "62%",
                    "posture": "Strict",
                    "activeResponse": "yes",
                    "shutdownEnabled": "false",
                    "updateEnabled": "true",
                    "telemetryEnabled": "true",
                    "discoveryEnabled": "true",
                    "traceyBanLocalBans": "1",
                    "traceyBanRemoteBans": "2",
                    "traceyBanRemoteAgents": "1",
                    "traceyBanLocalEntries": ["ssh:192.0.2.10 (2)"],
                    "traceyBanRemoteEntries": ["api:192.0.2.11 (1)"],
                    "peerLocations": [
                        {
                            "agent_id": "peer-b",
                            "host": "peer-b",
                            "relation": "peer"
                        }
                    ]
                }
            }
        })
        .to_string();

        let snapshot = parse_proxy_snapshot(&payload).expect("payload should recover");

        assert_eq!(snapshot.agent_id, "peer-a");
        assert_eq!(snapshot.agent_version.as_deref(), Some("2.3.4"));
        assert_eq!(snapshot.decision_threshold, 0.62);
        assert!(snapshot.active_response);
        assert_eq!(snapshot.leader_count, 2);
        assert_eq!(snapshot.peer_locations.len(), 1);
        assert_eq!(snapshot.proxy_latency_ms, Some(18));
    }

    proptest! {
        #[test]
        fn proxy_payload_parser_is_panic_safe(body in ".{0,2048}") {
            let _ = parse_proxy_snapshot(&body);
        }

        #[test]
        fn proxy_payload_semantic_validator_is_panic_safe(
            agent_id in ".{0,220}",
            leader_rank in 0usize..20usize,
            leader_count in 0usize..20usize,
            decision_threshold in -5.0f64..5.0f64,
            local_entries in prop::collection::vec(".{0,64}", 0..16),
            remote_entries in prop::collection::vec(".{0,64}", 0..16),
        ) {
            let body = serde_json::json!({
                "ts_ms": 1,
                "agent_id": agent_id,
                "is_coordinator": false,
                "leader_rank": leader_rank,
                "leader_count": leader_count,
                "proxy_agent_id": null,
                "proxy_addr": null,
                "proxy_latency_ms": null,
                "posture": "Balanced",
                "decision_threshold": decision_threshold,
                "active_response": false,
                "shutdown_enabled": false,
                "update_enabled": true,
                "telemetry_enabled": true,
                "discovery_enabled": true,
                "tracey_ban_local_bans": 0,
                "tracey_ban_remote_bans": 0,
                "tracey_ban_remote_agents": 0,
                "tracey_ban_local_entries": local_entries,
                "tracey_ban_remote_entries": remote_entries
            })
            .to_string();

            let _ = parse_proxy_snapshot(&body);
        }
    }
}
