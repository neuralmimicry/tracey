//! HTTP status/control surface for local and proxied cluster state.
//!
//! Includes posture-aware snapshots, TraceyBan summaries, and TraceyGuard
//! status/control endpoints with optional auth gating.

use crate::auth::AuthGate;
use crate::coordination::{Coordination, CoordinatorRole};
use crate::event::now_ms;
use crate::governance::GovernanceState;
use crate::location::AgentLocationSnapshot;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;

const STATUS_BODY_PREVIEW_BYTES: usize = 256;
const STATUS_MAX_AGENT_ID_LEN: usize = 128;

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
    let snapshot =
        serde_json::from_str::<StatusSnapshot>(body).map_err(ProxySnapshotParseError::Syntax)?;
    validate_proxy_snapshot(&snapshot).map_err(ProxySnapshotParseError::Semantics)?;
    Ok(snapshot)
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
