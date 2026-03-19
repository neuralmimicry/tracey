use crate::coordination::CoordinatorRole;
use crate::event::now_ms;
use crate::governance::GovernanceState;
use crate::auth::AuthGate;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Clone)]
pub struct StatusService {
    pub agent_id: String,
    pub coordination_role: Arc<tokio::sync::RwLock<CoordinatorRole>>,
    pub governance_state: Arc<tokio::sync::RwLock<GovernanceState>>,
    pub client: reqwest::Client,
    pub auth: AuthGate,
}

#[derive(Serialize, Deserialize)]
struct StatusSnapshot {
    ts_ms: u64,
    agent_id: String,
    is_coordinator: bool,
    leader_rank: usize,
    leader_count: usize,
    proxy_agent_id: Option<String>,
    proxy_addr: Option<String>,
    proxy_latency_ms: Option<u64>,
    posture: String,
    decision_threshold: f64,
    active_response: bool,
    shutdown_enabled: bool,
    update_enabled: bool,
    telemetry_enabled: bool,
    discovery_enabled: bool,
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
        .with_state(service);
    if let Err(err) = axum::serve(tokio::net::TcpListener::bind(listen_addr).await.unwrap(), app)
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
    let hop = headers
        .get("x-tracey-proxy-hop")
        .and_then(|val| val.to_str().ok())
        .unwrap_or("0")
        .parse::<u8>()
        .unwrap_or(0);

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

async fn forward_to_proxy(
    service: &StatusService,
    proxy_addr: &str,
    auth_header: Option<&str>,
) -> Option<StatusSnapshot> {
    let url = normalize_url(proxy_addr, "/status");
    let mut request = service
        .client
        .get(url)
        .header("x-tracey-proxy-hop", "1");
    if let Some(auth) = auth_header {
        request = request.header("authorization", auth);
    }

    match request.send().await {
        Ok(resp) => {
            if !resp.status().is_success() {
                return None;
            }
            resp.json::<StatusSnapshot>().await.ok()
        }
        Err(_) => None,
    }
}

async fn local_snapshot(service: &StatusService, role: &CoordinatorRole) -> StatusSnapshot {
    let state = service.governance_state.read().await;
    StatusSnapshot {
        ts_ms: now_ms(),
        agent_id: service.agent_id.clone(),
        is_coordinator: role.is_coordinator,
        leader_rank: role.leader_rank,
        leader_count: role.leader_count,
        proxy_agent_id: role.proxy_agent_id.clone(),
        proxy_addr: role.proxy_addr.clone(),
        proxy_latency_ms: role.proxy_latency_ms,
        posture: format!("{:?}", state.posture),
        decision_threshold: state.decision_threshold,
        active_response: state.active_response,
        shutdown_enabled: state.shutdown_enabled,
        update_enabled: state.update_enabled,
        telemetry_enabled: state.telemetry_enabled,
        discovery_enabled: state.discovery_enabled,
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
