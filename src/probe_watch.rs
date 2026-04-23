//! Lightweight network probe detection for Tracey's externally reachable surfaces.
//!
//! ProbeWatch can publish alerts into Tracey's event/storage pipeline or run in
//! memory/persisted mode for standalone components such as the loader.

use crate::bus::EventBus;
use crate::event::{Event, EventKind, Severity, now_ms};
use crate::storage::Storage;
use crate::update;
use axum::http::{HeaderMap, StatusCode};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

const WINDOW_MS: u64 = 30_000;
const BURST_THRESHOLD: usize = 8;
const SWEEP_THRESHOLD: usize = 4;
const ALERT_COOLDOWN_MS: u64 = 10_000;
const MAX_RECENT_ALERTS: usize = 32;
const MAX_MERGED_ALERTS: usize = 64;
const MAX_USER_AGENT_LEN: usize = 160;
const MAX_SURFACE_LEN: usize = 64;
const LOADER_PROBE_WATCH_SNAPSHOT: &str = "tracey-loader.probe_watch.snapshot.json";

static PROBE_EVENT_COUNTER: AtomicU64 = AtomicU64::new(90_000);

#[derive(Clone)]
pub struct ProbeWatchHandle {
    inner: Option<Arc<ProbeWatchInner>>,
}

struct ProbeWatchInner {
    surface: String,
    bus: Option<EventBus>,
    storage: Option<Storage>,
    snapshot_path: Option<PathBuf>,
    state: tokio::sync::RwLock<ProbeWatchState>,
}

#[derive(Default)]
struct ProbeWatchState {
    total_observations: u64,
    total_alerts: u64,
    recent_alerts: VecDeque<ProbeAlert>,
    sources: HashMap<String, SourceWindow>,
    last_alert_ms: HashMap<String, u64>,
}

#[derive(Default)]
struct SourceWindow {
    requests: VecDeque<RequestSample>,
}

#[derive(Clone)]
struct RequestSample {
    ts_ms: u64,
    path: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeAlertClassification {
    CooperativeProbe,
    PathScan,
    RouteSweep,
    BurstScan,
    UnauthorizedControlProbe,
    SuspiciousUserAgent,
}

impl ProbeAlertClassification {
    fn as_str(self) -> &'static str {
        match self {
            Self::CooperativeProbe => "cooperative_probe",
            Self::PathScan => "path_scan",
            Self::RouteSweep => "route_sweep",
            Self::BurstScan => "burst_scan",
            Self::UnauthorizedControlProbe => "unauthorized_control_probe",
            Self::SuspiciousUserAgent => "suspicious_user_agent",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProbeAlert {
    pub ts_ms: u64,
    pub surface: String,
    pub source: String,
    pub method: String,
    pub path: String,
    pub status_code: u16,
    pub classification: ProbeAlertClassification,
    pub severity: Severity,
    pub signal: f64,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized: Option<bool>,
    #[serde(default)]
    pub known_route: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProbeWatchSurfaceSnapshot {
    pub enabled: bool,
    pub surface: String,
    pub total_observations: u64,
    pub total_alerts: u64,
    pub distinct_sources: usize,
    #[serde(default)]
    pub recent_alerts: Vec<ProbeAlert>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProbeWatchSnapshot {
    pub enabled: bool,
    pub total_observations: u64,
    pub total_alerts: u64,
    pub distinct_sources: usize,
    #[serde(default)]
    pub recent_alerts: Vec<ProbeAlert>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub surfaces: Vec<ProbeWatchSurfaceSnapshot>,
}

impl Default for ProbeWatchSnapshot {
    fn default() -> Self {
        Self {
            enabled: false,
            total_observations: 0,
            total_alerts: 0,
            distinct_sources: 0,
            recent_alerts: Vec::new(),
            surfaces: Vec::new(),
        }
    }
}

#[derive(Clone)]
pub struct ProbeWatchSnapshotHandle {
    snapshot_path: PathBuf,
}

pub struct ProbeObservation<'a> {
    pub remote_addr: Option<SocketAddr>,
    pub method: &'a str,
    pub path: &'a str,
    pub status_code: StatusCode,
    pub headers: &'a HeaderMap,
    pub known_route: bool,
    pub control_route: bool,
    pub authorized: Option<bool>,
}

impl ProbeWatchHandle {
    pub fn enabled(surface: impl Into<String>, bus: EventBus, storage: Storage) -> Self {
        Self::build(surface, Some(bus), Some(storage), None)
    }

    pub fn memory_only(surface: impl Into<String>) -> Self {
        Self::build(surface, None, None, None)
    }

    pub fn persisted(surface: impl Into<String>, snapshot_path: PathBuf) -> Self {
        Self::build(surface, None, None, Some(snapshot_path))
    }

    fn build(
        surface: impl Into<String>,
        bus: Option<EventBus>,
        storage: Option<Storage>,
        snapshot_path: Option<PathBuf>,
    ) -> Self {
        Self {
            inner: Some(Arc::new(ProbeWatchInner {
                surface: sanitize_surface(surface.into()),
                bus,
                storage,
                snapshot_path,
                state: tokio::sync::RwLock::new(ProbeWatchState::default()),
            })),
        }
    }

    pub fn disabled() -> Self {
        Self { inner: None }
    }

    pub async fn observe_http(&self, observation: ProbeObservation<'_>) {
        let Some(inner) = &self.inner else {
            return;
        };

        let ts_ms = now_ms();
        let surface = inner.surface.clone();
        let source_ip = extract_source_ip(observation.remote_addr, observation.headers);
        let source = source_ip
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let loopback = source_ip.map(|ip| ip.is_loopback()).unwrap_or(false);
        let cooperative = observation
            .headers
            .get("x-neuralmimicry-redteam")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| !value.trim().is_empty())
            || header_contains(observation.headers, "user-agent", "NeuralMimicry-RedTeam");
        let user_agent = observation
            .headers
            .get("user-agent")
            .and_then(|value| value.to_str().ok())
            .map(|value| truncate(value.trim(), MAX_USER_AGENT_LEN));
        let suspicious_user_agent = user_agent
            .as_deref()
            .map(is_suspicious_user_agent)
            .unwrap_or(false);
        let suspicious_path = is_suspicious_path(observation.path);
        let run_id = observation
            .headers
            .get("x-neuralmimicry-run-id")
            .and_then(|value| value.to_str().ok())
            .map(|value| truncate(value.trim(), 80));

        let (maybe_alert, surface_snapshot) = {
            let mut state = inner.state.write().await;
            state.total_observations = state.total_observations.saturating_add(1);

            let source_window = state.sources.entry(source.clone()).or_default();
            prune_source_window(source_window, ts_ms);
            source_window.requests.push_back(RequestSample {
                ts_ms,
                path: observation.path.to_string(),
            });
            let request_count = source_window.requests.len();
            let unique_paths = source_window
                .requests
                .iter()
                .map(|sample| sample.path.as_str())
                .collect::<HashSet<_>>()
                .len();

            let classification =
                if observation.control_route && observation.authorized == Some(false) {
                    Some((
                        ProbeAlertClassification::UnauthorizedControlProbe,
                        Severity::High,
                        0.90,
                        format!(
                            "unauthorized control probe against {} with status {}",
                            observation.path,
                            observation.status_code.as_u16()
                        ),
                    ))
                } else if suspicious_path && (!loopback || cooperative) {
                    Some((
                        ProbeAlertClassification::PathScan,
                        Severity::High,
                        0.84,
                        format!("unexpected path probe for {}", observation.path),
                    ))
                } else if unique_paths >= SWEEP_THRESHOLD && (!loopback || cooperative) {
                    Some((
                        ProbeAlertClassification::RouteSweep,
                        Severity::High,
                        0.79,
                        format!(
                            "route sweep across {} unique paths in {} ms",
                            unique_paths, WINDOW_MS
                        ),
                    ))
                } else if request_count >= BURST_THRESHOLD && (!loopback || cooperative) {
                    Some((
                        ProbeAlertClassification::BurstScan,
                        Severity::Medium,
                        0.72,
                        format!("burst of {} requests in {} ms", request_count, WINDOW_MS),
                    ))
                } else if suspicious_user_agent && (!loopback || cooperative) {
                    Some((
                        ProbeAlertClassification::SuspiciousUserAgent,
                        Severity::Medium,
                        0.70,
                        format!(
                            "suspicious user-agent {}",
                            user_agent.clone().unwrap_or_default()
                        ),
                    ))
                } else if cooperative {
                    Some((
                        ProbeAlertClassification::CooperativeProbe,
                        Severity::Medium,
                        0.66,
                        format!("cooperative probe observed on {}", observation.path),
                    ))
                } else {
                    None
                };

            let mut maybe_alert = None;
            if let Some((classification, severity, signal, reason)) = classification {
                let cooldown_key = format!("{}:{}:{}", surface, source, classification.as_str());
                let emit = state
                    .last_alert_ms
                    .get(&cooldown_key)
                    .copied()
                    .map(|last| ts_ms.saturating_sub(last) >= ALERT_COOLDOWN_MS)
                    .unwrap_or(true);
                if emit {
                    state.last_alert_ms.insert(cooldown_key, ts_ms);
                    state.total_alerts = state.total_alerts.saturating_add(1);
                    let alert = ProbeAlert {
                        ts_ms,
                        surface: surface.clone(),
                        source: source.clone(),
                        method: observation.method.to_string(),
                        path: observation.path.to_string(),
                        status_code: observation.status_code.as_u16(),
                        classification,
                        severity,
                        signal,
                        reason,
                        user_agent: user_agent.clone(),
                        run_id,
                        authorized: observation.authorized,
                        known_route: observation.known_route,
                    };
                    state.recent_alerts.push_front(alert.clone());
                    while state.recent_alerts.len() > MAX_RECENT_ALERTS {
                        state.recent_alerts.pop_back();
                    }
                    maybe_alert = Some(alert);
                }
            }

            state.sources.retain(|_, window| {
                prune_source_window(window, ts_ms);
                !window.requests.is_empty()
            });

            (maybe_alert, build_surface_snapshot(&surface, &state))
        };

        if let Some(snapshot_path) = &inner.snapshot_path {
            persist_surface_snapshot(snapshot_path, &surface_snapshot).await;
        }

        if let Some(alert) = maybe_alert {
            let event = Event::new(
                PROBE_EVENT_COUNTER.fetch_add(1, Ordering::Relaxed),
                format!("probe_watch:{}", alert.classification.as_str()),
                EventKind::NetworkFlow,
                alert.signal,
                alert.severity,
            )
            .with_attr("classification", alert.classification.as_str())
            .with_attr("surface", alert.surface.clone())
            .with_attr("path", alert.path.clone())
            .with_attr("method", alert.method.clone())
            .with_attr("status_code", alert.status_code.to_string())
            .with_attr("source_ip", alert.source.clone())
            .with_attr("reason", alert.reason.clone());
            if let Some(bus) = &inner.bus {
                bus.publish(event.clone());
            }
            if let Some(storage) = &inner.storage {
                storage.record_event(event).await;
            }
            tracing::warn!(
                surface = %alert.surface,
                classification = alert.classification.as_str(),
                source = %alert.source,
                path = %alert.path,
                status_code = alert.status_code,
                "probe watch alert"
            );
        }
    }

    pub async fn surface_snapshot(&self) -> Option<ProbeWatchSurfaceSnapshot> {
        let Some(inner) = &self.inner else {
            return None;
        };
        let state = inner.state.read().await;
        Some(build_surface_snapshot(&inner.surface, &state))
    }

    pub async fn snapshot(&self) -> Option<ProbeWatchSnapshot> {
        let surface = self.surface_snapshot().await?;
        aggregate_snapshots([surface])
    }
}

impl ProbeWatchSnapshotHandle {
    pub fn from_path(snapshot_path: PathBuf) -> Self {
        Self { snapshot_path }
    }

    pub fn from_loader_config(
        config: &crate::config::LoaderConfig,
    ) -> Result<Self, std::io::Error> {
        let root = resolve_loader_root(config)?;
        Ok(Self {
            snapshot_path: root.join(LOADER_PROBE_WATCH_SNAPSHOT),
        })
    }

    pub async fn snapshot(&self) -> Option<ProbeWatchSurfaceSnapshot> {
        if !self.snapshot_path.exists() {
            return None;
        }
        let raw = tokio::fs::read(&self.snapshot_path).await.ok()?;
        match serde_json::from_slice::<ProbeWatchSurfaceSnapshot>(&raw) {
            Ok(snapshot) => Some(snapshot),
            Err(err) => {
                tracing::warn!(
                    path = %self.snapshot_path.display(),
                    error = %err,
                    "probe watch snapshot was malformed; ignoring"
                );
                None
            }
        }
    }
}

pub fn aggregate_snapshots<I>(snapshots: I) -> Option<ProbeWatchSnapshot>
where
    I: IntoIterator<Item = ProbeWatchSurfaceSnapshot>,
{
    let mut surfaces = snapshots
        .into_iter()
        .filter(|snapshot| snapshot.enabled)
        .collect::<Vec<_>>();
    if surfaces.is_empty() {
        return None;
    }

    surfaces.sort_by(|left, right| {
        right
            .total_alerts
            .cmp(&left.total_alerts)
            .then(left.surface.cmp(&right.surface))
    });

    let mut recent_alerts = surfaces
        .iter()
        .flat_map(|snapshot| snapshot.recent_alerts.iter().cloned())
        .collect::<Vec<_>>();
    recent_alerts.sort_by(|left, right| right.ts_ms.cmp(&left.ts_ms));
    recent_alerts.truncate(MAX_MERGED_ALERTS);

    Some(ProbeWatchSnapshot {
        enabled: true,
        total_observations: surfaces
            .iter()
            .map(|snapshot| snapshot.total_observations)
            .sum(),
        total_alerts: surfaces.iter().map(|snapshot| snapshot.total_alerts).sum(),
        distinct_sources: surfaces
            .iter()
            .map(|snapshot| snapshot.distinct_sources)
            .sum(),
        recent_alerts,
        surfaces,
    })
}

fn build_surface_snapshot(surface: &str, state: &ProbeWatchState) -> ProbeWatchSurfaceSnapshot {
    ProbeWatchSurfaceSnapshot {
        enabled: true,
        surface: sanitize_surface(surface.to_string()),
        total_observations: state.total_observations,
        total_alerts: state.total_alerts,
        distinct_sources: state.sources.len(),
        recent_alerts: state.recent_alerts.iter().cloned().collect(),
    }
}

async fn persist_surface_snapshot(path: &Path, snapshot: &ProbeWatchSurfaceSnapshot) {
    let payload = match serde_json::to_vec_pretty(snapshot) {
        Ok(payload) => payload,
        Err(err) => {
            tracing::warn!(
                path = %path.display(),
                error = %err,
                "probe watch snapshot serialization failed"
            );
            return;
        }
    };

    if let Err(err) = update::write_atomic(path, &payload).await {
        tracing::warn!(
            path = %path.display(),
            error = %err,
            "probe watch snapshot persistence failed"
        );
    }
}

fn prune_source_window(window: &mut SourceWindow, now_ms: u64) {
    while window
        .requests
        .front()
        .is_some_and(|sample| now_ms.saturating_sub(sample.ts_ms) > WINDOW_MS)
    {
        window.requests.pop_front();
    }
}

fn extract_source_ip(remote_addr: Option<SocketAddr>, headers: &HeaderMap) -> Option<IpAddr> {
    if let Some(remote) = remote_addr {
        return Some(remote.ip());
    }
    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .and_then(|value| value.trim().parse::<IpAddr>().ok())
}

fn header_contains(headers: &HeaderMap, name: &str, needle: &str) -> bool {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.contains(needle))
}

fn truncate(value: &str, max_len: usize) -> String {
    if value.len() <= max_len {
        value.to_string()
    } else {
        value[..max_len].to_string()
    }
}

fn sanitize_surface(value: String) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        "unknown".to_string()
    } else {
        truncate(trimmed, MAX_SURFACE_LEN)
    }
}

fn resolve_loader_root(config: &crate::config::LoaderConfig) -> Result<PathBuf, std::io::Error> {
    if config.state_dir.is_absolute() {
        Ok(config.state_dir.clone())
    } else {
        Ok(std::env::current_dir()?.join(&config.state_dir))
    }
}

fn is_suspicious_user_agent(user_agent: &str) -> bool {
    let lower = user_agent.to_ascii_lowercase();
    [
        "nmap",
        "sqlmap",
        "nikto",
        "masscan",
        "zgrab",
        "python-requests",
        "curl/",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn is_suspicious_path(path: &str) -> bool {
    [
        "/.git",
        "/.env",
        "/wp-login",
        "/phpmyadmin",
        "/admin",
        "/cgi-bin",
        "/manager/html",
        "../",
    ]
    .iter()
    .any(|needle| path.starts_with(needle) || path.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{LoaderConfig, StorageConfig};
    use crate::shutdown::Shutdown;

    #[tokio::test]
    async fn cooperative_probe_generates_recent_alert() {
        let bus = EventBus::new(16);
        let (shutdown, listener) = Shutdown::new();
        let mut storage_cfg = StorageConfig::default();
        storage_cfg.log_path = std::env::temp_dir().join(format!(
            "probe-watch-test-{}-{}.jsonl",
            std::process::id(),
            now_ms()
        ));
        let storage = Storage::new(storage_cfg.clone(), listener)
            .await
            .expect("storage should start");
        let handle = ProbeWatchHandle::enabled("status", bus, storage);
        let mut headers = HeaderMap::new();
        headers.insert("x-neuralmimicry-redteam", "live-probe".parse().unwrap());
        headers.insert("user-agent", "NeuralMimicry-RedTeam/0.1".parse().unwrap());

        handle
            .observe_http(ProbeObservation {
                remote_addr: Some("127.0.0.1:53000".parse().unwrap()),
                method: "GET",
                path: "/status",
                status_code: StatusCode::OK,
                headers: &headers,
                known_route: true,
                control_route: false,
                authorized: Some(true),
            })
            .await;

        let snapshot = handle
            .surface_snapshot()
            .await
            .expect("snapshot should exist");
        assert_eq!(snapshot.surface, "status");
        assert!(snapshot.total_alerts >= 1);
        assert!(snapshot.recent_alerts.iter().any(|alert| {
            alert.classification == ProbeAlertClassification::CooperativeProbe
                && alert.surface == "status"
        }));

        shutdown.trigger();
        let _ = tokio::fs::remove_file(storage_cfg.log_path).await;
    }

    #[tokio::test]
    async fn persisted_snapshot_handle_reads_surface_snapshot() {
        let path = std::env::temp_dir().join(format!(
            "probe-watch-loader-{}-{}.json",
            std::process::id(),
            now_ms()
        ));
        let handle = ProbeWatchHandle::persisted("loader_transfer", path.clone());
        let mut headers = HeaderMap::new();
        headers.insert("x-neuralmimicry-redteam", "live-probe".parse().unwrap());
        headers.insert("user-agent", "NeuralMimicry-RedTeam/0.1".parse().unwrap());

        handle
            .observe_http(ProbeObservation {
                remote_addr: Some("127.0.0.1:53001".parse().unwrap()),
                method: "GET",
                path: "/loader/status",
                status_code: StatusCode::OK,
                headers: &headers,
                known_route: true,
                control_route: false,
                authorized: None,
            })
            .await;

        let snapshot = ProbeWatchSnapshotHandle::from_path(path.clone())
            .snapshot()
            .await
            .expect("persisted snapshot should be readable");
        assert_eq!(snapshot.surface, "loader_transfer");
        assert!(snapshot.total_alerts >= 1);

        let _ = tokio::fs::remove_file(path).await;
    }

    #[test]
    fn aggregate_snapshot_merges_surfaces() {
        let status = ProbeWatchSurfaceSnapshot {
            enabled: true,
            surface: "status".to_string(),
            total_observations: 4,
            total_alerts: 1,
            distinct_sources: 1,
            recent_alerts: vec![ProbeAlert {
                ts_ms: 10,
                surface: "status".to_string(),
                source: "127.0.0.1".to_string(),
                method: "GET".to_string(),
                path: "/status".to_string(),
                status_code: 200,
                classification: ProbeAlertClassification::CooperativeProbe,
                severity: Severity::Medium,
                signal: 0.66,
                reason: "cooperative".to_string(),
                user_agent: None,
                run_id: None,
                authorized: Some(true),
                known_route: true,
            }],
        };
        let loader = ProbeWatchSurfaceSnapshot {
            enabled: true,
            surface: "loader_transfer".to_string(),
            total_observations: 2,
            total_alerts: 1,
            distinct_sources: 1,
            recent_alerts: vec![ProbeAlert {
                ts_ms: 20,
                surface: "loader_transfer".to_string(),
                source: "127.0.0.1".to_string(),
                method: "GET".to_string(),
                path: "/.git/config".to_string(),
                status_code: 404,
                classification: ProbeAlertClassification::PathScan,
                severity: Severity::High,
                signal: 0.84,
                reason: "path scan".to_string(),
                user_agent: None,
                run_id: None,
                authorized: None,
                known_route: false,
            }],
        };

        let aggregate = aggregate_snapshots([status, loader]).expect("aggregate should exist");
        assert_eq!(aggregate.total_observations, 6);
        assert_eq!(aggregate.total_alerts, 2);
        assert_eq!(aggregate.surfaces.len(), 2);
        assert_eq!(aggregate.recent_alerts[0].surface, "loader_transfer");
    }

    #[test]
    fn loader_snapshot_handle_resolves_loader_root() {
        let mut config = LoaderConfig::default();
        config.state_dir = PathBuf::from("loader-test");
        let handle = ProbeWatchSnapshotHandle::from_loader_config(&config)
            .expect("loader config should resolve");
        assert!(
            handle
                .snapshot_path
                .ends_with(Path::new("loader-test").join(LOADER_PROBE_WATCH_SNAPSHOT))
        );
    }
}
