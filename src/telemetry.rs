//! Telemetry ingestion bridges for Prometheus text scrape and OTLP metrics.
//!
//! Metrics are normalized into Tracey `Event` records with optional
//! deduplication when Prometheus is the preferred source.

use crate::auth::{AuthGate, AuthSystem};
use crate::bus::EventBus;
use crate::config::{OtlpReceiverConfig, TelemetryConfig};
use crate::event::{Event, EventKind, Severity};
use crate::governance::GovernanceState;
use crate::probe_watch::{ProbeObservation, ProbeWatchHandle};
use crate::shutdown::ShutdownListener;
use crate::storage::Storage;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::routing::any;
use axum::{Router, body::Bytes};
use opentelemetry_proto::tonic::collector::metrics::v1::metrics_service_server::{
    MetricsService, MetricsServiceServer,
};
use opentelemetry_proto::tonic::collector::metrics::v1::{
    ExportMetricsServiceRequest, ExportMetricsServiceResponse,
};
use opentelemetry_proto::tonic::common::v1::KeyValue;
use opentelemetry_proto::tonic::metrics::v1::metric::Data;
use opentelemetry_proto::tonic::metrics::v1::number_data_point::Value as NumberValue;
use opentelemetry_proto::tonic::metrics::v1::{
    ExponentialHistogram, ExponentialHistogramDataPoint, Gauge, Histogram, HistogramDataPoint,
    Metric, NumberDataPoint, Summary, SummaryDataPoint,
};
use opentelemetry_proto::tonic::resource::v1::Resource;
use prost::Message;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tonic::metadata::{KeyAndValueRef, MetadataMap};

static TELEMETRY_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MetricSource {
    Prometheus,
    OtlpGrpc,
    OtlpHttp,
}

struct MetricRouter {
    prefer_prometheus: bool,
    dedup_ttl: Duration,
    prom_seen: Mutex<HashMap<String, Instant>>,
}

impl MetricRouter {
    fn new(prefer_prometheus: bool, dedup_ttl: Duration) -> Self {
        Self {
            prefer_prometheus,
            dedup_ttl,
            prom_seen: Mutex::new(HashMap::new()),
        }
    }

    async fn allow(&self, key: &str, source: MetricSource) -> bool {
        if self.prefer_prometheus && source != MetricSource::Prometheus {
            let map = self.prom_seen.lock().await;
            if let Some(ts) = map.get(key) {
                if ts.elapsed() < self.dedup_ttl {
                    return false;
                }
            }
        }
        true
    }

    async fn record_prom(&self, key: &str) {
        let mut map = self.prom_seen.lock().await;
        map.insert(key.to_string(), Instant::now());
        if map.len() > 10_000 {
            let ttl = self.dedup_ttl;
            map.retain(|_, ts| ts.elapsed() < ttl);
        }
    }
}

pub async fn spawn_telemetry(
    bus: EventBus,
    storage: Storage,
    config: TelemetryConfig,
    shutdown: ShutdownListener,
    governance_state: std::sync::Arc<tokio::sync::RwLock<GovernanceState>>,
    auth: AuthSystem,
    otlp_http_probe_watch: ProbeWatchHandle,
    otlp_grpc_probe_watch: ProbeWatchHandle,
) {
    if !config.enabled {
        tracing::info!("telemetry integration disabled");
        return;
    }

    let router = Arc::new(MetricRouter::new(
        config.prefer_prometheus,
        Duration::from_millis(config.dedup_ttl_ms),
    ));

    let mut any_enabled = false;

    if config.prometheus_enabled {
        any_enabled = true;
        let router = router.clone();
        let governance_state = governance_state.clone();
        let bus = bus.clone();
        let storage = storage.clone();
        let config = config.clone();
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            run_prometheus_scraper(bus, storage, config, router, shutdown, governance_state).await;
        });
    }

    if config.otlp.enabled {
        any_enabled = true;
        let otlp = config.otlp.clone();
        let bus = bus.clone();
        let storage = storage.clone();
        let config = config.clone();
        let router = router.clone();
        let shutdown = shutdown.clone();
        let governance_state = governance_state.clone();
        let auth = auth.clone();
        tokio::spawn(async move {
            run_otlp_receivers(
                bus,
                storage,
                config,
                otlp,
                router,
                shutdown,
                governance_state,
                auth,
                otlp_http_probe_watch,
                otlp_grpc_probe_watch,
            )
            .await;
        });
    }

    if !any_enabled {
        tracing::warn!("telemetry enabled but no ingestion methods configured");
    }
}

async fn run_prometheus_scraper(
    bus: EventBus,
    storage: Storage,
    config: TelemetryConfig,
    router: Arc<MetricRouter>,
    mut shutdown: ShutdownListener,
    governance_state: std::sync::Arc<tokio::sync::RwLock<GovernanceState>>,
) {
    let mut endpoints = config.endpoints.clone();
    if config.autodiscover_local {
        endpoints.extend(default_local_endpoints());
    }
    endpoints.extend(env_endpoints());
    endpoints.sort();
    endpoints.dedup();

    if endpoints.is_empty() {
        tracing::warn!("telemetry prometheus enabled but no endpoints configured");
        return;
    }

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_millis(config.timeout_ms))
        .build()
    {
        Ok(client) => client,
        Err(err) => {
            tracing::warn!("telemetry client failed: {}", err);
            return;
        }
    };

    let mut interval = tokio::time::interval(Duration::from_millis(config.scrape_interval_ms));

    loop {
        tokio::select! {
            _ = shutdown.wait() => {
                break;
            }
            _ = interval.tick() => {
                let state = governance_state.read().await;
                if !state.telemetry_enabled || !state.prometheus_enabled {
                    continue;
                }
                for endpoint in &endpoints {
                    if (!config.allow_remote || !state.telemetry_allow_remote) && !is_loopback(endpoint) {
                        continue;
                    }
                    match client.get(endpoint).send().await {
                        Ok(resp) => {
                            if !resp.status().is_success() {
                                continue;
                            }
                            if let Ok(body) = resp.text().await {
                                ingest_prometheus_metrics(
                                    &body,
                                    endpoint,
                                    &config,
                                    &bus,
                                    &storage,
                                    &router,
                                )
                                .await;
                            }
                        }
                        Err(_) => {}
                    }
                }
            }
        }
    }
}

async fn run_otlp_receivers(
    bus: EventBus,
    storage: Storage,
    config: TelemetryConfig,
    otlp: OtlpReceiverConfig,
    router: Arc<MetricRouter>,
    mut shutdown: ShutdownListener,
    governance_state: std::sync::Arc<tokio::sync::RwLock<GovernanceState>>,
    auth: AuthSystem,
    otlp_http_probe_watch: ProbeWatchHandle,
    otlp_grpc_probe_watch: ProbeWatchHandle,
) {
    let mut tasks = Vec::new();

    if otlp.enable_grpc {
        let addr = otlp.grpc_addr.parse().ok();
        if let Some(addr) = addr {
            let service = OtlpService::new(
                bus.clone(),
                storage.clone(),
                config.clone(),
                router.clone(),
                governance_state.clone(),
                auth.otlp_grpc_gate(),
                otlp_grpc_probe_watch.clone(),
            );
            let mut shutdown = shutdown.clone();
            let task = tokio::spawn(async move {
                if let Err(err) = tonic::transport::Server::builder()
                    .add_service(MetricsServiceServer::new(service))
                    .serve_with_shutdown(addr, async move { shutdown.wait().await })
                    .await
                {
                    tracing::warn!("otlp grpc server error: {}", err);
                }
            });
            tasks.push(task);
        }
    }

    if otlp.enable_http {
        if let Ok(addr) = otlp.http_addr.parse::<std::net::SocketAddr>() {
            let state = OtlpHttpState::new(
                bus.clone(),
                storage.clone(),
                config.clone(),
                router.clone(),
                governance_state.clone(),
                auth.otlp_http_gate(),
                otlp_http_probe_watch.clone(),
            );
            let mut shutdown = shutdown.clone();
            let app = Router::new()
                .route("/v1/metrics", any(otlp_http_handler))
                .fallback(otlp_http_fallback_handler)
                .with_state(state);
            let task = tokio::spawn(async move {
                let listener = match tokio::net::TcpListener::bind(addr).await {
                    Ok(listener) => listener,
                    Err(err) => {
                        tracing::warn!("otlp http bind failed: {}", err);
                        return;
                    }
                };
                let server = axum::serve(
                    listener,
                    app.into_make_service_with_connect_info::<SocketAddr>(),
                );
                let _ = server
                    .with_graceful_shutdown(async move { shutdown.wait().await })
                    .await;
            });
            tasks.push(task);
        }
    }

    if tasks.is_empty() {
        return;
    }

    shutdown.wait().await;
}

async fn ingest_prometheus_metrics(
    body: &str,
    endpoint: &str,
    config: &TelemetryConfig,
    bus: &EventBus,
    storage: &Storage,
    router: &MetricRouter,
) {
    let mut emitted = 0usize;
    for line in body.lines() {
        if emitted >= config.max_samples {
            break;
        }
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        if let Some((name, value, labels)) = parse_metric_line(line) {
            if !is_allowed(&name, config) {
                continue;
            }
            let key = metric_key(&name, &labels);
            if !router.allow(&key, MetricSource::Prometheus).await {
                continue;
            }
            router.record_prom(&key).await;
            emit_metric(
                name,
                value,
                config,
                bus,
                storage,
                "prometheus",
                endpoint,
                None,
                None,
            )
            .await;
            emitted += 1;
        }
    }
}

async fn ingest_otlp_request(
    request: ExportMetricsServiceRequest,
    config: &TelemetryConfig,
    bus: &EventBus,
    storage: &Storage,
    router: &MetricRouter,
    source: MetricSource,
    endpoint: &str,
) {
    let mut emitted = 0usize;
    for resource_metrics in request.resource_metrics {
        let (service_name, resource_attrs) =
            extract_resource_info(resource_metrics.resource.as_ref());
        for scope_metrics in resource_metrics.scope_metrics {
            let scope_name = scope_metrics
                .scope
                .as_ref()
                .map(|scope| scope.name.clone())
                .unwrap_or_default();
            for metric in scope_metrics.metrics {
                if emitted >= config.max_samples {
                    return;
                }
                emitted += emit_metric_from_otlp(
                    metric,
                    &service_name,
                    &scope_name,
                    &resource_attrs,
                    config,
                    bus,
                    storage,
                    router,
                    source,
                    endpoint,
                )
                .await;
            }
        }
    }
}

async fn emit_metric_from_otlp(
    metric: Metric,
    service_name: &Option<String>,
    scope_name: &str,
    resource_attrs: &HashMap<String, String>,
    config: &TelemetryConfig,
    bus: &EventBus,
    storage: &Storage,
    router: &MetricRouter,
    source: MetricSource,
    endpoint: &str,
) -> usize {
    let name = metric.name.clone();
    if !is_allowed(&name, config) {
        return 0;
    }

    let mut emitted = 0usize;
    if let Some(data) = metric.data {
        match data {
            Data::Gauge(Gauge { data_points }) => {
                for data_point in data_points {
                    if let Some(value) = number_value(&data_point) {
                        let attrs =
                            merge_attributes(resource_attrs, &data_point.attributes, scope_name);
                        let key = metric_key(&name, &attrs);
                        if router.allow(&key, source).await {
                            emitted += emit_metric(
                                name.clone(),
                                value,
                                config,
                                bus,
                                storage,
                                metric_source_label(source),
                                endpoint,
                                service_name.as_deref(),
                                Some(scope_name),
                            )
                            .await;
                        }
                    }
                }
            }
            Data::Sum(sum) => {
                emitted += handle_sum(
                    &name,
                    sum,
                    config,
                    bus,
                    storage,
                    router,
                    source,
                    endpoint,
                    service_name,
                    scope_name,
                    resource_attrs,
                )
                .await;
            }
            Data::Histogram(hist) => {
                emitted += handle_histogram(
                    &name,
                    hist,
                    config,
                    bus,
                    storage,
                    router,
                    source,
                    endpoint,
                    service_name,
                    scope_name,
                    resource_attrs,
                )
                .await;
            }
            Data::ExponentialHistogram(hist) => {
                emitted += handle_exponential_histogram(
                    &name,
                    hist,
                    config,
                    bus,
                    storage,
                    router,
                    source,
                    endpoint,
                    service_name,
                    scope_name,
                    resource_attrs,
                )
                .await;
            }
            Data::Summary(summary) => {
                emitted += handle_summary(
                    &name,
                    summary,
                    config,
                    bus,
                    storage,
                    router,
                    source,
                    endpoint,
                    service_name,
                    scope_name,
                    resource_attrs,
                )
                .await;
            }
        }
    }
    if !resource_attrs.is_empty() {
        let _ = resource_attrs;
    }
    emitted
}

async fn handle_sum(
    name: &str,
    sum: opentelemetry_proto::tonic::metrics::v1::Sum,
    config: &TelemetryConfig,
    bus: &EventBus,
    storage: &Storage,
    router: &MetricRouter,
    source: MetricSource,
    endpoint: &str,
    service_name: &Option<String>,
    scope_name: &str,
    resource_attrs: &HashMap<String, String>,
) -> usize {
    let mut emitted = 0usize;
    for data_point in sum.data_points {
        if let Some(value) = number_value(&data_point) {
            let attrs = merge_attributes(resource_attrs, &data_point.attributes, scope_name);
            let key = metric_key(name, &attrs);
            if router.allow(&key, source).await {
                emitted += emit_metric(
                    name.to_string(),
                    value,
                    config,
                    bus,
                    storage,
                    metric_source_label(source),
                    endpoint,
                    service_name.as_deref(),
                    Some(scope_name),
                )
                .await;
            }
        }
    }
    emitted
}

async fn handle_histogram(
    name: &str,
    hist: Histogram,
    config: &TelemetryConfig,
    bus: &EventBus,
    storage: &Storage,
    router: &MetricRouter,
    source: MetricSource,
    endpoint: &str,
    service_name: &Option<String>,
    scope_name: &str,
    resource_attrs: &HashMap<String, String>,
) -> usize {
    let mut emitted = 0usize;
    for data_point in hist.data_points {
        if let Some(value) = histogram_value(&data_point) {
            let attrs = merge_attributes(resource_attrs, &data_point.attributes, scope_name);
            let key = metric_key(name, &attrs);
            if router.allow(&key, source).await {
                emitted += emit_metric(
                    name.to_string(),
                    value,
                    config,
                    bus,
                    storage,
                    metric_source_label(source),
                    endpoint,
                    service_name.as_deref(),
                    Some(scope_name),
                )
                .await;
            }
        }
    }
    emitted
}

async fn handle_exponential_histogram(
    name: &str,
    hist: ExponentialHistogram,
    config: &TelemetryConfig,
    bus: &EventBus,
    storage: &Storage,
    router: &MetricRouter,
    source: MetricSource,
    endpoint: &str,
    service_name: &Option<String>,
    scope_name: &str,
    resource_attrs: &HashMap<String, String>,
) -> usize {
    let mut emitted = 0usize;
    for data_point in hist.data_points {
        if let Some(value) = exponential_histogram_value(&data_point) {
            let attrs = merge_attributes(resource_attrs, &data_point.attributes, scope_name);
            let key = metric_key(name, &attrs);
            if router.allow(&key, source).await {
                emitted += emit_metric(
                    name.to_string(),
                    value,
                    config,
                    bus,
                    storage,
                    metric_source_label(source),
                    endpoint,
                    service_name.as_deref(),
                    Some(scope_name),
                )
                .await;
            }
        }
    }
    emitted
}

async fn handle_summary(
    name: &str,
    summary: Summary,
    config: &TelemetryConfig,
    bus: &EventBus,
    storage: &Storage,
    router: &MetricRouter,
    source: MetricSource,
    endpoint: &str,
    service_name: &Option<String>,
    scope_name: &str,
    resource_attrs: &HashMap<String, String>,
) -> usize {
    let mut emitted = 0usize;
    for data_point in summary.data_points {
        if let Some(value) = summary_value(&data_point) {
            let attrs = merge_attributes(resource_attrs, &data_point.attributes, scope_name);
            let key = metric_key(name, &attrs);
            if router.allow(&key, source).await {
                emitted += emit_metric(
                    name.to_string(),
                    value,
                    config,
                    bus,
                    storage,
                    metric_source_label(source),
                    endpoint,
                    service_name.as_deref(),
                    Some(scope_name),
                )
                .await;
            }
        }
    }
    emitted
}

fn number_value(data_point: &NumberDataPoint) -> Option<f64> {
    match data_point.value.as_ref()? {
        NumberValue::AsDouble(value) => Some(*value),
        NumberValue::AsInt(value) => Some(*value as f64),
    }
}

fn histogram_value(data_point: &HistogramDataPoint) -> Option<f64> {
    let count = data_point.count;
    if count == 0 {
        return None;
    }
    data_point.sum.map(|sum| sum / count as f64)
}

fn exponential_histogram_value(data_point: &ExponentialHistogramDataPoint) -> Option<f64> {
    let count = data_point.count;
    if count == 0 {
        return None;
    }
    data_point.sum.map(|sum| sum / count as f64)
}

fn summary_value(data_point: &SummaryDataPoint) -> Option<f64> {
    let count = data_point.count;
    if count == 0 {
        return None;
    }
    Some(data_point.sum / count as f64)
}

fn metric_source_label(source: MetricSource) -> &'static str {
    match source {
        MetricSource::Prometheus => "prometheus",
        MetricSource::OtlpGrpc => "otlp_grpc",
        MetricSource::OtlpHttp => "otlp_http",
    }
}

async fn emit_metric(
    name: String,
    value: f64,
    config: &TelemetryConfig,
    bus: &EventBus,
    storage: &Storage,
    source: &str,
    endpoint: &str,
    service_name: Option<&str>,
    scope_name: Option<&str>,
) -> usize {
    let id = TELEMETRY_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut event = Event::new(
        id,
        config.source.clone(),
        EventKind::Observability,
        value,
        Severity::Medium,
    )
    .with_attr("metric", name)
    .with_attr("endpoint", endpoint.to_string())
    .with_attr("telemetry_source", source.to_string());

    if let Some(service) = service_name {
        event = event.with_attr("service", service.to_string());
    }
    if let Some(scope) = scope_name {
        if !scope.is_empty() {
            event = event.with_attr("scope", scope.to_string());
        }
    }

    bus.publish(event.clone());
    storage.record_event(event).await;
    1
}

fn parse_metric_line(line: &str) -> Option<(String, f64, HashMap<String, String>)> {
    let mut iter = line.split_whitespace();
    let metric = iter.next()?;
    let value = iter.next()?;
    let value = value.parse::<f64>().ok()?;
    if let Some(start) = metric.find('{') {
        let end = metric.rfind('}')?;
        let name = metric[..start].to_string();
        let labels = parse_labels(&metric[start + 1..end]);
        Some((name, value, labels))
    } else {
        Some((metric.to_string(), value, HashMap::new()))
    }
}

fn is_allowed(name: &str, config: &TelemetryConfig) -> bool {
    if !config.allow_exact.is_empty() && config.allow_exact.iter().any(|item| item == name) {
        return true;
    }
    if !config.allow_prefixes.is_empty() {
        return config
            .allow_prefixes
            .iter()
            .any(|prefix| name.starts_with(prefix));
    }
    true
}

fn extract_resource_info(resource: Option<&Resource>) -> (Option<String>, HashMap<String, String>) {
    let mut attrs = HashMap::new();
    let mut service_name = None;
    if let Some(resource) = resource {
        for attr in &resource.attributes {
            if let Some(value) = any_value_to_string(&attr.value) {
                if attr.key == "service.name" {
                    service_name = Some(value.clone());
                }
                attrs.insert(attr.key.clone(), value);
            }
        }
    }
    (service_name, attrs)
}

fn merge_attributes(
    resource_attrs: &HashMap<String, String>,
    data_point_attrs: &[KeyValue],
    scope_name: &str,
) -> HashMap<String, String> {
    let mut attrs = resource_attrs.clone();
    for attr in data_point_attrs {
        if let Some(value) = any_value_to_string(&attr.value) {
            attrs.insert(attr.key.clone(), value);
        }
    }
    if !scope_name.is_empty() {
        attrs.insert("otel.scope.name".to_string(), scope_name.to_string());
    }
    attrs
}

fn metric_key(name: &str, attrs: &HashMap<String, String>) -> String {
    if attrs.is_empty() {
        return name.to_string();
    }
    let mut pairs: Vec<(&String, &String)> = attrs.iter().collect();
    pairs.sort_by(|a, b| a.0.cmp(b.0).then_with(|| a.1.cmp(b.1)));
    let mut key = String::with_capacity(name.len() + pairs.len() * 16);
    key.push_str(name);
    for (k, v) in pairs {
        key.push('|');
        key.push_str(k);
        key.push('=');
        key.push_str(v);
    }
    key
}

fn parse_labels(raw: &str) -> HashMap<String, String> {
    let mut labels = HashMap::new();
    for pair in raw.split(',') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let (key, value) = match pair.split_once('=') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => continue,
        };
        let value = unquote(value);
        if !key.is_empty() {
            labels.insert(key.to_string(), value);
        }
    }
    labels
}

fn unquote(value: &str) -> String {
    let value = value.trim();
    if value.len() >= 2 && value.starts_with('\"') && value.ends_with('\"') {
        let inner = &value[1..value.len() - 1];
        inner.replace("\\\"", "\"").replace("\\\\", "\\")
    } else {
        value.to_string()
    }
}

fn any_value_to_string(
    value: &Option<opentelemetry_proto::tonic::common::v1::AnyValue>,
) -> Option<String> {
    let value = value.as_ref()?;
    match value.value.as_ref()? {
        opentelemetry_proto::tonic::common::v1::any_value::Value::StringValue(val) => {
            Some(val.clone())
        }
        opentelemetry_proto::tonic::common::v1::any_value::Value::IntValue(val) => {
            Some(val.to_string())
        }
        opentelemetry_proto::tonic::common::v1::any_value::Value::DoubleValue(val) => {
            Some(val.to_string())
        }
        opentelemetry_proto::tonic::common::v1::any_value::Value::BoolValue(val) => {
            Some(val.to_string())
        }
        _ => None,
    }
}

fn env_endpoints() -> Vec<String> {
    let mut endpoints = Vec::new();
    if let Ok(raw) = std::env::var("TRACEY_TELEMETRY_ENDPOINTS") {
        for part in raw.split(',') {
            let trimmed = part.trim();
            if !trimmed.is_empty() {
                endpoints.push(trimmed.to_string());
            }
        }
    }
    for key in [
        "PROMETHEUS_ENDPOINT",
        "PROMETHEUS_URL",
        "OTEL_PROMETHEUS_ENDPOINT",
    ] {
        if let Ok(value) = std::env::var(key) {
            if !value.trim().is_empty() {
                endpoints.push(value);
            }
        }
    }
    endpoints
}

fn default_local_endpoints() -> Vec<String> {
    vec![
        "http://127.0.0.1:8888/metrics".to_string(),
        "http://127.0.0.1:8889/metrics".to_string(),
        "http://127.0.0.1:9100/metrics".to_string(),
        "http://127.0.0.1:9464/metrics".to_string(),
    ]
}

fn is_loopback(url: &str) -> bool {
    let url = url.trim();
    url.starts_with("http://127.0.0.1")
        || url.starts_with("http://localhost")
        || url.starts_with("http://[::1]")
        || url.starts_with("https://127.0.0.1")
        || url.starts_with("https://localhost")
        || url.starts_with("https://[::1]")
}

#[derive(Clone)]
struct OtlpService {
    bus: EventBus,
    storage: Storage,
    config: TelemetryConfig,
    router: Arc<MetricRouter>,
    governance: std::sync::Arc<tokio::sync::RwLock<GovernanceState>>,
    auth: AuthGate,
    probe_watch: ProbeWatchHandle,
}

impl OtlpService {
    fn new(
        bus: EventBus,
        storage: Storage,
        config: TelemetryConfig,
        router: Arc<MetricRouter>,
        governance: std::sync::Arc<tokio::sync::RwLock<GovernanceState>>,
        auth: AuthGate,
        probe_watch: ProbeWatchHandle,
    ) -> Self {
        Self {
            bus,
            storage,
            config,
            router,
            governance,
            auth,
            probe_watch,
        }
    }
}

#[tonic::async_trait]
impl MetricsService for OtlpService {
    async fn export(
        &self,
        request: tonic::Request<ExportMetricsServiceRequest>,
    ) -> Result<tonic::Response<ExportMetricsServiceResponse>, tonic::Status> {
        let headers = metadata_to_header_map(request.metadata());
        if let Err(status) = self.auth.authorize_grpc(request.metadata()).await {
            observe_otlp_grpc_request(
                &self.probe_watch,
                &headers,
                grpc_status_to_http(status.code()),
                Some(false),
            )
            .await;
            return Err(status);
        }
        let state = self.governance.read().await;
        if !state.telemetry_enabled || !state.otlp_enabled {
            drop(state);
            observe_otlp_grpc_request(&self.probe_watch, &headers, StatusCode::OK, Some(true))
                .await;
            return Ok(tonic::Response::new(ExportMetricsServiceResponse {
                partial_success: None,
            }));
        }
        drop(state);
        let payload = request.into_inner();
        ingest_otlp_request(
            payload,
            &self.config,
            &self.bus,
            &self.storage,
            &self.router,
            MetricSource::OtlpGrpc,
            "otlp_grpc",
        )
        .await;
        observe_otlp_grpc_request(&self.probe_watch, &headers, StatusCode::OK, Some(true)).await;
        Ok(tonic::Response::new(ExportMetricsServiceResponse {
            partial_success: None,
        }))
    }
}

#[derive(Clone)]
struct OtlpHttpState {
    bus: EventBus,
    storage: Storage,
    config: TelemetryConfig,
    router: Arc<MetricRouter>,
    governance: std::sync::Arc<tokio::sync::RwLock<GovernanceState>>,
    auth: AuthGate,
    probe_watch: ProbeWatchHandle,
}

impl OtlpHttpState {
    fn new(
        bus: EventBus,
        storage: Storage,
        config: TelemetryConfig,
        router: Arc<MetricRouter>,
        governance: std::sync::Arc<tokio::sync::RwLock<GovernanceState>>,
        auth: AuthGate,
        probe_watch: ProbeWatchHandle,
    ) -> Self {
        Self {
            bus,
            storage,
            config,
            router,
            governance,
            auth,
            probe_watch,
        }
    }
}

async fn otlp_http_handler(
    State(state): State<OtlpHttpState>,
    remote: Option<ConnectInfo<SocketAddr>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, StatusCode> {
    let remote_addr = remote.map(|value| value.0);
    if method != Method::POST {
        observe_otlp_http_request(
            &state.probe_watch,
            remote_addr,
            method.as_str(),
            uri.path(),
            &headers,
            StatusCode::METHOD_NOT_ALLOWED,
            true,
            None,
        )
        .await;
        return Ok(StatusCode::METHOD_NOT_ALLOWED);
    }
    if let Err(code) = state.auth.authorize_http(&headers).await {
        observe_otlp_http_request(
            &state.probe_watch,
            remote_addr,
            method.as_str(),
            uri.path(),
            &headers,
            code,
            true,
            Some(false),
        )
        .await;
        return Err(code);
    }
    let guard = state.governance.read().await;
    if !guard.telemetry_enabled || !guard.otlp_enabled {
        drop(guard);
        observe_otlp_http_request(
            &state.probe_watch,
            remote_addr,
            method.as_str(),
            uri.path(),
            &headers,
            StatusCode::OK,
            true,
            Some(true),
        )
        .await;
        return Ok(StatusCode::OK);
    }
    drop(guard);
    let request = match ExportMetricsServiceRequest::decode(body.as_ref()) {
        Ok(request) => request,
        Err(_) => {
            observe_otlp_http_request(
                &state.probe_watch,
                remote_addr,
                method.as_str(),
                uri.path(),
                &headers,
                StatusCode::BAD_REQUEST,
                true,
                Some(true),
            )
            .await;
            return Err(StatusCode::BAD_REQUEST);
        }
    };
    ingest_otlp_request(
        request,
        &state.config,
        &state.bus,
        &state.storage,
        &state.router,
        MetricSource::OtlpHttp,
        "otlp_http",
    )
    .await;
    observe_otlp_http_request(
        &state.probe_watch,
        remote_addr,
        method.as_str(),
        uri.path(),
        &headers,
        StatusCode::OK,
        true,
        Some(true),
    )
    .await;
    Ok(StatusCode::OK)
}

async fn otlp_http_fallback_handler(
    State(state): State<OtlpHttpState>,
    remote: Option<ConnectInfo<SocketAddr>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> StatusCode {
    observe_otlp_http_request(
        &state.probe_watch,
        remote.map(|value| value.0),
        method.as_str(),
        uri.path(),
        &headers,
        StatusCode::NOT_FOUND,
        false,
        None,
    )
    .await;
    StatusCode::NOT_FOUND
}

async fn observe_otlp_http_request(
    probe_watch: &ProbeWatchHandle,
    remote_addr: Option<SocketAddr>,
    method: &str,
    path: &str,
    headers: &HeaderMap,
    status_code: StatusCode,
    known_route: bool,
    authorized: Option<bool>,
) {
    probe_watch
        .observe_http(ProbeObservation {
            remote_addr,
            method,
            path,
            status_code,
            headers,
            known_route,
            control_route: false,
            authorized,
        })
        .await;
}

async fn observe_otlp_grpc_request(
    probe_watch: &ProbeWatchHandle,
    headers: &HeaderMap,
    status_code: StatusCode,
    authorized: Option<bool>,
) {
    probe_watch
        .observe_http(ProbeObservation {
            remote_addr: None,
            method: "EXPORT",
            path: "/v1/metrics",
            status_code,
            headers,
            known_route: true,
            control_route: false,
            authorized,
        })
        .await;
}

fn metadata_to_header_map(metadata: &MetadataMap) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for entry in metadata.iter() {
        if let KeyAndValueRef::Ascii(key, value) = entry
            && let Ok(header_name) = axum::http::HeaderName::from_bytes(key.as_str().as_bytes())
            && let Ok(header_value) = axum::http::HeaderValue::from_bytes(value.as_bytes())
        {
            headers.append(header_name, header_value);
        }
    }
    headers
}

fn grpc_status_to_http(code: tonic::Code) -> StatusCode {
    match code {
        tonic::Code::Unauthenticated => StatusCode::UNAUTHORIZED,
        tonic::Code::PermissionDenied => StatusCode::FORBIDDEN,
        tonic::Code::InvalidArgument => StatusCode::BAD_REQUEST,
        tonic::Code::NotFound => StatusCode::NOT_FOUND,
        tonic::Code::AlreadyExists => StatusCode::CONFLICT,
        tonic::Code::ResourceExhausted => StatusCode::TOO_MANY_REQUESTS,
        tonic::Code::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        tonic::Code::DeadlineExceeded => StatusCode::GATEWAY_TIMEOUT,
        _ => StatusCode::BAD_REQUEST,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_metric_line_parses_labels_and_value() {
        let line = r#"node_cpu_seconds_total{cpu="0",mode="idle"} 12.5"#;
        let parsed = parse_metric_line(line).expect("line should parse");
        assert_eq!(parsed.0, "node_cpu_seconds_total");
        assert_eq!(parsed.1, 12.5);
        assert_eq!(parsed.2.get("cpu").map(String::as_str), Some("0"));
        assert_eq!(parsed.2.get("mode").map(String::as_str), Some("idle"));
    }

    #[test]
    fn parse_labels_unescapes_quotes_and_backslashes() {
        let labels = parse_labels(r#"a="hello \"world\"",b="c:\\path""#);
        assert_eq!(
            labels.get("a").map(String::as_str),
            Some(r#"hello "world""#)
        );
        assert_eq!(labels.get("b").map(String::as_str), Some(r#"c:\path"#));
    }

    #[test]
    fn metric_key_is_deterministic_across_map_order() {
        let mut a = HashMap::new();
        a.insert("host".to_string(), "a".to_string());
        a.insert("zone".to_string(), "1".to_string());
        let mut b = HashMap::new();
        b.insert("zone".to_string(), "1".to_string());
        b.insert("host".to_string(), "a".to_string());
        assert_eq!(metric_key("metric_name", &a), metric_key("metric_name", &b));
    }

    #[test]
    fn allow_rules_honor_exact_then_prefixes() {
        let mut cfg = TelemetryConfig::default();
        cfg.allow_exact = vec!["exact_metric".to_string()];
        cfg.allow_prefixes = vec!["node_".to_string()];
        assert!(is_allowed("exact_metric", &cfg));
        assert!(is_allowed("node_cpu", &cfg));
        assert!(!is_allowed("random", &cfg));
    }

    #[test]
    fn loopback_detection_handles_common_local_urls() {
        assert!(is_loopback("http://127.0.0.1:9100/metrics"));
        assert!(is_loopback("https://localhost/metrics"));
        assert!(is_loopback("http://[::1]:9464/metrics"));
        assert!(!is_loopback("http://10.0.0.5:9100/metrics"));
    }
}
