//! Resource growth analysis and optional Gail-backed advisory hints.
//!
//! The worker consumes the bounded Continuum telemetry snapshot instead of the
//! hot event path so forecast math and optional AI calls stay off the collector
//! critical path. Local heuristics always remain available; Gail advice is an
//! asynchronous enrichment layer when explicitly configured.

use crate::config::ResourceForecastConfig;
use crate::continuum_telemetry::ContinuumTelemetryHandle;
use crate::event::now_ms;
use crate::shutdown::ShutdownListener;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ResourceForecastAiAdvice {
    pub summary: String,
    pub latency_focus: String,
    pub cpu_focus: String,
    pub memory_focus: String,
    pub power_focus: String,
    pub simulation_focus: String,
    pub confidence: Option<f64>,
    pub provider: Option<String>,
    pub model: Option<String>,
    pub generated_ms: u64,
    pub last_error: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ResourceForecastSimulationHint {
    pub cpu_scale_factor: f64,
    pub memory_scale_factor: f64,
    pub power_scale_factor: f64,
    pub estimated_cpu_cores: f64,
    pub estimated_memory_working_set_bytes: f64,
    pub estimated_network_bps: f64,
    pub estimated_power_w: f64,
    pub collector_backend: String,
    pub attribution_confidence: f64,
    pub estimated_flows: usize,
    pub udp_active_flows: usize,
    pub udp_drop_delta: u64,
    pub latency_pressure: f64,
    pub queue_pressure: f64,
    pub active_flows: usize,
    pub cross_network_flows: usize,
    pub dominant_process: String,
    pub dominant_remote_ip: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ResourceForecastSnapshot {
    pub ts_ms: u64,
    pub enabled: bool,
    pub status: String,
    pub sample_count: usize,
    pub traffic_growth_pct_per_min: f64,
    pub cross_network_growth_pct_per_min: f64,
    pub flow_growth_pct_per_min: f64,
    pub projected_total_bps_5m: f64,
    pub projected_total_bps_15m: f64,
    pub projected_cross_network_bps_5m: f64,
    pub projected_cross_network_bps_15m: f64,
    pub projected_active_flows_5m: f64,
    pub projected_active_flows_15m: f64,
    pub simulation: ResourceForecastSimulationHint,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ai_advice: Option<ResourceForecastAiAdvice>,
}

#[derive(Clone)]
pub struct ResourceForecastHandle {
    snapshot: Arc<RwLock<ResourceForecastSnapshot>>,
}

impl ResourceForecastHandle {
    pub fn disabled() -> Self {
        Self {
            snapshot: Arc::new(RwLock::new(ResourceForecastSnapshot {
                ts_ms: now_ms(),
                enabled: false,
                status: "disabled".to_string(),
                ..ResourceForecastSnapshot::default()
            })),
        }
    }

    pub async fn snapshot(&self) -> ResourceForecastSnapshot {
        self.snapshot.read().await.clone()
    }
}

pub fn spawn_resource_forecast(
    config: ResourceForecastConfig,
    telemetry: ContinuumTelemetryHandle,
    mut shutdown: ShutdownListener,
) -> ResourceForecastHandle {
    if !config.enabled {
        return ResourceForecastHandle::disabled();
    }

    let handle = ResourceForecastHandle::disabled();
    let snapshot = handle.snapshot.clone();
    tokio::spawn(async move {
        let client = if config.gail.enabled && !config.gail.base_url.trim().is_empty() {
            reqwest::Client::builder()
                .timeout(Duration::from_millis(config.gail.timeout_ms))
                .build()
                .ok()
        } else {
            None
        };
        let mut interval = tokio::time::interval(Duration::from_millis(config.poll_interval_ms));
        let mut history = VecDeque::new();
        let mut last_ai_advice: Option<ResourceForecastAiAdvice> = None;
        let mut last_ai_digest = String::new();
        let mut last_ai_refresh_ms = 0u64;

        loop {
            tokio::select! {
                _ = shutdown.wait() => {
                    tracing::info!("resource forecast worker shutting down");
                    break;
                }
                _ = interval.tick() => {
                    let telemetry_snapshot = telemetry.snapshot().await;
                    push_history_point(&mut history, &telemetry_snapshot, config.history_points);
                    let mut forecast = build_forecast(&history, &telemetry_snapshot);
                    forecast.enabled = true;
                    forecast.status = if history.len() >= 2 { "forecasting".to_string() } else { "collecting".to_string() };
                    forecast.ai_advice = last_ai_advice.clone();

                    if let Some(client) = &client
                        && should_refresh_ai(&config, forecast.ts_ms, last_ai_refresh_ms)
                    {
                        let digest = forecast_digest(&forecast, &telemetry_snapshot);
                        if digest != last_ai_digest {
                            match fetch_gail_advice(client, &config, &forecast, &telemetry_snapshot).await {
                                Ok(advice) => {
                                    last_ai_refresh_ms = forecast.ts_ms;
                                    last_ai_digest = digest;
                                    last_ai_advice = Some(advice.clone());
                                    forecast.ai_advice = Some(advice);
                                }
                                Err(error) => {
                                    let mut advice = last_ai_advice.unwrap_or_default();
                                    advice.generated_ms = forecast.ts_ms;
                                    advice.last_error = error;
                                    last_ai_advice = Some(advice.clone());
                                    forecast.ai_advice = Some(advice);
                                }
                            }
                        }
                    }

                    *snapshot.write().await = forecast;
                }
            }
        }
    });
    handle
}

#[derive(Clone, Copy)]
struct ForecastPoint {
    ts_ms: u64,
    attributed_total_bps: f64,
    cross_network_bps: f64,
    active_flows: f64,
}

fn push_history_point(
    history: &mut VecDeque<ForecastPoint>,
    telemetry: &crate::continuum_telemetry::ContinuumTelemetrySnapshot,
    max_points: usize,
) {
    history.push_back(ForecastPoint {
        ts_ms: telemetry.ts_ms.max(now_ms()),
        attributed_total_bps: telemetry
            .server
            .network
            .summary
            .attributed_total_bps
            .unwrap_or_default(),
        cross_network_bps: telemetry
            .server
            .network
            .summary
            .cross_network_bps
            .unwrap_or_default(),
        active_flows: telemetry.server.network.summary.active_flows as f64,
    });
    while history.len() > max_points.max(2) {
        history.pop_front();
    }
}

fn build_forecast(
    history: &VecDeque<ForecastPoint>,
    telemetry: &crate::continuum_telemetry::ContinuumTelemetrySnapshot,
) -> ResourceForecastSnapshot {
    let now = now_ms();
    let first = history.front().copied();
    let last = history.back().copied();
    let growth_total = growth_pct_per_min(first, last, |point| point.attributed_total_bps);
    let growth_cross = growth_pct_per_min(first, last, |point| point.cross_network_bps);
    let growth_flows = growth_pct_per_min(first, last, |point| point.active_flows);

    let current_total_bps = telemetry
        .server
        .network
        .summary
        .attributed_total_bps
        .unwrap_or_default();
    let current_cross_bps = telemetry
        .server
        .network
        .summary
        .cross_network_bps
        .unwrap_or_default();
    let current_active_flows = telemetry.server.network.summary.active_flows as f64;

    let projected_total_bps_5m =
        project_linear(first, last, |point| point.attributed_total_bps, 5.0).max(current_total_bps);
    let projected_total_bps_15m =
        project_linear(first, last, |point| point.attributed_total_bps, 15.0)
            .max(projected_total_bps_5m);
    let projected_cross_bps_5m =
        project_linear(first, last, |point| point.cross_network_bps, 5.0).max(current_cross_bps);
    let projected_cross_bps_15m =
        project_linear(first, last, |point| point.cross_network_bps, 15.0)
            .max(projected_cross_bps_5m);
    let projected_active_flows_5m =
        project_linear(first, last, |point| point.active_flows, 5.0).max(current_active_flows);
    let projected_active_flows_15m = project_linear(first, last, |point| point.active_flows, 15.0)
        .max(projected_active_flows_5m);

    let current_cpu_pct = telemetry
        .server
        .cpu_usage_pct
        .unwrap_or_default()
        .clamp(0.0, 100.0);
    let current_mem_used_pct = telemetry
        .server
        .mem_used_pct
        .unwrap_or_default()
        .clamp(0.0, 100.0);
    let current_gpu_power_w = telemetry
        .server
        .gpu_power_total_w
        .unwrap_or_default()
        .max(0.0);
    let queue_pressure = telemetry
        .server
        .network
        .summary
        .queue_pressure
        .unwrap_or_default()
        .clamp(0.0, 1.0);
    let attribution_confidence = telemetry
        .server
        .network
        .summary
        .attribution_confidence
        .unwrap_or(1.0)
        .clamp(0.0, 1.0);
    let udp_drop_delta = telemetry.server.network.summary.udp_drop_delta;
    let uncertainty_boost = ((1.0 - attribution_confidence) * 0.35
        + ((udp_drop_delta as f64 / telemetry.server.network.summary.udp_active_flows.max(1) as f64)
            / 8.0)
            .clamp(0.0, 1.0)
            * 0.15)
        .clamp(0.0, 0.45);
    let latency_pressure = telemetry
        .server
        .network
        .summary
        .latency_pressure
        .unwrap_or_default()
        .clamp(0.0, 1.0);

    let growth_multiplier = if current_total_bps > 0.0 {
        (projected_total_bps_15m / current_total_bps).clamp(1.0, 6.0)
    } else if projected_total_bps_15m > 0.0 {
        1.25
    } else {
        1.0
    };
    let cross_multiplier = if current_cross_bps > 0.0 {
        (projected_cross_bps_15m / current_cross_bps).clamp(1.0, 6.0)
    } else if projected_cross_bps_15m > 0.0 {
        1.15
    } else {
        1.0
    };

    let cpu_scale_factor = (1.0
        + (growth_multiplier - 1.0) * 0.60
        + latency_pressure * 0.25
        + queue_pressure * 0.15
        + uncertainty_boost * 0.12)
            .clamp(1.0, 4.0);
    let memory_scale_factor = (1.0
        + (growth_multiplier - 1.0) * 0.35
        + queue_pressure * 0.20
        + (current_mem_used_pct / 100.0) * 0.15
        + uncertainty_boost * 0.08)
        .clamp(1.0, 4.0);
    let power_scale_factor = (1.0
        + (cross_multiplier - 1.0) * 0.20
        + latency_pressure * 0.10
        + queue_pressure * 0.10
        + uncertainty_boost * 0.10)
        .clamp(1.0, 3.5);

    let estimated_cpu_cores =
        ((current_cpu_pct / 100.0) * num_cpus::get() as f64 * cpu_scale_factor).max(1.0);
    let working_set_bytes = telemetry
        .server
        .processes
        .iter()
        .filter_map(|process| process.mem_bytes)
        .sum::<f64>();
    let estimated_memory_working_set_bytes =
        (working_set_bytes * memory_scale_factor).max(working_set_bytes);
    let estimated_network_bps = projected_total_bps_15m.max(current_total_bps);
    let estimated_power_w = (current_gpu_power_w * power_scale_factor)
        + ((estimated_network_bps / 125_000_000.0) * 12.0);

    let dominant_process = telemetry
        .server
        .network
        .top_processes
        .first()
        .map(|process| process.name.clone())
        .unwrap_or_default();
    let dominant_remote_ip = telemetry
        .server
        .network
        .top_flows
        .first()
        .and_then(|flow| flow.remote_ip.clone())
        .unwrap_or_default();

    ResourceForecastSnapshot {
        ts_ms: now,
        enabled: true,
        status: String::new(),
        sample_count: history.len(),
        traffic_growth_pct_per_min: growth_total,
        cross_network_growth_pct_per_min: growth_cross,
        flow_growth_pct_per_min: growth_flows,
        projected_total_bps_5m,
        projected_total_bps_15m,
        projected_cross_network_bps_5m: projected_cross_bps_5m,
        projected_cross_network_bps_15m: projected_cross_bps_15m,
        projected_active_flows_5m,
        projected_active_flows_15m,
        simulation: ResourceForecastSimulationHint {
            cpu_scale_factor,
            memory_scale_factor,
            power_scale_factor,
            estimated_cpu_cores,
            estimated_memory_working_set_bytes,
            estimated_network_bps,
            estimated_power_w,
            collector_backend: telemetry.server.network.summary.collector_backend.clone(),
            attribution_confidence,
            estimated_flows: telemetry.server.network.summary.estimated_flows,
            udp_active_flows: telemetry.server.network.summary.udp_active_flows,
            udp_drop_delta,
            latency_pressure,
            queue_pressure,
            active_flows: telemetry.server.network.summary.active_flows,
            cross_network_flows: telemetry.server.network.summary.cross_network_flows,
            dominant_process,
            dominant_remote_ip,
        },
        ai_advice: None,
    }
}

fn growth_pct_per_min(
    first: Option<ForecastPoint>,
    last: Option<ForecastPoint>,
    selector: impl Fn(ForecastPoint) -> f64,
) -> f64 {
    let (Some(first), Some(last)) = (first, last) else {
        return 0.0;
    };
    if last.ts_ms <= first.ts_ms {
        return 0.0;
    }
    let start = selector(first);
    let end = selector(last);
    let elapsed_min = (last.ts_ms - first.ts_ms) as f64 / 60_000.0;
    if elapsed_min <= 0.0 {
        return 0.0;
    }
    if start <= 0.0 {
        return if end <= 0.0 { 0.0 } else { 100.0 };
    }
    ((end - start) / start) * 100.0 / elapsed_min
}

fn project_linear(
    first: Option<ForecastPoint>,
    last: Option<ForecastPoint>,
    selector: impl Fn(ForecastPoint) -> f64,
    minutes_forward: f64,
) -> f64 {
    let (Some(first), Some(last)) = (first, last) else {
        return 0.0;
    };
    let elapsed_min = (last.ts_ms.saturating_sub(first.ts_ms)) as f64 / 60_000.0;
    if elapsed_min <= 0.0 {
        return selector(last);
    }
    let start = selector(first);
    let end = selector(last);
    let slope_per_min = (end - start) / elapsed_min;
    (end + (slope_per_min * minutes_forward)).max(0.0)
}

fn should_refresh_ai(config: &ResourceForecastConfig, now_ms: u64, last_refresh_ms: u64) -> bool {
    config.gail.enabled
        && !config.gail.base_url.trim().is_empty()
        && (last_refresh_ms == 0
            || now_ms.saturating_sub(last_refresh_ms) >= config.gail.request_interval_ms)
}

fn forecast_digest(
    forecast: &ResourceForecastSnapshot,
    telemetry: &crate::continuum_telemetry::ContinuumTelemetrySnapshot,
) -> String {
    let payload = json!({
        "traffic_growth_pct_per_min": forecast.traffic_growth_pct_per_min,
        "cross_network_growth_pct_per_min": forecast.cross_network_growth_pct_per_min,
        "flow_growth_pct_per_min": forecast.flow_growth_pct_per_min,
        "projected_total_bps_15m": forecast.projected_total_bps_15m,
        "projected_active_flows_15m": forecast.projected_active_flows_15m,
        "cpu_usage_pct": telemetry.server.cpu_usage_pct,
        "mem_used_pct": telemetry.server.mem_used_pct,
        "network_summary": telemetry.server.network.summary,
        "dominant_process": forecast.simulation.dominant_process,
        "dominant_remote_ip": forecast.simulation.dominant_remote_ip,
    });
    blake3::hash(payload.to_string().as_bytes())
        .to_hex()
        .to_string()
}

async fn fetch_gail_advice(
    client: &reqwest::Client,
    config: &ResourceForecastConfig,
    forecast: &ResourceForecastSnapshot,
    telemetry: &crate::continuum_telemetry::ContinuumTelemetrySnapshot,
) -> Result<ResourceForecastAiAdvice, String> {
    let prompt = json!({
        "host": telemetry.identity.host,
        "network": telemetry.server.network.summary,
        "resource_forecast": forecast,
        "top_processes": telemetry.server.network.top_processes,
        "top_flows": telemetry.server.network.top_flows,
        "top_host_processes": telemetry.server.processes,
        "instruction": "Return compact JSON only with keys summary, latency_focus, cpu_focus, memory_focus, power_focus, simulation_focus, confidence. Keep every string under 160 characters."
    });
    let request_body = json!({
        "workflow": config.gail.workflow,
        "role": config.gail.role,
        "selection_mode": "fastest",
        "max_candidates": 1,
        "max_tokens": config.gail.max_tokens,
        "temperature": 0.1,
        "request_category": "tracey_resource_forecast",
        "messages": [
            {
                "role": "user",
                "content": prompt.to_string()
            }
        ]
    });

    let url = format!(
        "{}/v1/llm/complete",
        config.gail.base_url.trim_end_matches('/')
    );
    let mut request = client.post(url).json(&request_body);
    if let Some(token) = config.gail.bearer_token.as_deref() {
        request = request.bearer_auth(token);
    }
    let response = request.send().await.map_err(|error| error.to_string())?;
    if !response.status().is_success() {
        return Err(format!("gail returned HTTP {}", response.status()));
    }
    let payload = response
        .json::<GailCompletionResponse>()
        .await
        .map_err(|error| error.to_string())?;
    let parsed = parse_gail_text(&payload.text);
    Ok(ResourceForecastAiAdvice {
        summary: parsed.summary,
        latency_focus: parsed.latency_focus,
        cpu_focus: parsed.cpu_focus,
        memory_focus: parsed.memory_focus,
        power_focus: parsed.power_focus,
        simulation_focus: parsed.simulation_focus,
        confidence: parsed.confidence,
        provider: Some(payload.provider),
        model: Some(payload.model),
        generated_ms: now_ms(),
        last_error: String::new(),
    })
}

#[derive(Deserialize)]
struct GailCompletionResponse {
    text: String,
    provider: String,
    model: String,
}

#[derive(Default)]
struct ParsedAdvice {
    summary: String,
    latency_focus: String,
    cpu_focus: String,
    memory_focus: String,
    power_focus: String,
    simulation_focus: String,
    confidence: Option<f64>,
}

fn parse_gail_text(text: &str) -> ParsedAdvice {
    let trimmed = text.trim();
    let parsed = serde_json::from_str::<serde_json::Value>(trimmed)
        .ok()
        .or_else(|| {
            extract_json_object(trimmed)
                .and_then(|value| serde_json::from_str::<serde_json::Value>(&value).ok())
        });
    let Some(parsed) = parsed else {
        return ParsedAdvice {
            summary: trimmed.to_string(),
            ..ParsedAdvice::default()
        };
    };
    ParsedAdvice {
        summary: parsed
            .get("summary")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(trimmed)
            .to_string(),
        latency_focus: parsed
            .get("latency_focus")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string(),
        cpu_focus: parsed
            .get("cpu_focus")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string(),
        memory_focus: parsed
            .get("memory_focus")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string(),
        power_focus: parsed
            .get("power_focus")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string(),
        simulation_focus: parsed
            .get("simulation_focus")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string(),
        confidence: parsed.get("confidence").and_then(serde_json::Value::as_f64),
    }
}

fn extract_json_object(text: &str) -> Option<String> {
    let start = text.find('{')?;
    let end = text.rfind('}')?;
    (end > start).then(|| text[start..=end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_structured_gail_text() {
        let parsed = parse_gail_text(
            r#"{"summary":"scale cpu","latency_focus":"cut tail latency","confidence":0.8}"#,
        );
        assert_eq!(parsed.summary, "scale cpu");
        assert_eq!(parsed.latency_focus, "cut tail latency");
        assert_eq!(parsed.confidence, Some(0.8));
    }

    #[test]
    fn extracts_embedded_json() {
        let parsed = parse_gail_text(
            "Answer: {\"summary\":\"watch queues\",\"cpu_focus\":\"pin hot workers\"}",
        );
        assert_eq!(parsed.summary, "watch queues");
        assert_eq!(parsed.cpu_focus, "pin hot workers");
    }
}
