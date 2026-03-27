//! Refiner service integration: health monitoring and security feed ingestion.

use crate::bus::EventBus;
use crate::config::RefinerTrackingConfig;
use crate::event::{Event, EventKind, Severity};
use crate::shutdown::ShutdownListener;
use crate::storage::Storage;
use serde::Deserialize;
use serde_json::Value;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};

static REFINER_EVENT_COUNTER: AtomicU64 = AtomicU64::new(5_000_000);

#[derive(Debug, Clone)]
struct HealthProbe {
    healthy: bool,
    severity: Severity,
    signal: f64,
    message: String,
    queue_depth: Option<u64>,
    queue_capacity: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct SecurityFindingInput {
    service: Option<String>,
    image: Option<String>,
    severity: Option<String>,
    cvss: Option<f64>,
    cve: Option<String>,
    title: Option<String>,
    scanner: Option<String>,
    status: Option<String>,
    source: Option<String>,
    finding_id: Option<String>,
}

pub async fn spawn_refiner_tracking(
    bus: EventBus,
    storage: Storage,
    config: RefinerTrackingConfig,
    mut shutdown: ShutdownListener,
) {
    if !config.enabled {
        tracing::info!("refiner tracking disabled");
        return;
    }

    tracing::info!(
        health_url = %config.health_url,
        feed_path = %config.security_feed_path.display(),
        "refiner tracking enabled"
    );

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_millis(config.timeout_ms))
        .build()
    {
        Ok(client) => client,
        Err(err) => {
            tracing::warn!("refiner tracking client init failed: {}", err);
            return;
        }
    };

    let mut feed_offset = 0u64;
    let mut ticker = tokio::time::interval(Duration::from_millis(config.poll_interval_ms));
    let mut last_health_state: Option<bool> = None;

    loop {
        tokio::select! {
            _ = shutdown.wait() => {
                tracing::info!("refiner tracking shutting down");
                break;
            }
            _ = ticker.tick() => {
                let probe = probe_health(&client, &config).await;
                let state_changed = last_health_state.map(|v| v != probe.healthy).unwrap_or(true);
                if state_changed || !probe.healthy {
                    emit_health_event(&bus, &storage, &config, probe.clone()).await;
                }
                last_health_state = Some(probe.healthy);

                if let Err(err) = read_security_feed(&config, &mut feed_offset, &bus, &storage).await {
                    tracing::warn!("refiner security feed read failed: {}", err);
                }
            }
        }
    }
}

async fn probe_health(client: &reqwest::Client, config: &RefinerTrackingConfig) -> HealthProbe {
    let request = client.get(&config.health_url).send().await;
    let response = match request {
        Ok(resp) => resp,
        Err(err) => {
            return HealthProbe {
                healthy: false,
                severity: Severity::Critical,
                signal: 0.98,
                message: format!("health request failed: {}", err),
                queue_depth: None,
                queue_capacity: None,
            };
        }
    };

    let status_code = response.status();
    let body = match response.text().await {
        Ok(text) => text,
        Err(err) => {
            return HealthProbe {
                healthy: false,
                severity: Severity::High,
                signal: 0.92,
                message: format!("health response read failed: {}", err),
                queue_depth: None,
                queue_capacity: None,
            };
        }
    };

    if !status_code.is_success() {
        return HealthProbe {
            healthy: false,
            severity: Severity::Critical,
            signal: 0.99,
            message: format!("health endpoint returned status {}", status_code.as_u16()),
            queue_depth: None,
            queue_capacity: None,
        };
    }

    let parsed: Value = serde_json::from_str(&body).unwrap_or_else(|_| Value::Null);
    let status = parsed
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_lowercase();
    let queue_depth = parsed
        .get("job_actions")
        .and_then(|v| v.get("queue_depth"))
        .and_then(Value::as_u64);
    let queue_capacity = parsed
        .get("job_actions")
        .and_then(|v| v.get("queue_capacity"))
        .and_then(Value::as_u64);

    let mut healthy = status == "ok";
    let mut severity = Severity::Low;
    let mut signal = 0.20;
    let mut message = "refiner health is ok".to_string();

    if !healthy {
        severity = Severity::High;
        signal = 0.91;
        message = format!("refiner health status={} (expected ok)", status);
    } else if let (Some(depth), Some(capacity)) = (queue_depth, queue_capacity) {
        if capacity > 0 {
            let utilization = depth as f64 / capacity as f64;
            if utilization >= 0.90 {
                healthy = false;
                severity = Severity::High;
                signal = 0.88;
                message = format!(
                    "refiner queue pressure high (depth={} capacity={} utilization={:.2})",
                    depth, capacity, utilization
                );
            } else if utilization >= 0.75 {
                healthy = false;
                severity = Severity::Medium;
                signal = 0.72;
                message = format!(
                    "refiner queue pressure elevated (depth={} capacity={} utilization={:.2})",
                    depth, capacity, utilization
                );
            }
        }
    }

    HealthProbe {
        healthy,
        severity,
        signal,
        message,
        queue_depth,
        queue_capacity,
    }
}

async fn emit_health_event(
    bus: &EventBus,
    storage: &Storage,
    config: &RefinerTrackingConfig,
    probe: HealthProbe,
) {
    let source = if probe.healthy {
        format!("{}_health_recovery", config.source)
    } else {
        format!("{}_health", config.source)
    };
    let mut event = Event::new(
        next_event_id(),
        source,
        EventKind::Observability,
        probe.signal,
        probe.severity,
    )
    .with_attr("service", config.service_name.clone())
    .with_attr("health_url", config.health_url.clone())
    .with_attr("healthy", probe.healthy.to_string())
    .with_attr("message", probe.message);

    if let Some(depth) = probe.queue_depth {
        event = event.with_attr("queue_depth", depth.to_string());
    }
    if let Some(capacity) = probe.queue_capacity {
        event = event.with_attr("queue_capacity", capacity.to_string());
    }

    bus.publish(event.clone());
    storage.record_event(event).await;
}

async fn read_security_feed(
    config: &RefinerTrackingConfig,
    offset: &mut u64,
    bus: &EventBus,
    storage: &Storage,
) -> std::io::Result<()> {
    if !config.security_feed_path.exists() {
        return Ok(());
    }

    let mut file = File::open(&config.security_feed_path).await?;
    let metadata = file.metadata().await?;
    if metadata.len() < *offset {
        *offset = 0;
    }

    file.seek(std::io::SeekFrom::Start(*offset)).await?;
    let mut reader = BufReader::new(file);
    let mut line = String::new();

    loop {
        line.clear();
        let bytes = reader.read_line(&mut line).await?;
        if bytes == 0 {
            break;
        }
        if let Ok(input) = serde_json::from_str::<SecurityFindingInput>(line.trim()) {
            if let Some(event) = finding_to_event(config, input) {
                bus.publish(event.clone());
                storage.record_event(event).await;
            }
        }
    }

    *offset = reader.stream_position().await?;
    Ok(())
}

fn finding_to_event(config: &RefinerTrackingConfig, input: SecurityFindingInput) -> Option<Event> {
    let service = input.service.unwrap_or_default();
    let image = input.image.unwrap_or_default();
    let service_match = !service.is_empty() && service == config.service_name;
    let image_match = !image.is_empty()
        && image
            .to_lowercase()
            .contains(&config.service_name.to_lowercase());
    if !service_match && !image_match {
        return None;
    }

    let severity_raw = input
        .severity
        .unwrap_or_else(|| "medium".to_string())
        .to_lowercase();
    let (severity, signal) = match severity_raw.as_str() {
        "critical" => (Severity::Critical, 0.99),
        "high" => (Severity::High, 0.90),
        "medium" => (Severity::Medium, 0.74),
        "low" => (Severity::Low, 0.58),
        _ => (Severity::Medium, 0.70),
    };

    let source = input
        .source
        .unwrap_or_else(|| format!("{}_security_feed", config.source));
    let mut event = Event::new(
        next_event_id(),
        source,
        EventKind::Observability,
        signal,
        severity,
    )
    .with_attr("service", config.service_name.clone())
    .with_attr("feed_path", config.security_feed_path.display().to_string())
    .with_attr("finding_severity", severity_raw);

    if !service.is_empty() {
        event = event.with_attr("finding_service", service);
    }
    if !image.is_empty() {
        event = event.with_attr("image", image);
    }
    if let Some(cvss) = input.cvss {
        event = event.with_attr("cvss", format!("{:.2}", cvss));
    }
    if let Some(cve) = input.cve {
        event = event.with_attr("cve", cve);
    }
    if let Some(title) = input.title {
        event = event.with_attr("title", title);
    }
    if let Some(scanner) = input.scanner {
        event = event.with_attr("scanner", scanner);
    }
    if let Some(status) = input.status {
        event = event.with_attr("status", status);
    }
    if let Some(finding_id) = input.finding_id {
        event = event.with_attr("finding_id", finding_id);
    }

    Some(event)
}

fn next_event_id() -> u64 {
    REFINER_EVENT_COUNTER.fetch_add(1, Ordering::Relaxed)
}
