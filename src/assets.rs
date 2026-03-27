//! External asset feed ingestion (JSONL) with normalization into host observations.

use crate::config::AssetFeedConfig;
use crate::event::now_ms;
use crate::governance::GovernanceState;
use crate::inventory::Inventory;
use crate::shutdown::ShutdownListener;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};
use tokio::time::Duration;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HostObservation {
    pub host_id: String,
    pub ip: Option<String>,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub source: String,
    pub ts_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct HostObservationInput {
    pub host_id: Option<String>,
    pub ip: Option<String>,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub source: Option<String>,
    pub ts_ms: Option<u64>,
}

pub async fn spawn_asset_feed(
    config: AssetFeedConfig,
    inventory: Inventory,
    mut shutdown: ShutdownListener,
    governance_state: std::sync::Arc<tokio::sync::RwLock<GovernanceState>>,
) {
    if !config.enabled {
        tracing::info!("asset feed disabled");
        return;
    }

    tracing::info!(path = %config.path.display(), "asset feed enabled");
    let mut offset = 0u64;
    let mut ticker = tokio::time::interval(Duration::from_millis(config.poll_interval_ms));

    loop {
        tokio::select! {
            _ = shutdown.wait() => {
                tracing::info!("asset feed shutting down");
                break;
            }
            _ = ticker.tick() => {
                if !governance_state.read().await.asset_feed_enabled {
                    continue;
                }
                if let Err(err) = read_feed(&config.path, &config.source, &mut offset, &inventory).await {
                    tracing::warn!("asset feed read failed: {}", err);
                }
            }
        }
    }
}

async fn read_feed(
    path: &PathBuf,
    source: &str,
    offset: &mut u64,
    inventory: &Inventory,
) -> std::io::Result<()> {
    if !path.exists() {
        return Ok(());
    }

    let mut file = File::open(path).await?;
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
        if let Ok(input) = serde_json::from_str::<HostObservationInput>(line.trim()) {
            let observation = normalize_observation(input, source);
            inventory.record_host(observation).await;
        }
    }

    let pos = reader.stream_position().await?;
    *offset = pos;
    Ok(())
}

fn normalize_observation(input: HostObservationInput, source: &str) -> HostObservation {
    let host_id = input
        .host_id
        .or_else(|| input.hostname.clone())
        .or_else(|| input.mac.clone())
        .or_else(|| input.ip.clone())
        .unwrap_or_else(|| "unknown".to_string());

    HostObservation {
        host_id,
        ip: input.ip,
        mac: input.mac,
        hostname: input.hostname,
        os: input.os,
        source: input.source.unwrap_or_else(|| source.to_string()),
        ts_ms: input.ts_ms.unwrap_or_else(now_ms),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_observation_prefers_explicit_host_id() {
        let observation = normalize_observation(
            HostObservationInput {
                host_id: Some("asset-1".to_string()),
                ip: Some("10.0.0.1".to_string()),
                mac: Some("aa:bb:cc:dd:ee:ff".to_string()),
                hostname: Some("srv".to_string()),
                os: Some("linux".to_string()),
                source: None,
                ts_ms: Some(123),
            },
            "feed",
        );
        assert_eq!(observation.host_id, "asset-1");
        assert_eq!(observation.source, "feed");
        assert_eq!(observation.ts_ms, 123);
    }

    #[test]
    fn normalize_observation_falls_back_through_identity_fields() {
        let observation = normalize_observation(
            HostObservationInput {
                host_id: None,
                ip: Some("10.0.0.2".to_string()),
                mac: Some("aa:bb:cc:dd:ee:11".to_string()),
                hostname: Some("host-2".to_string()),
                os: None,
                source: Some("cmdb".to_string()),
                ts_ms: None,
            },
            "feed",
        );
        assert_eq!(observation.host_id, "host-2");
        assert_eq!(observation.source, "cmdb");
    }
}
