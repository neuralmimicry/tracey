use crate::assets::HostObservation;
use crate::config::StorageConfig;
use crate::discovery::AgentPresence;
use crate::event::{Event, now_ms};
use crate::governance::GovernanceUpdate;
use crate::inventory::UnmanagedHost;
use crate::shutdown::ShutdownListener;
use crate::swarm::Decision;
use crate::swarm::LearningSnapshot;
use crate::tuning::TuningUpdate;
use crate::update::UpdateRecord;
use serde::Serialize;
use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::time::Duration;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::sync::mpsc;

#[derive(Clone)]
pub struct Storage {
    tx: mpsc::Sender<StorageRecord>,
}

#[derive(Serialize, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StorageRecord {
    Event { payload: Event },
    Decision { payload: Decision },
    Learning { payload: LearningSnapshot },
    AgentPresence { payload: AgentPresence },
    HostObservation { payload: HostObservation },
    UnmanagedHost { payload: UnmanagedHost },
    TuningUpdate { payload: TuningUpdate },
    UpdateRecord { payload: UpdateRecord },
    GovernanceUpdate { payload: GovernanceUpdate },
}

impl Storage {
    pub async fn new(
        config: StorageConfig,
        mut shutdown: ShutdownListener,
    ) -> std::io::Result<Self> {
        let (tx, mut rx) = mpsc::channel::<StorageRecord>(2048);
        let path = config.log_path.clone();
        let mut writer = open_writer(&path).await?;
        let mut compact_tick =
            tokio::time::interval(Duration::from_millis(config.compact_interval_ms));

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown.wait() => {
                        break;
                    }
                    _ = compact_tick.tick() => {
                        if let Err(err) = maybe_compact(&path, &config, &mut writer).await {
                            tracing::warn!("Storage compaction failed: {}", err);
                        }
                    }
                    record = rx.recv() => {
                        let Some(record) = record else { break; };
                        match serde_json::to_vec(&record) {
                            Ok(mut line) => {
                                line.push(b'\n');
                                if let Err(err) = writer.write_all(&line).await {
                                    tracing::error!("Storage write failed: {}", err);
                                    break;
                                }
                            }
                            Err(err) => {
                                tracing::error!("Failed to serialize record: {}", err);
                            }
                        }
                    }
                }
            }
            let _ = writer.flush().await;
        });

        Ok(Self { tx })
    }

    pub async fn record_event(&self, event: Event) {
        let _ = self.tx.send(StorageRecord::Event { payload: event }).await;
    }

    pub async fn record_decision(&self, decision: Decision) {
        let _ = self
            .tx
            .send(StorageRecord::Decision { payload: decision })
            .await;
    }

    pub async fn record_learning(&self, snapshot: LearningSnapshot) {
        let _ = self
            .tx
            .send(StorageRecord::Learning { payload: snapshot })
            .await;
    }

    pub async fn record_agent(&self, presence: AgentPresence) {
        let _ = self
            .tx
            .send(StorageRecord::AgentPresence { payload: presence })
            .await;
    }

    pub async fn record_host(&self, host: HostObservation) {
        let _ = self
            .tx
            .send(StorageRecord::HostObservation { payload: host })
            .await;
    }

    pub async fn record_unmanaged(&self, host: UnmanagedHost) {
        let _ = self
            .tx
            .send(StorageRecord::UnmanagedHost { payload: host })
            .await;
    }

    pub async fn record_tuning(&self, update: TuningUpdate) {
        let _ = self
            .tx
            .send(StorageRecord::TuningUpdate { payload: update })
            .await;
    }

    pub async fn record_update(&self, record: UpdateRecord) {
        let _ = self
            .tx
            .send(StorageRecord::UpdateRecord { payload: record })
            .await;
    }

    pub async fn record_governance(&self, update: GovernanceUpdate) {
        let _ = self
            .tx
            .send(StorageRecord::GovernanceUpdate { payload: update })
            .await;
    }
}

#[derive(Serialize)]
struct SummaryCount {
    key: String,
    count: u64,
}

#[derive(Serialize)]
struct LogSummary {
    ts_ms: u64,
    truncated_lines: u64,
    retained_lines: u64,
    truncated_from_ts_ms: Option<u64>,
    truncated_to_ts_ms: Option<u64>,
    invalid_lines: u64,
    by_type: Vec<SummaryCount>,
    by_key: Vec<SummaryCount>,
}

async fn open_writer(path: &PathBuf) -> std::io::Result<BufWriter<File>> {
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await?;
    Ok(BufWriter::new(file))
}

async fn maybe_compact(
    path: &PathBuf,
    config: &StorageConfig,
    writer: &mut BufWriter<File>,
) -> std::io::Result<()> {
    if config.max_bytes == 0 || config.retain_lines == 0 || config.compact_interval_ms == 0 {
        return Ok(());
    }
    let meta = match tokio::fs::metadata(path).await {
        Ok(meta) => meta,
        Err(_) => return Ok(()),
    };
    if meta.len() <= config.max_bytes {
        return Ok(());
    }
    writer.flush().await?;
    compact_log(path, config).await?;
    *writer = open_writer(path).await?;
    Ok(())
}

async fn compact_log(path: &PathBuf, config: &StorageConfig) -> std::io::Result<()> {
    let total_lines = count_lines(path).await?;
    if total_lines <= config.retain_lines as u64 {
        return Ok(());
    }

    let cut_lines = total_lines - config.retain_lines as u64;
    let file = File::open(path).await?;
    let mut reader = BufReader::new(file);
    let mut idx: u64 = 0;
    let mut line = String::new();
    let mut tail: VecDeque<String> = VecDeque::with_capacity(config.retain_lines);

    let mut by_type: HashMap<String, u64> = HashMap::new();
    let mut by_key: HashMap<String, u64> = HashMap::new();
    let mut invalid_lines = 0u64;
    let mut ts_min: Option<u64> = None;
    let mut ts_max: Option<u64> = None;

    loop {
        line.clear();
        let bytes = reader.read_line(&mut line).await?;
        if bytes == 0 {
            break;
        }
        idx += 1;
        if idx <= cut_lines {
            ingest_summary_line(
                line.trim_end_matches('\n'),
                &mut by_type,
                &mut by_key,
                &mut invalid_lines,
                &mut ts_min,
                &mut ts_max,
            );
        } else {
            if tail.len() == config.retain_lines {
                tail.pop_front();
            }
            tail.push_back(line.clone());
        }
    }

    let summary = LogSummary {
        ts_ms: now_ms(),
        truncated_lines: cut_lines,
        retained_lines: tail.len() as u64,
        truncated_from_ts_ms: ts_min,
        truncated_to_ts_ms: ts_max,
        invalid_lines,
        by_type: top_counts(by_type, config.summary_top_keys),
        by_key: top_counts(by_key, config.summary_top_keys),
    };

    let tmp_path = path.with_extension("compact");
    let mut output = BufWriter::new(File::create(&tmp_path).await?);
    let summary_record = serde_json::json!({
        "type": "log_summary",
        "payload": summary,
    });
    let mut summary_line = serde_json::to_vec(&summary_record).unwrap_or_default();
    summary_line.push(b'\n');
    output.write_all(&summary_line).await?;

    for mut kept in tail {
        if !kept.ends_with('\n') {
            kept.push('\n');
        }
        output.write_all(kept.as_bytes()).await?;
    }
    output.flush().await?;
    tokio::fs::rename(&tmp_path, path).await?;
    Ok(())
}

async fn count_lines(path: &PathBuf) -> std::io::Result<u64> {
    let file = File::open(path).await?;
    let mut reader = BufReader::new(file);
    let mut count = 0u64;
    let mut line = String::new();
    loop {
        line.clear();
        let bytes = reader.read_line(&mut line).await?;
        if bytes == 0 {
            break;
        }
        count += 1;
    }
    Ok(count)
}

fn ingest_summary_line(
    line: &str,
    by_type: &mut HashMap<String, u64>,
    by_key: &mut HashMap<String, u64>,
    invalid_lines: &mut u64,
    ts_min: &mut Option<u64>,
    ts_max: &mut Option<u64>,
) -> bool {
    if line.trim().is_empty() {
        return false;
    }
    let value: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(_) => {
            *invalid_lines = invalid_lines.saturating_add(1);
            return false;
        }
    };
    let typ = value
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    *by_type.entry(typ.to_string()).or_insert(0) += 1;
    if let Some(payload) = value.get("payload") {
        if let Some(key) = summary_key(typ, payload) {
            *by_key.entry(key).or_insert(0) += 1;
        }
        if let Some(ts) = extract_ts_ms(payload, &value) {
            *ts_min = Some(ts_min.map(|min| min.min(ts)).unwrap_or(ts));
            *ts_max = Some(ts_max.map(|max| max.max(ts)).unwrap_or(ts));
        }
    }
    true
}

fn extract_ts_ms(payload: &Value, root: &Value) -> Option<u64> {
    payload
        .get("ts_ms")
        .and_then(|v| v.as_u64())
        .or_else(|| root.get("ts_ms").and_then(|v| v.as_u64()))
}

fn summary_key(typ: &str, payload: &Value) -> Option<String> {
    match typ {
        "event" => {
            let source = payload
                .get("source")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let kind = payload
                .get("kind")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let metric = payload
                .get("attributes")
                .and_then(|v| v.get("metric"))
                .and_then(|v| v.as_str());
            if let Some(metric) = metric {
                Some(format!("event:{}:{}:{}", source, kind, metric))
            } else {
                Some(format!("event:{}:{}", source, kind))
            }
        }
        "decision" => {
            let action = payload
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let kind = payload
                .get("kind")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            Some(format!("decision:{}:{}", action, kind))
        }
        "governance_update" => {
            let posture = payload
                .get("posture")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            Some(format!("governance:{}", posture))
        }
        "update_record" => {
            let status = payload
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            Some(format!("update:{}", status))
        }
        "unmanaged_host" => {
            let reason = payload
                .get("reason")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            Some(format!("unmanaged:{}", reason))
        }
        "host_observation" => {
            let source = payload
                .get("source")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            Some(format!("host_observation:{}", source))
        }
        "tuning_update" => Some("tuning_update".to_string()),
        "agent_presence" => Some("agent_presence".to_string()),
        "learning" => Some("learning".to_string()),
        _ => None,
    }
}

fn top_counts(map: HashMap<String, u64>, limit: usize) -> Vec<SummaryCount> {
    let mut entries: Vec<SummaryCount> = map
        .into_iter()
        .map(|(key, count)| SummaryCount { key, count })
        .collect();
    entries.sort_by(|a, b| b.count.cmp(&a.count));
    if entries.len() > limit {
        entries.truncate(limit);
    }
    entries
}
