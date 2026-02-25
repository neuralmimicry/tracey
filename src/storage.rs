use crate::assets::HostObservation;
use crate::discovery::AgentPresence;
use crate::event::Event;
use crate::governance::GovernanceUpdate;
use crate::inventory::UnmanagedHost;
use crate::shutdown::ShutdownListener;
use crate::swarm::Decision;
use crate::swarm::LearningSnapshot;
use crate::tuning::TuningUpdate;
use crate::update::UpdateRecord;
use serde::Serialize;
use std::path::PathBuf;
use tokio::fs::OpenOptions;
use tokio::io::{AsyncWriteExt, BufWriter};
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
    pub async fn new(path: PathBuf, mut shutdown: ShutdownListener) -> std::io::Result<Self> {
        let (tx, mut rx) = mpsc::channel::<StorageRecord>(2048);
        let file = OpenOptions::new().create(true).append(true).open(path).await?;
        let mut writer = BufWriter::new(file);

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown.wait() => {
                        break;
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
        let _ = self.tx.send(StorageRecord::Decision { payload: decision }).await;
    }

    pub async fn record_learning(&self, snapshot: LearningSnapshot) {
        let _ = self.tx.send(StorageRecord::Learning { payload: snapshot }).await;
    }

    pub async fn record_agent(&self, presence: AgentPresence) {
        let _ = self.tx.send(StorageRecord::AgentPresence { payload: presence }).await;
    }

    pub async fn record_host(&self, host: HostObservation) {
        let _ = self.tx.send(StorageRecord::HostObservation { payload: host }).await;
    }

    pub async fn record_unmanaged(&self, host: UnmanagedHost) {
        let _ = self.tx.send(StorageRecord::UnmanagedHost { payload: host }).await;
    }

    pub async fn record_tuning(&self, update: TuningUpdate) {
        let _ = self.tx.send(StorageRecord::TuningUpdate { payload: update }).await;
    }

    pub async fn record_update(&self, record: UpdateRecord) {
        let _ = self.tx.send(StorageRecord::UpdateRecord { payload: record }).await;
    }

    pub async fn record_governance(&self, update: GovernanceUpdate) {
        let _ = self.tx.send(StorageRecord::GovernanceUpdate { payload: update }).await;
    }
}
