use crate::assets::HostObservation;
use crate::config::InventoryConfig;
use crate::discovery::AgentPresence;
use crate::event::now_ms;
use crate::shutdown::ShutdownListener;
use crate::storage::Storage;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnmanagedHost {
    pub host_id: String,
    pub ip: Option<String>,
    pub hostname: Option<String>,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub reason: String,
}

#[derive(Clone)]
pub struct Inventory {
    tx: mpsc::Sender<InventoryEvent>,
}

enum InventoryEvent {
    Agent(AgentPresence),
    Host(HostObservation),
}

impl Inventory {
    pub fn new(config: InventoryConfig, storage: Storage, mut shutdown: ShutdownListener) -> Self {
        let (tx, mut rx) = mpsc::channel::<InventoryEvent>(2048);

        tokio::spawn(async move {
            let mut agents: HashMap<String, Instant> = HashMap::new();
            let mut hosts: HashMap<String, (Instant, HostObservation)> = HashMap::new();
            let mut unmanaged_reported: HashMap<String, Instant> = HashMap::new();

            let agent_ttl = Duration::from_millis(config.agent_ttl_ms);
            let host_ttl = Duration::from_millis(config.host_ttl_ms);
            let resend_ttl = Duration::from_millis(config.unmanaged_resend_ms);
            let mut cleanup_tick = tokio::time::interval(Duration::from_millis(1000));

            loop {
                tokio::select! {
                    _ = shutdown.wait() => {
                        break;
                    }
                    _ = cleanup_tick.tick() => {
                        purge_expired(&mut agents, agent_ttl);
                        purge_expired(&mut unmanaged_reported, resend_ttl * 2);
                        purge_hosts(&mut hosts, host_ttl);
                    }
                    Some(event) = rx.recv() => {
                        match event {
                            InventoryEvent::Agent(presence) => {
                                agents.insert(presence.agent_id.clone(), Instant::now());
                                storage.record_agent(presence).await;
                            }
                            InventoryEvent::Host(host) => {
                                let now = Instant::now();
                                hosts.insert(host.host_id.clone(), (now, host.clone()));
                                storage.record_host(host.clone()).await;

                                if !agents.contains_key(&host.host_id) {
                                    let should_report = unmanaged_reported
                                        .get(&host.host_id)
                                        .map(|last| last.elapsed() >= resend_ttl)
                                        .unwrap_or(true);
                                    if should_report {
                                        unmanaged_reported.insert(host.host_id.clone(), Instant::now());
                                        let unmanaged = UnmanagedHost {
                                            host_id: host.host_id.clone(),
                                            ip: host.ip.clone(),
                                            hostname: host.hostname.clone(),
                                            first_seen_ms: now_ms(),
                                            last_seen_ms: now_ms(),
                                            reason: "no agent detected for host_id".to_string(),
                                        };
                                        storage.record_unmanaged(unmanaged).await;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });

        Self { tx }
    }

    pub async fn record_agent(&self, presence: AgentPresence) {
        let _ = self.tx.send(InventoryEvent::Agent(presence)).await;
    }

    pub async fn record_host(&self, host: HostObservation) {
        let _ = self.tx.send(InventoryEvent::Host(host)).await;
    }
}

fn purge_expired(map: &mut HashMap<String, Instant>, ttl: Duration) {
    map.retain(|_, last_seen| last_seen.elapsed() < ttl);
}

fn purge_hosts(map: &mut HashMap<String, (Instant, HostObservation)>, ttl: Duration) {
    map.retain(|_, (last_seen, _)| last_seen.elapsed() < ttl);
}
