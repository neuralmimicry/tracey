//! Low-overhead host socket attribution collector.
//!
//! The preferred backend correlates `/proc/net/*` socket tables with
//! `/proc/<pid>/fd` ownership so Tracey can attribute live network sockets to
//! processes without packet capture. When Linux exposes TCP byte counters
//! through `TCP_INFO`, the collector derives per-flow throughput between
//! samples. On non-Linux systems the collector falls back to `lsof`, which is
//! less detailed but still provides process-to-port attribution with low
//! overhead. UDP remains heuristic-only without eBPF, so the collector exposes
//! explicit confidence and drop/activity estimates to downstream consumers.

use crate::bus::EventBus;
use crate::config::EmbeddedConfig;
use crate::event::{Event, EventKind, Severity, now_ms};
use crate::network_ebpf::NetworkEbpfMonitor;
use crate::storage::Storage;
#[cfg(not(target_os = "linux"))]
use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::ffi::CStr;
#[cfg(not(target_os = "linux"))]
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::fs;
#[cfg(not(target_os = "linux"))]
use tokio::process::Command;

const HISTORY_POINTS: usize = 24;
const MAX_CMDLINE_LEN: usize = 320;
const MAX_CGROUP_LEN: usize = 192;
const MAX_EXE_LEN: usize = 192;
const UDP_DROP_ESTIMATED_BYTES: f64 = 1_500.0;

static NETWORK_EVENT_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CollectorBackend {
    Procfs,
    #[cfg(not(target_os = "linux"))]
    Lsof,
}

impl CollectorBackend {
    fn as_str(self) -> &'static str {
        match self {
            Self::Procfs => "procfs",
            #[cfg(not(target_os = "linux"))]
            Self::Lsof => "lsof",
        }
    }

    fn base_confidence(self) -> f64 {
        match self {
            Self::Procfs => 0.92,
            #[cfg(not(target_os = "linux"))]
            Self::Lsof => 0.68,
        }
    }
}

struct BackendSnapshot {
    backend: CollectorBackend,
    sockets: Vec<AttributedSocket>,
    owner_misses: usize,
}

struct AttributedSocket {
    socket: SocketEntry,
    owner: SocketOwner,
    backend: CollectorBackend,
    base_confidence: f64,
}

struct RateSample {
    rx_bps: f64,
    tx_bps: f64,
    bytes_estimated: bool,
    attribution_confidence: f64,
    udp_drop_delta: u64,
}

#[derive(Default)]
pub struct NetworkAttributionCollector {
    last_sample: Option<Instant>,
    owner_cache: HashMap<u64, CachedSocketOwner>,
    flow_prev: HashMap<FlowKey, FlowCounters>,
    flow_rate_peak: HashMap<String, f64>,
    process_rate_peak: HashMap<String, f64>,
    queue_peak: HashMap<String, f64>,
    history: VecDeque<SummaryPoint>,
    ebpf: Option<NetworkEbpfMonitor>,
}

impl NetworkAttributionCollector {
    pub fn new(ebpf: Option<NetworkEbpfMonitor>) -> Self {
        Self {
            ebpf,
            ..Self::default()
        }
    }

    pub async fn shutdown(&mut self) {
        if let Some(monitor) = self.ebpf.as_mut() {
            monitor.shutdown().await;
        }
    }

    pub async fn collect(&mut self, bus: &EventBus, storage: &Storage, config: &EmbeddedConfig) {
        let elapsed = match self.last_sample.replace(Instant::now()) {
            Some(last) if last.elapsed() < Duration::from_millis(config.network_window_ms) => {
                self.last_sample = Some(last);
                return;
            }
            Some(last) => last.elapsed().as_secs_f64().max(0.001),
            None => return,
        };

        let ebpf_snapshot = if let Some(monitor) = self.ebpf.as_mut() {
            Some(monitor.sample().await)
        } else {
            None
        };
        if !config.network_attribution_enabled {
            if ebpf_snapshot.is_none() {
                return;
            }
            emit_ebpf_metrics(bus, storage, config, ebpf_snapshot.as_ref(), "ebpf").await;
            return;
        }

        let interfaces = collect_interface_inventory();
        let arp_cache = read_arp_cache().await;
        let BackendSnapshot {
            backend,
            sockets,
            owner_misses,
        } = self.collect_backend_snapshot(config).await;
        let collector_backend = if ebpf_snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot.active)
        {
            format!("{}+ebpf", backend.as_str())
        } else {
            backend.as_str().to_string()
        };

        let sampled_ms = now_ms();
        let mut top_flows = Vec::new();
        let mut top_listeners = Vec::new();
        let mut process_totals: HashMap<u32, ProcessAggregate> = HashMap::new();
        let mut remote_endpoints = HashSet::new();
        let mut total_attributed_rx_bps = 0.0;
        let mut total_attributed_tx_bps = 0.0;
        let mut cross_network_bps = 0.0;
        let mut active_flows = 0usize;
        let mut established_flows = 0usize;
        let mut listeners = 0usize;
        let mut cross_network_flows = 0usize;
        let mut lan_flows = 0usize;
        let mut local_host_flows = 0usize;
        let mut unknown_remote_mac_flows = 0usize;
        let mut estimated_flows = 0usize;
        let mut udp_active_flows = 0usize;
        let mut udp_estimated_total_bps = 0.0;
        let mut udp_drop_delta_total = 0u64;
        let mut queue_total_bytes = 0.0;
        let mut max_rtt_ms: f64 = 0.0;
        let mut retransmit_total = 0u64;
        let mut attribution_confidence_total = 0.0;
        let mut attribution_confidence_samples = 0usize;

        self.flow_prev.retain(|key, _| {
            sockets.iter().any(|entry| {
                let socket = &entry.socket;
                socket.inode == key.inode
                    && socket.protocol == key.protocol
                    && socket.local_ip == key.local_ip
                    && socket.local_port == key.local_port
                    && socket.remote_ip == key.remote_ip
                    && socket.remote_port == key.remote_port
                    && socket.pid == key.pid
            })
        });

        for entry in sockets {
            let AttributedSocket {
                mut socket,
                owner,
                backend: socket_backend,
                base_confidence,
            } = entry;
            socket.pid = owner.pid;
            let scope = classify_socket_scope(&socket, &interfaces);
            if scope.same_lan {
                lan_flows += 1;
            }
            if scope.local_host {
                local_host_flows += 1;
            }
            if scope.cross_network {
                cross_network_flows += 1;
            }

            let local_iface = interfaces.iface_for_ip(&socket.local_ip);
            let local_mac = local_iface.and_then(|addr| addr.mac.clone());
            let remote_mac = match socket.remote_ip {
                IpAddr::V4(ip) => arp_cache.get(&ip).cloned(),
                IpAddr::V6(_) => None,
            };
            if scope.cross_network && remote_mac.is_none() {
                unknown_remote_mac_flows += 1;
            }

            let tcp_stats = if socket.protocol == Protocol::Tcp {
                read_tcp_socket_stats(owner.pid, owner.fd)
            } else {
                None
            };
            let key = FlowKey::from_socket(&socket);
            let rate = self.rate_from_counters(
                &key,
                &socket,
                tcp_stats.as_ref(),
                elapsed,
                socket_backend,
                base_confidence,
            );
            let rx_bps = rate.rx_bps;
            let tx_bps = rate.tx_bps;
            let total_bps = rx_bps + tx_bps;
            let queue_bytes = socket.rx_queue_bytes as f64 + socket.tx_queue_bytes as f64;
            queue_total_bytes += queue_bytes;
            attribution_confidence_total += rate.attribution_confidence;
            attribution_confidence_samples += 1;
            if rate.bytes_estimated || rate.attribution_confidence < 0.85 {
                estimated_flows += usize::from(!socket.is_listener());
            }
            if socket.protocol == Protocol::Udp && !socket.is_listener() {
                udp_active_flows += 1;
                udp_estimated_total_bps += total_bps;
                udp_drop_delta_total = udp_drop_delta_total.saturating_add(rate.udp_drop_delta);
            }

            if socket.is_listener() {
                listeners += 1;
                top_listeners.push(ListenerSample {
                    key: listener_key(&socket),
                    pid: owner.pid,
                    process: owner.process.clone(),
                    protocol: socket.protocol,
                    state: socket.state.clone(),
                    iface: local_iface.map(|entry| entry.iface.clone()),
                    local_ip: socket.local_ip,
                    local_port: socket.local_port,
                    local_mac: local_mac.clone(),
                    queue_bytes,
                    uid: socket.uid,
                    collector_backend: socket_backend,
                    attribution_confidence: base_confidence,
                });
            } else {
                active_flows += 1;
                if socket.is_established() {
                    established_flows += 1;
                }
                total_attributed_rx_bps += rx_bps;
                total_attributed_tx_bps += tx_bps;
                if scope.cross_network {
                    cross_network_bps += total_bps;
                }
                if !socket.remote_ip.is_unspecified() {
                    remote_endpoints.insert(socket.remote_ip);
                }
                if let Some(stats) = &tcp_stats {
                    max_rtt_ms = max_rtt_ms.max(stats.rtt_ms);
                    retransmit_total = retransmit_total.saturating_add(stats.total_retrans as u64);
                }
                top_flows.push(FlowSample {
                    key: key.clone(),
                    process: owner.process.clone(),
                    exe_path: owner.exe_path.clone(),
                    cmdline: owner.cmdline.clone(),
                    cgroup: owner.cgroup.clone(),
                    protocol: socket.protocol,
                    state: socket.state.clone(),
                    uid: socket.uid,
                    iface: local_iface.map(|entry| entry.iface.clone()),
                    local_ip: socket.local_ip,
                    local_port: socket.local_port,
                    local_mac,
                    remote_ip: socket.remote_ip,
                    remote_port: socket.remote_port,
                    remote_mac,
                    rx_bps,
                    tx_bps,
                    total_bps,
                    queue_bytes,
                    rtt_ms: tcp_stats.as_ref().map(|stats| stats.rtt_ms),
                    retransmits: tcp_stats.as_ref().map(|stats| stats.total_retrans),
                    cross_network: scope.cross_network,
                    same_lan: scope.same_lan,
                    local_host: scope.local_host,
                    bytes_estimated: rate.bytes_estimated,
                    collector_backend: socket_backend,
                    attribution_confidence: rate.attribution_confidence,
                    udp_drop_delta: rate.udp_drop_delta,
                });
            }

            let aggregate = process_totals
                .entry(owner.pid)
                .or_insert_with(|| ProcessAggregate::from_owner(&owner));
            aggregate.collector_backend = socket_backend.as_str().to_string();
            aggregate.attribution_confidence_total += if socket.is_listener() {
                base_confidence
            } else {
                rate.attribution_confidence
            };
            aggregate.attribution_confidence_samples += 1;
            if socket.is_listener() {
                aggregate.listener_count += 1;
                aggregate.local_ports.insert(socket.local_port);
            } else {
                aggregate.flow_count += 1;
                aggregate.rx_bps += rx_bps;
                aggregate.tx_bps += tx_bps;
                aggregate.queue_bytes += queue_bytes;
                if scope.cross_network {
                    aggregate.cross_network_flows += 1;
                }
                if let Some(rtt_ms) = tcp_stats.as_ref().map(|stats| stats.rtt_ms) {
                    aggregate.max_rtt_ms =
                        Some(aggregate.max_rtt_ms.unwrap_or_default().max(rtt_ms));
                }
                aggregate.local_ports.insert(socket.local_port);
                if socket.remote_port > 0 {
                    aggregate.remote_ports.insert(socket.remote_port);
                }
                if !socket.remote_ip.is_unspecified() && !scope.local_host {
                    aggregate.dominant_remote_ip = Some(socket.remote_ip.to_string());
                }
            }
        }

        top_flows.sort_by(|left, right| {
            right
                .total_bps
                .partial_cmp(&left.total_bps)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| {
                    right
                        .rtt_ms
                        .unwrap_or_default()
                        .partial_cmp(&left.rtt_ms.unwrap_or_default())
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
        });
        top_listeners.sort_by(|left, right| {
            right
                .queue_bytes
                .partial_cmp(&left.queue_bytes)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| left.process.cmp(&right.process))
                .then_with(|| left.local_port.cmp(&right.local_port))
        });

        let mut top_processes: Vec<_> = process_totals.into_values().collect();
        top_processes.sort_by(|left, right| {
            right
                .total_bps()
                .partial_cmp(&left.total_bps())
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| {
                    right
                        .max_rtt_ms
                        .unwrap_or_default()
                        .partial_cmp(&left.max_rtt_ms.unwrap_or_default())
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
        });

        let total_attributed_bps = total_attributed_rx_bps + total_attributed_tx_bps;
        let queue_pressure = track_level(&mut self.queue_peak, "network:queue", queue_total_bytes);
        let latency_pressure = ((max_rtt_ms / 125.0).clamp(0.0, 1.0)
            + ((retransmit_total as f64 / established_flows.max(1) as f64) / 8.0).clamp(0.0, 1.0)
                * 0.35)
            .clamp(0.0, 1.0);
        let attribution_confidence = if attribution_confidence_samples > 0 {
            (attribution_confidence_total / attribution_confidence_samples as f64).clamp(0.0, 1.0)
        } else {
            0.0
        };

        self.history.push_back(SummaryPoint {
            ts_ms: sampled_ms,
            total_bps: total_attributed_bps,
            cross_network_bps,
            active_flows: active_flows as f64,
        });
        while self.history.len() > HISTORY_POINTS {
            self.history.pop_front();
        }
        let traffic_growth_pct =
            growth_pct_per_min(self.history.front(), self.history.back(), |point| {
                point.total_bps
            });
        let cross_growth_pct =
            growth_pct_per_min(self.history.front(), self.history.back(), |point| {
                point.cross_network_bps
            });
        let flow_growth_pct =
            growth_pct_per_min(self.history.front(), self.history.back(), |point| {
                point.active_flows
            });

        emit_summary_metric(
            bus,
            storage,
            "network_active_flows",
            active_flows as f64,
            "count",
            ratio_from_count(active_flows),
            severity_from_count(active_flows),
            &[("window_ms", config.network_window_ms.to_string())],
        )
        .await;
        emit_summary_metric(
            bus,
            storage,
            "network_established_flows",
            established_flows as f64,
            "count",
            ratio_from_count(established_flows),
            severity_from_count(established_flows),
            &[("window_ms", config.network_window_ms.to_string())],
        )
        .await;
        emit_summary_metric(
            bus,
            storage,
            "network_listeners",
            listeners as f64,
            "count",
            ratio_from_count(listeners),
            Severity::Low,
            &[],
        )
        .await;
        emit_summary_metric(
            bus,
            storage,
            "network_owner_misses",
            owner_misses as f64,
            "count",
            ratio_from_count(owner_misses),
            if owner_misses > 0 {
                Severity::Medium
            } else {
                Severity::Low
            },
            &[],
        )
        .await;
        emit_summary_metric(
            bus,
            storage,
            "network_remote_endpoints",
            remote_endpoints.len() as f64,
            "count",
            ratio_from_count(remote_endpoints.len()),
            Severity::Low,
            &[],
        )
        .await;
        emit_summary_metric(
            bus,
            storage,
            "network_cross_network_flows",
            cross_network_flows as f64,
            "count",
            ratio_from_count(cross_network_flows),
            severity_from_count(cross_network_flows),
            &[],
        )
        .await;
        emit_summary_metric(
            bus,
            storage,
            "network_lan_flows",
            lan_flows as f64,
            "count",
            ratio_from_count(lan_flows),
            Severity::Low,
            &[],
        )
        .await;
        emit_summary_metric(
            bus,
            storage,
            "network_local_host_flows",
            local_host_flows as f64,
            "count",
            ratio_from_count(local_host_flows),
            Severity::Low,
            &[],
        )
        .await;
        emit_summary_metric(
            bus,
            storage,
            "network_unknown_remote_mac_flows",
            unknown_remote_mac_flows as f64,
            "count",
            ratio_from_count(unknown_remote_mac_flows),
            if unknown_remote_mac_flows > 0 {
                Severity::Medium
            } else {
                Severity::Low
            },
            &[],
        )
        .await;
        emit_summary_metric(
            bus,
            storage,
            "network_estimated_flows",
            estimated_flows as f64,
            "count",
            ratio_from_count(estimated_flows),
            if estimated_flows > 0 {
                Severity::Medium
            } else {
                Severity::Low
            },
            &[],
        )
        .await;
        emit_summary_metric(
            bus,
            storage,
            "network_udp_active_flows",
            udp_active_flows as f64,
            "count",
            ratio_from_count(udp_active_flows),
            Severity::Low,
            &[],
        )
        .await;
        emit_summary_metric(
            bus,
            storage,
            "network_udp_estimated_total_bps",
            udp_estimated_total_bps,
            "bytes_per_sec",
            track_rate(
                &mut self.flow_rate_peak,
                "network:udp_estimated_total_bps",
                udp_estimated_total_bps,
            ),
            Severity::Low,
            &[],
        )
        .await;
        emit_summary_metric(
            bus,
            storage,
            "network_udp_drop_delta",
            udp_drop_delta_total as f64,
            "count",
            ratio_from_count(udp_drop_delta_total.min(64) as usize),
            if udp_drop_delta_total > 0 {
                Severity::Medium
            } else {
                Severity::Low
            },
            &[],
        )
        .await;
        emit_summary_metric(
            bus,
            storage,
            "network_attribution_confidence",
            attribution_confidence,
            "ratio",
            attribution_confidence,
            if attribution_confidence < 0.45 {
                Severity::High
            } else if attribution_confidence < 0.70 {
                Severity::Medium
            } else {
                Severity::Low
            },
            &[("collector_backend", collector_backend.clone())],
        )
        .await;
        emit_summary_metric(
            bus,
            storage,
            "network_attributed_rx_bps",
            total_attributed_rx_bps,
            "bytes_per_sec",
            track_rate(
                &mut self.flow_rate_peak,
                "network:attributed_rx_bps",
                total_attributed_rx_bps,
            ),
            Severity::Low,
            &[],
        )
        .await;
        emit_summary_metric(
            bus,
            storage,
            "network_attributed_tx_bps",
            total_attributed_tx_bps,
            "bytes_per_sec",
            track_rate(
                &mut self.flow_rate_peak,
                "network:attributed_tx_bps",
                total_attributed_tx_bps,
            ),
            Severity::Low,
            &[],
        )
        .await;
        emit_summary_metric(
            bus,
            storage,
            "network_attributed_total_bps",
            total_attributed_bps,
            "bytes_per_sec",
            track_rate(
                &mut self.flow_rate_peak,
                "network:attributed_total_bps",
                total_attributed_bps,
            ),
            severity_from_signal(track_rate(
                &mut self.flow_rate_peak,
                "network:attributed_total_bps:severity",
                total_attributed_bps,
            )),
            &[],
        )
        .await;
        emit_summary_metric(
            bus,
            storage,
            "network_cross_network_bps",
            cross_network_bps,
            "bytes_per_sec",
            track_rate(
                &mut self.flow_rate_peak,
                "network:cross_network_bps",
                cross_network_bps,
            ),
            Severity::Low,
            &[],
        )
        .await;
        emit_summary_metric(
            bus,
            storage,
            "network_latency_pressure",
            latency_pressure,
            "ratio",
            latency_pressure,
            severity_from_signal(latency_pressure),
            &[("rtt_ms_max", format!("{max_rtt_ms:.3}"))],
        )
        .await;
        emit_summary_metric(
            bus,
            storage,
            "network_queue_pressure",
            queue_total_bytes,
            "bytes",
            queue_pressure,
            severity_from_signal(queue_pressure),
            &[],
        )
        .await;
        emit_summary_metric(
            bus,
            storage,
            "network_traffic_growth_pct_per_min",
            traffic_growth_pct,
            "pct_per_min",
            ratio_from_growth_pct(traffic_growth_pct),
            severity_from_growth(traffic_growth_pct),
            &[],
        )
        .await;
        emit_summary_metric(
            bus,
            storage,
            "network_cross_network_growth_pct_per_min",
            cross_growth_pct,
            "pct_per_min",
            ratio_from_growth_pct(cross_growth_pct),
            severity_from_growth(cross_growth_pct),
            &[],
        )
        .await;
        emit_summary_metric(
            bus,
            storage,
            "network_flow_growth_pct_per_min",
            flow_growth_pct,
            "pct_per_min",
            ratio_from_growth_pct(flow_growth_pct),
            severity_from_growth(flow_growth_pct),
            &[],
        )
        .await;
        emit_ebpf_metrics(
            bus,
            storage,
            config,
            ebpf_snapshot.as_ref(),
            &collector_backend,
        )
        .await;

        for flow in top_flows.into_iter().take(config.network_top_flows) {
            let signal = track_rate(
                &mut self.flow_rate_peak,
                &format!("flow:{}", flow.key.flow_id()),
                flow.total_bps,
            );
            let anomaly = signal >= 0.92
                || flow.rtt_ms.unwrap_or_default() >= 120.0
                || (flow.cross_network && flow.remote_mac.is_none() && flow.total_bps > 0.0);
            emit_network_metric(
                bus,
                storage,
                "network_process_flow_bps",
                flow.total_bps,
                "bytes_per_sec",
                signal,
                flow_severity(signal, flow.rtt_ms.unwrap_or_default(), flow.cross_network),
                &flow.attributes(anomaly),
            )
            .await;
        }

        for process in top_processes.into_iter().take(config.network_top_processes) {
            let signal = track_rate(
                &mut self.process_rate_peak,
                &format!("pid:{}", process.pid),
                process.total_bps(),
            );
            emit_network_metric(
                bus,
                storage,
                "network_process_total_bps",
                process.total_bps(),
                "bytes_per_sec",
                signal,
                if process.attribution_confidence() < 0.45 {
                    Severity::High
                } else {
                    severity_from_signal(signal)
                },
                &process.attributes(),
            )
            .await;
        }

        for listener in top_listeners.into_iter().take(config.network_top_listeners) {
            emit_network_metric(
                bus,
                storage,
                "network_listener_socket",
                listener.queue_bytes,
                "bytes",
                track_level(
                    &mut self.queue_peak,
                    &format!("listener:{}", listener.key),
                    listener.queue_bytes,
                ),
                Severity::Low,
                &listener.attributes(),
            )
            .await;
        }
    }

    async fn collect_backend_snapshot(&mut self, config: &EmbeddedConfig) -> BackendSnapshot {
        #[cfg(target_os = "linux")]
        {
            let mut sockets = read_socket_table("/proc/net/tcp", Protocol::Tcp).await;
            sockets.extend(read_socket_table("/proc/net/tcp6", Protocol::Tcp).await);
            sockets.extend(read_socket_table("/proc/net/udp", Protocol::Udp).await);
            sockets.extend(read_socket_table("/proc/net/udp6", Protocol::Udp).await);
            let owners = self
                .resolve_socket_owners(&sockets, config.network_owner_cache_ttl_ms)
                .await;
            let owner_misses = sockets
                .iter()
                .filter(|socket| !owners.contains_key(&socket.inode))
                .count();
            let sockets = sockets
                .into_iter()
                .filter_map(|socket| {
                    owners
                        .get(&socket.inode)
                        .cloned()
                        .map(|owner| AttributedSocket {
                            socket,
                            owner,
                            backend: CollectorBackend::Procfs,
                            base_confidence: CollectorBackend::Procfs.base_confidence(),
                        })
                })
                .collect();
            return BackendSnapshot {
                backend: CollectorBackend::Procfs,
                sockets,
                owner_misses,
            };
        }

        #[cfg(not(target_os = "linux"))]
        {
            let sockets = collect_lsof_sockets().await;
            return BackendSnapshot {
                backend: CollectorBackend::Lsof,
                owner_misses: 0,
                sockets,
            };
        }
    }

    async fn resolve_socket_owners(
        &mut self,
        sockets: &[SocketEntry],
        ttl_ms: u64,
    ) -> HashMap<u64, SocketOwner> {
        let now = now_ms();
        let live_inodes: HashSet<u64> = sockets.iter().map(|socket| socket.inode).collect();
        self.owner_cache.retain(|inode, entry| {
            live_inodes.contains(inode) || now.saturating_sub(entry.last_seen_ms) <= ttl_ms
        });

        let mut owners = HashMap::new();
        let mut unresolved = HashSet::new();
        for inode in live_inodes {
            if let Some(entry) = self.owner_cache.get_mut(&inode) {
                entry.last_seen_ms = now;
                owners.insert(inode, entry.owner.clone());
            } else {
                unresolved.insert(inode);
            }
        }

        if unresolved.is_empty() {
            return owners;
        }

        for (inode, owner) in scan_proc_socket_owners(&unresolved).await {
            owners.insert(inode, owner.clone());
            self.owner_cache.insert(
                inode,
                CachedSocketOwner {
                    owner,
                    last_seen_ms: now,
                },
            );
        }
        owners
    }

    fn rate_from_counters(
        &mut self,
        key: &FlowKey,
        socket: &SocketEntry,
        tcp_stats: Option<&TcpSocketStats>,
        elapsed: f64,
        backend: CollectorBackend,
        base_confidence: f64,
    ) -> RateSample {
        let next = FlowCounters {
            rx_bytes: tcp_stats.and_then(|stats| {
                stats
                    .byte_counters_available
                    .then_some(stats.bytes_received)
            }),
            tx_bytes: tcp_stats
                .and_then(|stats| stats.byte_counters_available.then_some(stats.bytes_acked)),
            rx_queue_bytes: socket.rx_queue_bytes,
            tx_queue_bytes: socket.tx_queue_bytes,
            drops: socket.drops,
        };
        let prev = self.flow_prev.insert(key.clone(), next.clone());
        let Some(prev) = prev else {
            return RateSample {
                rx_bps: 0.0,
                tx_bps: 0.0,
                bytes_estimated: false,
                attribution_confidence: if tcp_stats
                    .is_some_and(|stats| stats.byte_counters_available)
                {
                    (base_confidence * 0.82).clamp(0.0, 1.0)
                } else {
                    (base_confidence
                        * if socket.protocol == Protocol::Udp {
                            0.42
                        } else {
                            0.58
                        })
                    .clamp(0.0, 1.0)
                },
                udp_drop_delta: 0,
            };
        };
        if let (Some(prev_rx), Some(prev_tx), Some(next_rx), Some(next_tx)) =
            (prev.rx_bytes, prev.tx_bytes, next.rx_bytes, next.tx_bytes)
        {
            let rx_bps = next_rx.saturating_sub(prev_rx) as f64 / elapsed;
            let tx_bps = next_tx.saturating_sub(prev_tx) as f64 / elapsed;
            return RateSample {
                rx_bps: rx_bps.max(0.0),
                tx_bps: tx_bps.max(0.0),
                bytes_estimated: false,
                attribution_confidence: (base_confidence
                    * if backend == CollectorBackend::Procfs {
                        1.0
                    } else {
                        0.92
                    })
                .clamp(0.0, 1.0),
                udp_drop_delta: 0,
            };
        }
        let rx_queue_delta = socket.rx_queue_bytes.max(prev.rx_queue_bytes)
            - socket.rx_queue_bytes.min(prev.rx_queue_bytes);
        let tx_queue_delta = socket.tx_queue_bytes.max(prev.tx_queue_bytes)
            - socket.tx_queue_bytes.min(prev.tx_queue_bytes);
        let udp_drop_delta = socket.drops.saturating_sub(prev.drops);
        let rx_bps =
            (rx_queue_delta as f64 + udp_drop_delta as f64 * UDP_DROP_ESTIMATED_BYTES) / elapsed;
        let tx_bps = tx_queue_delta as f64 / elapsed;
        let bytes_estimated = rx_bps > 0.0 || tx_bps > 0.0;
        let confidence_multiplier = if socket.protocol == Protocol::Udp {
            if bytes_estimated { 0.55 } else { 0.30 }
        } else if bytes_estimated {
            0.72
        } else {
            0.44
        };
        RateSample {
            rx_bps: rx_bps.max(0.0),
            tx_bps: tx_bps.max(0.0),
            bytes_estimated,
            attribution_confidence: (base_confidence * confidence_multiplier).clamp(0.0, 1.0),
            udp_drop_delta,
        }
    }
}

#[derive(Clone)]
struct CachedSocketOwner {
    owner: SocketOwner,
    last_seen_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

#[derive(Clone)]
struct SocketEntry {
    protocol: Protocol,
    pid: u32,
    local_ip: IpAddr,
    local_port: u16,
    remote_ip: IpAddr,
    remote_port: u16,
    state: String,
    tx_queue_bytes: u64,
    rx_queue_bytes: u64,
    drops: u64,
    uid: u32,
    inode: u64,
}

impl SocketEntry {
    fn is_listener(&self) -> bool {
        self.remote_port == 0
            && self.remote_ip.is_unspecified()
            && (self.protocol == Protocol::Udp || self.state == "listen")
    }

    fn is_established(&self) -> bool {
        self.protocol == Protocol::Tcp && self.state == "established"
    }
}

#[derive(Clone)]
struct SocketOwner {
    pid: u32,
    fd: i32,
    process: String,
    exe_path: Option<String>,
    cmdline: Option<String>,
    cgroup: Option<String>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct FlowKey {
    pid: u32,
    protocol: Protocol,
    inode: u64,
    local_ip: IpAddr,
    local_port: u16,
    remote_ip: IpAddr,
    remote_port: u16,
}

impl FlowKey {
    fn from_socket(socket: &SocketEntry) -> Self {
        Self {
            pid: socket.pid,
            protocol: socket.protocol,
            inode: socket.inode,
            local_ip: socket.local_ip,
            local_port: socket.local_port,
            remote_ip: socket.remote_ip,
            remote_port: socket.remote_port,
        }
    }

    fn flow_id(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}:{}",
            self.protocol.as_str(),
            self.pid,
            self.local_ip,
            self.local_port,
            self.remote_ip,
            self.remote_port
        )
    }
}

#[derive(Clone)]
struct FlowCounters {
    rx_bytes: Option<u64>,
    tx_bytes: Option<u64>,
    rx_queue_bytes: u64,
    tx_queue_bytes: u64,
    drops: u64,
}

#[derive(Clone)]
struct TcpSocketStats {
    byte_counters_available: bool,
    bytes_acked: u64,
    bytes_received: u64,
    rtt_ms: f64,
    total_retrans: u32,
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct LinuxTcpInfo {
    tcpi_state: u8,
    tcpi_ca_state: u8,
    tcpi_retransmits: u8,
    tcpi_probes: u8,
    tcpi_backoff: u8,
    tcpi_options: u8,
    tcpi_wscale_bits: u8,
    tcpi_delivery_flags: u8,
    tcpi_rto: u32,
    tcpi_ato: u32,
    tcpi_snd_mss: u32,
    tcpi_rcv_mss: u32,
    tcpi_unacked: u32,
    tcpi_sacked: u32,
    tcpi_lost: u32,
    tcpi_retrans: u32,
    tcpi_fackets: u32,
    tcpi_last_data_sent: u32,
    tcpi_last_ack_sent: u32,
    tcpi_last_data_recv: u32,
    tcpi_last_ack_recv: u32,
    tcpi_pmtu: u32,
    tcpi_rcv_ssthresh: u32,
    tcpi_rtt: u32,
    tcpi_rttvar: u32,
    tcpi_snd_ssthresh: u32,
    tcpi_snd_cwnd: u32,
    tcpi_advmss: u32,
    tcpi_reordering: u32,
    tcpi_rcv_rtt: u32,
    tcpi_rcv_space: u32,
    tcpi_total_retrans: u32,
    tcpi_pacing_rate: u64,
    tcpi_max_pacing_rate: u64,
    tcpi_bytes_acked: u64,
    tcpi_bytes_received: u64,
}

#[derive(Clone)]
struct InterfaceAddress {
    iface: String,
    ip: IpAddr,
    prefix_len: u8,
    mac: Option<String>,
}

#[derive(Default)]
struct InterfaceInventory {
    addresses: Vec<InterfaceAddress>,
}

impl InterfaceInventory {
    fn iface_for_ip(&self, ip: &IpAddr) -> Option<&InterfaceAddress> {
        self.addresses.iter().find(|entry| &entry.ip == ip)
    }

    fn is_local_host(&self, ip: &IpAddr) -> bool {
        ip.is_loopback() || self.addresses.iter().any(|entry| &entry.ip == ip)
    }

    fn is_same_lan(&self, ip: &IpAddr) -> bool {
        self.addresses
            .iter()
            .any(|entry| ip_matches_prefix(ip, &entry.ip, entry.prefix_len))
    }
}

#[derive(Clone, Copy, Default)]
struct SocketScope {
    same_lan: bool,
    local_host: bool,
    cross_network: bool,
}

struct FlowSample {
    key: FlowKey,
    process: String,
    exe_path: Option<String>,
    cmdline: Option<String>,
    cgroup: Option<String>,
    protocol: Protocol,
    state: String,
    uid: u32,
    iface: Option<String>,
    local_ip: IpAddr,
    local_port: u16,
    local_mac: Option<String>,
    remote_ip: IpAddr,
    remote_port: u16,
    remote_mac: Option<String>,
    rx_bps: f64,
    tx_bps: f64,
    total_bps: f64,
    queue_bytes: f64,
    rtt_ms: Option<f64>,
    retransmits: Option<u32>,
    cross_network: bool,
    same_lan: bool,
    local_host: bool,
    bytes_estimated: bool,
    collector_backend: CollectorBackend,
    attribution_confidence: f64,
    udp_drop_delta: u64,
}

impl FlowSample {
    fn attributes(&self, anomaly: bool) -> Vec<(&'static str, String)> {
        let mut attrs = vec![
            ("flow_id", self.key.flow_id()),
            ("pid", self.key.pid.to_string()),
            ("process", self.process.clone()),
            ("protocol", self.protocol.as_str().to_string()),
            ("socket_state", self.state.clone()),
            ("uid", self.uid.to_string()),
            ("local_ip", self.local_ip.to_string()),
            ("local_port", self.local_port.to_string()),
            ("remote_ip", self.remote_ip.to_string()),
            ("remote_port", self.remote_port.to_string()),
            ("rx_bps", format!("{:.3}", self.rx_bps)),
            ("tx_bps", format!("{:.3}", self.tx_bps)),
            ("queue_bytes", format!("{:.3}", self.queue_bytes)),
            ("cross_network", self.cross_network.to_string()),
            ("same_lan", self.same_lan.to_string()),
            ("local_host", self.local_host.to_string()),
            ("bytes_estimated", self.bytes_estimated.to_string()),
            (
                "collector_backend",
                self.collector_backend.as_str().to_string(),
            ),
            (
                "attribution_confidence",
                format!("{:.3}", self.attribution_confidence),
            ),
            ("udp_drop_delta", self.udp_drop_delta.to_string()),
        ];
        if let Some(iface) = &self.iface {
            attrs.push(("iface", iface.clone()));
        }
        if let Some(local_mac) = &self.local_mac {
            attrs.push(("local_mac", local_mac.clone()));
        }
        if let Some(remote_mac) = &self.remote_mac {
            attrs.push(("remote_mac", remote_mac.clone()));
        }
        if let Some(exe_path) = &self.exe_path {
            attrs.push(("exe_path", exe_path.clone()));
        }
        if let Some(cmdline) = &self.cmdline {
            attrs.push(("cmdline", cmdline.clone()));
        }
        if let Some(cgroup) = &self.cgroup {
            attrs.push(("cgroup", cgroup.clone()));
        }
        if let Some(rtt_ms) = self.rtt_ms {
            attrs.push(("rtt_ms", format!("{rtt_ms:.3}")));
        }
        if let Some(retransmits) = self.retransmits {
            attrs.push(("retransmits", retransmits.to_string()));
        }
        if anomaly {
            attrs.push(("anomaly", "true".to_string()));
        }
        attrs
    }
}

struct ListenerSample {
    key: String,
    pid: u32,
    process: String,
    protocol: Protocol,
    state: String,
    iface: Option<String>,
    local_ip: IpAddr,
    local_port: u16,
    local_mac: Option<String>,
    queue_bytes: f64,
    uid: u32,
    collector_backend: CollectorBackend,
    attribution_confidence: f64,
}

impl ListenerSample {
    fn attributes(&self) -> Vec<(&'static str, String)> {
        let mut attrs = vec![
            ("listener_id", self.key.clone()),
            ("pid", self.pid.to_string()),
            ("process", self.process.clone()),
            ("protocol", self.protocol.as_str().to_string()),
            ("socket_state", self.state.clone()),
            ("uid", self.uid.to_string()),
            ("local_ip", self.local_ip.to_string()),
            ("local_port", self.local_port.to_string()),
            (
                "collector_backend",
                self.collector_backend.as_str().to_string(),
            ),
            (
                "attribution_confidence",
                format!("{:.3}", self.attribution_confidence),
            ),
        ];
        if let Some(iface) = &self.iface {
            attrs.push(("iface", iface.clone()));
        }
        if let Some(local_mac) = &self.local_mac {
            attrs.push(("local_mac", local_mac.clone()));
        }
        attrs
    }
}

struct ProcessAggregate {
    pid: u32,
    process: String,
    exe_path: Option<String>,
    cmdline: Option<String>,
    cgroup: Option<String>,
    flow_count: usize,
    listener_count: usize,
    cross_network_flows: usize,
    rx_bps: f64,
    tx_bps: f64,
    queue_bytes: f64,
    max_rtt_ms: Option<f64>,
    local_ports: BTreeSet<u16>,
    remote_ports: BTreeSet<u16>,
    dominant_remote_ip: Option<String>,
    collector_backend: String,
    attribution_confidence_total: f64,
    attribution_confidence_samples: usize,
}

impl ProcessAggregate {
    fn from_owner(owner: &SocketOwner) -> Self {
        Self {
            pid: owner.pid,
            process: owner.process.clone(),
            exe_path: owner.exe_path.clone(),
            cmdline: owner.cmdline.clone(),
            cgroup: owner.cgroup.clone(),
            flow_count: 0,
            listener_count: 0,
            cross_network_flows: 0,
            rx_bps: 0.0,
            tx_bps: 0.0,
            queue_bytes: 0.0,
            max_rtt_ms: None,
            local_ports: BTreeSet::new(),
            remote_ports: BTreeSet::new(),
            dominant_remote_ip: None,
            collector_backend: CollectorBackend::Procfs.as_str().to_string(),
            attribution_confidence_total: 0.0,
            attribution_confidence_samples: 0,
        }
    }

    fn total_bps(&self) -> f64 {
        self.rx_bps + self.tx_bps
    }

    fn attribution_confidence(&self) -> f64 {
        if self.attribution_confidence_samples == 0 {
            0.0
        } else {
            (self.attribution_confidence_total / self.attribution_confidence_samples as f64)
                .clamp(0.0, 1.0)
        }
    }

    fn attributes(&self) -> Vec<(&'static str, String)> {
        let mut attrs = vec![
            ("pid", self.pid.to_string()),
            ("process", self.process.clone()),
            ("flow_count", self.flow_count.to_string()),
            ("listener_count", self.listener_count.to_string()),
            ("cross_network_flows", self.cross_network_flows.to_string()),
            ("rx_bps", format!("{:.3}", self.rx_bps)),
            ("tx_bps", format!("{:.3}", self.tx_bps)),
            ("queue_bytes", format!("{:.3}", self.queue_bytes)),
            ("collector_backend", self.collector_backend.clone()),
            (
                "attribution_confidence",
                format!("{:.3}", self.attribution_confidence()),
            ),
        ];
        if let Some(exe_path) = &self.exe_path {
            attrs.push(("exe_path", exe_path.clone()));
        }
        if let Some(cmdline) = &self.cmdline {
            attrs.push(("cmdline", cmdline.clone()));
        }
        if let Some(cgroup) = &self.cgroup {
            attrs.push(("cgroup", cgroup.clone()));
        }
        if let Some(max_rtt_ms) = self.max_rtt_ms {
            attrs.push(("max_rtt_ms", format!("{max_rtt_ms:.3}")));
        }
        if let Some(dominant_remote_ip) = &self.dominant_remote_ip {
            attrs.push(("dominant_remote_ip", dominant_remote_ip.clone()));
        }
        if !self.local_ports.is_empty() {
            attrs.push((
                "local_ports",
                self.local_ports
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            ));
        }
        if !self.remote_ports.is_empty() {
            attrs.push((
                "remote_ports",
                self.remote_ports
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            ));
        }
        attrs
    }
}

#[derive(Clone, Copy)]
struct SummaryPoint {
    ts_ms: u64,
    total_bps: f64,
    cross_network_bps: f64,
    active_flows: f64,
}

async fn read_socket_table(path: &str, protocol: Protocol) -> Vec<SocketEntry> {
    let raw = fs::read_to_string(path).await.unwrap_or_default();
    let mut lines = raw.lines();
    let header = lines.next().unwrap_or_default();
    let drops_index = header.split_whitespace().position(|value| value == "drops");
    lines
        .filter_map(|line| parse_socket_entry(line, protocol, drops_index))
        .collect()
}

fn parse_socket_entry(
    line: &str,
    protocol: Protocol,
    drops_index: Option<usize>,
) -> Option<SocketEntry> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 10 {
        return None;
    }
    let (local_ip, local_port) = parse_socket_address(parts[1])?;
    let (remote_ip, remote_port) = parse_socket_address(parts[2])?;
    let state = socket_state_label(protocol, parts[3], remote_ip, remote_port);
    let (tx_queue_bytes, rx_queue_bytes) = parse_queue_pair(parts[4])?;
    let uid = parts.get(7)?.parse::<u32>().ok()?;
    let inode = parts.get(9)?.parse::<u64>().ok()?;
    let drops = drops_index
        .and_then(|idx| parts.get(idx))
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or_default();
    Some(SocketEntry {
        protocol,
        pid: 0,
        local_ip,
        local_port,
        remote_ip,
        remote_port,
        state,
        tx_queue_bytes,
        rx_queue_bytes,
        drops,
        uid,
        inode,
    })
}

#[cfg(not(target_os = "linux"))]
async fn collect_lsof_sockets() -> Vec<AttributedSocket> {
    let Ok(output) = Command::new("lsof")
        .args(["-nP", "-iTCP", "-iUDP", "-FpcfPtnTu", "-Tqs"])
        .output()
        .await
    else {
        return Vec::new();
    };
    if !output.status.success() && output.stdout.is_empty() {
        return Vec::new();
    }

    let mut raw_records = Vec::new();
    let mut current_pid = 0u32;
    let mut current_process = String::new();
    let mut current_uid = 0u32;
    let mut current_file = LsofFileRecord::default();
    let mut has_file = false;

    let mut finalize_file = |records: &mut Vec<LsofRecord>,
                             pid: u32,
                             process: &str,
                             uid: u32,
                             file: &mut LsofFileRecord,
                             has_file: &mut bool| {
        if !*has_file {
            return;
        }
        if let Some((socket, fd)) = file.try_build(pid, process, uid) {
            records.push(LsofRecord {
                socket,
                pid,
                fd,
                process: process.to_string(),
            });
        }
        *has_file = false;
        *file = LsofFileRecord::default();
    };

    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let Some(tag) = line.chars().next() else {
            continue;
        };
        match tag {
            'p' => {
                finalize_file(
                    &mut raw_records,
                    current_pid,
                    &current_process,
                    current_uid,
                    &mut current_file,
                    &mut has_file,
                );
                current_pid = line[1..].trim().parse::<u32>().unwrap_or_default();
            }
            'c' => {
                current_process = line[1..].trim().to_string();
            }
            'u' => {
                current_uid = line[1..].trim().parse::<u32>().unwrap_or_default();
            }
            'f' => {
                finalize_file(
                    &mut raw_records,
                    current_pid,
                    &current_process,
                    current_uid,
                    &mut current_file,
                    &mut has_file,
                );
                current_file = LsofFileRecord {
                    fd: parse_lsof_fd(&line[1..]),
                    ..LsofFileRecord::default()
                };
                has_file = true;
            }
            't' => {
                if has_file {
                    current_file.address_family = line[1..].trim().to_string();
                }
            }
            'P' => {
                if has_file {
                    current_file.protocol = match line[1..].trim() {
                        "TCP" => Some(Protocol::Tcp),
                        "UDP" => Some(Protocol::Udp),
                        _ => None,
                    };
                }
            }
            'n' => {
                if has_file {
                    current_file.endpoint = line[1..].trim().to_string();
                }
            }
            'T' => {
                if has_file {
                    current_file.consume_token(line);
                }
            }
            _ => {}
        }
    }
    finalize_file(
        &mut raw_records,
        current_pid,
        &current_process,
        current_uid,
        &mut current_file,
        &mut has_file,
    );

    let mut metadata_by_pid: HashMap<u32, SocketOwner> = HashMap::new();
    let mut sockets = Vec::new();
    for record in raw_records {
        let owner = if let Some(owner) = metadata_by_pid.get(&record.pid) {
            owner.clone()
        } else {
            let owner = read_process_owner(record.pid)
                .await
                .unwrap_or_else(|| SocketOwner {
                    pid: record.pid,
                    fd: record.fd,
                    process: record.process.clone(),
                    exe_path: None,
                    cmdline: None,
                    cgroup: None,
                });
            metadata_by_pid.insert(record.pid, owner.clone());
            owner
        };
        let mut owner = owner;
        owner.fd = record.fd;
        if owner.process.trim().is_empty() {
            owner.process = record.process;
        }
        sockets.push(AttributedSocket {
            socket: record.socket,
            owner,
            backend: CollectorBackend::Lsof,
            base_confidence: CollectorBackend::Lsof.base_confidence(),
        });
    }
    sockets
}

#[cfg(not(target_os = "linux"))]
#[derive(Default)]
struct LsofFileRecord {
    fd: i32,
    protocol: Option<Protocol>,
    endpoint: String,
    state: Option<String>,
    rx_queue_bytes: u64,
    tx_queue_bytes: u64,
    address_family: String,
}

#[cfg(not(target_os = "linux"))]
impl LsofFileRecord {
    fn consume_token(&mut self, raw: &str) {
        if let Some(value) = raw.strip_prefix("TST=") {
            self.state = Some(value.trim().to_ascii_lowercase());
        } else if let Some(value) = raw.strip_prefix("TQR=") {
            self.rx_queue_bytes = value.trim().parse::<u64>().unwrap_or_default();
        } else if let Some(value) = raw.strip_prefix("TQS=") {
            self.tx_queue_bytes = value.trim().parse::<u64>().unwrap_or_default();
        }
    }

    fn try_build(&self, pid: u32, process: &str, uid: u32) -> Option<(SocketEntry, i32)> {
        let protocol = self.protocol?;
        let (local_ip, local_port, remote_ip, remote_port) =
            parse_lsof_endpoint(&self.endpoint, &self.address_family)?;
        let state = self
            .state
            .clone()
            .unwrap_or_else(|| socket_state_label(protocol, "", remote_ip, remote_port));
        Some((
            SocketEntry {
                protocol,
                pid,
                local_ip,
                local_port,
                remote_ip,
                remote_port,
                state,
                tx_queue_bytes: self.tx_queue_bytes,
                rx_queue_bytes: self.rx_queue_bytes,
                drops: 0,
                uid,
                inode: synthetic_inode(
                    pid,
                    self.fd,
                    protocol,
                    local_ip,
                    local_port,
                    remote_ip,
                    remote_port,
                ),
            },
            self.fd,
        ))
    }
}

#[cfg(not(target_os = "linux"))]
struct LsofRecord {
    socket: SocketEntry,
    pid: u32,
    fd: i32,
    process: String,
}

#[cfg(not(target_os = "linux"))]
fn parse_lsof_fd(value: &str) -> i32 {
    value
        .chars()
        .take_while(|ch| ch.is_ascii_digit())
        .collect::<String>()
        .parse::<i32>()
        .unwrap_or(-1)
}

#[cfg(not(target_os = "linux"))]
fn parse_lsof_endpoint(value: &str, _family: &str) -> Option<(IpAddr, u16, IpAddr, u16)> {
    let (local, remote) = value
        .split_once("->")
        .map(|(left, right)| (left, Some(right)))
        .unwrap_or((value, None));
    let (local_ip, local_port) = parse_host_port(local)?;
    let (remote_ip, remote_port) = remote
        .and_then(parse_host_port)
        .unwrap_or((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
    Some((local_ip, local_port, remote_ip, remote_port))
}

#[cfg(not(target_os = "linux"))]
fn parse_host_port(value: &str) -> Option<(IpAddr, u16)> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(rest) = trimmed.strip_prefix('[') {
        let (host, port) = rest.split_once("]:")?;
        return Some((host.parse::<IpAddr>().ok()?, port.parse::<u16>().ok()?));
    }
    let (host, port) = trimmed.rsplit_once(':')?;
    let ip = if host == "*" || host.is_empty() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        host.parse::<IpAddr>().ok()?
    };
    Some((ip, port.parse::<u16>().ok()?))
}

#[cfg(not(target_os = "linux"))]
fn synthetic_inode(
    pid: u32,
    fd: i32,
    protocol: Protocol,
    local_ip: IpAddr,
    local_port: u16,
    remote_ip: IpAddr,
    remote_port: u16,
) -> u64 {
    let mut hasher = DefaultHasher::new();
    pid.hash(&mut hasher);
    fd.hash(&mut hasher);
    protocol.hash(&mut hasher);
    local_ip.hash(&mut hasher);
    local_port.hash(&mut hasher);
    remote_ip.hash(&mut hasher);
    remote_port.hash(&mut hasher);
    hasher.finish()
}

fn parse_socket_address(value: &str) -> Option<(IpAddr, u16)> {
    let (addr_hex, port_hex) = value.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    match addr_hex.len() {
        8 => {
            let raw = u32::from_str_radix(addr_hex, 16).ok()?;
            let ip = Ipv4Addr::from(raw.to_le_bytes());
            Some((IpAddr::V4(ip), port))
        }
        32 => {
            let mut bytes = [0u8; 16];
            for (idx, chunk) in addr_hex.as_bytes().chunks(8).enumerate() {
                let word = std::str::from_utf8(chunk).ok()?;
                let raw = u32::from_str_radix(word, 16).ok()?;
                bytes[idx * 4..(idx + 1) * 4].copy_from_slice(&raw.to_le_bytes());
            }
            let ip = Ipv6Addr::from(bytes);
            Some((normalize_ip(ip), port))
        }
        _ => None,
    }
}

fn normalize_ip(ip: Ipv6Addr) -> IpAddr {
    ip.to_ipv4_mapped()
        .map(IpAddr::V4)
        .unwrap_or(IpAddr::V6(ip))
}

fn parse_queue_pair(value: &str) -> Option<(u64, u64)> {
    let (tx_hex, rx_hex) = value.split_once(':')?;
    Some((
        u64::from_str_radix(tx_hex, 16).ok()?,
        u64::from_str_radix(rx_hex, 16).ok()?,
    ))
}

fn socket_state_label(
    protocol: Protocol,
    value: &str,
    remote_ip: IpAddr,
    remote_port: u16,
) -> String {
    if protocol == Protocol::Udp {
        if remote_port == 0 && remote_ip.is_unspecified() {
            return "listen".to_string();
        }
        return "open".to_string();
    }
    match value {
        "01" => "established",
        "02" => "syn_sent",
        "03" => "syn_recv",
        "04" => "fin_wait1",
        "05" => "fin_wait2",
        "06" => "time_wait",
        "07" => "close",
        "08" => "close_wait",
        "09" => "last_ack",
        "0A" => "listen",
        "0B" => "closing",
        _ => "unknown",
    }
    .to_string()
}

async fn read_arp_cache() -> HashMap<Ipv4Addr, String> {
    let raw = fs::read_to_string("/proc/net/arp")
        .await
        .unwrap_or_default();
    let mut out = HashMap::new();
    for line in raw.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        let Ok(ip) = parts[0].parse::<Ipv4Addr>() else {
            continue;
        };
        let mac = parts[3].trim();
        if mac.is_empty() || mac == "00:00:00:00:00:00" {
            continue;
        }
        out.insert(ip, mac.to_ascii_lowercase());
    }
    out
}

fn collect_interface_inventory() -> InterfaceInventory {
    let mut addresses = Vec::new();
    let mut ifap = std::ptr::null_mut::<libc::ifaddrs>();
    let rc = unsafe { libc::getifaddrs(&mut ifap) };
    if rc != 0 || ifap.is_null() {
        return InterfaceInventory::default();
    }

    let mut mac_by_iface = HashMap::new();

    #[cfg(target_os = "linux")]
    {
        let mut current = ifap;
        while !current.is_null() {
            let ifa = unsafe { &*current };
            let Some(name) = (unsafe { c_string(ifa.ifa_name) }) else {
                current = ifa.ifa_next;
                continue;
            };
            if let Some(addr) = unsafe { ifa.ifa_addr.as_ref() }
                && addr.sa_family as i32 == libc::AF_PACKET
            {
                let packet = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_ll) };
                if packet.sll_halen >= 6 {
                    let mac = packet.sll_addr[..6]
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<Vec<_>>()
                        .join(":");
                    mac_by_iface.insert(name.clone(), mac);
                }
            }
            current = ifa.ifa_next;
        }
    }

    let mut current = ifap;
    while !current.is_null() {
        let ifa = unsafe { &*current };
        let Some(name) = (unsafe { c_string(ifa.ifa_name) }) else {
            current = ifa.ifa_next;
            continue;
        };
        let Some(addr) = (unsafe { ifa.ifa_addr.as_ref() }) else {
            current = ifa.ifa_next;
            continue;
        };
        let family = addr.sa_family as i32;
        match family {
            libc::AF_INET => {
                let sockaddr = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
                let ip = IpAddr::V4(Ipv4Addr::from(sockaddr.sin_addr.s_addr.to_le_bytes()));
                let prefix_len = unsafe {
                    ifa.ifa_netmask
                        .as_ref()
                        .map(|mask| {
                            ipv4_prefix_len(
                                &*(mask as *const libc::sockaddr as *const libc::sockaddr_in),
                            )
                        })
                        .unwrap_or(0)
                };
                addresses.push(InterfaceAddress {
                    iface: name.clone(),
                    ip,
                    prefix_len,
                    mac: mac_by_iface.get(&name).cloned(),
                });
            }
            libc::AF_INET6 => {
                let sockaddr = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in6) };
                let ip = normalize_ip(Ipv6Addr::from(sockaddr.sin6_addr.s6_addr));
                let prefix_len = unsafe {
                    ifa.ifa_netmask
                        .as_ref()
                        .map(|mask| {
                            ipv6_prefix_len(
                                &*(mask as *const libc::sockaddr as *const libc::sockaddr_in6),
                            )
                        })
                        .unwrap_or(0)
                };
                addresses.push(InterfaceAddress {
                    iface: name.clone(),
                    ip,
                    prefix_len,
                    mac: mac_by_iface.get(&name).cloned(),
                });
            }
            _ => {}
        }
        current = ifa.ifa_next;
    }

    unsafe { libc::freeifaddrs(ifap) };
    InterfaceInventory { addresses }
}

unsafe fn c_string(raw: *const libc::c_char) -> Option<String> {
    if raw.is_null() {
        return None;
    }
    Some(
        unsafe { CStr::from_ptr(raw) }
            .to_string_lossy()
            .into_owned(),
    )
}

fn ipv4_prefix_len(mask: &libc::sockaddr_in) -> u8 {
    mask.sin_addr
        .s_addr
        .to_le_bytes()
        .iter()
        .map(|byte| byte.count_ones())
        .sum::<u32>() as u8
}

fn ipv6_prefix_len(mask: &libc::sockaddr_in6) -> u8 {
    mask.sin6_addr
        .s6_addr
        .iter()
        .map(|byte| byte.count_ones())
        .sum::<u32>() as u8
}

fn ip_matches_prefix(left: &IpAddr, right: &IpAddr, prefix_len: u8) -> bool {
    match (left, right) {
        (IpAddr::V4(left), IpAddr::V4(right)) => {
            if prefix_len == 0 {
                return false;
            }
            let mask = if prefix_len >= 32 {
                u32::MAX
            } else {
                (!0u32) << (32 - prefix_len)
            };
            let left = u32::from_be_bytes(left.octets());
            let right = u32::from_be_bytes(right.octets());
            (left & mask) == (right & mask)
        }
        (IpAddr::V6(left), IpAddr::V6(right)) => prefix_match_v6(left, right, prefix_len),
        _ => false,
    }
}

fn prefix_match_v6(left: &Ipv6Addr, right: &Ipv6Addr, prefix_len: u8) -> bool {
    if prefix_len == 0 {
        return false;
    }
    let left = left.octets();
    let right = right.octets();
    let whole_bytes = (prefix_len / 8) as usize;
    let remainder = prefix_len % 8;
    if left[..whole_bytes] != right[..whole_bytes] {
        return false;
    }
    if remainder == 0 {
        return true;
    }
    let mask = (!0u8) << (8 - remainder);
    (left[whole_bytes] & mask) == (right[whole_bytes] & mask)
}

fn classify_socket_scope(socket: &SocketEntry, interfaces: &InterfaceInventory) -> SocketScope {
    if socket.is_listener() || socket.remote_ip.is_unspecified() {
        return SocketScope::default();
    }
    if interfaces.is_local_host(&socket.remote_ip) {
        return SocketScope {
            local_host: true,
            ..SocketScope::default()
        };
    }
    if interfaces.is_same_lan(&socket.remote_ip) {
        return SocketScope {
            same_lan: true,
            ..SocketScope::default()
        };
    }
    if socket.remote_ip.is_loopback() {
        return SocketScope {
            local_host: true,
            ..SocketScope::default()
        };
    }
    SocketScope {
        cross_network: true,
        ..SocketScope::default()
    }
}

async fn scan_proc_socket_owners(target_inodes: &HashSet<u64>) -> HashMap<u64, SocketOwner> {
    let mut unresolved = target_inodes.clone();
    let Ok(mut proc_dir) = fs::read_dir("/proc").await else {
        return HashMap::new();
    };
    let mut pids = Vec::new();
    while let Ok(Some(entry)) = proc_dir.next_entry().await {
        if let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() {
            pids.push(pid);
        }
    }
    pids.sort_unstable();

    let mut owners = HashMap::new();
    for pid in pids {
        if unresolved.is_empty() {
            break;
        }
        let fd_dir_path = format!("/proc/{pid}/fd");
        let Ok(mut fd_dir) = fs::read_dir(&fd_dir_path).await else {
            continue;
        };
        let mut base_meta: Option<SocketOwner> = None;
        while let Ok(Some(entry)) = fd_dir.next_entry().await {
            let Ok(fd) = entry.file_name().to_string_lossy().parse::<i32>() else {
                continue;
            };
            let Ok(target) = fs::read_link(entry.path()).await else {
                continue;
            };
            let Some(inode) = parse_socket_inode(&target) else {
                continue;
            };
            if !unresolved.contains(&inode) {
                continue;
            }
            if base_meta.is_none() {
                base_meta = read_process_owner(pid).await;
            }
            if let Some(base_meta) = &base_meta {
                owners.insert(
                    inode,
                    SocketOwner {
                        fd,
                        ..base_meta.clone()
                    },
                );
                unresolved.remove(&inode);
            }
            if unresolved.is_empty() {
                break;
            }
        }
    }
    owners
}

fn parse_socket_inode(target: &PathBuf) -> Option<u64> {
    let raw = target.to_string_lossy();
    let value = raw.strip_prefix("socket:[")?.strip_suffix(']')?;
    value.parse::<u64>().ok()
}

async fn read_process_owner(pid: u32) -> Option<SocketOwner> {
    let process = read_process_name(pid).await?;
    let exe_path = fs::read_link(format!("/proc/{pid}/exe"))
        .await
        .ok()
        .map(|path| truncate_text(path.to_string_lossy().as_ref(), MAX_EXE_LEN));
    let cmdline = read_process_cmdline(pid).await;
    let cgroup = read_process_cgroup(pid).await;
    Some(SocketOwner {
        pid,
        fd: -1,
        process,
        exe_path,
        cmdline,
        cgroup,
    })
}

async fn read_process_name(pid: u32) -> Option<String> {
    let raw = fs::read_to_string(format!("/proc/{pid}/comm")).await.ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

async fn read_process_cmdline(pid: u32) -> Option<String> {
    let raw = fs::read(format!("/proc/{pid}/cmdline")).await.ok()?;
    if raw.is_empty() {
        return None;
    }
    let mut parts = Vec::new();
    let mut start = 0usize;
    for (idx, byte) in raw.iter().enumerate() {
        if *byte == 0 {
            if idx > start {
                parts.push(String::from_utf8_lossy(&raw[start..idx]).to_string());
            }
            start = idx + 1;
        }
    }
    if start < raw.len() {
        parts.push(String::from_utf8_lossy(&raw[start..]).to_string());
    }
    let joined = parts.join(" ");
    if joined.trim().is_empty() {
        None
    } else {
        Some(truncate_text(&joined, MAX_CMDLINE_LEN))
    }
}

async fn read_process_cgroup(pid: u32) -> Option<String> {
    let raw = fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .await
        .ok()?;
    let value = raw
        .lines()
        .filter_map(|line| line.rsplit(':').next())
        .find(|segment| !segment.trim().is_empty())?;
    Some(truncate_text(value.trim(), MAX_CGROUP_LEN))
}

#[cfg(target_os = "linux")]
fn read_tcp_socket_stats(pid: u32, fd: i32) -> Option<TcpSocketStats> {
    if fd < 0 {
        return None;
    }

    // `pidfd_getfd` duplicates the target socket descriptor without touching the
    // traced process. That keeps attribution cheap and avoids packet capture.
    let pidfd =
        unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) as libc::c_int };
    if pidfd < 0 {
        return None;
    }
    let dupfd = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd, fd, 0) as libc::c_int };
    unsafe {
        libc::close(pidfd);
    }
    if dupfd < 0 {
        return None;
    }

    let mut info: LinuxTcpInfo = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<LinuxTcpInfo>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            dupfd,
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            &mut info as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    unsafe {
        libc::close(dupfd);
    }
    if rc != 0 {
        return None;
    }

    let byte_counters_available = len as usize >= std::mem::size_of::<LinuxTcpInfo>();
    Some(TcpSocketStats {
        byte_counters_available,
        bytes_acked: if byte_counters_available {
            info.tcpi_bytes_acked
        } else {
            0
        },
        bytes_received: if byte_counters_available {
            info.tcpi_bytes_received
        } else {
            0
        },
        rtt_ms: info.tcpi_rtt as f64 / 1000.0,
        total_retrans: info.tcpi_total_retrans,
    })
}

#[cfg(not(target_os = "linux"))]
fn read_tcp_socket_stats(_pid: u32, _fd: i32) -> Option<TcpSocketStats> {
    None
}

fn track_rate(cache: &mut HashMap<String, f64>, key: &str, value: f64) -> f64 {
    let entry = cache.entry(key.to_string()).or_insert(value.max(1.0));
    *entry = (*entry * 0.95).max(value).max(1.0);
    (value / *entry).clamp(0.0, 1.0)
}

fn track_level(cache: &mut HashMap<String, f64>, key: &str, value: f64) -> f64 {
    match cache.entry(key.to_string()) {
        std::collections::hash_map::Entry::Occupied(mut entry) => {
            let peak = (*entry.get() * 0.985).max(value).max(1.0);
            *entry.get_mut() = peak;
            (value / peak).clamp(0.0, 1.0)
        }
        std::collections::hash_map::Entry::Vacant(entry) => {
            entry.insert(value.max(1.0));
            1.0
        }
    }
}

fn growth_pct_per_min(
    first: Option<&SummaryPoint>,
    last: Option<&SummaryPoint>,
    project: impl Fn(&SummaryPoint) -> f64,
) -> f64 {
    let (Some(first), Some(last)) = (first, last) else {
        return 0.0;
    };
    if last.ts_ms <= first.ts_ms {
        return 0.0;
    }
    let elapsed_min = (last.ts_ms - first.ts_ms) as f64 / 60_000.0;
    if elapsed_min <= 0.0 {
        return 0.0;
    }
    let start = project(first);
    let end = project(last);
    if start <= 0.0 {
        return if end <= 0.0 { 0.0 } else { 100.0 };
    }
    ((end - start) / start) * 100.0 / elapsed_min
}

fn ratio_from_count(value: usize) -> f64 {
    ((value as f64) / 64.0).clamp(0.0, 1.0)
}

fn ratio_from_growth_pct(value: f64) -> f64 {
    (value.abs() / 200.0).clamp(0.0, 1.0)
}

fn severity_from_count(value: usize) -> Severity {
    if value >= 48 {
        Severity::High
    } else if value >= 16 {
        Severity::Medium
    } else {
        Severity::Low
    }
}

fn severity_from_growth(value: f64) -> Severity {
    if value.abs() >= 120.0 {
        Severity::High
    } else if value.abs() >= 45.0 {
        Severity::Medium
    } else {
        Severity::Low
    }
}

fn severity_from_signal(signal: f64) -> Severity {
    if signal >= 0.92 {
        Severity::High
    } else if signal >= 0.75 {
        Severity::Medium
    } else {
        Severity::Low
    }
}

fn flow_severity(signal: f64, rtt_ms: f64, cross_network: bool) -> Severity {
    if signal >= 0.92 || rtt_ms >= 160.0 {
        Severity::High
    } else if signal >= 0.75 || (cross_network && rtt_ms >= 80.0) {
        Severity::Medium
    } else {
        Severity::Low
    }
}

fn truncate_text(value: &str, max_len: usize) -> String {
    value.chars().take(max_len).collect::<String>()
}

fn listener_key(socket: &SocketEntry) -> String {
    format!(
        "{}:{}:{}:{}",
        socket.protocol.as_str(),
        socket.local_ip,
        socket.local_port,
        socket.inode
    )
}

async fn emit_ebpf_metrics(
    bus: &EventBus,
    storage: &Storage,
    config: &EmbeddedConfig,
    snapshot: Option<&crate::network_ebpf::NetworkEbpfSnapshot>,
    collector_backend: &str,
) {
    let enabled = !matches!(
        config
            .network_ebpf_mode
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "disabled" | ""
    );
    let active = snapshot.is_some_and(|snapshot| snapshot.active);
    let total_events = snapshot
        .map(|snapshot| snapshot.total_events)
        .unwrap_or_default();
    let established_events = snapshot
        .map(|snapshot| snapshot.established_events)
        .unwrap_or_default();
    let closing_events = snapshot
        .map(|snapshot| snapshot.closing_events)
        .unwrap_or_default();
    let alerted_surfaces = snapshot
        .map(|snapshot| snapshot.alerted_surfaces)
        .unwrap_or_default();
    let source = snapshot
        .map(|snapshot| snapshot.source.clone())
        .unwrap_or_else(|| config.network_ebpf_program.clone());
    let detail = snapshot
        .and_then(|snapshot| snapshot.detail.clone())
        .unwrap_or_default();
    let signal = ebpf_signal(total_events as usize, config.network_ebpf_burst_threshold);
    let severity = ebpf_severity(
        enabled,
        active,
        total_events as usize,
        alerted_surfaces,
        config.network_ebpf_burst_threshold,
    );
    let common_attrs = vec![
        ("collector_backend", collector_backend.to_string()),
        ("ebpf_enabled", enabled.to_string()),
        ("ebpf_active", active.to_string()),
        ("ebpf_source", source.clone()),
        ("ebpf_detail", truncate_text(&detail, 160)),
    ];

    emit_summary_metric(
        bus,
        storage,
        "network_ebpf_events",
        total_events as f64,
        "count",
        signal,
        severity,
        &common_attrs,
    )
    .await;
    emit_summary_metric(
        bus,
        storage,
        "network_ebpf_established_events",
        established_events as f64,
        "count",
        ebpf_signal(
            established_events as usize,
            config.network_ebpf_burst_threshold,
        ),
        if active && established_events > 0 {
            Severity::Low
        } else {
            severity
        },
        &common_attrs,
    )
    .await;
    emit_summary_metric(
        bus,
        storage,
        "network_ebpf_closing_events",
        closing_events as f64,
        "count",
        ebpf_signal(closing_events as usize, config.network_ebpf_burst_threshold),
        if closing_events > 0 {
            Severity::Medium
        } else {
            Severity::Low
        },
        &common_attrs,
    )
    .await;
    emit_summary_metric(
        bus,
        storage,
        "network_ebpf_alerted_surfaces",
        alerted_surfaces as f64,
        "count",
        ratio_from_count(alerted_surfaces),
        if alerted_surfaces > 1 {
            Severity::High
        } else if alerted_surfaces > 0 {
            Severity::Medium
        } else {
            Severity::Low
        },
        &common_attrs,
    )
    .await;

    if let Some(snapshot) = snapshot {
        for surface in snapshot
            .surfaces
            .iter()
            .filter(|surface| surface.events > 0)
        {
            let signal = ebpf_signal(surface.events as usize, config.network_ebpf_burst_threshold);
            emit_network_metric(
                bus,
                storage,
                "network_ebpf_surface_events",
                surface.events as f64,
                "count",
                signal,
                ebpf_severity(
                    enabled,
                    active,
                    surface.events as usize,
                    usize::from(surface.events > 0),
                    config.network_ebpf_burst_threshold,
                ),
                &[
                    ("collector_backend", collector_backend.to_string()),
                    ("surface", surface.surface.clone()),
                    ("local_port", surface.local_port.to_string()),
                    ("established_events", surface.established_events.to_string()),
                    ("closing_events", surface.closing_events.to_string()),
                    ("ebpf_source", source.clone()),
                ],
            )
            .await;
        }
    }
}

fn ebpf_signal(total_events: usize, burst_threshold: usize) -> f64 {
    (total_events as f64 / burst_threshold.max(1) as f64).clamp(0.0, 1.0)
}

fn ebpf_severity(
    enabled: bool,
    active: bool,
    total_events: usize,
    alerted_surfaces: usize,
    burst_threshold: usize,
) -> Severity {
    if enabled && !active {
        Severity::Medium
    } else if alerted_surfaces > 1 || total_events >= burst_threshold.saturating_mul(2) {
        Severity::High
    } else if total_events >= burst_threshold || alerted_surfaces > 0 {
        Severity::Medium
    } else {
        Severity::Low
    }
}

async fn emit_summary_metric(
    bus: &EventBus,
    storage: &Storage,
    metric: &str,
    value: f64,
    unit: &str,
    signal: f64,
    severity: Severity,
    attrs: &[(&str, String)],
) {
    emit_network_metric(bus, storage, metric, value, unit, signal, severity, attrs).await;
}

async fn emit_network_metric(
    bus: &EventBus,
    storage: &Storage,
    metric: &str,
    value: f64,
    unit: &str,
    signal: f64,
    severity: Severity,
    attrs: &[(&str, String)],
) {
    let id = NETWORK_EVENT_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut event = Event::new(id, "embedded", EventKind::NetworkFlow, signal, severity)
        .with_attr("metric", metric)
        .with_attr("value", format!("{value:.3}"))
        .with_attr("unit", unit);
    for (key, value) in attrs {
        event = event.with_attr(*key, value.clone());
    }
    bus.publish(event.clone());
    storage.record_event(event).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_proc_socket_address() {
        let (ip, port) = parse_socket_address("017AA8C0:01BB").expect("socket");
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(192, 168, 122, 1)));
        assert_eq!(port, 443);
    }

    #[test]
    fn parses_ipv6_proc_socket_address() {
        let (ip, port) =
            parse_socket_address("0000000000000000FFFF00000100007F:CE5D").expect("socket");
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(port, 52_829);
    }

    #[test]
    fn parses_socket_inode_symlink() {
        let target = PathBuf::from("socket:[123456]");
        assert_eq!(parse_socket_inode(&target), Some(123_456));
    }

    #[test]
    fn classifies_tcp_listen_state() {
        let state = socket_state_label(Protocol::Tcp, "0A", IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        assert_eq!(state, "listen");
    }
}
