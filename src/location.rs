use crate::coordination::{CoordinatorRole, PresenceRecord};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock, RwLock};
use std::time::Duration;

const MAX_LABEL_LEN: usize = 64;
const BLOCKED_IP_LOCATION_MAX_ENTRIES: usize = 24;
const BLOCKED_IP_PROBE_TIMEOUT_MS: u64 = 180;
const BLOCKED_IP_PROBE_CACHE_TTL_MS: u64 = 24 * 60 * 60 * 1000;
const BLOCKED_IP_PROBE_SCHEDULE_COOLDOWN_MS: u64 = 30_000;
const BLOCKED_IP_PROBE_SCHEDULE_BUDGET: usize = 1;
const BLOCKED_IP_PROBE_PORTS: &[u16] = &[443, 80];
#[cfg(test)]
const BLOCKED_IP_ACTIVE_PROBING_ENABLED: bool = false;
#[cfg(not(test))]
const BLOCKED_IP_ACTIVE_PROBING_ENABLED: bool = true;
const GENERIC_TOKENS: &[&str] = &[
    "tracey",
    "agent",
    "host",
    "node",
    "server",
    "srv",
    "status",
    "local",
    "localhost",
    "internal",
    "cluster",
    "lan",
    "corp",
];

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct LocationGuess {
    pub label: String,
    pub confidence: f64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentLocationSnapshot {
    pub agent_id: String,
    #[serde(default)]
    pub agent_version: Option<String>,
    pub host: String,
    pub system: Option<String>,
    pub cpu: Option<String>,
    pub process: Option<String>,
    pub threads: Option<usize>,
    pub relation: String,
    pub latency_ms: Option<u64>,
    pub status_addr: Option<String>,
    pub advertise_addr: Option<String>,
    pub observed_addr: Option<String>,
    pub addresses: Vec<String>,
    pub tags: Vec<String>,
    pub secure_status: bool,
    pub is_self: bool,
    pub is_coordinator: bool,
    pub geo: Option<LocationGuess>,
    pub site: Option<LocationGuess>,
    pub building: Option<LocationGuess>,
    pub room: Option<LocationGuess>,
    pub network: Option<LocationGuess>,
    pub physical: Option<LocationGuess>,
    pub evidence: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct BlockedIpProbeSnapshot {
    pub mode: String,
    pub status: String,
    pub sampled_at_ms: Option<u64>,
    pub open_ports: Vec<u16>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct BlockedIpLocationSnapshot {
    pub ip: String,
    pub source: String,
    pub ban_count: u32,
    pub last_ban_ms: u64,
    pub confidence: f64,
    pub geo: Option<LocationGuess>,
    pub site: Option<LocationGuess>,
    pub room: Option<LocationGuess>,
    pub network: Option<LocationGuess>,
    pub physical: Option<LocationGuess>,
    pub evidence: Vec<String>,
    pub probe: BlockedIpProbeSnapshot,
}

#[derive(Clone, Debug, Default)]
struct BlockedIpProbeCacheEntry {
    sampled_at_ms: u64,
    open_ports: Vec<u16>,
}

#[derive(Clone, Debug, Default)]
struct BlockedIpAggregate {
    ip: String,
    ban_count: u32,
    last_ban_ms: u64,
    local_seen: bool,
    remote_seen: bool,
}

#[derive(Clone, Debug, Default)]
struct LocationHints {
    geo: Option<String>,
    site: Option<String>,
    building: Option<String>,
    room: Option<String>,
}

#[derive(Clone, Debug, Default)]
struct LocalStaticFacts {
    hostname: Option<String>,
    timezone: Option<String>,
    route_ips: Vec<String>,
    threads: Option<usize>,
    container_runtime: Option<String>,
    vm_product: Option<String>,
}

#[derive(Clone, Debug, Default)]
struct RawAgentContext {
    agent_id: String,
    agent_version: Option<String>,
    host_label: String,
    system_label: Option<String>,
    cpu_label: Option<String>,
    process_label: Option<String>,
    threads: Option<usize>,
    relation: String,
    latency_ms: Option<u64>,
    status_addr: Option<String>,
    advertise_addr: Option<String>,
    observed_addr: Option<String>,
    addresses: Vec<String>,
    tags: Vec<String>,
    secure_status: bool,
    is_self: bool,
    is_coordinator: bool,
}

#[derive(Clone, Debug, Default)]
struct DirectInference {
    geo: Option<LocationGuess>,
    site: Option<LocationGuess>,
    building: Option<LocationGuess>,
    room: Option<LocationGuess>,
    network: Option<LocationGuess>,
    physical: Option<LocationGuess>,
}

static LOCAL_STATIC_FACTS: OnceLock<LocalStaticFacts> = OnceLock::new();
static BLOCKED_IP_PROBE_CACHE: OnceLock<RwLock<HashMap<String, BlockedIpProbeCacheEntry>>> =
    OnceLock::new();
static BLOCKED_IP_PROBE_INFLIGHT: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
static BLOCKED_IP_LAST_PROBE_SCHEDULE_MS: AtomicU64 = AtomicU64::new(0);

pub fn local_capability_tags() -> Vec<String> {
    let hints = LocationHints::from_env();
    let facts = local_static_facts();
    let mut tags = Vec::new();

    if let Some(hostname) = facts.hostname.as_deref() {
        if let Some(tag) = prefixed_tag("host", hostname) {
            tags.push(tag);
        }
    }
    if let Some(site) = hints.site.as_deref() {
        if let Some(tag) = prefixed_tag("site", site) {
            tags.push(tag);
        }
    }
    if let Some(building) = hints.building.as_deref() {
        if let Some(tag) = prefixed_tag("building", building) {
            tags.push(tag);
        }
    }
    if let Some(room) = hints.room.as_deref() {
        if let Some(tag) = prefixed_tag("room", room) {
            tags.push(tag);
        }
    }
    if let Some(geo) = hints.geo.as_deref().or(facts.timezone.as_deref()) {
        if let Some(tag) = prefixed_tag("geo", geo) {
            tags.push(tag);
        }
    }

    if facts.container_runtime.is_some() {
        tags.push("physical:container".to_string());
    } else if facts.vm_product.is_some() {
        tags.push("physical:virtual-machine".to_string());
    } else {
        tags.push("physical:bare-metal".to_string());
    }

    dedup_strings(tags)
}

pub fn infer_cluster_locations(
    local_agent_id: &str,
    role: &CoordinatorRole,
    local_status_addr: Option<&str>,
    presence: &[PresenceRecord],
) -> (AgentLocationSnapshot, Vec<AgentLocationSnapshot>) {
    let hints = LocationHints::from_env();
    let facts = local_static_facts();

    let local_presence = presence
        .iter()
        .find(|record| record.agent_id == local_agent_id);
    let local_ctx = build_local_context(
        local_agent_id,
        local_status_addr,
        local_presence,
        facts,
        role,
    );

    let mut peer_contexts: Vec<RawAgentContext> = presence
        .iter()
        .filter(|record| record.agent_id != local_agent_id)
        .map(|record| build_peer_context(record, role))
        .collect();
    peer_contexts.sort_by(|left, right| {
        left.latency_ms
            .cmp(&right.latency_ms)
            .then_with(|| left.host_label.cmp(&right.host_label))
            .then_with(|| left.agent_id.cmp(&right.agent_id))
    });

    let mut cluster = Vec::with_capacity(peer_contexts.len() + 1);
    cluster.push(local_ctx.clone());
    cluster.extend(peer_contexts.iter().cloned());
    let cluster_token = cluster_consensus_token(&cluster);

    let local_direct =
        infer_direct_labels(&local_ctx, &hints, facts, &cluster, cluster_token.as_ref());
    let local_snapshot = finalize_snapshot(&local_ctx, local_direct.clone());

    let peer_snapshots = peer_contexts
        .iter()
        .map(|peer| {
            let direct = infer_direct_labels(peer, &hints, facts, &cluster, cluster_token.as_ref());
            let merged = merge_peer_labels(peer, direct, &local_ctx, &local_snapshot);
            finalize_snapshot(peer, merged)
        })
        .collect();

    (local_snapshot, peer_snapshots)
}

pub fn infer_single_agent_location(
    agent_id: &str,
    status_addr: Option<&str>,
    is_coordinator: bool,
) -> AgentLocationSnapshot {
    let hints = LocationHints::from_env();
    let local_facts = local_static_facts().clone();
    let is_local_target = status_addr
        .map(|value| target_matches_local_machine(value, &local_facts))
        .unwrap_or(true);
    let inference_facts = if is_local_target {
        local_facts.clone()
    } else {
        LocalStaticFacts::default()
    };
    let node = build_single_agent_context(
        agent_id,
        status_addr,
        is_coordinator,
        is_local_target,
        &local_facts,
    );
    let cluster = vec![node.clone()];
    let inferred = infer_direct_labels(&node, &hints, &inference_facts, &cluster, None);
    finalize_snapshot(&node, inferred)
}

pub fn infer_blocked_ip_locations(
    local_entries: &[crate::tracey_ban::BanAdvertisementEntry],
    remote_entries: &[crate::tracey_ban::BanAdvertisementEntry],
    local: &AgentLocationSnapshot,
    peers: &[AgentLocationSnapshot],
) -> Vec<BlockedIpLocationSnapshot> {
    let mut aggregates: HashMap<String, BlockedIpAggregate> = HashMap::new();
    for entry in local_entries {
        accumulate_blocked_ip(&mut aggregates, entry, true);
    }
    for entry in remote_entries {
        accumulate_blocked_ip(&mut aggregates, entry, false);
    }

    let mut ordered: Vec<BlockedIpAggregate> = aggregates.into_values().collect();
    ordered.sort_by(|left, right| right.last_ban_ms.cmp(&left.last_ban_ms));
    if ordered.len() > BLOCKED_IP_LOCATION_MAX_ENTRIES {
        ordered.truncate(BLOCKED_IP_LOCATION_MAX_ENTRIES);
    }

    let mut trusted_nodes = Vec::with_capacity(peers.len() + 1);
    trusted_nodes.push(local.clone());
    trusted_nodes.extend(peers.iter().cloned());

    let mut probe_budget = BLOCKED_IP_PROBE_SCHEDULE_BUDGET;
    ordered
        .into_iter()
        .filter_map(|entry| infer_blocked_entry_location(entry, &trusted_nodes, &mut probe_budget))
        .collect()
}

fn accumulate_blocked_ip(
    aggregates: &mut HashMap<String, BlockedIpAggregate>,
    entry: &crate::tracey_ban::BanAdvertisementEntry,
    local: bool,
) {
    let Ok(parsed) = entry.ip.parse::<IpAddr>() else {
        return;
    };
    let ip = parsed.to_string();
    let slot = aggregates
        .entry(ip.clone())
        .or_insert_with(|| BlockedIpAggregate {
            ip,
            ..BlockedIpAggregate::default()
        });
    slot.ban_count = slot.ban_count.saturating_add(entry.ban_count.max(1));
    slot.last_ban_ms = slot.last_ban_ms.max(entry.last_ban_ms);
    if local {
        slot.local_seen = true;
    } else {
        slot.remote_seen = true;
    }
}

fn infer_blocked_entry_location(
    entry: BlockedIpAggregate,
    trusted_nodes: &[AgentLocationSnapshot],
    probe_budget: &mut usize,
) -> Option<BlockedIpLocationSnapshot> {
    let ip = entry.ip.parse::<IpAddr>().ok()?;
    let private_like = is_private_like(ip);
    let source_label = blocked_source_label(&entry);
    let mut evidence = vec![format!("ban intel source {}", source_label)];

    let mut confidence = if private_like { 0.46 } else { 0.28 };
    let mut site = None;
    let mut room = None;
    let mut geo = None;
    let network = Some(LocationGuess {
        label: subnet_label(ip),
        confidence: if private_like { 0.72 } else { 0.22 },
    });
    let mut physical = Some(LocationGuess {
        label: if private_like {
            "private-network".to_string()
        } else {
            "external-network".to_string()
        },
        confidence: if private_like { 0.52 } else { 0.44 },
    });

    if let Some((supporting_agent, affinity)) = best_supporting_agent(ip, trusted_nodes) {
        if affinity >= 0.34 {
            site = merge_guess(
                site,
                propagated_guess(
                    supporting_agent
                        .site
                        .as_ref()
                        .or(supporting_agent.building.as_ref()),
                    affinity,
                    0.18,
                ),
            );
            room = merge_guess(
                room,
                propagated_guess(
                    supporting_agent
                        .room
                        .as_ref()
                        .or(supporting_agent.network.as_ref()),
                    affinity,
                    0.20,
                ),
            );
            geo = merge_guess(
                geo,
                propagated_guess(
                    supporting_agent
                        .geo
                        .as_ref()
                        .or(supporting_agent.site.as_ref()),
                    affinity * 0.9,
                    0.16,
                ),
            );
            if affinity >= 0.72 {
                physical = Some(LocationGuess {
                    label: "near-authorized-node".to_string(),
                    confidence: (0.55 + 0.35 * affinity).clamp(0.0, 0.95),
                });
            }
            confidence += 0.26 * affinity;
            evidence.push(format!(
                "subnet affinity {:.0}% to authorized agent {}",
                affinity * 100.0,
                shorten(&supporting_agent.agent_id, 24)
            ));
            if supporting_agent.site.is_some() {
                evidence.push("site/room copied from nearby trusted node map".to_string());
            }
        }
    }

    if !private_like && geo.is_none() {
        geo = Some(LocationGuess {
            label: "internet".to_string(),
            confidence: 0.20,
        });
    }
    if private_like && site.is_none() {
        site = Some(LocationGuess {
            label: "private-lan".to_string(),
            confidence: 0.24,
        });
    }

    let probe = blocked_ip_probe_snapshot(&entry.ip, probe_budget);
    if probe.status == "cached" && !probe.open_ports.is_empty() {
        confidence += 0.05;
        evidence.push(format!(
            "minimal probe cached open tcp ports {}",
            probe
                .open_ports
                .iter()
                .map(|port| port.to_string())
                .collect::<Vec<_>>()
                .join(",")
        ));
        if !private_like {
            physical = Some(LocationGuess {
                label: "internet-host".to_string(),
                confidence: 0.57,
            });
        }
    } else if probe.status == "scheduled" {
        evidence.push("minimal probe scheduled (cached to avoid repeated scans)".to_string());
    } else if probe.status == "pending" {
        evidence.push("minimal probe already in progress".to_string());
    }

    confidence = confidence.clamp(0.0, 0.95);
    Some(BlockedIpLocationSnapshot {
        ip: entry.ip,
        source: source_label,
        ban_count: entry.ban_count.max(1),
        last_ban_ms: entry.last_ban_ms,
        confidence,
        geo,
        site,
        room,
        network,
        physical,
        evidence: dedup_strings(evidence),
        probe,
    })
}

fn blocked_source_label(entry: &BlockedIpAggregate) -> String {
    match (entry.local_seen, entry.remote_seen) {
        (true, true) => "local+remote".to_string(),
        (true, false) => "local".to_string(),
        (false, true) => "remote".to_string(),
        (false, false) => "unknown".to_string(),
    }
}

fn best_supporting_agent(
    blocked_ip: IpAddr,
    trusted_nodes: &[AgentLocationSnapshot],
) -> Option<(&AgentLocationSnapshot, f64)> {
    trusted_nodes
        .iter()
        .filter_map(|node| {
            let agent_ip = best_ip(&node.addresses)?;
            let affinity = blocked_ip_affinity(blocked_ip, agent_ip);
            (affinity > 0.0).then_some((node, affinity))
        })
        .max_by(|left, right| left.1.total_cmp(&right.1))
}

fn blocked_ip_affinity(left: IpAddr, right: IpAddr) -> f64 {
    match (left, right) {
        (IpAddr::V4(left), IpAddr::V4(right)) => {
            let left_octets = left.octets();
            let right_octets = right.octets();
            if left_octets[0..3] == right_octets[0..3] {
                1.0
            } else if left_octets[0..2] == right_octets[0..2] {
                0.74
            } else if left_octets[0] == right_octets[0] {
                0.38
            } else {
                0.0
            }
        }
        (IpAddr::V6(left), IpAddr::V6(right)) => {
            let left_segments = left.segments();
            let right_segments = right.segments();
            if left_segments[0..4] == right_segments[0..4] {
                1.0
            } else if left_segments[0..3] == right_segments[0..3] {
                0.70
            } else if left_segments[0..2] == right_segments[0..2] {
                0.36
            } else {
                0.0
            }
        }
        _ => 0.0,
    }
}

fn is_private_like(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(value) => value.is_private() || value.is_loopback() || value.is_link_local(),
        IpAddr::V6(value) => {
            value.is_unique_local() || value.is_loopback() || value.is_unicast_link_local()
        }
    }
}

fn blocked_ip_probe_snapshot(ip: &str, probe_budget: &mut usize) -> BlockedIpProbeSnapshot {
    let now = crate::event::now_ms();
    prune_blocked_ip_probe_cache(now);
    let cached = blocked_ip_probe_cache_entry(ip);
    if let Some(entry) = cached.as_ref() {
        if now.saturating_sub(entry.sampled_at_ms) <= BLOCKED_IP_PROBE_CACHE_TTL_MS {
            return probe_snapshot("cached", Some(entry.clone()));
        }
    }

    if !BLOCKED_IP_ACTIVE_PROBING_ENABLED {
        return probe_snapshot("disabled", cached);
    }
    if blocked_ip_probe_is_inflight(ip) {
        return probe_snapshot("pending", cached);
    }
    if *probe_budget == 0 || !permit_probe_schedule(now) {
        return probe_snapshot("deferred", cached);
    }
    if schedule_blocked_ip_probe(ip.to_string()) {
        *probe_budget = probe_budget.saturating_sub(1);
        return probe_snapshot("scheduled", cached);
    }
    probe_snapshot("deferred", cached)
}

fn blocked_ip_probe_cache_entry(ip: &str) -> Option<BlockedIpProbeCacheEntry> {
    blocked_ip_probe_cache()
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(ip)
        .cloned()
}

fn prune_blocked_ip_probe_cache(now: u64) {
    let retention = BLOCKED_IP_PROBE_CACHE_TTL_MS.saturating_mul(2);
    blocked_ip_probe_cache()
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .retain(|_, entry| now.saturating_sub(entry.sampled_at_ms) <= retention);
}

fn blocked_ip_probe_is_inflight(ip: &str) -> bool {
    blocked_ip_probe_inflight()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .contains(ip)
}

fn permit_probe_schedule(now: u64) -> bool {
    let last = BLOCKED_IP_LAST_PROBE_SCHEDULE_MS.load(Ordering::Relaxed);
    if now.saturating_sub(last) < BLOCKED_IP_PROBE_SCHEDULE_COOLDOWN_MS {
        return false;
    }
    BLOCKED_IP_LAST_PROBE_SCHEDULE_MS.store(now, Ordering::Relaxed);
    true
}

fn schedule_blocked_ip_probe(ip: String) -> bool {
    let Ok(parsed_ip) = ip.parse::<IpAddr>() else {
        return false;
    };
    {
        let mut inflight = blocked_ip_probe_inflight()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if inflight.contains(&ip) {
            return true;
        }
        inflight.insert(ip.clone());
    }

    let label = shorten(&format!("tracey-ban-{}", ip.replace(':', "_")), 24);
    let probe_ip = ip.clone();
    let thread = std::thread::Builder::new().name(label).spawn(move || {
        let open_ports = run_minimal_blocked_ip_probe(parsed_ip);
        let sampled_at_ms = crate::event::now_ms();
        blocked_ip_probe_cache()
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(
                probe_ip.clone(),
                BlockedIpProbeCacheEntry {
                    sampled_at_ms,
                    open_ports,
                },
            );
        blocked_ip_probe_inflight()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&probe_ip);
    });

    if thread.is_err() {
        blocked_ip_probe_inflight()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&ip);
        return false;
    }
    true
}

fn run_minimal_blocked_ip_probe(ip: IpAddr) -> Vec<u16> {
    let mut open_ports = Vec::new();
    for port in BLOCKED_IP_PROBE_PORTS {
        let socket = SocketAddr::new(ip, *port);
        if TcpStream::connect_timeout(&socket, Duration::from_millis(BLOCKED_IP_PROBE_TIMEOUT_MS))
            .is_ok()
        {
            open_ports.push(*port);
        }
    }
    open_ports
}

fn probe_snapshot(
    status: &str,
    cached: Option<BlockedIpProbeCacheEntry>,
) -> BlockedIpProbeSnapshot {
    BlockedIpProbeSnapshot {
        mode: "minimal_tcp_connect".to_string(),
        status: status.to_string(),
        sampled_at_ms: cached.as_ref().map(|entry| entry.sampled_at_ms),
        open_ports: cached.map(|entry| entry.open_ports).unwrap_or_default(),
    }
}

fn blocked_ip_probe_cache() -> &'static RwLock<HashMap<String, BlockedIpProbeCacheEntry>> {
    BLOCKED_IP_PROBE_CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

fn blocked_ip_probe_inflight() -> &'static Mutex<HashSet<String>> {
    BLOCKED_IP_PROBE_INFLIGHT.get_or_init(|| Mutex::new(HashSet::new()))
}

impl LocationHints {
    fn from_env() -> Self {
        Self {
            geo: env_hint(&[
                "TRACEY_GEO",
                "NM_TRACEY_GEO",
                "TRACEY_REGION",
                "NM_TRACEY_REGION",
                "TRACEY_CITY",
                "NM_TRACEY_CITY",
                "TRACEY_COUNTRY",
                "NM_TRACEY_COUNTRY",
            ]),
            site: env_hint(&[
                "TRACEY_SITE",
                "NM_TRACEY_SITE",
                "TRACEY_DC",
                "NM_TRACEY_DC",
                "SITE",
                "DATACENTER",
            ]),
            building: env_hint(&[
                "TRACEY_BUILDING",
                "NM_TRACEY_BUILDING",
                "BUILDING",
                "TRACEY_FACILITY",
                "NM_TRACEY_FACILITY",
            ]),
            room: env_hint(&[
                "TRACEY_ROOM",
                "NM_TRACEY_ROOM",
                "ROOM",
                "TRACEY_ZONE",
                "NM_TRACEY_ZONE",
                "TRACEY_RACK",
                "NM_TRACEY_RACK",
            ]),
        }
    }
}

fn local_static_facts() -> &'static LocalStaticFacts {
    LOCAL_STATIC_FACTS.get_or_init(collect_local_static_facts)
}

fn collect_local_static_facts() -> LocalStaticFacts {
    LocalStaticFacts {
        hostname: detect_hostname(),
        timezone: detect_timezone(),
        route_ips: discover_route_ips(),
        threads: detect_thread_count(),
        container_runtime: detect_container_runtime(),
        vm_product: detect_vm_product(),
    }
}

fn build_local_context(
    local_agent_id: &str,
    local_status_addr: Option<&str>,
    local_presence: Option<&PresenceRecord>,
    facts: &LocalStaticFacts,
    role: &CoordinatorRole,
) -> RawAgentContext {
    let status_addr = local_status_addr.map(|value| value.trim().to_string());
    let advertise_addr = local_presence.and_then(|record| record.advertise_addr.clone());
    let observed_addr = local_presence.and_then(|record| record.observed_addr.clone());
    let mut addresses = Vec::new();
    if let Some(addr) = status_addr.as_deref() {
        addresses.extend(address_candidates(addr));
    }
    if let Some(addr) = advertise_addr.as_deref() {
        addresses.extend(address_candidates(addr));
    }
    addresses.extend(facts.route_ips.clone());
    if let Some(addr) = observed_addr.as_deref() {
        addresses.extend(address_candidates(addr));
    }

    let host_label = facts
        .hostname
        .clone()
        .or_else(|| local_presence.and_then(|record| tag_hint(&record.tags, "host")))
        .or_else(|| host_from_agent_id(local_agent_id))
        .or_else(|| status_addr.as_deref().and_then(extract_host))
        .unwrap_or_else(|| local_agent_id.to_string());

    let cpu_cores = local_presence
        .map(|record| record.cpu_cores)
        .unwrap_or_else(num_cpus::get);
    let system_label = Some(format!(
        "{}/{}",
        local_presence
            .map(|record| record.os.as_str())
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(std::env::consts::OS),
        local_presence
            .map(|record| record.arch.as_str())
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(std::env::consts::ARCH)
    ));
    let cpu_label = Some(format!("{} cores", cpu_cores.max(1)));
    let process_label = Some(format!(
        "{} pid {}",
        local_process_name(),
        std::process::id()
    ));

    RawAgentContext {
        agent_id: local_agent_id.to_string(),
        agent_version: local_presence.and_then(|record| record.agent_version.clone()),
        host_label,
        system_label,
        cpu_label,
        process_label,
        threads: facts.threads,
        relation: relation_label(local_agent_id, role, true, role.is_coordinator),
        latency_ms: Some(0),
        status_addr: status_addr.clone(),
        advertise_addr,
        observed_addr,
        addresses: dedup_strings(addresses),
        tags: dedup_strings(
            local_presence
                .map(|record| record.tags.clone())
                .unwrap_or_else(local_capability_tags),
        ),
        secure_status: status_addr
            .as_deref()
            .is_some_and(|value| value.trim_start().starts_with("https://")),
        is_self: true,
        is_coordinator: role.is_coordinator,
    }
}

fn build_peer_context(record: &PresenceRecord, role: &CoordinatorRole) -> RawAgentContext {
    let status_addr = record.status_addr.clone();
    let advertise_addr = record.advertise_addr.clone();
    let observed_addr = record.observed_addr.clone();
    let mut addresses = Vec::new();
    if let Some(addr) = status_addr.as_deref() {
        addresses.extend(address_candidates(addr));
    }
    if let Some(addr) = advertise_addr.as_deref() {
        addresses.extend(address_candidates(addr));
    }
    if let Some(addr) = observed_addr.as_deref() {
        addresses.extend(address_candidates(addr));
    }

    let host_label = tag_hint(&record.tags, "host")
        .or_else(|| host_from_agent_id(&record.agent_id))
        .or_else(|| status_addr.as_deref().and_then(extract_host))
        .or_else(|| advertise_addr.as_deref().and_then(extract_host))
        .or_else(|| observed_addr.as_deref().and_then(extract_host))
        .unwrap_or_else(|| record.agent_id.clone());

    RawAgentContext {
        agent_id: record.agent_id.clone(),
        agent_version: record.agent_version.clone(),
        host_label,
        system_label: Some(format!("{}/{}", record.os, record.arch)),
        cpu_label: Some(format!("{} cores", record.cpu_cores.max(1))),
        process_label: None,
        threads: None,
        relation: relation_label(&record.agent_id, role, false, record.is_coordinator),
        latency_ms: Some(record.latency_ms),
        status_addr: status_addr.clone(),
        advertise_addr,
        observed_addr,
        addresses: dedup_strings(addresses),
        tags: dedup_strings(record.tags.clone()),
        secure_status: status_addr
            .as_deref()
            .is_some_and(|value| value.trim_start().starts_with("https://")),
        is_self: false,
        is_coordinator: record.is_coordinator,
    }
}

fn build_single_agent_context(
    agent_id: &str,
    status_addr: Option<&str>,
    is_coordinator: bool,
    is_local_target: bool,
    facts: &LocalStaticFacts,
) -> RawAgentContext {
    let status_addr = status_addr.map(|value| value.trim().to_string());
    let mut addresses = Vec::new();
    if let Some(addr) = status_addr.as_deref() {
        addresses.extend(address_candidates(addr));
    }
    if is_local_target {
        addresses.extend(facts.route_ips.clone());
    }

    let host_label = if is_local_target {
        facts.hostname.clone()
    } else {
        None
    }
    .or_else(|| status_addr.as_deref().and_then(extract_host))
    .or_else(|| host_from_agent_id(agent_id))
    .unwrap_or_else(|| agent_id.to_string());

    RawAgentContext {
        agent_id: agent_id.to_string(),
        agent_version: None,
        host_label,
        system_label: is_local_target
            .then(|| format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH)),
        cpu_label: is_local_target.then(|| format!("{} cores", num_cpus::get().max(1))),
        process_label: is_local_target
            .then(|| format!("{} pid {}", local_process_name(), std::process::id())),
        threads: is_local_target.then_some(facts.threads).flatten(),
        relation: if is_coordinator {
            "self,coord".to_string()
        } else {
            "self".to_string()
        },
        latency_ms: Some(0),
        status_addr: status_addr.clone(),
        advertise_addr: None,
        observed_addr: None,
        addresses: dedup_strings(addresses),
        tags: if is_local_target {
            local_capability_tags()
        } else {
            Vec::new()
        },
        secure_status: status_addr
            .as_deref()
            .is_some_and(|value| value.trim_start().starts_with("https://")),
        is_self: true,
        is_coordinator,
    }
}

fn infer_direct_labels(
    node: &RawAgentContext,
    hints: &LocationHints,
    facts: &LocalStaticFacts,
    cluster: &[RawAgentContext],
    cluster_token: Option<&LocationGuess>,
) -> DirectInference {
    let network = infer_network_guess(node, cluster);
    let room = infer_room_guess(node, hints, network.as_ref(), cluster);
    let site = infer_site_guess(node, hints, cluster_token);
    let building = infer_building_guess(node, hints, site.as_ref());
    let geo = infer_geo_guess(node, hints, facts, site.as_ref());
    let physical = infer_physical_guess(node, facts);

    DirectInference {
        geo,
        site,
        building,
        room,
        network,
        physical,
    }
}

fn merge_peer_labels(
    peer: &RawAgentContext,
    direct: DirectInference,
    local_ctx: &RawAgentContext,
    local_snapshot: &AgentLocationSnapshot,
) -> DirectInference {
    let room = merge_guess(
        propagated_guess(
            local_snapshot.room.as_ref(),
            same_room_membership(local_ctx, peer),
            0.42,
        ),
        direct.room,
    );
    let building = merge_guess(
        propagated_guess(
            local_snapshot
                .building
                .as_ref()
                .or(local_snapshot.site.as_ref()),
            same_building_membership(local_ctx, peer),
            0.34,
        ),
        direct.building,
    );
    let site = merge_guess(
        propagated_guess(
            local_snapshot.site.as_ref(),
            same_site_membership(local_ctx, peer),
            0.30,
        ),
        direct.site,
    );
    let geo = merge_guess(
        propagated_guess(
            local_snapshot.geo.as_ref(),
            same_geo_membership(local_ctx, peer),
            0.26,
        ),
        direct.geo,
    );

    DirectInference {
        geo,
        site,
        building,
        room,
        network: direct.network,
        physical: direct.physical,
    }
}

fn finalize_snapshot(node: &RawAgentContext, inferred: DirectInference) -> AgentLocationSnapshot {
    let evidence = build_evidence(node, &inferred);
    AgentLocationSnapshot {
        agent_id: node.agent_id.clone(),
        agent_version: node.agent_version.clone(),
        host: node.host_label.clone(),
        system: node.system_label.clone(),
        cpu: node.cpu_label.clone(),
        process: node.process_label.clone(),
        threads: node.threads,
        relation: node.relation.clone(),
        latency_ms: node.latency_ms,
        status_addr: node.status_addr.clone(),
        advertise_addr: node.advertise_addr.clone(),
        observed_addr: node.observed_addr.clone(),
        addresses: node.addresses.clone(),
        tags: node.tags.clone(),
        secure_status: node.secure_status,
        is_self: node.is_self,
        is_coordinator: node.is_coordinator,
        geo: inferred.geo,
        site: inferred.site,
        building: inferred.building,
        room: inferred.room,
        network: inferred.network,
        physical: inferred.physical,
        evidence,
    }
}

fn infer_network_guess(
    node: &RawAgentContext,
    cluster: &[RawAgentContext],
) -> Option<LocationGuess> {
    let primary_ip = best_ip(&node.addresses);
    if let Some(ip) = primary_ip {
        let label = subnet_label(ip);
        let peer_support = cluster
            .iter()
            .filter(|other| other.agent_id != node.agent_id)
            .filter(|other| {
                best_ip(&other.addresses).is_some_and(|other_ip| subnet_label(other_ip) == label)
            })
            .count();
        let confidence = (0.78 + (peer_support as f64 * 0.05).min(0.16)).clamp(0.0, 0.96);
        return Some(LocationGuess { label, confidence });
    }

    if let Some(host) = [
        node.status_addr.as_deref(),
        node.advertise_addr.as_deref(),
        node.observed_addr.as_deref(),
    ]
    .into_iter()
    .flatten()
    .find_map(extract_host)
    {
        return Some(LocationGuess {
            label: clean_label(&host),
            confidence: 0.46,
        });
    }

    None
}

fn infer_room_guess(
    node: &RawAgentContext,
    hints: &LocationHints,
    network: Option<&LocationGuess>,
    cluster: &[RawAgentContext],
) -> Option<LocationGuess> {
    if let Some(tag) = tag_hint(&node.tags, "room") {
        return Some(LocationGuess {
            label: tag,
            confidence: 0.95,
        });
    }
    if node.is_self
        && let Some(room) = hints.room.as_deref()
    {
        return Some(LocationGuess {
            label: room.to_string(),
            confidence: 0.99,
        });
    }
    let network = network?;
    let support = cluster
        .iter()
        .filter(|other| other.agent_id != node.agent_id)
        .filter(|other| same_room_membership(node, other) >= 0.55)
        .count();
    Some(LocationGuess {
        label: network.label.clone(),
        confidence: (network.confidence * (0.68 + (support as f64 * 0.08).min(0.22)))
            .clamp(0.0, 0.94),
    })
}

fn infer_site_guess(
    node: &RawAgentContext,
    hints: &LocationHints,
    cluster_token: Option<&LocationGuess>,
) -> Option<LocationGuess> {
    if let Some(tag) = tag_hint(&node.tags, "site") {
        return Some(LocationGuess {
            label: tag,
            confidence: 0.95,
        });
    }
    if node.is_self
        && let Some(site) = hints.site.as_deref()
    {
        return Some(LocationGuess {
            label: site.to_string(),
            confidence: 0.99,
        });
    }
    if let Some(domain) = domain_site_hint(node) {
        return Some(LocationGuess {
            label: domain,
            confidence: 0.68,
        });
    }
    if let Some(token) = cluster_token {
        return Some(token.clone());
    }
    first_location_token(node).map(|label| LocationGuess {
        label,
        confidence: 0.38,
    })
}

fn infer_building_guess(
    node: &RawAgentContext,
    hints: &LocationHints,
    site: Option<&LocationGuess>,
) -> Option<LocationGuess> {
    if let Some(tag) = tag_hint(&node.tags, "building") {
        return Some(LocationGuess {
            label: tag,
            confidence: 0.95,
        });
    }
    if node.is_self
        && let Some(building) = hints.building.as_deref()
    {
        return Some(LocationGuess {
            label: building.to_string(),
            confidence: 0.99,
        });
    }

    let tokens = host_tokens(node);
    let site_label = site.map(|guess| guess.label.as_str());
    tokens
        .into_iter()
        .find(|token| Some(token.as_str()) != site_label)
        .map(|label| LocationGuess {
            label,
            confidence: 0.48,
        })
}

fn infer_geo_guess(
    node: &RawAgentContext,
    hints: &LocationHints,
    facts: &LocalStaticFacts,
    site: Option<&LocationGuess>,
) -> Option<LocationGuess> {
    if let Some(tag) = tag_hint(&node.tags, "geo") {
        return Some(LocationGuess {
            label: tag,
            confidence: 0.95,
        });
    }
    if node.is_self
        && let Some(geo) = hints.geo.as_deref()
    {
        return Some(LocationGuess {
            label: geo.to_string(),
            confidence: 0.99,
        });
    }
    if node.is_self
        && let Some(timezone) = facts.timezone.as_deref()
    {
        return Some(LocationGuess {
            label: clean_label(timezone),
            confidence: 0.62,
        });
    }
    site.map(|guess| LocationGuess {
        label: guess.label.clone(),
        confidence: (guess.confidence * 0.62).clamp(0.0, 0.58),
    })
}

fn infer_physical_guess(node: &RawAgentContext, facts: &LocalStaticFacts) -> Option<LocationGuess> {
    if let Some(tag) = tag_hint(&node.tags, "physical") {
        return Some(LocationGuess {
            label: tag,
            confidence: 0.96,
        });
    }
    if node.tags.iter().any(|tag| tag == "jetson") {
        return Some(LocationGuess {
            label: "edge-jetson".to_string(),
            confidence: 0.94,
        });
    }
    if node.is_self {
        if facts.container_runtime.is_some() {
            return Some(LocationGuess {
                label: "container".to_string(),
                confidence: 0.95,
            });
        }
        if facts.vm_product.is_some() {
            return Some(LocationGuess {
                label: "virtual-machine".to_string(),
                confidence: 0.90,
            });
        }
        return Some(LocationGuess {
            label: "bare-metal".to_string(),
            confidence: 0.58,
        });
    }
    if node.tags.iter().any(|tag| tag.starts_with("slurm:")) {
        return Some(LocationGuess {
            label: "cluster-node".to_string(),
            confidence: 0.58,
        });
    }
    Some(LocationGuess {
        label: "host".to_string(),
        confidence: 0.28,
    })
}

fn propagated_guess(
    source: Option<&LocationGuess>,
    membership: f64,
    min_confidence: f64,
) -> Option<LocationGuess> {
    let source = source?;
    let confidence = (source.confidence * (0.40 + membership * 0.55)).clamp(0.0, 0.96);
    (confidence >= min_confidence).then(|| LocationGuess {
        label: source.label.clone(),
        confidence,
    })
}

fn merge_guess(
    preferred: Option<LocationGuess>,
    fallback: Option<LocationGuess>,
) -> Option<LocationGuess> {
    match (preferred, fallback) {
        (Some(left), Some(right)) => {
            if left.label.eq_ignore_ascii_case(&right.label) {
                Some(LocationGuess {
                    label: left.label,
                    confidence: left.confidence.max(right.confidence),
                })
            } else if left.confidence >= right.confidence {
                Some(left)
            } else {
                Some(right)
            }
        }
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    }
}

fn same_room_membership(left: &RawAgentContext, right: &RawAgentContext) -> f64 {
    (0.60 * same_subnet_membership(left, right)
        + 0.25 * latency_membership(right.latency_ms)
        + 0.15 * token_affinity(left, right))
    .clamp(0.0, 1.0)
}

fn same_building_membership(left: &RawAgentContext, right: &RawAgentContext) -> f64 {
    (0.35 * same_subnet_membership(left, right)
        + 0.20 * latency_membership(right.latency_ms)
        + 0.45 * token_affinity(left, right))
    .clamp(0.0, 1.0)
}

fn same_site_membership(left: &RawAgentContext, right: &RawAgentContext) -> f64 {
    let domain =
        if domain_site_hint(left).is_some() && domain_site_hint(left) == domain_site_hint(right) {
            1.0
        } else {
            0.0
        };
    (0.55 * domain
        + 0.25 * token_affinity(left, right)
        + 0.20 * latency_membership(right.latency_ms))
    .clamp(0.0, 1.0)
}

fn same_geo_membership(left: &RawAgentContext, right: &RawAgentContext) -> f64 {
    (0.55 * same_site_membership(left, right)
        + 0.20 * same_subnet_membership(left, right)
        + 0.25 * latency_membership(right.latency_ms))
    .clamp(0.0, 1.0)
}

fn same_subnet_membership(left: &RawAgentContext, right: &RawAgentContext) -> f64 {
    match (best_ip(&left.addresses), best_ip(&right.addresses)) {
        (Some(left_ip), Some(right_ip)) if subnet_label(left_ip) == subnet_label(right_ip) => 1.0,
        (Some(IpAddr::V4(left_ip)), Some(IpAddr::V4(right_ip)))
            if left_ip.octets()[0..2] == right_ip.octets()[0..2] =>
        {
            0.72
        }
        (Some(IpAddr::V6(left_ip)), Some(IpAddr::V6(right_ip)))
            if left_ip.segments()[0..3] == right_ip.segments()[0..3] =>
        {
            0.66
        }
        _ => 0.0,
    }
}

fn latency_membership(latency_ms: Option<u64>) -> f64 {
    let latency = latency_ms.unwrap_or(250);
    match latency {
        0..=2 => 1.0,
        3..=5 => 0.90,
        6..=12 => 0.72,
        13..=30 => 0.48,
        31..=80 => 0.24,
        81..=150 => 0.12,
        _ => 0.04,
    }
}

fn token_affinity(left: &RawAgentContext, right: &RawAgentContext) -> f64 {
    let left_tokens = location_tokens(left);
    let right_tokens = location_tokens(right);
    if left_tokens.is_empty() || right_tokens.is_empty() {
        return 0.0;
    }

    let left_set: BTreeSet<_> = left_tokens.into_iter().collect();
    let right_set: BTreeSet<_> = right_tokens.into_iter().collect();
    let overlap = left_set.intersection(&right_set).count();
    let total = left_set.union(&right_set).count().max(1);
    overlap as f64 / total as f64
}

fn cluster_consensus_token(cluster: &[RawAgentContext]) -> Option<LocationGuess> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for node in cluster {
        let seen: BTreeSet<_> = location_tokens(node).into_iter().collect();
        for token in seen {
            *counts.entry(token).or_default() += 1;
        }
    }

    let (label, count) = counts
        .into_iter()
        .filter(|(_, count)| *count > 1)
        .max_by(|left, right| left.1.cmp(&right.1).then_with(|| left.0.cmp(&right.0)))?;

    Some(LocationGuess {
        label,
        confidence: (0.30 + (count as f64 / cluster.len().max(1) as f64) * 0.52).clamp(0.0, 0.82),
    })
}

fn host_tokens(node: &RawAgentContext) -> Vec<String> {
    let mut tokens = Vec::new();
    tokens.extend(tokenize(&node.host_label));
    for addr in [
        node.status_addr.as_deref(),
        node.advertise_addr.as_deref(),
        node.observed_addr.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if let Some(host) = extract_host(addr) {
            tokens.extend(tokenize(&host));
        }
    }
    dedup_strings(tokens)
}

fn location_tokens(node: &RawAgentContext) -> Vec<String> {
    let mut tokens = host_tokens(node);
    for prefix in ["site", "building", "room", "geo"] {
        if let Some(tag) = tag_hint(&node.tags, prefix) {
            tokens.extend(tokenize(&tag));
        }
    }
    dedup_strings(tokens)
}

fn first_location_token(node: &RawAgentContext) -> Option<String> {
    host_tokens(node)
        .into_iter()
        .next()
        .or_else(|| location_tokens(node).into_iter().next())
}

fn domain_site_hint(node: &RawAgentContext) -> Option<String> {
    for raw in [
        node.status_addr.as_deref(),
        node.advertise_addr.as_deref(),
        node.observed_addr.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        let Some(host) = extract_host(raw) else {
            continue;
        };
        if host.parse::<IpAddr>().is_ok() {
            continue;
        }
        let labels: Vec<String> = host
            .split('.')
            .map(clean_label)
            .filter(|part| !part.is_empty() && !is_generic_token(part))
            .collect();
        if labels.len() >= 2 {
            return labels.get(1).cloned().or_else(|| labels.first().cloned());
        }
        if let Some(first) = labels.first() {
            return Some(first.clone());
        }
    }
    None
}

fn build_evidence(node: &RawAgentContext, inferred: &DirectInference) -> Vec<String> {
    let mut evidence = Vec::new();
    evidence.push(format!("host {}", clean_label(&node.host_label)));
    if let Some(network) = &inferred.network {
        evidence.push(format!(
            "net {} {:.0}%",
            network.label,
            network.confidence * 100.0
        ));
    }
    if let Some(latency_ms) = node.latency_ms {
        evidence.push(format!("lat {}ms", latency_ms));
    }
    if let Some(status) = node.status_addr.as_deref() {
        evidence.push(format!("status {}", shorten(status, 28)));
    }
    if let Some(observed) = node.observed_addr.as_deref() {
        evidence.push(format!("seen {}", shorten(observed, 24)));
    }
    if let Some(physical) = &inferred.physical {
        evidence.push(format!(
            "phys {} {:.0}%",
            physical.label,
            physical.confidence * 100.0
        ));
    }
    if !node.tags.is_empty() {
        evidence.push(format!("tags {}", shorten(&node.tags.join(","), 24)));
    }
    evidence.truncate(6);
    evidence
}

fn relation_label(
    agent_id: &str,
    role: &CoordinatorRole,
    is_self: bool,
    is_coordinator: bool,
) -> String {
    let mut parts = Vec::new();
    parts.push(if is_self { "self" } else { "peer" }.to_string());
    if is_coordinator {
        parts.push("coord".to_string());
    }
    if role.proxy_agent_id.as_deref() == Some(agent_id) {
        parts.push("proxy".to_string());
    }
    if role.prometheus_exporter_agent_id.as_deref() == Some(agent_id) {
        parts.push("exporter".to_string());
    }
    parts.join(",")
}

fn detect_hostname() -> Option<String> {
    env_hint(&["HOSTNAME", "COMPUTERNAME"])
        .or_else(|| read_trimmed("/proc/sys/kernel/hostname"))
        .or_else(|| read_trimmed("/etc/hostname"))
}

fn detect_timezone() -> Option<String> {
    env_hint(&["TZ"])
        .or_else(|| read_trimmed("/etc/timezone"))
        .or_else(|| {
            std::fs::read_link("/etc/localtime")
                .ok()
                .and_then(|path| path.to_str().map(|value| value.to_string()))
                .and_then(|path| path.split("/zoneinfo/").nth(1).map(clean_label))
        })
}

fn detect_thread_count() -> Option<usize> {
    let body = std::fs::read_to_string("/proc/self/status").ok()?;
    body.lines().find_map(|line| {
        let value = line.strip_prefix("Threads:")?;
        value.trim().parse::<usize>().ok()
    })
}

fn detect_container_runtime() -> Option<String> {
    if std::path::Path::new("/.dockerenv").exists() {
        return Some("docker".to_string());
    }
    if std::path::Path::new("/run/.containerenv").exists() {
        return Some("podman".to_string());
    }
    let cgroup = std::fs::read_to_string("/proc/1/cgroup")
        .ok()?
        .to_lowercase();
    for needle in ["docker", "containerd", "kubepods", "podman", "lxc"] {
        if cgroup.contains(needle) {
            return Some(needle.to_string());
        }
    }
    None
}

fn target_matches_local_machine(raw: &str, facts: &LocalStaticFacts) -> bool {
    let Some(host) = extract_host(raw) else {
        return false;
    };

    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }

    if let Ok(ip) = host.parse::<IpAddr>() {
        return ip.is_loopback()
            || facts
                .route_ips
                .iter()
                .filter_map(|value| value.parse::<IpAddr>().ok())
                .any(|candidate| candidate == ip);
    }

    let host_short = host.split('.').next().unwrap_or(host.as_str());
    facts.hostname.as_deref().is_some_and(|hostname| {
        let clean_hostname = clean_label(hostname);
        let hostname_short = clean_hostname
            .split('.')
            .next()
            .unwrap_or(clean_hostname.as_str());
        host.eq_ignore_ascii_case(&clean_hostname)
            || host_short.eq_ignore_ascii_case(hostname_short)
    })
}

fn detect_vm_product() -> Option<String> {
    for path in [
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/sys_vendor",
    ] {
        let Some(value) = read_trimmed(path) else {
            continue;
        };
        let lower = value.to_lowercase();
        if [
            "kvm",
            "vmware",
            "virtualbox",
            "virtual machine",
            "qemu",
            "hyper-v",
        ]
        .iter()
        .any(|needle| lower.contains(needle))
        {
            return Some(value);
        }
    }
    None
}

fn discover_route_ips() -> Vec<String> {
    let mut out = Vec::new();
    for (bind, target) in [
        ("0.0.0.0:0", "8.8.8.8:80"),
        ("0.0.0.0:0", "1.1.1.1:80"),
        ("[::]:0", "[2001:4860:4860::8888]:80"),
    ] {
        let Ok(socket) = UdpSocket::bind(bind) else {
            continue;
        };
        if socket.connect(target).is_err() {
            continue;
        }
        let Ok(addr) = socket.local_addr() else {
            continue;
        };
        let ip = addr.ip();
        if ip.is_loopback() || ip.is_unspecified() {
            continue;
        }
        out.push(ip.to_string());
    }
    dedup_strings(out)
}

fn env_hint(keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| std::env::var(key).ok())
        .and_then(|value| {
            let cleaned = clean_label(&value);
            (!cleaned.is_empty()).then_some(cleaned)
        })
}

fn read_trimmed(path: &str) -> Option<String> {
    let body = std::fs::read_to_string(path).ok()?;
    let cleaned = clean_label(&body);
    (!cleaned.is_empty()).then_some(cleaned)
}

fn local_process_name() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|path| {
            path.file_name()
                .and_then(|name| name.to_str().map(str::to_string))
        })
        .unwrap_or_else(|| "tracey".to_string())
}

fn prefixed_tag(prefix: &str, value: &str) -> Option<String> {
    let value = tag_component(value);
    (!value.is_empty()).then(|| format!("{prefix}:{value}"))
}

fn tag_hint(tags: &[String], prefix: &str) -> Option<String> {
    tags.iter().find_map(|tag| {
        let value = tag.strip_prefix(&format!("{prefix}:"))?;
        let label = clean_label(&value.replace('_', " "));
        (!label.is_empty()).then_some(label)
    })
}

fn extract_host(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let trimmed = trimmed
        .strip_prefix("http://")
        .or_else(|| trimmed.strip_prefix("https://"))
        .unwrap_or(trimmed);
    let authority = trimmed.split('/').next().unwrap_or(trimmed);
    if let Some(host) = authority.strip_prefix('[') {
        return host.split(']').next().map(clean_label);
    }
    if authority.bytes().filter(|byte| *byte == b':').count() > 1 {
        return Some(clean_label(authority));
    }
    Some(clean_label(
        authority.split(':').next().unwrap_or(authority),
    ))
}

fn address_candidates(raw: &str) -> Vec<String> {
    extract_host(raw).into_iter().collect()
}

fn host_from_agent_id(agent_id: &str) -> Option<String> {
    let trimmed = clean_label(agent_id);
    if trimmed.is_empty() {
        return None;
    }
    if let Some((host, suffix)) = trimmed.rsplit_once('-')
        && suffix.chars().all(|ch| ch.is_ascii_digit())
    {
        return Some(clean_label(host));
    }
    Some(trimmed)
}

fn best_ip(values: &[String]) -> Option<IpAddr> {
    let mut best = None;
    let mut best_score = i32::MIN;
    for value in values {
        let Ok(ip) = value.parse::<IpAddr>() else {
            continue;
        };
        let score = ip_score(ip);
        if score > best_score {
            best = Some(ip);
            best_score = score;
        }
    }
    best
}

fn ip_score(ip: IpAddr) -> i32 {
    match ip {
        IpAddr::V4(value) => {
            if value.is_loopback() || value.is_unspecified() {
                0
            } else if value.is_private() {
                4
            } else {
                3
            }
        }
        IpAddr::V6(value) => {
            if value.is_loopback() || value.is_unspecified() {
                0
            } else if value.is_unique_local() {
                4
            } else if value.is_unicast_link_local() {
                1
            } else {
                3
            }
        }
    }
}

fn subnet_label(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(value) => {
            let octets = value.octets();
            format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2])
        }
        IpAddr::V6(value) => {
            let segments = value.segments();
            format!(
                "{:x}:{:x}:{:x}:{:x}::/64",
                segments[0], segments[1], segments[2], segments[3]
            )
        }
    }
}

fn tokenize(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    for ch in value.chars() {
        let ch = ch.to_ascii_lowercase();
        if ch.is_ascii_alphanumeric() {
            current.push(ch);
        } else if !current.is_empty() {
            if !is_generic_token(&current) && !current.chars().all(|c| c.is_ascii_digit()) {
                out.push(current.clone());
            }
            current.clear();
        }
    }
    if !current.is_empty()
        && !is_generic_token(&current)
        && !current.chars().all(|c| c.is_ascii_digit())
    {
        out.push(current);
    }
    dedup_strings(out)
}

fn is_generic_token(value: &str) -> bool {
    GENERIC_TOKENS.contains(&value)
}

fn clean_label(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut last_space = false;
    for ch in value.trim().chars() {
        if ch.is_control() {
            continue;
        }
        if ch.is_whitespace() {
            if !last_space {
                out.push(' ');
            }
            last_space = true;
        } else {
            out.push(ch);
            last_space = false;
        }
    }
    if out.len() > MAX_LABEL_LEN {
        out.truncate(MAX_LABEL_LEN);
    }
    out.trim().to_string()
}

fn tag_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        let ch = ch.to_ascii_lowercase();
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch);
        } else if ch == ' ' || ch == '/' || ch == '.' || ch == ':' {
            out.push('_');
        }
    }
    if out.len() > MAX_LABEL_LEN {
        out.truncate(MAX_LABEL_LEN);
    }
    out.trim_matches('_').to_string()
}

fn dedup_strings(values: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for value in values {
        if value.trim().is_empty() {
            continue;
        }
        if seen.insert(value.clone()) {
            out.push(value);
        }
    }
    out
}

fn shorten(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        value.to_string()
    } else {
        value
            .chars()
            .take(max.saturating_sub(3))
            .collect::<String>()
            + "..."
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordination::{CoordinatorRole, PrometheusProbe};
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn role() -> CoordinatorRole {
        CoordinatorRole {
            agent_id: "alpha-1000".to_string(),
            score: 1,
            is_coordinator: true,
            leader_rank: 0,
            leader_count: 1,
            epoch: 1,
            last_update_ms: 1,
            proxy_agent_id: Some("alpha-1000".to_string()),
            proxy_latency_ms: Some(0),
            proxy_addr: Some("http://10.42.7.10:48000".to_string()),
            is_prometheus_exporter: true,
            prometheus_exporter_agent_id: Some("alpha-1000".to_string()),
            prometheus_exporter_addr: Some("http://10.42.7.10:48000".to_string()),
            prometheus_exporter_latency_ms: Some(2),
            prometheus_exporter_bandwidth_mbps: Some(42.0),
            prometheus_probe: Some(PrometheusProbe {
                ready: true,
                latency_ms: 2,
                bandwidth_mbps: 42.0,
                sampled_at_ms: 1,
            }),
        }
    }

    fn record(
        agent_id: &str,
        status_addr: &str,
        observed_addr: &str,
        latency_ms: u64,
    ) -> PresenceRecord {
        PresenceRecord {
            agent_id: agent_id.to_string(),
            agent_version: Some(crate::package_version().to_string()),
            score: 1,
            cpu_cores: 8,
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            latency_ms,
            advertise_addr: Some(status_addr.to_string()),
            status_addr: Some(status_addr.to_string()),
            observed_addr: Some(observed_addr.to_string()),
            tags: vec!["physical:bare-metal".to_string()],
            is_coordinator: agent_id == "alpha-1000",
            epoch: 1,
            last_seen_ms: 1,
            prometheus_probe: None,
        }
    }

    #[test]
    fn subnet_label_formats_ipv4_and_ipv6() {
        assert_eq!(
            subnet_label(IpAddr::V4(Ipv4Addr::new(10, 42, 7, 11))),
            "10.42.7.0/24"
        );
        assert_eq!(
            subnet_label(IpAddr::V6(Ipv6Addr::new(0xfd00, 1, 2, 3, 4, 5, 6, 7))),
            "fd00:1:2:3::/64"
        );
    }

    #[test]
    fn location_inference_uses_subnet_for_room_grouping() {
        let local = record(
            "alpha-1000",
            "http://10.42.7.10:48000",
            "10.42.7.10:47990",
            0,
        );
        let peer = record(
            "beta-1001",
            "http://10.42.7.11:48000",
            "10.42.7.11:47990",
            3,
        );
        let (self_loc, peers) = infer_cluster_locations(
            "alpha-1000",
            &role(),
            Some("http://10.42.7.10:48000"),
            &[local, peer],
        );
        assert_eq!(
            self_loc.room.as_ref().map(|guess| guess.label.as_str()),
            Some("10.42.7.0/24")
        );
        assert_eq!(
            peers[0].room.as_ref().map(|guess| guess.label.as_str()),
            Some("10.42.7.0/24")
        );
        assert!(peers[0].room.as_ref().unwrap().confidence >= 0.42);
    }

    #[test]
    fn location_inference_preserves_https_security_state() {
        let local = record(
            "alpha-1000",
            "https://tracey.example.com:48000/status",
            "203.0.113.10:47990",
            0,
        );
        let (self_loc, peers) = infer_cluster_locations(
            "alpha-1000",
            &role(),
            Some("https://tracey.example.com:48000/status"),
            &[local],
        );
        assert!(self_loc.secure_status);
        assert!(peers.is_empty());
        assert_eq!(
            self_loc.agent_version.as_deref(),
            Some(crate::package_version())
        );
    }

    #[test]
    fn location_inference_uses_peer_tokens_for_site_consensus() {
        let local = record(
            "cortex-a-1000",
            "http://cortex-a.lab.example.com:48000",
            "10.0.0.10:47990",
            0,
        );
        let peer = record(
            "cortex-b-1001",
            "http://cortex-b.lab.example.com:48000",
            "10.0.0.11:47990",
            4,
        );
        let (self_loc, peers) = infer_cluster_locations(
            "cortex-a-1000",
            &role(),
            Some("http://cortex-a.lab.example.com:48000"),
            &[local, peer],
        );
        assert_eq!(
            self_loc.site.as_ref().map(|guess| guess.label.as_str()),
            Some("lab")
        );
        assert_eq!(
            peers[0].site.as_ref().map(|guess| guess.label.as_str()),
            Some("lab")
        );
        assert_eq!(
            peers[0].agent_version.as_deref(),
            Some(crate::package_version())
        );
    }

    #[test]
    fn single_agent_inference_uses_local_runtime_for_loopback_targets() {
        let snapshot =
            infer_single_agent_location("alpha-1000", Some("http://127.0.0.1:48000/status"), true);

        assert_eq!(snapshot.agent_id, "alpha-1000");
        assert!(snapshot.is_self);
        assert!(snapshot.is_coordinator);
        assert!(!snapshot.secure_status);
        assert!(snapshot.process.is_some());
        assert!(snapshot.system.is_some());
        assert!(snapshot.room.is_some());
        assert!(snapshot.network.is_some());
        assert!(!snapshot.evidence.is_empty());
    }

    #[test]
    fn single_agent_inference_keeps_remote_targets_remote() {
        let snapshot = infer_single_agent_location(
            "cortex-west-1000",
            Some("https://cortex-west.lab.example.com:48000/status"),
            false,
        );

        assert_eq!(snapshot.agent_id, "cortex-west-1000");
        assert!(snapshot.is_self);
        assert!(!snapshot.is_coordinator);
        assert!(snapshot.secure_status);
        assert!(snapshot.process.is_none());
        assert!(snapshot.system.is_none());
        assert_eq!(
            snapshot.site.as_ref().map(|guess| guess.label.as_str()),
            Some("lab")
        );
    }

    #[test]
    fn blocked_ip_location_inference_uses_trusted_agent_affinity() {
        let local = AgentLocationSnapshot {
            agent_id: "tracey-alpha".to_string(),
            host: "alpha".to_string(),
            addresses: vec!["10.42.7.10".to_string()],
            site: Some(LocationGuess {
                label: "lab".to_string(),
                confidence: 0.92,
            }),
            room: Some(LocationGuess {
                label: "rack-7".to_string(),
                confidence: 0.94,
            }),
            network: Some(LocationGuess {
                label: "10.42.7.0/24".to_string(),
                confidence: 0.90,
            }),
            physical: Some(LocationGuess {
                label: "bare-metal".to_string(),
                confidence: 0.80,
            }),
            is_self: true,
            ..AgentLocationSnapshot::default()
        };
        let local_entries = vec![crate::tracey_ban::BanAdvertisementEntry {
            ip: "10.42.7.250".to_string(),
            jail: "web-api-rate-abuse".to_string(),
            expires_ms: None,
            ban_count: 3,
            last_ban_ms: 100,
        }];

        let inferred = infer_blocked_ip_locations(&local_entries, &[], &local, &[]);
        assert_eq!(inferred.len(), 1);
        assert_eq!(inferred[0].ip, "10.42.7.250");
        assert_eq!(inferred[0].source, "local");
        assert_eq!(
            inferred[0].site.as_ref().map(|guess| guess.label.as_str()),
            Some("lab")
        );
        assert_eq!(
            inferred[0].room.as_ref().map(|guess| guess.label.as_str()),
            Some("rack-7")
        );
        assert!(inferred[0].confidence >= 0.55);
    }

    #[test]
    fn blocked_ip_location_inference_merges_local_and_remote_sources() {
        let local = AgentLocationSnapshot {
            agent_id: "tracey-alpha".to_string(),
            host: "alpha".to_string(),
            addresses: vec!["10.42.7.10".to_string()],
            is_self: true,
            ..AgentLocationSnapshot::default()
        };
        let local_entries = vec![crate::tracey_ban::BanAdvertisementEntry {
            ip: "185.136.52.240".to_string(),
            jail: "web-file-scan-probe".to_string(),
            expires_ms: None,
            ban_count: 2,
            last_ban_ms: 100,
        }];
        let remote_entries = vec![crate::tracey_ban::BanAdvertisementEntry {
            ip: "185.136.52.240".to_string(),
            jail: "web-file-scan-probe".to_string(),
            expires_ms: None,
            ban_count: 1,
            last_ban_ms: 120,
        }];

        let inferred = infer_blocked_ip_locations(&local_entries, &remote_entries, &local, &[]);
        assert_eq!(inferred.len(), 1);
        assert_eq!(inferred[0].source, "local+remote");
        assert_eq!(inferred[0].ban_count, 3);
        assert_eq!(inferred[0].last_ban_ms, 120);
        assert_eq!(inferred[0].probe.status, "disabled");
    }
}
