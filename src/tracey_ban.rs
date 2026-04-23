//! TraceyBan-compatible jail runtime with local/remote ban intelligence sharing.

use crate::bus::EventBus;
use crate::config::{TraceyBanConfig, TraceyBanJailConfig};
use crate::event::{Event, EventKind, Severity, now_ms};
use crate::shutdown::ShutdownListener;
use crate::storage::{BanUpdateRecord, Storage};
use crate::swarm::AdaptiveScorer;
use regex::{Captures, Regex};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};
use tokio::process::Command;
use tokio::sync::{RwLock, mpsc, oneshot};

static TRACEY_BAN_FUZZY_EVENT_COUNTER: AtomicU64 = AtomicU64::new(20_000_000);
const TRACEY_BAN_ELEVATION_MARKER: &str = "TRACEY_TRACEY_BAN_ELEVATED";
const ROOT_LOG_PREFIXES: &[&str] = &[
    "/var/log/",
    "/var/lib/journal/",
    "/run/log/journal/",
    "/var/audit/",
    "/var/ossec/",
];
const FIREWALL_ACTION_KEYWORDS: &[&str] = &[
    "iptables",
    "ip6tables",
    "nft",
    "ipset",
    "ufw",
    "firewall-cmd",
    "pfctl",
    "netsh advfirewall",
];
const TRACEY_BAN_LOCAL_SNAPSHOT_MAX_ENTRIES: usize = 128;
const TRACEY_BAN_REMOTE_SNAPSHOT_MAX_ENTRIES: usize = 128;

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TraceyBanFirewallBackend {
    Ufw,
    Firewalld,
    Nftables,
    #[default]
    Unknown,
}

impl TraceyBanFirewallBackend {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ufw => "ufw",
            Self::Firewalld => "firewalld",
            Self::Nftables => "nftables",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TraceyBanSummary {
    pub ts_ms: u64,
    pub enabled: bool,
    pub jail_count: usize,
    pub active_jails: usize,
    pub local_ban_count: usize,
    pub remote_ban_count: usize,
    pub remote_agents: usize,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TraceyBanJailSnapshot {
    pub name: String,
    pub enabled: bool,
    pub backend: String,
    pub filter_catalog: Option<String>,
    pub action_catalog: Option<String>,
    pub firewall_backend: String,
    pub resolved_firewall_backend: String,
    pub firewalld_zone: Option<String>,
    pub last_backend_refresh_ms: u64,
    pub monitor_logs: bool,
    pub monitor_journal: bool,
    pub monitor_events: bool,
    pub max_retry: u32,
    pub find_time_ms: u64,
    pub ban_time_ms: i64,
    pub active_bans: usize,
    pub recidive_entries: usize,
    pub ports: Vec<u16>,
    pub protocol: String,
    pub log_paths: Vec<String>,
    pub journal_matches: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TraceyBanStatusSnapshot {
    pub summary: TraceyBanSummary,
    pub jails: Vec<TraceyBanJailSnapshot>,
    pub local_entries: Vec<BanAdvertisementEntry>,
    pub remote_entries: Vec<BanAdvertisementEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "operation")]
pub enum TraceyBanControlRequest {
    Ban {
        jail: String,
        ip: String,
        #[serde(default)]
        reason: Option<String>,
        #[serde(default)]
        source: Option<String>,
        #[serde(default)]
        ban_time_ms: Option<u64>,
    },
    Unban {
        jail: String,
        ip: String,
        #[serde(default)]
        reason: Option<String>,
        #[serde(default)]
        source: Option<String>,
    },
    RefreshBackend {
        #[serde(default)]
        jail: Option<String>,
    },
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TraceyBanControlTarget {
    pub jail: String,
    pub ip: Option<String>,
    pub resolved_firewall_backend: String,
    pub active_bans: usize,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TraceyBanControlResponse {
    pub ok: bool,
    pub operation: String,
    pub message: String,
    pub targets: Vec<TraceyBanControlTarget>,
    pub updated_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TraceyBanFilterCatalogInfo {
    pub name: String,
    pub description: String,
    pub log_paths: Vec<String>,
    pub journal_matches: Vec<String>,
    pub ports: Vec<u16>,
    pub protocol: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TraceyBanActionCatalogInfo {
    pub name: String,
    pub description: String,
}

#[derive(Clone)]
pub struct TraceyBanRuntimeHandle {
    control_tx: Option<mpsc::Sender<TraceyBanControlEnvelope>>,
    snapshot: Arc<RwLock<TraceyBanStatusSnapshot>>,
    intel_hub: BanIntelHub,
}

impl TraceyBanRuntimeHandle {
    pub fn disabled(intel_hub: BanIntelHub) -> Self {
        let mut snapshot = TraceyBanStatusSnapshot::default();
        snapshot.summary.enabled = false;
        snapshot.summary.ts_ms = now_ms();
        Self {
            control_tx: None,
            snapshot: Arc::new(RwLock::new(snapshot)),
            intel_hub,
        }
    }

    pub fn intel_hub(&self) -> BanIntelHub {
        self.intel_hub.clone()
    }

    pub async fn snapshot(&self) -> TraceyBanStatusSnapshot {
        let mut snapshot = self.snapshot.read().await.clone();
        let intel = self
            .intel_hub
            .snapshot(
                TRACEY_BAN_LOCAL_SNAPSHOT_MAX_ENTRIES.max(TRACEY_BAN_REMOTE_SNAPSHOT_MAX_ENTRIES),
            )
            .await;
        snapshot.summary.ts_ms = now_ms();
        snapshot.summary.local_ban_count = intel.local_ban_count;
        snapshot.summary.remote_ban_count = intel.remote_ban_count;
        snapshot.summary.remote_agents = intel.remote_agents;
        snapshot.local_entries = intel.local_entries;
        snapshot.remote_entries = intel.remote_entries;
        snapshot
    }

    pub async fn apply_control(
        &self,
        request: TraceyBanControlRequest,
    ) -> TraceyBanControlResponse {
        let Some(control_tx) = &self.control_tx else {
            return TraceyBanControlResponse {
                ok: false,
                operation: control_operation_name(&request).to_string(),
                message: "tracey_ban runtime disabled".to_string(),
                targets: Vec::new(),
                updated_ms: now_ms(),
            };
        };

        let (response_tx, response_rx) = oneshot::channel();
        if control_tx
            .send(TraceyBanControlEnvelope {
                request,
                response_tx,
            })
            .await
            .is_err()
        {
            return TraceyBanControlResponse {
                ok: false,
                operation: "control".to_string(),
                message: "tracey_ban runtime unavailable".to_string(),
                targets: Vec::new(),
                updated_ms: now_ms(),
            };
        }

        match response_rx.await {
            Ok(response) => response,
            Err(_) => TraceyBanControlResponse {
                ok: false,
                operation: "control".to_string(),
                message: "tracey_ban control response channel closed".to_string(),
                targets: Vec::new(),
                updated_ms: now_ms(),
            },
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BanAdvertisementEntry {
    pub ip: String,
    pub jail: String,
    pub expires_ms: Option<u64>,
    pub ban_count: u32,
    pub last_ban_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct BanAdvertisement {
    pub ts_ms: u64,
    pub epoch: u64,
    pub entries: Vec<BanAdvertisementEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct BanStatusSnapshot {
    pub ts_ms: u64,
    pub local_ban_count: usize,
    pub remote_ban_count: usize,
    pub remote_agents: usize,
    pub local_entries: Vec<BanAdvertisementEntry>,
    pub remote_entries: Vec<BanAdvertisementEntry>,
}

#[derive(Clone, Debug)]
struct LocalBanRecord {
    entry: BanAdvertisementEntry,
}

#[derive(Clone, Debug)]
struct RemoteBanRecord {
    ts_ms: u64,
    entries: Vec<BanAdvertisementEntry>,
}

#[derive(Default)]
struct BanIntelState {
    epoch: u64,
    local: HashMap<String, LocalBanRecord>,
    remote: HashMap<String, RemoteBanRecord>,
    remote_ttl_ms: u64,
}

#[derive(Clone)]
pub struct BanIntelHub {
    state: Arc<RwLock<BanIntelState>>,
}

impl BanIntelHub {
    pub fn new(remote_ttl_ms: u64) -> Self {
        Self {
            state: Arc::new(RwLock::new(BanIntelState {
                epoch: 0,
                local: HashMap::new(),
                remote: HashMap::new(),
                remote_ttl_ms,
            })),
        }
    }

    pub async fn update_local_ban(&self, entry: BanAdvertisementEntry) {
        let mut state = self.state.write().await;
        cleanup_expired(&mut state, now_ms());
        state.epoch = state.epoch.saturating_add(1);
        state.local.insert(
            make_ban_key(&entry.jail, &entry.ip),
            LocalBanRecord { entry },
        );
    }

    pub async fn remove_local_ban(&self, jail: &str, ip: &str) {
        let Some(ip) = normalize_ip(ip) else {
            return;
        };
        let mut state = self.state.write().await;
        cleanup_expired(&mut state, now_ms());
        if state.local.remove(&make_ban_key(jail, &ip)).is_some() {
            state.epoch = state.epoch.saturating_add(1);
        }
    }

    pub async fn clear_local_jail(&self, jail: &str) {
        let mut state = self.state.write().await;
        cleanup_expired(&mut state, now_ms());
        let before = state.local.len();
        state
            .local
            .retain(|key, _| !key.starts_with(&format!("{}::", jail)));
        if state.local.len() != before {
            state.epoch = state.epoch.saturating_add(1);
        }
    }

    pub async fn build_advertisement(&self, max_entries: usize) -> BanAdvertisement {
        let mut state = self.state.write().await;
        cleanup_expired(&mut state, now_ms());

        let mut entries: Vec<BanAdvertisementEntry> =
            state.local.values().map(|v| v.entry.clone()).collect();
        entries.sort_by(|a, b| b.last_ban_ms.cmp(&a.last_ban_ms));
        if entries.len() > max_entries {
            entries.truncate(max_entries);
        }

        BanAdvertisement {
            ts_ms: now_ms(),
            epoch: state.epoch,
            entries,
        }
    }

    pub async fn ingest_remote(&self, agent_id: &str, advertisement: BanAdvertisement) {
        let mut state = self.state.write().await;
        cleanup_expired(&mut state, now_ms());

        let mut entries = Vec::with_capacity(advertisement.entries.len());
        for mut entry in advertisement.entries {
            let Some(ip) = normalize_ip(&entry.ip) else {
                continue;
            };
            entry.ip = ip;
            entries.push(entry);
        }

        state.remote.insert(
            agent_id.to_string(),
            RemoteBanRecord {
                ts_ms: advertisement.ts_ms,
                entries,
            },
        );
    }

    pub async fn remote_support_count(&self, ip: &str) -> usize {
        let Some(normalized) = normalize_ip(ip) else {
            return 0;
        };
        let mut state = self.state.write().await;
        cleanup_expired(&mut state, now_ms());
        state
            .remote
            .values()
            .filter(|record| record.entries.iter().any(|entry| entry.ip == normalized))
            .count()
    }

    pub async fn snapshot(&self, max_entries: usize) -> BanStatusSnapshot {
        let mut state = self.state.write().await;
        cleanup_expired(&mut state, now_ms());

        let mut local_entries: Vec<BanAdvertisementEntry> =
            state.local.values().map(|v| v.entry.clone()).collect();
        local_entries.sort_by(|a, b| b.last_ban_ms.cmp(&a.last_ban_ms));

        let mut remote_entries: Vec<BanAdvertisementEntry> = state
            .remote
            .values()
            .flat_map(|record| record.entries.iter().cloned())
            .collect();
        remote_entries.sort_by(|a, b| b.last_ban_ms.cmp(&a.last_ban_ms));

        BanStatusSnapshot {
            ts_ms: now_ms(),
            local_ban_count: local_entries.len(),
            remote_ban_count: remote_entries.len(),
            remote_agents: state.remote.len(),
            local_entries: local_entries.into_iter().take(max_entries).collect(),
            remote_entries: remote_entries.into_iter().take(max_entries).collect(),
        }
    }
}

fn cleanup_expired(state: &mut BanIntelState, now: u64) {
    state
        .local
        .retain(|_, record| record.entry.expires_ms.is_none_or(|expires| expires > now));

    let remote_ttl_ms = state.remote_ttl_ms;
    state
        .remote
        .retain(|_, record| now.saturating_sub(record.ts_ms) <= remote_ttl_ms);
    for record in state.remote.values_mut() {
        record
            .entries
            .retain(|entry| entry.expires_ms.is_none_or(|expires| expires > now));
    }
}

fn make_ban_key(jail: &str, ip: &str) -> String {
    format!("{}::{}", jail, ip)
}

#[derive(Clone, Debug)]
struct Detection {
    jail: String,
    ip: String,
    ts_ms: u64,
    source: String,
    reason: String,
    line: Option<String>,
}

#[derive(Clone, Debug)]
struct FuzzyBanDecision {
    risk: f64,
    confidence: f64,
    telemetry: BanFuzzyTelemetry,
    adjusted_retry: u32,
    signal: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct BanFuzzyTelemetry {
    order: u8,
    z_abs: f64,
    core_risk: f64,
    interval_width: f64,
    edge_membership: f64,
    security_context: f64,
    aarnn_context: f64,
    learned_confidence: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ActiveBan {
    jail: String,
    ip: String,
    banned_at_ms: u64,
    expires_ms: Option<u64>,
    ban_count: u32,
    source: String,
    reason: String,
    fuzzy_risk: Option<f64>,
    fuzzy_confidence: Option<f64>,
    fuzzy_signal: Option<f64>,
    fuzzy_adjusted_retry: Option<u32>,
    fuzzy_telemetry: Option<BanFuzzyTelemetry>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct PersistedState {
    version: u8,
    offsets: HashMap<String, u64>,
    bans: Vec<ActiveBan>,
    ban_counts: HashMap<String, u32>,
}

#[derive(Clone, Debug)]
struct ParsedFilterDefinition {
    fail: Vec<String>,
    ignore: Vec<String>,
    journal_matches: Vec<String>,
}

#[derive(Clone, Debug)]
struct FilterCatalogDefinition {
    description: &'static str,
    log_paths: &'static [&'static str],
    journal_matches: &'static [&'static str],
    fail_regex: &'static [&'static str],
    ignore_regex: &'static [&'static str],
    ports: &'static [u16],
    protocol: &'static str,
}

#[derive(Clone, Debug, Default)]
struct FirewallBackendProbe {
    ufw_available: bool,
    ufw_active: bool,
    firewalld_available: bool,
    firewalld_running: bool,
    nft_available: bool,
}

#[derive(Debug)]
struct TraceyBanControlEnvelope {
    request: TraceyBanControlRequest,
    response_tx: oneshot::Sender<TraceyBanControlResponse>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JailActionKind {
    Start,
    Stop,
    Ban,
    Unban,
}

impl JailActionKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Ban => "ban",
            Self::Unban => "unban",
        }
    }
}

#[derive(Clone, Debug)]
struct CommandRunResult {
    success: bool,
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
    timed_out: bool,
    error: Option<String>,
}

#[derive(Clone, Debug)]
enum IgnoreNetwork {
    V4 { network: u32, prefix: u8 },
    V6 { network: u128, prefix: u8 },
}

impl IgnoreNetwork {
    fn parse(input: &str) -> Option<Self> {
        let (ip, prefix) = input.trim().split_once('/')?;
        let prefix = prefix.parse::<u8>().ok()?;
        match ip.parse::<IpAddr>().ok()? {
            IpAddr::V4(addr) if prefix <= 32 => {
                let network = mask_ipv4(u32::from(addr), prefix);
                Some(Self::V4 { network, prefix })
            }
            IpAddr::V6(addr) if prefix <= 128 => {
                let network = mask_ipv6(u128::from_be_bytes(addr.octets()), prefix);
                Some(Self::V6 { network, prefix })
            }
            _ => None,
        }
    }

    fn contains(&self, ip: &IpAddr) -> bool {
        match (self, ip) {
            (Self::V4 { network, prefix }, IpAddr::V4(addr)) => {
                mask_ipv4(u32::from(*addr), *prefix) == *network
            }
            (Self::V6 { network, prefix }, IpAddr::V6(addr)) => {
                mask_ipv6(u128::from_be_bytes(addr.octets()), *prefix) == *network
            }
            _ => false,
        }
    }
}

fn mask_ipv4(value: u32, prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        value & (!0u32 << (32 - prefix))
    }
}

fn mask_ipv6(value: u128, prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        value & (!0u128 << (128 - prefix))
    }
}

struct JailRuntime {
    config: TraceyBanJailConfig,
    fail_regex: Vec<Regex>,
    ignore_regex: Vec<Regex>,
    prefilter_regex: Option<Regex>,
    ignore_ip_set: HashSet<IpAddr>,
    ignore_networks: Vec<IgnoreNetwork>,
    ignore_ip_raw: HashSet<String>,
    failure_windows: HashMap<String, VecDeque<u64>>,
    active_bans: HashMap<String, ActiveBan>,
    ban_counts: HashMap<String, u32>,
    scorer: AdaptiveScorer,
    resolved_firewall_backend: TraceyBanFirewallBackend,
    resolved_firewalld_zone: Option<String>,
    last_backend_refresh_ms: u64,
}

impl JailRuntime {
    fn from_config(config: &TraceyBanJailConfig, tracey_ban_cfg: &TraceyBanConfig) -> Option<Self> {
        if !config.enabled {
            return None;
        }

        let mut config = match merge_filter_catalog_into_jail(config) {
            Ok(config) => config,
            Err(err) => {
                tracing::warn!(jail = %config.name, error = %err, "tracey_ban filter catalog resolution failed");
                return None;
            }
        };

        let mut fail_patterns = config.fail_regex.clone();
        let mut ignore_patterns = config.ignore_regex.clone();
        let mut journal_matches = config.journal_matches.clone();
        for filter_file in &config.filter_files {
            if let Ok(parsed) = parse_tracey_ban_filter_file(filter_file) {
                fail_patterns.extend(parsed.fail);
                ignore_patterns.extend(parsed.ignore);
                journal_matches.extend(parsed.journal_matches);
            }
        }

        let fail_regex = compile_regexes(&fail_patterns, "failregex", &config.name);
        if fail_regex.is_empty() {
            tracing::warn!(
                jail = %config.name,
                "tracey_ban jail has no valid fail regex; jail disabled"
            );
            return None;
        }

        let ignore_regex = compile_regexes(&ignore_patterns, "ignoreregex", &config.name);
        let prefilter_regex = config
            .prefilter_regex
            .as_ref()
            .and_then(|p| Regex::new(p).ok());

        let mut ignore_ip_set = HashSet::new();
        let mut ignore_networks = Vec::new();
        let mut ignore_ip_raw = HashSet::new();
        for ip in &config.ignore_ips {
            if let Ok(parsed) = ip.parse::<IpAddr>() {
                ignore_ip_set.insert(parsed);
            } else if let Some(network) = IgnoreNetwork::parse(ip) {
                ignore_networks.push(network);
            } else {
                ignore_ip_raw.insert(ip.trim().to_ascii_lowercase());
            }
        }

        config.journal_matches.extend(journal_matches);
        dedup_vec(&mut config.journal_matches);

        Some(Self {
            config,
            fail_regex,
            ignore_regex,
            prefilter_regex,
            ignore_ip_set,
            ignore_networks,
            ignore_ip_raw,
            failure_windows: HashMap::new(),
            active_bans: HashMap::new(),
            ban_counts: HashMap::new(),
            scorer: AdaptiveScorer::new(tracey_ban_cfg.min_samples, tracey_ban_cfg.fuzzy.clone()),
            resolved_firewall_backend: TraceyBanFirewallBackend::Unknown,
            resolved_firewalld_zone: None,
            last_backend_refresh_ms: 0,
        })
    }

    fn should_process_logs(&self) -> bool {
        matches!(
            self.config.backend.as_str(),
            "auto" | "file" | "polling" | "pyinotify" | "hybrid"
        ) && !self.config.log_paths.is_empty()
    }

    fn should_process_journal(&self) -> bool {
        matches!(
            self.config.backend.as_str(),
            "auto" | "systemd" | "journal" | "hybrid"
        ) && !self.config.journal_matches.is_empty()
    }

    fn should_process_events(&self) -> bool {
        matches!(
            self.config.backend.as_str(),
            "event" | "tracey_event" | "hybrid"
        )
    }

    fn is_ignored_ip(&self, ip: &str) -> bool {
        if let Ok(addr) = ip.parse::<IpAddr>() {
            return self.ignore_ip_set.contains(&addr)
                || self
                    .ignore_networks
                    .iter()
                    .any(|network| network.contains(&addr));
        }
        self.ignore_ip_raw.contains(&ip.to_ascii_lowercase())
    }
}

fn compile_regexes(patterns: &[String], label: &str, jail: &str) -> Vec<Regex> {
    let mut out = Vec::new();
    for pattern in patterns {
        let translated = match translate_tracey_ban_regex(pattern) {
            Ok(translated) => translated,
            Err(err) => {
                tracing::warn!(
                    jail = jail,
                    regex = %pattern,
                    error = %err,
                    "unsupported {} skipped", label
                );
                continue;
            }
        };
        match Regex::new(&translated) {
            Ok(regex) => out.push(regex),
            Err(err) => tracing::warn!(
                jail = jail,
                regex = %pattern,
                translated = %translated,
                error = %err,
                "invalid {} skipped", label
            ),
        }
    }
    out
}

fn built_in_filter_catalog(name: &str) -> Option<FilterCatalogDefinition> {
    const SSHD_LOG_PATHS: &[&str] = &["/var/log/auth.log", "/var/log/secure"];
    const SSHD_JOURNAL_MATCHES: &[&str] = &[
        "_SYSTEMD_UNIT=sshd.service + _COMM=sshd",
        "_SYSTEMD_UNIT=ssh.service + _COMM=sshd",
    ];
    const SSHD_FAIL_REGEX: &[&str] = &[
        r"(?i)^.*Failed password for(?: invalid user)? .* from <HOST>(?: port \d+)?(?: ssh\d+)?\s*$",
        r"(?i)^.*Invalid user .* from <HOST>(?: port \d+)?(?: ssh\d+)?\s*$",
        r"(?i)^.*(?:error: )?PAM: Authentication failure .*rhost=<HOST>.*$",
        r"(?i)^.*maximum authentication attempts exceeded .* from <HOST>(?: port \d+)?(?: ssh\d+)?\s*$",
    ];
    const SSHD_AGGRESSIVE_FAIL_REGEX: &[&str] = &[
        r"(?i)^.*Failed password for(?: invalid user)? .* from <HOST>(?: port \d+)?(?: ssh\d+)?\s*$",
        r"(?i)^.*Invalid user .* from <HOST>(?: port \d+)?(?: ssh\d+)?\s*$",
        r"(?i)^.*(?:error: )?PAM: Authentication failure .*rhost=<HOST>.*$",
        r"(?i)^.*maximum authentication attempts exceeded .* from <HOST>(?: port \d+)?(?: ssh\d+)?\s*$",
        r"(?i)^.*Disconnected from authenticating user .* <HOST>(?: port \d+)?(?: \[preauth\])?\s*$",
        r"(?i)^.*Connection closed by authenticating user .* <HOST>(?: port \d+)?(?: \[preauth\])?\s*$",
        r"(?i)^.*Received disconnect from <HOST>(?: port \d+)?:.*Too many authentication failures.*$",
    ];
    const NGINX_HTTP_AUTH_LOG_PATHS: &[&str] = &["/var/log/nginx/error.log"];
    const NGINX_HTTP_AUTH_JOURNAL_MATCHES: &[&str] = &["_SYSTEMD_UNIT=nginx.service + _COMM=nginx"];
    const NGINX_HTTP_AUTH_FAIL_REGEX: &[&str] = &[
        r#"(?i)^.*(?:password mismatch|no user/password was provided for basic authentication|user ".*" was not found).*, client: <HOST>(?:,|$).*$"#,
        r#"(?i)^.*client: <HOST>,.*(?:basic authentication|password mismatch).*$"#,
    ];
    const APACHE_AUTH_LOG_PATHS: &[&str] =
        &["/var/log/apache2/error.log", "/var/log/httpd/error_log"];
    const APACHE_AUTH_JOURNAL_MATCHES: &[&str] = &[
        "_SYSTEMD_UNIT=apache2.service + _COMM=apache2",
        "_SYSTEMD_UNIT=httpd.service + _COMM=httpd",
    ];
    const APACHE_AUTH_FAIL_REGEX: &[&str] = &[
        r"(?i)^.*\[client <HOST>(?::\d+)?\].*(?:AH01617|AH01790|authentication failure|password mismatch).*$",
        r#"(?i)^.*\[client <HOST>(?::\d+)?\].*(?:AH01618|user .* not found).*$"#,
    ];
    const POSTFIX_LOG_PATHS: &[&str] = &["/var/log/mail.log", "/var/log/maillog"];
    const POSTFIX_JOURNAL_MATCHES: &[&str] = &[
        "_SYSTEMD_UNIT=postfix.service + _COMM=postfix/smtpd",
        "_SYSTEMD_UNIT=postfix@-.service + _COMM=postfix/smtpd",
    ];
    const POSTFIX_FAIL_REGEX: &[&str] = &[
        r"(?i)^.*warning: .*?\[<HOST>\]: SASL (?:LOGIN|PLAIN|XOAUTH2|(?:CRAM|DIGEST)-MD5)? ?authentication failed:.*$",
        r"(?i)^.*lost connection after AUTH from .*?\[<HOST>\].*$",
    ];
    const RECIDIVE_LOG_PATHS: &[&str] = &["tracey.log.jsonl"];
    const RECIDIVE_FAIL_REGEX: &[&str] = &[
        r#"(?i)^\{"type":"ban_update","payload":\{.*"jail":"[^"]+".*"ip":"<HOST>".*"banned":true.*\}\}\s*$"#,
    ];
    const RECIDIVE_IGNORE_REGEX: &[&str] = &[
        r#"(?i)^\{"type":"ban_update","payload":\{.*"jail":"<TRACEY_JAIL_NAME>".*"ip":"<HOST>".*"banned":true.*\}\}\s*$"#,
    ];
    const EMPTY: &[&str] = &[];
    const EMPTY_PORTS: &[u16] = &[];
    const SSH_PORTS: &[u16] = &[22];
    const HTTP_PORTS: &[u16] = &[80, 443];
    const SMTP_PORTS: &[u16] = &[25, 465, 587];

    match name {
        "sshd" => Some(FilterCatalogDefinition {
            description: "OpenSSH authentication failures",
            log_paths: SSHD_LOG_PATHS,
            journal_matches: SSHD_JOURNAL_MATCHES,
            fail_regex: SSHD_FAIL_REGEX,
            ignore_regex: EMPTY,
            ports: SSH_PORTS,
            protocol: "tcp",
        }),
        "sshd-aggressive" => Some(FilterCatalogDefinition {
            description: "OpenSSH authentication failures plus aggressive pre-auth disconnect patterns",
            log_paths: SSHD_LOG_PATHS,
            journal_matches: SSHD_JOURNAL_MATCHES,
            fail_regex: SSHD_AGGRESSIVE_FAIL_REGEX,
            ignore_regex: EMPTY,
            ports: SSH_PORTS,
            protocol: "tcp",
        }),
        "nginx-http-auth" => Some(FilterCatalogDefinition {
            description: "Nginx basic-auth and htpasswd authentication failures",
            log_paths: NGINX_HTTP_AUTH_LOG_PATHS,
            journal_matches: NGINX_HTTP_AUTH_JOURNAL_MATCHES,
            fail_regex: NGINX_HTTP_AUTH_FAIL_REGEX,
            ignore_regex: EMPTY,
            ports: HTTP_PORTS,
            protocol: "tcp",
        }),
        "apache-auth" => Some(FilterCatalogDefinition {
            description: "Apache HTTP auth_basic/auth_digest authentication failures",
            log_paths: APACHE_AUTH_LOG_PATHS,
            journal_matches: APACHE_AUTH_JOURNAL_MATCHES,
            fail_regex: APACHE_AUTH_FAIL_REGEX,
            ignore_regex: EMPTY,
            ports: HTTP_PORTS,
            protocol: "tcp",
        }),
        "postfix" => Some(FilterCatalogDefinition {
            description: "Postfix SMTP AUTH authentication failures",
            log_paths: POSTFIX_LOG_PATHS,
            journal_matches: POSTFIX_JOURNAL_MATCHES,
            fail_regex: POSTFIX_FAIL_REGEX,
            ignore_regex: EMPTY,
            ports: SMTP_PORTS,
            protocol: "tcp",
        }),
        "recidive" => Some(FilterCatalogDefinition {
            description: "Escalate repeat offenders from TraceyBan ban records in tracey.log.jsonl",
            log_paths: RECIDIVE_LOG_PATHS,
            journal_matches: EMPTY,
            fail_regex: RECIDIVE_FAIL_REGEX,
            ignore_regex: RECIDIVE_IGNORE_REGEX,
            ports: EMPTY_PORTS,
            protocol: "tcp",
        }),
        _ => None,
    }
}

pub fn built_in_filter_catalog_summaries() -> Vec<TraceyBanFilterCatalogInfo> {
    [
        "sshd",
        "sshd-aggressive",
        "nginx-http-auth",
        "apache-auth",
        "postfix",
        "recidive",
    ]
    .into_iter()
    .filter_map(|name| {
        built_in_filter_catalog(name).map(|definition| TraceyBanFilterCatalogInfo {
            name: name.to_string(),
            description: definition.description.to_string(),
            log_paths: definition
                .log_paths
                .iter()
                .map(|value| value.to_string())
                .collect(),
            journal_matches: definition
                .journal_matches
                .iter()
                .map(|value| value.to_string())
                .collect(),
            ports: definition.ports.to_vec(),
            protocol: definition.protocol.to_string(),
        })
    })
    .collect()
}

pub fn built_in_action_catalog_summaries() -> Vec<TraceyBanActionCatalogInfo> {
    vec![
        TraceyBanActionCatalogInfo {
            name: "auto".to_string(),
            description:
                "Auto-detect active firewall management and prefer firewalld, then ufw, then nftables"
                    .to_string(),
        },
        TraceyBanActionCatalogInfo {
            name: "ufw".to_string(),
            description: "Use UFW deny/delete rules for the jail's configured ports".to_string(),
        },
        TraceyBanActionCatalogInfo {
            name: "firewalld".to_string(),
            description:
                "Use firewalld rich rules in the configured or detected zone".to_string(),
        },
        TraceyBanActionCatalogInfo {
            name: "nftables".to_string(),
            description:
                "Use nftables sets and input-chain drop rules managed by TraceyBan".to_string(),
        },
    ]
}

fn merge_filter_catalog_into_jail(
    config: &TraceyBanJailConfig,
) -> Result<TraceyBanJailConfig, String> {
    let mut resolved = config.clone();
    let Some(filter_catalog) = resolved.filter_catalog.as_deref() else {
        return Ok(resolved);
    };
    let definition = built_in_filter_catalog(filter_catalog)
        .ok_or_else(|| format!("unknown filter catalog {}", filter_catalog))?;

    extend_unique(
        &mut resolved.log_paths,
        definition.log_paths.iter().map(PathBuf::from),
    );
    extend_unique(
        &mut resolved.journal_matches,
        definition
            .journal_matches
            .iter()
            .map(|value| value.to_string()),
    );

    let mut merged_fail_regex: Vec<String> = definition
        .fail_regex
        .iter()
        .map(|value| resolve_filter_catalog_placeholders(value, &resolved))
        .collect();
    extend_unique(&mut merged_fail_regex, resolved.fail_regex.clone());
    resolved.fail_regex = merged_fail_regex;

    let mut merged_ignore_regex: Vec<String> = definition
        .ignore_regex
        .iter()
        .map(|value| resolve_filter_catalog_placeholders(value, &resolved))
        .collect();
    extend_unique(&mut merged_ignore_regex, resolved.ignore_regex.clone());
    resolved.ignore_regex = merged_ignore_regex;

    if resolved.ports.is_empty() || resolved.ports == TraceyBanJailConfig::default().ports {
        resolved.ports = definition.ports.to_vec();
    }
    if resolved.protocol.trim().is_empty()
        || resolved.protocol == TraceyBanJailConfig::default().protocol
    {
        resolved.protocol = definition.protocol.to_string();
    }

    Ok(resolved)
}

fn resolve_filter_catalog_placeholders(value: &str, config: &TraceyBanJailConfig) -> String {
    value.replace("<TRACEY_JAIL_NAME>", &regex::escape(&config.name))
}

fn extend_unique<T>(target: &mut Vec<T>, values: impl IntoIterator<Item = T>)
where
    T: PartialEq,
{
    for value in values {
        if !target.contains(&value) {
            target.push(value);
        }
    }
}

fn dedup_vec<T>(values: &mut Vec<T>)
where
    T: PartialEq,
{
    let mut idx = 0usize;
    while idx < values.len() {
        let mut remove = idx + 1;
        while remove < values.len() {
            if values[idx] == values[remove] {
                values.remove(remove);
            } else {
                remove += 1;
            }
        }
        idx += 1;
    }
}

fn autodetect_firewall_backend(probe: &FirewallBackendProbe) -> TraceyBanFirewallBackend {
    if probe.firewalld_running {
        TraceyBanFirewallBackend::Firewalld
    } else if probe.ufw_active {
        TraceyBanFirewallBackend::Ufw
    } else if probe.nft_available {
        TraceyBanFirewallBackend::Nftables
    } else {
        TraceyBanFirewallBackend::Unknown
    }
}

fn resolve_requested_firewall_backend(
    requested: &str,
    probe: &FirewallBackendProbe,
) -> TraceyBanFirewallBackend {
    match requested {
        "auto" => autodetect_firewall_backend(probe),
        "ufw" => {
            if probe.ufw_available {
                TraceyBanFirewallBackend::Ufw
            } else {
                TraceyBanFirewallBackend::Unknown
            }
        }
        "firewalld" => {
            if probe.firewalld_available {
                TraceyBanFirewallBackend::Firewalld
            } else {
                TraceyBanFirewallBackend::Unknown
            }
        }
        "nft" | "nftables" => {
            if probe.nft_available {
                TraceyBanFirewallBackend::Nftables
            } else {
                TraceyBanFirewallBackend::Unknown
            }
        }
        _ => TraceyBanFirewallBackend::Unknown,
    }
}

pub fn maybe_elevate_for_tracey_ban(config: &TraceyBanConfig) -> Option<i32> {
    if !config.enabled {
        return None;
    }
    if is_running_as_root() {
        return None;
    }

    let needs_root_logs = config
        .jails
        .iter()
        .filter(|jail| jail.enabled)
        .filter_map(|jail| merge_filter_catalog_into_jail(jail).ok())
        .flat_map(|jail| jail.log_paths.into_iter())
        .any(|path| is_root_log_path(&path));
    let needs_root_actions = config.jails.iter().filter(|jail| jail.enabled).any(|jail| {
        jail.action_catalog.is_some()
            || jail.action_start.is_some()
            || jail.action_stop.is_some()
            || jail.action_ban.is_some()
            || jail.action_unban.is_some()
    }) && config.jails.iter().filter(|jail| jail.enabled).any(|jail| {
        [
            jail.action_start.as_deref(),
            jail.action_stop.as_deref(),
            jail.action_ban.as_deref(),
            jail.action_unban.as_deref(),
        ]
        .into_iter()
        .flatten()
        .any(looks_like_firewall_rule_command)
            || jail.action_catalog.is_some()
    });

    if !needs_root_logs && !needs_root_actions {
        return None;
    }

    tracing::warn!(
        needs_root_logs,
        needs_root_actions,
        "tracey_ban requires elevated privileges for configured log paths/actions"
    );

    if !config.auto_elevate_root {
        tracing::warn!(
            "tracey_ban auto-elevation disabled; root-protected logs/firewall actions may fail"
        );
        return None;
    }
    if std::env::var_os(TRACEY_BAN_ELEVATION_MARKER).is_some() {
        tracing::warn!(
            "tracey_ban elevation already attempted in this process; continuing unprivileged"
        );
        return None;
    }

    let exe = match std::env::current_exe() {
        Ok(path) => path,
        Err(err) => {
            tracing::warn!(error=%err, "failed to resolve current executable for tracey_ban elevation");
            return None;
        }
    };

    let mut cmd = StdCommand::new(&config.sudo_program);
    if config.sudo_non_interactive {
        cmd.arg("-n");
    }
    cmd.arg(exe);
    cmd.args(std::env::args().skip(1));
    cmd.env(TRACEY_BAN_ELEVATION_MARKER, "1");

    match cmd.status() {
        Ok(status) => {
            let code = status
                .code()
                .unwrap_or(if status.success() { 0 } else { 1 });
            if status.success() {
                tracing::info!(
                    code,
                    "tracey_ban elevated process completed; exiting parent process"
                );
                Some(code)
            } else {
                tracing::warn!(
                    code,
                    "tracey_ban elevation command exited non-zero; continuing unprivileged"
                );
                None
            }
        }
        Err(err) => {
            tracing::warn!(
                sudo_program = %config.sudo_program,
                error = %err,
                "failed to execute tracey_ban elevation command; continuing unprivileged"
            );
            None
        }
    }
}

pub fn spawn_tracey_ban(
    config: TraceyBanConfig,
    bus: EventBus,
    storage: Storage,
    shutdown: ShutdownListener,
    intel_hub: BanIntelHub,
) -> TraceyBanRuntimeHandle {
    if !config.enabled {
        tracing::info!("tracey_ban runtime disabled");
        return TraceyBanRuntimeHandle::disabled(intel_hub);
    }

    let snapshot = Arc::new(RwLock::new(TraceyBanStatusSnapshot::default()));
    let (control_tx, control_rx) = mpsc::channel::<TraceyBanControlEnvelope>(128);
    let handle = TraceyBanRuntimeHandle {
        control_tx: Some(control_tx),
        snapshot: snapshot.clone(),
        intel_hub: intel_hub.clone(),
    };

    tokio::spawn(async move {
        run_tracey_ban_runtime(
            config, bus, storage, shutdown, intel_hub, snapshot, control_rx,
        )
        .await;
    });

    handle
}

async fn run_tracey_ban_runtime(
    config: TraceyBanConfig,
    bus: EventBus,
    storage: Storage,
    mut shutdown: ShutdownListener,
    intel_hub: BanIntelHub,
    snapshot: Arc<RwLock<TraceyBanStatusSnapshot>>,
    mut control_rx: mpsc::Receiver<TraceyBanControlEnvelope>,
) {
    let mut jails = HashMap::<String, JailRuntime>::new();
    for jail_cfg in &config.jails {
        if let Some(jail) = JailRuntime::from_config(jail_cfg, &config) {
            jails.insert(jail.config.name.clone(), jail);
        }
    }

    if jails.is_empty() {
        tracing::warn!("tracey_ban enabled but no usable jails configured");
        refresh_tracey_ban_snapshot(&snapshot, &jails, &intel_hub, false).await;
        return;
    }

    tracing::info!(jail_count = jails.len(), "tracey_ban runtime enabled");

    let mut persisted = load_state(&config.state_path).await;
    let offsets = Arc::new(RwLock::new(std::mem::take(&mut persisted.offsets)));

    restore_persisted_bans(&mut jails, &mut persisted, &intel_hub).await;
    refresh_firewall_backends(&config, &mut jails, None).await;

    for jail in jails.values_mut() {
        let _ = run_jail_action(&config, jail, JailActionKind::Start, None, None, None).await;
    }

    refresh_tracey_ban_snapshot(&snapshot, &jails, &intel_hub, true).await;

    let (detection_tx, mut detection_rx) = mpsc::channel::<Detection>(4096);

    for jail in jails.values() {
        if jail.should_process_logs() {
            let jail_name = jail.config.name.clone();
            let jail_cfg = jail.config.clone();
            let fail_regex = jail.fail_regex.clone();
            let ignore_regex = jail.ignore_regex.clone();
            let prefilter = jail.prefilter_regex.clone();
            let tx = detection_tx.clone();
            let offsets = offsets.clone();
            let shutdown = shutdown.clone();
            tokio::spawn(async move {
                run_log_worker(
                    jail_name,
                    jail_cfg,
                    fail_regex,
                    ignore_regex,
                    prefilter,
                    offsets,
                    tx,
                    shutdown,
                )
                .await;
            });
        }

        if jail.should_process_journal() {
            let jail_name = jail.config.name.clone();
            let jail_cfg = jail.config.clone();
            let fail_regex = jail.fail_regex.clone();
            let ignore_regex = jail.ignore_regex.clone();
            let prefilter = jail.prefilter_regex.clone();
            let tx = detection_tx.clone();
            let shutdown = shutdown.clone();
            tokio::spawn(async move {
                run_journal_worker(
                    jail_name,
                    jail_cfg,
                    fail_regex,
                    ignore_regex,
                    prefilter,
                    tx,
                    shutdown,
                )
                .await;
            });
        }

        if jail.should_process_events() {
            let jail_name = jail.config.name.clone();
            let jail_cfg = jail.config.clone();
            let fail_regex = jail.fail_regex.clone();
            let ignore_regex = jail.ignore_regex.clone();
            let prefilter = jail.prefilter_regex.clone();
            let tx = detection_tx.clone();
            let mut bus_rx = bus.subscribe();
            let shutdown = shutdown.clone();
            tokio::spawn(async move {
                run_event_worker(
                    jail_name,
                    jail_cfg,
                    fail_regex,
                    ignore_regex,
                    prefilter,
                    &mut bus_rx,
                    tx,
                    shutdown,
                )
                .await;
            });
        }
    }

    drop(detection_tx);

    let mut unban_tick = tokio::time::interval(Duration::from_millis(config.unban_check_ms));
    let mut persist_tick = tokio::time::interval(Duration::from_millis(config.persist_interval_ms));

    loop {
        tokio::select! {
            _ = shutdown.wait() => {
                tracing::info!("tracey_ban runtime shutting down");
                break;
            }
            Some(envelope) = control_rx.recv() => {
                let response = process_control_request(
                    envelope.request,
                    &mut jails,
                    &config,
                    &bus,
                    &storage,
                    &intel_hub,
                ).await;
                refresh_tracey_ban_snapshot(&snapshot, &jails, &intel_hub, true).await;
                let _ = envelope.response_tx.send(response);
            }
            Some(detection) = detection_rx.recv() => {
                process_detection(
                    detection,
                    &mut jails,
                    &config,
                    &bus,
                    &storage,
                    &intel_hub,
                ).await;
                refresh_tracey_ban_snapshot(&snapshot, &jails, &intel_hub, true).await;
            }
            _ = unban_tick.tick() => {
                process_unbans(&mut jails, &bus, &storage, &intel_hub, &config, &config.agent_id).await;
                refresh_tracey_ban_snapshot(&snapshot, &jails, &intel_hub, true).await;
            }
            _ = persist_tick.tick() => {
                persist_runtime_state(&config.state_path, &jails, &offsets).await;
            }
        }
    }

    for jail in jails.values_mut() {
        let _ = run_jail_action(&config, jail, JailActionKind::Stop, None, None, None).await;
        intel_hub.clear_local_jail(&jail.config.name).await;
    }

    persist_runtime_state(&config.state_path, &jails, &offsets).await;
    refresh_tracey_ban_snapshot(&snapshot, &jails, &intel_hub, false).await;
}

async fn refresh_tracey_ban_snapshot(
    snapshot: &Arc<RwLock<TraceyBanStatusSnapshot>>,
    jails: &HashMap<String, JailRuntime>,
    intel_hub: &BanIntelHub,
    enabled: bool,
) {
    let intel = intel_hub
        .snapshot(TRACEY_BAN_LOCAL_SNAPSHOT_MAX_ENTRIES.max(TRACEY_BAN_REMOTE_SNAPSHOT_MAX_ENTRIES))
        .await;
    let mut jail_snapshots: Vec<TraceyBanJailSnapshot> = jails
        .values()
        .map(|jail| TraceyBanJailSnapshot {
            name: jail.config.name.clone(),
            enabled: jail.config.enabled,
            backend: jail.config.backend.clone(),
            filter_catalog: jail.config.filter_catalog.clone(),
            action_catalog: jail.config.action_catalog.clone(),
            firewall_backend: jail.config.firewall_backend.clone(),
            resolved_firewall_backend: jail.resolved_firewall_backend.as_str().to_string(),
            firewalld_zone: jail.resolved_firewalld_zone.clone(),
            last_backend_refresh_ms: jail.last_backend_refresh_ms,
            monitor_logs: jail.should_process_logs(),
            monitor_journal: jail.should_process_journal(),
            monitor_events: jail.should_process_events(),
            max_retry: jail.config.max_retry,
            find_time_ms: jail.config.find_time_ms,
            ban_time_ms: jail.config.ban_time_ms,
            active_bans: jail.active_bans.len(),
            recidive_entries: jail.ban_counts.len(),
            ports: jail.config.ports.clone(),
            protocol: jail.config.protocol.clone(),
            log_paths: jail
                .config
                .log_paths
                .iter()
                .map(|path| path.display().to_string())
                .collect(),
            journal_matches: jail.config.journal_matches.clone(),
        })
        .collect();
    jail_snapshots.sort_by(|a, b| a.name.cmp(&b.name));

    let mut write = snapshot.write().await;
    write.summary = TraceyBanSummary {
        ts_ms: now_ms(),
        enabled,
        jail_count: jails.len(),
        active_jails: jail_snapshots.len(),
        local_ban_count: intel.local_ban_count,
        remote_ban_count: intel.remote_ban_count,
        remote_agents: intel.remote_agents,
    };
    write.jails = jail_snapshots;
    write.local_entries = intel.local_entries;
    write.remote_entries = intel.remote_entries;
}

async fn refresh_firewall_backends(
    config: &TraceyBanConfig,
    jails: &mut HashMap<String, JailRuntime>,
    target_jail: Option<&str>,
) {
    let probe = probe_firewall_backend().await;
    for jail in jails.values_mut() {
        if target_jail.is_some_and(|target| jail.config.name != target) {
            continue;
        }
        refresh_single_jail_backend(config, jail, &probe).await;
    }
}

async fn refresh_single_jail_backend(
    config: &TraceyBanConfig,
    jail: &mut JailRuntime,
    probe: &FirewallBackendProbe,
) {
    let resolved = match jail.config.action_catalog.as_deref() {
        Some("auto") => resolve_requested_firewall_backend(&jail.config.firewall_backend, probe),
        Some("ufw") => resolve_requested_firewall_backend("ufw", probe),
        Some("firewalld") => resolve_requested_firewall_backend("firewalld", probe),
        Some("nft") | Some("nftables") => resolve_requested_firewall_backend("nftables", probe),
        Some(other) => {
            tracing::warn!(jail = %jail.config.name, action_catalog = %other, "unknown tracey_ban action catalog");
            TraceyBanFirewallBackend::Unknown
        }
        None => TraceyBanFirewallBackend::Unknown,
    };

    jail.resolved_firewall_backend = resolved;
    jail.resolved_firewalld_zone = if resolved == TraceyBanFirewallBackend::Firewalld {
        Some(resolve_firewalld_zone(config, jail).await)
    } else {
        None
    };
    jail.last_backend_refresh_ms = now_ms();
}

async fn resolve_firewalld_zone(config: &TraceyBanConfig, jail: &JailRuntime) -> String {
    if let Some(zone) = jail
        .config
        .firewalld_zone
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    {
        return zone.to_string();
    }

    let args = vec!["firewall-cmd".to_string(), "--get-default-zone".to_string()];
    let result = run_argv_action(config, &jail.config, &args, false).await;
    if result.success {
        let zone = result.stdout.trim();
        if !zone.is_empty() {
            return zone.to_string();
        }
    }

    "public".to_string()
}

async fn process_control_request(
    request: TraceyBanControlRequest,
    jails: &mut HashMap<String, JailRuntime>,
    config: &TraceyBanConfig,
    bus: &EventBus,
    storage: &Storage,
    intel_hub: &BanIntelHub,
) -> TraceyBanControlResponse {
    match request {
        TraceyBanControlRequest::Ban {
            jail,
            ip,
            reason,
            source,
            ban_time_ms,
        } => {
            let Some(normalized_ip) = normalize_ip(&ip) else {
                return TraceyBanControlResponse {
                    ok: false,
                    operation: "ban".to_string(),
                    message: format!("invalid IP {}", ip),
                    targets: Vec::new(),
                    updated_ms: now_ms(),
                };
            };
            let Some(jail_runtime) = jails.get_mut(&jail) else {
                return TraceyBanControlResponse {
                    ok: false,
                    operation: "ban".to_string(),
                    message: format!("unknown jail {}", jail),
                    targets: Vec::new(),
                    updated_ms: now_ms(),
                };
            };

            if jail_runtime.active_bans.contains_key(&normalized_ip) {
                return TraceyBanControlResponse {
                    ok: true,
                    operation: "ban".to_string(),
                    message: format!(
                        "IP {} already banned in {}",
                        normalized_ip, jail_runtime.config.name
                    ),
                    targets: vec![control_target(jail_runtime, Some(normalized_ip))],
                    updated_ms: now_ms(),
                };
            }

            let next_ban_count = jail_runtime
                .ban_counts
                .get(&make_ban_key(&jail_runtime.config.name, &normalized_ip))
                .copied()
                .unwrap_or(0)
                + 1;
            let duration_ms = match ban_time_ms {
                Some(0) => None,
                Some(value) => Some(value),
                None => compute_ban_duration_ms(&jail_runtime.config, next_ban_count),
            };
            let manual_reason = reason
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "manual_control".to_string());
            let manual_source = source
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "manual_control".to_string());

            let ok = install_ban_record(
                jail_runtime,
                config,
                bus,
                storage,
                intel_hub,
                &normalized_ip,
                now_ms(),
                &manual_source,
                &manual_reason,
                duration_ms,
                None,
                None,
                next_ban_count,
            )
            .await;

            TraceyBanControlResponse {
                ok,
                operation: "ban".to_string(),
                message: if ok {
                    format!("banned {} in {}", normalized_ip, jail_runtime.config.name)
                } else {
                    format!(
                        "failed to enforce ban for {} in {}",
                        normalized_ip, jail_runtime.config.name
                    )
                },
                targets: vec![control_target(jail_runtime, Some(normalized_ip))],
                updated_ms: now_ms(),
            }
        }
        TraceyBanControlRequest::Unban {
            jail,
            ip,
            reason,
            source,
        } => {
            let Some(normalized_ip) = normalize_ip(&ip) else {
                return TraceyBanControlResponse {
                    ok: false,
                    operation: "unban".to_string(),
                    message: format!("invalid IP {}", ip),
                    targets: Vec::new(),
                    updated_ms: now_ms(),
                };
            };
            let Some(jail_runtime) = jails.get_mut(&jail) else {
                return TraceyBanControlResponse {
                    ok: false,
                    operation: "unban".to_string(),
                    message: format!("unknown jail {}", jail),
                    targets: Vec::new(),
                    updated_ms: now_ms(),
                };
            };

            let manual_reason = reason
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "manual_control".to_string());
            let manual_source = source
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "manual_control".to_string());

            let ok = uninstall_ban_record(
                jail_runtime,
                config,
                bus,
                storage,
                intel_hub,
                &normalized_ip,
                &manual_source,
                &manual_reason,
                config.agent_id.as_str(),
            )
            .await;

            TraceyBanControlResponse {
                ok,
                operation: "unban".to_string(),
                message: if ok {
                    format!("unbanned {} in {}", normalized_ip, jail_runtime.config.name)
                } else {
                    format!(
                        "failed to remove ban for {} in {}",
                        normalized_ip, jail_runtime.config.name
                    )
                },
                targets: vec![control_target(jail_runtime, Some(normalized_ip))],
                updated_ms: now_ms(),
            }
        }
        TraceyBanControlRequest::RefreshBackend { jail } => {
            if let Some(target) = jail.as_deref()
                && !jails.contains_key(target)
            {
                return TraceyBanControlResponse {
                    ok: false,
                    operation: "refresh_backend".to_string(),
                    message: format!("unknown jail {}", target),
                    targets: Vec::new(),
                    updated_ms: now_ms(),
                };
            }

            refresh_firewall_backends(config, jails, jail.as_deref()).await;
            let mut targets: Vec<TraceyBanControlTarget> = jails
                .values()
                .filter(|runtime| {
                    jail.as_deref()
                        .is_none_or(|target| runtime.config.name == target)
                })
                .map(|runtime| control_target(runtime, None))
                .collect();
            targets.sort_by(|a, b| a.jail.cmp(&b.jail));

            TraceyBanControlResponse {
                ok: true,
                operation: "refresh_backend".to_string(),
                message: "tracey_ban firewall backend probe refreshed".to_string(),
                targets,
                updated_ms: now_ms(),
            }
        }
    }
}

fn control_target(jail: &JailRuntime, ip: Option<String>) -> TraceyBanControlTarget {
    TraceyBanControlTarget {
        jail: jail.config.name.clone(),
        ip,
        resolved_firewall_backend: jail.resolved_firewall_backend.as_str().to_string(),
        active_bans: jail.active_bans.len(),
    }
}

fn control_operation_name(request: &TraceyBanControlRequest) -> &'static str {
    match request {
        TraceyBanControlRequest::Ban { .. } => "ban",
        TraceyBanControlRequest::Unban { .. } => "unban",
        TraceyBanControlRequest::RefreshBackend { .. } => "refresh_backend",
    }
}

async fn run_journal_worker(
    jail_name: String,
    jail_cfg: TraceyBanJailConfig,
    fail_regex: Vec<Regex>,
    ignore_regex: Vec<Regex>,
    prefilter: Option<Regex>,
    tx: mpsc::Sender<Detection>,
    mut shutdown: ShutdownListener,
) {
    let restart_delay = Duration::from_millis(jail_cfg.poll_interval_ms.max(500));

    loop {
        let mut command = Command::new("journalctl");
        command
            .arg("--no-pager")
            .arg("-n")
            .arg("0")
            .arg("-f")
            .arg("-o")
            .arg("cat");

        for matcher in &jail_cfg.journal_matches {
            match split_command_line(matcher) {
                Ok(args) => {
                    for arg in args {
                        command.arg(arg);
                    }
                }
                Err(err) => {
                    tracing::warn!(
                        jail = %jail_name,
                        matcher = %matcher,
                        error = %err,
                        "tracey_ban journalmatch could not be tokenized"
                    );
                    return;
                }
            }
        }

        command
            .kill_on_drop(true)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(err) => {
                tracing::warn!(
                    jail = %jail_name,
                    error = %err,
                    "tracey_ban journal worker failed to spawn journalctl"
                );
                tokio::select! {
                    _ = shutdown.wait() => return,
                    _ = tokio::time::sleep(restart_delay) => {}
                }
                continue;
            }
        };

        let Some(stdout) = child.stdout.take() else {
            tracing::warn!(jail = %jail_name, "tracey_ban journal worker missing stdout");
            let _ = child.kill().await;
            tokio::select! {
                _ = shutdown.wait() => return,
                _ = tokio::time::sleep(restart_delay) => {}
            }
            continue;
        };
        let Some(stderr) = child.stderr.take() else {
            tracing::warn!(jail = %jail_name, "tracey_ban journal worker missing stderr");
            let _ = child.kill().await;
            tokio::select! {
                _ = shutdown.wait() => return,
                _ = tokio::time::sleep(restart_delay) => {}
            }
            continue;
        };

        let stderr_jail = jail_name.clone();
        tokio::spawn(async move {
            let mut reader = BufReader::new(stderr).lines();
            loop {
                match reader.next_line().await {
                    Ok(Some(line)) if !line.trim().is_empty() => {
                        tracing::debug!(jail = %stderr_jail, line = %line, "tracey_ban journalctl stderr");
                    }
                    Ok(Some(_)) => {}
                    Ok(None) => break,
                    Err(err) => {
                        tracing::debug!(
                            jail = %stderr_jail,
                            error = %err,
                            "tracey_ban journalctl stderr reader failed"
                        );
                        break;
                    }
                }
            }
        });

        let mut reader = BufReader::new(stdout).lines();
        let mut should_restart = true;
        loop {
            tokio::select! {
                _ = shutdown.wait() => {
                    let _ = child.kill().await;
                    return;
                }
                line = reader.next_line() => match line {
                    Ok(Some(line)) => {
                        let trimmed = line.trim_end();
                        if let Some(ip) = match_line_with_regexes(trimmed, &fail_regex, &ignore_regex, prefilter.as_ref())
                            && tx
                                .send(Detection {
                                    jail: jail_name.clone(),
                                    ip,
                                    ts_ms: now_ms(),
                                    source: "journalctl".to_string(),
                                    reason: "journal_regex_match".to_string(),
                                    line: Some(trimmed.to_string()),
                                })
                                .await
                                .is_err()
                        {
                            should_restart = false;
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(err) => {
                        tracing::warn!(
                            jail = %jail_name,
                            error = %err,
                            "tracey_ban journal worker failed to read journalctl output"
                        );
                        break;
                    }
                }
            }
        }

        let _ = child.kill().await;
        let _ = child.wait().await;

        if !should_restart {
            return;
        }

        tokio::select! {
            _ = shutdown.wait() => return,
            _ = tokio::time::sleep(restart_delay) => {}
        }
    }
}

async fn run_log_worker(
    jail_name: String,
    jail_cfg: TraceyBanJailConfig,
    fail_regex: Vec<Regex>,
    ignore_regex: Vec<Regex>,
    prefilter: Option<Regex>,
    offsets: Arc<RwLock<HashMap<String, u64>>>,
    tx: mpsc::Sender<Detection>,
    mut shutdown: ShutdownListener,
) {
    let mut interval = tokio::time::interval(Duration::from_millis(jail_cfg.poll_interval_ms));
    loop {
        tokio::select! {
            _ = shutdown.wait() => break,
            _ = interval.tick() => {
                for path in &jail_cfg.log_paths {
                    if let Err(err) = process_log_path(
                        &jail_name,
                        path,
                        &fail_regex,
                        &ignore_regex,
                        prefilter.as_ref(),
                        &offsets,
                        &tx,
                    ).await {
                        if err.kind() == std::io::ErrorKind::PermissionDenied {
                            tracing::warn!(
                                jail = %jail_name,
                                path = %path.display(),
                                root_like_path = is_root_log_path(path),
                                error = %err,
                                "tracey_ban cannot read log path due to permissions"
                            );
                        } else {
                            tracing::debug!(jail=%jail_name, path=%path.display(), error=%err, "tracey_ban log worker read failed");
                        }
                    }
                }
            }
        }
    }
}

async fn process_log_path(
    jail_name: &str,
    path: &Path,
    fail_regex: &[Regex],
    ignore_regex: &[Regex],
    prefilter: Option<&Regex>,
    offsets: &Arc<RwLock<HashMap<String, u64>>>,
    tx: &mpsc::Sender<Detection>,
) -> std::io::Result<()> {
    if !path.exists() {
        return Ok(());
    }

    let key = format!("{}::{}", jail_name, path.display());
    let mut start_offset = offsets.read().await.get(&key).copied().unwrap_or(0);

    let mut file = tokio::fs::File::open(path).await?;
    let metadata = file.metadata().await?;
    if metadata.len() < start_offset {
        start_offset = 0;
    }

    file.seek(std::io::SeekFrom::Start(start_offset)).await?;
    let mut reader = BufReader::new(file);
    let mut line = String::new();

    loop {
        line.clear();
        let bytes = reader.read_line(&mut line).await?;
        if bytes == 0 {
            break;
        }

        let trimmed = line.trim_end();
        if let Some(ip) = match_line_with_regexes(trimmed, fail_regex, ignore_regex, prefilter)
            && tx
                .send(Detection {
                    jail: jail_name.to_string(),
                    ip,
                    ts_ms: now_ms(),
                    source: path.display().to_string(),
                    reason: "log_regex_match".to_string(),
                    line: Some(trimmed.to_string()),
                })
                .await
                .is_err()
        {
            break;
        }
    }

    let end_offset = reader.stream_position().await?;
    offsets.write().await.insert(key, end_offset);
    Ok(())
}

async fn run_event_worker(
    jail_name: String,
    jail_cfg: TraceyBanJailConfig,
    fail_regex: Vec<Regex>,
    ignore_regex: Vec<Regex>,
    prefilter: Option<Regex>,
    bus_rx: &mut tokio::sync::broadcast::Receiver<Event>,
    tx: mpsc::Sender<Detection>,
    mut shutdown: ShutdownListener,
) {
    loop {
        tokio::select! {
            _ = shutdown.wait() => break,
            recv = bus_rx.recv() => {
                let Ok(event) = recv else {
                    continue;
                };
                if event.source.starts_with("tracey_ban") {
                    continue;
                }
                if let Some(ip) = extract_ip_from_event(&event, &jail_cfg) {
                    let message = event_candidate_message(&event);
                    let explicit_match = event_requests_explicit_ban(&event);
                    let regex_match = message
                        .as_deref()
                        .and_then(|message| {
                            match_line_with_regexes(
                                message,
                                &fail_regex,
                                &ignore_regex,
                                prefilter.as_ref(),
                            )
                        });

                    let matched = if let Some(ip) = regex_match {
                        Some((
                            ip,
                            "tracey_event_regex_match".to_string(),
                            message.clone().or_else(|| Some(default_event_line(&event))),
                        ))
                    } else if explicit_match {
                        Some((
                            ip.clone(),
                            "tracey_event_explicit".to_string(),
                            Some(explicit_event_line(&event, message.as_deref())),
                        ))
                    } else if !jail_cfg.event_require_message_match {
                        Some((
                            ip.clone(),
                            "tracey_event_ip_only".to_string(),
                            message.clone().or_else(|| Some(default_event_line(&event))),
                        ))
                    } else {
                        None
                    };

                    if let Some((ip, reason, line)) = matched {
                        let _ = tx
                            .send(Detection {
                                jail: jail_name.clone(),
                                ip,
                                ts_ms: event.ts_ms,
                                source: event.source,
                                reason,
                                line,
                            })
                            .await;
                    }
                }
            }
        }
    }
}

fn extract_ip_from_event(event: &Event, jail_cfg: &TraceyBanJailConfig) -> Option<String> {
    for key in &jail_cfg.event_ip_keys {
        if let Some(value) = event.attributes.get(key)
            && let Some(ip) = normalize_ip(value)
        {
            return Some(ip);
        }
    }

    if jail_cfg.scan_all_event_attrs_for_ip {
        return event
            .attributes
            .values()
            .find_map(|value| extract_ip_from_line(value));
    }

    None
}

fn event_candidate_message(event: &Event) -> Option<String> {
    for key in ["message", "reason", "title", "summary"] {
        if let Some(value) = event.attributes.get(key)
            && !value.trim().is_empty()
        {
            return Some(value.clone());
        }
    }
    None
}

fn event_requests_explicit_ban(event: &Event) -> bool {
    ["tracey_ban_match", "tracey_ban_explicit", "ban_candidate"]
        .into_iter()
        .any(|key| {
            event
                .attributes
                .get(key)
                .is_some_and(|value| parse_boolish(value))
        })
}

fn parse_boolish(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn explicit_event_line(event: &Event, message: Option<&str>) -> String {
    if let Some(reason) = event.attributes.get("tracey_ban_reason")
        && !reason.trim().is_empty()
    {
        return reason.clone();
    }
    message
        .map(ToString::to_string)
        .unwrap_or_else(|| default_event_line(event))
}

fn default_event_line(event: &Event) -> String {
    format!("source={} signal={:.3}", event.source, event.signal)
}

fn match_line_with_regexes(
    line: &str,
    fail_regex: &[Regex],
    ignore_regex: &[Regex],
    prefilter: Option<&Regex>,
) -> Option<String> {
    if let Some(prefilter) = prefilter
        && !prefilter.is_match(line)
    {
        return None;
    }

    for regex in ignore_regex {
        if regex.is_match(line) {
            return None;
        }
    }

    for regex in fail_regex {
        if let Some(caps) = regex.captures(line)
            && let Some(ip) = extract_ip_from_captures(&caps, line)
        {
            return Some(ip);
        }
    }

    None
}

fn extract_ip_from_captures(caps: &Captures<'_>, line: &str) -> Option<String> {
    for name in ["host", "ip", "addr", "ip4", "ip6", "client", "remote"] {
        if let Some(value) = caps.name(name)
            && let Some(ip) = normalize_ip(value.as_str())
        {
            return Some(ip);
        }
    }

    extract_ip_from_line(line)
}

fn extract_ip_from_line(line: &str) -> Option<String> {
    if let Some(caps) = ip_extract_re().captures(line)
        && let Some(value) = caps.name("ip")
    {
        return normalize_ip(value.as_str());
    }
    None
}

fn ip_extract_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4})")
            .expect("ip regex")
    })
}

async fn process_detection(
    detection: Detection,
    jails: &mut HashMap<String, JailRuntime>,
    config: &TraceyBanConfig,
    bus: &EventBus,
    storage: &Storage,
    intel_hub: &BanIntelHub,
) {
    let Some(jail) = jails.get_mut(&detection.jail) else {
        return;
    };

    if jail.is_ignored_ip(&detection.ip) {
        return;
    }

    if jail.active_bans.contains_key(&detection.ip) {
        return;
    }

    let find_time_start = detection
        .ts_ms
        .saturating_sub(jail.config.find_time_ms.max(1));
    let attempts = {
        let queue = jail
            .failure_windows
            .entry(detection.ip.clone())
            .or_insert_with(VecDeque::new);
        queue.push_back(detection.ts_ms);
        while queue.front().is_some_and(|ts| *ts < find_time_start) {
            queue.pop_front();
        }
        queue.len() as u32
    };
    let remote_support = intel_hub.remote_support_count(&detection.ip).await as u32;
    let effective_retry = jail
        .config
        .max_retry
        .saturating_sub(remote_support.min(jail.config.max_retry.saturating_sub(1)))
        .max(1);
    let fuzzy_decision = evaluate_fuzzy_decision(
        jail,
        detection.line.as_deref(),
        &detection,
        attempts,
        effective_retry,
        remote_support,
        config,
    );
    let adjusted_retry = fuzzy_decision
        .as_ref()
        .map(|decision| decision.adjusted_retry)
        .unwrap_or(effective_retry);

    if attempts < adjusted_retry {
        return;
    }

    let counter_key = make_ban_key(&jail.config.name, &detection.ip);
    let next_ban_count = jail.ban_counts.get(&counter_key).copied().unwrap_or(0) + 1;
    let duration_ms = compute_ban_duration_ms(&jail.config, next_ban_count);
    let reason = format!(
        "{} attempts={} threshold={} adjusted_retry={} remote_support={} fuzzy_risk={:.2} fuzzy_confidence={:.2} fuzzy_signal={:.2}",
        detection.reason,
        attempts,
        effective_retry,
        adjusted_retry,
        remote_support,
        fuzzy_decision
            .as_ref()
            .map(|decision| decision.risk)
            .unwrap_or(0.0),
        fuzzy_decision
            .as_ref()
            .map(|decision| decision.confidence)
            .unwrap_or(0.0),
        fuzzy_decision
            .as_ref()
            .map(|decision| decision.signal)
            .unwrap_or(0.0),
    );

    let installed = install_ban_record(
        jail,
        config,
        bus,
        storage,
        intel_hub,
        &detection.ip,
        detection.ts_ms,
        &detection.source,
        &reason,
        duration_ms,
        detection.line.as_deref(),
        fuzzy_decision.as_ref(),
        next_ban_count,
    )
    .await;

    if installed && let Some(queue) = jail.failure_windows.get_mut(&detection.ip) {
        queue.clear();
    }
}

fn evaluate_fuzzy_decision(
    jail: &mut JailRuntime,
    line: Option<&str>,
    detection: &Detection,
    attempts: u32,
    effective_retry: u32,
    remote_support: u32,
    config: &TraceyBanConfig,
) -> Option<FuzzyBanDecision> {
    if !config.fuzzy.enabled {
        return None;
    }

    let recidive_count = jail
        .ban_counts
        .get(&make_ban_key(&jail.config.name, &detection.ip))
        .copied()
        .unwrap_or(0);
    let signal = build_fuzzy_signal(
        attempts,
        effective_retry,
        remote_support,
        recidive_count,
        jail.config.max_retry,
    );
    let severity = infer_detection_severity(line, attempts, effective_retry, remote_support);

    let mut event = Event::new(
        TRACEY_BAN_FUZZY_EVENT_COUNTER.fetch_add(1, Ordering::Relaxed),
        format!("tracey_ban::{}", jail.config.name),
        EventKind::NetworkFlow,
        signal,
        severity,
    )
    .with_attr("anomaly", "true")
    .with_attr("ip", detection.ip.clone())
    .with_attr("source", detection.source.clone())
    .with_attr("reason", detection.reason.clone())
    .with_attr("attempts", attempts.to_string())
    .with_attr("effective_retry", effective_retry.to_string())
    .with_attr("remote_support", remote_support.to_string())
    .with_attr("recidive_count", recidive_count.to_string());

    if let Some(text) = line {
        let text = normalize_line_preview(text, 768);
        event = event.with_attr("message", text.clone());
        if let Some(finding_severity) = infer_finding_severity(&text) {
            event = event.with_attr("finding_severity", finding_severity);
        }
        if let Some(cve) = extract_cve(&text) {
            event = event.with_attr("cve", cve);
        }
        if let Some(cvss) = extract_cvss(&text) {
            event = event.with_attr("cvss", format!("{:.1}", cvss));
        }
    }

    let score = jail.scorer.score_and_update(&event);
    let adjusted_retry = adjusted_retry_with_fuzzy(
        effective_retry,
        score.risk,
        score.confidence,
        config.fuzzy_min_risk,
        config.fuzzy_min_confidence,
        config.fuzzy_retry_reduction,
    );

    Some(FuzzyBanDecision {
        risk: score.risk,
        confidence: score.confidence,
        telemetry: BanFuzzyTelemetry {
            order: score.telemetry.order,
            z_abs: score.telemetry.z_abs,
            core_risk: score.telemetry.core_risk,
            interval_width: score.telemetry.interval_width,
            edge_membership: score.telemetry.edge_membership,
            security_context: score.telemetry.security_context,
            aarnn_context: score.telemetry.aarnn_context,
            learned_confidence: score.telemetry.learned_confidence,
        },
        adjusted_retry,
        signal,
    })
}

fn adjusted_retry_with_fuzzy(
    base_retry: u32,
    risk: f64,
    confidence: f64,
    min_risk: f64,
    min_confidence: f64,
    retry_reduction: f64,
) -> u32 {
    if base_retry <= 1 {
        return 1;
    }
    if risk < min_risk || confidence < min_confidence || retry_reduction <= 0.0 {
        return base_retry.max(1);
    }

    let reduction = (risk * confidence * retry_reduction).clamp(0.0, 0.95);
    let reduced = ((base_retry as f64) * (1.0 - reduction)).ceil() as u32;
    reduced.clamp(1, base_retry)
}

fn build_fuzzy_signal(
    attempts: u32,
    effective_retry: u32,
    remote_support: u32,
    recidive_count: u32,
    max_retry: u32,
) -> f64 {
    let retry = effective_retry.max(1) as f64;
    let max_retry = max_retry.max(1) as f64;
    let attempt_pressure = (attempts as f64 / retry).clamp(0.0, 2.0);
    let remote_pressure = (remote_support as f64 / retry).clamp(0.0, 1.0);
    let recidive_pressure = (recidive_count as f64 / max_retry).clamp(0.0, 1.0);
    (0.58 * (attempt_pressure / 2.0) + 0.22 * remote_pressure + 0.20 * recidive_pressure)
        .clamp(0.0, 1.0)
}

fn infer_detection_severity(
    line: Option<&str>,
    attempts: u32,
    effective_retry: u32,
    remote_support: u32,
) -> Severity {
    let attempt_ratio = attempts as f64 / effective_retry.max(1) as f64;
    if attempt_ratio >= 1.8 || remote_support >= 4 {
        return Severity::Critical;
    }
    if attempt_ratio >= 1.2 || remote_support >= 2 {
        return Severity::High;
    }

    if let Some(line) = line {
        let lower = line.to_ascii_lowercase();
        if lower.contains("sqlmap")
            || lower.contains("rce")
            || lower.contains("exploit")
            || lower.contains("credential stuffing")
            || lower.contains("bruteforce")
            || lower.contains("brute force")
        {
            return Severity::High;
        }
        if lower.contains("failed")
            || lower.contains("invalid")
            || lower.contains("denied")
            || lower.contains("unauthorized")
            || lower.contains("forbidden")
        {
            return Severity::Medium;
        }
    }

    Severity::Low
}

fn infer_finding_severity(line: &str) -> Option<&'static str> {
    let lower = line.to_ascii_lowercase();
    if lower.contains("critical") {
        Some("critical")
    } else if lower.contains("high") {
        Some("high")
    } else if lower.contains("medium") {
        Some("medium")
    } else if lower.contains("low") {
        Some("low")
    } else {
        None
    }
}

fn normalize_line_preview(line: &str, max_chars: usize) -> String {
    let mut normalized = line.replace('\n', " ").replace('\r', " ");
    if normalized.len() > max_chars {
        normalized.truncate(max_chars);
    }
    normalized
}

fn extract_cve(line: &str) -> Option<String> {
    cve_re()
        .captures(line)
        .and_then(|caps| caps.get(0))
        .map(|m| m.as_str().to_ascii_uppercase())
}

fn cve_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)CVE-\d{4}-\d{4,7}").expect("cve regex"))
}

fn extract_cvss(line: &str) -> Option<f64> {
    let captures = cvss_re().captures(line)?;
    let raw = captures.get(1)?.as_str();
    raw.parse::<f64>().ok().map(|v| v.clamp(0.0, 10.0))
}

fn cvss_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)cvss[^0-9]{0,8}([0-9](?:\.[0-9])?)").expect("cvss regex"))
}

async fn process_unbans(
    jails: &mut HashMap<String, JailRuntime>,
    bus: &EventBus,
    storage: &Storage,
    intel_hub: &BanIntelHub,
    config: &TraceyBanConfig,
    agent_id: &str,
) {
    let now = now_ms();

    for jail in jails.values_mut() {
        let mut to_unban = Vec::new();
        for (ip, ban) in &jail.active_bans {
            if ban.expires_ms.is_some_and(|expires| expires <= now) {
                to_unban.push(ip.clone());
            }
        }

        for ip in to_unban {
            let _ = uninstall_ban_record(
                jail,
                config,
                bus,
                storage,
                intel_hub,
                &ip,
                "tracey_ban_timer",
                "ban_expired",
                agent_id,
            )
            .await;
        }
    }
}

async fn install_ban_record(
    jail: &mut JailRuntime,
    config: &TraceyBanConfig,
    bus: &EventBus,
    storage: &Storage,
    intel_hub: &BanIntelHub,
    ip: &str,
    ts_ms: u64,
    source: &str,
    reason: &str,
    duration_ms: Option<u64>,
    line: Option<&str>,
    fuzzy_decision: Option<&FuzzyBanDecision>,
    next_ban_count: u32,
) -> bool {
    if !run_jail_action(
        config,
        jail,
        JailActionKind::Ban,
        Some(ip),
        duration_ms,
        line,
    )
    .await
    {
        tracing::warn!(
            jail = %jail.config.name,
            ip = %ip,
            action = JailActionKind::Ban.as_str(),
            "tracey_ban did not record ban because enforcement failed"
        );
        return false;
    }

    let counter_key = make_ban_key(&jail.config.name, ip);
    jail.ban_counts.insert(counter_key, next_ban_count);

    let ban = ActiveBan {
        jail: jail.config.name.clone(),
        ip: ip.to_string(),
        banned_at_ms: ts_ms,
        expires_ms: duration_ms.map(|duration| ts_ms.saturating_add(duration)),
        ban_count: next_ban_count,
        source: source.to_string(),
        reason: reason.to_string(),
        fuzzy_risk: fuzzy_decision.map(|decision| decision.risk),
        fuzzy_confidence: fuzzy_decision.map(|decision| decision.confidence),
        fuzzy_signal: fuzzy_decision.map(|decision| decision.signal),
        fuzzy_adjusted_retry: fuzzy_decision.map(|decision| decision.adjusted_retry),
        fuzzy_telemetry: fuzzy_decision.map(|decision| decision.telemetry.clone()),
    };

    jail.active_bans.insert(ip.to_string(), ban.clone());
    intel_hub
        .update_local_ban(BanAdvertisementEntry {
            ip: ban.ip.clone(),
            jail: ban.jail.clone(),
            expires_ms: ban.expires_ms,
            ban_count: ban.ban_count,
            last_ban_ms: ban.banned_at_ms,
        })
        .await;
    emit_ban_event(bus, storage, &ban, true, config.agent_id.as_str()).await;
    true
}

async fn uninstall_ban_record(
    jail: &mut JailRuntime,
    config: &TraceyBanConfig,
    bus: &EventBus,
    storage: &Storage,
    intel_hub: &BanIntelHub,
    ip: &str,
    source: &str,
    reason: &str,
    agent_id: &str,
) -> bool {
    let existing_ban = jail.active_bans.get(ip).cloned();
    if !run_jail_action(config, jail, JailActionKind::Unban, Some(ip), None, None).await {
        tracing::warn!(
            jail = %jail.config.name,
            ip = %ip,
            action = JailActionKind::Unban.as_str(),
            "tracey_ban retained ban state because unban enforcement failed"
        );
        return false;
    }

    if let Some(mut ban) = existing_ban {
        jail.active_bans.remove(ip);
        ban.source = source.to_string();
        ban.reason = reason.to_string();
        intel_hub.remove_local_ban(&ban.jail, &ban.ip).await;
        emit_ban_event(bus, storage, &ban, false, agent_id).await;
    } else {
        intel_hub.remove_local_ban(&jail.config.name, ip).await;
    }

    true
}

async fn emit_ban_event(
    bus: &EventBus,
    storage: &Storage,
    ban: &ActiveBan,
    banned: bool,
    agent_id: &str,
) {
    let mut event = Event::new(
        now_ms(),
        if banned {
            "tracey_ban_ban"
        } else {
            "tracey_ban_unban"
        },
        EventKind::NetworkFlow,
        if banned { 0.96 } else { 0.35 },
        if banned {
            Severity::High
        } else {
            Severity::Medium
        },
    )
    .with_attr("agent_id", agent_id)
    .with_attr("jail", ban.jail.clone())
    .with_attr("ip", ban.ip.clone())
    .with_attr("banned", banned.to_string())
    .with_attr("source", ban.source.clone())
    .with_attr("reason", ban.reason.clone())
    .with_attr("ban_count", ban.ban_count.to_string());

    if let Some(expires_ms) = ban.expires_ms {
        event = event.with_attr("expires_ms", expires_ms.to_string());
    } else {
        event = event.with_attr("expires_ms", "never");
    }
    if let Some(value) = ban.fuzzy_risk {
        event = event.with_attr("fuzzy_risk", format!("{:.4}", value));
    }
    if let Some(value) = ban.fuzzy_confidence {
        event = event.with_attr("fuzzy_confidence", format!("{:.4}", value));
    }
    if let Some(value) = ban.fuzzy_signal {
        event = event.with_attr("fuzzy_signal", format!("{:.4}", value));
    }
    if let Some(value) = ban.fuzzy_adjusted_retry {
        event = event.with_attr("fuzzy_adjusted_retry", value.to_string());
    }
    if let Some(telemetry) = &ban.fuzzy_telemetry {
        event = event
            .with_attr("fuzzy_order", telemetry.order.to_string())
            .with_attr("fuzzy_core_risk", format!("{:.4}", telemetry.core_risk))
            .with_attr(
                "fuzzy_interval_width",
                format!("{:.4}", telemetry.interval_width),
            )
            .with_attr(
                "fuzzy_edge_membership",
                format!("{:.4}", telemetry.edge_membership),
            )
            .with_attr(
                "fuzzy_security_context",
                format!("{:.4}", telemetry.security_context),
            )
            .with_attr(
                "fuzzy_aarnn_context",
                format!("{:.4}", telemetry.aarnn_context),
            )
            .with_attr(
                "fuzzy_learned_confidence",
                format!("{:.4}", telemetry.learned_confidence),
            );
    }

    bus.publish(event.clone());
    storage.record_event(event).await;
    storage
        .record_ban_update(BanUpdateRecord {
            ts_ms: now_ms(),
            jail: ban.jail.clone(),
            ip: ban.ip.clone(),
            banned,
            ban_count: ban.ban_count,
            expires_ms: ban.expires_ms,
            reason: ban.reason.clone(),
            source: ban.source.clone(),
            fuzzy_risk: ban.fuzzy_risk,
            fuzzy_confidence: ban.fuzzy_confidence,
            fuzzy_signal: ban.fuzzy_signal,
            fuzzy_adjusted_retry: ban.fuzzy_adjusted_retry,
        })
        .await;
}

fn compute_ban_duration_ms(config: &TraceyBanJailConfig, ban_count: u32) -> Option<u64> {
    if config.ban_time_ms <= 0 {
        return None;
    }

    let mut duration = config.ban_time_ms as f64;
    if config.ban_increment {
        let exponent = ban_count.saturating_sub(1) as f64;
        duration *= config.ban_multiplier.powf(exponent.max(0.0));
    }

    if config.ban_max_time_ms > 0 {
        duration = duration.min(config.ban_max_time_ms as f64);
    }

    if config.ban_randomize_ms > 0 {
        let hash = blake3::hash(
            format!(
                "{}:{}:{}",
                config.name,
                ban_count,
                crate::event::now_ms() / 1000
            )
            .as_bytes(),
        );
        let value = u64::from_le_bytes([
            hash.as_bytes()[0],
            hash.as_bytes()[1],
            hash.as_bytes()[2],
            hash.as_bytes()[3],
            hash.as_bytes()[4],
            hash.as_bytes()[5],
            hash.as_bytes()[6],
            hash.as_bytes()[7],
        ]);
        duration += (value % config.ban_randomize_ms.max(1)) as f64;
    }

    Some(duration.max(1.0) as u64)
}

async fn run_jail_action(
    config: &TraceyBanConfig,
    jail: &mut JailRuntime,
    action: JailActionKind,
    ip: Option<&str>,
    ban_time_ms: Option<u64>,
    line: Option<&str>,
) -> bool {
    if let Some(template) = action_template_for_kind(&jail.config, action) {
        return run_template_action(
            config,
            &jail.config,
            action,
            template,
            ip,
            ban_time_ms,
            line,
        )
        .await;
    }

    if jail.config.action_catalog.is_none() {
        return matches!(action, JailActionKind::Start | JailActionKind::Stop);
    }

    run_builtin_action(config, jail, action, ip).await
}

fn action_template_for_kind<'a>(
    jail: &'a TraceyBanJailConfig,
    action: JailActionKind,
) -> Option<&'a str> {
    match action {
        JailActionKind::Start => jail.action_start.as_deref(),
        JailActionKind::Stop => jail.action_stop.as_deref(),
        JailActionKind::Ban => jail.action_ban.as_deref(),
        JailActionKind::Unban => jail.action_unban.as_deref(),
    }
}

async fn run_template_action(
    config: &TraceyBanConfig,
    jail: &TraceyBanJailConfig,
    action: JailActionKind,
    template: &str,
    ip: Option<&str>,
    ban_time_ms: Option<u64>,
    line: Option<&str>,
) -> bool {
    if template.trim().is_empty() {
        return true;
    }

    let use_sudo = config.use_sudo_for_actions && !is_running_as_root();
    let rendered = render_action_template(template, jail, ip, ban_time_ms, line);
    let parsed = split_command_line(template);

    let result = match parsed {
        Ok(tokens) => {
            let args: Vec<String> = tokens
                .into_iter()
                .map(|token| render_action_template(&token, jail, ip, ban_time_ms, line))
                .collect();
            if args.is_empty() {
                return false;
            }
            if contains_shell_control_tokens(&args) {
                if config.allow_shell_actions {
                    run_shell_action(config, jail, &rendered, use_sudo).await
                } else {
                    tracing::warn!(
                        jail = %jail.name,
                        action = %template,
                        action_kind = action.as_str(),
                        "tracey_ban skipped action containing shell control operators; enable tracey_ban.allow_shell_actions to allow shell fallback"
                    );
                    return false;
                }
            } else {
                run_argv_action(config, jail, &args, use_sudo).await
            }
        }
        Err(err) => {
            if config.allow_shell_actions {
                tracing::warn!(
                    jail = %jail.name,
                    action = %template,
                    action_kind = action.as_str(),
                    error = %err,
                    "tracey_ban falling back to shell action because argv tokenization failed"
                );
                run_shell_action(config, jail, &rendered, use_sudo).await
            } else {
                tracing::warn!(
                    jail = %jail.name,
                    action = %template,
                    action_kind = action.as_str(),
                    error = %err,
                    "tracey_ban skipped action because argv tokenization failed and shell actions are disabled"
                );
                return false;
            }
        }
    };

    if !result.success {
        log_action_failure(config, jail, action, template, use_sudo, &result);
    }
    result.success
}

async fn run_builtin_action(
    config: &TraceyBanConfig,
    jail: &mut JailRuntime,
    action: JailActionKind,
    ip: Option<&str>,
) -> bool {
    if matches!(action, JailActionKind::Start | JailActionKind::Stop)
        && jail.config.action_catalog.is_none()
    {
        return true;
    }

    if jail.resolved_firewall_backend == TraceyBanFirewallBackend::Unknown {
        let probe = probe_firewall_backend().await;
        refresh_single_jail_backend(config, jail, &probe).await;
    }

    match jail.resolved_firewall_backend {
        TraceyBanFirewallBackend::Ufw => {
            run_builtin_ufw_action(config, &jail.config, action, ip).await
        }
        TraceyBanFirewallBackend::Firewalld => {
            run_builtin_firewalld_action(config, jail, action, ip).await
        }
        TraceyBanFirewallBackend::Nftables => {
            run_builtin_nftables_action(config, jail, action, ip).await
        }
        TraceyBanFirewallBackend::Unknown => {
            tracing::warn!(
                jail = %jail.config.name,
                action_kind = action.as_str(),
                action_catalog = ?jail.config.action_catalog,
                firewall_backend = %jail.config.firewall_backend,
                "tracey_ban could not resolve a usable built-in firewall backend"
            );
            matches!(action, JailActionKind::Start | JailActionKind::Stop)
        }
    }
}

async fn run_builtin_ufw_action(
    config: &TraceyBanConfig,
    jail: &TraceyBanJailConfig,
    action: JailActionKind,
    ip: Option<&str>,
) -> bool {
    match action {
        JailActionKind::Start | JailActionKind::Stop => true,
        JailActionKind::Ban | JailActionKind::Unban => {
            let Some(ip) = ip else {
                return false;
            };
            for args in build_ufw_action_args(jail, action, ip) {
                let result = run_argv_action(
                    config,
                    jail,
                    &args,
                    config.use_sudo_for_actions && !is_running_as_root(),
                )
                .await;
                if !ufw_action_succeeded(action, &result) {
                    log_action_failure(
                        config,
                        jail,
                        action,
                        &args.join(" "),
                        config.use_sudo_for_actions && !is_running_as_root(),
                        &result,
                    );
                    return false;
                }
            }
            true
        }
    }
}

async fn run_builtin_firewalld_action(
    config: &TraceyBanConfig,
    jail: &mut JailRuntime,
    action: JailActionKind,
    ip: Option<&str>,
) -> bool {
    match action {
        JailActionKind::Start | JailActionKind::Stop => true,
        JailActionKind::Ban | JailActionKind::Unban => {
            let Some(ip) = ip else {
                return false;
            };
            let zone = jail
                .resolved_firewalld_zone
                .clone()
                .unwrap_or_else(|| "public".to_string());
            for args in build_firewalld_action_args(&jail.config, action, ip, &zone) {
                let result = run_argv_action(
                    config,
                    &jail.config,
                    &args,
                    config.use_sudo_for_actions && !is_running_as_root(),
                )
                .await;
                if !firewalld_action_succeeded(action, &result) {
                    log_action_failure(
                        config,
                        &jail.config,
                        action,
                        &args.join(" "),
                        config.use_sudo_for_actions && !is_running_as_root(),
                        &result,
                    );
                    return false;
                }
            }
            true
        }
    }
}

async fn run_builtin_nftables_action(
    config: &TraceyBanConfig,
    jail: &mut JailRuntime,
    action: JailActionKind,
    ip: Option<&str>,
) -> bool {
    if !ensure_nftables_infra(config, jail).await {
        return matches!(action, JailActionKind::Stop);
    }

    match action {
        JailActionKind::Start | JailActionKind::Stop => true,
        JailActionKind::Ban => {
            let Some(ip) = ip else {
                return false;
            };
            let args = build_nft_element_action_args(&jail.config, true, ip);
            let result = run_argv_action(
                config,
                &jail.config,
                &args,
                config.use_sudo_for_actions && !is_running_as_root(),
            )
            .await;
            if nft_action_succeeded(true, &result) {
                true
            } else {
                log_action_failure(
                    config,
                    &jail.config,
                    action,
                    &args.join(" "),
                    config.use_sudo_for_actions && !is_running_as_root(),
                    &result,
                );
                false
            }
        }
        JailActionKind::Unban => {
            let Some(ip) = ip else {
                return false;
            };
            let args = build_nft_element_action_args(&jail.config, false, ip);
            let result = run_argv_action(
                config,
                &jail.config,
                &args,
                config.use_sudo_for_actions && !is_running_as_root(),
            )
            .await;
            if nft_action_succeeded(false, &result) {
                true
            } else {
                log_action_failure(
                    config,
                    &jail.config,
                    action,
                    &args.join(" "),
                    config.use_sudo_for_actions && !is_running_as_root(),
                    &result,
                );
                false
            }
        }
    }
}

async fn ensure_nftables_infra(config: &TraceyBanConfig, jail: &mut JailRuntime) -> bool {
    let table = jail.config.nftables_table.clone();
    let chain = jail.config.nftables_chain.clone();
    let use_sudo = config.use_sudo_for_actions && !is_running_as_root();

    let table_args = vec![
        "nft".to_string(),
        "list".to_string(),
        "table".to_string(),
        "inet".to_string(),
        table.clone(),
    ];
    let table_result = run_argv_action(config, &jail.config, &table_args, use_sudo).await;
    if !table_result.success {
        let add_args = vec![
            "nft".to_string(),
            "add".to_string(),
            "table".to_string(),
            "inet".to_string(),
            table.clone(),
        ];
        let add_result = run_argv_action(config, &jail.config, &add_args, use_sudo).await;
        if !nft_definition_succeeded(&add_result) {
            log_action_failure(
                config,
                &jail.config,
                JailActionKind::Start,
                &add_args.join(" "),
                use_sudo,
                &add_result,
            );
            return false;
        }
    }

    let chain_args = vec![
        "nft".to_string(),
        "list".to_string(),
        "chain".to_string(),
        "inet".to_string(),
        table.clone(),
        chain.clone(),
    ];
    let chain_result = run_argv_action(config, &jail.config, &chain_args, use_sudo).await;
    if !chain_result.success {
        let add_args = vec![
            "nft".to_string(),
            "add".to_string(),
            "chain".to_string(),
            "inet".to_string(),
            table.clone(),
            chain.clone(),
            "{ type filter hook input priority -10; policy accept; }".to_string(),
        ];
        let add_result = run_argv_action(config, &jail.config, &add_args, use_sudo).await;
        if !nft_definition_succeeded(&add_result) {
            log_action_failure(
                config,
                &jail.config,
                JailActionKind::Start,
                &add_args.join(" "),
                use_sudo,
                &add_result,
            );
            return false;
        }
    }

    for (family, set_name) in nftables_set_names(&jail.config) {
        let list_args = vec![
            "nft".to_string(),
            "list".to_string(),
            "set".to_string(),
            "inet".to_string(),
            table.clone(),
            set_name.clone(),
        ];
        let list_result = run_argv_action(config, &jail.config, &list_args, use_sudo).await;
        if !list_result.success {
            let add_args = vec![
                "nft".to_string(),
                "add".to_string(),
                "set".to_string(),
                "inet".to_string(),
                table.clone(),
                set_name.clone(),
                format!("{{ type {}; }}", family),
            ];
            let add_result = run_argv_action(config, &jail.config, &add_args, use_sudo).await;
            if !nft_definition_succeeded(&add_result) {
                log_action_failure(
                    config,
                    &jail.config,
                    JailActionKind::Start,
                    &add_args.join(" "),
                    use_sudo,
                    &add_result,
                );
                return false;
            }
        }
    }

    let chain_state_args = vec![
        "nft".to_string(),
        "list".to_string(),
        "chain".to_string(),
        "inet".to_string(),
        table.clone(),
        chain.clone(),
    ];
    let chain_state = run_argv_action(config, &jail.config, &chain_state_args, use_sudo).await;
    if !chain_state.success {
        log_action_failure(
            config,
            &jail.config,
            JailActionKind::Start,
            &chain_state_args.join(" "),
            use_sudo,
            &chain_state,
        );
        return false;
    }

    for (is_ipv6, set_name) in [
        (false, nftables_set_name(&jail.config, "v4")),
        (true, nftables_set_name(&jail.config, "v6")),
    ] {
        let signature = nft_rule_signature(&jail.config, &set_name, is_ipv6);
        if chain_state.stdout.contains(&signature) {
            continue;
        }
        let add_args = build_nft_rule_args(&jail.config, &set_name, is_ipv6);
        let add_result = run_argv_action(config, &jail.config, &add_args, use_sudo).await;
        if !nft_definition_succeeded(&add_result) {
            log_action_failure(
                config,
                &jail.config,
                JailActionKind::Start,
                &add_args.join(" "),
                use_sudo,
                &add_result,
            );
            return false;
        }
    }

    true
}

fn render_action_template(
    template: &str,
    jail: &TraceyBanJailConfig,
    ip: Option<&str>,
    ban_time_ms: Option<u64>,
    line: Option<&str>,
) -> String {
    let mut command = template.to_string();
    command = command.replace("<jail>", &jail.name);
    command = command.replace("<ip>", ip.unwrap_or(""));
    command = command.replace(
        "<bantime>",
        &ban_time_ms
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-1".to_string()),
    );
    command.replace("<matches>", line.unwrap_or(""))
}

async fn run_argv_action(
    config: &TraceyBanConfig,
    jail: &TraceyBanJailConfig,
    args: &[String],
    use_sudo: bool,
) -> CommandRunResult {
    if args.is_empty() {
        return CommandRunResult {
            success: false,
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
            timed_out: false,
            error: Some("empty argv action".to_string()),
        };
    }

    let mut process = if use_sudo {
        let mut cmd = Command::new(&config.sudo_program);
        if config.sudo_non_interactive {
            cmd.arg("-n");
        }
        cmd.arg(&args[0]);
        if args.len() > 1 {
            cmd.args(&args[1..]);
        }
        cmd
    } else {
        let mut cmd = Command::new(&args[0]);
        if args.len() > 1 {
            cmd.args(&args[1..]);
        }
        cmd
    };
    process
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    match tokio::time::timeout(
        Duration::from_millis(jail.action_timeout_ms),
        process.output(),
    )
    .await
    {
        Ok(Ok(output)) => CommandRunResult {
            success: output.status.success(),
            exit_code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            timed_out: false,
            error: None,
        },
        Ok(Err(err)) => CommandRunResult {
            success: false,
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
            timed_out: false,
            error: Some(err.to_string()),
        },
        Err(_) => CommandRunResult {
            success: false,
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
            timed_out: true,
            error: None,
        },
    }
}

async fn run_shell_action(
    config: &TraceyBanConfig,
    jail: &TraceyBanJailConfig,
    command: &str,
    use_sudo: bool,
) -> CommandRunResult {
    let shell = if jail.shell.is_empty() {
        "/bin/sh"
    } else {
        jail.shell.as_str()
    };
    let mut process = if use_sudo {
        let mut cmd = Command::new(&config.sudo_program);
        if config.sudo_non_interactive {
            cmd.arg("-n");
        }
        cmd.arg(shell).arg("-lc").arg(command);
        cmd
    } else {
        let mut cmd = Command::new(shell);
        cmd.arg("-lc").arg(command);
        cmd
    };
    process
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    match tokio::time::timeout(
        Duration::from_millis(jail.action_timeout_ms),
        process.output(),
    )
    .await
    {
        Ok(Ok(output)) => CommandRunResult {
            success: output.status.success(),
            exit_code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            timed_out: false,
            error: None,
        },
        Ok(Err(err)) => CommandRunResult {
            success: false,
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
            timed_out: false,
            error: Some(err.to_string()),
        },
        Err(_) => CommandRunResult {
            success: false,
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
            timed_out: true,
            error: None,
        },
    }
}

fn build_ufw_action_args(
    jail: &TraceyBanJailConfig,
    action: JailActionKind,
    ip: &str,
) -> Vec<Vec<String>> {
    action_ports(jail)
        .into_iter()
        .map(|port| {
            let mut args = vec!["ufw".to_string(), "--force".to_string()];
            match action {
                JailActionKind::Ban => {
                    args.extend(["insert".to_string(), "1".to_string(), "deny".to_string()]);
                }
                JailActionKind::Unban => {
                    args.extend(["delete".to_string(), "deny".to_string()]);
                }
                JailActionKind::Start | JailActionKind::Stop => {}
            }
            args.extend(["from".to_string(), ip.to_string()]);
            if let Some(port) = port {
                args.extend([
                    "to".to_string(),
                    "any".to_string(),
                    "port".to_string(),
                    port.to_string(),
                    "proto".to_string(),
                    jail.protocol.clone(),
                ]);
            }
            args
        })
        .collect()
}

fn build_firewalld_action_args(
    jail: &TraceyBanJailConfig,
    action: JailActionKind,
    ip: &str,
    zone: &str,
) -> Vec<Vec<String>> {
    action_ports(jail)
        .into_iter()
        .map(|port| {
            let rich_rule = render_firewalld_rich_rule(ip, port, &jail.protocol);
            let mut args = vec![
                "firewall-cmd".to_string(),
                "--quiet".to_string(),
                "--zone".to_string(),
                zone.to_string(),
            ];
            match action {
                JailActionKind::Ban => {
                    args.push(format!("--add-rich-rule={}", rich_rule));
                }
                JailActionKind::Unban => {
                    args.push(format!("--remove-rich-rule={}", rich_rule));
                }
                JailActionKind::Start | JailActionKind::Stop => {}
            }
            args
        })
        .collect()
}

fn render_firewalld_rich_rule(ip: &str, port: Option<u16>, protocol: &str) -> String {
    let family = if ip.parse::<IpAddr>().ok().is_some_and(|addr| addr.is_ipv6()) {
        "ipv6"
    } else {
        "ipv4"
    };
    let mut rule = format!("rule family=\"{}\" source address=\"{}\"", family, ip);
    if let Some(port) = port {
        rule.push_str(&format!(
            " port port=\"{}\" protocol=\"{}\"",
            port, protocol
        ));
    }
    rule.push_str(" drop");
    rule
}

fn action_ports(jail: &TraceyBanJailConfig) -> Vec<Option<u16>> {
    if jail.ports.is_empty() {
        vec![None]
    } else {
        jail.ports.iter().copied().map(Some).collect()
    }
}

fn ufw_action_succeeded(action: JailActionKind, result: &CommandRunResult) -> bool {
    if result.success {
        return true;
    }
    let output = combined_action_output(result);
    match action {
        JailActionKind::Ban => output.contains("skipping adding existing rule"),
        JailActionKind::Unban => output.contains("could not delete non-existent rule"),
        JailActionKind::Start | JailActionKind::Stop => true,
    }
}

fn firewalld_action_succeeded(action: JailActionKind, result: &CommandRunResult) -> bool {
    if result.success {
        return true;
    }
    let output = combined_action_output(result);
    match action {
        JailActionKind::Ban => {
            output.contains("already_enabled") || output.contains("already enabled")
        }
        JailActionKind::Unban => output.contains("not_enabled") || output.contains("not enabled"),
        JailActionKind::Start | JailActionKind::Stop => true,
    }
}

fn nft_definition_succeeded(result: &CommandRunResult) -> bool {
    result.success || combined_action_output(result).contains("file exists")
}

fn nft_action_succeeded(adding: bool, result: &CommandRunResult) -> bool {
    if result.success {
        return true;
    }
    let output = combined_action_output(result);
    if adding {
        output.contains("file exists")
    } else {
        output.contains("no such element") || output.contains("no such file or directory")
    }
}

fn combined_action_output(result: &CommandRunResult) -> String {
    format!("{} {}", result.stdout, result.stderr).to_ascii_lowercase()
}

fn nftables_set_names(jail: &TraceyBanJailConfig) -> Vec<(String, String)> {
    vec![
        ("ipv4_addr".to_string(), nftables_set_name(jail, "v4")),
        ("ipv6_addr".to_string(), nftables_set_name(jail, "v6")),
    ]
}

fn nftables_set_name(jail: &TraceyBanJailConfig, suffix: &str) -> String {
    format!(
        "tb_{}_{}",
        sanitize_nft_identifier(&jail.name),
        sanitize_nft_identifier(suffix)
    )
}

fn sanitize_nft_identifier(input: &str) -> String {
    let mut output = String::with_capacity(input.len().max(8));
    let mut last_was_underscore = false;
    for ch in input.chars() {
        let next = if ch.is_ascii_alphanumeric() {
            ch.to_ascii_lowercase()
        } else {
            '_'
        };
        if next == '_' {
            if last_was_underscore {
                continue;
            }
            last_was_underscore = true;
        } else {
            last_was_underscore = false;
        }
        output.push(next);
    }
    let trimmed = output.trim_matches('_');
    let mut sanitized = if trimmed.is_empty() {
        "tracey".to_string()
    } else {
        trimmed.to_string()
    };
    if sanitized
        .chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_digit())
    {
        sanitized.insert_str(0, "tb_");
    }
    sanitized.truncate(40);
    sanitized
}

fn nft_rule_signature(jail: &TraceyBanJailConfig, set_name: &str, ipv6: bool) -> String {
    let family = if ipv6 { "ip6" } else { "ip" };
    if let Some(ports) = nft_ports_expression(jail) {
        format!(
            "{} saddr @{} {} dport {} drop",
            family, set_name, jail.protocol, ports
        )
    } else {
        format!("{} saddr @{} drop", family, set_name)
    }
}

fn build_nft_rule_args(jail: &TraceyBanJailConfig, set_name: &str, ipv6: bool) -> Vec<String> {
    let mut args = vec![
        "nft".to_string(),
        "add".to_string(),
        "rule".to_string(),
        "inet".to_string(),
        jail.nftables_table.clone(),
        jail.nftables_chain.clone(),
        if ipv6 { "ip6" } else { "ip" }.to_string(),
        "saddr".to_string(),
        format!("@{}", set_name),
    ];
    if let Some(ports) = nft_ports_expression(jail) {
        args.extend([jail.protocol.clone(), "dport".to_string(), ports]);
    }
    args.push("drop".to_string());
    args
}

fn build_nft_element_action_args(
    jail: &TraceyBanJailConfig,
    adding: bool,
    ip: &str,
) -> Vec<String> {
    let set_name = if ip.parse::<IpAddr>().ok().is_some_and(|addr| addr.is_ipv6()) {
        nftables_set_name(jail, "v6")
    } else {
        nftables_set_name(jail, "v4")
    };
    vec![
        "nft".to_string(),
        if adding { "add" } else { "delete" }.to_string(),
        "element".to_string(),
        "inet".to_string(),
        jail.nftables_table.clone(),
        set_name,
        format!("{{ {} }}", ip),
    ]
}

fn nft_ports_expression(jail: &TraceyBanJailConfig) -> Option<String> {
    if jail.ports.is_empty() {
        None
    } else if jail.ports.len() == 1 {
        Some(jail.ports[0].to_string())
    } else {
        Some(format!(
            "{{ {} }}",
            jail.ports
                .iter()
                .map(|port| port.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ))
    }
}

fn log_action_failure(
    config: &TraceyBanConfig,
    jail: &TraceyBanJailConfig,
    action: JailActionKind,
    description: &str,
    use_sudo: bool,
    result: &CommandRunResult,
) {
    if result.timed_out {
        tracing::warn!(
            jail = %jail.name,
            action_kind = action.as_str(),
            command = %description,
            "tracey_ban action command timed out"
        );
        return;
    }
    if let Some(error) = &result.error {
        tracing::warn!(
            jail = %jail.name,
            action_kind = action.as_str(),
            command = %description,
            error = %error,
            "tracey_ban action execution failed"
        );
        return;
    }

    tracing::warn!(
        jail = %jail.name,
        action_kind = action.as_str(),
        command = %description,
        use_sudo,
        exit_code = ?result.exit_code,
        stdout = %result.stdout,
        stderr = %result.stderr,
        "tracey_ban action command failed"
    );

    if use_sudo {
        let lower = combined_action_output(result);
        if lower.contains("password") || lower.contains("permission denied") {
            tracing::warn!(
                jail = %jail.name,
                sudo_program = %config.sudo_program,
                "tracey_ban action likely failed due to missing sudo privileges"
            );
        }
    }
}

fn contains_shell_control_tokens(tokens: &[String]) -> bool {
    tokens.iter().any(|token| {
        matches!(
            token.as_str(),
            "|" | "||" | "&&" | ";" | ">" | ">>" | "<" | "<<"
        ) || token.contains("$(")
            || token.contains('`')
    })
}

fn split_command_line(input: &str) -> Result<Vec<String>, String> {
    #[derive(Clone, Copy)]
    enum QuoteMode {
        Single,
        Double,
    }

    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut chars = input.chars().peekable();
    let mut quote_mode = None;

    while let Some(ch) = chars.next() {
        match quote_mode {
            None => match ch {
                '\'' => quote_mode = Some(QuoteMode::Single),
                '"' => quote_mode = Some(QuoteMode::Double),
                '\\' => {
                    let Some(next) = chars.next() else {
                        return Err("dangling escape sequence".to_string());
                    };
                    current.push(next);
                }
                ch if ch.is_whitespace() => {
                    if !current.is_empty() {
                        tokens.push(std::mem::take(&mut current));
                    }
                }
                _ => current.push(ch),
            },
            Some(QuoteMode::Single) => {
                if ch == '\'' {
                    quote_mode = None;
                } else {
                    current.push(ch);
                }
            }
            Some(QuoteMode::Double) => {
                if ch == '"' {
                    quote_mode = None;
                } else if ch == '\\' {
                    let Some(next) = chars.next() else {
                        return Err("dangling escape sequence in double quotes".to_string());
                    };
                    current.push(next);
                } else {
                    current.push(ch);
                }
            }
        }
    }

    if quote_mode.is_some() {
        return Err("unterminated quoted string".to_string());
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    if tokens.is_empty() {
        return Err("empty command".to_string());
    }
    Ok(tokens)
}

async fn probe_firewall_backend() -> FirewallBackendProbe {
    let ufw_available = command_available("ufw");
    let firewalld_available = command_available("firewall-cmd");
    let nft_available = command_available("nft");

    let ufw_active = if ufw_available {
        let result = run_probe_command("ufw", &["status"], 2_000).await;
        result.success
            && result
                .stdout
                .to_ascii_lowercase()
                .contains("status: active")
    } else {
        false
    };

    let firewalld_running = if firewalld_available {
        let result = run_probe_command("firewall-cmd", &["--state"], 2_000).await;
        result.success && result.stdout.trim().eq_ignore_ascii_case("running")
    } else {
        false
    };

    FirewallBackendProbe {
        ufw_available,
        ufw_active,
        firewalld_available,
        firewalld_running,
        nft_available,
    }
}

fn command_available(program: &str) -> bool {
    if program.contains('/') {
        return std::fs::metadata(program)
            .map(|metadata| metadata.is_file())
            .unwrap_or(false);
    }
    let Some(paths) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&paths).any(|dir| {
        std::fs::metadata(dir.join(program))
            .map(|metadata| metadata.is_file())
            .unwrap_or(false)
    })
}

async fn run_probe_command(program: &str, args: &[&str], timeout_ms: u64) -> CommandRunResult {
    let mut process = Command::new(program);
    process
        .args(args)
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    match tokio::time::timeout(Duration::from_millis(timeout_ms), process.output()).await {
        Ok(Ok(output)) => CommandRunResult {
            success: output.status.success(),
            exit_code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            timed_out: false,
            error: None,
        },
        Ok(Err(err)) => CommandRunResult {
            success: false,
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
            timed_out: false,
            error: Some(err.to_string()),
        },
        Err(_) => CommandRunResult {
            success: false,
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
            timed_out: true,
            error: None,
        },
    }
}

async fn load_state(path: &PathBuf) -> PersistedState {
    match tokio::fs::read_to_string(path).await {
        Ok(raw) => match serde_json::from_str::<PersistedState>(&raw) {
            Ok(state) => state,
            Err(err) => {
                tracing::warn!(path=%path.display(), error=%err, "failed to parse tracey_ban state");
                PersistedState::default()
            }
        },
        Err(_) => PersistedState::default(),
    }
}

async fn restore_persisted_bans(
    jails: &mut HashMap<String, JailRuntime>,
    persisted: &mut PersistedState,
    intel_hub: &BanIntelHub,
) {
    let now = now_ms();

    for (key, value) in std::mem::take(&mut persisted.ban_counts) {
        if let Some((jail_name, _)) = key.split_once("::")
            && let Some(jail) = jails.get_mut(jail_name)
        {
            jail.ban_counts.insert(key, value);
        }
    }

    for ban in std::mem::take(&mut persisted.bans) {
        if ban.expires_ms.is_some_and(|expires| expires <= now) {
            continue;
        }
        if let Some(jail) = jails.get_mut(&ban.jail) {
            let entry = BanAdvertisementEntry {
                ip: ban.ip.clone(),
                jail: ban.jail.clone(),
                expires_ms: ban.expires_ms,
                ban_count: ban.ban_count,
                last_ban_ms: ban.banned_at_ms,
            };
            jail.active_bans.insert(ban.ip.clone(), ban.clone());
            intel_hub.update_local_ban(entry).await;
        }
    }
}

async fn persist_runtime_state(
    path: &Path,
    jails: &HashMap<String, JailRuntime>,
    offsets: &Arc<RwLock<HashMap<String, u64>>>,
) {
    let mut bans = Vec::new();
    let mut ban_counts = HashMap::new();

    for jail in jails.values() {
        for ban in jail.active_bans.values() {
            bans.push(ban.clone());
        }
        for (key, value) in &jail.ban_counts {
            ban_counts.insert(key.clone(), *value);
        }
    }

    let state = PersistedState {
        version: 1,
        offsets: offsets.read().await.clone(),
        bans,
        ban_counts,
    };

    let Some(parent) = path.parent() else {
        return;
    };

    if !parent.as_os_str().is_empty() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }

    match serde_json::to_vec_pretty(&state) {
        Ok(payload) => {
            if let Err(err) = tokio::fs::write(path, payload).await {
                tracing::warn!(path=%path.display(), error=%err, "failed to persist tracey_ban state");
            }
        }
        Err(err) => {
            tracing::warn!(path=%path.display(), error=%err, "failed to serialize tracey_ban state");
        }
    }
}

fn parse_tracey_ban_filter_file(path: &Path) -> std::io::Result<ParsedFilterDefinition> {
    let raw = std::fs::read_to_string(path)?;
    let mut parsed = ParsedFilterDefinition {
        fail: Vec::new(),
        ignore: Vec::new(),
        journal_matches: Vec::new(),
    };

    let mut in_definition = false;
    let mut active_key: Option<String> = None;

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }

        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_definition = trimmed
                .trim_start_matches('[')
                .trim_end_matches(']')
                .eq_ignore_ascii_case("Definition");
            active_key = None;
            continue;
        }

        if !in_definition {
            continue;
        }

        if let Some((key, value)) = trimmed.split_once('=') {
            let key = key.trim().to_ascii_lowercase();
            let value = value.trim();
            if key == "failregex" || key == "ignoreregex" || key == "journalmatch" {
                active_key = Some(key.clone());
                if !value.is_empty() {
                    if key == "failregex" {
                        parsed.fail.push(value.to_string());
                    } else if key == "ignoreregex" {
                        parsed.ignore.push(value.to_string());
                    } else {
                        parsed.journal_matches.push(value.to_string());
                    }
                }
            } else {
                active_key = None;
            }
            continue;
        }

        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(key) = &active_key {
                if key == "failregex" {
                    parsed.fail.push(trimmed.to_string());
                } else if key == "ignoreregex" {
                    parsed.ignore.push(trimmed.to_string());
                } else if key == "journalmatch" {
                    parsed.journal_matches.push(trimmed.to_string());
                }
            }
        }
    }

    Ok(parsed)
}

fn is_running_as_root() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: libc::geteuid is thread-safe and has no preconditions.
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

fn is_root_log_path(path: &Path) -> bool {
    let lower = path.to_string_lossy().to_ascii_lowercase();
    ROOT_LOG_PREFIXES
        .iter()
        .any(|prefix| lower.starts_with(&prefix.to_ascii_lowercase()))
}

fn looks_like_firewall_rule_command(command: &str) -> bool {
    let lower = command.to_ascii_lowercase();
    FIREWALL_ACTION_KEYWORDS
        .iter()
        .any(|keyword| lower.contains(keyword))
}

fn translate_tracey_ban_regex(input: &str) -> Result<String, String> {
    let mut output = input.to_string();

    let replacements = [
        (
            "<HOST>",
            r"(?P<host>(?:\d{1,3}\.){3}\d{1,3}|(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4})",
        ),
        (
            "<ADDR>",
            r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4})",
        ),
        ("<IP4>", r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})"),
        (
            "<IP6>",
            r"(?P<ip>(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4})",
        ),
        ("<F-USER>", ""),
        ("</F-USER>", ""),
        ("<F-PORT>", ""),
        ("</F-PORT>", ""),
        ("<F-ID/>", ""),
        ("<SKIPLINES>", r"(?:.*\\n)*"),
    ];
    for (from, to) in replacements {
        output = output.replace(from, to);
    }

    output = field_tag_re().replace_all(&output, "").to_string();

    if format_macro_re().is_match(&output) {
        return Err(
            "legacy jail interpolation macros are not supported in TraceyBan regexes".to_string(),
        );
    }
    if let Some(tag) = find_unsupported_legacy_filter_tag(&output) {
        return Err(format!("unsupported legacy filter tag {}", tag));
    }

    Ok(output)
}

fn normalize_ip(ip: &str) -> Option<String> {
    ip.trim()
        .parse::<IpAddr>()
        .ok()
        .map(|value| value.to_string())
}

fn field_tag_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"</?F-[A-Z0-9_-]+/?>(?:</?F-[A-Z0-9_-]+/?>)?").expect("field tag regex")
    })
}

fn format_macro_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"%\([^)]+\)s").expect("format macro regex"))
}

fn find_unsupported_legacy_filter_tag(output: &str) -> Option<String> {
    let mut idx = 0usize;
    while let Some(offset) = output[idx..].find('<') {
        let start = idx + offset;
        if output[..start].ends_with("(?P") {
            idx = start + 1;
            continue;
        }
        let end = output[start..].find('>')?;
        return Some(output[start..start + end + 1].to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::StorageConfig;
    use crate::shutdown::Shutdown;

    #[test]
    fn adjusted_retry_uses_fuzzy_reduction_when_risk_confident() {
        let retry = adjusted_retry_with_fuzzy(6, 0.95, 0.90, 0.60, 0.30, 0.55);
        assert!(
            retry < 6,
            "expected fuzzy-driven retry reduction, got retry={}",
            retry
        );
    }

    #[test]
    fn adjusted_retry_keeps_base_when_below_gate() {
        let retry = adjusted_retry_with_fuzzy(6, 0.40, 0.20, 0.60, 0.30, 0.55);
        assert_eq!(retry, 6);
    }

    #[test]
    fn adjusted_retry_never_drops_below_one() {
        let retry = adjusted_retry_with_fuzzy(3, 1.0, 1.0, 0.0, 0.0, 0.95);
        assert_eq!(retry, 1);
    }

    #[test]
    fn fuzzy_signal_increases_with_remote_and_recidive_pressure() {
        let low = build_fuzzy_signal(2, 5, 0, 0, 5);
        let high = build_fuzzy_signal(2, 5, 3, 5, 5);
        assert!(
            high > low,
            "expected higher fuzzy signal under more pressure"
        );
    }

    #[test]
    fn line_context_extracts_cve_and_cvss() {
        let line = "blocked exploit CVE-2026-12345 with CVSS 9.8 remote";
        assert_eq!(extract_cve(line).as_deref(), Some("CVE-2026-12345"));
        assert_eq!(extract_cvss(line), Some(9.8));
    }

    #[test]
    fn root_log_path_detection_matches_standard_locations() {
        assert!(is_root_log_path(Path::new("/var/log/auth.log")));
        assert!(is_root_log_path(Path::new(
            "/var/lib/journal/system.journal"
        )));
        assert!(!is_root_log_path(Path::new("logs/app.log")));
    }

    #[test]
    fn firewall_action_detection_matches_common_commands() {
        assert!(looks_like_firewall_rule_command(
            "iptables -I INPUT -s <ip> -j DROP"
        ));
        assert!(looks_like_firewall_rule_command(
            "nft add element inet filter tracey_ban { <ip> }"
        ));
        assert!(!looks_like_firewall_rule_command("echo notify-only action"));
    }

    #[test]
    fn match_line_requires_failure_regex_match() {
        let fail = compile_regexes(
            &[r"(?i)^.*failed .* from <HOST>.*$".to_string()],
            "failregex",
            "unit",
        );
        assert_eq!(
            match_line_with_regexes(
                "Accepted password for root from 203.0.113.10 port 22 ssh2",
                &fail,
                &[],
                None
            ),
            None
        );
        assert_eq!(
            match_line_with_regexes(
                "Failed password for root from 203.0.113.10 port 22 ssh2",
                &fail,
                &[],
                None
            )
            .as_deref(),
            Some("203.0.113.10")
        );
    }

    #[test]
    fn extract_ip_from_event_does_not_scan_all_attrs_by_default() {
        let jail = TraceyBanJailConfig::default();
        let event = Event::new(1, "unit", EventKind::Observability, 0.2, Severity::Low)
            .with_attr("message", "failed login from 198.51.100.25");
        assert_eq!(extract_ip_from_event(&event, &jail), None);

        let mut permissive = jail.clone();
        permissive.scan_all_event_attrs_for_ip = true;
        assert_eq!(
            extract_ip_from_event(&event, &permissive).as_deref(),
            Some("198.51.100.25")
        );
    }

    #[test]
    fn explicit_ban_event_flag_is_boolish() {
        let event = Event::new(1, "unit", EventKind::Observability, 0.2, Severity::Low)
            .with_attr("tracey_ban_match", "yes");
        assert!(event_requests_explicit_ban(&event));
    }

    #[test]
    fn command_line_split_preserves_quoted_arguments() {
        let tokens =
            split_command_line("ufw --force deny from <ip> comment \"bad actor <matches>\"")
                .expect("tokenized");
        assert_eq!(
            tokens,
            vec![
                "ufw",
                "--force",
                "deny",
                "from",
                "<ip>",
                "comment",
                "bad actor <matches>"
            ]
        );
    }

    #[test]
    fn shell_control_tokens_are_detected() {
        assert!(contains_shell_control_tokens(&[
            "iptables".to_string(),
            "&&".to_string(),
            "logger".to_string()
        ]));
        assert!(!contains_shell_control_tokens(&[
            "nft".to_string(),
            "add".to_string(),
            "set".to_string(),
            "timeout;".to_string()
        ]));
    }

    #[test]
    fn regex_translation_rejects_unknown_tags_and_macros() {
        assert!(translate_tracey_ban_regex("failed from <HOST>").is_ok());
        assert!(translate_tracey_ban_regex("%(__prefix_line)s failed from <HOST>").is_err());
        assert!(translate_tracey_ban_regex("failed from <UNKNOWN>").is_err());
    }

    #[test]
    fn cidr_ignore_network_matches_members() {
        let network = IgnoreNetwork::parse("192.0.2.0/24").expect("network");
        assert!(network.contains(&"192.0.2.42".parse::<IpAddr>().expect("ip")));
        assert!(!network.contains(&"198.51.100.1".parse::<IpAddr>().expect("ip")));
    }

    #[test]
    fn filter_parser_collects_journalmatch_lines() {
        let path = std::env::temp_dir().join(format!("tracey_ban_filter_{}.conf", now_ms()));
        std::fs::write(
            &path,
            "[Definition]\nfailregex = failed from <HOST>\njournalmatch = _SYSTEMD_UNIT=sshd.service + _COMM=sshd\n",
        )
        .expect("write filter");
        let parsed = parse_tracey_ban_filter_file(&path).expect("parsed filter");
        let _ = std::fs::remove_file(&path);

        assert_eq!(parsed.fail, vec!["failed from <HOST>".to_string()]);
        assert_eq!(
            parsed.journal_matches,
            vec!["_SYSTEMD_UNIT=sshd.service + _COMM=sshd".to_string()]
        );
    }

    #[test]
    fn autodetect_prefers_firewalld_then_ufw_then_nftables() {
        assert_eq!(
            autodetect_firewall_backend(&FirewallBackendProbe {
                firewalld_running: true,
                nft_available: true,
                ufw_available: true,
                ufw_active: true,
                firewalld_available: true,
            }),
            TraceyBanFirewallBackend::Firewalld
        );
        assert_eq!(
            autodetect_firewall_backend(&FirewallBackendProbe {
                ufw_active: true,
                nft_available: true,
                ufw_available: true,
                firewalld_available: false,
                firewalld_running: false,
            }),
            TraceyBanFirewallBackend::Ufw
        );
        assert_eq!(
            autodetect_firewall_backend(&FirewallBackendProbe {
                nft_available: true,
                ..FirewallBackendProbe::default()
            }),
            TraceyBanFirewallBackend::Nftables
        );
    }

    #[test]
    fn filter_catalog_merges_sshd_defaults() {
        let mut jail = TraceyBanJailConfig::default();
        jail.log_paths.clear();
        jail.journal_matches.clear();
        jail.fail_regex.clear();
        let resolved = merge_filter_catalog_into_jail(&jail).expect("catalog resolved");
        assert!(
            resolved
                .log_paths
                .iter()
                .any(|path| path == Path::new("/var/log/auth.log"))
        );
        assert!(
            resolved
                .log_paths
                .iter()
                .any(|path| path == Path::new("/var/log/secure"))
        );
        assert!(
            resolved
                .journal_matches
                .iter()
                .any(|value| value.contains("_SYSTEMD_UNIT=sshd.service"))
        );
        assert!(
            resolved
                .fail_regex
                .iter()
                .any(|value| value.contains("Failed password"))
        );
    }

    #[test]
    fn built_in_filter_catalogs_cover_common_auth_surfaces() {
        let filter_names: Vec<String> = built_in_filter_catalog_summaries()
            .into_iter()
            .map(|entry| entry.name)
            .collect();
        assert!(filter_names.contains(&"nginx-http-auth".to_string()));
        assert!(filter_names.contains(&"apache-auth".to_string()));
        assert!(filter_names.contains(&"postfix".to_string()));
        assert!(filter_names.contains(&"recidive".to_string()));
    }

    #[test]
    fn nginx_http_auth_filter_matches_example() {
        let jail = TraceyBanJailConfig {
            name: "nginx".to_string(),
            filter_catalog: Some("nginx-http-auth".to_string()),
            ..TraceyBanJailConfig::default()
        };
        let resolved = merge_filter_catalog_into_jail(&jail).expect("catalog resolved");
        assert_eq!(resolved.ports, vec![80, 443]);
        let fail = compile_regexes(&resolved.fail_regex, "failregex", &resolved.name);
        let line = r#"2026/04/08 10:00:00 [error] 1234#1234: *1 user "admin": password mismatch, client: 203.0.113.21, server: example.com, request: "GET /secure HTTP/1.1", host: "example.com""#;
        assert_eq!(
            match_line_with_regexes(line, &fail, &[], None).as_deref(),
            Some("203.0.113.21")
        );
    }

    #[test]
    fn apache_auth_filter_matches_example() {
        let jail = TraceyBanJailConfig {
            name: "apache".to_string(),
            filter_catalog: Some("apache-auth".to_string()),
            ..TraceyBanJailConfig::default()
        };
        let resolved = merge_filter_catalog_into_jail(&jail).expect("catalog resolved");
        let fail = compile_regexes(&resolved.fail_regex, "failregex", &resolved.name);
        let line = r#"[Tue Apr 08 10:00:00.000000 2026] [auth_basic:error] [pid 1234:tid 12345] [client 203.0.113.22:0] AH01617: user admin: authentication failure for "/secure": Password Mismatch"#;
        assert_eq!(
            match_line_with_regexes(line, &fail, &[], None).as_deref(),
            Some("203.0.113.22")
        );
    }

    #[test]
    fn postfix_filter_matches_example() {
        let jail = TraceyBanJailConfig {
            name: "postfix".to_string(),
            filter_catalog: Some("postfix".to_string()),
            ..TraceyBanJailConfig::default()
        };
        let resolved = merge_filter_catalog_into_jail(&jail).expect("catalog resolved");
        assert_eq!(resolved.ports, vec![25, 465, 587]);
        let fail = compile_regexes(&resolved.fail_regex, "failregex", &resolved.name);
        let line = "Apr  8 10:00:00 mx postfix/smtpd[1234]: warning: unknown[203.0.113.23]: SASL LOGIN authentication failed: authentication failure";
        assert_eq!(
            match_line_with_regexes(line, &fail, &[], None).as_deref(),
            Some("203.0.113.23")
        );
    }

    #[test]
    fn recidive_filter_ignores_its_own_jail_records() {
        let jail = TraceyBanJailConfig {
            name: "recidive".to_string(),
            filter_catalog: Some("recidive".to_string()),
            ..TraceyBanJailConfig::default()
        };
        let resolved = merge_filter_catalog_into_jail(&jail).expect("catalog resolved");
        assert!(resolved.ports.is_empty());
        let fail = compile_regexes(&resolved.fail_regex, "failregex", &resolved.name);
        let ignore = compile_regexes(&resolved.ignore_regex, "ignoreregex", &resolved.name);
        let self_line = r#"{"type":"ban_update","payload":{"ts_ms":1,"jail":"recidive","ip":"203.0.113.24","banned":true,"ban_count":1,"expires_ms":null,"reason":"x","source":"x","fuzzy_risk":null,"fuzzy_confidence":null,"fuzzy_signal":null,"fuzzy_adjusted_retry":null}}"#;
        let other_line = r#"{"type":"ban_update","payload":{"ts_ms":1,"jail":"sshd-auth","ip":"203.0.113.24","banned":true,"ban_count":1,"expires_ms":null,"reason":"x","source":"x","fuzzy_risk":null,"fuzzy_confidence":null,"fuzzy_signal":null,"fuzzy_adjusted_retry":null}}"#;
        assert_eq!(
            match_line_with_regexes(self_line, &fail, &ignore, None),
            None
        );
        assert_eq!(
            match_line_with_regexes(other_line, &fail, &ignore, None).as_deref(),
            Some("203.0.113.24")
        );
    }

    #[test]
    fn ufw_action_args_include_ports_and_protocol() {
        let jail = TraceyBanJailConfig::default();
        let args = build_ufw_action_args(&jail, JailActionKind::Ban, "203.0.113.9");
        assert_eq!(
            args[0],
            vec![
                "ufw",
                "--force",
                "insert",
                "1",
                "deny",
                "from",
                "203.0.113.9",
                "to",
                "any",
                "port",
                "22",
                "proto",
                "tcp"
            ]
        );
    }

    #[test]
    fn firewalld_action_args_render_rich_rule() {
        let jail = TraceyBanJailConfig::default();
        let args = build_firewalld_action_args(&jail, JailActionKind::Ban, "203.0.113.9", "public");
        assert_eq!(args[0][0], "firewall-cmd");
        assert!(
            args[0]
                .last()
                .expect("rich rule arg")
                .contains("source address=\"203.0.113.9\"")
        );
        assert!(
            args[0]
                .last()
                .expect("rich rule arg")
                .contains("port port=\"22\" protocol=\"tcp\"")
        );
    }

    #[test]
    fn nft_action_builders_render_expected_structure() {
        let jail = TraceyBanJailConfig::default();
        let rule_args = build_nft_rule_args(&jail, "tb_tracey_default_v4", false);
        assert_eq!(
            rule_args,
            vec![
                "nft",
                "add",
                "rule",
                "inet",
                "tracey_ban",
                "tracey_input",
                "ip",
                "saddr",
                "@tb_tracey_default_v4",
                "tcp",
                "dport",
                "22",
                "drop"
            ]
        );

        let element_args = build_nft_element_action_args(&jail, true, "203.0.113.9");
        assert_eq!(
            element_args,
            vec![
                "nft",
                "add",
                "element",
                "inet",
                "tracey_ban",
                "tb_tracey_default_v4",
                "{ 203.0.113.9 }"
            ]
        );
    }

    #[tokio::test]
    async fn failed_ban_action_does_not_record_active_ban() {
        let mut config = TraceyBanConfig::default();
        config.agent_id = "unit".to_string();
        config.use_sudo_for_actions = false;
        let mut jail_cfg = TraceyBanJailConfig::default();
        jail_cfg.name = "unit".to_string();
        jail_cfg.filter_catalog = None;
        jail_cfg.fail_regex = vec![r"(?i)^.*failed .* from <HOST>.*$".to_string()];
        jail_cfg.action_catalog = None;
        jail_cfg.action_ban = Some("false".to_string());

        let jail = JailRuntime::from_config(&jail_cfg, &config).expect("jail runtime");
        let mut jails = HashMap::from([(jail.config.name.clone(), jail)]);

        let bus = EventBus::new(16);
        let (shutdown, listener) = Shutdown::new();
        let storage_path =
            std::env::temp_dir().join(format!("tracey_ban_state_test_{}.jsonl", now_ms()));
        let storage = Storage::new(
            StorageConfig {
                log_path: storage_path.clone(),
                ..StorageConfig::default()
            },
            listener,
        )
        .await
        .expect("storage");
        let intel_hub = BanIntelHub::new(15_000);

        process_detection(
            Detection {
                jail: "unit".to_string(),
                ip: "203.0.113.9".to_string(),
                ts_ms: now_ms(),
                source: "unit-test".to_string(),
                reason: "match".to_string(),
                line: Some("Failed password for root from 203.0.113.9 port 22 ssh2".to_string()),
            },
            &mut jails,
            &config,
            &bus,
            &storage,
            &intel_hub,
        )
        .await;

        let jail = jails.get("unit").expect("jail");
        assert!(jail.active_bans.is_empty());
        assert!(jail.ban_counts.is_empty());

        shutdown.trigger();
        let _ = tokio::fs::remove_file(storage_path).await;
    }

    #[tokio::test]
    async fn failed_unban_action_retains_active_ban() {
        let mut config = TraceyBanConfig::default();
        config.agent_id = "unit".to_string();
        config.use_sudo_for_actions = false;
        let mut jail_cfg = TraceyBanJailConfig::default();
        jail_cfg.name = "unit".to_string();
        jail_cfg.filter_catalog = None;
        jail_cfg.fail_regex = vec![r"(?i)^.*failed .* from <HOST>.*$".to_string()];
        jail_cfg.action_catalog = None;
        jail_cfg.action_ban = Some("true".to_string());
        jail_cfg.action_unban = Some("false".to_string());

        let mut jail = JailRuntime::from_config(&jail_cfg, &config).expect("jail runtime");
        let bus = EventBus::new(16);
        let (shutdown, listener) = Shutdown::new();
        let storage_path =
            std::env::temp_dir().join(format!("tracey_ban_unban_test_{}.jsonl", now_ms()));
        let storage = Storage::new(
            StorageConfig {
                log_path: storage_path.clone(),
                ..StorageConfig::default()
            },
            listener,
        )
        .await
        .expect("storage");
        let intel_hub = BanIntelHub::new(15_000);

        assert!(
            install_ban_record(
                &mut jail,
                &config,
                &bus,
                &storage,
                &intel_hub,
                "203.0.113.10",
                now_ms(),
                "unit-test",
                "manual",
                Some(60_000),
                None,
                None,
                1,
            )
            .await
        );
        assert!(jail.active_bans.contains_key("203.0.113.10"));

        assert!(
            !uninstall_ban_record(
                &mut jail,
                &config,
                &bus,
                &storage,
                &intel_hub,
                "203.0.113.10",
                "unit-test",
                "manual",
                "unit",
            )
            .await
        );
        assert!(jail.active_bans.contains_key("203.0.113.10"));

        shutdown.trigger();
        let _ = tokio::fs::remove_file(storage_path).await;
    }
}
