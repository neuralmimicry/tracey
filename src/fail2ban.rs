use crate::bus::EventBus;
use crate::config::{Fail2BanConfig, Fail2BanJailConfig};
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
use tokio::sync::{RwLock, mpsc};

static FAIL2BAN_FUZZY_EVENT_COUNTER: AtomicU64 = AtomicU64::new(20_000_000);
const FAIL2BAN_ELEVATION_MARKER: &str = "TRACEY_FAIL2BAN_ELEVATED";
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

struct JailRuntime {
    config: Fail2BanJailConfig,
    fail_regex: Vec<Regex>,
    ignore_regex: Vec<Regex>,
    prefilter_regex: Option<Regex>,
    ignore_ip_set: HashSet<IpAddr>,
    ignore_ip_raw: HashSet<String>,
    failure_windows: HashMap<String, VecDeque<u64>>,
    active_bans: HashMap<String, ActiveBan>,
    ban_counts: HashMap<String, u32>,
    scorer: AdaptiveScorer,
}

impl JailRuntime {
    fn from_config(config: &Fail2BanJailConfig, fail2ban_cfg: &Fail2BanConfig) -> Option<Self> {
        if !config.enabled {
            return None;
        }

        let mut fail_patterns = config.fail_regex.clone();
        let mut ignore_patterns = config.ignore_regex.clone();
        for filter_file in &config.filter_files {
            if let Ok((fails, ignores)) = parse_fail2ban_filter_file(filter_file) {
                fail_patterns.extend(fails);
                ignore_patterns.extend(ignores);
            }
        }

        let fail_regex = compile_regexes(&fail_patterns, "failregex", &config.name);
        if fail_regex.is_empty() {
            tracing::warn!(
                jail = %config.name,
                "fail2ban jail has no valid fail regex; jail disabled"
            );
            return None;
        }

        let ignore_regex = compile_regexes(&ignore_patterns, "ignoreregex", &config.name);
        let prefilter_regex = config
            .prefilter_regex
            .as_ref()
            .and_then(|p| Regex::new(p).ok());

        let mut ignore_ip_set = HashSet::new();
        let mut ignore_ip_raw = HashSet::new();
        for ip in &config.ignore_ips {
            if let Ok(parsed) = ip.parse::<IpAddr>() {
                ignore_ip_set.insert(parsed);
            } else {
                ignore_ip_raw.insert(ip.trim().to_ascii_lowercase());
            }
        }

        Some(Self {
            config: config.clone(),
            fail_regex,
            ignore_regex,
            prefilter_regex,
            ignore_ip_set,
            ignore_ip_raw,
            failure_windows: HashMap::new(),
            active_bans: HashMap::new(),
            ban_counts: HashMap::new(),
            scorer: AdaptiveScorer::new(fail2ban_cfg.min_samples, fail2ban_cfg.fuzzy.clone()),
        })
    }

    fn should_process_logs(&self) -> bool {
        matches!(
            self.config.backend.as_str(),
            "auto" | "file" | "polling" | "pyinotify" | "hybrid"
        ) && !self.config.log_paths.is_empty()
    }

    fn should_process_events(&self) -> bool {
        matches!(
            self.config.backend.as_str(),
            "auto" | "event" | "tracey_event" | "hybrid"
        )
    }

    fn is_ignored_ip(&self, ip: &str) -> bool {
        if let Ok(addr) = ip.parse::<IpAddr>() {
            return self.ignore_ip_set.contains(&addr);
        }
        self.ignore_ip_raw.contains(&ip.to_ascii_lowercase())
    }
}

fn compile_regexes(patterns: &[String], label: &str, jail: &str) -> Vec<Regex> {
    let mut out = Vec::new();
    for pattern in patterns {
        let translated = translate_fail2ban_regex(pattern);
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

pub fn maybe_elevate_for_fail2ban(config: &Fail2BanConfig) -> Option<i32> {
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
        .flat_map(|jail| jail.log_paths.iter())
        .any(|path| is_root_log_path(path));
    let needs_root_actions = config.jails.iter().filter(|jail| jail.enabled).any(|jail| {
        [
            jail.action_start.as_deref(),
            jail.action_stop.as_deref(),
            jail.action_ban.as_deref(),
            jail.action_unban.as_deref(),
        ]
        .into_iter()
        .flatten()
        .any(looks_like_firewall_rule_command)
    });

    if !needs_root_logs && !needs_root_actions {
        return None;
    }

    tracing::warn!(
        needs_root_logs,
        needs_root_actions,
        "fail2ban requires elevated privileges for configured log paths/actions"
    );

    if !config.auto_elevate_root {
        tracing::warn!(
            "fail2ban auto-elevation disabled; root-protected logs/firewall actions may fail"
        );
        return None;
    }
    if std::env::var_os(FAIL2BAN_ELEVATION_MARKER).is_some() {
        tracing::warn!(
            "fail2ban elevation already attempted in this process; continuing unprivileged"
        );
        return None;
    }

    let exe = match std::env::current_exe() {
        Ok(path) => path,
        Err(err) => {
            tracing::warn!(error=%err, "failed to resolve current executable for fail2ban elevation");
            return None;
        }
    };

    let mut cmd = StdCommand::new(&config.sudo_program);
    if config.sudo_non_interactive {
        cmd.arg("-n");
    }
    cmd.arg(exe);
    cmd.args(std::env::args().skip(1));
    cmd.env(FAIL2BAN_ELEVATION_MARKER, "1");

    match cmd.status() {
        Ok(status) => {
            let code = status
                .code()
                .unwrap_or(if status.success() { 0 } else { 1 });
            if status.success() {
                tracing::info!(
                    code,
                    "fail2ban elevated process completed; exiting parent process"
                );
                Some(code)
            } else {
                tracing::warn!(
                    code,
                    "fail2ban elevation command exited non-zero; continuing unprivileged"
                );
                None
            }
        }
        Err(err) => {
            tracing::warn!(
                sudo_program = %config.sudo_program,
                error = %err,
                "failed to execute fail2ban elevation command; continuing unprivileged"
            );
            None
        }
    }
}

pub async fn spawn_fail2ban(
    config: Fail2BanConfig,
    bus: EventBus,
    storage: Storage,
    mut shutdown: ShutdownListener,
    intel_hub: BanIntelHub,
) {
    if !config.enabled {
        tracing::info!("fail2ban runtime disabled");
        return;
    }

    let mut jails = HashMap::<String, JailRuntime>::new();
    for jail_cfg in &config.jails {
        if let Some(jail) = JailRuntime::from_config(jail_cfg, &config) {
            jails.insert(jail.config.name.clone(), jail);
        }
    }

    if jails.is_empty() {
        tracing::warn!("fail2ban enabled but no usable jails configured");
        return;
    }

    tracing::info!(jail_count = jails.len(), "fail2ban runtime enabled");

    let mut persisted = load_state(&config.state_path).await;
    let offsets = Arc::new(RwLock::new(std::mem::take(&mut persisted.offsets)));

    restore_persisted_bans(&mut jails, &mut persisted, &intel_hub).await;

    for jail in jails.values() {
        run_jail_action(
            &config,
            &jail.config,
            jail.config.action_start.as_deref(),
            None,
            None,
            None,
        )
        .await;
    }

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
                tracing::info!("fail2ban runtime shutting down");
                break;
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
            }
            _ = unban_tick.tick() => {
                process_unbans(&mut jails, &bus, &storage, &intel_hub, &config, &config.agent_id).await;
            }
            _ = persist_tick.tick() => {
                persist_runtime_state(&config.state_path, &jails, &offsets).await;
            }
        }
    }

    for jail in jails.values() {
        run_jail_action(
            &config,
            &jail.config,
            jail.config.action_stop.as_deref(),
            None,
            None,
            None,
        )
        .await;
        intel_hub.clear_local_jail(&jail.config.name).await;
    }

    persist_runtime_state(&config.state_path, &jails, &offsets).await;
}

async fn run_log_worker(
    jail_name: String,
    jail_cfg: Fail2BanJailConfig,
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
                                "fail2ban cannot read log path due to permissions"
                            );
                        } else {
                            tracing::debug!(jail=%jail_name, path=%path.display(), error=%err, "fail2ban log worker read failed");
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
    jail_cfg: Fail2BanJailConfig,
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
                if event.source.starts_with("fail2ban") {
                    continue;
                }
                if let Some(ip) = extract_ip_from_event(&event, &jail_cfg) {
                    let message = event
                        .attributes
                        .get("message")
                        .cloned()
                        .unwrap_or_else(|| format!("source={} signal={:.3}", event.source, event.signal));
                    let matched = if fail_regex.is_empty() {
                        Some(ip.clone())
                    } else {
                        match_line_with_regexes(&message, &fail_regex, &ignore_regex, prefilter.as_ref())
                            .or_else(|| Some(ip.clone()))
                    };

                    if let Some(ip) = matched {
                        let _ = tx
                            .send(Detection {
                                jail: jail_name.clone(),
                                ip,
                                ts_ms: event.ts_ms,
                                source: event.source,
                                reason: "tracey_event".to_string(),
                                line: Some(message),
                            })
                            .await;
                    }
                }
            }
        }
    }
}

fn extract_ip_from_event(event: &Event, jail_cfg: &Fail2BanJailConfig) -> Option<String> {
    for key in &jail_cfg.event_ip_keys {
        if let Some(value) = event.attributes.get(key)
            && let Some(ip) = normalize_ip(value)
        {
            return Some(ip);
        }
    }

    event
        .attributes
        .values()
        .find_map(|value| extract_ip_from_line(value))
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

    extract_ip_from_line(line)
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
    config: &Fail2BanConfig,
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
    jail.ban_counts.insert(counter_key, next_ban_count);

    let duration_ms = compute_ban_duration_ms(&jail.config, next_ban_count);
    let expires_ms = duration_ms.map(|d| detection.ts_ms.saturating_add(d));

    run_jail_action(
        config,
        &jail.config,
        jail.config.action_ban.as_deref(),
        Some(&detection.ip),
        duration_ms,
        detection.line.as_deref(),
    )
    .await;

    let ban = ActiveBan {
        jail: jail.config.name.clone(),
        ip: detection.ip.clone(),
        banned_at_ms: detection.ts_ms,
        expires_ms,
        ban_count: next_ban_count,
        source: detection.source.clone(),
        reason: format!(
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
        ),
        fuzzy_risk: fuzzy_decision.as_ref().map(|decision| decision.risk),
        fuzzy_confidence: fuzzy_decision.as_ref().map(|decision| decision.confidence),
        fuzzy_signal: fuzzy_decision.as_ref().map(|decision| decision.signal),
        fuzzy_adjusted_retry: fuzzy_decision
            .as_ref()
            .map(|decision| decision.adjusted_retry),
        fuzzy_telemetry: fuzzy_decision
            .as_ref()
            .map(|decision| decision.telemetry.clone()),
    };

    if let Some(queue) = jail.failure_windows.get_mut(&detection.ip) {
        queue.clear();
    }
    jail.active_bans.insert(detection.ip.clone(), ban.clone());

    let advertisement_entry = BanAdvertisementEntry {
        ip: ban.ip.clone(),
        jail: ban.jail.clone(),
        expires_ms: ban.expires_ms,
        ban_count: ban.ban_count,
        last_ban_ms: ban.banned_at_ms,
    };
    intel_hub.update_local_ban(advertisement_entry).await;

    emit_ban_event(bus, storage, &ban, true, config.agent_id.as_str()).await;
}

fn evaluate_fuzzy_decision(
    jail: &mut JailRuntime,
    line: Option<&str>,
    detection: &Detection,
    attempts: u32,
    effective_retry: u32,
    remote_support: u32,
    config: &Fail2BanConfig,
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
        FAIL2BAN_FUZZY_EVENT_COUNTER.fetch_add(1, Ordering::Relaxed),
        format!("fail2ban::{}", jail.config.name),
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
    config: &Fail2BanConfig,
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
            if let Some(ban) = jail.active_bans.remove(&ip) {
                run_jail_action(
                    config,
                    &jail.config,
                    jail.config.action_unban.as_deref(),
                    Some(&ban.ip),
                    None,
                    None,
                )
                .await;
                intel_hub.remove_local_ban(&ban.jail, &ban.ip).await;
                emit_ban_event(bus, storage, &ban, false, agent_id).await;
            }
        }
    }
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
            "fail2ban_ban"
        } else {
            "fail2ban_unban"
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

fn compute_ban_duration_ms(config: &Fail2BanJailConfig, ban_count: u32) -> Option<u64> {
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
    config: &Fail2BanConfig,
    jail: &Fail2BanJailConfig,
    template: Option<&str>,
    ip: Option<&str>,
    ban_time_ms: Option<u64>,
    line: Option<&str>,
) {
    let Some(template) = template else {
        return;
    };
    if template.trim().is_empty() {
        return;
    }

    let mut command = template.to_string();
    command = command.replace("<jail>", &jail.name);
    command = command.replace("<ip>", ip.unwrap_or(""));
    command = command.replace(
        "<bantime>",
        &ban_time_ms
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-1".to_string()),
    );
    command = command.replace("<matches>", line.unwrap_or(""));

    let shell = if jail.shell.is_empty() {
        "/bin/sh"
    } else {
        jail.shell.as_str()
    };

    let use_sudo = config.use_sudo_for_actions && !is_running_as_root();

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
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped());

    match tokio::time::timeout(
        Duration::from_millis(jail.action_timeout_ms),
        process.output(),
    )
    .await
    {
        Ok(Ok(output)) => {
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                tracing::warn!(
                    jail = %jail.name,
                    use_sudo,
                    stderr=%stderr,
                    "fail2ban action command failed"
                );
                if use_sudo {
                    let lower = stderr.to_ascii_lowercase();
                    if lower.contains("password") || lower.contains("permission denied") {
                        tracing::warn!(
                            jail = %jail.name,
                            sudo_program = %config.sudo_program,
                            "fail2ban action likely failed due to missing sudo privileges"
                        );
                    }
                }
            }
        }
        Ok(Err(err)) => {
            tracing::warn!(
                jail = %jail.name,
                use_sudo,
                error = %err,
                "fail2ban action execution failed"
            );
        }
        Err(_) => {
            tracing::warn!(jail = %jail.name, "fail2ban action command timed out");
        }
    }
}

async fn load_state(path: &PathBuf) -> PersistedState {
    match tokio::fs::read_to_string(path).await {
        Ok(raw) => match serde_json::from_str::<PersistedState>(&raw) {
            Ok(state) => state,
            Err(err) => {
                tracing::warn!(path=%path.display(), error=%err, "failed to parse fail2ban state");
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
                tracing::warn!(path=%path.display(), error=%err, "failed to persist fail2ban state");
            }
        }
        Err(err) => {
            tracing::warn!(path=%path.display(), error=%err, "failed to serialize fail2ban state");
        }
    }
}

fn parse_fail2ban_filter_file(path: &Path) -> std::io::Result<(Vec<String>, Vec<String>)> {
    let raw = std::fs::read_to_string(path)?;
    let mut fail = Vec::new();
    let mut ignore = Vec::new();

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
            if key == "failregex" || key == "ignoreregex" {
                active_key = Some(key.clone());
                if !value.is_empty() {
                    if key == "failregex" {
                        fail.push(translate_fail2ban_regex(value));
                    } else {
                        ignore.push(translate_fail2ban_regex(value));
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
                    fail.push(translate_fail2ban_regex(trimmed));
                } else if key == "ignoreregex" {
                    ignore.push(translate_fail2ban_regex(trimmed));
                }
            }
        }
    }

    Ok((fail, ignore))
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

fn translate_fail2ban_regex(input: &str) -> String {
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

    unknown_tag_re().replace_all(&output, ".*").to_string()
}

fn normalize_ip(ip: &str) -> Option<String> {
    ip.trim()
        .parse::<IpAddr>()
        .ok()
        .map(|value| value.to_string())
}

fn unknown_tag_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"<[^>]+>").expect("unknown tag regex"))
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
