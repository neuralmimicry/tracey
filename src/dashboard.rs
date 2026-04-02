use crate::autoscaler::ContinuumAutoscalerSnapshot;
use crate::config::{Config, StatusConfig, StorageConfig};
use crate::event::{Event, EventKind, Severity, now_ms};
use crate::governance::GovernanceUpdate;
use crate::location::{AgentLocationSnapshot, infer_single_agent_location};
use crate::security::Action;
use crate::slurm::SlurmSnapshot;
use crate::storage::BanUpdateRecord;
use crate::swarm::Decision;
use crate::tracey_guard::TraceyGuardStatusSnapshot;
use crossterm::cursor;
use crossterm::event::{self, Event as CEvent, KeyCode, KeyEventKind};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::backend::CrosstermBackend;
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Sparkline, Table, Wrap};
use reqwest::blocking::Client;
use serde::Deserialize;
use serde_json::Value;
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};
use std::error::Error;
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

const DEFAULT_REFRESH_MS: u64 = 1_000;
const DEFAULT_TAIL_BYTES: usize = 512 * 1024;
const MAX_TAIL_LINES: usize = 700;
const HISTORY_POINTS: usize = 64;
const MAX_ACTIVITY_ROWS: usize = 10;
const MAX_PROCESS_ROWS: usize = 5;
const MAX_GPU_ROWS: usize = 4;
const MAX_DISK_ROWS: usize = 3;
const MAX_BAN_LINES: usize = 6;
const MAX_CLUSTER_PRESSURE: usize = 3;
const MIN_TUI_WIDTH: u16 = 120;
const MIN_TUI_HEIGHT: u16 = 33;

pub fn run_tracey_top(args: Vec<String>) -> Result<(), Box<dyn Error>> {
    run_dashboard(args, "tracey-top")
}

pub fn run_tracey_tui(args: Vec<String>) -> Result<(), Box<dyn Error>> {
    run_dashboard(strip_dashboard_flag(args), "tracey --tui")
}

fn run_dashboard(args: Vec<String>, invocation: &str) -> Result<(), Box<dyn Error>> {
    let config = Config::load();
    let mut options = TopOptions::parse(&args, &config)?;
    if options.show_help {
        print_help(&config, invocation);
        return Ok(());
    }

    let client = Client::builder()
        .timeout(Duration::from_millis(1_200))
        .build()?;
    resolve_attach_target(&mut options, &client);

    let mut app = TraceyTopApp::new(options);
    app.refresh(&client);

    let mut terminal = TerminalSession::enter()?;
    loop {
        terminal.draw(|frame| draw_ui(frame, &app))?;

        if event::poll(app.time_until_refresh())? {
            if let CEvent::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Release {
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Char('r') => app.refresh(&client),
                    KeyCode::Tab | KeyCode::Right => app.next_page(),
                    KeyCode::BackTab | KeyCode::Left => app.previous_page(),
                    KeyCode::Char('1') => app.set_page(DashboardPage::Overview),
                    KeyCode::Char('2') => app.set_page(DashboardPage::Locations),
                    _ => {}
                }
            }
        }

        if app.refresh_due() {
            app.refresh(&client);
        }
    }

    Ok(())
}

fn strip_dashboard_flag(args: Vec<String>) -> Vec<String> {
    let mut filtered = Vec::with_capacity(args.len());
    if let Some(program) = args.first() {
        filtered.push(program.clone());
    }
    filtered.extend(args.into_iter().skip(1).filter(|arg| arg != "--tui"));
    filtered
}

#[derive(Clone, Debug)]
struct TopOptions {
    status_url: String,
    log_path: Option<PathBuf>,
    refresh_interval: Duration,
    auth_token: Option<String>,
    tail_bytes: usize,
    show_help: bool,
    status_explicit: bool,
    log_path_explicit: bool,
    attach_label: Option<String>,
}

impl TopOptions {
    fn parse(args: &[String], config: &Config) -> Result<Self, Box<dyn Error>> {
        let mut status_url = default_status_url(config);
        let mut log_path = Some(config.storage.log_path.clone());
        let mut refresh_interval = Duration::from_millis(DEFAULT_REFRESH_MS);
        let mut auth_token = None;
        let mut tail_bytes = DEFAULT_TAIL_BYTES;
        let mut show_help = false;
        let mut status_explicit = false;
        let mut log_path_explicit = false;

        let mut idx = 1;
        while idx < args.len() {
            match args[idx].as_str() {
                "--status" => {
                    idx += 1;
                    let value = args.get(idx).ok_or("missing value for --status")?;
                    status_url = normalize_status_url(value);
                    status_explicit = true;
                }
                "--log-path" => {
                    idx += 1;
                    let value = args.get(idx).ok_or("missing value for --log-path")?;
                    log_path = Some(PathBuf::from(value));
                    log_path_explicit = true;
                }
                "--no-log" => {
                    log_path = None;
                    log_path_explicit = true;
                }
                "--refresh-ms" => {
                    idx += 1;
                    let value = args.get(idx).ok_or("missing value for --refresh-ms")?;
                    let millis = value.parse::<u64>()?;
                    refresh_interval = Duration::from_millis(millis.max(250));
                }
                "--bearer" => {
                    idx += 1;
                    let value = args.get(idx).ok_or("missing value for --bearer")?;
                    auth_token = Some(value.to_string());
                }
                "--tail-bytes" => {
                    idx += 1;
                    let value = args.get(idx).ok_or("missing value for --tail-bytes")?;
                    tail_bytes = value.parse::<usize>()?.max(16 * 1024);
                }
                "--help" | "-h" => {
                    show_help = true;
                }
                other => {
                    return Err(format!("unrecognized argument '{other}'").into());
                }
            }
            idx += 1;
        }

        Ok(Self {
            status_url,
            log_path,
            refresh_interval,
            auth_token,
            tail_bytes,
            show_help,
            status_explicit,
            log_path_explicit,
            attach_label: None,
        })
    }
}

#[derive(Clone, Debug)]
struct LocalAgentAttach {
    pid: u32,
    status_url: String,
    log_path: Option<PathBuf>,
    label: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
struct AttachConfigFile {
    status: AttachStatusConfigFile,
    storage: AttachStorageConfigFile,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
struct AttachStatusConfigFile {
    enabled: bool,
    listen_addr: Option<String>,
}

impl Default for AttachStatusConfigFile {
    fn default() -> Self {
        Self {
            enabled: true,
            listen_addr: None,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
struct AttachStorageConfigFile {
    log_path: Option<PathBuf>,
}

fn resolve_attach_target(options: &mut TopOptions, client: &Client) {
    if options.status_explicit && options.log_path_explicit {
        return;
    }

    let Some(local_agent) = detect_local_agent_attach(client, options.auth_token.as_deref()) else {
        return;
    };

    if !options.status_explicit {
        options.status_url = local_agent.status_url.clone();
    }
    if !options.log_path_explicit {
        options.log_path = local_agent.log_path.clone();
    }
    options.attach_label = Some(local_agent.label);
}

fn detect_local_agent_attach(
    client: &Client,
    auth_token: Option<&str>,
) -> Option<LocalAgentAttach> {
    let current_pid = std::process::id();
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing()
            .with_cmd(UpdateKind::OnlyIfNotSet)
            .with_cwd(UpdateKind::OnlyIfNotSet)
            .with_environ(UpdateKind::OnlyIfNotSet)
            .with_exe(UpdateKind::OnlyIfNotSet),
    );

    let mut candidates = Vec::new();
    for (pid, process) in system.processes() {
        let pid = pid.as_u32();
        if pid == current_pid {
            continue;
        }
        if !is_local_tracey_agent_process(process.name(), process.cmd()) {
            continue;
        }
        if let Some(candidate) = build_local_agent_attach(process, pid) {
            candidates.push(candidate);
        }
    }

    candidates.sort_by(|left, right| right.pid.cmp(&left.pid));
    candidates
        .into_iter()
        .find(|candidate| probe_status_endpoint(client, &candidate.status_url, auth_token))
}

fn is_local_tracey_agent_process(name: &std::ffi::OsStr, cmd: &[OsString]) -> bool {
    let name = name.to_string_lossy().to_ascii_lowercase();
    let cmd_parts: Vec<String> = cmd
        .iter()
        .map(|part| part.to_string_lossy().to_string())
        .collect();
    let first = cmd_parts
        .first()
        .map(|value| file_name_of(value))
        .unwrap_or_default();
    let is_tracey_binary = matches!(name.as_str(), "tracey" | "tracey-core")
        || matches!(first.as_str(), "tracey" | "tracey-core");

    if !is_tracey_binary {
        return false;
    }
    if cmd_parts
        .iter()
        .any(|arg| arg == "--tui" || arg == "sign-update")
    {
        return false;
    }
    if cmd_parts
        .iter()
        .any(|arg| matches!(arg.as_str(), "--version" | "-V" | "--supervisor"))
    {
        return false;
    }
    true
}

fn build_local_agent_attach(process: &sysinfo::Process, pid: u32) -> Option<LocalAgentAttach> {
    let cwd = process
        .cwd()
        .map(Path::to_path_buf)
        .or_else(|| read_proc_cwd(pid));
    let mut env_map = parse_process_environ(process.environ());
    if env_map.is_empty() {
        env_map = read_proc_environ(pid);
    }
    let attach_cfg = load_attach_config(&env_map, cwd.as_deref());
    if !attach_cfg.status.enabled {
        return None;
    }

    let listen_addr = attach_cfg
        .status
        .listen_addr
        .clone()
        .unwrap_or_else(|| StatusConfig::default().listen_addr);
    let status_url = normalize_status_url(&listen_addr);

    let log_path = resolve_agent_log_path(&env_map, &attach_cfg, cwd.as_deref());
    let display_cwd = cwd
        .as_ref()
        .map(|path| truncate(&path.display().to_string(), 22))
        .unwrap_or_else(|| "?".to_string());
    let label = format!("local agent pid {pid} {display_cwd}");

    Some(LocalAgentAttach {
        pid,
        status_url,
        log_path,
        label,
    })
}

fn parse_process_environ(values: &[OsString]) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for raw in values {
        let raw = raw.to_string_lossy();
        let Some((key, value)) = raw.split_once('=') else {
            continue;
        };
        map.insert(key.to_string(), value.to_string());
    }
    map
}

fn read_proc_cwd(pid: u32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/cwd")).ok()
}

fn read_proc_environ(pid: u32) -> HashMap<String, String> {
    let Ok(bytes) = std::fs::read(format!("/proc/{pid}/environ")) else {
        return HashMap::new();
    };

    let mut map = HashMap::new();
    for raw in bytes.split(|byte| *byte == b'\0') {
        if raw.is_empty() {
            continue;
        }
        let raw = String::from_utf8_lossy(raw);
        let Some((key, value)) = raw.split_once('=') else {
            continue;
        };
        map.insert(key.to_string(), value.to_string());
    }
    map
}

fn load_attach_config(env_map: &HashMap<String, String>, cwd: Option<&Path>) -> AttachConfigFile {
    let Some(raw_path) = env_map.get("TRACEY_CONFIG") else {
        return AttachConfigFile::default();
    };
    let path = resolve_process_path(PathBuf::from(raw_path), cwd);
    let Ok(body) = std::fs::read_to_string(&path) else {
        return AttachConfigFile::default();
    };
    serde_json::from_str::<AttachConfigFile>(&body).unwrap_or_default()
}

fn resolve_agent_log_path(
    env_map: &HashMap<String, String>,
    attach_cfg: &AttachConfigFile,
    cwd: Option<&Path>,
) -> Option<PathBuf> {
    let raw = env_map
        .get("TRACEY_STORAGE_PATH")
        .or_else(|| env_map.get("NM_STORAGE_PATH"))
        .map(PathBuf::from)
        .or_else(|| attach_cfg.storage.log_path.clone())
        .unwrap_or_else(|| StorageConfig::default().log_path);
    let path = resolve_process_path(raw, cwd);
    path.exists().then_some(path)
}

fn resolve_process_path(path: PathBuf, cwd: Option<&Path>) -> PathBuf {
    if path.is_absolute() {
        path
    } else if let Some(cwd) = cwd {
        cwd.join(path)
    } else {
        path
    }
}

fn probe_status_endpoint(client: &Client, status_url: &str, auth_token: Option<&str>) -> bool {
    let mut request = client.get(status_url);
    if let Some(token) = auth_token {
        request = request.bearer_auth(token);
    }
    match request.send() {
        Ok(response) => {
            response.status().is_success()
                || response.status() == reqwest::StatusCode::UNAUTHORIZED
                || response.status() == reqwest::StatusCode::FORBIDDEN
        }
        Err(_) => false,
    }
}

fn file_name_of(value: &str) -> String {
    Path::new(value)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(value)
        .to_ascii_lowercase()
}

fn print_help(config: &Config, invocation: &str) {
    println!(
        "{invocation}\n\nUsage:\n  {invocation} [--status <url>] [--bearer <token>] [--log-path <path> | --no-log]\n             [--refresh-ms <ms>] [--tail-bytes <bytes>]\n\nDefaults:\n  status url : {}\n  log path   : {}\n  refresh    : {}ms\n  tail bytes : {}\n\nNotes:\n  auto attach: prefers a reachable local tracey agent when --status is omitted\n  transport  : loopback targets default to http, other no-scheme targets default to https\n  header     : shows the active status transport as 🔒 https or 🔓 http\n  location   : page 2 renders the inferred cluster map and location evidence\n  minimum tty: {}x{}\n\nKeys:\n  q, Esc     quit\n  r          refresh immediately\n  Tab, ←/→   switch page\n  1 / 2      jump to overview or locations\n",
        default_status_url(config),
        config.storage.log_path.display(),
        DEFAULT_REFRESH_MS,
        DEFAULT_TAIL_BYTES,
        MIN_TUI_WIDTH,
        MIN_TUI_HEIGHT
    );
}

fn default_status_url(config: &Config) -> String {
    let raw = config
        .status
        .public_addr
        .as_deref()
        .unwrap_or(config.status.listen_addr.as_str());
    normalize_status_url(raw)
}

fn normalize_status_url(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('/');
    let (scheme, rest) =
        split_status_scheme(trimmed).unwrap_or((preferred_status_scheme(trimmed), trimmed));
    let rewritten = rewrite_unspecified_status_host(rest);

    let url = format!("{scheme}{rewritten}");
    if url.trim_end_matches('/').ends_with("/status") {
        url
    } else {
        format!("{}/status", url.trim_end_matches('/'))
    }
}

fn split_status_scheme(raw: &str) -> Option<(&'static str, &str)> {
    if let Some(value) = raw.strip_prefix("http://") {
        Some(("http://", value))
    } else if let Some(value) = raw.strip_prefix("https://") {
        Some(("https://", value))
    } else {
        None
    }
}

fn preferred_status_scheme(raw: &str) -> &'static str {
    if is_local_status_target(raw) {
        "http://"
    } else {
        "https://"
    }
}

fn is_local_status_target(raw: &str) -> bool {
    let authority = raw.split('/').next().unwrap_or(raw).trim();
    if authority.is_empty() {
        return false;
    }

    let host = status_authority_host(authority);
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }

    let host = host.trim_matches('[').trim_matches(']');
    host.parse::<IpAddr>()
        .map(|ip| ip.is_loopback() || ip.is_unspecified())
        .unwrap_or(false)
}

fn status_authority_host(authority: &str) -> &str {
    if let Some(host) = authority.strip_prefix('[') {
        return host.split(']').next().unwrap_or(host);
    }

    if authority.bytes().filter(|byte| *byte == b':').count() > 1 {
        authority
    } else {
        authority.split(':').next().unwrap_or(authority)
    }
}

fn rewrite_unspecified_status_host(rest: &str) -> String {
    if let Some(port) = rest.strip_prefix("0.0.0.0:") {
        format!("127.0.0.1:{port}")
    } else if rest == "0.0.0.0" {
        "127.0.0.1".to_string()
    } else if let Some(port) = rest.strip_prefix("[::]:") {
        format!("[::1]:{port}")
    } else if rest == "[::]" || rest == "::" {
        "[::1]".to_string()
    } else {
        rest.to_string()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StatusTransport {
    Secure,
    Insecure,
}

impl StatusTransport {
    fn from_url(url: &str) -> Self {
        if url.trim_start().starts_with("https://") {
            Self::Secure
        } else {
            Self::Insecure
        }
    }

    fn badge(self) -> &'static str {
        match self {
            Self::Secure => "🔒 https",
            Self::Insecure => "🔓 http",
        }
    }

    fn color(self, theme: Theme) -> Color {
        match self {
            Self::Secure => theme.good,
            Self::Insecure => theme.bad,
        }
    }
}

#[derive(Clone, Debug)]
struct TraceyTopApp {
    options: TopOptions,
    page: DashboardPage,
    status: Option<StatusSnapshot>,
    log_view: LogView,
    status_error: Option<String>,
    log_error: Option<String>,
    last_refresh: Instant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DashboardPage {
    Overview,
    Locations,
}

impl DashboardPage {
    fn next(self) -> Self {
        match self {
            Self::Overview => Self::Locations,
            Self::Locations => Self::Overview,
        }
    }

    fn previous(self) -> Self {
        self.next()
    }

    fn label(self) -> &'static str {
        match self {
            Self::Overview => "overview",
            Self::Locations => "locations",
        }
    }

    fn shortcut(self) -> &'static str {
        match self {
            Self::Overview => "1/2",
            Self::Locations => "2/2",
        }
    }
}

impl TraceyTopApp {
    fn new(options: TopOptions) -> Self {
        Self {
            last_refresh: Instant::now() - options.refresh_interval,
            options,
            page: DashboardPage::Overview,
            status: None,
            log_view: LogView::default(),
            status_error: None,
            log_error: None,
        }
    }

    fn refresh_due(&self) -> bool {
        self.last_refresh.elapsed() >= self.options.refresh_interval
    }

    fn time_until_refresh(&self) -> Duration {
        self.options
            .refresh_interval
            .saturating_sub(self.last_refresh.elapsed())
    }

    fn next_page(&mut self) {
        self.page = self.page.next();
    }

    fn previous_page(&mut self) {
        self.page = self.page.previous();
    }

    fn set_page(&mut self, page: DashboardPage) {
        self.page = page;
    }

    fn refresh(&mut self, client: &Client) {
        self.last_refresh = Instant::now();

        match fetch_status(client, &self.options) {
            Ok(status) => {
                self.status = Some(status);
                self.status_error = None;
            }
            Err(err) => {
                self.status_error = Some(err.to_string());
            }
        }

        if let Some(path) = &self.options.log_path {
            match read_log_view(path, self.options.tail_bytes) {
                Ok(log_view) => {
                    self.log_view = log_view;
                    self.log_error = None;
                }
                Err(err) => {
                    self.log_error = Some(err.to_string());
                }
            }
        } else {
            self.log_view = LogView::default();
            self.log_error = None;
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
struct StatusSnapshot {
    ts_ms: u64,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    status_addr: Option<String>,
    agent_id: String,
    #[serde(default)]
    agent_version: Option<String>,
    is_coordinator: bool,
    leader_rank: usize,
    leader_count: usize,
    #[serde(default)]
    proxy_agent_id: Option<String>,
    #[serde(default)]
    proxy_addr: Option<String>,
    #[serde(default)]
    proxy_latency_ms: Option<u64>,
    #[serde(default)]
    is_prometheus_exporter: bool,
    #[serde(default)]
    prometheus_exporter_agent_id: Option<String>,
    #[serde(default)]
    prometheus_exporter_addr: Option<String>,
    #[serde(default)]
    prometheus_exporter_latency_ms: Option<u64>,
    #[serde(default)]
    prometheus_exporter_bandwidth_mbps: Option<f64>,
    #[serde(default)]
    local_prometheus_probe_ready: Option<bool>,
    #[serde(default)]
    local_prometheus_latency_ms: Option<u64>,
    #[serde(default)]
    local_prometheus_bandwidth_mbps: Option<f64>,
    posture: String,
    decision_threshold: f64,
    active_response: bool,
    shutdown_enabled: bool,
    update_enabled: bool,
    telemetry_enabled: bool,
    discovery_enabled: bool,
    tracey_ban_local_bans: usize,
    tracey_ban_remote_bans: usize,
    tracey_ban_remote_agents: usize,
    #[serde(default)]
    tracey_ban_local_entries: Vec<String>,
    #[serde(default)]
    tracey_ban_remote_entries: Vec<String>,
    #[serde(default)]
    tracey_guard: Option<TraceyGuardStatusSnapshot>,
    #[serde(default)]
    slurm: Option<SlurmSnapshot>,
    #[serde(default)]
    continuum_autoscaler: Option<ContinuumAutoscalerSnapshot>,
    #[serde(default)]
    location: AgentLocationSnapshot,
    #[serde(default)]
    peer_locations: Vec<AgentLocationSnapshot>,
}

fn fetch_status(client: &Client, options: &TopOptions) -> Result<StatusSnapshot, Box<dyn Error>> {
    let mut request = client.get(&options.status_url);
    if let Some(token) = &options.auth_token {
        request = request.bearer_auth(token);
    }
    let response = request.send()?;
    if !response.status().is_success() {
        return Err(format!("status request failed with {}", response.status()).into());
    }
    Ok(response.json::<StatusSnapshot>()?)
}

#[derive(Clone, Debug, Default)]
struct LogView {
    cpu_history: Vec<u64>,
    mem_history: Vec<u64>,
    net_history: Vec<u64>,
    risk_history: Vec<u64>,
    last_cpu_pct: Option<f64>,
    last_mem_pct: Option<f64>,
    last_net_rx_bps: Option<f64>,
    last_net_tx_bps: Option<f64>,
    process_rows: Vec<ProcessRow>,
    gpu_rows: Vec<GpuRow>,
    disk_rows: Vec<DiskRow>,
    activity_rows: Vec<ActivityRow>,
    last_log_ts_ms: Option<u64>,
}

#[derive(Clone, Debug, Default)]
struct ProcessRow {
    pid: u32,
    name: String,
    cpu_pct: Option<f64>,
    mem_bytes: Option<f64>,
    io_bps: Option<f64>,
}

#[derive(Clone, Debug, Default)]
struct GpuRow {
    id: String,
    name: String,
    source: String,
    util_pct: Option<f64>,
    temp_c: Option<f64>,
    power_w: Option<f64>,
}

#[derive(Clone, Debug, Default)]
struct DiskRow {
    mount: String,
    used_ratio: Option<f64>,
    used_bytes: Option<f64>,
    total_bytes: Option<f64>,
}

#[derive(Clone, Debug)]
struct ActivityRow {
    ts_ms: u64,
    kind: &'static str,
    item: String,
    score: Option<f64>,
    detail: String,
    tone: Tone,
}

#[derive(Clone, Copy, Debug, Default)]
enum Tone {
    Good,
    Warn,
    Bad,
    Info,
    #[default]
    Neutral,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct RawLogRecord {
    #[serde(rename = "type")]
    record_type: String,
    payload: Value,
}

fn read_log_view(path: &Path, tail_bytes: usize) -> io::Result<LogView> {
    let lines = read_tail_lines(path, tail_bytes, MAX_TAIL_LINES)?;
    Ok(build_log_view(&lines))
}

fn read_tail_lines(path: &Path, tail_bytes: usize, max_lines: usize) -> io::Result<Vec<String>> {
    let mut file = File::open(path)?;
    let len = file.metadata()?.len();
    let start = len.saturating_sub(tail_bytes as u64);
    file.seek(SeekFrom::Start(start))?;

    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    let text = String::from_utf8_lossy(&buf);
    let mut lines: Vec<&str> = text.lines().collect();
    if start > 0 && !text.starts_with('\n') && !text.starts_with('\r') && !lines.is_empty() {
        lines.remove(0);
    }

    let mut selected = Vec::new();
    for line in lines.into_iter().rev().take(max_lines).rev() {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            selected.push(trimmed.to_string());
        }
    }
    Ok(selected)
}

fn build_log_view(lines: &[String]) -> LogView {
    let mut cpu_history = Vec::new();
    let mut mem_history = Vec::new();
    let mut risk_history = Vec::new();
    let mut net_by_ts: BTreeMap<u64, (f64, f64)> = BTreeMap::new();
    let mut processes: HashMap<u32, ProcessRow> = HashMap::new();
    let mut gpus: HashMap<String, GpuRow> = HashMap::new();
    let mut disks: HashMap<String, DiskRow> = HashMap::new();
    let mut activity_rows = Vec::new();
    let mut last_log_ts_ms = None;

    for line in lines {
        let Ok(raw) = serde_json::from_str::<RawLogRecord>(line) else {
            continue;
        };
        match raw.record_type.as_str() {
            "event" => {
                if let Ok(event) = serde_json::from_value::<Event>(raw.payload) {
                    last_log_ts_ms = max_u64(last_log_ts_ms, Some(event.ts_ms));
                    ingest_event(
                        &event,
                        &mut cpu_history,
                        &mut mem_history,
                        &mut net_by_ts,
                        &mut processes,
                        &mut gpus,
                        &mut disks,
                        &mut activity_rows,
                    );
                }
            }
            "decision" => {
                if let Ok(decision) = serde_json::from_value::<Decision>(raw.payload) {
                    last_log_ts_ms = max_u64(last_log_ts_ms, Some(decision.ts_ms));
                    push_history(
                        &mut risk_history,
                        (decision.mean_risk.clamp(0.0, 1.0) * 100.0) as u64,
                    );
                    activity_rows.push(ActivityRow {
                        ts_ms: decision.ts_ms,
                        kind: "DECISION",
                        item: format!(
                            "{} {}",
                            short_event_kind(decision.kind),
                            short_action(decision.action)
                        ),
                        score: Some(decision.mean_risk),
                        detail: truncate(
                            &format!(
                                "conf {:.2} quorum {}/{} {}",
                                decision.mean_confidence,
                                decision.quorum,
                                decision.agents,
                                decision.reason
                            ),
                            64,
                        ),
                        tone: tone_for_action(decision.action),
                    });
                }
            }
            "governance_update" => {
                if let Ok(update) = serde_json::from_value::<GovernanceUpdate>(raw.payload) {
                    last_log_ts_ms = max_u64(last_log_ts_ms, Some(update.ts_ms));
                    activity_rows.push(ActivityRow {
                        ts_ms: update.ts_ms,
                        kind: "POSTURE",
                        item: format!("{:?}", update.posture),
                        score: Some(update.support_ratio),
                        detail: truncate(
                            &format!("votes {} {}", update.total_votes, update.reason),
                            64,
                        ),
                        tone: posture_tone(&format!("{:?}", update.posture)),
                    });
                }
            }
            "ban_update" => {
                if let Ok(update) = serde_json::from_value::<BanUpdateRecord>(raw.payload) {
                    last_log_ts_ms = max_u64(last_log_ts_ms, Some(update.ts_ms));
                    let action = if update.banned { "ban" } else { "unban" };
                    activity_rows.push(ActivityRow {
                        ts_ms: update.ts_ms,
                        kind: "BAN",
                        item: format!("{} {}", action, update.ip),
                        score: update.fuzzy_risk,
                        detail: truncate(&format!("{} {}", update.jail, update.reason), 64),
                        tone: if update.banned { Tone::Bad } else { Tone::Good },
                    });
                }
            }
            "update_record" => {
                if let Ok(update) =
                    serde_json::from_value::<crate::update::UpdateRecord>(raw.payload)
                {
                    last_log_ts_ms = max_u64(last_log_ts_ms, Some(update.ts_ms));
                    activity_rows.push(ActivityRow {
                        ts_ms: update.ts_ms,
                        kind: "UPDATE",
                        item: update.status,
                        score: None,
                        detail: truncate(
                            &format!(
                                "{} {}",
                                update.version.unwrap_or_else(|| "unknown".to_string()),
                                update.detail
                            ),
                            64,
                        ),
                        tone: Tone::Info,
                    });
                }
            }
            _ => {}
        }
    }

    let mut net_history = Vec::new();
    for (_, (rx_bps, tx_bps)) in net_by_ts.iter().rev().take(HISTORY_POINTS).rev() {
        net_history.push((rx_bps + tx_bps).round() as u64);
    }
    let (last_net_rx_bps, last_net_tx_bps) = net_by_ts
        .iter()
        .last()
        .map(|(_, value)| (Some(value.0), Some(value.1)))
        .unwrap_or((None, None));

    activity_rows.sort_by(|left, right| right.ts_ms.cmp(&left.ts_ms));
    activity_rows.truncate(MAX_ACTIVITY_ROWS);

    let mut process_rows: Vec<ProcessRow> = processes.into_values().collect();
    process_rows.sort_by(compare_process_rows);
    process_rows.truncate(MAX_PROCESS_ROWS);

    let mut gpu_rows: Vec<GpuRow> = gpus.into_values().collect();
    gpu_rows.sort_by(compare_gpu_rows);
    gpu_rows.truncate(MAX_GPU_ROWS);

    let mut disk_rows: Vec<DiskRow> = disks.into_values().collect();
    disk_rows.sort_by(compare_disk_rows);
    disk_rows.truncate(MAX_DISK_ROWS);

    LogView {
        last_cpu_pct: cpu_history.last().copied().map(|value| value as f64),
        last_mem_pct: mem_history.last().copied().map(|value| value as f64),
        cpu_history,
        mem_history,
        net_history,
        risk_history,
        last_net_rx_bps,
        last_net_tx_bps,
        process_rows,
        gpu_rows,
        disk_rows,
        activity_rows,
        last_log_ts_ms,
    }
}

#[allow(clippy::too_many_arguments)]
fn ingest_event(
    event: &Event,
    cpu_history: &mut Vec<u64>,
    mem_history: &mut Vec<u64>,
    net_by_ts: &mut BTreeMap<u64, (f64, f64)>,
    processes: &mut HashMap<u32, ProcessRow>,
    gpus: &mut HashMap<String, GpuRow>,
    disks: &mut HashMap<String, DiskRow>,
    activity_rows: &mut Vec<ActivityRow>,
) {
    if event.source == "embedded" {
        ingest_embedded_event(
            event,
            cpu_history,
            mem_history,
            net_by_ts,
            processes,
            gpus,
            disks,
        );
        return;
    }

    if event.severity == Severity::Low && event.kind == EventKind::SystemMetric {
        return;
    }

    let metric = event.attributes.get("metric").cloned().unwrap_or_default();
    let mut detail_parts = Vec::new();
    for key in [
        "process", "iface", "device", "mount", "gpu_id", "user", "action", "reason", "state",
    ] {
        if let Some(value) = event.attributes.get(key) {
            detail_parts.push(format!("{key}={value}"));
        }
    }
    if detail_parts.is_empty() {
        if let Some(value) = event.attributes.get("value") {
            detail_parts.push(format!("value={value}"));
        }
    }

    let item = if metric.is_empty() {
        event.source.clone()
    } else {
        format!("{} {}", event.source, metric)
    };

    activity_rows.push(ActivityRow {
        ts_ms: event.ts_ms,
        kind: "EVENT",
        item: truncate(&item, 28),
        score: Some(event.signal),
        detail: truncate(&detail_parts.join(" "), 64),
        tone: tone_for_severity(event.severity),
    });
}

fn ingest_embedded_event(
    event: &Event,
    cpu_history: &mut Vec<u64>,
    mem_history: &mut Vec<u64>,
    net_by_ts: &mut BTreeMap<u64, (f64, f64)>,
    processes: &mut HashMap<u32, ProcessRow>,
    gpus: &mut HashMap<String, GpuRow>,
    disks: &mut HashMap<String, DiskRow>,
) {
    let metric = event
        .attributes
        .get("metric")
        .map(String::as_str)
        .unwrap_or("");
    let value = parse_attr_f64(event, "value");
    match metric {
        "cpu_usage" => {
            push_history(
                cpu_history,
                value.unwrap_or(event.signal * 100.0).round() as u64,
            );
        }
        "mem_used" => {
            push_history(
                mem_history,
                (event.signal.clamp(0.0, 1.0) * 100.0).round() as u64,
            );
        }
        "net_rx_bps" => {
            if let Some(value) = value {
                net_by_ts.entry(event.ts_ms).or_default().0 += value;
            }
        }
        "net_tx_bps" => {
            if let Some(value) = value {
                net_by_ts.entry(event.ts_ms).or_default().1 += value;
            }
        }
        "process_cpu_percent" => {
            if let Some(pid) = parse_attr_u32(event, "pid") {
                let row = processes.entry(pid).or_insert_with(|| ProcessRow {
                    pid,
                    name: event
                        .attributes
                        .get("process")
                        .cloned()
                        .unwrap_or_else(|| "unknown".to_string()),
                    ..ProcessRow::default()
                });
                row.cpu_pct = value;
                if let Some(name) = event.attributes.get("process") {
                    row.name = name.clone();
                }
            }
        }
        "process_mem_rss_bytes" => {
            if let Some(pid) = parse_attr_u32(event, "pid") {
                let row = processes.entry(pid).or_insert_with(|| ProcessRow {
                    pid,
                    name: event
                        .attributes
                        .get("process")
                        .cloned()
                        .unwrap_or_else(|| "unknown".to_string()),
                    ..ProcessRow::default()
                });
                row.mem_bytes = value;
                if let Some(name) = event.attributes.get("process") {
                    row.name = name.clone();
                }
            }
        }
        "process_io_bps" => {
            if let Some(pid) = parse_attr_u32(event, "pid") {
                let row = processes.entry(pid).or_insert_with(|| ProcessRow {
                    pid,
                    name: event
                        .attributes
                        .get("process")
                        .cloned()
                        .unwrap_or_else(|| "unknown".to_string()),
                    ..ProcessRow::default()
                });
                row.io_bps = value;
                if let Some(name) = event.attributes.get("process") {
                    row.name = name.clone();
                }
            }
        }
        "gpu_util_percent" | "gpu_temp_c" | "gpu_power_w" => {
            let gpu_id = event
                .attributes
                .get("gpu_id")
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            let row = gpus.entry(gpu_id.clone()).or_insert_with(|| GpuRow {
                id: gpu_id.clone(),
                name: event
                    .attributes
                    .get("gpu_name")
                    .cloned()
                    .unwrap_or_else(|| "gpu".to_string()),
                source: event
                    .attributes
                    .get("gpu_source")
                    .cloned()
                    .unwrap_or_else(|| "embedded".to_string()),
                ..GpuRow::default()
            });
            if let Some(name) = event.attributes.get("gpu_name") {
                row.name = name.clone();
            }
            if let Some(source) = event.attributes.get("gpu_source") {
                row.source = source.clone();
            }
            match metric {
                "gpu_util_percent" => row.util_pct = value,
                "gpu_temp_c" => row.temp_c = value,
                "gpu_power_w" => row.power_w = value,
                _ => {}
            }
        }
        "disk_used_bytes" | "disk_total_bytes" => {
            let mount = event
                .attributes
                .get("mount")
                .cloned()
                .unwrap_or_else(|| "/".to_string());
            let row = disks.entry(mount.clone()).or_insert_with(|| DiskRow {
                mount: mount.clone(),
                ..DiskRow::default()
            });
            if metric == "disk_used_bytes" {
                row.used_bytes = value;
                row.used_ratio = parse_attr_f64(event, "used_ratio").or(Some(event.signal));
            } else {
                row.total_bytes = value;
            }
        }
        _ => {}
    }
}

fn parse_attr_f64(event: &Event, key: &str) -> Option<f64> {
    event
        .attributes
        .get(key)
        .and_then(|value| value.parse::<f64>().ok())
}

fn parse_attr_u32(event: &Event, key: &str) -> Option<u32> {
    event
        .attributes
        .get(key)
        .and_then(|value| value.parse::<u32>().ok())
}

fn push_history(values: &mut Vec<u64>, value: u64) {
    values.push(value);
    if values.len() > HISTORY_POINTS {
        let drop = values.len() - HISTORY_POINTS;
        values.drain(0..drop);
    }
}

fn max_u64(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    }
}

fn compare_process_rows(left: &ProcessRow, right: &ProcessRow) -> Ordering {
    cmp_opt_desc(right.cpu_pct, left.cpu_pct)
        .then_with(|| cmp_opt_desc(right.mem_bytes, left.mem_bytes))
        .then_with(|| cmp_opt_desc(right.io_bps, left.io_bps))
        .then_with(|| left.name.cmp(&right.name))
}

fn compare_gpu_rows(left: &GpuRow, right: &GpuRow) -> Ordering {
    cmp_opt_desc(right.util_pct, left.util_pct)
        .then_with(|| cmp_opt_desc(right.temp_c, left.temp_c))
        .then_with(|| left.id.cmp(&right.id))
}

fn compare_disk_rows(left: &DiskRow, right: &DiskRow) -> Ordering {
    cmp_opt_desc(right.used_ratio, left.used_ratio)
        .then_with(|| cmp_opt_desc(right.used_bytes, left.used_bytes))
        .then_with(|| left.mount.cmp(&right.mount))
}

fn cmp_opt_desc(left: Option<f64>, right: Option<f64>) -> Ordering {
    match (left, right) {
        (Some(left), Some(right)) => left.partial_cmp(&right).unwrap_or(Ordering::Equal),
        (Some(_), None) => Ordering::Greater,
        (None, Some(_)) => Ordering::Less,
        (None, None) => Ordering::Equal,
    }
}

fn short_event_kind(kind: EventKind) -> &'static str {
    match kind {
        EventKind::SystemMetric => "metric",
        EventKind::NetworkFlow => "net",
        EventKind::UserAction => "user",
        EventKind::AutomationAction => "auto",
        EventKind::Observability => "obs",
    }
}

fn short_action(action: Action) -> &'static str {
    match action {
        Action::Monitor => "monitor",
        Action::Alert => "alert",
        Action::Throttle => "throttle",
        Action::Isolate => "isolate",
        Action::Shutdown => "shutdown",
    }
}

fn tone_for_action(action: Action) -> Tone {
    match action {
        Action::Monitor => Tone::Neutral,
        Action::Alert => Tone::Warn,
        Action::Throttle | Action::Isolate | Action::Shutdown => Tone::Bad,
    }
}

fn tone_for_severity(severity: Severity) -> Tone {
    match severity {
        Severity::Low => Tone::Neutral,
        Severity::Medium => Tone::Info,
        Severity::High => Tone::Warn,
        Severity::Critical => Tone::Bad,
    }
}

fn posture_tone(posture: &str) -> Tone {
    match posture {
        "Relaxed" | "healthy" => Tone::Good,
        "Balanced" => Tone::Info,
        "Strict" | "degraded" => Tone::Warn,
        "Lockdown" | "offline" => Tone::Bad,
        _ => Tone::Neutral,
    }
}

#[derive(Clone, Copy)]
struct Theme {
    frame: Color,
    accent: Color,
    good: Color,
    warn: Color,
    bad: Color,
    muted: Color,
    text: Color,
    cpu: Color,
    mem: Color,
    net: Color,
    risk: Color,
}

impl Default for Theme {
    fn default() -> Self {
        Self {
            frame: Color::Rgb(70, 90, 110),
            accent: Color::Rgb(102, 217, 239),
            good: Color::Rgb(166, 226, 46),
            warn: Color::Rgb(253, 151, 31),
            bad: Color::Rgb(249, 38, 114),
            muted: Color::Rgb(117, 113, 94),
            text: Color::Rgb(248, 248, 242),
            cpu: Color::Rgb(166, 226, 46),
            mem: Color::Rgb(230, 219, 116),
            net: Color::Rgb(174, 129, 255),
            risk: Color::Rgb(249, 38, 114),
        }
    }
}

struct TerminalSession {
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
}

impl TerminalSession {
    fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        crossterm::execute!(stdout, EnterAlternateScreen, cursor::Hide)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;
        terminal.clear()?;
        Ok(Self { terminal })
    }

    fn draw<F>(&mut self, render: F) -> io::Result<()>
    where
        F: FnOnce(&mut Frame),
    {
        self.terminal.draw(render).map(|_| ())
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = crossterm::execute!(io::stdout(), LeaveAlternateScreen, cursor::Show);
        let _ = self.terminal.show_cursor();
    }
}

fn draw_ui(frame: &mut Frame, app: &TraceyTopApp) {
    let theme = Theme::default();
    let area = frame.area();
    if area.width < MIN_TUI_WIDTH || area.height < MIN_TUI_HEIGHT {
        render_resize_notice(frame, area, theme);
        return;
    }

    match app.page {
        DashboardPage::Overview => render_overview_page(frame, area, app, theme),
        DashboardPage::Locations => render_locations_page(frame, area, app, theme),
    }
}

fn render_overview_page(frame: &mut Frame, area: Rect, app: &TraceyTopApp, theme: Theme) {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Length(10),
            Constraint::Length(9),
            Constraint::Min(9),
            Constraint::Length(1),
        ])
        .split(area);

    render_header(frame, outer[0], app, theme);

    let top = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(28),
            Constraint::Percentage(32),
            Constraint::Percentage(40),
        ])
        .split(outer[1]);
    render_governance_panel(frame, top[0], app, theme);
    render_coordination_panel(frame, top[1], app, theme);
    render_guard_panel(frame, top[2], app, theme);

    let middle = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(outer[2]);
    render_signals_panel(frame, middle[0], app, theme);
    render_activity_panel(frame, middle[1], app, theme);

    let bottom = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(28),
            Constraint::Percentage(32),
            Constraint::Percentage(40),
        ])
        .split(outer[3]);
    render_ban_panel(frame, bottom[0], app, theme);
    render_cluster_panel(frame, bottom[1], app, theme);
    render_workload_panel(frame, bottom[2], app, theme);

    render_footer(frame, outer[4], app, theme);
}

fn render_locations_page(frame: &mut Frame, area: Rect, app: &TraceyTopApp, theme: Theme) {
    let banner_height = u16::from(location_inference_banner_text(app).is_some());
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Length(banner_height),
            Constraint::Length(9),
            Constraint::Min(18),
            Constraint::Length(1),
        ])
        .split(area);

    render_header(frame, outer[0], app, theme);
    render_location_inference_banner(frame, outer[1], app, theme);

    let summary = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
        .split(outer[2]);
    render_local_location_panel(frame, summary[0], app, theme);
    render_location_summary_panel(frame, summary[1], app, theme);
    render_location_map_panel(frame, outer[3], app, theme);
    render_footer(frame, outer[4], app, theme);
}

fn effective_self_location(app: &TraceyTopApp) -> Option<AgentLocationSnapshot> {
    let status = app.status.as_ref()?;
    if !status.location.agent_id.trim().is_empty() {
        let mut location = status.location.clone();
        if location.agent_version.is_none() {
            location.agent_version = status.agent_version.clone();
        }
        return Some(location);
    }

    let status_addr = status
        .status_addr
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .or(Some(app.options.status_url.as_str()));
    let mut location =
        infer_single_agent_location(&status.agent_id, status_addr, status.is_coordinator);
    location.agent_version = status.agent_version.clone();
    Some(location)
}

fn location_inference_banner_text(app: &TraceyTopApp) -> Option<&'static str> {
    app.status
        .as_ref()
        .filter(|status| status.location.agent_id.trim().is_empty())
        .map(|_| {
            "client-side fallback inference active: self location synthesized from target url and local runtime hints"
        })
}

fn effective_peer_locations(
    app: &TraceyTopApp,
    self_location: Option<&AgentLocationSnapshot>,
) -> Vec<AgentLocationSnapshot> {
    let Some(status) = &app.status else {
        return Vec::new();
    };

    let mut peers = status.peer_locations.clone();
    if let Some(self_location) = self_location {
        peers.retain(|peer| peer.agent_id != self_location.agent_id);
    }
    peers
}

fn render_location_inference_banner(
    frame: &mut Frame,
    area: Rect,
    app: &TraceyTopApp,
    theme: Theme,
) {
    let Some(text) = location_inference_banner_text(app) else {
        return;
    };
    let line = Line::from(vec![
        Span::styled(
            " FALLBACK ",
            Style::default()
                .fg(Color::Black)
                .bg(theme.warn)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" {text}"),
            Style::default().fg(theme.warn).add_modifier(Modifier::BOLD),
        ),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

fn render_header(frame: &mut Frame, area: Rect, app: &TraceyTopApp, theme: Theme) {
    let block = panel_block(" tracey tui ", theme);
    let lines = build_header_lines(app, theme);
    frame.render_widget(
        Paragraph::new(lines).block(block).wrap(Wrap { trim: true }),
        area,
    );
}

fn build_header_lines<'a>(app: &'a TraceyTopApp, theme: Theme) -> Vec<Line<'a>> {
    let status = app.status.as_ref();
    let agent = status
        .map(|value| value.agent_id.as_str())
        .unwrap_or("status-unavailable");
    let version = status
        .and_then(|value| value.agent_version.as_deref())
        .filter(|value| !value.trim().is_empty())
        .map(|value| format!("v{value}"))
        .unwrap_or_else(|| "v?".to_string());
    let posture = status
        .map(|value| value.posture.as_str())
        .unwrap_or("offline");
    let health = status
        .and_then(|value| value.status.as_deref())
        .unwrap_or("offline");
    let role = if status.is_some_and(|value| value.is_coordinator) {
        "coordinator"
    } else {
        "follower"
    };
    let log_target = app
        .options
        .log_path
        .as_ref()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "disabled".to_string());
    let attach = app
        .options
        .attach_label
        .as_deref()
        .unwrap_or("configured target");
    let transport = StatusTransport::from_url(&app.options.status_url);

    vec![
        Line::from(vec![
            Span::styled("agent ", Style::default().fg(theme.muted)),
            Span::styled(
                agent,
                Style::default()
                    .fg(theme.accent)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled(version, Style::default().fg(theme.muted)),
            Span::raw("  "),
            Span::styled("posture ", Style::default().fg(theme.muted)),
            Span::styled(
                posture,
                Style::default().fg(tone_color(posture_tone(posture), theme)),
            ),
            Span::raw("  "),
            Span::styled("health ", Style::default().fg(theme.muted)),
            Span::styled(
                health,
                Style::default().fg(tone_color(posture_tone(health), theme)),
            ),
            Span::raw("  "),
            Span::styled("role ", Style::default().fg(theme.muted)),
            Span::styled(role, Style::default().fg(theme.text)),
        ]),
        Line::from(vec![
            Span::styled("page ", Style::default().fg(theme.muted)),
            Span::raw(app.page.label()),
            Span::raw("  "),
            Span::styled("conn ", Style::default().fg(theme.muted)),
            Span::styled(
                transport.badge(),
                Style::default()
                    .fg(transport.color(theme))
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled("status ", Style::default().fg(theme.muted)),
            Span::raw(truncate(&app.options.status_url, 28)),
            Span::raw("  "),
            Span::styled("attach ", Style::default().fg(theme.muted)),
            Span::raw(truncate(attach, 18)),
            Span::raw("  "),
            Span::styled("log ", Style::default().fg(theme.muted)),
            Span::raw(truncate(&log_target, 18)),
            Span::raw("  "),
            Span::styled("refresh ", Style::default().fg(theme.muted)),
            Span::raw(format!("{}ms", app.options.refresh_interval.as_millis())),
        ]),
    ]
}

fn render_resize_notice(frame: &mut Frame, area: Rect, theme: Theme) {
    let lines = vec![
        Line::from(Span::styled(
            "Window too small for the Tracey dashboard.",
            Style::default().fg(theme.bad).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(format!("Current size : {} x {}", area.width, area.height)),
        Line::from(format!(
            "Minimum size : {} x {}",
            MIN_TUI_WIDTH, MIN_TUI_HEIGHT
        )),
        Line::from(""),
        Line::from(
            "Enlarge the terminal. The dashboard will redraw automatically once the window is large enough.",
        ),
        Line::from("Press q or Esc to quit."),
    ];
    let paragraph = Paragraph::new(lines)
        .block(panel_block(" tracey tui ", theme))
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: true });
    frame.render_widget(paragraph, area);
}

fn render_governance_panel(frame: &mut Frame, area: Rect, app: &TraceyTopApp, theme: Theme) {
    let block = panel_block(" governance ", theme);
    let mut lines = Vec::new();
    if let Some(status) = &app.status {
        lines.push(kv_line(
            theme,
            "posture",
            &status.posture,
            Some(posture_tone(&status.posture)),
        ));
        lines.push(kv_line(
            theme,
            "threshold",
            &format!("{:.2}", status.decision_threshold),
            None,
        ));
        lines.push(kv_line(
            theme,
            "response",
            bool_word(status.active_response),
            Some(if status.active_response {
                Tone::Warn
            } else {
                Tone::Neutral
            }),
        ));
        lines.push(kv_line(
            theme,
            "shutdown",
            bool_word(status.shutdown_enabled),
            Some(if status.shutdown_enabled {
                Tone::Bad
            } else {
                Tone::Neutral
            }),
        ));
        lines.push(kv_line(
            theme,
            "update",
            bool_word(status.update_enabled),
            Some(if status.update_enabled {
                Tone::Good
            } else {
                Tone::Warn
            }),
        ));
        lines.push(kv_line(
            theme,
            "telemetry",
            bool_word(status.telemetry_enabled),
            Some(if status.telemetry_enabled {
                Tone::Good
            } else {
                Tone::Neutral
            }),
        ));
        lines.push(kv_line(
            theme,
            "discovery",
            bool_word(status.discovery_enabled),
            Some(if status.discovery_enabled {
                Tone::Good
            } else {
                Tone::Neutral
            }),
        ));
        lines.push(kv_line(
            theme,
            "snapshot age",
            &human_age_ms(now_ms().saturating_sub(status.ts_ms)),
            None,
        ));
    } else {
        lines.push(error_line(
            theme,
            app.status_error.as_deref().unwrap_or("status offline"),
        ));
    }
    frame.render_widget(
        Paragraph::new(lines).block(block).wrap(Wrap { trim: true }),
        area,
    );
}

fn render_coordination_panel(frame: &mut Frame, area: Rect, app: &TraceyTopApp, theme: Theme) {
    let block = panel_block(" coordination ", theme);
    let mut lines = Vec::new();
    if let Some(status) = &app.status {
        let role = if status.is_coordinator {
            format!(
                "leader {}/{}",
                status.leader_rank.saturating_add(1),
                status.leader_count
            )
        } else {
            format!(
                "follower {}/{}",
                status.leader_rank.saturating_add(1),
                status.leader_count
            )
        };
        lines.push(kv_line(theme, "role", &role, Some(Tone::Info)));
        lines.push(kv_line(
            theme,
            "proxy",
            &format!(
                "{} {}",
                status.proxy_agent_id.as_deref().unwrap_or("none"),
                status
                    .proxy_latency_ms
                    .map(|value| format!("({})", human_age_ms(value)))
                    .unwrap_or_default()
            ),
            None,
        ));
        lines.push(kv_line(
            theme,
            "exporter",
            &format!(
                "{} {} {}",
                status.prometheus_exporter_agent_id.as_deref().unwrap_or(
                    if status.is_prometheus_exporter {
                        "self"
                    } else {
                        "none"
                    }
                ),
                status
                    .prometheus_exporter_latency_ms
                    .map(human_age_ms)
                    .unwrap_or_default(),
                status
                    .prometheus_exporter_bandwidth_mbps
                    .map(format_mbps)
                    .unwrap_or_default()
            ),
            Some(if status.is_prometheus_exporter {
                Tone::Good
            } else {
                Tone::Neutral
            }),
        ));
        lines.push(kv_line(
            theme,
            "probe",
            &format!(
                "{} {} {}",
                status
                    .local_prometheus_probe_ready
                    .map(bool_word)
                    .unwrap_or("n/a"),
                status
                    .local_prometheus_latency_ms
                    .map(human_age_ms)
                    .unwrap_or_else(|| "".to_string()),
                status
                    .local_prometheus_bandwidth_mbps
                    .map(format_mbps)
                    .unwrap_or_else(|| "".to_string())
            )
            .trim()
            .to_string(),
            Some(if status.local_prometheus_probe_ready == Some(true) {
                Tone::Good
            } else {
                Tone::Neutral
            }),
        ));
        if let Some(addr) = &status.proxy_addr {
            lines.push(kv_line(theme, "proxy addr", &truncate(addr, 28), None));
        }
        if let Some(addr) = &status.prometheus_exporter_addr {
            lines.push(kv_line(theme, "exp addr", &truncate(addr, 28), None));
        }
    } else {
        lines.push(error_line(
            theme,
            app.status_error.as_deref().unwrap_or("status offline"),
        ));
    }
    frame.render_widget(
        Paragraph::new(lines).block(block).wrap(Wrap { trim: true }),
        area,
    );
}

fn render_guard_panel(frame: &mut Frame, area: Rect, app: &TraceyTopApp, theme: Theme) {
    let block = panel_block(" tracey guard ", theme);
    let mut lines = Vec::new();
    if let Some(guard) = app
        .status
        .as_ref()
        .and_then(|status| status.tracey_guard.as_ref())
    {
        lines.push(kv_line(
            theme,
            "mode",
            &format!(
                "{} deep={} budget={:.1}%",
                bool_word(guard.summary.enabled),
                bool_word(guard.summary.deep_dive),
                guard.summary.overhead_budget_pct
            ),
            Some(if guard.summary.enabled {
                Tone::Good
            } else {
                Tone::Warn
            }),
        ));
        lines.push(kv_line(
            theme,
            "devices",
            &format!(
                "{} total / {} healthy / {} suspect / {} quarantine",
                guard.summary.total_devices,
                guard.summary.healthy_devices,
                guard.summary.suspect_devices,
                guard.summary.quarantined_devices
            ),
            None,
        ));
        lines.push(kv_line(
            theme,
            "runtime",
            &format!(
                "exec={} fail={} err={} timeout={}",
                guard.summary.total_executions,
                guard.summary.total_failures,
                guard.summary.total_errors,
                guard.summary.total_timeouts
            ),
            None,
        ));
        lines.push(kv_line(
            theme,
            "fault intel",
            &format!(
                "local={} remote={} support={}",
                guard.recent_faults.len(),
                guard.remote_faults.len(),
                guard.summary.remote_fault_support
            ),
            Some(if !guard.recent_faults.is_empty() {
                Tone::Warn
            } else {
                Tone::Good
            }),
        ));

        let mut probe_rows: Vec<_> = guard.summary.probes.iter().collect();
        probe_rows.sort_by(|left, right| right.1.executions.cmp(&left.1.executions));
        for (name, counters) in probe_rows.into_iter().take(2) {
            lines.push(kv_line(
                theme,
                &truncate(name, 10),
                &format!(
                    "pass={} fail={} risk={:.2}",
                    counters.pass, counters.fail, counters.last_risk
                ),
                Some(if counters.fail > 0 {
                    Tone::Warn
                } else {
                    Tone::Good
                }),
            ));
        }

        for gpu in guard.gpu_health.iter().take(2) {
            lines.push(kv_line(
                theme,
                &truncate(&gpu.gpu_id, 10),
                &format!(
                    "{:?} rel={:.2} fail={} {}",
                    gpu.state,
                    gpu.reliability_score,
                    gpu.consecutive_failures,
                    truncate(&gpu.last_reason, 18)
                ),
                Some(match format!("{:?}", gpu.state).as_str() {
                    "Healthy" => Tone::Good,
                    "Suspect" => Tone::Warn,
                    _ => Tone::Bad,
                }),
            ));
        }
    } else {
        lines.push(error_line(
            theme,
            app.status_error
                .as_deref()
                .unwrap_or("tracey guard snapshot unavailable"),
        ));
    }
    frame.render_widget(
        Paragraph::new(lines).block(block).wrap(Wrap { trim: true }),
        area,
    );
}

fn render_signals_panel(frame: &mut Frame, area: Rect, app: &TraceyTopApp, theme: Theme) {
    let block = panel_block(" signal history ", theme);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if app.log_view.cpu_history.is_empty()
        && app.log_view.mem_history.is_empty()
        && app.log_view.net_history.is_empty()
        && app.log_view.risk_history.is_empty()
    {
        let message = if let Some(error) = &app.log_error {
            format!("log unavailable: {error}")
        } else if app.options.log_path.is_none() {
            "log tail disabled".to_string()
        } else {
            "waiting for embedded metrics in the storage log".to_string()
        };
        frame.render_widget(
            Paragraph::new(message).style(Style::default().fg(theme.muted)),
            inner,
        );
        return;
    }

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Length(2),
            Constraint::Length(2),
            Constraint::Length(2),
        ])
        .split(inner);

    render_signal_row(
        frame,
        rows[0],
        theme,
        "cpu",
        &app.log_view.cpu_history,
        app.log_view
            .last_cpu_pct
            .map(|value| format!("{value:.0}%")),
        theme.cpu,
    );
    render_signal_row(
        frame,
        rows[1],
        theme,
        "mem",
        &app.log_view.mem_history,
        app.log_view
            .last_mem_pct
            .map(|value| format!("{value:.0}%")),
        theme.mem,
    );
    render_signal_row(
        frame,
        rows[2],
        theme,
        "net",
        &app.log_view.net_history,
        Some(format!(
            "{} / {}",
            app.log_view
                .last_net_rx_bps
                .map(format_bps)
                .unwrap_or_else(|| "n/a".to_string()),
            app.log_view
                .last_net_tx_bps
                .map(format_bps)
                .unwrap_or_else(|| "n/a".to_string())
        )),
        theme.net,
    );
    render_signal_row(
        frame,
        rows[3],
        theme,
        "risk",
        &app.log_view.risk_history,
        app.log_view
            .risk_history
            .last()
            .map(|value| format!("{:.2}", (*value as f64) / 100.0)),
        theme.risk,
    );
}

fn render_signal_row(
    frame: &mut Frame,
    area: Rect,
    theme: Theme,
    label: &str,
    history: &[u64],
    value: Option<String>,
    color: Color,
) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(6),
            Constraint::Min(10),
            Constraint::Length(20),
        ])
        .split(area);

    frame.render_widget(
        Paragraph::new(label).style(Style::default().fg(theme.muted)),
        chunks[0],
    );
    frame.render_widget(
        Sparkline::default()
            .data(history)
            .style(Style::default().fg(color)),
        chunks[1],
    );
    frame.render_widget(
        Paragraph::new(value.unwrap_or_else(|| "n/a".to_string()))
            .alignment(Alignment::Right)
            .style(Style::default().fg(color)),
        chunks[2],
    );
}

fn render_activity_panel(frame: &mut Frame, area: Rect, app: &TraceyTopApp, theme: Theme) {
    let block = panel_block(" activity ", theme);
    if app.log_view.activity_rows.is_empty() {
        let message = if let Some(error) = &app.log_error {
            format!("activity unavailable: {error}")
        } else {
            "waiting for recent decisions and events".to_string()
        };
        frame.render_widget(
            Paragraph::new(message)
                .block(block)
                .style(Style::default().fg(theme.muted)),
            area,
        );
        return;
    }

    let header = Row::new(vec!["age", "type", "item", "score", "detail"]).style(
        Style::default()
            .fg(theme.accent)
            .add_modifier(Modifier::BOLD),
    );
    let rows = app.log_view.activity_rows.iter().map(|row| {
        let score = row
            .score
            .map(|value| format!("{value:.2}"))
            .unwrap_or_else(|| "-".to_string());
        Row::new(vec![
            Cell::from(human_age_ms(now_ms().saturating_sub(row.ts_ms))),
            Cell::from(row.kind),
            Cell::from(truncate(&row.item, 20)),
            Cell::from(score),
            Cell::from(truncate(&row.detail, 50)),
        ])
        .style(Style::default().fg(tone_color(row.tone, theme)))
    });

    let table = Table::new(
        rows,
        [
            Constraint::Length(7),
            Constraint::Length(9),
            Constraint::Length(20),
            Constraint::Length(7),
            Constraint::Min(12),
        ],
    )
    .header(header)
    .block(block)
    .column_spacing(1);
    frame.render_widget(table, area);
}

fn render_ban_panel(frame: &mut Frame, area: Rect, app: &TraceyTopApp, theme: Theme) {
    let block = panel_block(" ban intel ", theme);
    let mut lines = Vec::new();
    if let Some(status) = &app.status {
        lines.push(kv_line(
            theme,
            "counts",
            &format!(
                "local={} remote={} agents={}",
                status.tracey_ban_local_bans,
                status.tracey_ban_remote_bans,
                status.tracey_ban_remote_agents
            ),
            Some(
                if status.tracey_ban_local_bans > 0 || status.tracey_ban_remote_bans > 0 {
                    Tone::Warn
                } else {
                    Tone::Good
                },
            ),
        ));
        let mut shown = 0usize;
        for entry in status
            .tracey_ban_local_entries
            .iter()
            .take(MAX_BAN_LINES / 2)
        {
            lines.push(kv_line(
                theme,
                "local",
                &truncate(entry, 32),
                Some(Tone::Bad),
            ));
            shown += 1;
        }
        for entry in status
            .tracey_ban_remote_entries
            .iter()
            .take(MAX_BAN_LINES.saturating_sub(shown))
        {
            lines.push(kv_line(
                theme,
                "remote",
                &truncate(entry, 32),
                Some(Tone::Warn),
            ));
        }
    } else {
        lines.push(error_line(
            theme,
            app.status_error.as_deref().unwrap_or("status offline"),
        ));
    }
    frame.render_widget(
        Paragraph::new(lines).block(block).wrap(Wrap { trim: true }),
        area,
    );
}

fn render_cluster_panel(frame: &mut Frame, area: Rect, app: &TraceyTopApp, theme: Theme) {
    let block = panel_block(" cluster / scale ", theme);
    let mut lines = Vec::new();
    if let Some(status) = &app.status {
        if let Some(slurm) = &status.slurm {
            lines.push(kv_line(
                theme,
                "slurm",
                &format!(
                    "{} {}",
                    slurm.mode,
                    slurm.cluster_name.as_deref().unwrap_or("cluster")
                ),
                Some(if slurm.controller_healthy {
                    Tone::Good
                } else {
                    Tone::Warn
                }),
            ));
            if !slurm.roles.is_empty() {
                lines.push(kv_line(theme, "roles", &slurm.roles.join(","), None));
            }
            lines.push(kv_line(
                theme,
                "nodes",
                &format!(
                    "{} total {} idle {} alloc {} down",
                    slurm.nodes_total, slurm.nodes_idle, slurm.nodes_allocated, slurm.nodes_down
                ),
                None,
            ));
            lines.push(kv_line(
                theme,
                "jobs",
                &format!(
                    "{} total {} pending {} running {} failed",
                    slurm.jobs_total, slurm.jobs_pending, slurm.jobs_running, slurm.jobs_failed
                ),
                None,
            ));
        }
        if let Some(autoscaler) = &status.continuum_autoscaler {
            lines.push(kv_line(
                theme,
                "autoscale",
                &format!(
                    "{} req={} active={}",
                    autoscaler.controller_role,
                    autoscaler.requested_remote_nodes,
                    autoscaler.active_remote_nodes
                ),
                Some(if autoscaler.enabled {
                    Tone::Info
                } else {
                    Tone::Neutral
                }),
            ));
            if !autoscaler.pressure_signals.is_empty() {
                lines.push(kv_line(
                    theme,
                    "pressure",
                    &truncate(
                        &autoscaler
                            .pressure_signals
                            .iter()
                            .take(MAX_CLUSTER_PRESSURE)
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(" | "),
                        40,
                    ),
                    Some(Tone::Warn),
                ));
            }
            if let Some(action) = &autoscaler.last_action {
                lines.push(kv_line(theme, "last action", &truncate(action, 40), None));
            }
        }
        if lines.is_empty() {
            lines.push(kv_line(
                theme,
                "cluster",
                "no slurm or autoscaler snapshot",
                Some(Tone::Neutral),
            ));
        }
    } else {
        lines.push(error_line(
            theme,
            app.status_error.as_deref().unwrap_or("status offline"),
        ));
    }
    frame.render_widget(
        Paragraph::new(lines).block(block).wrap(Wrap { trim: true }),
        area,
    );
}

fn render_workload_panel(frame: &mut Frame, area: Rect, app: &TraceyTopApp, theme: Theme) {
    let block = panel_block(" workloads ", theme);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if !app.log_view.process_rows.is_empty() {
        let sections = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(5), Constraint::Length(2)])
            .split(inner);
        let header = Row::new(vec!["pid", "proc", "cpu", "mem", "io"]).style(
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        );
        let rows = app.log_view.process_rows.iter().map(|row| {
            Row::new(vec![
                Cell::from(row.pid.to_string()),
                Cell::from(truncate(&row.name, 14)),
                Cell::from(
                    row.cpu_pct
                        .map(|value| format!("{value:.1}"))
                        .unwrap_or_else(|| "-".to_string()),
                ),
                Cell::from(
                    row.mem_bytes
                        .map(format_bytes)
                        .unwrap_or_else(|| "-".to_string()),
                ),
                Cell::from(
                    row.io_bps
                        .map(format_bps)
                        .unwrap_or_else(|| "-".to_string()),
                ),
            ])
        });
        let table = Table::new(
            rows,
            [
                Constraint::Length(6),
                Constraint::Length(14),
                Constraint::Length(6),
                Constraint::Length(10),
                Constraint::Min(8),
            ],
        )
        .header(header)
        .column_spacing(1);
        frame.render_widget(table, sections[0]);

        let summary = workload_summary(app);
        frame.render_widget(
            Paragraph::new(summary).style(Style::default().fg(theme.muted)),
            sections[1],
        );
        return;
    }

    let mut lines = Vec::new();
    for gpu in &app.log_view.gpu_rows {
        lines.push(kv_line(
            theme,
            &truncate(&gpu.id, 10),
            &format!(
                "{} util={} temp={} power={}",
                truncate(&gpu.name, 10),
                gpu.util_pct
                    .map(|value| format!("{value:.0}%"))
                    .unwrap_or_else(|| "n/a".to_string()),
                gpu.temp_c
                    .map(|value| format!("{value:.0}C"))
                    .unwrap_or_else(|| "n/a".to_string()),
                gpu.power_w
                    .map(|value| format!("{value:.0}W"))
                    .unwrap_or_else(|| "n/a".to_string())
            ),
            Some(Tone::Info),
        ));
    }
    for disk in &app.log_view.disk_rows {
        lines.push(kv_line(
            theme,
            &truncate(&disk.mount, 10),
            &format!(
                "{} of {} ({})",
                disk.used_bytes
                    .map(format_bytes)
                    .unwrap_or_else(|| "n/a".to_string()),
                disk.total_bytes
                    .map(format_bytes)
                    .unwrap_or_else(|| "n/a".to_string()),
                disk.used_ratio
                    .map(|value| format!("{:.0}%", value * 100.0))
                    .unwrap_or_else(|| "n/a".to_string())
            ),
            Some(if disk.used_ratio.unwrap_or(0.0) >= 0.85 {
                Tone::Warn
            } else {
                Tone::Neutral
            }),
        ));
    }
    if lines.is_empty() {
        lines.push(error_line(
            theme,
            app.log_error
                .as_deref()
                .unwrap_or("waiting for process, gpu, or disk samples"),
        ));
    }
    frame.render_widget(
        Paragraph::new(lines).block(panel_block(" workloads ", theme)),
        area,
    );
}

fn workload_summary(app: &TraceyTopApp) -> String {
    let mut summary = Vec::new();
    if let Some(gpu) = app.log_view.gpu_rows.first() {
        summary.push(format!(
            "gpu {} util {} temp {}",
            gpu.id,
            gpu.util_pct
                .map(|value| format!("{value:.0}%"))
                .unwrap_or_else(|| "n/a".to_string()),
            gpu.temp_c
                .map(|value| format!("{value:.0}C"))
                .unwrap_or_else(|| "n/a".to_string())
        ));
    }
    if let Some(disk) = app.log_view.disk_rows.first() {
        summary.push(format!(
            "disk {} {}",
            disk.mount,
            disk.used_ratio
                .map(|value| format!("{:.0}% used", value * 100.0))
                .unwrap_or_else(|| "n/a".to_string())
        ));
    }
    if summary.is_empty() {
        "no gpu or disk summary from recent embedded samples".to_string()
    } else {
        truncate(&summary.join(" | "), 80)
    }
}

fn render_local_location_panel(frame: &mut Frame, area: Rect, app: &TraceyTopApp, theme: Theme) {
    if app.status.is_none() {
        frame.render_widget(
            Paragraph::new(vec![error_line(theme, "waiting for status snapshot")])
                .block(panel_block(" self / inference ", theme)),
            area,
        );
        return;
    }
    let Some(location) = effective_self_location(app) else {
        frame.render_widget(
            Paragraph::new(vec![error_line(theme, "location inference unavailable")])
                .block(panel_block(" self / inference ", theme)),
            area,
        );
        return;
    };
    let mut lines = Vec::new();
    lines.push(kv_line(theme, "host", &location.host, Some(Tone::Info)));
    lines.push(kv_line(
        theme,
        "relation",
        &location.relation,
        Some(Tone::Neutral),
    ));
    if let Some(system) = location.system.as_deref() {
        lines.push(kv_line(theme, "system", system, Some(Tone::Neutral)));
    }
    if let Some(cpu) = location.cpu.as_deref() {
        lines.push(kv_line(theme, "cpu", cpu, Some(Tone::Neutral)));
    }
    if let Some(process) = location.process.as_deref() {
        lines.push(kv_line(theme, "process", process, Some(Tone::Neutral)));
    }
    if let Some(threads) = location.threads {
        lines.push(kv_line(
            theme,
            "threads",
            &threads.to_string(),
            Some(Tone::Neutral),
        ));
    }
    lines.push(location_guess_line(theme, "geo", location.geo.as_ref()));
    lines.push(location_guess_line(theme, "site", location.site.as_ref()));
    lines.push(location_guess_line(
        theme,
        "building",
        location.building.as_ref(),
    ));
    lines.push(location_guess_line(theme, "room", location.room.as_ref()));
    lines.push(location_guess_line(
        theme,
        "network",
        location.network.as_ref(),
    ));
    lines.push(location_guess_line(
        theme,
        "physical",
        location.physical.as_ref(),
    ));
    if let Some(status_addr) = location.status_addr.as_deref() {
        lines.push(kv_line(
            theme,
            "status",
            &format!(
                "{} {}",
                if location.secure_status {
                    "🔒"
                } else {
                    "🔓"
                },
                status_addr
            ),
            Some(if location.secure_status {
                Tone::Good
            } else {
                Tone::Warn
            }),
        ));
    }
    if !location.addresses.is_empty() {
        lines.push(kv_line(
            theme,
            "ip",
            &location.addresses.join(", "),
            Some(Tone::Info),
        ));
    }
    if !location.evidence.is_empty() {
        lines.push(kv_line(
            theme,
            "evidence",
            &location.evidence.join(" | "),
            Some(Tone::Neutral),
        ));
    }

    frame.render_widget(
        Paragraph::new(lines)
            .block(panel_block(" self / inference ", theme))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_location_summary_panel(frame: &mut Frame, area: Rect, app: &TraceyTopApp, theme: Theme) {
    let Some(status) = &app.status else {
        frame.render_widget(
            Paragraph::new(vec![error_line(theme, "waiting for cluster topology")])
                .block(panel_block(" cluster location ", theme)),
            area,
        );
        return;
    };

    let Some(location) = effective_self_location(app) else {
        frame.render_widget(
            Paragraph::new(vec![error_line(theme, "location inference unavailable")])
                .block(panel_block(" cluster location ", theme)),
            area,
        );
        return;
    };

    let peers = effective_peer_locations(app, Some(&location));
    let secure_count = peers.iter().filter(|peer| peer.secure_status).count()
        + usize::from(location.secure_status);
    let insecure_count = peers.len() + 1usize - secure_count;
    let same_room = peers
        .iter()
        .filter(|peer| same_location_guess(location.room.as_ref(), peer.room.as_ref()))
        .count();
    let same_building = peers
        .iter()
        .filter(|peer| same_location_guess(location.building.as_ref(), peer.building.as_ref()))
        .count();
    let mut lines = vec![
        kv_line(
            theme,
            "cluster",
            &format!("{} nodes / {} peers", peers.len() + 1, peers.len()),
            Some(Tone::Info),
        ),
        kv_line(
            theme,
            "coordinator",
            status
                .proxy_agent_id
                .as_deref()
                .unwrap_or(status.agent_id.as_str()),
            Some(Tone::Neutral),
        ),
        kv_line(
            theme,
            "security",
            &format!("{secure_count} secure / {insecure_count} insecure"),
            Some(if insecure_count == 0 {
                Tone::Good
            } else {
                Tone::Warn
            }),
        ),
        kv_line(
            theme,
            "same room",
            &format!("{same_room} peers share the strongest room hypothesis"),
            Some(Tone::Neutral),
        ),
        kv_line(
            theme,
            "same bldg",
            &format!("{same_building} peers align on building/site"),
            Some(Tone::Neutral),
        ),
    ];

    let mut nearest: Vec<_> = peers.iter().collect();
    nearest.sort_by(|left, right| {
        left.latency_ms
            .cmp(&right.latency_ms)
            .then_with(|| left.host.cmp(&right.host))
            .then_with(|| left.agent_id.cmp(&right.agent_id))
    });
    for peer in nearest.into_iter().take(4) {
        let room = location_guess_compact(peer.room.as_ref().or(peer.network.as_ref()));
        let latency = peer
            .latency_ms
            .map(|value| format!("{value}ms"))
            .unwrap_or_else(|| "n/a".to_string());
        let lock = if peer.secure_status { "🔒" } else { "🔓" };
        lines.push(kv_line(
            theme,
            &truncate(&peer.host, 11),
            &format!("{lock} {latency} {} {}", peer.relation, room),
            Some(if peer.latency_ms.unwrap_or(u64::MAX) <= 10 {
                Tone::Good
            } else {
                Tone::Info
            }),
        ));
    }

    if peers.is_empty() {
        lines.push(error_line(
            theme,
            "no remote peers discovered yet; map will update from discovery gossip",
        ));
    }

    frame.render_widget(
        Paragraph::new(lines)
            .block(panel_block(" cluster location ", theme))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_location_map_panel(frame: &mut Frame, area: Rect, app: &TraceyTopApp, theme: Theme) {
    let lines = build_location_map_lines(app, area.width.saturating_sub(2) as usize, area.height);
    frame.render_widget(
        Paragraph::new(lines)
            .block(panel_block(" inferred map ", theme))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn build_location_map_lines(app: &TraceyTopApp, width: usize, height: u16) -> Vec<Line<'static>> {
    if app.status.is_none() {
        return vec![Line::from("waiting for status snapshot")];
    }

    let Some(self_location) = effective_self_location(app) else {
        return vec![Line::from("location inference unavailable")];
    };

    let mut nodes = Vec::new();
    nodes.push(self_location.clone());
    nodes.extend(effective_peer_locations(app, Some(&self_location)));

    nodes.sort_by(|left, right| {
        right
            .is_self
            .cmp(&left.is_self)
            .then_with(|| left.latency_ms.cmp(&right.latency_ms))
            .then_with(|| left.host.cmp(&right.host))
            .then_with(|| left.agent_id.cmp(&right.agent_id))
    });

    let mut rows: Vec<(String, String, String, AgentLocationSnapshot)> = nodes
        .into_iter()
        .map(|node| {
            let geo = diagram_group_label(node.geo.as_ref(), "geo ?");
            let site = diagram_group_label(node.site.as_ref().or(node.building.as_ref()), "site ?");
            let room = diagram_group_label(node.room.as_ref().or(node.network.as_ref()), "room ?");
            (geo, site, room, node)
        })
        .collect();
    rows.sort_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then_with(|| left.1.cmp(&right.1))
            .then_with(|| left.2.cmp(&right.2))
            .then_with(|| right.3.is_self.cmp(&left.3.is_self))
            .then_with(|| left.3.latency_ms.cmp(&right.3.latency_ms))
            .then_with(|| left.3.host.cmp(&right.3.host))
    });

    let mut lines = vec![Line::from("fuzzy location graph")];
    let mut current_geo: Option<String> = None;
    let mut current_site: Option<String> = None;
    let mut current_room: Option<String> = None;

    for (geo, site, room, node) in rows {
        if current_geo.as_deref() != Some(geo.as_str()) {
            lines.push(Line::from(truncate(&format!("geo {geo}"), width)));
            current_geo = Some(geo.clone());
            current_site = None;
            current_room = None;
        }
        if current_site.as_deref() != Some(site.as_str()) {
            lines.push(Line::from(truncate(&format!("|- site {site}"), width)));
            current_site = Some(site.clone());
            current_room = None;
        }
        if current_room.as_deref() != Some(room.as_str()) {
            lines.push(Line::from(truncate(&format!("|  `- room {room}"), width)));
            current_room = Some(room.clone());
        }
        lines.push(Line::from(truncate(
            &format!("|     |- {}", location_map_node(&node)),
            width,
        )));
    }

    let max_lines = height.saturating_sub(2) as usize;
    if lines.len() > max_lines {
        let hidden = lines.len() - max_lines + 1;
        lines.truncate(max_lines.saturating_sub(1));
        lines.push(Line::from(truncate(
            &format!("... {hidden} more rows hidden; widen or filter the cluster"),
            width,
        )));
    }
    lines
}

fn location_map_node(node: &AgentLocationSnapshot) -> String {
    let lock = if node.secure_status { "🔒" } else { "🔓" };
    let version = format!(
        "ver={}",
        node.agent_version
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .map(|value| format!("v{value}"))
            .unwrap_or_else(|| "v?".to_string())
    );
    let latency = node
        .latency_ms
        .map(|value| format!("{value}ms"))
        .unwrap_or_else(|| "n/a".to_string());
    let room = location_guess_compact(node.room.as_ref().or(node.network.as_ref()));
    let physical = location_guess_compact(node.physical.as_ref());
    let mut parts = vec![
        if node.is_self { "self" } else { "peer" }.to_string(),
        node.host.clone(),
        version,
        lock.to_string(),
        format!("lat={latency}"),
        format!("role={}", node.relation),
        format!("room={room}"),
        format!("phys={physical}"),
    ];
    if let Some(building) = node.building.as_ref() {
        parts.push(format!(
            "bldg={} {:.0}%",
            building.label,
            building.confidence * 100.0
        ));
    }
    parts.join(" ")
}

fn diagram_group_label(guess: Option<&crate::location::LocationGuess>, fallback: &str) -> String {
    guess
        .map(|value| format!("{} ({:.0}%)", value.label, value.confidence * 100.0))
        .unwrap_or_else(|| fallback.to_string())
}

fn location_guess_line(
    theme: Theme,
    key: &str,
    guess: Option<&crate::location::LocationGuess>,
) -> Line<'static> {
    match guess {
        Some(guess) => kv_line(
            theme,
            key,
            &format!("{} ({:.0}%)", guess.label, guess.confidence * 100.0),
            Some(tone_for_location_confidence(guess.confidence)),
        ),
        None => kv_line(theme, key, "?", Some(Tone::Warn)),
    }
}

fn location_guess_compact(guess: Option<&crate::location::LocationGuess>) -> String {
    guess
        .map(|value| format!("{}:{:.0}%", value.label, value.confidence * 100.0))
        .unwrap_or_else(|| "?".to_string())
}

fn tone_for_location_confidence(confidence: f64) -> Tone {
    if confidence >= 0.80 {
        Tone::Good
    } else if confidence >= 0.55 {
        Tone::Info
    } else if confidence >= 0.35 {
        Tone::Warn
    } else {
        Tone::Bad
    }
}

fn same_location_guess(
    left: Option<&crate::location::LocationGuess>,
    right: Option<&crate::location::LocationGuess>,
) -> bool {
    matches!(
        (left, right),
        (Some(left), Some(right)) if left.label.eq_ignore_ascii_case(&right.label)
    )
}

fn render_footer(frame: &mut Frame, area: Rect, app: &TraceyTopApp, theme: Theme) {
    let mut parts = Vec::new();
    parts.push(Span::styled("q/Esc", Style::default().fg(theme.accent)));
    parts.push(Span::styled(" quit  ", Style::default().fg(theme.muted)));
    parts.push(Span::styled("r", Style::default().fg(theme.accent)));
    parts.push(Span::styled(" refresh  ", Style::default().fg(theme.muted)));
    parts.push(Span::styled("Tab/←/→", Style::default().fg(theme.accent)));
    parts.push(Span::styled(
        format!(" page {} {}  ", app.page.label(), app.page.shortcut()),
        Style::default().fg(theme.muted),
    ));

    if let Some(status_error) = &app.status_error {
        parts.push(Span::styled(
            truncate(status_error, 42),
            Style::default().fg(theme.bad),
        ));
    } else if let Some(log_error) = &app.log_error {
        parts.push(Span::styled(
            truncate(log_error, 42),
            Style::default().fg(theme.warn),
        ));
    } else if let Some(ts_ms) = app.log_view.last_log_ts_ms {
        parts.push(Span::styled(
            format!("log age {}", human_age_ms(now_ms().saturating_sub(ts_ms))),
            Style::default().fg(theme.muted),
        ));
    }

    frame.render_widget(Paragraph::new(Line::from(parts)), area);
}

fn panel_block<'a>(title: &'a str, theme: Theme) -> Block<'a> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.frame))
        .title(Span::styled(
            title,
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        ))
}

fn kv_line(theme: Theme, key: &str, value: &str, tone: Option<Tone>) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{key:<11}"), Style::default().fg(theme.muted)),
        Span::styled(
            truncate(value, 52),
            Style::default().fg(tone
                .map(|tone| tone_color(tone, theme))
                .unwrap_or(theme.text)),
        ),
    ])
}

fn error_line(theme: Theme, value: &str) -> Line<'static> {
    Line::from(vec![Span::styled(
        truncate(value, 60),
        Style::default().fg(theme.bad),
    )])
}

fn tone_color(tone: Tone, theme: Theme) -> Color {
    match tone {
        Tone::Good => theme.good,
        Tone::Warn => theme.warn,
        Tone::Bad => theme.bad,
        Tone::Info => theme.accent,
        Tone::Neutral => theme.text,
    }
}

fn bool_word(value: bool) -> &'static str {
    if value { "on" } else { "off" }
}

fn truncate(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    value
        .chars()
        .take(max_chars.saturating_sub(3))
        .collect::<String>()
        + "..."
}

fn human_age_ms(ms: u64) -> String {
    if ms < 1_000 {
        format!("{}ms", ms)
    } else if ms < 60_000 {
        format!("{:.1}s", (ms as f64) / 1_000.0)
    } else if ms < 3_600_000 {
        format!("{:.1}m", (ms as f64) / 60_000.0)
    } else {
        format!("{:.1}h", (ms as f64) / 3_600_000.0)
    }
}

fn format_mbps(value: f64) -> String {
    format!("{value:.0}Mbps")
}

fn format_bytes(value: f64) -> String {
    human_bytes(value, false)
}

fn format_bps(value: f64) -> String {
    human_bytes(value, true)
}

fn human_bytes(value: f64, per_second: bool) -> String {
    let mut scaled = value.max(0.0);
    let units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut idx = 0usize;
    while scaled >= 1024.0 && idx + 1 < units.len() {
        scaled /= 1024.0;
        idx += 1;
    }
    if per_second {
        format!("{scaled:.1} {}/s", units[idx])
    } else {
        format!("{scaled:.1} {}", units[idx])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    use std::time::Duration;

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "tracey-top-test-{}-{}-{}",
            name,
            std::process::id(),
            now_ms()
        ))
    }

    fn test_options(status_url: &str) -> TopOptions {
        TopOptions {
            status_url: status_url.to_string(),
            log_path: None,
            refresh_interval: Duration::from_secs(1),
            auth_token: None,
            tail_bytes: DEFAULT_TAIL_BYTES,
            show_help: false,
            status_explicit: true,
            log_path_explicit: true,
            attach_label: Some("test".to_string()),
        }
    }

    fn test_status(agent_id: &str) -> StatusSnapshot {
        StatusSnapshot {
            ts_ms: 1,
            status: Some("healthy".to_string()),
            status_addr: None,
            agent_id: agent_id.to_string(),
            agent_version: Some(crate::package_version().to_string()),
            is_coordinator: true,
            leader_rank: 0,
            leader_count: 1,
            proxy_agent_id: None,
            proxy_addr: None,
            proxy_latency_ms: None,
            is_prometheus_exporter: false,
            prometheus_exporter_agent_id: None,
            prometheus_exporter_addr: None,
            prometheus_exporter_latency_ms: None,
            prometheus_exporter_bandwidth_mbps: None,
            local_prometheus_probe_ready: None,
            local_prometheus_latency_ms: None,
            local_prometheus_bandwidth_mbps: None,
            posture: "Balanced".to_string(),
            decision_threshold: 0.5,
            active_response: false,
            shutdown_enabled: false,
            update_enabled: false,
            telemetry_enabled: true,
            discovery_enabled: true,
            tracey_ban_local_bans: 0,
            tracey_ban_remote_bans: 0,
            tracey_ban_remote_agents: 0,
            tracey_ban_local_entries: Vec::new(),
            tracey_ban_remote_entries: Vec::new(),
            tracey_guard: None,
            slurm: None,
            continuum_autoscaler: None,
            location: AgentLocationSnapshot::default(),
            peer_locations: Vec::new(),
        }
    }

    fn test_app(status_url: &str, status: StatusSnapshot) -> TraceyTopApp {
        TraceyTopApp {
            options: test_options(status_url),
            page: DashboardPage::Locations,
            status: Some(status),
            log_view: LogView::default(),
            status_error: None,
            log_error: None,
            last_refresh: Instant::now(),
        }
    }

    fn line_text(line: &Line<'_>) -> String {
        line.spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect::<String>()
    }

    #[test]
    fn normalize_status_url_rewrites_unspecified_bind_hosts() {
        assert_eq!(
            normalize_status_url("0.0.0.0:48000"),
            "http://127.0.0.1:48000/status"
        );
        assert_eq!(normalize_status_url("0.0.0.0"), "http://127.0.0.1/status");
        assert_eq!(
            normalize_status_url("http://[::]:48000"),
            "http://[::1]:48000/status"
        );
        assert_eq!(normalize_status_url("[::]"), "http://[::1]/status");
        assert_eq!(
            normalize_status_url("https://tracey.local:48000/status"),
            "https://tracey.local:48000/status"
        );
    }

    #[test]
    fn normalize_status_url_prefers_https_for_non_loopback_targets() {
        assert_eq!(
            normalize_status_url("tracey.example.com:48000"),
            "https://tracey.example.com:48000/status"
        );
        assert_eq!(
            normalize_status_url("192.0.2.15:48000"),
            "https://192.0.2.15:48000/status"
        );
    }

    #[test]
    fn normalize_status_url_keeps_loopback_targets_on_http() {
        assert_eq!(
            normalize_status_url("localhost:48000"),
            "http://localhost:48000/status"
        );
        assert_eq!(
            normalize_status_url("127.0.0.1:48000"),
            "http://127.0.0.1:48000/status"
        );
        assert_eq!(
            normalize_status_url("[::1]:48000"),
            "http://[::1]:48000/status"
        );
    }

    #[test]
    fn default_status_url_prefers_https_for_public_addr_without_scheme() {
        let mut config = Config::default();
        config.status.public_addr = Some("tracey.example.com:48000".to_string());
        assert_eq!(
            default_status_url(&config),
            "https://tracey.example.com:48000/status"
        );
    }

    #[test]
    fn read_tail_lines_drops_partial_prefix() {
        let path = temp_path("tail-lines");
        fs::write(&path, "ignored-prefix\nline-one\nline-two\nline-three\n").unwrap();
        let lines = read_tail_lines(&path, 22, 10).unwrap();
        assert_eq!(
            lines,
            vec!["line-two".to_string(), "line-three".to_string()]
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn build_log_view_extracts_metrics_and_activity() {
        let event_cpu = json!({
            "type": "event",
            "payload": {
                "id": 1,
                "ts_ms": 10,
                "source": "embedded",
                "kind": "system_metric",
                "signal": 0.42,
                "severity": "medium",
                "attributes": {
                    "metric": "cpu_usage",
                    "value": "42.000",
                    "unit": "percent"
                }
            }
        })
        .to_string();
        let event_proc = json!({
            "type": "event",
            "payload": {
                "id": 2,
                "ts_ms": 11,
                "source": "embedded",
                "kind": "system_metric",
                "signal": 0.55,
                "severity": "medium",
                "attributes": {
                    "metric": "process_cpu_percent",
                    "value": "55.000",
                    "pid": "123",
                    "process": "tracey"
                }
            }
        })
        .to_string();
        let decision = json!({
            "type": "decision",
            "payload": {
                "event_id": 7,
                "ts_ms": 12,
                "kind": "observability",
                "action": "alert",
                "mean_risk": 0.81,
                "mean_confidence": 0.77,
                "telemetry": {
                    "fuzzy_order": 2,
                    "mean_z_abs": 1.2,
                    "mean_core_risk": 0.81,
                    "mean_interval_width": 0.18,
                    "mean_edge_membership": 0.44,
                    "mean_security_context": 0.55,
                    "mean_metric_context": 0.66,
                    "mean_aarnn_context": 0.0,
                    "mean_learned_confidence": 0.77
                },
                "quorum": 3,
                "agents": 4,
                "reason": "unit test"
            }
        })
        .to_string();

        let view = build_log_view(&vec![event_cpu, event_proc, decision]);
        assert_eq!(view.last_cpu_pct, Some(42.0));
        assert_eq!(view.process_rows.len(), 1);
        assert_eq!(view.process_rows[0].name, "tracey");
        assert_eq!(view.activity_rows.len(), 1);
        assert_eq!(view.activity_rows[0].kind, "DECISION");
        assert_eq!(view.risk_history.last().copied(), Some(81));
    }

    #[test]
    fn load_attach_config_uses_local_agent_config_and_storage_override() {
        let dir = temp_path("attach-config");
        std::fs::create_dir_all(&dir).unwrap();
        let cfg_path = dir.join("tracey.json");
        let override_log = dir.join("override.log");
        fs::write(
            &cfg_path,
            r#"{
                "status": { "enabled": true, "listen_addr": "0.0.0.0:49000" },
                "storage": { "log_path": "from-config.log" }
            }"#,
        )
        .unwrap();
        fs::write(&override_log, "").unwrap();

        let mut env_map = HashMap::new();
        env_map.insert("TRACEY_CONFIG".to_string(), "tracey.json".to_string());
        env_map.insert(
            "TRACEY_STORAGE_PATH".to_string(),
            "override.log".to_string(),
        );

        let cfg = load_attach_config(&env_map, Some(&dir));
        assert!(cfg.status.enabled);
        assert_eq!(cfg.status.listen_addr.as_deref(), Some("0.0.0.0:49000"));
        assert_eq!(
            resolve_agent_log_path(&env_map, &cfg, Some(&dir)),
            Some(override_log.clone())
        );
        assert_eq!(
            normalize_status_url(cfg.status.listen_addr.as_deref().unwrap()),
            "http://127.0.0.1:49000/status"
        );

        let _ = fs::remove_file(&cfg_path);
        let _ = fs::remove_file(&override_log);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn effective_self_location_falls_back_for_older_agents() {
        let mut status = test_status("cortex-1000");
        status.status_addr = Some("http://127.0.0.1:48000/status".to_string());
        let app = test_app("http://127.0.0.1:48000/status", status);

        let location = effective_self_location(&app).expect("fallback location");
        assert_eq!(location.agent_id, "cortex-1000");
        assert!(location.is_self);
        assert!(location.room.is_some());
        assert!(location.network.is_some());
        assert_eq!(
            location.status_addr.as_deref(),
            Some("http://127.0.0.1:48000/status")
        );
        assert_eq!(
            location.agent_version.as_deref(),
            Some(crate::package_version())
        );
    }

    #[test]
    fn fallback_banner_appears_when_server_location_is_missing() {
        let app = test_app("http://127.0.0.1:48000/status", test_status("cortex-1000"));

        let banner = location_inference_banner_text(&app).expect("fallback banner");
        assert!(banner.contains("client-side fallback inference active"));
    }

    #[test]
    fn fallback_banner_is_hidden_when_server_location_exists() {
        let mut status = test_status("cortex-1000");
        status.location.agent_id = "cortex-1000".to_string();
        status.location.host = "cortex".to_string();
        let app = test_app("http://127.0.0.1:48000/status", status);

        assert!(location_inference_banner_text(&app).is_none());
    }

    #[test]
    fn location_map_uses_fallback_self_snapshot() {
        let app = test_app("http://127.0.0.1:48000/status", test_status("cortex-1000"));

        let text = build_location_map_lines(&app, 90, 12)
            .iter()
            .map(line_text)
            .collect::<Vec<_>>()
            .join("\n");

        assert!(text.contains("fuzzy location graph"));
        assert!(text.contains("self"));
        assert!(text.contains(&format!("ver=v{}", crate::package_version())));
        assert!(text.contains("role=self"));
        assert!(!text.contains("location inference unavailable"));
    }

    #[test]
    fn header_lines_show_agent_version_discreetly() {
        let app = test_app(
            "https://tracey.example.com:48000/status",
            test_status("cortex-1000"),
        );
        let text = build_header_lines(&app, Theme::default())
            .iter()
            .map(line_text)
            .collect::<Vec<_>>()
            .join("\n");

        assert!(text.contains(&format!("v{}", crate::package_version())));
        assert!(text.contains("agent cortex-1000"));
    }

    #[test]
    fn location_map_shows_peer_versions() {
        let mut status = test_status("cortex-1000");
        status.location.agent_id = "cortex-1000".to_string();
        status.location.agent_version = Some("1.2.3".to_string());
        status.location.host = "cortex".to_string();
        status.location.relation = "self,coord".to_string();
        status.location.is_self = true;
        status.location.is_coordinator = true;
        status.peer_locations.push(AgentLocationSnapshot {
            agent_id: "peer-2000".to_string(),
            agent_version: Some("2.4.6".to_string()),
            host: "peerbox".to_string(),
            relation: "peer".to_string(),
            latency_ms: Some(8),
            secure_status: true,
            ..AgentLocationSnapshot::default()
        });
        let app = test_app("https://tracey.example.com:48000/status", status);

        let text = build_location_map_lines(&app, 120, 12)
            .iter()
            .map(line_text)
            .collect::<Vec<_>>()
            .join("\n");

        assert!(text.contains("ver=v1.2.3"));
        assert!(text.contains("ver=v2.4.6"));
        assert!(text.contains("peerbox"));
    }
}
