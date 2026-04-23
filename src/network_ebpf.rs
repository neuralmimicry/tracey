use crate::config::EmbeddedConfig;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

const STARTUP_GRACE_MS: u64 = 150;
const STDERR_LINES: usize = 8;
const STATE_ESTABLISHED: i32 = 1;
const STATE_TIME_WAIT: i32 = 6;
const STATE_CLOSE: i32 = 7;
const STATE_CLOSE_WAIT: i32 = 8;
const STATE_LAST_ACK: i32 = 9;
const STATE_CLOSING: i32 = 11;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkEbpfTarget {
    pub surface: String,
    pub port: u16,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkEbpfEvent {
    pub ts_ms: u64,
    pub pid: u32,
    pub process: String,
    pub surface: String,
    pub local_port: u16,
    pub remote_port: u16,
    pub family: u16,
    pub old_state: i32,
    pub new_state: i32,
    pub transition: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkEbpfSurfaceSnapshot {
    pub surface: String,
    pub local_port: u16,
    pub events: u64,
    pub established_events: u64,
    pub closing_events: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkEbpfSnapshot {
    pub enabled: bool,
    pub active: bool,
    pub source: String,
    pub total_events: u64,
    pub established_events: u64,
    pub closing_events: u64,
    pub alerted_surfaces: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub surfaces: Vec<NetworkEbpfSurfaceSnapshot>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recent_events: Vec<NetworkEbpfEvent>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NetworkEbpfMode {
    Disabled,
    Auto,
    Required,
}

pub struct NetworkEbpfMonitor {
    mode: NetworkEbpfMode,
    program: String,
    shared: Arc<SharedMonitor>,
    stdout_task: Option<tokio::task::JoinHandle<()>>,
    stderr_task: Option<tokio::task::JoinHandle<()>>,
    child: Option<Child>,
    last_total_events: u64,
    last_established_events: u64,
    last_closing_events: u64,
    last_port_counts: HashMap<u16, PortCounters>,
    last_ts_ms: u64,
}

impl NetworkEbpfMonitor {
    pub async fn start(
        config: &EmbeddedConfig,
        targets: &[NetworkEbpfTarget],
    ) -> Result<Option<Self>, String> {
        let mode = parse_mode(&config.network_ebpf_mode);
        if matches!(mode, NetworkEbpfMode::Disabled) {
            return Ok(None);
        }
        let targets = normalize_targets(targets);
        if targets.is_empty() {
            return Ok(None);
        }
        if !cfg!(target_os = "linux") {
            return required_or_inactive(
                mode,
                &config.network_ebpf_program,
                targets,
                "network eBPF capture requires Linux".to_string(),
            );
        }

        let program = config.network_ebpf_program.clone();
        let max_events = config.network_ebpf_max_events.max(16);
        let script = build_trace_program(&targets);
        let mut child = match Command::new(&program)
            .arg("-q")
            .arg("-B")
            .arg("none")
            .arg("-e")
            .arg(script)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
        {
            Ok(child) => child,
            Err(err) => {
                return required_or_inactive(
                    mode,
                    &program,
                    targets,
                    format!("failed to launch {program}: {err}"),
                );
            }
        };

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "network eBPF stdout pipe missing".to_string())?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| "network eBPF stderr pipe missing".to_string())?;
        let shared = Arc::new(SharedMonitor::default());
        let stdout_task = spawn_stdout_reader(stdout, shared.clone(), targets.clone(), max_events);
        let stderr_task = spawn_stderr_reader(stderr, shared.clone());

        tokio::time::sleep(Duration::from_millis(STARTUP_GRACE_MS)).await;
        if let Some(status) = child.try_wait().map_err(|err| err.to_string())? {
            let _ = stdout_task.await;
            let _ = stderr_task.await;
            let detail = shared
                .detail()
                .unwrap_or_else(|| format!("{program} exited before capture with status {status}"));
            return required_or_inactive(mode, &program, targets, detail);
        }

        Ok(Some(Self {
            mode,
            program,
            shared,
            stdout_task: Some(stdout_task),
            stderr_task: Some(stderr_task),
            child: Some(child),
            last_total_events: 0,
            last_established_events: 0,
            last_closing_events: 0,
            last_port_counts: HashMap::new(),
            last_ts_ms: 0,
        }))
    }

    pub async fn sample(&mut self) -> NetworkEbpfSnapshot {
        self.refresh_child_state().await;
        let cumulative = self.shared.snapshot(
            !matches!(self.mode, NetworkEbpfMode::Disabled),
            self.child.is_some(),
            &self.program,
        );
        let total_events = cumulative
            .total_events
            .saturating_sub(self.last_total_events);
        let established_events = cumulative
            .established_events
            .saturating_sub(self.last_established_events);
        let closing_events = cumulative
            .closing_events
            .saturating_sub(self.last_closing_events);
        let surfaces = cumulative
            .surfaces
            .iter()
            .filter_map(|surface| {
                let previous = self
                    .last_port_counts
                    .get(&surface.local_port)
                    .cloned()
                    .unwrap_or_default();
                let events = surface.events.saturating_sub(previous.events);
                let established = surface
                    .established_events
                    .saturating_sub(previous.established_events);
                let closing = surface
                    .closing_events
                    .saturating_sub(previous.closing_events);
                (events > 0 || established > 0 || closing > 0).then(|| NetworkEbpfSurfaceSnapshot {
                    surface: surface.surface.clone(),
                    local_port: surface.local_port,
                    events,
                    established_events: established,
                    closing_events: closing,
                })
            })
            .collect::<Vec<_>>();
        let recent_events = cumulative
            .recent_events
            .iter()
            .filter(|event| event.ts_ms > self.last_ts_ms)
            .cloned()
            .collect::<Vec<_>>();

        self.last_total_events = cumulative.total_events;
        self.last_established_events = cumulative.established_events;
        self.last_closing_events = cumulative.closing_events;
        self.last_port_counts = cumulative
            .surfaces
            .iter()
            .map(|surface| {
                (
                    surface.local_port,
                    PortCounters {
                        events: surface.events,
                        established_events: surface.established_events,
                        closing_events: surface.closing_events,
                    },
                )
            })
            .collect();
        self.last_ts_ms = recent_events
            .last()
            .map(|event| event.ts_ms)
            .unwrap_or(self.last_ts_ms);

        NetworkEbpfSnapshot {
            enabled: cumulative.enabled,
            active: cumulative.active,
            source: cumulative.source,
            total_events,
            established_events,
            closing_events,
            alerted_surfaces: surfaces.len(),
            detail: cumulative.detail,
            surfaces,
            recent_events,
        }
    }

    pub async fn shutdown(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.start_kill();
            let _ = child.wait().await;
        }
        if let Some(task) = self.stdout_task.take() {
            let _ = task.await;
        }
        if let Some(task) = self.stderr_task.take() {
            let _ = task.await;
        }
    }

    async fn refresh_child_state(&mut self) {
        let Some(child) = self.child.as_mut() else {
            return;
        };
        match child.try_wait() {
            Ok(Some(status)) => {
                self.shared
                    .record_stderr(format!("{} exited with status {}", self.program, status));
                let mut child = self.child.take().expect("child exists");
                let _ = child.wait().await;
                if let Some(task) = self.stdout_task.take() {
                    let _ = task.await;
                }
                if let Some(task) = self.stderr_task.take() {
                    let _ = task.await;
                }
            }
            Ok(None) | Err(_) => {}
        }
    }
}

#[derive(Default)]
struct SharedMonitor {
    state: Mutex<MonitorState>,
}

#[derive(Default)]
struct MonitorState {
    total_events: u64,
    established_events: u64,
    closing_events: u64,
    recent_events: VecDeque<NetworkEbpfEvent>,
    stderr_lines: VecDeque<String>,
    surfaces: HashMap<u16, PortSnapshot>,
}

#[derive(Clone, Debug, Default)]
struct PortCounters {
    events: u64,
    established_events: u64,
    closing_events: u64,
}

#[derive(Clone, Debug, Default)]
struct PortSnapshot {
    surface: String,
    counters: PortCounters,
}

#[derive(Clone, Debug, Default)]
struct CumulativeSnapshot {
    enabled: bool,
    active: bool,
    source: String,
    total_events: u64,
    established_events: u64,
    closing_events: u64,
    detail: Option<String>,
    surfaces: Vec<NetworkEbpfSurfaceSnapshot>,
    recent_events: Vec<NetworkEbpfEvent>,
}

impl SharedMonitor {
    fn record_event(&self, event: NetworkEbpfEvent, max_events: usize) {
        let mut state = self.state.lock().expect("network ebpf mutex");
        state.total_events += 1;
        if event.new_state == STATE_ESTABLISHED {
            state.established_events += 1;
        }
        if is_closing_state(event.new_state) {
            state.closing_events += 1;
        }
        let entry = state
            .surfaces
            .entry(event.local_port)
            .or_insert_with(|| PortSnapshot {
                surface: event.surface.clone(),
                counters: PortCounters::default(),
            });
        entry.counters.events += 1;
        if event.new_state == STATE_ESTABLISHED {
            entry.counters.established_events += 1;
        }
        if is_closing_state(event.new_state) {
            entry.counters.closing_events += 1;
        }
        state.recent_events.push_back(event);
        while state.recent_events.len() > max_events {
            state.recent_events.pop_front();
        }
    }

    fn record_stderr(&self, line: String) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return;
        }
        let mut state = self.state.lock().expect("network ebpf mutex");
        state.stderr_lines.push_back(trimmed.to_string());
        while state.stderr_lines.len() > STDERR_LINES {
            state.stderr_lines.pop_front();
        }
    }

    fn detail(&self) -> Option<String> {
        let state = self.state.lock().expect("network ebpf mutex");
        (!state.stderr_lines.is_empty()).then(|| {
            state
                .stderr_lines
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(" | ")
        })
    }

    fn snapshot(&self, enabled: bool, active: bool, source: &str) -> CumulativeSnapshot {
        let state = self.state.lock().expect("network ebpf mutex");
        let mut surfaces = state
            .surfaces
            .iter()
            .map(|(port, snapshot)| NetworkEbpfSurfaceSnapshot {
                surface: snapshot.surface.clone(),
                local_port: *port,
                events: snapshot.counters.events,
                established_events: snapshot.counters.established_events,
                closing_events: snapshot.counters.closing_events,
            })
            .collect::<Vec<_>>();
        surfaces.sort_by(|left, right| {
            right
                .events
                .cmp(&left.events)
                .then(left.local_port.cmp(&right.local_port))
        });
        CumulativeSnapshot {
            enabled,
            active,
            source: source.to_string(),
            total_events: state.total_events,
            established_events: state.established_events,
            closing_events: state.closing_events,
            detail: (!state.stderr_lines.is_empty()).then(|| {
                state
                    .stderr_lines
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(" | ")
            }),
            surfaces,
            recent_events: state.recent_events.iter().cloned().collect(),
        }
    }
}

fn normalize_targets(targets: &[NetworkEbpfTarget]) -> Vec<NetworkEbpfTarget> {
    let mut by_port = HashMap::<u16, String>::new();
    for target in targets {
        if target.port == 0 {
            continue;
        }
        by_port
            .entry(target.port)
            .or_insert_with(|| target.surface.trim().to_string());
    }
    let mut targets = by_port
        .into_iter()
        .map(|(port, surface)| NetworkEbpfTarget { surface, port })
        .collect::<Vec<_>>();
    targets.sort_by(|left, right| left.port.cmp(&right.port));
    targets
}

fn parse_mode(raw: &str) -> NetworkEbpfMode {
    match raw.trim().to_ascii_lowercase().as_str() {
        "auto" => NetworkEbpfMode::Auto,
        "required" => NetworkEbpfMode::Required,
        _ => NetworkEbpfMode::Disabled,
    }
}

fn required_or_inactive(
    mode: NetworkEbpfMode,
    program: &str,
    _targets: Vec<NetworkEbpfTarget>,
    detail: String,
) -> Result<Option<NetworkEbpfMonitor>, String> {
    if matches!(mode, NetworkEbpfMode::Required) {
        Err(detail)
    } else {
        let shared = Arc::new(SharedMonitor::default());
        shared.record_stderr(detail);
        Ok(Some(NetworkEbpfMonitor {
            mode,
            program: program.to_string(),
            shared,
            stdout_task: None,
            stderr_task: None,
            child: None,
            last_total_events: 0,
            last_established_events: 0,
            last_closing_events: 0,
            last_port_counts: HashMap::new(),
            last_ts_ms: 0,
        }))
    }
}

fn spawn_stdout_reader(
    stdout: tokio::process::ChildStdout,
    shared: Arc<SharedMonitor>,
    targets: Vec<NetworkEbpfTarget>,
    max_events: usize,
) -> tokio::task::JoinHandle<()> {
    let surface_by_port = targets
        .into_iter()
        .map(|target| (target.port, target.surface))
        .collect::<HashMap<_, _>>();
    tokio::spawn(async move {
        let mut lines = BufReader::new(stdout).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if let Some(event) = parse_event_line(&line, &surface_by_port) {
                shared.record_event(event, max_events);
            }
        }
    })
}

fn spawn_stderr_reader(
    stderr: tokio::process::ChildStderr,
    shared: Arc<SharedMonitor>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut lines = BufReader::new(stderr).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            shared.record_stderr(line);
        }
    })
}

fn build_trace_program(targets: &[NetworkEbpfTarget]) -> String {
    let port_filter = targets
        .iter()
        .map(|target| format!("ntohs(args.sport) == {}", target.port))
        .collect::<Vec<_>>()
        .join(" || ");
    format!(
        r#"tracepoint:sock:inet_sock_set_state
/ args.protocol == 6 && ({port_filter}) /
{{
  printf("NMTRC\t%llu\t%d\t%s\t%d\t%d\t%d\t%d\t%d\n",
         nsecs / 1000000, pid, comm, ntohs(args.sport), ntohs(args.dport),
         args.oldstate, args.newstate, args.family);
}}"#
    )
}

fn parse_event_line(
    line: &str,
    surface_by_port: &HashMap<u16, String>,
) -> Option<NetworkEbpfEvent> {
    let mut parts = line.trim().split('\t');
    if parts.next()? != "NMTRC" {
        return None;
    }
    let ts_ms = parts.next()?.parse::<u64>().ok()?;
    let pid = parts.next()?.parse::<u32>().ok()?;
    let process = parts.next()?.trim().to_string();
    let local_port = parts.next()?.parse::<u16>().ok()?;
    let remote_port = parts.next()?.parse::<u16>().ok()?;
    let old_state = parts.next()?.parse::<i32>().ok()?;
    let new_state = parts.next()?.parse::<i32>().ok()?;
    let family = parts.next()?.parse::<u16>().ok()?;
    Some(NetworkEbpfEvent {
        ts_ms,
        pid,
        process,
        surface: surface_by_port
            .get(&local_port)
            .cloned()
            .unwrap_or_else(|| format!("port_{local_port}")),
        local_port,
        remote_port,
        family,
        old_state,
        new_state,
        transition: tcp_transition_name(old_state, new_state).to_string(),
    })
}

fn tcp_transition_name(old_state: i32, new_state: i32) -> String {
    format!(
        "{}_to_{}",
        tcp_state_name(old_state),
        tcp_state_name(new_state)
    )
}

fn tcp_state_name(state: i32) -> &'static str {
    match state {
        1 => "established",
        2 => "syn_sent",
        3 => "syn_recv",
        4 => "fin_wait1",
        5 => "fin_wait2",
        6 => "time_wait",
        7 => "close",
        8 => "close_wait",
        9 => "last_ack",
        10 => "listen",
        11 => "closing",
        12 => "new_syn_recv",
        _ => "unknown",
    }
}

fn is_closing_state(state: i32) -> bool {
    matches!(
        state,
        STATE_TIME_WAIT | STATE_CLOSE | STATE_CLOSE_WAIT | STATE_LAST_ACK | STATE_CLOSING
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_trace_program_filters_local_ports() {
        let program = build_trace_program(&[
            NetworkEbpfTarget {
                surface: "status".to_string(),
                port: 48000,
            },
            NetworkEbpfTarget {
                surface: "telemetry_http".to_string(),
                port: 4318,
            },
        ]);
        assert!(program.contains("ntohs(args.sport) == 48000"));
        assert!(program.contains("ntohs(args.sport) == 4318"));
        assert!(program.contains("NMTRC"));
    }

    #[test]
    fn parse_event_line_resolves_surface_from_port() {
        let mapping = HashMap::from([(48000u16, "status".to_string())]);
        let event = parse_event_line("NMTRC\t42\t100\ttracey\t48000\t55124\t3\t1\t2", &mapping)
            .expect("event");
        assert_eq!(event.surface, "status");
        assert_eq!(event.transition, "syn_recv_to_established");
    }

    #[test]
    fn shared_monitor_counts_per_surface() {
        let shared = SharedMonitor::default();
        shared.record_event(
            NetworkEbpfEvent {
                ts_ms: 1,
                pid: 10,
                process: "tracey".to_string(),
                surface: "status".to_string(),
                local_port: 48000,
                remote_port: 55124,
                family: 2,
                old_state: 3,
                new_state: 1,
                transition: "syn_recv_to_established".to_string(),
            },
            4,
        );
        shared.record_event(
            NetworkEbpfEvent {
                ts_ms: 2,
                pid: 10,
                process: "tracey".to_string(),
                surface: "status".to_string(),
                local_port: 48000,
                remote_port: 55124,
                family: 2,
                old_state: 1,
                new_state: 7,
                transition: "established_to_close".to_string(),
            },
            4,
        );
        let snapshot = shared.snapshot(true, true, "bpftrace");
        assert_eq!(snapshot.total_events, 2);
        assert_eq!(snapshot.established_events, 1);
        assert_eq!(snapshot.closing_events, 1);
        assert_eq!(snapshot.surfaces[0].events, 2);
    }
}
