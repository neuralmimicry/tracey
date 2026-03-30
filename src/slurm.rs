//! Automatic Slurm environment detection and lightweight cluster status polling.
//!
//! Detects both native Slurm deployments and the Podman-based Slurm topology used
//! in Continuum. Publishes compact snapshots for `/status` and discovery gossip.

use crate::event::now_ms;
use crate::shutdown::ShutdownListener;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::process::Command;
use tokio::sync::RwLock;

const SLURM_POLL_INTERVAL_MS: u64 = 10_000;
const SLURM_COMMAND_TIMEOUT_MS: u64 = 4_000;
const MAX_SLURM_ROLES: usize = 8;
const MAX_SLURM_ROLE_LEN: usize = 32;
const MAX_SLURM_MODE_LEN: usize = 16;
const MAX_SLURM_CLUSTER_NAME_LEN: usize = 128;
const PODMAN_FRONTEND_NAME: &str = "slurmfrontend";
const PODMAN_MASTER_NAME: &str = "slurmmaster";
const PODMAN_CONFIG_HINTS: &[&str] = &[
    "/opt/continuum/slurm-podman/configs/slurm.conf.frontend",
    "/opt/continuum/slurm-podman/configs/slurm.conf.master",
    "/opt/continuum/slurm-podman/configs/slurm.conf.base",
];
const LOCAL_CONFIG_HINTS: &[&str] = &["/etc/slurm/slurm.conf"];

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SlurmSnapshot {
    pub updated_ms: u64,
    pub mode: String,
    #[serde(default)]
    pub cluster_name: Option<String>,
    #[serde(default)]
    pub roles: Vec<String>,
    pub controller_healthy: bool,
    pub nodes_total: u32,
    pub nodes_idle: u32,
    pub nodes_allocated: u32,
    pub nodes_down: u32,
    pub nodes_other: u32,
    pub jobs_total: u32,
    pub jobs_pending: u32,
    pub jobs_running: u32,
    pub jobs_completing: u32,
    pub jobs_failed: u32,
    pub jobs_other: u32,
}

impl SlurmSnapshot {
    pub fn capability_tags(&self) -> Vec<String> {
        let mut tags = vec!["orchestrator:slurm".to_string()];
        if !self.mode.is_empty() {
            tags.push(format!("slurm:{}", self.mode));
        }
        for role in &self.roles {
            if !role.is_empty() {
                tags.push(format!("slurm:{}", role));
            }
        }
        dedup_strings(tags)
    }

    pub fn sanitize(&mut self) {
        self.mode = normalize_component(&self.mode);
        if self.mode.len() > MAX_SLURM_MODE_LEN {
            self.mode.truncate(MAX_SLURM_MODE_LEN);
        }

        self.cluster_name = self.cluster_name.as_ref().and_then(|name| {
            let trimmed = name.trim();
            if trimmed.is_empty() {
                None
            } else {
                let mut out = trimmed.to_string();
                if out.len() > MAX_SLURM_CLUSTER_NAME_LEN {
                    out.truncate(MAX_SLURM_CLUSTER_NAME_LEN);
                }
                Some(out)
            }
        });

        self.roles = dedup_strings(
            self.roles
                .iter()
                .map(|role| normalize_component(role))
                .filter(|role| !role.is_empty())
                .take(MAX_SLURM_ROLES)
                .map(|mut role| {
                    if role.len() > MAX_SLURM_ROLE_LEN {
                        role.truncate(MAX_SLURM_ROLE_LEN);
                    }
                    role
                })
                .collect(),
        );
    }
}

#[derive(Clone)]
pub struct SlurmRuntimeHandle {
    snapshot: Arc<RwLock<Option<SlurmSnapshot>>>,
}

impl Default for SlurmRuntimeHandle {
    fn default() -> Self {
        Self {
            snapshot: Arc::new(RwLock::new(None)),
        }
    }
}

impl SlurmRuntimeHandle {
    pub async fn snapshot(&self) -> Option<SlurmSnapshot> {
        self.snapshot.read().await.clone()
    }

    pub async fn capability_tags(&self) -> Vec<String> {
        self.snapshot()
            .await
            .map(|snapshot| snapshot.capability_tags())
            .unwrap_or_default()
    }
}

#[derive(Clone, Debug)]
struct ProbeContext {
    mode: &'static str,
    roles: Vec<String>,
    command_prefix: Vec<String>,
    config_hints: Vec<String>,
}

pub async fn spawn_slurm_runtime(mut shutdown: ShutdownListener) -> SlurmRuntimeHandle {
    let handle = SlurmRuntimeHandle::default();
    {
        let mut guard = handle.snapshot.write().await;
        *guard = collect_snapshot().await;
    }

    let snapshot = handle.snapshot.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(SLURM_POLL_INTERVAL_MS));
        interval.tick().await;
        loop {
            tokio::select! {
                _ = shutdown.wait() => {
                    break;
                }
                _ = interval.tick() => {
                    let next = collect_snapshot().await;
                    let mut guard = snapshot.write().await;
                    *guard = next;
                }
            }
        }
    });

    handle
}

async fn collect_snapshot() -> Option<SlurmSnapshot> {
    if let Some(context) = detect_podman_context().await {
        return Some(probe_context(context).await);
    }
    if let Some(context) = detect_local_context() {
        return Some(probe_context(context).await);
    }
    None
}

async fn detect_podman_context() -> Option<ProbeContext> {
    let output = run_string_command(&[
        "podman".to_string(),
        "ps".to_string(),
        "-a".to_string(),
        "--format".to_string(),
        "{{.Names}}".to_string(),
    ])
    .await?;

    let names: Vec<String> = output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToString::to_string)
        .collect();

    if names.is_empty() {
        return None;
    }

    let has_frontend = names.iter().any(|name| name == PODMAN_FRONTEND_NAME);
    let has_master = names.iter().any(|name| name == PODMAN_MASTER_NAME);
    let first_node = names
        .iter()
        .find(|name| is_podman_slurm_node_name(name))
        .cloned();

    if !has_frontend && !has_master && first_node.is_none() {
        return None;
    }

    let exec_target = if has_frontend {
        PODMAN_FRONTEND_NAME.to_string()
    } else if has_master {
        PODMAN_MASTER_NAME.to_string()
    } else {
        first_node.clone()? 
    };

    let mut roles = vec!["host".to_string()];
    if has_frontend {
        roles.push("frontend".to_string());
    }
    if has_master {
        roles.push("controller".to_string());
    }
    if first_node.is_some() {
        roles.push("compute".to_string());
    }

    Some(ProbeContext {
        mode: "podman",
        roles: dedup_strings(roles),
        command_prefix: vec![
            "podman".to_string(),
            "exec".to_string(),
            exec_target,
        ],
        config_hints: PODMAN_CONFIG_HINTS.iter().map(|path| path.to_string()).collect(),
    })
}

fn detect_local_context() -> Option<ProbeContext> {
    let config_present = LOCAL_CONFIG_HINTS.iter().any(|path| Path::new(path).exists());
    let env_present = std::env::vars_os().any(|(key, _)| key.to_string_lossy().starts_with("SLURM_"));
    let commands_present = path_has_executable("scontrol")
        || path_has_executable("sinfo")
        || path_has_executable("squeue");

    if !config_present && !env_present && !commands_present {
        return None;
    }

    let mut roles = Vec::new();
    if process_running("slurmctld") {
        roles.push("controller".to_string());
    }
    if process_running("slurmd") {
        roles.push("compute".to_string());
    }
    if roles.is_empty() {
        roles.push("client".to_string());
    }

    Some(ProbeContext {
        mode: "local",
        roles: dedup_strings(roles),
        command_prefix: Vec::new(),
        config_hints: LOCAL_CONFIG_HINTS
            .iter()
            .filter(|path| Path::new(path).exists())
            .map(|path| path.to_string())
            .collect(),
    })
}

async fn probe_context(context: ProbeContext) -> SlurmSnapshot {
    let controller_healthy = probe_controller_health(&context).await;
    let cluster_name = probe_cluster_name(&context).await;
    let node_states = run_probe_command(&context, "sinfo", &["-h", "-N", "-o", "%T"])
        .await
        .unwrap_or_default();
    let job_states = run_probe_command(&context, "squeue", &["-h", "-o", "%T"])
        .await
        .unwrap_or_default();

    let mut snapshot = SlurmSnapshot {
        updated_ms: now_ms(),
        mode: context.mode.to_string(),
        cluster_name,
        roles: context.roles,
        controller_healthy,
        ..Default::default()
    };

    apply_node_state_lines(&mut snapshot, &node_states);
    apply_job_state_lines(&mut snapshot, &job_states);
    snapshot.sanitize();
    snapshot
}

async fn probe_controller_health(context: &ProbeContext) -> bool {
    let Some(output) = run_probe_command(context, "scontrol", &["ping"]).await else {
        return false;
    };
    let lower = output.to_ascii_lowercase();
    lower.contains(" is up")
        || lower.ends_with(" up")
        || lower.contains("slurmctld(primary) at") && lower.contains("up")
}

async fn probe_cluster_name(context: &ProbeContext) -> Option<String> {
    if let Some(output) = run_probe_command(context, "scontrol", &["show", "config"]).await {
        if let Some(name) = extract_cluster_name(&output) {
            return Some(name);
        }
    }

    for path in &context.config_hints {
        if let Ok(raw) = std::fs::read_to_string(path) {
            if let Some(name) = extract_cluster_name(&raw) {
                return Some(name);
            }
        }
    }

    None
}

async fn run_probe_command(context: &ProbeContext, program: &str, args: &[&str]) -> Option<String> {
    let mut argv = context.command_prefix.clone();
    argv.push(program.to_string());
    argv.extend(args.iter().map(|arg| (*arg).to_string()));
    run_string_command(&argv).await
}

async fn run_string_command(argv: &[String]) -> Option<String> {
    let (program, args) = argv.split_first()?;
    let mut command = Command::new(program);
    command.args(args);
    command.stdin(Stdio::null());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    command.kill_on_drop(true);

    let output = tokio::time::timeout(
        Duration::from_millis(SLURM_COMMAND_TIMEOUT_MS),
        command.output(),
    )
    .await
    .ok()?
    .ok()?;

    if !output.status.success() {
        return None;
    }

    Some(String::from_utf8_lossy(&output.stdout).to_string())
}

fn apply_node_state_lines(snapshot: &mut SlurmSnapshot, output: &str) {
    for state in output.lines().map(str::trim).filter(|line| !line.is_empty()) {
        snapshot.nodes_total = snapshot.nodes_total.saturating_add(1);
        let normalized = normalize_state(state);
        if normalized == "idle" {
            snapshot.nodes_idle = snapshot.nodes_idle.saturating_add(1);
        } else if normalized.contains("alloc")
            || normalized.contains("mix")
            || normalized.contains("comp")
        {
            snapshot.nodes_allocated = snapshot.nodes_allocated.saturating_add(1);
        } else if normalized.contains("down")
            || normalized.contains("drain")
            || normalized.contains("fail")
        {
            snapshot.nodes_down = snapshot.nodes_down.saturating_add(1);
        } else {
            snapshot.nodes_other = snapshot.nodes_other.saturating_add(1);
        }
    }
}

fn apply_job_state_lines(snapshot: &mut SlurmSnapshot, output: &str) {
    for state in output.lines().map(str::trim).filter(|line| !line.is_empty()) {
        snapshot.jobs_total = snapshot.jobs_total.saturating_add(1);
        let normalized = normalize_state(state);
        if normalized == "pending" {
            snapshot.jobs_pending = snapshot.jobs_pending.saturating_add(1);
        } else if normalized == "running" {
            snapshot.jobs_running = snapshot.jobs_running.saturating_add(1);
        } else if normalized == "completing" {
            snapshot.jobs_completing = snapshot.jobs_completing.saturating_add(1);
        } else if normalized.starts_with("fail")
            || normalized == "cancelled"
            || normalized == "timeout"
            || normalized == "node_fail"
            || normalized == "boot_fail"
        {
            snapshot.jobs_failed = snapshot.jobs_failed.saturating_add(1);
        } else {
            snapshot.jobs_other = snapshot.jobs_other.saturating_add(1);
        }
    }
}

fn extract_cluster_name(raw: &str) -> Option<String> {
    for line in raw.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("ClusterName") {
            let rest = rest.trim_start();
            let rest = rest.strip_prefix('=').unwrap_or(rest).trim();
            let value = rest.split_whitespace().next()?;
            let mut name = value.trim().to_string();
            if name.len() > MAX_SLURM_CLUSTER_NAME_LEN {
                name.truncate(MAX_SLURM_CLUSTER_NAME_LEN);
            }
            if !name.is_empty() {
                return Some(name);
            }
        }
    }
    None
}

fn is_podman_slurm_node_name(name: &str) -> bool {
    let Some(suffix) = name.strip_prefix("slurmnode") else {
        return false;
    };
    !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
}

fn normalize_state(value: &str) -> String {
    value
        .trim()
        .to_ascii_lowercase()
        .replace('+', "_")
        .replace('~', "_")
        .replace('*', "_")
}

fn normalize_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        let ch = ch.to_ascii_lowercase();
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch);
        } else if ch == ' ' || ch == ',' || ch == '.' || ch == '/' {
            out.push('_');
        }
    }
    out.trim_matches('_').to_string()
}

fn dedup_strings(values: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for value in values {
        if value.is_empty() {
            continue;
        }
        if seen.insert(value.clone()) {
            out.push(value);
        }
    }
    out
}

fn process_running(name: &str) -> bool {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return false;
    };
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(pid) = file_name.to_str() else {
            continue;
        };
        if !pid.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        if let Ok(comm) = std::fs::read_to_string(entry.path().join("comm")) {
            if comm.trim() == name {
                return true;
            }
        }
    }
    false
}

fn path_has_executable(binary: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| {
        let candidate = dir.join(binary);
        candidate.is_file() && is_executable(&candidate)
    })
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|meta| meta.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_cluster_name_parses_common_formats() {
        assert_eq!(
            extract_cluster_name("ClusterName=cluster
SlurmctldHost=controller"),
            Some("cluster".to_string())
        );
        assert_eq!(
            extract_cluster_name("ClusterName = continuum
SchedulerType = sched/backfill"),
            Some("continuum".to_string())
        );
    }

    #[test]
    fn snapshot_sanitize_normalizes_mode_and_roles() {
        let mut snapshot = SlurmSnapshot {
            mode: "Podman Host".to_string(),
            cluster_name: Some(" cluster ".to_string()),
            roles: vec![
                "Host".to_string(),
                "controller".to_string(),
                "Host".to_string(),
                "compute/node".to_string(),
            ],
            ..Default::default()
        };
        snapshot.sanitize();
        assert_eq!(snapshot.mode, "podman_host");
        assert_eq!(snapshot.cluster_name.as_deref(), Some("cluster"));
        assert_eq!(
            snapshot.roles,
            vec![
                "host".to_string(),
                "controller".to_string(),
                "compute_node".to_string()
            ]
        );
    }

    #[test]
    fn node_state_classification_counts_expected_buckets() {
        let mut snapshot = SlurmSnapshot::default();
        apply_node_state_lines(&mut snapshot, "idle
alloc
mixed
down
future
");
        assert_eq!(snapshot.nodes_total, 5);
        assert_eq!(snapshot.nodes_idle, 1);
        assert_eq!(snapshot.nodes_allocated, 2);
        assert_eq!(snapshot.nodes_down, 1);
        assert_eq!(snapshot.nodes_other, 1);
    }

    #[test]
    fn job_state_classification_counts_expected_buckets() {
        let mut snapshot = SlurmSnapshot::default();
        apply_job_state_lines(&mut snapshot, "PENDING
RUNNING
COMPLETING
FAILED
COMPLETED
");
        assert_eq!(snapshot.jobs_total, 5);
        assert_eq!(snapshot.jobs_pending, 1);
        assert_eq!(snapshot.jobs_running, 1);
        assert_eq!(snapshot.jobs_completing, 1);
        assert_eq!(snapshot.jobs_failed, 1);
        assert_eq!(snapshot.jobs_other, 1);
    }
}
