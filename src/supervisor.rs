//! Supervisor process for crash restart and zero-downtime binary handoff.

use crate::config::Config;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::fs;
use tokio::process::{Child, Command};

#[derive(Debug, Serialize, Deserialize)]
struct SupervisorRequest {
    binary_path: String,
    version: String,
    os: String,
    arch: String,
}

struct ManagedChild {
    child: Child,
    shutdown_path: PathBuf,
    shutdown_token: String,
}

pub async fn run_supervisor() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load();
    let update_dir = config.update.update_dir.clone();
    let handoff_timeout = Duration::from_millis(config.update.handoff_timeout_ms);

    let mut current_binary = std::env::current_exe()?;
    let args: Vec<String> = std::env::args()
        .skip(1)
        .filter(|arg| arg != "--supervisor")
        .collect();

    let mut backoff = Duration::from_millis(500);
    let mut child = spawn_child(&current_binary, &args, &update_dir, None).await?;
    let mut tick = tokio::time::interval(Duration::from_millis(1000));

    tracing::info!("supervisor started");

    loop {
        tokio::select! {
            status = child.child.wait() => {
                tracing::warn!(code = ?status.ok().and_then(|s| s.code()), "agent exited; restarting");

                if let Some(next) = read_update_request(&update_dir).await {
                    tracing::info!(next = %next.display(), "supervisor switching to updated binary");
                    current_binary = next;
                    backoff = Duration::from_millis(250);
                }

                if backoff > Duration::from_millis(0) {
                    tokio::time::sleep(backoff).await;
                }

                child = spawn_child(&current_binary, &args, &update_dir, None).await?;

                if backoff < Duration::from_secs(10) {
                    backoff = (backoff * 2).min(Duration::from_secs(10));
                }
            }
            _ = tick.tick() => {
                if let Some(next) = read_update_request(&update_dir).await {
                    tracing::info!(next = %next.display(), "supervisor applying zero-downtime update");
                    match perform_handoff(&mut child, &next, &args, &update_dir, handoff_timeout).await {
                        Ok(new_child) => {
                            child = new_child;
                            current_binary = next;
                            backoff = Duration::from_millis(250);
                        }
                        Err(err) => {
                            tracing::warn!("handoff failed: {}", err);
                        }
                    }
                }
            }
        }
    }
}

async fn perform_handoff(
    current: &mut ManagedChild,
    next_binary: &Path,
    args: &[String],
    update_dir: &Path,
    timeout: Duration,
) -> Result<ManagedChild, std::io::Error> {
    let handoff_token = generate_token();
    let handoff_path = update_dir.join(format!("handoff-{}.ready", handoff_token));

    let mut next = spawn_child(
        next_binary,
        args,
        update_dir,
        Some((handoff_path.clone(), handoff_token.clone())),
    )
    .await?;

    let ready = wait_for_handoff(&handoff_path, &handoff_token, timeout).await;
    if !ready {
        let _ = next.child.kill().await;
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "handoff readiness timeout",
        ));
    }

    request_shutdown(&current.shutdown_path, &current.shutdown_token).await;

    let shutdown_wait = tokio::time::timeout(timeout, current.child.wait()).await;
    if shutdown_wait.is_err() {
        let _ = current.child.kill().await;
    }

    Ok(next)
}

async fn spawn_child(
    binary: &Path,
    args: &[String],
    update_dir: &Path,
    handoff: Option<(PathBuf, String)>,
) -> std::io::Result<ManagedChild> {
    let shutdown_token = generate_token();
    let shutdown_path = update_dir.join(format!("shutdown-{}.token", shutdown_token));

    let mut command = Command::new(binary);
    command.args(args).env("TRACEY_SUPERVISED", "1");
    command
        .env("TRACEY_SHUTDOWN_PATH", &shutdown_path)
        .env("TRACEY_SHUTDOWN_TOKEN", &shutdown_token);

    if let Some((handoff_path, handoff_token)) = handoff {
        command
            .env("TRACEY_HANDOFF_PATH", handoff_path)
            .env("TRACEY_HANDOFF_TOKEN", handoff_token)
            .env("TRACEY_UPDATED_FROM", "supervisor");
    }

    let child = command.spawn()?;

    Ok(ManagedChild {
        child,
        shutdown_path,
        shutdown_token,
    })
}

async fn request_shutdown(path: &Path, token: &str) {
    let _ = fs::write(path, token.as_bytes()).await;
}

async fn wait_for_handoff(path: &Path, token: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if Instant::now() >= deadline {
            return false;
        }
        if let Ok(contents) = fs::read_to_string(path).await {
            if contents.trim() == token {
                let _ = fs::remove_file(path).await;
                return true;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn read_update_request(update_dir: &Path) -> Option<PathBuf> {
    let request_path = update_dir.join("tracey.supervisor.request.json");
    let raw = fs::read(&request_path).await.ok()?;
    let request: SupervisorRequest = serde_json::from_slice(&raw).ok()?;
    let _ = fs::remove_file(&request_path).await;
    if request.binary_path.is_empty() {
        return None;
    }
    Some(PathBuf::from(request.binary_path))
}

pub async fn write_update_request(
    update_dir: &Path,
    binary_path: &Path,
    version: &str,
    os: &str,
    arch: &str,
) -> std::io::Result<()> {
    let request = SupervisorRequest {
        binary_path: binary_path.display().to_string(),
        version: version.to_string(),
        os: os.to_string(),
        arch: arch.to_string(),
    };
    let payload = serde_json::to_vec(&request)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
    let request_path = update_dir.join("tracey.supervisor.request.json");
    write_atomic(&request_path, &payload).await
}

async fn write_atomic(path: &Path, payload: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).await?;
    }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, payload).await?;
    fs::rename(tmp, path).await
}

fn generate_token() -> String {
    let seed = format!(
        "{}:{}:{:?}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
        std::process::id(),
        std::thread::current().id()
    );
    let hash = blake3::hash(seed.as_bytes());
    to_hex(hash.as_bytes())
}

fn to_hex(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(LUT[(b >> 4) as usize] as char);
        out.push(LUT[(b & 0x0f) as usize] as char);
    }
    out
}
