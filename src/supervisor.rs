//! Supervisor process for crash restart and zero-downtime binary handoff.

use crate::config::Config;
use crate::update::{self, UpdateChannel, UpdateMetadata};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::fs;
use tokio::process::{Child, Command};

#[derive(Debug, Serialize, Deserialize)]
pub struct SupervisorRequest {
    pub binary_path: String,
    pub version: String,
    pub os: String,
    pub arch: String,
    #[serde(default)]
    pub channel: UpdateChannel,
    #[serde(default)]
    pub blake3: String,
    #[serde(default)]
    pub signature: String,
}

impl SupervisorRequest {
    pub fn metadata(&self) -> Option<UpdateMetadata> {
        if self.version.trim().is_empty()
            || self.os.trim().is_empty()
            || self.arch.trim().is_empty()
        {
            return None;
        }
        Some(UpdateMetadata {
            version: self.version.clone(),
            os: self.os.clone(),
            arch: self.arch.clone(),
            blake3: self.blake3.clone(),
            channel: self.channel.clone(),
        })
    }
}

pub(crate) struct ManagedChild {
    pub child: Child,
    pub shutdown_path: PathBuf,
    pub shutdown_token: String,
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
                    tracing::info!(next = %next.binary_path, "supervisor switching to updated binary");
                    current_binary = PathBuf::from(next.binary_path);
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
                    tracing::info!(next = %next.binary_path, "supervisor applying zero-downtime update");
                    let next_binary = PathBuf::from(&next.binary_path);
                    match perform_handoff(&mut child, &next_binary, &args, &update_dir, handoff_timeout).await {
                        Ok(new_child) => {
                            child = new_child;
                            current_binary = next_binary;
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

pub(crate) async fn perform_handoff(
    current: &mut ManagedChild,
    next_binary: &Path,
    args: &[String],
    update_dir: &Path,
    timeout: Duration,
) -> Result<ManagedChild, std::io::Error> {
    perform_handoff_with_env(
        current,
        next_binary,
        args,
        update_dir,
        timeout,
        &[],
        None,
        "supervisor",
    )
    .await
}

pub(crate) async fn perform_handoff_with_env(
    current: &mut ManagedChild,
    next_binary: &Path,
    args: &[String],
    update_dir: &Path,
    timeout: Duration,
    extra_env: &[(String, String)],
    current_dir: Option<&Path>,
    updated_from: &str,
) -> Result<ManagedChild, std::io::Error> {
    let handoff_token = generate_token();
    let handoff_path = update_dir.join(format!("handoff-{}.ready", handoff_token));

    let mut next = spawn_child_with_env(
        next_binary,
        args,
        update_dir,
        Some((handoff_path.clone(), handoff_token.clone())),
        extra_env,
        current_dir,
        updated_from,
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

pub(crate) async fn spawn_child(
    binary: &Path,
    args: &[String],
    update_dir: &Path,
    handoff: Option<(PathBuf, String)>,
) -> std::io::Result<ManagedChild> {
    spawn_child_with_env(binary, args, update_dir, handoff, &[], None, "supervisor").await
}

pub(crate) async fn spawn_child_with_env(
    binary: &Path,
    args: &[String],
    update_dir: &Path,
    handoff: Option<(PathBuf, String)>,
    extra_env: &[(String, String)],
    current_dir: Option<&Path>,
    updated_from: &str,
) -> std::io::Result<ManagedChild> {
    let shutdown_token = generate_token();
    let shutdown_path = update_dir.join(format!("shutdown-{}.token", shutdown_token));

    let mut command = Command::new(binary);
    command.args(args).env("TRACEY_SUPERVISED", "1");
    command
        .env("TRACEY_SHUTDOWN_PATH", &shutdown_path)
        .env("TRACEY_SHUTDOWN_TOKEN", &shutdown_token);

    if let Some(current_dir) = current_dir {
        command.current_dir(current_dir);
    }
    for (key, value) in extra_env {
        command.env(key, value);
    }

    if let Some((handoff_path, handoff_token)) = handoff {
        command
            .env("TRACEY_HANDOFF_PATH", handoff_path)
            .env("TRACEY_HANDOFF_TOKEN", handoff_token)
            .env("TRACEY_UPDATED_FROM", updated_from);
    }

    let child = command.spawn()?;

    Ok(ManagedChild {
        child,
        shutdown_path,
        shutdown_token,
    })
}

pub(crate) async fn request_shutdown(path: &Path, token: &str) {
    let _ = fs::write(path, token.as_bytes()).await;
}

pub(crate) async fn wait_for_handoff(path: &Path, token: &str, timeout: Duration) -> bool {
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

pub(crate) async fn read_update_request(update_dir: &Path) -> Option<SupervisorRequest> {
    let request_path = update_dir.join("tracey.supervisor.request.json");
    let raw = fs::read(&request_path).await.ok()?;
    let request: SupervisorRequest = serde_json::from_slice(&raw).ok()?;
    let _ = fs::remove_file(&request_path).await;
    if request.binary_path.is_empty() {
        return None;
    }
    Some(request)
}

pub async fn write_update_request(
    update_dir: &Path,
    binary_path: &Path,
    metadata: &UpdateMetadata,
    signature: &str,
) -> std::io::Result<()> {
    let request = SupervisorRequest {
        binary_path: binary_path.display().to_string(),
        version: metadata.version.clone(),
        os: metadata.os.clone(),
        arch: metadata.arch.clone(),
        channel: metadata.channel.clone(),
        blake3: metadata.blake3.clone(),
        signature: signature.to_string(),
    };
    let payload = serde_json::to_vec(&request)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
    let request_path = update_dir.join("tracey.supervisor.request.json");
    update::write_atomic(&request_path, &payload).await
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
    update::to_hex(hash.as_bytes())
}
