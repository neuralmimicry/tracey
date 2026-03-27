//! Cooperative shutdown primitives used by all long-running tasks.
//!
//! `Shutdown` is the trigger handle, while `ShutdownListener` provides an awaitable
//! watcher clone for each task.

use tokio::sync::watch;

#[derive(Clone)]
pub struct Shutdown {
    tx: watch::Sender<bool>,
}

#[derive(Clone)]
pub struct ShutdownListener {
    rx: watch::Receiver<bool>,
}

impl Shutdown {
    /// Returns a trigger/listener pair.
    pub fn new() -> (Self, ShutdownListener) {
        let (tx, rx) = watch::channel(false);
        (Self { tx }, ShutdownListener { rx })
    }

    /// Signals shutdown to all listeners.
    pub fn trigger(&self) {
        let _ = self.tx.send(true);
    }
}

impl ShutdownListener {
    /// Waits until shutdown is triggered or sender closes.
    pub async fn wait(&mut self) {
        while !*self.rx.borrow() {
            if self.rx.changed().await.is_err() {
                break;
            }
        }
    }
}

pub fn spawn_shutdown_watcher(shutdown: Shutdown) {
    let path = std::env::var("TRACEY_SHUTDOWN_PATH").ok();
    let token = std::env::var("TRACEY_SHUTDOWN_TOKEN").ok();
    let Some(path) = path else {
        return;
    };
    let Some(token) = token else {
        return;
    };

    tokio::spawn(async move {
        loop {
            match tokio::fs::read_to_string(&path).await {
                Ok(contents) if contents.trim() == token => {
                    let _ = tokio::fs::remove_file(&path).await;
                    shutdown.trigger();
                    break;
                }
                _ => {}
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn listener_unblocks_after_trigger() {
        let (shutdown, mut listener) = Shutdown::new();
        let waiter = tokio::spawn(async move {
            listener.wait().await;
        });
        tokio::time::sleep(Duration::from_millis(5)).await;
        shutdown.trigger();
        tokio::time::timeout(Duration::from_millis(200), waiter)
            .await
            .expect("listener should complete after trigger")
            .expect("wait task should not panic");
    }
}
