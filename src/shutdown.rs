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
    pub fn new() -> (Self, ShutdownListener) {
        let (tx, rx) = watch::channel(false);
        (Self { tx }, ShutdownListener { rx })
    }

    pub fn trigger(&self) {
        let _ = self.tx.send(true);
    }
}

impl ShutdownListener {
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
    let Some(path) = path else { return; };
    let Some(token) = token else { return; };

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
