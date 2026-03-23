use crate::bus::EventBus;
use crate::config::Config;
use crate::event::{Event, EventKind, Severity};
use crate::shutdown::ShutdownListener;
use crate::storage::Storage;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static EVENT_COUNTER: AtomicU64 = AtomicU64::new(1);

pub struct SimulatedSensor {
    name: String,
    kind: EventKind,
    base: f64,
    jitter: f64,
    anomaly_rate: f64,
    anomaly_boost: f64,
}

impl SimulatedSensor {
    pub fn new(
        name: impl Into<String>,
        kind: EventKind,
        base: f64,
        jitter: f64,
        anomaly_rate: f64,
        anomaly_boost: f64,
    ) -> Self {
        Self {
            name: name.into(),
            kind,
            base,
            jitter,
            anomaly_rate,
            anomaly_boost,
        }
    }

    pub async fn run(
        self,
        bus: EventBus,
        storage: Storage,
        config: Config,
        mut shutdown: ShutdownListener,
    ) {
        let mut prng = Prng::new(seed_from_name(&self.name));
        let mut interval = tokio::time::interval(Duration::from_millis(config.event_rate_ms));
        loop {
            tokio::select! {
                _ = shutdown.wait() => {
                    tracing::info!(sensor = %self.name, "sensor shutting down");
                    break;
                }
                _ = interval.tick() => {
                    let event = self.generate_event(&mut prng);
                    bus.publish(event.clone());
                    storage.record_event(event).await;
                }
            }
        }
    }

    fn generate_event(&self, prng: &mut Prng) -> Event {
        let jitter = (prng.next_f64() - 0.5) * 2.0 * self.jitter;
        let mut signal = self.base + jitter;
        let anomaly = prng.next_f64() < self.anomaly_rate;
        let severity = if anomaly {
            let spike = self.anomaly_boost * (0.6 + prng.next_f64());
            signal += spike;
            Severity::High
        } else {
            Severity::Medium
        };

        let id = EVENT_COUNTER.fetch_add(1, Ordering::Relaxed);
        Event::new(id, self.name.clone(), self.kind, signal, severity)
            .with_attr("anomaly", anomaly.to_string())
    }
}

pub fn spawn_default_sensors(
    bus: EventBus,
    storage: Storage,
    config: Config,
    shutdown: ShutdownListener,
) {
    let sensors = vec![
        SimulatedSensor::new("system_cpu", EventKind::SystemMetric, 0.45, 0.12, 0.04, 0.6),
        SimulatedSensor::new(
            "network_flow",
            EventKind::NetworkFlow,
            0.35,
            0.18,
            0.05,
            0.7,
        ),
        SimulatedSensor::new("user_actions", EventKind::UserAction, 0.25, 0.2, 0.03, 0.5),
        SimulatedSensor::new(
            "automation",
            EventKind::AutomationAction,
            0.3,
            0.15,
            0.04,
            0.65,
        ),
    ];

    for sensor in sensors {
        let bus = bus.clone();
        let storage = storage.clone();
        let cfg = config.clone();
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            sensor.run(bus, storage, cfg, shutdown).await;
        });
    }
}

#[derive(Clone)]
struct Prng {
    state: u64,
}

impl Prng {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        // LCG parameters from Numerical Recipes
        self.state = self.state.wrapping_mul(6364136223846793005).wrapping_add(1);
        self.state
    }

    fn next_f64(&mut self) -> f64 {
        let value = self.next_u64() >> 11;
        (value as f64) / ((1u64 << 53) as f64)
    }
}

fn seed_from_name(name: &str) -> u64 {
    let mut hash = 1469598103934665603u64;
    for byte in name.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(1099511628211);
    }
    hash
}
