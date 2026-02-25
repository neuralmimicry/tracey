use crate::event::now_ms;
use crate::security::Action;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct TuningConfig {
    pub enabled: bool,
    pub target_alert_rate: f64,
    pub adjustment_rate: f64,
    pub min_threshold: f64,
    pub max_threshold: f64,
    pub window_ms: u64,
}

impl Default for TuningConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            target_alert_rate: 0.08,
            adjustment_rate: 0.05,
            min_threshold: 0.55,
            max_threshold: 0.95,
            window_ms: 10_000,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TuningUpdate {
    pub ts_ms: u64,
    pub old_threshold: f64,
    pub new_threshold: f64,
    pub alert_rate: f64,
    pub target_rate: f64,
    pub reason: String,
}

pub struct AdaptiveTuner {
    config: TuningConfig,
    window_start: Instant,
    total: u64,
    alerted: u64,
    threshold: f64,
}

impl AdaptiveTuner {
    pub fn new(config: TuningConfig, initial_threshold: f64) -> Self {
        Self {
            window_start: Instant::now(),
            total: 0,
            alerted: 0,
            threshold: initial_threshold,
            config,
        }
    }

    pub fn observe(&mut self, action: Action) -> Option<TuningUpdate> {
        self.total = self.total.saturating_add(1);
        if action.is_alerting() {
            self.alerted = self.alerted.saturating_add(1);
        }

        if self.window_start.elapsed() < Duration::from_millis(self.config.window_ms) {
            return None;
        }

        let alert_rate = if self.total == 0 {
            0.0
        } else {
            self.alerted as f64 / self.total as f64
        };

        let error = alert_rate - self.config.target_alert_rate;
        let adjustment = error * self.config.adjustment_rate;
        let old_threshold = self.threshold;
        self.threshold = (self.threshold + adjustment)
            .clamp(self.config.min_threshold, self.config.max_threshold);

        let update = TuningUpdate {
            ts_ms: now_ms(),
            old_threshold,
            new_threshold: self.threshold,
            alert_rate,
            target_rate: self.config.target_alert_rate,
            reason: "adaptive threshold tuning".to_string(),
        };

        self.window_start = Instant::now();
        self.total = 0;
        self.alerted = 0;

        Some(update)
    }

    pub fn threshold(&self) -> f64 {
        self.threshold
    }
}
