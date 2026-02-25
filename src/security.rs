use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Monitor,
    Alert,
    Throttle,
    Isolate,
    Shutdown,
}

impl Action {
    pub fn is_alerting(self) -> bool {
        matches!(
            self,
            Action::Alert | Action::Throttle | Action::Isolate | Action::Shutdown
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ActionPolicy {
    pub alert_threshold: f64,
    pub throttle_threshold: f64,
    pub isolate_threshold: f64,
    pub shutdown_threshold: f64,
    pub min_confidence: f64,
}

impl Default for ActionPolicy {
    fn default() -> Self {
        Self {
            alert_threshold: 0.65,
            throttle_threshold: 0.78,
            isolate_threshold: 0.88,
            shutdown_threshold: 0.97,
            min_confidence: 0.55,
        }
    }
}

impl ActionPolicy {
    pub fn decide(&self, risk: f64, confidence: f64) -> Action {
        if confidence < self.min_confidence {
            return Action::Monitor;
        }
        if risk >= self.shutdown_threshold {
            Action::Shutdown
        } else if risk >= self.isolate_threshold {
            Action::Isolate
        } else if risk >= self.throttle_threshold {
            Action::Throttle
        } else if risk >= self.alert_threshold {
            Action::Alert
        } else {
            Action::Monitor
        }
    }
}
