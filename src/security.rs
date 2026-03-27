//! Action policy mapping risk/confidence scores into response actions.
//!
//! This is a core safety boundary: any stricter response must pass both
//! confidence gating and threshold ordering.

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
    /// Returns true when the action triggers operator-visible handling.
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
    /// Decides the response action for a risk/confidence pair.
    ///
    /// Confidence is checked first to avoid acting on low-quality signals.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn low_confidence_forces_monitor() {
        let policy = ActionPolicy::default();
        let action = policy.decide(1.0, policy.min_confidence - 0.01);
        assert_eq!(action, Action::Monitor);
    }

    #[test]
    fn thresholds_map_to_expected_actions() {
        let policy = ActionPolicy::default();
        let c = policy.min_confidence;
        assert_eq!(
            policy.decide(policy.alert_threshold - 0.001, c),
            Action::Monitor
        );
        assert_eq!(policy.decide(policy.alert_threshold, c), Action::Alert);
        assert_eq!(
            policy.decide(policy.throttle_threshold, c),
            Action::Throttle
        );
        assert_eq!(policy.decide(policy.isolate_threshold, c), Action::Isolate);
        assert_eq!(
            policy.decide(policy.shutdown_threshold, c),
            Action::Shutdown
        );
    }
}
