//! Core event model used across sensors, telemetry, swarm, and storage paths.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    SystemMetric,
    NetworkFlow,
    UserAction,
    AutomationAction,
    Observability,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Weight used to bias downstream risk scoring by severity class.
    pub fn weight(self) -> f64 {
        match self {
            Severity::Low => 0.7,
            Severity::Medium => 0.9,
            Severity::High => 1.1,
            Severity::Critical => 1.3,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    pub id: u64,
    pub ts_ms: u64,
    pub source: String,
    pub kind: EventKind,
    pub signal: f64,
    pub severity: Severity,
    pub attributes: BTreeMap<String, String>,
}

impl Event {
    /// Creates a new event with the current timestamp and no attributes.
    pub fn new(
        id: u64,
        source: impl Into<String>,
        kind: EventKind,
        signal: f64,
        severity: Severity,
    ) -> Self {
        Self {
            id,
            ts_ms: now_ms(),
            source: source.into(),
            kind,
            signal,
            severity,
            attributes: BTreeMap::new(),
        }
    }

    /// Adds or replaces a string attribute on the event.
    pub fn with_attr(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }
}

/// Returns current wall-clock time in milliseconds since unix epoch.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_weights_are_ordered() {
        assert!(Severity::Low.weight() < Severity::Medium.weight());
        assert!(Severity::Medium.weight() < Severity::High.weight());
        assert!(Severity::High.weight() < Severity::Critical.weight());
    }

    #[test]
    fn with_attr_inserts_attribute() {
        let event =
            Event::new(1, "unit", EventKind::Observability, 0.2, Severity::Low).with_attr("k", "v");
        assert_eq!(event.attributes.get("k").map(String::as_str), Some("v"));
    }

    #[test]
    fn now_ms_is_non_zero() {
        assert!(now_ms() > 0);
    }
}
