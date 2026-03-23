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

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
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

    pub fn with_attr(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
