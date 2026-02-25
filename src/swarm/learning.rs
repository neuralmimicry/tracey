use crate::event::{Event, EventKind};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct OnlineStats {
    pub count: u64,
    pub mean: f64,
    pub m2: f64,
}

impl OnlineStats {
    pub fn update(&mut self, value: f64) {
        self.count += 1;
        let delta = value - self.mean;
        self.mean += delta / self.count as f64;
        let delta2 = value - self.mean;
        self.m2 += delta * delta2;
    }

    pub fn variance(&self) -> f64 {
        if self.count < 2 {
            0.0
        } else {
            self.m2 / (self.count - 1) as f64
        }
    }

    pub fn stddev(&self) -> f64 {
        self.variance().sqrt()
    }

    pub fn merge(&mut self, other: OnlineStats, alpha: f64) {
        if other.count == 0 {
            return;
        }
        if self.count == 0 {
            *self = other;
            return;
        }
        let blended_mean = self.mean * (1.0 - alpha) + other.mean * alpha;
        let blended_var = self.variance() * (1.0 - alpha) + other.variance() * alpha;
        self.mean = blended_mean;
        self.m2 = blended_var * (self.count.max(1) as f64).max(1.0);
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LearningSnapshot {
    pub stats: Vec<(EventKind, OnlineStats)>,
}

#[derive(Clone, Debug)]
pub struct Score {
    pub risk: f64,
    pub confidence: f64,
}

#[derive(Clone, Debug)]
pub struct AdaptiveScorer {
    stats: HashMap<EventKind, OnlineStats>,
    min_samples: u64,
    focus: Option<EventKind>,
    focus_boost: f64,
}

impl AdaptiveScorer {
    pub fn new(min_samples: u64) -> Self {
        Self {
            stats: HashMap::new(),
            min_samples,
            focus: None,
            focus_boost: 1.0,
        }
    }

    pub fn set_focus(&mut self, focus: Option<EventKind>, boost: f64) {
        self.focus = focus;
        self.focus_boost = boost.clamp(1.0, 1.8);
    }

    pub fn merge_snapshot(&mut self, snapshot: &LearningSnapshot, alpha: f64) {
        for (kind, incoming) in &snapshot.stats {
            let entry = self.stats.entry(*kind).or_default();
            entry.merge(*incoming, alpha);
        }
    }

    pub fn snapshot(&self) -> LearningSnapshot {
        let stats = self.stats.iter().map(|(k, v)| (*k, *v)).collect();
        LearningSnapshot { stats }
    }

    pub fn score_and_update(&mut self, event: &Event) -> Score {
        let stats = self.stats.entry(event.kind).or_default();
        let stddev = stats.stddev().max(0.05);
        let z = if stats.count < self.min_samples {
            0.0
        } else {
            (event.signal - stats.mean) / stddev
        };

        let mut risk = sigmoid(z.abs()) * event.severity.weight();
        if self.focus == Some(event.kind) {
            risk *= self.focus_boost;
        }
        risk = risk.clamp(0.0, 1.0);

        let confidence = (stats.count as f64 / (self.min_samples as f64)).clamp(0.0, 1.0);
        stats.update(event.signal);

        Score { risk, confidence }
    }
}

fn sigmoid(x: f64) -> f64 {
    1.0 / (1.0 + (-x).exp())
}
