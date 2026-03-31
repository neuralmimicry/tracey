//! Online adaptive scoring model with fuzzy Type-n refinement.

use crate::config::FuzzyConfig;
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
    /// Updates running moments using Welford's algorithm.
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
    pub telemetry: FuzzyTelemetry,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FuzzyTelemetry {
    pub order: u8,
    pub z_abs: f64,
    pub core_risk: f64,
    pub interval_width: f64,
    pub edge_membership: f64,
    pub security_context: f64,
    pub metric_context: f64,
    pub aarnn_context: f64,
    pub learned_confidence: f64,
}

#[derive(Clone, Debug)]
pub struct AdaptiveScorer {
    stats: HashMap<EventKind, OnlineStats>,
    last_signal: HashMap<EventKind, f64>,
    min_samples: u64,
    focus: Option<EventKind>,
    focus_boost: f64,
    fuzzy: FuzzyConfig,
}

impl AdaptiveScorer {
    /// Creates an adaptive scorer keyed by event kind.
    pub fn new(min_samples: u64, fuzzy: FuzzyConfig) -> Self {
        Self {
            stats: HashMap::new(),
            last_signal: HashMap::new(),
            min_samples,
            focus: None,
            focus_boost: 1.0,
            fuzzy,
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

    /// Scores an event and updates per-kind baseline statistics.
    pub fn score_and_update(&mut self, event: &Event) -> Score {
        let (count, mean, stddev) = {
            let stats = self.stats.entry(event.kind).or_default();
            (stats.count, stats.mean, stats.stddev().max(0.05))
        };

        let learned_confidence = (count as f64 / (self.min_samples.max(1) as f64)).clamp(0.0, 1.0);
        let raw_z = if count == 0 {
            0.0
        } else {
            (event.signal - mean) / stddev
        };
        let z_abs = (raw_z * (0.35 + 0.65 * learned_confidence)).abs();

        let previous_signal = self.last_signal.get(&event.kind).copied().unwrap_or(mean);
        let delta_membership = right_shoulder((event.signal - previous_signal).abs(), 0.05, 0.45);
        let edge_membership = triangle(z_abs, 0.55, 1.45, 2.45).max(delta_membership * 0.6);
        let severity_membership = ((event.severity.weight() - 0.7) / 0.6).clamp(0.0, 1.0);
        let security_membership = security_context(event);
        let metric_membership = metric_context(event);
        let aarnn_membership = if is_aarnn_event(event) { 1.0 } else { 0.0 };

        let (core_risk, interval_width) = if self.fuzzy.enabled {
            let type1 = self.type1_risk(
                z_abs,
                edge_membership,
                delta_membership,
                security_membership,
                metric_membership,
                severity_membership,
            );

            let volatility = (stddev / (mean.abs() + 0.2)).clamp(0.0, 1.0);
            let ambiguity = 1.0 - (2.0 * type1 - 1.0).abs();
            let uncertainty = self.fuzzy.uncertainty
                * (0.5 * (1.0 - learned_confidence) + 0.25 * volatility + 0.25 * ambiguity);

            self.type_n_refine(
                type1,
                uncertainty,
                edge_membership,
                security_membership,
                metric_membership,
                aarnn_membership,
            )
        } else {
            (sigmoid(z_abs), 0.0)
        };

        let mut risk = (core_risk * event.severity.weight()).clamp(0.0, 1.0);
        if self.focus == Some(event.kind) {
            risk *= self.focus_boost;
        }
        risk = risk.clamp(0.0, 1.0);

        let confidence = if self.fuzzy.enabled {
            let interval_confidence = (1.0 - interval_width * 1.2).clamp(0.0, 1.0);
            (learned_confidence * 0.7 + interval_confidence * 0.3).clamp(0.0, 1.0)
        } else {
            learned_confidence
        };

        let telemetry = FuzzyTelemetry {
            order: if self.fuzzy.enabled {
                self.fuzzy.order.max(1)
            } else {
                0
            },
            z_abs,
            core_risk,
            interval_width,
            edge_membership,
            security_context: security_membership,
            metric_context: metric_membership,
            aarnn_context: aarnn_membership,
            learned_confidence,
        };

        let stats = self.stats.entry(event.kind).or_default();
        stats.update(event.signal);
        self.last_signal.insert(event.kind, event.signal);

        Score {
            risk,
            confidence,
            telemetry,
        }
    }

    fn type1_risk(
        &self,
        z_abs: f64,
        edge_membership: f64,
        novelty_membership: f64,
        security_membership: f64,
        metric_membership: f64,
        severity_membership: f64,
    ) -> f64 {
        let normal = left_shoulder(z_abs, 0.25, 1.0);
        let suspicious = triangle(z_abs, 0.70, 1.70, 3.00);
        let anomalous = right_shoulder(z_abs, 1.80, 3.30);

        let anomaly_strength = anomalous.max((suspicious * 0.72) + (edge_membership * 0.28));
        let contextual = (0.34 * novelty_membership
            + 0.28 * security_membership
            + 0.22 * metric_membership
            + 0.16 * severity_membership)
            .clamp(0.0, 1.0);
        let suppressed = anomaly_strength * (1.0 - normal * 0.35);

        let security_pull =
            (self.fuzzy.security_weight * security_membership * 0.25).clamp(0.0, 0.25);
        let metric_pull = (metric_membership * 0.16).clamp(0.0, 0.16);
        (suppressed * (0.74 + security_pull + metric_pull * 0.5)
            + contextual * (0.26 + security_pull * 0.7 + metric_pull))
            .clamp(0.0, 1.0)
    }

    fn type_n_refine(
        &self,
        base_risk: f64,
        uncertainty: f64,
        edge_membership: f64,
        security_membership: f64,
        metric_membership: f64,
        aarnn_membership: f64,
    ) -> (f64, f64) {
        let order = self.fuzzy.order.max(1);
        if order <= 1 {
            return (base_risk.clamp(0.0, 1.0), 0.0);
        }

        let mut center = base_risk.clamp(0.0, 1.0);
        let mut span = uncertainty.clamp(0.0, 1.0) * 0.5;
        let mut interval_width = 0.0;
        let context_bias = (edge_membership * self.fuzzy.edge_bias
            + security_membership * self.fuzzy.security_weight
            + metric_membership * 0.35
            + aarnn_membership * self.fuzzy.aarnn_weight)
            .clamp(0.0, 1.0);

        for layer in 2..=order {
            let decay = 1.0 / layer as f64;
            let layer_span = (span * decay).clamp(0.0, 0.49);
            let lower = (center - layer_span * (1.0 - context_bias * 0.5)).clamp(0.0, 1.0);
            let upper = (center + layer_span * (1.0 + context_bias * 0.8)).clamp(0.0, 1.0);
            interval_width = upper - lower;

            let optimistic_pull = (0.5 + context_bias * 0.35).clamp(0.0, 1.0);
            center = (lower * (1.0 - optimistic_pull) + upper * optimistic_pull).clamp(0.0, 1.0);
            span = layer_span;
        }

        (center, interval_width)
    }
}

fn sigmoid(x: f64) -> f64 {
    1.0 / (1.0 + (-x).exp())
}

fn is_aarnn_event(event: &Event) -> bool {
    event.source.eq_ignore_ascii_case("aarnn")
        || event.attributes.contains_key("aarnn_output_index")
}

fn security_context(event: &Event) -> f64 {
    let mut score: f64 = 0.0;
    let source_lower = event.source.to_ascii_lowercase();
    if source_lower.contains("security") || source_lower.contains("refiner") {
        score += 0.20;
    }
    if is_aarnn_event(event) {
        score += 0.20;
    }
    if event.attributes.contains_key("cve") {
        score += 0.22;
    }
    if event.attributes.contains_key("cvss") {
        score += 0.20;
    }
    if event.attributes.contains_key("finding_id") {
        score += 0.12;
    }
    if let Some(value) = event.attributes.get("finding_severity") {
        score += match value.trim().to_ascii_lowercase().as_str() {
            "critical" => 0.30,
            "high" => 0.24,
            "medium" => 0.16,
            "low" => 0.10,
            _ => 0.08,
        };
    }
    if let Some(value) = event.attributes.get("anomaly") {
        if value.eq_ignore_ascii_case("true") {
            score += 0.16;
        }
    }
    score.clamp(0.0, 1.0)
}

fn metric_context(event: &Event) -> f64 {
    let Some(metric) = event.attributes.get("metric").map(String::as_str) else {
        return 0.0;
    };

    let signal = event.signal.clamp(0.0, 1.0);
    let mut score = 0.0;
    match metric {
        "gpu_power_w" => {
            score += right_shoulder(signal, 0.55, 0.88) * 0.32;
        }
        "gpu_clock_graphics_mhz" => {
            score += right_shoulder(signal, 0.50, 0.85) * 0.24;
        }
        "gpu_clock_memory_mhz" => {
            score += right_shoulder(signal, 0.55, 0.88) * 0.20;
        }
        "gpu_fan_speed_percent" => {
            score += right_shoulder(signal, 0.70, 0.92) * 0.18;
        }
        "gpu_encoder_util_percent" => {
            score += right_shoulder(signal, 0.35, 0.75) * 0.30;
        }
        "gpu_decoder_util_percent" => {
            score += right_shoulder(signal, 0.45, 0.85) * 0.22;
        }
        "gpu_mem_used_bytes" | "mem_app_used" | "swap_used" => {
            score += right_shoulder(signal, 0.72, 0.92) * 0.24;
        }
        "mem_used" => {
            score += right_shoulder(signal, 0.75, 0.94) * 0.18;
        }
        "mem_bufcache" => {
            score += triangle(signal, 0.10, 0.45, 0.85) * 0.08;
        }
        _ => {}
    }

    if metric.starts_with("gpu_") {
        score += 0.05;
    }
    if event.source.eq_ignore_ascii_case("embedded") {
        score += 0.03;
    }
    score.clamp(0.0, 1.0)
}

fn left_shoulder(x: f64, start: f64, end: f64) -> f64 {
    if x <= start {
        1.0
    } else if x >= end {
        0.0
    } else {
        (end - x) / (end - start)
    }
}

fn right_shoulder(x: f64, start: f64, end: f64) -> f64 {
    if x <= start {
        0.0
    } else if x >= end {
        1.0
    } else {
        (x - start) / (end - start)
    }
}

fn triangle(x: f64, left: f64, center: f64, right: f64) -> f64 {
    if x <= left || x >= right {
        0.0
    } else if x <= center {
        (x - left) / (center - left)
    } else {
        (right - x) / (right - center)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Severity;

    fn scorer_with_order(order: u8) -> AdaptiveScorer {
        let mut fuzzy = FuzzyConfig::default();
        fuzzy.order = order;
        AdaptiveScorer::new(8, fuzzy)
    }

    fn warmup_kind(scorer: &mut AdaptiveScorer, kind: EventKind) {
        for i in 0..48u64 {
            let signal = 0.46 + ((i % 7) as f64) * 0.015;
            let event = Event::new(i + 1, "baseline", kind, signal, Severity::Medium);
            let _ = scorer.score_and_update(&event);
        }
    }

    fn warmup(scorer: &mut AdaptiveScorer) {
        warmup_kind(scorer, EventKind::Observability);
    }

    #[test]
    fn deeper_type_n_boosts_aarnn_edge_case_risk() {
        let mut shallow = scorer_with_order(1);
        let mut deep = scorer_with_order(5);
        warmup(&mut shallow);
        warmup(&mut deep);

        let event = Event::new(
            9_001,
            "aarnn",
            EventKind::Observability,
            0.59,
            Severity::High,
        )
        .with_attr("aarnn_output_index", "7");

        let shallow_score = shallow.score_and_update(&event);
        let deep_score = deep.score_and_update(&event);
        assert!(
            deep_score.risk > shallow_score.risk,
            "expected deeper type-n fuzzy order to increase edge-case risk (deep={}, shallow={})",
            deep_score.risk,
            shallow_score.risk
        );
    }

    #[test]
    fn security_context_increases_risk_for_same_signal() {
        let mut plain = scorer_with_order(3);
        let mut enriched = scorer_with_order(3);
        warmup(&mut plain);
        warmup(&mut enriched);

        let plain_event = Event::new(
            9_101,
            "refiner_security_feed",
            EventKind::Observability,
            0.57,
            Severity::Medium,
        );
        let enriched_event = Event::new(
            9_101,
            "refiner_security_feed",
            EventKind::Observability,
            0.57,
            Severity::Medium,
        )
        .with_attr("finding_severity", "critical")
        .with_attr("cvss", "9.8")
        .with_attr("cve", "CVE-2026-12345");

        let plain_score = plain.score_and_update(&plain_event);
        let enriched_score = enriched.score_and_update(&enriched_event);
        assert!(
            enriched_score.risk > plain_score.risk,
            "expected security context to increase risk (enriched={}, plain={})",
            enriched_score.risk,
            plain_score.risk
        );
    }

    #[test]
    fn embedded_metric_context_increases_risk_for_same_signal() {
        let mut plain = scorer_with_order(3);
        let mut enriched = scorer_with_order(3);
        warmup_kind(&mut plain, EventKind::SystemMetric);
        warmup_kind(&mut enriched, EventKind::SystemMetric);

        let plain_event = Event::new(
            9_201,
            "embedded",
            EventKind::SystemMetric,
            0.68,
            Severity::Medium,
        )
        .with_attr("metric", "gpu_mem_total_bytes");
        let enriched_event = Event::new(
            9_202,
            "embedded",
            EventKind::SystemMetric,
            0.68,
            Severity::Medium,
        )
        .with_attr("metric", "gpu_encoder_util_percent")
        .with_attr("gpu_id", "nvidia:0");

        let plain_score = plain.score_and_update(&plain_event);
        let enriched_score = enriched.score_and_update(&enriched_event);
        assert!(
            enriched_score.risk > plain_score.risk,
            "expected metric-aware fuzzy context to increase risk (enriched={}, plain={})",
            enriched_score.risk,
            plain_score.risk
        );
        assert!(enriched_score.telemetry.metric_context > plain_score.telemetry.metric_context);
    }
}
