//! Swarm governance policy for posture decisions and feature gating.
//!
//! Governance translates aggregated votes into runtime mode changes
//! (threshold, response posture, update/telemetry allowances).

use crate::config::Config;
use crate::event::now_ms;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct GovernanceConfig {
    pub enabled: bool,
    pub vote_interval_ms: u64,
    pub vote_ttl_ms: u64,
    pub quorum: usize,
    pub decision_threshold: f64,
    pub min_confidence: f64,
    pub relaxed_risk: f64,
    pub strict_risk: f64,
    pub lockdown_risk: f64,
    pub rebel: RebelConfig,
}

impl Default for GovernanceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            vote_interval_ms: 1500,
            vote_ttl_ms: 5000,
            quorum: 3,
            decision_threshold: 0.6,
            min_confidence: 0.5,
            relaxed_risk: 0.2,
            strict_risk: 0.7,
            lockdown_risk: 0.9,
            rebel: RebelConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct RebelConfig {
    pub enabled: bool,
    pub probability: f64,
    pub max_streak: u32,
    pub cooldown_ms: u64,
}

impl Default for RebelConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            probability: 0.03,
            max_streak: 2,
            cooldown_ms: 10_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Posture {
    Relaxed,
    Balanced,
    Strict,
    Lockdown,
}

impl Posture {
    /// Maps mean risk to a posture bucket using configured cutoffs.
    pub fn from_risk(risk: f64, cfg: &GovernanceConfig) -> Self {
        if risk >= cfg.lockdown_risk {
            Posture::Lockdown
        } else if risk >= cfg.strict_risk {
            Posture::Strict
        } else if risk <= cfg.relaxed_risk {
            Posture::Relaxed
        } else {
            Posture::Balanced
        }
    }

    /// Deterministic adversarial vote flip used for rebel simulation.
    pub fn rebel_flip(self) -> Self {
        match self {
            Posture::Relaxed => Posture::Lockdown,
            Posture::Balanced => Posture::Strict,
            Posture::Strict => Posture::Balanced,
            Posture::Lockdown => Posture::Relaxed,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovernanceVote {
    pub agent_id: u32,
    pub ts_ms: u64,
    pub posture: Posture,
    pub confidence: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovernanceState {
    pub posture: Posture,
    pub base_decision_threshold: f64,
    pub decision_threshold: f64,
    pub active_response: bool,
    pub shutdown_enabled: bool,
    pub update_enabled: bool,
    pub telemetry_enabled: bool,
    pub telemetry_allow_remote: bool,
    pub prometheus_enabled: bool,
    pub otlp_enabled: bool,
    pub discovery_enabled: bool,
    pub asset_feed_enabled: bool,
    pub coordination_enabled: bool,
}

impl GovernanceState {
    /// Initializes governance state from static config defaults.
    pub fn from_config(cfg: &Config) -> Self {
        let mut state = Self {
            posture: Posture::Balanced,
            base_decision_threshold: cfg.decision_threshold,
            decision_threshold: cfg.decision_threshold,
            active_response: cfg.active_response,
            shutdown_enabled: cfg.shutdown_enabled,
            update_enabled: cfg.update.enabled,
            telemetry_enabled: cfg.telemetry.enabled,
            telemetry_allow_remote: cfg.telemetry.allow_remote,
            prometheus_enabled: cfg.telemetry.prometheus_enabled,
            otlp_enabled: cfg.telemetry.otlp.enabled,
            discovery_enabled: cfg.discovery.enabled,
            asset_feed_enabled: cfg.asset_feed.enabled,
            coordination_enabled: cfg.coordination.enabled,
        };
        state.apply_posture(state.posture, cfg);
        state
    }

    /// Sets and reapplies base threshold used by posture transforms.
    pub fn set_base_threshold(&mut self, base: f64, cfg: &Config) {
        self.base_decision_threshold = base;
        self.apply_posture(self.posture, cfg);
    }

    /// Applies posture-derived policy toggles.
    pub fn apply_posture(&mut self, posture: Posture, cfg: &Config) {
        self.posture = posture;

        let mut threshold = self.base_decision_threshold;
        threshold = match posture {
            Posture::Relaxed => threshold + 0.05,
            Posture::Balanced => threshold,
            Posture::Strict => threshold - 0.05,
            Posture::Lockdown => threshold - 0.1,
        };
        self.decision_threshold = threshold.clamp(0.1, 0.99);

        self.active_response =
            cfg.active_response && matches!(posture, Posture::Strict | Posture::Lockdown);
        self.shutdown_enabled = cfg.shutdown_enabled && posture == Posture::Lockdown;

        self.update_enabled =
            cfg.update.enabled && !matches!(posture, Posture::Strict | Posture::Lockdown);
        self.telemetry_enabled = cfg.telemetry.enabled;
        self.telemetry_allow_remote = cfg.telemetry.allow_remote && posture == Posture::Relaxed;
        self.prometheus_enabled = cfg.telemetry.prometheus_enabled;
        self.otlp_enabled = cfg.telemetry.otlp.enabled;
        self.discovery_enabled = cfg.discovery.enabled;
        self.asset_feed_enabled = cfg.asset_feed.enabled;
        self.coordination_enabled = cfg.coordination.enabled;
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovernanceUpdate {
    pub ts_ms: u64,
    pub posture: Posture,
    pub support_ratio: f64,
    pub total_votes: usize,
    pub reason: String,
}

impl GovernanceUpdate {
    /// Creates a governance update stamped with current wall time.
    pub fn new(
        posture: Posture,
        support_ratio: f64,
        total_votes: usize,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            ts_ms: now_ms(),
            posture,
            support_ratio,
            total_votes,
            reason: reason.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn posture_from_risk_respects_thresholds() {
        let cfg = GovernanceConfig::default();
        assert_eq!(Posture::from_risk(0.0, &cfg), Posture::Relaxed);
        assert_eq!(Posture::from_risk(0.5, &cfg), Posture::Balanced);
        assert_eq!(Posture::from_risk(cfg.strict_risk, &cfg), Posture::Strict);
        assert_eq!(
            Posture::from_risk(cfg.lockdown_risk, &cfg),
            Posture::Lockdown
        );
    }

    #[test]
    fn apply_posture_updates_feature_gates() {
        let mut cfg = Config::default();
        cfg.active_response = true;
        cfg.shutdown_enabled = true;
        cfg.update.enabled = true;
        cfg.telemetry.enabled = true;
        cfg.telemetry.allow_remote = true;

        let mut state = GovernanceState::from_config(&cfg);

        state.apply_posture(Posture::Strict, &cfg);
        assert!(state.active_response);
        assert!(!state.shutdown_enabled);
        assert!(!state.update_enabled);
        assert!(!state.telemetry_allow_remote);

        state.apply_posture(Posture::Lockdown, &cfg);
        assert!(state.active_response);
        assert!(state.shutdown_enabled);
        assert!(!state.update_enabled);

        state.apply_posture(Posture::Relaxed, &cfg);
        assert!(!state.active_response);
        assert!(state.update_enabled);
        assert!(state.telemetry_allow_remote);
    }

    #[test]
    fn set_base_threshold_clamps_resulting_threshold() {
        let cfg = Config::default();
        let mut state = GovernanceState::from_config(&cfg);
        state.apply_posture(Posture::Lockdown, &cfg);
        state.set_base_threshold(1.5, &cfg);
        assert!((0.1..=0.99).contains(&state.decision_threshold));
    }
}
