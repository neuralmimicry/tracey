//! Coordinator logic that aggregates agent assessments into final decisions.
//!
//! It also owns governance vote processing, learning snapshot broadcast,
//! and optional adaptive threshold tuning.

use crate::config::Config;
use crate::coordination::Coordination;
use crate::event::{Event, EventKind, Severity, now_ms};
use crate::governance::{
    GovernanceConfig, GovernanceState, GovernanceUpdate, GovernanceVote, Posture,
};
use crate::security::{Action, ActionPolicy};
use crate::shutdown::ShutdownListener;
use crate::storage::Storage;
use crate::swarm::agent::{Assessment, SwarmDirective};
use crate::swarm::learning::AdaptiveScorer;
use crate::tuning::AdaptiveTuner;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, mpsc, watch};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Decision {
    pub event_id: u64,
    pub ts_ms: u64,
    pub kind: EventKind,
    pub action: Action,
    pub mean_risk: f64,
    pub mean_confidence: f64,
    pub telemetry: DecisionTelemetry,
    pub quorum: usize,
    pub agents: usize,
    pub reason: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DecisionTelemetry {
    pub fuzzy_order: u8,
    pub mean_z_abs: f64,
    pub mean_core_risk: f64,
    pub mean_interval_width: f64,
    pub mean_edge_membership: f64,
    pub mean_security_context: f64,
    pub mean_metric_context: f64,
    pub mean_aarnn_context: f64,
    pub mean_learned_confidence: f64,
}

struct Pending {
    first_seen: Instant,
    kind: EventKind,
    severity: Severity,
    assessments: Vec<Assessment>,
}

pub struct Coordinator {
    assessment_rx: mpsc::Receiver<Assessment>,
    governance_rx: mpsc::Receiver<GovernanceVote>,
    directive_tx: watch::Sender<SwarmDirective>,
    learning_tx: watch::Sender<crate::swarm::LearningSnapshot>,
    policy: ActionPolicy,
    base_decision_threshold: f64,
    decision_ttl: Duration,
    quorum: usize,
    learning_broadcast: Duration,
    directive_broadcast: Duration,
    storage: Storage,
    decision_tap: broadcast::Sender<Decision>,
    global_scorer: AdaptiveScorer,
    rolling_risk: HashMap<EventKind, f64>,
    tuner: Option<AdaptiveTuner>,
    governance_cfg: GovernanceConfig,
    governance_state: std::sync::Arc<tokio::sync::RwLock<GovernanceState>>,
    governance_votes: Vec<GovernanceVote>,
    coordination: Coordination,
    was_leader: bool,
}

impl Coordinator {
    /// Builds the coordinator with channels, policy, and governance context.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        assessment_rx: mpsc::Receiver<Assessment>,
        governance_rx: mpsc::Receiver<GovernanceVote>,
        directive_tx: watch::Sender<SwarmDirective>,
        learning_tx: watch::Sender<crate::swarm::LearningSnapshot>,
        policy: ActionPolicy,
        decision_threshold: f64,
        decision_ttl: Duration,
        quorum: usize,
        _active_response: bool,
        _shutdown_enabled: bool,
        learning_broadcast: Duration,
        directive_broadcast: Duration,
        storage: Storage,
        decision_tap: broadcast::Sender<Decision>,
        global_scorer: AdaptiveScorer,
        tuner: Option<AdaptiveTuner>,
        governance_cfg: GovernanceConfig,
        governance_state: std::sync::Arc<tokio::sync::RwLock<GovernanceState>>,
        coordination: Coordination,
    ) -> Self {
        Self {
            assessment_rx,
            governance_rx,
            directive_tx,
            learning_tx,
            policy,
            base_decision_threshold: decision_threshold,
            decision_ttl,
            quorum,
            learning_broadcast,
            directive_broadcast,
            storage,
            decision_tap,
            global_scorer,
            rolling_risk: HashMap::new(),
            tuner,
            governance_cfg,
            governance_state,
            governance_votes: Vec::new(),
            coordination,
            was_leader: false,
        }
    }

    /// Runs coordinator orchestration loops until shutdown.
    pub async fn run(mut self, mut shutdown: ShutdownListener) {
        let mut pending: HashMap<u64, Pending> = HashMap::new();
        let mut cleanup_tick = tokio::time::interval(Duration::from_millis(200));
        let mut governance_tick =
            tokio::time::interval(Duration::from_millis(self.governance_cfg.vote_interval_ms));
        let mut learning_tick = tokio::time::interval(self.learning_broadcast);
        let mut directive_tick = tokio::time::interval(self.directive_broadcast);

        loop {
            tokio::select! {
                _ = shutdown.wait() => {
                    tracing::info!("coordinator shutting down");
                    break;
                }
                Some(assessment) = self.assessment_rx.recv() => {
                    self.ingest_assessment(assessment, &mut pending).await;
                }
                Some(vote) = self.governance_rx.recv() => {
                    self.governance_votes.push(vote);
                }
                _ = cleanup_tick.tick() => {
                    self.flush_expired(&mut pending).await;
                }
                _ = governance_tick.tick() => {
                    self.process_governance().await;
                }
                _ = learning_tick.tick() => {
                    let leader = self.leader_info().await;
                    if leader.is_leader && leader.rank == 0 {
                        let snapshot = self.global_scorer.snapshot();
                        let _ = self.learning_tx.send(snapshot.clone());
                        self.storage.record_learning(snapshot).await;
                    }
                }
                _ = directive_tick.tick() => {
                    let leader = self.leader_info().await;
                    if leader.is_leader && leader.rank == 0 {
                        self.broadcast_directive();
                    }
                }
            }
        }
    }

    async fn ingest_assessment(
        &mut self,
        assessment: Assessment,
        pending: &mut HashMap<u64, Pending>,
    ) {
        let leader = self.leader_info().await;
        if !leader.is_leader {
            if self.was_leader {
                pending.clear();
                self.was_leader = false;
            }
            return;
        }
        self.was_leader = true;
        if !leader.handles_event(assessment.event_id) {
            return;
        }
        let event_id = assessment.event_id;
        let reached_quorum = {
            let entry = pending.entry(event_id).or_insert_with(|| Pending {
                first_seen: Instant::now(),
                kind: assessment.kind,
                severity: assessment.severity,
                assessments: Vec::new(),
            });
            entry.assessments.push(assessment);
            entry.assessments.len() >= self.quorum
        };

        if reached_quorum {
            if let Some(item) = pending.remove(&event_id) {
                self.finalize_decision(item).await;
            }
        }
    }

    async fn flush_expired(&mut self, pending: &mut HashMap<u64, Pending>) {
        let leader = self.leader_info().await;
        if !leader.is_leader {
            pending.clear();
            self.was_leader = false;
            return;
        }
        let mut expired = Vec::new();
        for (event_id, item) in pending.iter() {
            if item.first_seen.elapsed() >= self.decision_ttl {
                expired.push(*event_id);
            }
        }
        for event_id in expired {
            if let Some(item) = pending.remove(&event_id) {
                self.finalize_decision(item).await;
            }
        }
    }

    async fn finalize_decision(&mut self, pending: Pending) {
        let agents = pending.assessments.len();
        let mut risk_sum = 0.0;
        let mut conf_sum = 0.0;
        let mut signal_sum = 0.0;
        let mut z_abs_sum = 0.0;
        let mut core_risk_sum = 0.0;
        let mut interval_width_sum = 0.0;
        let mut edge_sum = 0.0;
        let mut security_sum = 0.0;
        let mut metric_sum = 0.0;
        let mut aarnn_sum = 0.0;
        let mut learned_confidence_sum = 0.0;
        let mut fuzzy_order = 0u8;
        for assessment in &pending.assessments {
            risk_sum += assessment.risk;
            conf_sum += assessment.confidence;
            signal_sum += assessment.signal;
            z_abs_sum += assessment.telemetry.z_abs;
            core_risk_sum += assessment.telemetry.core_risk;
            interval_width_sum += assessment.telemetry.interval_width;
            edge_sum += assessment.telemetry.edge_membership;
            security_sum += assessment.telemetry.security_context;
            metric_sum += assessment.telemetry.metric_context;
            aarnn_sum += assessment.telemetry.aarnn_context;
            learned_confidence_sum += assessment.telemetry.learned_confidence;
            fuzzy_order = fuzzy_order.max(assessment.telemetry.order);
        }
        let mean_risk = (risk_sum / agents as f64).clamp(0.0, 1.0);
        let mean_confidence = (conf_sum / agents as f64).clamp(0.0, 1.0);
        let mean_signal = signal_sum / agents as f64;
        let telemetry = DecisionTelemetry {
            fuzzy_order,
            mean_z_abs: z_abs_sum / agents as f64,
            mean_core_risk: core_risk_sum / agents as f64,
            mean_interval_width: interval_width_sum / agents as f64,
            mean_edge_membership: edge_sum / agents as f64,
            mean_security_context: security_sum / agents as f64,
            mean_metric_context: metric_sum / agents as f64,
            mean_aarnn_context: aarnn_sum / agents as f64,
            mean_learned_confidence: learned_confidence_sum / agents as f64,
        };

        let (decision_threshold, active_response, shutdown_enabled) =
            self.current_governance().await;
        let mut action = if mean_risk >= decision_threshold {
            self.policy.decide(mean_risk, mean_confidence)
        } else {
            Action::Monitor
        };
        action = enforce_response_mode(action, active_response, shutdown_enabled);

        let reason = build_reason(
            mean_risk,
            mean_confidence,
            &telemetry,
            agents,
            self.quorum,
            action,
            pending.kind,
        );

        let decision = Decision {
            event_id: pending.assessments[0].event_id,
            ts_ms: now_ms(),
            kind: pending.kind,
            action,
            mean_risk,
            mean_confidence,
            telemetry,
            quorum: self.quorum,
            agents,
            reason,
        };

        self.storage.record_decision(decision.clone()).await;
        let _ = self.decision_tap.send(decision.clone());
        self.update_learning(pending.kind, pending.severity, mean_signal)
            .await;
        self.update_directive_scores(pending.kind, mean_risk);

        if let Some(tuner) = self.tuner.as_mut() {
            if let Some(update) = tuner.observe(action) {
                self.base_decision_threshold = tuner.threshold();
                self.update_governance_base_threshold().await;
                tracing::info!(
                    old = update.old_threshold,
                    new = update.new_threshold,
                    rate = update.alert_rate,
                    "adaptive threshold update"
                );
                self.storage.record_tuning(update).await;
            }
        }

        if action == Action::Shutdown && shutdown_enabled {
            tracing::error!("shutdown action requested; integrate with your containment pipeline");
        }
    }

    async fn current_governance(&self) -> (f64, bool, bool) {
        let state = self.governance_state.read().await;
        (
            state.decision_threshold,
            state.active_response,
            state.shutdown_enabled,
        )
    }

    async fn leader_info(&self) -> LeaderInfo {
        let role = self.coordination.role_handle();
        let role = role.read().await.clone();
        LeaderInfo {
            is_leader: role.is_coordinator,
            rank: role.leader_rank,
            count: role.leader_count,
        }
    }

    async fn update_governance_base_threshold(&self) {
        if !self.governance_cfg.enabled {
            return;
        }
        let cfg = Config::load();
        let mut state = self.governance_state.write().await;
        state.set_base_threshold(self.base_decision_threshold, &cfg);
    }

    async fn process_governance(&mut self) {
        if !self.leader_info().await.is_leader {
            return;
        }
        if !self.governance_cfg.enabled {
            return;
        }

        let now = crate::event::now_ms();
        let ttl = self.governance_cfg.vote_ttl_ms;
        self.governance_votes
            .retain(|vote| now.saturating_sub(vote.ts_ms) <= ttl);

        let total_votes = self.governance_votes.len();
        if total_votes < self.governance_cfg.quorum {
            return;
        }

        let mut buckets: HashMap<Posture, f64> = HashMap::new();
        let mut confidence_sum = 0.0;
        for vote in &self.governance_votes {
            if vote.confidence < self.governance_cfg.min_confidence {
                continue;
            }
            let entry = buckets.entry(vote.posture).or_insert(0.0);
            *entry += vote.confidence.max(0.01);
            confidence_sum += vote.confidence.max(0.01);
        }

        if confidence_sum == 0.0 {
            return;
        }

        let (winner, winner_weight) = buckets
            .iter()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(k, v)| (*k, *v))
            .unwrap_or((Posture::Balanced, 0.0));

        let support_ratio = winner_weight / confidence_sum;
        if support_ratio < self.governance_cfg.decision_threshold {
            return;
        }

        let cfg = Config::load();
        {
            let mut state = self.governance_state.write().await;
            if state.posture != winner {
                state.apply_posture(winner, &cfg);
                let update = GovernanceUpdate::new(
                    winner,
                    support_ratio,
                    total_votes,
                    "swarm posture decision",
                );
                self.storage.record_governance(update).await;
            }
        }
    }

    async fn update_learning(&mut self, kind: EventKind, severity: Severity, signal: f64) {
        let event = Event {
            id: 0,
            ts_ms: now_ms(),
            source: "coordinator".to_string(),
            kind,
            signal,
            severity,
            attributes: BTreeMap::new(),
        };
        let _ = self.global_scorer.score_and_update(&event);
    }

    fn update_directive_scores(&mut self, kind: EventKind, mean_risk: f64) {
        let score = self.rolling_risk.entry(kind).or_insert(0.0);
        *score = (*score * 0.85) + (mean_risk * 0.15);
    }

    fn broadcast_directive(&mut self) {
        let focus_kind = self
            .rolling_risk
            .iter()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(kind, _)| *kind);

        let directive = SwarmDirective {
            focus_kind,
            boost: 1.35,
            reason: "hotspot focus".into(),
        };
        let _ = self.directive_tx.send(directive);
    }
}

fn enforce_response_mode(action: Action, active_response: bool, shutdown_enabled: bool) -> Action {
    if !active_response {
        return match action {
            Action::Monitor | Action::Alert => action,
            _ => Action::Alert,
        };
    }
    if !shutdown_enabled && action == Action::Shutdown {
        return Action::Isolate;
    }
    action
}

struct LeaderInfo {
    is_leader: bool,
    rank: usize,
    count: usize,
}

impl LeaderInfo {
    fn handles_event(&self, event_id: u64) -> bool {
        if !self.is_leader || self.count == 0 || self.rank == usize::MAX {
            return false;
        }
        if self.count <= 1 {
            return true;
        }
        (event_id % self.count as u64) as usize == self.rank
    }
}

fn build_reason(
    mean_risk: f64,
    mean_confidence: f64,
    telemetry: &DecisionTelemetry,
    agents: usize,
    quorum: usize,
    action: Action,
    kind: EventKind,
) -> String {
    format!(
        "risk={:.2} confidence={:.2} core={:.2} uncertainty={:.2} sec={:.2} metric={:.2} aarnn={:.2} order={} agents={}/{} action={:?} kind={:?}",
        mean_risk,
        mean_confidence,
        telemetry.mean_core_risk,
        telemetry.mean_interval_width,
        telemetry.mean_security_context,
        telemetry.mean_metric_context,
        telemetry.mean_aarnn_context,
        telemetry.fuzzy_order,
        agents,
        quorum,
        action,
        kind
    )
}
