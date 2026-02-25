use crate::event::{Event, EventKind, Severity, now_ms};
use crate::security::{Action, ActionPolicy};
use crate::governance::{GovernanceConfig, GovernanceVote, Posture};
use crate::shutdown::ShutdownListener;
use crate::swarm::learning::AdaptiveScorer;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc, watch};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Assessment {
    pub event_id: u64,
    pub agent_id: u32,
    pub ts_ms: u64,
    pub kind: EventKind,
    pub severity: Severity,
    pub signal: f64,
    pub risk: f64,
    pub confidence: f64,
    pub recommended: Action,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SwarmDirective {
    pub focus_kind: Option<EventKind>,
    pub boost: f64,
    pub reason: String,
}

impl Default for SwarmDirective {
    fn default() -> Self {
        Self {
            focus_kind: None,
            boost: 1.0,
            reason: "baseline".into(),
        }
    }
}

pub struct Agent {
    id: u32,
    receiver: broadcast::Receiver<Event>,
    assessment_tx: mpsc::Sender<Assessment>,
    learning_rx: watch::Receiver<crate::swarm::LearningSnapshot>,
    directive_rx: watch::Receiver<SwarmDirective>,
    scorer: AdaptiveScorer,
    policy: ActionPolicy,
    merge_alpha: f64,
    governance_tx: mpsc::Sender<GovernanceVote>,
    governance_cfg: GovernanceConfig,
    risk_ema: f64,
    confidence_ema: f64,
    rebel_last_ms: u64,
    rebel_streak: u32,
    prng_state: u64,
}

impl Agent {
    pub fn new(
        id: u32,
        receiver: broadcast::Receiver<Event>,
        assessment_tx: mpsc::Sender<Assessment>,
        learning_rx: watch::Receiver<crate::swarm::LearningSnapshot>,
        directive_rx: watch::Receiver<SwarmDirective>,
        scorer: AdaptiveScorer,
        policy: ActionPolicy,
        merge_alpha: f64,
        governance_tx: mpsc::Sender<GovernanceVote>,
        governance_cfg: GovernanceConfig,
    ) -> Self {
        Self {
            id,
            receiver,
            assessment_tx,
            learning_rx,
            directive_rx,
            scorer,
            policy,
            merge_alpha,
            governance_tx,
            governance_cfg,
            risk_ema: 0.0,
            confidence_ema: 0.0,
            rebel_last_ms: 0,
            rebel_streak: 0,
            prng_state: seed_prng(id),
        }
    }

    pub async fn run(mut self, mut shutdown: ShutdownListener) {
        let mut vote_tick = tokio::time::interval(std::time::Duration::from_millis(
            self.governance_cfg.vote_interval_ms,
        ));
        loop {
            tokio::select! {
                _ = shutdown.wait() => {
                    tracing::info!(agent_id = self.id, "agent shutting down");
                    break;
                }
                _ = vote_tick.tick() => {
                    self.emit_governance_vote().await;
                }
                changed = self.learning_rx.changed() => {
                    if changed.is_ok() {
                        let snapshot = self.learning_rx.borrow().clone();
                        self.scorer.merge_snapshot(&snapshot, self.merge_alpha);
                    }
                }
                changed = self.directive_rx.changed() => {
                    if changed.is_ok() {
                        let directive = self.directive_rx.borrow().clone();
                        self.scorer.set_focus(directive.focus_kind, directive.boost);
                    }
                }
                message = self.receiver.recv() => {
                    match message {
                        Ok(event) => {
                            self.handle_event(event).await;
                        }
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            tracing::warn!(agent_id = self.id, skipped, "agent lagged behind event stream");
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            break;
                        }
                    }
                }
            }
        }
    }

    async fn handle_event(&mut self, event: Event) {
        let score = self.scorer.score_and_update(&event);
        self.update_risk_ema(score.risk, score.confidence);
        let recommended = self.policy.decide(score.risk, score.confidence);
        let assessment = Assessment {
            event_id: event.id,
            agent_id: self.id,
            ts_ms: now_ms(),
            kind: event.kind,
            severity: event.severity,
            signal: event.signal,
            risk: score.risk,
            confidence: score.confidence,
            recommended,
        };
        if self.assessment_tx.send(assessment).await.is_err() {
            tracing::warn!(agent_id = self.id, "assessment channel closed");
        }
    }

    fn update_risk_ema(&mut self, risk: f64, confidence: f64) {
        let alpha = 0.15;
        self.risk_ema = (1.0 - alpha) * self.risk_ema + alpha * risk;
        self.confidence_ema = (1.0 - alpha) * self.confidence_ema + alpha * confidence;
    }

    async fn emit_governance_vote(&mut self) {
        if !self.governance_cfg.enabled {
            return;
        }
        let mut posture = Posture::from_risk(self.risk_ema, &self.governance_cfg);
        if self.should_rebel() {
            posture = posture.rebel_flip();
        }
        let vote = GovernanceVote {
            agent_id: self.id,
            ts_ms: crate::event::now_ms(),
            posture,
            confidence: self.confidence_ema.clamp(0.0, 1.0),
        };
        let _ = self.governance_tx.send(vote).await;
    }

    fn should_rebel(&mut self) -> bool {
        let cfg = &self.governance_cfg.rebel;
        if !cfg.enabled {
            return false;
        }
        let now = crate::event::now_ms();
        if self.rebel_last_ms != 0 && now.saturating_sub(self.rebel_last_ms) < cfg.cooldown_ms {
            return false;
        }
        if self.rebel_streak >= cfg.max_streak {
            return false;
        }
        let chance = next_f64(&mut self.prng_state);
        if chance < cfg.probability {
            self.rebel_last_ms = now;
            self.rebel_streak = self.rebel_streak.saturating_add(1);
            return true;
        }
        if self.rebel_last_ms != 0 && now.saturating_sub(self.rebel_last_ms) >= cfg.cooldown_ms {
            self.rebel_streak = 0;
        }
        false
    }
}

fn seed_prng(id: u32) -> u64 {
    let seed = crate::event::now_ms() ^ ((id as u64) << 32);
    seed ^ 0x9E3779B97F4A7C15u64
}

fn next_f64(state: &mut u64) -> f64 {
    // xorshift64*
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    let value = x >> 11;
    (value as f64) / ((1u64 << 53) as f64)
}
