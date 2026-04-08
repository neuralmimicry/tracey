use crate::autoscaler::ContinuumAutoscalerSnapshot;
use crate::continuum_assessment::ContinuumAssessmentSnapshot;
use crate::continuum_telemetry::ContinuumTelemetrySnapshot;
use crate::event::now_ms;
use crate::loader_threat::LoaderThreatSnapshot;
use crate::slurm::SlurmSnapshot;
use crate::tracey_guard::TraceyGuardStatusSnapshot;
use serde::{Deserialize, Serialize};

const MAX_SIGNALS: usize = 4;
const MAX_RECOMMENDATIONS: usize = 6;
const MAX_TEXT_LEN: usize = 120;
const TELEMETRY_FRESH_MS: u64 = 15_000;
const TELEMETRY_STALE_MS: u64 = 180_000;
const ASSESSMENT_FRESH_MS: u64 = 300_000;
const ASSESSMENT_STALE_MS: u64 = 1_800_000;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct ContinuumLoopPhaseSnapshot {
    pub status: String,
    pub score: f64,
    pub headline: String,
    pub signals: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct ContinuumLoopRecommendation {
    pub stage: String,
    pub priority: String,
    pub action: String,
    pub reason: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct ContinuumLoopSnapshot {
    pub ts_ms: u64,
    pub enabled: bool,
    pub mode: String,
    pub overall_score: f64,
    pub readiness_score: f64,
    pub placement_score: f64,
    pub gpu_headroom_pct: Option<f64>,
    pub requested_remote_nodes: usize,
    pub active_remote_nodes: usize,
    pub pressure_signal_count: usize,
    pub assessment_completion_pct: f64,
    pub compromise_risk: f64,
    pub fuzzy_confidence: f64,
    pub next_action: String,
    pub plan: ContinuumLoopPhaseSnapshot,
    pub ramp: ContinuumLoopPhaseSnapshot,
    pub optimize: ContinuumLoopPhaseSnapshot,
    pub repeat: ContinuumLoopPhaseSnapshot,
    pub recommendations: Vec<ContinuumLoopRecommendation>,
}

pub fn derive_continuum_loop_snapshot(
    autoscaler: Option<&ContinuumAutoscalerSnapshot>,
    assessment: Option<&ContinuumAssessmentSnapshot>,
    telemetry: Option<&ContinuumTelemetrySnapshot>,
    tracey_guard: Option<&TraceyGuardStatusSnapshot>,
    loader_threats: Option<&LoaderThreatSnapshot>,
    slurm: Option<&SlurmSnapshot>,
) -> ContinuumLoopSnapshot {
    let now = now_ms();
    let assessment_enabled = assessment.map(|snapshot| snapshot.enabled).unwrap_or(false);
    let compromise_risk = clamp01(
        assessment
            .map(|snapshot| snapshot.summary.compromise_risk)
            .unwrap_or_default(),
    );
    let compromise_confidence = clamp01(
        assessment
            .map(|snapshot| snapshot.summary.compromise_confidence)
            .unwrap_or_default(),
    );
    let fuzzy_confidence = clamp01(
        assessment
            .map(|snapshot| snapshot.summary.fuzzy_confidence)
            .unwrap_or_default(),
    );
    let completion = clamp01(
        assessment
            .map(|snapshot| snapshot.summary.cycle_completion_pct)
            .unwrap_or_default(),
    );
    let cve_matches = assessment
        .map(|snapshot| snapshot.summary.cve_matches)
        .unwrap_or_default();
    let kev_matches = assessment
        .map(|snapshot| snapshot.summary.kev_matches)
        .unwrap_or_default();
    let fuzzy_order = assessment
        .map(|snapshot| snapshot.summary.fuzzy_order)
        .unwrap_or_default();
    let recommended_action = assessment
        .map(|snapshot| display_action(&snapshot.summary.recommended_action))
        .unwrap_or_default();
    let assessment_last_error = assessment
        .map(|snapshot| truncate_text(&snapshot.summary.last_error, MAX_TEXT_LEN))
        .unwrap_or_default();
    let assessment_progress = assessment.and_then(|snapshot| snapshot.progress.as_ref());
    let assessment_last_report_ms = assessment_progress
        .map(|progress| progress.last_report_ms)
        .unwrap_or_else(|| assessment.map(|snapshot| snapshot.ts_ms).unwrap_or(0));
    let assessment_age_ms = age_ms(now, assessment_last_report_ms);
    let assessment_stale = assessment_enabled
        && (assessment_age_ms > ASSESSMENT_STALE_MS
            || (!assessment_last_error.is_empty() && assessment_age_ms > ASSESSMENT_FRESH_MS));

    let cpu_usage_pct = telemetry
        .and_then(|snapshot| snapshot.server.cpu_usage_pct)
        .unwrap_or_default();
    let mem_usage_pct = telemetry
        .and_then(|snapshot| snapshot.server.mem_used_pct)
        .unwrap_or_default();
    let gpu_utilization_pct = telemetry
        .and_then(|snapshot| snapshot.server.gpu_utilization_avg_pct)
        .unwrap_or(cpu_usage_pct.max(mem_usage_pct));
    let gpu_headroom_ratio = clamp01((100.0 - gpu_utilization_pct) / 100.0);
    let gpu_headroom_pct = telemetry.map(|_| gpu_headroom_ratio * 100.0);
    let gpu_temperature_max_c = telemetry
        .and_then(|snapshot| snapshot.server.gpu_temperature_max_c)
        .unwrap_or_default();
    let telemetry_recent_actions = telemetry
        .map(|snapshot| snapshot.server.recent_action_count)
        .unwrap_or_default();
    let telemetry_age_ms = telemetry
        .map(|snapshot| age_ms(now, snapshot.ts_ms))
        .unwrap_or(u64::MAX);
    let telemetry_stale = telemetry_age_ms > TELEMETRY_STALE_MS;
    let autonomy_risk = clamp01(
        telemetry
            .and_then(|snapshot| snapshot.server.autonomy_risk)
            .unwrap_or_default(),
    );
    let autonomy_action = telemetry
        .and_then(|snapshot| snapshot.server.autonomy_action.as_deref())
        .map(display_action)
        .unwrap_or_default();
    let gpu_count = telemetry
        .map(|snapshot| snapshot.gpus.len())
        .unwrap_or_default();

    let guard_quarantined = tracey_guard
        .map(|snapshot| snapshot.summary.quarantined_devices)
        .unwrap_or_default();
    let guard_total = tracey_guard
        .map(|snapshot| snapshot.summary.total_devices.max(1))
        .unwrap_or(1);
    let guard_failure_count = tracey_guard
        .map(|snapshot| snapshot.summary.total_failures)
        .unwrap_or_default();
    let guard_signal = clamp01(
        tracey_guard
            .map(|snapshot| snapshot.summary.scheduler_signal)
            .unwrap_or_default(),
    );

    let loader_blocked = loader_threats
        .map(|snapshot| {
            snapshot.summary.blocked_provider_count + snapshot.summary.blocked_artifact_count
        })
        .unwrap_or_default();
    let loader_risk = loader_threats
        .map(|snapshot| {
            snapshot
                .summary
                .highest_provider_risk
                .max(snapshot.summary.highest_artifact_risk)
        })
        .unwrap_or_default();

    let pressure_signals = autoscaler
        .map(|snapshot| snapshot.pressure_signals.clone())
        .unwrap_or_default();
    let pressure_signal_count = pressure_signals.len();
    let requested_remote_nodes = autoscaler
        .map(|snapshot| snapshot.requested_remote_nodes)
        .unwrap_or_default();
    let active_remote_nodes = autoscaler
        .map(|snapshot| snapshot.active_remote_nodes)
        .unwrap_or_default();
    let autoscaler_enabled = autoscaler.map(|snapshot| snapshot.enabled).unwrap_or(false);
    let autoscaler_role = autoscaler
        .map(|snapshot| truncate_text(&snapshot.controller_role, 24))
        .unwrap_or_default();
    let autoscaler_last_action = autoscaler
        .and_then(|snapshot| snapshot.last_action.as_deref())
        .map(|value| truncate_text(value, MAX_TEXT_LEN))
        .unwrap_or_default();

    let slurm_pending_jobs = slurm
        .map(|snapshot| snapshot.jobs_pending)
        .unwrap_or_default();
    let slurm_allocated_ratio = slurm
        .map(|snapshot| {
            if snapshot.nodes_total == 0 {
                0.0
            } else {
                snapshot.nodes_allocated as f64 / snapshot.nodes_total as f64
            }
        })
        .unwrap_or_default();

    let comm_failures = assessment
        .map(|snapshot| {
            snapshot.communication.consecutive_failures
                + snapshot.communication.plan_fetch_failures
                + snapshot.communication.report_failures
                + snapshot.communication.auth_failures
                + snapshot.communication.semantic_failures
        })
        .unwrap_or_default();

    let mut plan_signals = Vec::new();
    if assessment_enabled {
        push_signal(
            &mut plan_signals,
            format!(
                "risk {:.0}% @ conf {:.0}%",
                compromise_risk * 100.0,
                compromise_confidence * 100.0
            ),
        );
        if cve_matches > 0 || kev_matches > 0 {
            push_signal(
                &mut plan_signals,
                format!("{} CVE / {} KEV matches", cve_matches, kev_matches),
            );
        }
        push_signal(
            &mut plan_signals,
            format!(
                "cycle {:.0}% fuzzy order {}",
                completion * 100.0,
                fuzzy_order
            ),
        );
        if !assessment_last_error.is_empty() {
            push_signal(&mut plan_signals, assessment_last_error.clone());
        }
    } else {
        push_signal(
            &mut plan_signals,
            "external assessment disabled; using local signals",
        );
        push_signal(
            &mut plan_signals,
            format!("local cpu {:.0}% mem {:.0}%", cpu_usage_pct, mem_usage_pct),
        );
    }

    let plan_score = if assessment_enabled {
        clamp01(
            0.55 * (1.0 - compromise_risk)
                + 0.20 * fuzzy_confidence
                + 0.15 * completion
                + 0.10 * if comm_failures == 0 { 1.0 } else { 0.35 },
        )
    } else {
        clamp01(0.40 * (1.0 - autonomy_risk) + 0.35 * gpu_headroom_ratio + 0.25)
    };
    let plan_status = if !assessment_enabled {
        "local_only"
    } else if compromise_risk >= 0.80 || kev_matches > 0 {
        "constrained"
    } else if assessment_stale || comm_failures > 0 || !assessment_last_error.is_empty() {
        "degraded"
    } else if completion >= 0.65 {
        "ready"
    } else {
        "learning"
    };
    let plan_headline = if assessment_enabled {
        truncate_text(
            &format!(
                "{} | {} CVEs / {} KEVs | {:.0}% cycle",
                if recommended_action.is_empty() {
                    "monitor".to_string()
                } else {
                    recommended_action.clone()
                },
                cve_matches,
                kev_matches,
                completion * 100.0
            ),
            MAX_TEXT_LEN,
        )
    } else {
        "local telemetry plan only; no remote assessment cycle".to_string()
    };

    let mut ramp_signals = Vec::new();
    for signal in pressure_signals.iter().take(MAX_SIGNALS) {
        push_signal(&mut ramp_signals, signal.clone());
    }
    if slurm_pending_jobs > 0 {
        push_signal(
            &mut ramp_signals,
            format!("slurm pending {} jobs", slurm_pending_jobs),
        );
    }
    if !autoscaler_last_action.is_empty() {
        push_signal(&mut ramp_signals, autoscaler_last_action.clone());
    }
    if !autoscaler_role.is_empty() {
        push_signal(&mut ramp_signals, format!("controller {}", autoscaler_role));
    }

    let ramp_pressure = clamp01(
        pressure_signal_count as f64 * 0.22
            + requested_remote_nodes.saturating_sub(active_remote_nodes) as f64 * 0.18
            + if slurm_pending_jobs > 0 { 0.18 } else { 0.0 }
            + slurm_allocated_ratio * 0.16,
    );
    let ramp_score = clamp01(1.0 - ramp_pressure);
    let ramp_status = if pressure_signal_count > 0
        || requested_remote_nodes > active_remote_nodes
        || slurm_pending_jobs > 0
    {
        "active"
    } else if !autoscaler_enabled {
        "manual"
    } else if autoscaler_role.contains("standby") {
        "standby"
    } else {
        "steady"
    };
    let ramp_headline = truncate_text(
        &format!(
            "req {} active {} remote nodes",
            requested_remote_nodes, active_remote_nodes
        ),
        MAX_TEXT_LEN,
    );

    let temperature_penalty = if gpu_temperature_max_c >= 90.0 {
        1.0
    } else if gpu_temperature_max_c >= 82.0 {
        clamp01((gpu_temperature_max_c - 82.0) / 8.0)
    } else {
        0.0
    };
    let quarantine_penalty = clamp01(guard_quarantined as f64 / guard_total as f64);
    let loader_penalty = clamp01(loader_blocked as f64 / 4.0);
    let optimize_score = clamp01(
        0.40 * gpu_headroom_ratio
            + 0.25 * (1.0 - compromise_risk)
            + 0.15 * (1.0 - autonomy_risk)
            + 0.10 * (1.0 - temperature_penalty)
            + 0.10 * fuzzy_confidence
            - 0.08 * guard_signal
            - 0.12 * quarantine_penalty
            - 0.08 * loader_penalty,
    );

    let mut optimize_signals = Vec::new();
    push_signal(
        &mut optimize_signals,
        format!(
            "{} GPUs util {:.0}% headroom {:.0}%",
            gpu_count,
            gpu_utilization_pct,
            gpu_headroom_ratio * 100.0
        ),
    );
    push_signal(
        &mut optimize_signals,
        format!(
            "autonomy {:.0}% {}",
            autonomy_risk * 100.0,
            non_empty_or(&autonomy_action, "idle")
        ),
    );
    if guard_quarantined > 0 || guard_failure_count > 0 {
        push_signal(
            &mut optimize_signals,
            format!(
                "guard {} quarantined {} failures",
                guard_quarantined, guard_failure_count
            ),
        );
    }
    if loader_blocked > 0 {
        push_signal(
            &mut optimize_signals,
            format!("loader {} blocks", loader_blocked),
        );
    }

    let optimize_constrained = compromise_risk >= 0.80
        || quarantine_penalty >= 0.35
        || guard_signal >= 0.85
        || loader_risk >= 0.85
        || loader_blocked >= 4;
    let optimize_degraded = quarantine_penalty >= 0.10
        || guard_signal >= 0.60
        || loader_risk >= 0.55
        || loader_blocked > 0;
    let optimize_status = if optimize_constrained {
        "avoid"
    } else if optimize_score >= 0.72 {
        if optimize_degraded {
            "balanced"
        } else {
            "open"
        }
    } else if optimize_score >= 0.45 {
        if optimize_degraded {
            "tight"
        } else {
            "balanced"
        }
    } else {
        "tight"
    };
    let optimize_headline = truncate_text(
        &format!(
            "headroom {:.0}% | util {:.0}% | temp {:.0}C",
            gpu_headroom_ratio * 100.0,
            gpu_utilization_pct,
            gpu_temperature_max_c
        ),
        MAX_TEXT_LEN,
    );

    let telemetry_freshness =
        freshness_score(telemetry_age_ms, TELEMETRY_FRESH_MS, TELEMETRY_STALE_MS);
    let assessment_freshness = if assessment_enabled {
        freshness_score(assessment_age_ms, ASSESSMENT_FRESH_MS, ASSESSMENT_STALE_MS)
    } else {
        0.55
    };
    let activity_score = clamp01(telemetry_recent_actions.min(10) as f64 / 10.0);
    let repeat_score =
        clamp01(0.45 * telemetry_freshness + 0.35 * assessment_freshness + 0.20 * activity_score);

    let mut repeat_signals = Vec::new();
    push_signal(
        &mut repeat_signals,
        format!("telemetry {}", format_age_ms(telemetry_age_ms)),
    );
    if assessment_enabled {
        push_signal(
            &mut repeat_signals,
            format!("assessment {}", format_age_ms(assessment_age_ms)),
        );
    }
    push_signal(
        &mut repeat_signals,
        format!("{} recent actions", telemetry_recent_actions),
    );
    if guard_signal > 0.0 {
        push_signal(
            &mut repeat_signals,
            format!("guard scheduler {:.0}%", guard_signal * 100.0),
        );
    }

    let repeat_status = if telemetry_stale || assessment_stale {
        "stale"
    } else if telemetry_recent_actions > 0 || completion >= 0.50 {
        "learning"
    } else {
        "watch"
    };
    let repeat_headline = truncate_text(
        &format!(
            "telemetry {} | assessment {} | {} actions",
            format_age_ms(telemetry_age_ms),
            if assessment_enabled {
                format_age_ms(assessment_age_ms)
            } else {
                "n/a".to_string()
            },
            telemetry_recent_actions
        ),
        MAX_TEXT_LEN,
    );

    let readiness_score = clamp01((plan_score + repeat_score) / 2.0);
    let overall_score = clamp01(
        0.35 * plan_score + 0.25 * ramp_score + 0.30 * optimize_score + 0.10 * repeat_score,
    );

    let mut recommendations = Vec::new();
    if compromise_risk >= 0.80 {
        push_recommendation(
            &mut recommendations,
            "plan",
            "critical",
            non_empty_or(&recommended_action, "isolate host"),
            &format!(
                "compromise risk {:.0}% with {} KEV and {} CVE matches",
                compromise_risk * 100.0,
                kev_matches,
                cve_matches
            ),
        );
    } else if loader_blocked > 0 {
        push_recommendation(
            &mut recommendations,
            "plan",
            "high",
            "hold untrusted loader promotions",
            &format!(
                "loader threat intelligence recommends {} blocks",
                loader_blocked
            ),
        );
    }
    if pressure_signal_count > 0
        || requested_remote_nodes > active_remote_nodes
        || slurm_pending_jobs > 0
    {
        let ramp_action = if requested_remote_nodes > active_remote_nodes {
            format!(
                "complete {} pending remote recruits",
                requested_remote_nodes.saturating_sub(active_remote_nodes)
            )
        } else {
            "recruit additional capacity".to_string()
        };
        let ramp_reason = truncate_text(
            non_empty_or(
                pressure_signals
                    .first()
                    .map(|signal| signal.as_str())
                    .unwrap_or(""),
                &format!("slurm pending {} jobs", slurm_pending_jobs),
            ),
            MAX_TEXT_LEN,
        );
        push_recommendation(
            &mut recommendations,
            "ramp",
            if requested_remote_nodes > active_remote_nodes {
                "high"
            } else {
                "medium"
            },
            &ramp_action,
            &ramp_reason,
        );
    }
    if optimize_score >= 0.72
        && compromise_risk < 0.55
        && guard_quarantined == 0
        && loader_blocked == 0
    {
        push_recommendation(
            &mut recommendations,
            "optimize",
            "medium",
            "prefer for burst placement",
            &format!(
                "gpu headroom {:.0}% with autonomy risk {:.0}%",
                gpu_headroom_ratio * 100.0,
                autonomy_risk * 100.0
            ),
        );
    }
    if telemetry_stale || assessment_stale {
        push_recommendation(
            &mut recommendations,
            "repeat",
            "medium",
            "refresh loop inputs",
            &format!(
                "telemetry {} assessment {}",
                format_age_ms(telemetry_age_ms),
                if assessment_enabled {
                    format_age_ms(assessment_age_ms)
                } else {
                    "n/a".to_string()
                }
            ),
        );
    }
    if recommendations.is_empty() {
        push_recommendation(
            &mut recommendations,
            "repeat",
            "low",
            "hold steady",
            "no material pressure or compromise signals observed",
        );
    }

    let mode = if compromise_risk >= 0.80 || optimize_status == "avoid" {
        "constrained"
    } else if ramp_status == "active" {
        "ramping"
    } else if repeat_status == "stale" || plan_status == "degraded" {
        "degraded"
    } else if optimize_status == "open" {
        "ready"
    } else {
        "balanced"
    };

    ContinuumLoopSnapshot {
        ts_ms: now,
        enabled: telemetry.is_some() || assessment_enabled || autoscaler_enabled,
        mode: mode.to_string(),
        overall_score,
        readiness_score,
        placement_score: optimize_score,
        gpu_headroom_pct,
        requested_remote_nodes,
        active_remote_nodes,
        pressure_signal_count,
        assessment_completion_pct: completion,
        compromise_risk,
        fuzzy_confidence,
        next_action: recommendations
            .first()
            .map(|item| item.action.clone())
            .unwrap_or_else(|| "hold steady".to_string()),
        plan: ContinuumLoopPhaseSnapshot {
            status: plan_status.to_string(),
            score: plan_score,
            headline: plan_headline,
            signals: plan_signals,
        },
        ramp: ContinuumLoopPhaseSnapshot {
            status: ramp_status.to_string(),
            score: ramp_score,
            headline: ramp_headline,
            signals: ramp_signals,
        },
        optimize: ContinuumLoopPhaseSnapshot {
            status: optimize_status.to_string(),
            score: optimize_score,
            headline: optimize_headline,
            signals: optimize_signals,
        },
        repeat: ContinuumLoopPhaseSnapshot {
            status: repeat_status.to_string(),
            score: repeat_score,
            headline: repeat_headline,
            signals: repeat_signals,
        },
        recommendations,
    }
}

fn clamp01(value: f64) -> f64 {
    value.clamp(0.0, 1.0)
}

fn truncate_text(value: &str, max: usize) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let mut out = trimmed.to_string();
    if out.len() > max {
        out.truncate(max.saturating_sub(1));
        out.push('~');
    }
    out
}

fn display_action(value: &str) -> String {
    truncate_text(&value.replace('_', " "), 48)
}

fn non_empty_or<'a>(value: &'a str, fallback: &'a str) -> &'a str {
    if value.trim().is_empty() {
        fallback
    } else {
        value
    }
}

fn age_ms(now: u64, ts_ms: u64) -> u64 {
    if ts_ms == 0 || now <= ts_ms {
        0
    } else {
        now - ts_ms
    }
}

fn freshness_score(age_ms: u64, fresh_ms: u64, stale_ms: u64) -> f64 {
    if age_ms <= fresh_ms {
        1.0
    } else if age_ms >= stale_ms {
        0.15
    } else {
        let span = stale_ms.saturating_sub(fresh_ms).max(1) as f64;
        let offset = age_ms.saturating_sub(fresh_ms) as f64;
        clamp01(1.0 - 0.85 * (offset / span))
    }
}

fn format_age_ms(age_ms: u64) -> String {
    if age_ms < 1_000 {
        format!("{}ms", age_ms)
    } else if age_ms < 60_000 {
        format!("{}s", age_ms / 1_000)
    } else if age_ms < 3_600_000 {
        format!("{}m", age_ms / 60_000)
    } else {
        format!("{}h", age_ms / 3_600_000)
    }
}

fn push_signal(target: &mut Vec<String>, signal: impl Into<String>) {
    if target.len() >= MAX_SIGNALS {
        return;
    }
    let signal = truncate_text(&signal.into(), MAX_TEXT_LEN);
    if signal.is_empty() || target.iter().any(|existing| existing == &signal) {
        return;
    }
    target.push(signal);
}

fn push_recommendation(
    target: &mut Vec<ContinuumLoopRecommendation>,
    stage: &str,
    priority: &str,
    action: &str,
    reason: &str,
) {
    if target.len() >= MAX_RECOMMENDATIONS {
        return;
    }
    let action = truncate_text(action, 56);
    let reason = truncate_text(reason, MAX_TEXT_LEN);
    if action.is_empty() || reason.is_empty() {
        return;
    }
    if target
        .iter()
        .any(|item| item.stage == stage && item.action == action)
    {
        return;
    }
    target.push(ContinuumLoopRecommendation {
        stage: stage.to_string(),
        priority: priority.to_string(),
        action,
        reason,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::autoscaler::ContinuumAutoscalerSnapshot;
    use crate::continuum_assessment::{
        CompromiseAssessmentSummary, ContinuumAssessmentCommunicationSnapshot,
        ContinuumAssessmentSnapshot,
    };
    use crate::continuum_telemetry::{
        ContinuumIdentitySnapshot, ContinuumServerSnapshot, ContinuumTelemetrySnapshot,
    };
    use crate::loader_threat::{LoaderThreatSnapshot, LoaderThreatSummary};
    use crate::slurm::SlurmSnapshot;
    use crate::tracey_guard::{TraceyGuardStatusSnapshot, TraceyGuardSummary};

    #[test]
    fn constrained_snapshot_prioritizes_isolation() {
        let assessment = ContinuumAssessmentSnapshot {
            enabled: true,
            summary: CompromiseAssessmentSummary {
                status: "compromised".to_string(),
                compromise_risk: 0.91,
                compromise_confidence: 0.84,
                recommended_action: "isolate_host".to_string(),
                cve_matches: 12,
                kev_matches: 3,
                fuzzy_confidence: 0.76,
                fuzzy_order: 2,
                cycle_completion_pct: 0.88,
                ..CompromiseAssessmentSummary::default()
            },
            communication: ContinuumAssessmentCommunicationSnapshot::default(),
            ..ContinuumAssessmentSnapshot::default()
        };
        let telemetry = ContinuumTelemetrySnapshot {
            identity: ContinuumIdentitySnapshot {
                host: "host-a".to_string(),
                ..ContinuumIdentitySnapshot::default()
            },
            server: ContinuumServerSnapshot {
                cpu_usage_pct: Some(52.0),
                mem_used_pct: Some(48.0),
                gpu_utilization_avg_pct: Some(31.0),
                recent_action_count: 2,
                ..ContinuumServerSnapshot::default()
            },
            ..ContinuumTelemetrySnapshot::default()
        };

        let snapshot = derive_continuum_loop_snapshot(
            None,
            Some(&assessment),
            Some(&telemetry),
            None,
            None,
            None,
        );

        assert_eq!(snapshot.mode, "constrained");
        assert_eq!(snapshot.plan.status, "constrained");
        assert_eq!(snapshot.next_action, "isolate host");
        assert!(
            snapshot
                .recommendations
                .iter()
                .any(|item| item.stage == "plan" && item.priority == "critical")
        );
    }

    #[test]
    fn ramping_snapshot_surfaces_pressure_and_refresh() {
        let autoscaler = ContinuumAutoscalerSnapshot {
            enabled: true,
            controller_role: "leader".to_string(),
            requested_remote_nodes: 2,
            active_remote_nodes: 0,
            pressure_signals: vec!["slurm pending jobs 12 >= 1".to_string()],
            last_action: Some("queued two recruits".to_string()),
            ..ContinuumAutoscalerSnapshot::default()
        };
        let telemetry = ContinuumTelemetrySnapshot {
            ts_ms: now_ms().saturating_sub(240_000),
            server: ContinuumServerSnapshot {
                cpu_usage_pct: Some(83.0),
                mem_used_pct: Some(77.0),
                gpu_utilization_avg_pct: Some(79.0),
                recent_action_count: 0,
                ..ContinuumServerSnapshot::default()
            },
            ..ContinuumTelemetrySnapshot::default()
        };
        let guard = TraceyGuardStatusSnapshot {
            summary: TraceyGuardSummary {
                total_devices: 8,
                quarantined_devices: 1,
                total_failures: 6,
                scheduler_signal: 0.7,
                ..TraceyGuardSummary::default()
            },
            ..TraceyGuardStatusSnapshot::default()
        };
        let loader = LoaderThreatSnapshot {
            summary: LoaderThreatSummary {
                blocked_provider_count: 1,
                ..LoaderThreatSummary::default()
            },
            ..LoaderThreatSnapshot::default()
        };
        let slurm = SlurmSnapshot {
            nodes_total: 4,
            nodes_allocated: 4,
            jobs_pending: 12,
            ..SlurmSnapshot::default()
        };

        let snapshot = derive_continuum_loop_snapshot(
            Some(&autoscaler),
            None,
            Some(&telemetry),
            Some(&guard),
            Some(&loader),
            Some(&slurm),
        );

        assert_eq!(snapshot.mode, "ramping");
        assert_eq!(snapshot.ramp.status, "active");
        assert_eq!(snapshot.repeat.status, "stale");
        assert!(
            snapshot
                .recommendations
                .iter()
                .any(|item| item.stage == "ramp")
        );
        assert!(
            snapshot
                .recommendations
                .iter()
                .any(|item| item.stage == "repeat")
        );
    }
}
