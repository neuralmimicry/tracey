//! Safe AI-assisted lab emulation schema, policy, and correlation helpers.
//!
//! This module is deliberately narrow: models may propose only typed
//! `ControlledAction` values, every proposal must pass scope policy, and every
//! execution result is represented as evidence. It is not a shell broker.

use crate::event::now_ms;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Actor {
    Tracey,
    RedTeam,
    HumanOperator,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum EventSource {
    NetworkSensor,
    EndpointSensor,
    ApplicationLog,
    IdentitySystem,
    RedTeam,
    Tracey,
    LabController,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SecurityEventType {
    AssetObserved,
    ServiceObserved,
    AuthenticationAttempt,
    AuthenticationSucceeded,
    UnexpectedConnection,
    PrivilegeChangeEmulated,
    LateralMovementEmulated,
    DataStagingEmulated,
    ExfiltrationEmulated,
    DefensiveAction,
    PolicyViolation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum ControlledAction {
    ObserveAsset,
    ObserveService,
    TestSeededCredential,
    RequestSyntheticFile,
    EmulateLateralConnection,
    PlaceBenignMarker,
    StageSyntheticDataset,
    TransferSyntheticDatasetToSink,
    StartEvidenceCapture,
    IncreaseTelemetry,
    BlockLabConnection,
    QuarantineLabHost,
    DisableSeededCredential,
    IsolateContainer,
    RestoreSnapshot,
}

impl ControlledAction {
    pub fn risk_level(self) -> RiskLevel {
        match self {
            ControlledAction::ObserveAsset
            | ControlledAction::ObserveService
            | ControlledAction::StartEvidenceCapture
            | ControlledAction::IncreaseTelemetry => RiskLevel::Observation,
            ControlledAction::TestSeededCredential
            | ControlledAction::RequestSyntheticFile
            | ControlledAction::PlaceBenignMarker
            | ControlledAction::DisableSeededCredential => RiskLevel::Low,
            ControlledAction::EmulateLateralConnection
            | ControlledAction::StageSyntheticDataset
            | ControlledAction::TransferSyntheticDatasetToSink
            | ControlledAction::BlockLabConnection
            | ControlledAction::QuarantineLabHost
            | ControlledAction::IsolateContainer
            | ControlledAction::RestoreSnapshot => RiskLevel::Medium,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ControlledAction::ObserveAsset => "ObserveAsset",
            ControlledAction::ObserveService => "ObserveService",
            ControlledAction::TestSeededCredential => "TestSeededCredential",
            ControlledAction::RequestSyntheticFile => "RequestSyntheticFile",
            ControlledAction::EmulateLateralConnection => "EmulateLateralConnection",
            ControlledAction::PlaceBenignMarker => "PlaceBenignMarker",
            ControlledAction::StageSyntheticDataset => "StageSyntheticDataset",
            ControlledAction::TransferSyntheticDatasetToSink => "TransferSyntheticDatasetToSink",
            ControlledAction::StartEvidenceCapture => "StartEvidenceCapture",
            ControlledAction::IncreaseTelemetry => "IncreaseTelemetry",
            ControlledAction::BlockLabConnection => "BlockLabConnection",
            ControlledAction::QuarantineLabHost => "QuarantineLabHost",
            ControlledAction::DisableSeededCredential => "DisableSeededCredential",
            ControlledAction::IsolateContainer => "IsolateContainer",
            ControlledAction::RestoreSnapshot => "RestoreSnapshot",
        }
    }
}

pub fn all_controlled_actions() -> Vec<ControlledAction> {
    vec![
        ControlledAction::ObserveAsset,
        ControlledAction::ObserveService,
        ControlledAction::TestSeededCredential,
        ControlledAction::RequestSyntheticFile,
        ControlledAction::EmulateLateralConnection,
        ControlledAction::PlaceBenignMarker,
        ControlledAction::StageSyntheticDataset,
        ControlledAction::TransferSyntheticDatasetToSink,
        ControlledAction::StartEvidenceCapture,
        ControlledAction::IncreaseTelemetry,
        ControlledAction::BlockLabConnection,
        ControlledAction::QuarantineLabHost,
        ControlledAction::DisableSeededCredential,
        ControlledAction::IsolateContainer,
        ControlledAction::RestoreSnapshot,
    ]
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum RiskLevel {
    Observation,
    Low,
    Medium,
    High,
}

impl RiskLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            RiskLevel::Observation => "observation",
            RiskLevel::Low => "low",
            RiskLevel::Medium => "medium",
            RiskLevel::High => "high",
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AssetReference {
    pub host: Option<String>,
    pub ip: Option<String>,
    pub role: Option<String>,
    pub labels: Vec<String>,
}

impl AssetReference {
    pub fn label(&self) -> String {
        self.host
            .clone()
            .or_else(|| self.ip.clone())
            .or_else(|| self.role.clone())
            .unwrap_or_else(|| "lab-target".to_string())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub event_id: String,
    pub timestamp_ms: u64,
    pub scenario_id: String,
    pub source: EventSource,
    pub event_type: SecurityEventType,
    pub host: Option<String>,
    pub source_ip: Option<String>,
    pub destination_ip: Option<String>,
    pub destination_port: Option<u16>,
    pub severity_hint: u8,
    pub confidence: f32,
    pub attributes: BTreeMap<String, serde_json::Value>,
    pub evidence_reference: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActionProposal {
    pub action_id: String,
    pub scenario_id: String,
    pub actor: Actor,
    pub target: AssetReference,
    pub action: ControlledAction,
    pub rationale: String,
    pub expected_observation: String,
    pub confidence: f32,
    pub risk_level: RiskLevel,
    pub requires_approval: bool,
}

impl ActionProposal {
    pub fn new(
        scenario_id: impl Into<String>,
        actor: Actor,
        target: AssetReference,
        action: ControlledAction,
        rationale: impl Into<String>,
        expected_observation: impl Into<String>,
    ) -> Self {
        let risk_level = action.risk_level();
        Self {
            action_id: format!("act-{}", now_ms()),
            scenario_id: scenario_id.into(),
            actor,
            target,
            action,
            rationale: rationale.into(),
            expected_observation: expected_observation.into(),
            confidence: 0.70,
            risk_level,
            requires_approval: matches!(risk_level, RiskLevel::Medium | RiskLevel::High),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActionDecision {
    pub decision_id: String,
    pub action_id: String,
    pub scenario_id: String,
    pub actor: Actor,
    pub action: ControlledAction,
    pub permitted: bool,
    pub approval_required: bool,
    pub dry_run: bool,
    pub reason: String,
    pub decided_at_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActionResult {
    pub action_id: String,
    pub scenario_id: String,
    pub action: ControlledAction,
    pub executed: bool,
    pub dry_run: bool,
    pub started_at_ms: u64,
    pub finished_at_ms: u64,
    pub summary: String,
    pub observations: Vec<SecurityEvent>,
    pub rollback_hint: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct EvidenceBundle {
    pub scenario_id: String,
    pub evidence_root: PathBuf,
    pub event_timeline: Vec<SecurityEvent>,
    pub offensive_actions: Vec<ActionProposal>,
    pub defensive_actions: Vec<ActionProposal>,
    pub policy_decisions: Vec<ActionDecision>,
    pub model_interactions: Vec<ModelInteraction>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ModelInteraction {
    pub interaction_id: String,
    pub timestamp_ms: u64,
    pub actor: Actor,
    pub model_name: String,
    pub model_version: String,
    pub prompt_template_version: String,
    pub response_hash: String,
    pub validation_result: String,
    pub selected_action_id: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ScenarioDefinition {
    pub id: String,
    pub name: String,
    pub objective: ScenarioObjective,
    pub preconditions: Vec<String>,
    pub allowed_actions: Vec<ControlledAction>,
    pub targets: Vec<AssetReference>,
    pub success_conditions: BTreeMap<String, Vec<String>>,
    pub stop_conditions: Vec<String>,
    pub maximum_duration_minutes: u64,
    pub cleanup: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ScenarioObjective {
    pub description: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct AiLabConfig {
    pub enabled: bool,
    pub evidence_root: PathBuf,
    pub policy: ScopePolicy,
    pub continuum_report_url: Option<String>,
}

impl Default for AiLabConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            evidence_root: PathBuf::from("evidence"),
            policy: ScopePolicy::default(),
            continuum_report_url: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ScopePolicy {
    pub lab_id: String,
    pub allowed_networks: Vec<String>,
    pub allowed_hosts: Vec<String>,
    pub deny_public_addresses: bool,
    pub deny_default_route: bool,
    pub require_lab_token: bool,
    pub lab_token: Option<String>,
    pub require_snapshot_before_execution: bool,
    pub default_dry_run: bool,
    pub maximum_concurrent_actions: usize,
    pub maximum_scenario_duration_minutes: u64,
    pub maximum_requests_per_second: u32,
    pub stop_on_policy_violation: bool,
    pub approval: ApprovalPolicy,
    pub allowed_actions: Vec<ControlledAction>,
    pub kill_switch_path: Option<PathBuf>,
}

impl Default for ScopePolicy {
    fn default() -> Self {
        Self {
            lab_id: "tracey-demo-01".to_string(),
            allowed_networks: vec!["10.77.0.0/24".to_string()],
            allowed_hosts: vec![
                "attacker-ai".to_string(),
                "tracey".to_string(),
                "user-workstation".to_string(),
                "file-server".to_string(),
                "web-application".to_string(),
                "telemetry-server".to_string(),
                "evidence-sink".to_string(),
            ],
            deny_public_addresses: true,
            deny_default_route: true,
            require_lab_token: true,
            lab_token: None,
            require_snapshot_before_execution: true,
            default_dry_run: true,
            maximum_concurrent_actions: 2,
            maximum_scenario_duration_minutes: 20,
            maximum_requests_per_second: 2,
            stop_on_policy_violation: true,
            approval: ApprovalPolicy::default(),
            allowed_actions: all_controlled_actions(),
            kill_switch_path: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalMode {
    Automatic,
    Operator,
    Prohibited,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ApprovalPolicy {
    pub observation: ApprovalMode,
    pub low: ApprovalMode,
    pub medium: ApprovalMode,
    pub high: ApprovalMode,
}

impl Default for ApprovalPolicy {
    fn default() -> Self {
        Self {
            observation: ApprovalMode::Automatic,
            low: ApprovalMode::Automatic,
            medium: ApprovalMode::Operator,
            high: ApprovalMode::Prohibited,
        }
    }
}

impl ApprovalPolicy {
    fn mode_for(&self, risk: RiskLevel) -> ApprovalMode {
        match risk {
            RiskLevel::Observation => self.observation,
            RiskLevel::Low => self.low,
            RiskLevel::Medium => self.medium,
            RiskLevel::High => self.high,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ExecutionContext {
    pub lab_id: String,
    pub scenario_id: String,
    pub lab_token: Option<String>,
    pub snapshot_completed: bool,
    pub dry_run: bool,
    pub concurrent_actions: usize,
    pub recent_actions_in_last_second: u32,
    pub scenario_elapsed_ms: u64,
    pub scenario_allowed_actions: Vec<ControlledAction>,
    pub operator_approved: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyError {
    Denied(String),
}

pub trait ScopeAuthoriser {
    fn authorise(
        &self,
        proposal: &ActionProposal,
        context: &ExecutionContext,
    ) -> Result<ActionDecision, PolicyError>;
}

impl ScopeAuthoriser for ScopePolicy {
    fn authorise(
        &self,
        proposal: &ActionProposal,
        context: &ExecutionContext,
    ) -> Result<ActionDecision, PolicyError> {
        let mut permitted = true;
        let mut approval_required = false;
        let mut reason = String::from("permitted");

        if kill_switch_engaged(self) {
            permitted = false;
            reason = "kill switch engaged".to_string();
        } else if self.lab_id != context.lab_id {
            permitted = false;
            reason = "lab id does not match policy".to_string();
        } else if proposal.scenario_id != context.scenario_id {
            permitted = false;
            reason = "scenario id does not match execution context".to_string();
        } else if self.require_lab_token && !lab_token_matches(self, context.lab_token.as_deref()) {
            permitted = false;
            reason = "missing or invalid lab token".to_string();
        } else if self.require_snapshot_before_execution && !context.snapshot_completed {
            permitted = false;
            reason = "required lab snapshot has not been completed".to_string();
        } else if !self.allowed_actions.contains(&proposal.action) {
            permitted = false;
            reason = "action is not in policy allowlist".to_string();
        } else if !context.scenario_allowed_actions.is_empty()
            && !context.scenario_allowed_actions.contains(&proposal.action)
        {
            permitted = false;
            reason = "action is not allowed by scenario".to_string();
        } else if let Err(target_reason) = self.target_allowed(&proposal.target) {
            permitted = false;
            reason = target_reason;
        } else if context.concurrent_actions >= self.maximum_concurrent_actions {
            permitted = false;
            reason = "concurrency limit reached".to_string();
        } else if context.recent_actions_in_last_second >= self.maximum_requests_per_second {
            permitted = false;
            reason = "action rate limit reached".to_string();
        } else if context.scenario_elapsed_ms
            > self
                .maximum_scenario_duration_minutes
                .saturating_mul(60_000)
        {
            permitted = false;
            reason = "scenario duration limit reached".to_string();
        } else {
            match self.approval.mode_for(proposal.risk_level) {
                ApprovalMode::Automatic => {}
                ApprovalMode::Operator => {
                    approval_required = true;
                    if !context.operator_approved {
                        permitted = false;
                        reason = "operator approval required".to_string();
                    }
                }
                ApprovalMode::Prohibited => {
                    permitted = false;
                    reason = "risk level is prohibited by policy".to_string();
                }
            }
        }

        let decision = ActionDecision {
            decision_id: format!("dec-{}", now_ms()),
            action_id: proposal.action_id.clone(),
            scenario_id: proposal.scenario_id.clone(),
            actor: proposal.actor,
            action: proposal.action,
            permitted,
            approval_required,
            dry_run: context.dry_run || self.default_dry_run,
            reason,
            decided_at_ms: now_ms(),
        };

        if decision.permitted {
            Ok(decision)
        } else {
            Err(PolicyError::Denied(decision.reason.clone()))
        }
    }
}

impl ScopePolicy {
    fn target_allowed(&self, target: &AssetReference) -> Result<(), String> {
        if let Some(host) = target.host.as_deref() {
            let host = host.trim();
            if host.is_empty() || !self.allowed_hosts.iter().any(|allowed| allowed == host) {
                return Err("target host is not in allowlist".to_string());
            }
        }

        if let Some(ip) = target.ip.as_deref() {
            let ip = ip
                .parse::<IpAddr>()
                .map_err(|_| "target ip is invalid".to_string())?;
            if self.deny_default_route && is_default_route(ip) {
                return Err("default-route target is denied".to_string());
            }
            if self.deny_public_addresses && !is_private_or_loopback(ip) {
                return Err("public target address is denied".to_string());
            }
            if !ip_allowed_by_cidrs(ip, &self.allowed_networks) {
                return Err("target ip is outside allowed lab CIDRs".to_string());
            }
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AiLabStatusSnapshot {
    pub enabled: bool,
    pub lab_id: String,
    pub evidence_root: String,
    pub default_dry_run: bool,
    pub maximum_concurrent_actions: usize,
    pub maximum_scenario_duration_minutes: u64,
    pub maximum_requests_per_second: u32,
    pub allowed_actions: Vec<String>,
    pub allowed_hosts: Vec<String>,
    pub allowed_networks: Vec<String>,
    pub kill_switch_engaged: bool,
    pub safety_boundary: String,
}

impl AiLabStatusSnapshot {
    pub fn from_config(config: &AiLabConfig) -> Self {
        Self {
            enabled: config.enabled,
            lab_id: config.policy.lab_id.clone(),
            evidence_root: config.evidence_root.display().to_string(),
            default_dry_run: config.policy.default_dry_run,
            maximum_concurrent_actions: config.policy.maximum_concurrent_actions,
            maximum_scenario_duration_minutes: config.policy.maximum_scenario_duration_minutes,
            maximum_requests_per_second: config.policy.maximum_requests_per_second,
            allowed_actions: config
                .policy
                .allowed_actions
                .iter()
                .map(|action| action.as_str().to_string())
                .collect(),
            allowed_hosts: config.policy.allowed_hosts.clone(),
            allowed_networks: config.policy.allowed_networks.clone(),
            kill_switch_engaged: kill_switch_engaged(&config.policy),
            safety_boundary:
                "authorised isolated lab only; typed adapters only; no model shell access"
                    .to_string(),
        }
    }
}

pub fn load_scenario_yaml(raw: &str) -> Result<ScenarioDefinition, serde_yaml::Error> {
    serde_yaml::from_str(raw)
}

pub fn make_security_event(
    scenario_id: impl Into<String>,
    source: EventSource,
    event_type: SecurityEventType,
    target: &AssetReference,
    detail: impl Into<String>,
) -> SecurityEvent {
    let mut attributes = BTreeMap::new();
    attributes.insert(
        "detail".to_string(),
        serde_json::Value::String(detail.into()),
    );
    SecurityEvent {
        event_id: format!("evt-{}", now_ms()),
        timestamp_ms: now_ms(),
        scenario_id: scenario_id.into(),
        source,
        event_type,
        host: target.host.clone(),
        source_ip: None,
        destination_ip: target.ip.clone(),
        destination_port: None,
        severity_hint: 3,
        confidence: 0.8,
        attributes,
        evidence_reference: None,
    }
}

pub fn defensive_hypothesis(events: &[SecurityEvent]) -> Option<ActionProposal> {
    let scenario_id = events.first()?.scenario_id.clone();
    let auth = events
        .iter()
        .any(|event| event.event_type == SecurityEventType::AuthenticationSucceeded);
    let staging = events
        .iter()
        .any(|event| event.event_type == SecurityEventType::DataStagingEmulated);
    let movement = events
        .iter()
        .any(|event| event.event_type == SecurityEventType::LateralMovementEmulated);

    if auth && staging {
        let target = AssetReference {
            host: Some("user-workstation".to_string()),
            ip: Some("10.77.0.20".to_string()),
            role: Some("workstation".to_string()),
            labels: vec!["lab".to_string()],
        };
        Some(ActionProposal::new(
            scenario_id,
            Actor::Tracey,
            target,
            ControlledAction::QuarantineLabHost,
            "seeded credential use followed by synthetic data staging",
            "host isolation event and retained evidence bundle",
        ))
    } else if movement {
        let target = AssetReference {
            host: Some("telemetry-server".to_string()),
            ip: Some("10.77.0.10".to_string()),
            role: Some("sensor".to_string()),
            labels: vec!["lab".to_string()],
        };
        Some(ActionProposal::new(
            scenario_id,
            Actor::Tracey,
            target,
            ControlledAction::IncreaseTelemetry,
            "lateral movement emulation requires higher fidelity telemetry",
            "increased lab-only capture for the scenario window",
        ))
    } else {
        None
    }
}

fn lab_token_matches(policy: &ScopePolicy, supplied: Option<&str>) -> bool {
    match (policy.lab_token.as_deref(), supplied) {
        (Some(expected), Some(actual)) => !expected.is_empty() && expected == actual,
        (None, Some(actual)) => !actual.trim().is_empty(),
        _ => false,
    }
}

fn kill_switch_engaged(policy: &ScopePolicy) -> bool {
    if std::env::var("TRACEY_AI_LAB_KILL_SWITCH")
        .map(|value| {
            let value = value.to_ascii_lowercase();
            matches!(value.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(false)
    {
        return true;
    }
    policy
        .kill_switch_path
        .as_ref()
        .map(|path| path.exists())
        .unwrap_or(false)
}

fn is_default_route(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip == Ipv4Addr::UNSPECIFIED,
        IpAddr::V6(ip) => ip == Ipv6Addr::UNSPECIFIED,
    }
}

fn is_private_or_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private() || ip.is_loopback(),
        IpAddr::V6(ip) => ip.is_loopback() || is_unique_local_ipv6(ip),
    }
}

fn is_unique_local_ipv6(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xfe00) == 0xfc00
}

fn ip_allowed_by_cidrs(ip: IpAddr, cidrs: &[String]) -> bool {
    if cidrs.is_empty() {
        return false;
    }
    match ip {
        IpAddr::V4(ip) => cidrs
            .iter()
            .filter_map(|cidr| Ipv4Cidr::from_str(cidr).ok())
            .any(|cidr| cidr.contains(ip)),
        IpAddr::V6(ip) => cidrs
            .iter()
            .any(|cidr| cidr == "::1/128" && ip == Ipv6Addr::LOCALHOST),
    }
}

struct Ipv4Cidr {
    base: u32,
    prefix: u8,
}

impl Ipv4Cidr {
    fn contains(&self, ip: Ipv4Addr) -> bool {
        let mask = if self.prefix == 0 {
            0
        } else {
            u32::MAX << (32 - self.prefix)
        };
        (u32::from(ip) & mask) == (self.base & mask)
    }
}

impl FromStr for Ipv4Cidr {
    type Err = ();

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let (base, prefix) = raw.split_once('/').ok_or(())?;
        let base = base.parse::<Ipv4Addr>().map_err(|_| ())?;
        let prefix = prefix.parse::<u8>().map_err(|_| ())?;
        if prefix > 32 {
            return Err(());
        }
        Ok(Self {
            base: u32::from(base),
            prefix,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> ExecutionContext {
        ExecutionContext {
            lab_id: "tracey-demo-01".to_string(),
            scenario_id: "scenario-1".to_string(),
            lab_token: Some("token".to_string()),
            snapshot_completed: true,
            dry_run: true,
            concurrent_actions: 0,
            recent_actions_in_last_second: 0,
            scenario_elapsed_ms: 1000,
            scenario_allowed_actions: vec![ControlledAction::ObserveAsset],
            operator_approved: false,
        }
    }

    fn proposal(target: AssetReference, action: ControlledAction) -> ActionProposal {
        ActionProposal::new(
            "scenario-1",
            Actor::RedTeam,
            target,
            action,
            "unit test",
            "unit test result",
        )
    }

    #[test]
    fn denies_public_ip() {
        let policy = ScopePolicy {
            lab_token: Some("token".to_string()),
            ..ScopePolicy::default()
        };
        let target = AssetReference {
            host: Some("file-server".to_string()),
            ip: Some("8.8.8.8".to_string()),
            ..AssetReference::default()
        };
        let err = policy
            .authorise(
                &proposal(target, ControlledAction::ObserveAsset),
                &context(),
            )
            .expect_err("public IP should be denied");
        assert_eq!(
            err,
            PolicyError::Denied("public target address is denied".to_string())
        );
    }

    #[test]
    fn denies_unlisted_host() {
        let policy = ScopePolicy {
            lab_token: Some("token".to_string()),
            ..ScopePolicy::default()
        };
        let target = AssetReference {
            host: Some("prod-file-server".to_string()),
            ..AssetReference::default()
        };
        let err = policy
            .authorise(
                &proposal(target, ControlledAction::ObserveAsset),
                &context(),
            )
            .expect_err("unlisted host should be denied");
        assert_eq!(
            err,
            PolicyError::Denied("target host is not in allowlist".to_string())
        );
    }

    #[test]
    fn denies_action_outside_scenario() {
        let policy = ScopePolicy {
            lab_token: Some("token".to_string()),
            ..ScopePolicy::default()
        };
        let target = AssetReference {
            host: Some("file-server".to_string()),
            ip: Some("10.77.0.25".to_string()),
            ..AssetReference::default()
        };
        let err = policy
            .authorise(
                &proposal(target, ControlledAction::StageSyntheticDataset),
                &context(),
            )
            .expect_err("scenario action allowlist should be enforced");
        assert_eq!(
            err,
            PolicyError::Denied("action is not allowed by scenario".to_string())
        );
    }

    #[test]
    fn permits_dry_run_observation_in_lab_cidr() {
        let policy = ScopePolicy {
            lab_token: Some("token".to_string()),
            ..ScopePolicy::default()
        };
        let target = AssetReference {
            host: Some("file-server".to_string()),
            ip: Some("10.77.0.25".to_string()),
            ..AssetReference::default()
        };
        let decision = policy
            .authorise(
                &proposal(target, ControlledAction::ObserveAsset),
                &context(),
            )
            .expect("lab observation should be allowed");
        assert!(decision.permitted);
        assert!(decision.dry_run);
    }
}
