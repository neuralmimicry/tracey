//! Tracey runtime composition entrypoint.
//!
//! Wires all subsystems (sensors, swarm, governance, discovery, updates,
//! telemetry, status, and optional security runtimes) onto a shared async core.

mod aer;
mod assets;
mod auth;
mod bus;
mod capabilities;
mod config;
mod coordination;
mod discovery;
mod embedded;
mod event;
mod governance;
mod inventory;
mod refiner_tracking;
mod security;
mod sensors;
mod shutdown;
mod status;
mod stimuli;
mod storage;
mod supervisor;
mod swarm;
mod telemetry;
mod tracey_ban;
mod tracey_guard;
mod tuning;
mod update;

use crate::bus::EventBus;
use crate::config::Config;
use crate::shutdown::Shutdown;
use crate::swarm::{AdaptiveScorer, Agent, Coordinator, LearningSnapshot, SwarmDirective};
use crate::tracey_ban::BanIntelHub;
use crate::tracey_guard::TraceyGuardRuntimeHandle;
use crate::update::UpdateManager;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::{mpsc, watch};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("sign-update") {
        if let Err(msg) = update::run_sign_update(&args[2..]) {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, msg).into());
        }
        return Ok(());
    }

    if args.iter().any(|arg| arg == "--supervisor") && std::env::var("TRACEY_SUPERVISED").is_err() {
        supervisor::run_supervisor().await?;
        return Ok(());
    }

    let config = Config::load();
    tracing::info!(?config, "tracey starting");
    if let Some(code) = tracey_ban::maybe_elevate_for_tracey_ban(&config.tracey_ban) {
        std::process::exit(code);
    }

    if config.discovery.enabled && config.discovery.shared_key == "tracey-dev-key-change-me" {
        tracing::warn!(
            "discovery shared_key is using the default value; rotate it before production"
        );
    }

    let (shutdown, shutdown_listener) = Shutdown::new();
    shutdown::spawn_shutdown_watcher(shutdown.clone());

    let bus = EventBus::new(config.bus_capacity);
    let storage = storage::Storage::new(config.storage.clone(), shutdown_listener.clone()).await?;
    let inventory = inventory::Inventory::new(
        config.inventory.clone(),
        storage.clone(),
        shutdown_listener.clone(),
    );

    let (assessment_tx, assessment_rx) = mpsc::channel(config.assessment_channel_capacity);
    let (governance_tx, governance_rx) = mpsc::channel(config.assessment_channel_capacity);
    let (directive_tx, directive_rx) = watch::channel(SwarmDirective::default());
    let (learning_tx, learning_rx) = watch::channel(LearningSnapshot::default());

    let tuner = if config.tuning.enabled {
        Some(tuning::AdaptiveTuner::new(
            config.tuning.clone(),
            config.decision_threshold,
        ))
    } else {
        None
    };

    let governance_state = std::sync::Arc::new(tokio::sync::RwLock::new(
        governance::GovernanceState::from_config(&config),
    ));
    let ban_intel = BanIntelHub::new(config.tracey_ban.remote_ttl_ms);
    let tracey_guard = if config.tracey_guard.enabled {
        tracey_guard::spawn_tracey_guard(
            config.tracey_guard.clone(),
            bus.clone(),
            storage.clone(),
            shutdown_listener.clone(),
        )
    } else {
        TraceyGuardRuntimeHandle::disabled(config.tracey_guard.remote_fault_ttl_ms)
    };

    let auth_system = auth::AuthSystem::from_config(&config.auth);

    let local_capabilities = capabilities::Capabilities::local();

    let coordination = coordination::Coordination::new(
        config.agent_id.clone(),
        config.coordination.clone(),
        &config.discovery.shared_key,
        local_capabilities.clone(),
    );
    let coordination_role = coordination.role_handle();
    let coordination_for_election = coordination.clone();
    let coordination_governance = governance_state.clone();
    tokio::spawn(async move {
        coordination_for_election
            .spawn_election(coordination_governance)
            .await;
    });

    let coordinator = Coordinator::new(
        assessment_rx,
        governance_rx,
        directive_tx,
        learning_tx,
        config.policy.clone(),
        config.decision_threshold,
        Duration::from_millis(config.decision_ttl_ms),
        config.assessment_quorum,
        config.active_response,
        config.shutdown_enabled,
        Duration::from_millis(config.learning_broadcast_ms),
        Duration::from_millis(config.directive_broadcast_ms),
        storage.clone(),
        AdaptiveScorer::new(config.min_samples, config.fuzzy.clone()),
        tuner,
        config.governance.clone(),
        governance_state.clone(),
        coordination.clone(),
    );
    tokio::spawn(coordinator.run(shutdown_listener.clone()));

    for id in 0..config.agents {
        let agent = Agent::new(
            id as u32,
            bus.subscribe(),
            assessment_tx.clone(),
            learning_rx.clone(),
            directive_rx.clone(),
            AdaptiveScorer::new(config.min_samples, config.fuzzy.clone()),
            config.policy.clone(),
            config.learning_merge_alpha,
            governance_tx.clone(),
            config.governance.clone(),
        );
        tokio::spawn(agent.run(shutdown_listener.clone()));
    }

    let mut status_advertise_addr: Option<String> = None;
    if config.status.enabled {
        match config.status.listen_addr.parse::<SocketAddr>() {
            Ok(listen_addr) => {
                let status_public = config
                    .status
                    .public_addr
                    .clone()
                    .or_else(|| config.discovery.advertise_addr.clone())
                    .or_else(|| Some(config.status.listen_addr.clone()));
                status_advertise_addr = status_public.clone();
                let client = reqwest::Client::builder()
                    .timeout(Duration::from_millis(config.status.proxy_timeout_ms))
                    .build()
                    .unwrap_or_else(|err| {
                        tracing::warn!("status client init failed: {}", err);
                        reqwest::Client::new()
                    });
                let service = status::StatusService {
                    agent_id: config.agent_id.clone(),
                    coordination_role: coordination_role.clone(),
                    governance_state: governance_state.clone(),
                    client,
                    auth: auth_system.status_gate(),
                    ban_intel: if config.tracey_ban.enabled {
                        Some(ban_intel.clone())
                    } else {
                        None
                    },
                    tracey_guard: Some(tracey_guard.clone()),
                };
                let status_shutdown = shutdown_listener.clone();
                tokio::spawn(status::spawn_status(service, listen_addr, status_shutdown));
            }
            Err(err) => {
                tracing::warn!(
                    addr = %config.status.listen_addr,
                    error = %err,
                    "invalid status.listen_addr; status disabled"
                );
            }
        }
    }

    sensors::spawn_default_sensors(
        bus.clone(),
        storage.clone(),
        config.clone(),
        shutdown_listener.clone(),
    );
    embedded::spawn_embedded_collectors(
        bus.clone(),
        storage.clone(),
        config.embedded.clone(),
        shutdown_listener.clone(),
    );

    let stimuli_config = config.stimuli.clone();
    let stimuli_bus = bus.clone();
    let stimuli_shutdown = shutdown_listener.clone();
    let stimuli_governance = governance_state.clone();
    tokio::spawn(async move {
        if let Err(err) = stimuli::spawn_stimuli(
            stimuli_config,
            stimuli_bus,
            stimuli_governance,
            stimuli_shutdown,
        )
        .await
        {
            tracing::warn!("stimuli bridge failed: {}", err);
        }
    });

    let telemetry_config = config.telemetry.clone();
    let telemetry_bus = bus.clone();
    let telemetry_storage = storage.clone();
    let telemetry_shutdown = shutdown_listener.clone();
    let telemetry_governance = governance_state.clone();
    let telemetry_auth = auth_system.clone();
    tokio::spawn(async move {
        telemetry::spawn_telemetry(
            telemetry_bus,
            telemetry_storage,
            telemetry_config,
            telemetry_shutdown,
            telemetry_governance,
            telemetry_auth,
        )
        .await;
    });

    let mut tracey_ban_config = config.tracey_ban.clone();
    if tracey_ban_config.inherit_global_fuzzy {
        tracey_ban_config.fuzzy = config.fuzzy.clone();
        tracey_ban_config.min_samples = config.min_samples;
    }
    let tracey_ban_bus = bus.clone();
    let tracey_ban_storage = storage.clone();
    let tracey_ban_shutdown = shutdown_listener.clone();
    let tracey_ban_intel = ban_intel.clone();
    tokio::spawn(async move {
        tracey_ban::spawn_tracey_ban(
            tracey_ban_config,
            tracey_ban_bus,
            tracey_ban_storage,
            tracey_ban_shutdown,
            tracey_ban_intel,
        )
        .await;
    });

    let discovery_config = config.discovery.clone();
    let discovery_agent_id = config.agent_id.clone();
    let discovery_inventory = inventory.clone();
    let discovery_shutdown = shutdown_listener.clone();
    let discovery_governance = governance_state.clone();
    let discovery_coordination = coordination.clone();
    let discovery_role = coordination_role.clone();
    let discovery_status_addr = status_advertise_addr.clone();
    let discovery_ban_intel = if config.tracey_ban.enabled {
        Some(ban_intel.clone())
    } else {
        None
    };
    let discovery_ban_max = config.tracey_ban.max_advertised_ips;
    let discovery_fault_hub = tracey_guard.fault_hub();
    let discovery_fault_max = config.tracey_guard.max_advertised_faults;
    tokio::spawn(async move {
        if let Err(err) = discovery::spawn_discovery(
            discovery_config,
            discovery_agent_id,
            discovery_inventory,
            discovery_shutdown,
            discovery_governance,
            discovery_role,
            discovery_coordination,
            discovery_status_addr,
            local_capabilities,
            discovery_ban_intel,
            discovery_ban_max,
            Some(discovery_fault_hub),
            discovery_fault_max,
        )
        .await
        {
            tracing::warn!("discovery failed: {}", err);
        }
    });

    let asset_config = config.asset_feed.clone();
    let asset_inventory = inventory.clone();
    let asset_shutdown = shutdown_listener.clone();
    let asset_governance = governance_state.clone();
    tokio::spawn(async move {
        assets::spawn_asset_feed(
            asset_config,
            asset_inventory,
            asset_shutdown,
            asset_governance,
        )
        .await;
    });

    let refiner_config = config.refiner.clone();
    let refiner_bus = bus.clone();
    let refiner_storage = storage.clone();
    let refiner_shutdown = shutdown_listener.clone();
    tokio::spawn(async move {
        refiner_tracking::spawn_refiner_tracking(
            refiner_bus,
            refiner_storage,
            refiner_config,
            refiner_shutdown,
        )
        .await;
    });

    let update_manager = UpdateManager::new(
        config.update.clone(),
        shutdown.clone(),
        storage.clone(),
        shutdown_listener.clone(),
        governance_state.clone(),
    );
    tokio::spawn(update_manager.run());

    update::signal_handoff_ready().await;

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("ctrl-c received, shutting down");
        }
    }

    shutdown.trigger();
    tokio::time::sleep(Duration::from_millis(300)).await;

    Ok(())
}
