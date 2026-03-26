use crate::aer::{AerEvent, decode_events, encode_events};
use crate::bus::EventBus;
use crate::config::StimuliConfig;
use crate::event::{Event, EventKind, Severity};
use crate::governance::{GovernanceState, Posture};
use crate::shutdown::ShutdownListener;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::net::UdpSocket;

static STIMULI_EVENT_COUNTER: AtomicU64 = AtomicU64::new(10_000_000);

const TRACEY_EVENT_BASE: u32 = 0x1000;
const TRACEY_KIND_STRIDE: u32 = 0x10;
const TRACEY_POSTURE_BASE: u32 = 0x1100;
const AARNN_OUTPUT_BASE: u32 = 0x4000;

pub async fn spawn_stimuli(
    config: StimuliConfig,
    bus: EventBus,
    governance_state: std::sync::Arc<tokio::sync::RwLock<GovernanceState>>,
    mut shutdown: ShutdownListener,
) -> std::io::Result<()> {
    if !config.enabled {
        tracing::info!("stimuli disabled");
        return Ok(());
    }

    let socket = UdpSocket::bind(&config.listen_addr).await?;
    let mut bus_rx = bus.subscribe();
    let mut recv_buf = vec![0u8; config.max_packet_bytes];
    let mut pending_out: Vec<AerEvent> = Vec::with_capacity(config.max_batch);
    let peer = config.peer_addr.clone();

    let mut flush_tick = tokio::time::interval(Duration::from_millis(config.flush_interval_ms));
    let mut posture_tick = tokio::time::interval(Duration::from_millis(config.posture_interval_ms));
    let mut last_posture: Option<Posture> = None;

    tracing::info!(
        listen = %config.listen_addr,
        peer = ?peer,
        "stimuli AER bridge enabled"
    );

    loop {
        tokio::select! {
            _ = shutdown.wait() => {
                tracing::info!("stimuli shutting down");
                break;
            }
            recv = socket.recv_from(&mut recv_buf) => {
                match recv {
                    Ok((size, peer_addr)) => {
                        if size == recv_buf.len() {
                            tracing::warn!(
                                peer = %peer_addr,
                                size,
                                max_packet_bytes = recv_buf.len(),
                                "stimuli inbound packet may be truncated; dropping"
                            );
                            continue;
                        }
                        handle_inbound(&recv_buf[..size], &bus, &peer_addr.to_string());
                    }
                    Err(err) => {
                        tracing::warn!(error = %err, "stimuli receive failed");
                    }
                }
            }
            event = bus_rx.recv() => {
                match event {
                    Ok(event) => {
                        if event.source == "aarnn" {
                            continue;
                        }
                        let aer = event_to_aer(&event);
                        pending_out.push(aer);
                        if pending_out.len() >= config.max_batch {
                            flush_outbound(&socket, peer.as_deref(), &mut pending_out).await;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        continue;
                    }
                    Err(_) => {
                        break;
                    }
                }
            }
            _ = flush_tick.tick() => {
                flush_outbound(&socket, peer.as_deref(), &mut pending_out).await;
            }
            _ = posture_tick.tick() => {
                let posture = governance_state.read().await.posture;
                if Some(posture) != last_posture {
                    last_posture = Some(posture);
                    let aer = posture_to_aer(posture);
                    pending_out.push(aer);
                    flush_outbound(&socket, peer.as_deref(), &mut pending_out).await;
                }
            }
        }
    }

    Ok(())
}

fn handle_inbound(payload: &[u8], bus: &EventBus, peer: &str) {
    let events = match decode_events(payload) {
        Ok(events) => events,
        Err(err) => {
            tracing::warn!("invalid AER payload from {}: {}", peer, err);
            return;
        }
    };

    let mut unknown_count = 0usize;
    for ev in events {
        if !is_known_aer_addr(ev.addr) {
            unknown_count = unknown_count.saturating_add(1);
        }
        if let Some(event) = aer_to_event(&ev, peer) {
            bus.publish(event);
        }
    }
    if unknown_count > 0 {
        tracing::warn!(
            peer = %peer,
            unknown_count,
            "stimuli payload contained unsupported/unknown AER addresses"
        );
    }
}

async fn flush_outbound(socket: &UdpSocket, peer: Option<&str>, pending: &mut Vec<AerEvent>) {
    if pending.is_empty() {
        return;
    }
    if let Some(peer) = peer {
        let payload = encode_events(pending);
        if let Err(err) = socket.send_to(&payload, peer).await {
            tracing::warn!(peer = %peer, error = %err, "stimuli outbound send failed");
        }
    }
    pending.clear();
}

fn event_to_aer(event: &Event) -> AerEvent {
    let kind_idx = kind_index(event.kind);
    let sev_idx = severity_index(event.severity);
    let addr = TRACEY_EVENT_BASE + kind_idx * TRACEY_KIND_STRIDE + sev_idx;
    let scaled = (event.signal * event.severity.weight()).clamp(0.0, 1.0);
    let value = (scaled * 255.0) as u8;
    AerEvent {
        ts_us: event.ts_ms.saturating_mul(1000),
        addr,
        value,
    }
}

fn posture_to_aer(posture: Posture) -> AerEvent {
    let addr = TRACEY_POSTURE_BASE + posture_index(posture);
    AerEvent {
        ts_us: crate::event::now_ms().saturating_mul(1000),
        addr,
        value: 200,
    }
}

fn aer_to_event(ev: &AerEvent, peer: &str) -> Option<Event> {
    if let Some((kind, severity)) = addr_to_kind_severity(ev.addr) {
        let signal = (ev.value as f64) / 255.0;
        let id = STIMULI_EVENT_COUNTER.fetch_add(1, Ordering::Relaxed);
        let event = Event::new(id, "aarnn", kind, signal, severity)
            .with_attr("aer_addr", ev.addr.to_string())
            .with_attr("aer_value", ev.value.to_string())
            .with_attr("aer_peer", peer);
        return Some(event);
    }

    if ev.addr >= AARNN_OUTPUT_BASE {
        let idx = ev.addr.saturating_sub(AARNN_OUTPUT_BASE);
        let signal = (ev.value as f64) / 255.0;
        let id = STIMULI_EVENT_COUNTER.fetch_add(1, Ordering::Relaxed);
        let event = Event::new(
            id,
            "aarnn",
            EventKind::Observability,
            signal,
            Severity::Medium,
        )
        .with_attr("aer_addr", ev.addr.to_string())
        .with_attr("aer_value", ev.value.to_string())
        .with_attr("aer_peer", peer)
        .with_attr("aarnn_output_index", idx.to_string());
        return Some(event);
    }

    let id = STIMULI_EVENT_COUNTER.fetch_add(1, Ordering::Relaxed);
    Some(
        Event::new(
            id,
            "aarnn",
            EventKind::Observability,
            (ev.value as f64) / 255.0,
            Severity::Low,
        )
        .with_attr("aer_addr", ev.addr.to_string())
        .with_attr("aer_value", ev.value.to_string())
        .with_attr("aer_peer", peer),
    )
}

fn kind_index(kind: EventKind) -> u32 {
    match kind {
        EventKind::SystemMetric => 0,
        EventKind::NetworkFlow => 1,
        EventKind::UserAction => 2,
        EventKind::AutomationAction => 3,
        EventKind::Observability => 4,
    }
}

fn severity_index(severity: Severity) -> u32 {
    match severity {
        Severity::Low => 0,
        Severity::Medium => 1,
        Severity::High => 2,
        Severity::Critical => 3,
    }
}

fn addr_to_kind_severity(addr: u32) -> Option<(EventKind, Severity)> {
    if addr < TRACEY_EVENT_BASE {
        return None;
    }
    let rel = addr - TRACEY_EVENT_BASE;
    let kind = match rel / TRACEY_KIND_STRIDE {
        0 => EventKind::SystemMetric,
        1 => EventKind::NetworkFlow,
        2 => EventKind::UserAction,
        3 => EventKind::AutomationAction,
        4 => EventKind::Observability,
        _ => return None,
    };
    let sev = match rel % TRACEY_KIND_STRIDE {
        0 => Severity::Low,
        1 => Severity::Medium,
        2 => Severity::High,
        3 => Severity::Critical,
        _ => Severity::Low,
    };
    Some((kind, sev))
}

fn posture_index(posture: Posture) -> u32 {
    match posture {
        Posture::Relaxed => 0,
        Posture::Balanced => 1,
        Posture::Strict => 2,
        Posture::Lockdown => 3,
    }
}

fn is_known_aer_addr(addr: u32) -> bool {
    addr_to_kind_severity(addr).is_some() || addr >= AARNN_OUTPUT_BASE
}
