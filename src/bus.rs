//! Shared in-process event bus built on a bounded Tokio broadcast channel.
//!
//! The bus intentionally drops backpressure details (send errors are ignored)
//! because downstream modules already treat missed events as recoverable noise.

use crate::event::Event;
use tokio::sync::broadcast;

#[derive(Clone)]
pub struct EventBus {
    sender: broadcast::Sender<Event>,
}

impl EventBus {
    /// Creates a broadcast bus with the given ring-buffer capacity.
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    /// Publishes an event to all active subscribers.
    ///
    /// If no subscribers exist, the event is dropped.
    pub fn publish(&self, event: Event) {
        let _ = self.sender.send(event);
    }

    /// Creates a new subscription cursor for the bus stream.
    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.sender.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Event, EventKind, Severity};

    #[tokio::test]
    async fn publish_delivers_event_to_subscriber() {
        let bus = EventBus::new(8);
        let mut rx = bus.subscribe();
        let event = Event::new(42, "test", EventKind::Observability, 0.5, Severity::Medium);
        bus.publish(event.clone());
        let got = rx.recv().await.expect("event should be delivered");
        assert_eq!(got.id, event.id);
        assert_eq!(got.source, event.source);
    }
}
