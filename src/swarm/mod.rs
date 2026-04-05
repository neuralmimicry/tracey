//! Swarm runtime modules: agent workers, coordinator, and learning model state.

mod agent;
mod coordinator;
mod learning;

pub use agent::{Agent, SwarmDirective};
pub use coordinator::{Coordinator, Decision};
pub use learning::{AdaptiveScorer, FuzzyTelemetry, LearningSnapshot};
