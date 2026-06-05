//! Shared adaptive backoff helper for probe loops.

use std::time::Duration;

const MAX_BACKOFF_SHIFT: u32 = 6;

#[derive(Clone, Debug)]
pub struct AdaptiveProbeBackoff {
    base: Duration,
    max: Duration,
    stable_streak: u32,
    last_outcome: Option<bool>,
}

impl AdaptiveProbeBackoff {
    pub fn new(base: Duration, max: Duration) -> Self {
        let base = if base.is_zero() {
            Duration::from_millis(250)
        } else {
            base
        };
        let max = max.max(base);
        Self {
            base,
            max,
            stable_streak: 0,
            last_outcome: None,
        }
    }

    pub fn record_outcome(&mut self, outcome: bool) -> Duration {
        if self.last_outcome == Some(outcome) {
            self.stable_streak = self.stable_streak.saturating_add(1);
        } else {
            self.stable_streak = 0;
            self.last_outcome = Some(outcome);
        }

        // Increase delay after stable repeated outcomes while resetting quickly
        // on state changes. The delay doubles every two stable probes.
        let level = (self.stable_streak / 2).min(MAX_BACKOFF_SHIFT);
        let multiplier = 1u64 << level;
        scale_duration(self.base, multiplier).min(self.max)
    }
}

fn scale_duration(duration: Duration, multiplier: u64) -> Duration {
    let ms = duration.as_millis().max(1) as u64;
    Duration::from_millis(ms.saturating_mul(multiplier.max(1)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_scales_with_stable_outcomes() {
        let mut backoff =
            AdaptiveProbeBackoff::new(Duration::from_secs(5), Duration::from_secs(60));
        assert_eq!(backoff.record_outcome(true), Duration::from_secs(5));
        assert_eq!(backoff.record_outcome(true), Duration::from_secs(5));
        assert_eq!(backoff.record_outcome(true), Duration::from_secs(10));
        assert_eq!(backoff.record_outcome(true), Duration::from_secs(10));
        assert_eq!(backoff.record_outcome(true), Duration::from_secs(20));
    }

    #[test]
    fn backoff_resets_when_outcome_changes() {
        let mut backoff =
            AdaptiveProbeBackoff::new(Duration::from_secs(5), Duration::from_secs(60));
        let _ = backoff.record_outcome(false);
        let _ = backoff.record_outcome(false);
        assert_eq!(backoff.record_outcome(false), Duration::from_secs(10));
        assert_eq!(backoff.record_outcome(true), Duration::from_secs(5));
    }

    #[test]
    fn backoff_caps_at_maximum() {
        let mut backoff =
            AdaptiveProbeBackoff::new(Duration::from_secs(5), Duration::from_secs(30));
        let mut delay = Duration::from_secs(0);
        for _ in 0..16 {
            delay = backoff.record_outcome(true);
        }
        assert_eq!(delay, Duration::from_secs(30));
    }
}
