// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Message Expiry Interval and Will Delay Interval helpers (MQTT 5.0).

use std::time::{Duration, Instant};

use crate::codec::properties::property;
use crate::codec::Properties;

/// Absolute expiry deadline implied by a Message Expiry Interval property
/// received at `received_at`. `None` when the property is absent.
pub fn expiry_deadline(props: &Properties, received_at: Instant) -> Option<Instant> {
    props
        .get_u32(property::MESSAGE_EXPIRY_INTERVAL)
        .map(|secs| received_at + Duration::from_secs(secs as u64))
}

/// Whether a message stamped at `received_at` with `props` has expired by `now`.
pub fn is_expired(props: &Properties, received_at: Instant, now: Instant) -> bool {
    match expiry_deadline(props, received_at) {
        Some(deadline) => now >= deadline,
        None => false,
    }
}

/// Rewrite Message Expiry Interval to the remaining seconds at `now`, or
/// remove it if already expired / absent. Returns `false` when expired
/// (caller should drop the message).
pub fn adjust_remaining_expiry(props: &mut Properties, received_at: Instant, now: Instant) -> bool {
    let Some(deadline) = expiry_deadline(props, received_at) else {
        return true;
    };
    if now >= deadline {
        return false;
    }
    let remaining = deadline.saturating_duration_since(now).as_secs();
    let remaining = u32::try_from(remaining).unwrap_or(u32::MAX);
    props.set_u32(property::MESSAGE_EXPIRY_INTERVAL, remaining);
    true
}

/// Will Delay Interval from Will Properties, capped by Session Expiry when
/// Session Expiry is non-zero (MQTT 5.0 §3.1.2.5 / §3.1.3.2: Will Delay must
/// not exceed the session lifetime).
pub fn effective_will_delay(will_props: &Properties, session_expiry: Duration) -> Duration {
    let delay_secs = will_props
        .get_u32(property::WILL_DELAY_INTERVAL)
        .unwrap_or(0) as u64;
    let mut delay = Duration::from_secs(delay_secs);
    if !session_expiry.is_zero() && delay > session_expiry {
        delay = session_expiry;
    }
    delay
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adjust_remaining_rewrites_interval() {
        let mut props = Properties::new();
        props.set_u32(property::MESSAGE_EXPIRY_INTERVAL, 10);
        let received = Instant::now() - Duration::from_secs(3);
        assert!(adjust_remaining_expiry(&mut props, received, Instant::now()));
        let remaining = props.get_u32(property::MESSAGE_EXPIRY_INTERVAL).unwrap();
        assert!(remaining <= 7);
        assert!(remaining >= 5);
    }

    #[test]
    fn adjust_remaining_rejects_expired() {
        let mut props = Properties::new();
        props.set_u32(property::MESSAGE_EXPIRY_INTERVAL, 1);
        let received = Instant::now() - Duration::from_secs(5);
        assert!(!adjust_remaining_expiry(&mut props, received, Instant::now()));
    }

    #[test]
    fn will_delay_capped_by_session_expiry() {
        let mut props = Properties::new();
        props.set_u32(property::WILL_DELAY_INTERVAL, 100);
        assert_eq!(
            effective_will_delay(&props, Duration::from_secs(30)),
            Duration::from_secs(30)
        );
        assert_eq!(
            effective_will_delay(&props, Duration::ZERO),
            Duration::from_secs(100)
        );
    }
}
