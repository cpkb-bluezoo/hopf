// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! RFC 1982 serial number arithmetic on 32-bit wrapping counters.
//!
//! AMQP 1.0's transfer-id, delivery-id, and delivery-count fields are
//! unsigned 32-bit values that wrap around and are compared modulo 2^32
//! (core spec section 2.5.6 / 2.6.7 note); session window and link-credit
//! accounting subtracts and compares these serials directly, so ordinary
//! `u32` subtraction/comparison would misbehave the moment either side
//! wraps. `wrapping_add`/`wrapping_sub` alone don't recover a *sign* for
//! "is A before or after B", which is what RFC 1982 provides.

/// `a + b`, wrapping at 2^32 (RFC 1982 section 3.1, `ADDITION`).
pub fn serial_add(a: u32, b: u32) -> u32 {
    a.wrapping_add(b)
}

/// Signed distance `a - b` in serial-number space (RFC 1982 section 3.2),
/// i.e. how far `a` is ahead of (positive) or behind (negative) `b`. Valid
/// as long as the two serials are known to be within 2^31 of each other,
/// which holds for every AMQP 1.0 field this is used on (window and credit
/// values never legitimately drift that far apart).
pub fn serial_diff(a: u32, b: u32) -> i32 {
    a.wrapping_sub(b) as i32
}

/// `a < b` in serial-number space.
pub fn serial_lt(a: u32, b: u32) -> bool {
    serial_diff(a, b) < 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_wraps_at_u32_max() {
        assert_eq!(serial_add(u32::MAX, 1), 0);
        assert_eq!(serial_add(10, 5), 15);
    }

    #[test]
    fn diff_handles_wraparound() {
        // b is "before" a even though the raw u32 values suggest otherwise,
        // because a just wrapped past 0.
        let a: u32 = 5;
        let b: u32 = u32::MAX - 2;
        assert_eq!(serial_diff(a, b), 8); // a is 8 ahead of b in serial space
        assert!(!serial_lt(a, b));
        assert!(serial_lt(b, a));
    }

    #[test]
    fn diff_of_equal_is_zero() {
        assert_eq!(serial_diff(42, 42), 0);
        assert!(!serial_lt(42, 42));
    }
}
