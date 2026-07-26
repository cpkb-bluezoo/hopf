// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! RFC 5452 §2.1: DNS query IDs are the primary defense against off-path
//! response spoofing, so they must be unpredictable — not merely unique.

/// Allocates 16-bit DNS query IDs drawn from the OS CSPRNG (never a
/// predictable counter).
#[derive(Debug, Default)]
pub struct DnsQueryIdGenerator;

impl DnsQueryIdGenerator {
    /// New generator.
    pub fn new() -> Self {
        Self
    }

    /// Next ID (skips 0).
    pub fn next_id(&self) -> u16 {
        loop {
            let mut buf = [0u8; 2];
            getrandom::getrandom(&mut buf).expect("OS RNG");
            let id = u16::from_ne_bytes(buf);
            if id != 0 {
                return id;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_returns_zero() {
        let gen = DnsQueryIdGenerator::new();
        for _ in 0..10_000 {
            assert_ne!(gen.next_id(), 0);
        }
    }

    /// Not a rigorous randomness test, just a sanity check that successive
    /// IDs aren't a monotonic sequence (the exact bug being fixed) — over
    /// enough draws a real CSPRNG will produce non-monotonic runs and
    /// plenty of distinct values.
    #[test]
    fn ids_are_not_a_monotonic_counter() {
        let gen = DnsQueryIdGenerator::new();
        let ids: Vec<u16> = (0..200).map(|_| gen.next_id()).collect();
        let ascending_run = ids.windows(2).filter(|w| w[1] == w[0].wrapping_add(1)).count();
        assert!(ascending_run < 50, "IDs look sequential: {ascending_run} adjacent-by-one pairs out of 200");
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert!(unique.len() > 150, "too few distinct values for 200 draws: {}", unique.len());
    }
}
