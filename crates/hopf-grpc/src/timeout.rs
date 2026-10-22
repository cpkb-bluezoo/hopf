// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! `grpc-timeout` header parsing and formatting.

const MAX_DIGITS: usize = 8;
const MAX_AMOUNT: u64 = 99_999_999;

/// Unit letters, finest first (`n`, `u`, `m`, `S`, `M`, `H`).
const UNIT_CHARS: [char; 6] = ['n', 'u', 'm', 'S', 'M', 'H'];

/// Nanoseconds per unit in [`UNIT_CHARS`].
const UNIT_NANOS: [u64; 6] = [1, 1_000, 1_000_000, 1_000_000_000, 60_000_000_000, 3_600_000_000_000];

/// Parses a `grpc-timeout` value. Returns `None` if invalid.
pub fn parse(value: &str) -> Option<u64> {
    if value.len() < 2 || value.len() > MAX_DIGITS + 1 {
        return None;
    }
    let unit = unit_index(value.as_bytes()[value.len() - 1])?;
    let digits = &value[..value.len() - 1];
    let mut amount: u64 = 0;
    for &b in digits.as_bytes() {
        if !b.is_ascii_digit() {
            return None;
        }
        amount = amount
            .checked_mul(10)?
            .checked_add(u64::from(b - b'0'))?;
    }
    let nanos = amount.checked_mul(UNIT_NANOS[unit])?;
    if amount > MAX_AMOUNT && nanos != u64::MAX {
        return Some(u64::MAX);
    }
    Some(nanos)
}

/// Formats a timeout in nanoseconds for the `grpc-timeout` header (rounds up).
pub fn format(nanos: u64) -> String {
    if nanos == 0 {
        return "0n".to_string();
    }
    for (i, &unit_nanos) in UNIT_NANOS.iter().enumerate() {
        let amount = nanos.div_ceil(unit_nanos);
        if amount <= MAX_AMOUNT {
            return format!("{amount}{}", UNIT_CHARS[i]);
        }
    }
    format!("{MAX_AMOUNT}H")
}

fn unit_index(c: u8) -> Option<usize> {
    let ch = c as char;
    UNIT_CHARS.iter().position(|&u| u == ch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_50_milliseconds() {
        assert_eq!(parse("50m"), Some(50_000_000));
    }

    #[test]
    fn format_uses_finest_unit_that_fits() {
        assert_eq!(format(1), "1n");
        assert_eq!(format(999), "999n");
        assert_eq!(format(50_000_000), "50000000n");
    }

    #[test]
    fn parse_millisecond_header() {
        assert_eq!(parse("50m"), Some(50_000_000));
    }
}
