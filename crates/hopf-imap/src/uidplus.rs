// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! UIDPLUS response-code formatting (RFC 4315).

/// Format an `APPENDUID` response code body (without brackets).
pub fn format_appenduid(uid_validity: u64, uid: u64) -> String {
    format!("APPENDUID {uid_validity} {uid}")
}

/// Format a `COPYUID` response code body from parallel UID lists.
///
/// `source_uids` and `dest_uids` must be the same length and in matching order.
pub fn format_copyuid(uid_validity: u64, source_uids: &[u64], dest_uids: &[u64]) -> String {
    format!(
        "COPYUID {uid_validity} {} {}",
        compress_uid_set(source_uids),
        compress_uid_set(dest_uids)
    )
}

/// Compress a sorted or unsorted UID list into IMAP set syntax (`1,3:5,9`).
pub fn compress_uid_set(uids: &[u64]) -> String {
    if uids.is_empty() {
        return String::new();
    }
    let mut sorted = uids.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut parts = Vec::new();
    let mut start = sorted[0];
    let mut prev = sorted[0];
    for &u in &sorted[1..] {
        if u == prev + 1 {
            prev = u;
            continue;
        }
        parts.push(format_range(start, prev));
        start = u;
        prev = u;
    }
    parts.push(format_range(start, prev));
    parts.join(",")
}

fn format_range(start: u64, end: u64) -> String {
    if start == end {
        start.to_string()
    } else {
        format!("{start}:{end}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appenduid_format() {
        assert_eq!(format_appenduid(42, 7), "APPENDUID 42 7");
    }

    #[test]
    fn copyuid_format() {
        assert_eq!(
            format_copyuid(99, &[1, 2, 5], &[10, 11, 20]),
            "COPYUID 99 1:2,5 10:11,20"
        );
    }

    #[test]
    fn compress_contiguous() {
        assert_eq!(compress_uid_set(&[1, 2, 3, 5]), "1:3,5");
        assert_eq!(compress_uid_set(&[7]), "7");
        assert_eq!(compress_uid_set(&[]), "");
    }
}
