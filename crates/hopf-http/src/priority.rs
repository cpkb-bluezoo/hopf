// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Extensible Prioritization Scheme for HTTP (RFC 9218).
//!
//! Shared `u` / `i` parameter parsing and encoding for the `Priority` header
//! field and `PRIORITY_UPDATE` frames (Structured Fields Dictionary).

/// Default urgency when the parameter is absent (RFC 9218 §4.1).
pub const DEFAULT_URGENCY: u8 = 3;
/// Highest urgency (most important).
pub const URGENCY_HIGHEST: u8 = 0;
/// Lowest urgency (background).
pub const URGENCY_LOWEST: u8 = 7;

/// `Priority` header field name (RFC 9218 §5).
pub const PRIORITY_HEADER: &str = "priority";

/// Parsed priority parameters (RFC 9218 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PriorityParams {
    /// Urgency 0..=7 (0 = highest). Default [`DEFAULT_URGENCY`].
    pub urgency: u8,
    /// Whether the response is useful when delivered incrementally.
    /// Default `false`.
    pub incremental: bool,
}

impl Default for PriorityParams {
    fn default() -> Self {
        Self {
            urgency: DEFAULT_URGENCY,
            incremental: false,
        }
    }
}

impl PriorityParams {
    /// Construct with explicit values (clamped into range).
    pub fn new(urgency: u8, incremental: bool) -> Self {
        Self {
            urgency: urgency.min(URGENCY_LOWEST),
            incremental,
        }
    }

    /// Map urgency onto quinn-proto's stream priority (`i32`, higher = sooner).
    pub fn quinn_priority(self) -> i32 {
        i32::from(URGENCY_LOWEST - self.urgency)
    }

    /// Encode as a Structured Fields Dictionary suitable for the `Priority`
    /// header or a PRIORITY_UPDATE payload (RFC 9218 §4–§5).
    pub fn encode(&self) -> String {
        if self.incremental {
            if self.urgency == DEFAULT_URGENCY {
                "i".to_string()
            } else {
                format!("u={}, i", self.urgency)
            }
        } else if self.urgency == DEFAULT_URGENCY {
            String::new()
        } else {
            format!("u={}", self.urgency)
        }
    }

    /// Parse a Priority Field Value (Dictionary). Unknown keys and out-of-range
    /// values are ignored (RFC 9218 §4). On total parse failure returns
    /// [`Default`].
    pub fn parse(input: &str) -> Self {
        let mut out = Self::default();
        for member in split_dict_members(input) {
            let (key, value) = match member.split_once('=') {
                Some((k, v)) => (k.trim(), Some(v.trim())),
                None => (member.trim(), None),
            };
            if key.is_empty() {
                continue;
            }
            match key {
                "u" => {
                    if let Some(v) = value {
                        if let Ok(n) = v.parse::<i64>() {
                            if (0..=7).contains(&n) {
                                out.urgency = n as u8;
                            }
                        }
                    }
                }
                "i" => {
                    // Boolean: bare `i`, `i=?1`, `i=?0`, `i=1`, `i=0`.
                    out.incremental = match value {
                        None => true,
                        Some("?1") | Some("1") | Some("true") => true,
                        Some("?0") | Some("0") | Some("false") => false,
                        _ => out.incremental,
                    };
                }
                _ => {}
            }
        }
        out
    }

    /// Parse from request/response headers (`Priority` field), or default.
    pub fn from_headers(headers: &crate::Headers) -> Self {
        headers
            .get(PRIORITY_HEADER)
            .map(Self::parse)
            .unwrap_or_default()
    }
}

/// Split a Dictionary into members on top-level commas (no nested SF support
/// beyond what RFC 9218 needs for `u` / `i`).
fn split_dict_members(input: &str) -> impl Iterator<Item = &str> {
    input.split(',').map(str::trim).filter(|s| !s.is_empty())
}

/// Ordering key for scheduling: lower = flush sooner.
///
/// Order: urgency ascending, then incremental before non-incremental, then
/// stream id (request order) for stable ties.
pub fn schedule_key(params: PriorityParams, stream_id: u64) -> (u8, u8, u64) {
    (
        params.urgency,
        if params.incremental { 0 } else { 1 },
        stream_id,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Headers;

    #[test]
    fn parse_defaults() {
        assert_eq!(PriorityParams::parse(""), PriorityParams::default());
        assert_eq!(PriorityParams::parse("   "), PriorityParams::default());
    }

    #[test]
    fn parse_urgency_and_incremental() {
        assert_eq!(
            PriorityParams::parse("u=0"),
            PriorityParams::new(0, false)
        );
        assert_eq!(
            PriorityParams::parse("u=5, i"),
            PriorityParams::new(5, true)
        );
        assert_eq!(
            PriorityParams::parse("i=?1, u=1"),
            PriorityParams::new(1, true)
        );
        assert_eq!(
            PriorityParams::parse("i=?0"),
            PriorityParams::new(DEFAULT_URGENCY, false)
        );
    }

    #[test]
    fn ignores_unknown_and_oor() {
        assert_eq!(
            PriorityParams::parse("u=9, foo=bar, i"),
            PriorityParams::new(DEFAULT_URGENCY, true)
        );
    }

    #[test]
    fn encode_round_trips_common_forms() {
        let p = PriorityParams::new(0, false);
        assert_eq!(PriorityParams::parse(&p.encode()), p);
        let p2 = PriorityParams::new(5, true);
        assert_eq!(PriorityParams::parse(&p2.encode()), p2);
    }

    #[test]
    fn quinn_priority_inverts_urgency() {
        assert!(PriorityParams::new(0, false).quinn_priority()
            > PriorityParams::new(7, false).quinn_priority());
    }

    #[test]
    fn from_headers() {
        let mut h = Headers::new();
        h.set("Priority", "u=1, i");
        assert_eq!(
            PriorityParams::from_headers(&h),
            PriorityParams::new(1, true)
        );
    }

    #[test]
    fn schedule_key_orders_urgency_then_incremental() {
        let a = schedule_key(PriorityParams::new(0, false), 4);
        let b = schedule_key(PriorityParams::new(1, true), 0);
        let c = schedule_key(PriorityParams::new(0, true), 8);
        assert!(c < a);
        assert!(a < b);
    }
}
