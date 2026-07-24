// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! RFC 7541 Appendix A — static header table (indices 1–61).

/// One entry in the static header table.
#[derive(Debug, Clone, Copy)]
pub struct StaticEntry {
    /// Header field name (lower-case, including leading `:` for pseudo-headers).
    pub name: &'static str,
    /// Header field value; empty string for name-only entries.
    pub value: &'static str,
}

/// All 61 static table entries; `STATIC_TABLE[i]` corresponds to index `i+1`.
pub static STATIC_TABLE: [StaticEntry; 61] = [
    StaticEntry {
        name: ":authority",
        value: "",
    },
    StaticEntry {
        name: ":method",
        value: "GET",
    },
    StaticEntry {
        name: ":method",
        value: "POST",
    },
    StaticEntry {
        name: ":path",
        value: "/",
    },
    StaticEntry {
        name: ":path",
        value: "/index.html",
    },
    StaticEntry {
        name: ":scheme",
        value: "http",
    },
    StaticEntry {
        name: ":scheme",
        value: "https",
    },
    StaticEntry {
        name: ":status",
        value: "200",
    },
    StaticEntry {
        name: ":status",
        value: "204",
    },
    StaticEntry {
        name: ":status",
        value: "206",
    },
    StaticEntry {
        name: ":status",
        value: "304",
    },
    StaticEntry {
        name: ":status",
        value: "400",
    },
    StaticEntry {
        name: ":status",
        value: "404",
    },
    StaticEntry {
        name: ":status",
        value: "500",
    },
    StaticEntry {
        name: "accept-charset",
        value: "",
    },
    StaticEntry {
        name: "accept-encoding",
        value: "gzip, deflate",
    },
    StaticEntry {
        name: "accept-language",
        value: "",
    },
    StaticEntry {
        name: "accept-ranges",
        value: "",
    },
    StaticEntry {
        name: "accept",
        value: "",
    },
    StaticEntry {
        name: "access-control-allow-origin",
        value: "",
    },
    StaticEntry {
        name: "age",
        value: "",
    },
    StaticEntry {
        name: "allow",
        value: "",
    },
    StaticEntry {
        name: "authorization",
        value: "",
    },
    StaticEntry {
        name: "cache-control",
        value: "",
    },
    StaticEntry {
        name: "content-disposition",
        value: "",
    },
    StaticEntry {
        name: "content-encoding",
        value: "",
    },
    StaticEntry {
        name: "content-language",
        value: "",
    },
    StaticEntry {
        name: "content-length",
        value: "",
    },
    StaticEntry {
        name: "content-location",
        value: "",
    },
    StaticEntry {
        name: "content-range",
        value: "",
    },
    StaticEntry {
        name: "content-type",
        value: "",
    },
    StaticEntry {
        name: "cookie",
        value: "",
    },
    StaticEntry {
        name: "date",
        value: "",
    },
    StaticEntry {
        name: "etag",
        value: "",
    },
    StaticEntry {
        name: "expect",
        value: "",
    },
    StaticEntry {
        name: "expires",
        value: "",
    },
    StaticEntry {
        name: "from",
        value: "",
    },
    StaticEntry {
        name: "host",
        value: "",
    },
    StaticEntry {
        name: "if-match",
        value: "",
    },
    StaticEntry {
        name: "if-modified-since",
        value: "",
    },
    StaticEntry {
        name: "if-none-match",
        value: "",
    },
    StaticEntry {
        name: "if-range",
        value: "",
    },
    StaticEntry {
        name: "if-unmodified-since",
        value: "",
    },
    StaticEntry {
        name: "last-modified",
        value: "",
    },
    StaticEntry {
        name: "link",
        value: "",
    },
    StaticEntry {
        name: "location",
        value: "",
    },
    StaticEntry {
        name: "max-forwards",
        value: "",
    },
    StaticEntry {
        name: "proxy-authenticate",
        value: "",
    },
    StaticEntry {
        name: "proxy-authorization",
        value: "",
    },
    StaticEntry {
        name: "range",
        value: "",
    },
    StaticEntry {
        name: "referer",
        value: "",
    },
    StaticEntry {
        name: "refresh",
        value: "",
    },
    StaticEntry {
        name: "retry-after",
        value: "",
    },
    StaticEntry {
        name: "server",
        value: "",
    },
    StaticEntry {
        name: "set-cookie",
        value: "",
    },
    StaticEntry {
        name: "strict-transport-security",
        value: "",
    },
    StaticEntry {
        name: "transfer-encoding",
        value: "",
    },
    StaticEntry {
        name: "user-agent",
        value: "",
    },
    StaticEntry {
        name: "vary",
        value: "",
    },
    StaticEntry {
        name: "via",
        value: "",
    },
    StaticEntry {
        name: "www-authenticate",
        value: "",
    },
];

/// Entry size as defined in RFC 7541 §4.1: `name.len() + value.len() + 32`.
pub fn entry_size(name: &str, value: &str) -> usize {
    name.len() + value.len() + 32
}

/// Lookup by 1-based index (1–61). Returns `None` for out-of-range.
pub fn get(index: usize) -> Option<(&'static str, &'static str)> {
    if index == 0 || index > 61 {
        return None;
    }
    let e = &STATIC_TABLE[index - 1];
    Some((e.name, e.value))
}

/// Find the first static entry whose name matches (case-insensitive).
/// Returns `(index, full_match)` where `full_match` means both name and value matched.
pub fn find(name: &str, value: &str) -> Option<(usize, bool)> {
    let mut name_match: Option<usize> = None;
    for (i, e) in STATIC_TABLE.iter().enumerate() {
        if e.name.eq_ignore_ascii_case(name) {
            if e.value == value {
                return Some((i + 1, true));
            }
            if name_match.is_none() {
                name_match = Some(i + 1);
            }
        }
    }
    name_match.map(|idx| (idx, false))
}
