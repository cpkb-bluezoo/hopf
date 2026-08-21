// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! RFC 9204 Appendix A — QPACK static table (indices 0–98).

/// A QPACK static-table entry (indices are zero-based).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StaticEntry {
    /// Header name.
    pub name: &'static str,
    /// Header value.
    pub value: &'static str,
}

/// All 99 static entries from RFC 9204 Appendix A.
pub static STATIC_TABLE: &[StaticEntry] = &[
    StaticEntry { name: ":authority", value: "" },                              // 0
    StaticEntry { name: ":path", value: "/" },                                    // 1
    StaticEntry { name: "age", value: "0" },                                      // 2
    StaticEntry { name: "content-disposition", value: "" },                       // 3
    StaticEntry { name: "content-length", value: "0" },                           // 4
    StaticEntry { name: "cookie", value: "" },                                    // 5
    StaticEntry { name: "date", value: "" },                                      // 6
    StaticEntry { name: "etag", value: "" },                                      // 7
    StaticEntry { name: "if-modified-since", value: "" },                         // 8
    StaticEntry { name: "if-none-match", value: "" },                             // 9
    StaticEntry { name: "last-modified", value: "" },                             // 10
    StaticEntry { name: "link", value: "" },                                      // 11
    StaticEntry { name: "location", value: "" },                                  // 12
    StaticEntry { name: "referer", value: "" },                                   // 13
    StaticEntry { name: "set-cookie", value: "" },                                // 14
    StaticEntry { name: ":method", value: "CONNECT" },                            // 15
    StaticEntry { name: ":method", value: "DELETE" },                             // 16
    StaticEntry { name: ":method", value: "GET" },                                // 17
    StaticEntry { name: ":method", value: "HEAD" },                               // 18
    StaticEntry { name: ":method", value: "OPTIONS" },                            // 19
    StaticEntry { name: ":method", value: "POST" },                               // 20
    StaticEntry { name: ":method", value: "PUT" },                                // 21
    StaticEntry { name: ":scheme", value: "http" },                               // 22
    StaticEntry { name: ":scheme", value: "https" },                              // 23
    StaticEntry { name: ":status", value: "103" },                                // 24
    StaticEntry { name: ":status", value: "200" },                                // 25
    StaticEntry { name: ":status", value: "304" },                                // 26
    StaticEntry { name: ":status", value: "404" },                                // 27
    StaticEntry { name: ":status", value: "503" },                                // 28
    StaticEntry { name: "accept", value: "*/*" },                                 // 29
    StaticEntry { name: "accept", value: "application/dns-message" },             // 30
    StaticEntry { name: "accept-encoding", value: "gzip, deflate, br" },          // 31
    StaticEntry { name: "accept-ranges", value: "bytes" },                        // 32
    StaticEntry { name: "access-control-allow-headers", value: "cache-control" }, // 33
    StaticEntry { name: "access-control-allow-headers", value: "content-type" },  // 34
    StaticEntry { name: "access-control-allow-origin", value: "*" },              // 35
    StaticEntry { name: "cache-control", value: "max-age=0" },                    // 36
    StaticEntry { name: "cache-control", value: "max-age=2592000" },              // 37
    StaticEntry { name: "cache-control", value: "max-age=604800" },               // 38
    StaticEntry { name: "cache-control", value: "no-cache" },                     // 39
    StaticEntry { name: "cache-control", value: "no-store" },                     // 40
    StaticEntry {
        name: "cache-control",
        value: "public, max-age=31536000",
    }, // 41
    StaticEntry { name: "content-encoding", value: "br" },                       // 42
    StaticEntry { name: "content-encoding", value: "gzip" },                     // 43
    StaticEntry { name: "content-type", value: "application/dns-message" },      // 44
    StaticEntry { name: "content-type", value: "application/javascript" },       // 45
    StaticEntry { name: "content-type", value: "application/json" },             // 46
    StaticEntry {
        name: "content-type",
        value: "application/x-www-form-urlencoded",
    }, // 47
    StaticEntry { name: "content-type", value: "image/gif" },                    // 48
    StaticEntry { name: "content-type", value: "image/jpeg" },                   // 49
    StaticEntry { name: "content-type", value: "image/png" },                    // 50
    StaticEntry { name: "content-type", value: "text/css" },                     // 51
    StaticEntry { name: "content-type", value: "text/html; charset=utf-8" },     // 52
    StaticEntry { name: "content-type", value: "text/plain" },                   // 53
    StaticEntry { name: "content-type", value: "text/plain;charset=utf-8" },     // 54
    StaticEntry { name: "range", value: "bytes=0-" },                            // 55
    StaticEntry {
        name: "strict-transport-security",
        value: "max-age=31536000",
    }, // 56
    StaticEntry {
        name: "strict-transport-security",
        value: "max-age=31536000; includesubdomains",
    }, // 57
    StaticEntry {
        name: "strict-transport-security",
        value: "max-age=31536000; includesubdomains; preload",
    }, // 58
    StaticEntry { name: "vary", value: "accept-encoding" },                      // 59
    StaticEntry { name: "vary", value: "origin" },                               // 60
    StaticEntry { name: "x-content-type-options", value: "nosniff" },            // 61
    StaticEntry { name: "x-xss-protection", value: "1; mode=block" },            // 62
    StaticEntry { name: ":status", value: "100" },                               // 63
    StaticEntry { name: ":status", value: "204" },                               // 64
    StaticEntry { name: ":status", value: "206" },                               // 65
    StaticEntry { name: ":status", value: "302" },                               // 66
    StaticEntry { name: ":status", value: "400" },                               // 67
    StaticEntry { name: ":status", value: "403" },                               // 68
    StaticEntry { name: ":status", value: "421" },                               // 69
    StaticEntry { name: ":status", value: "425" },                               // 70
    StaticEntry { name: ":status", value: "500" },                               // 71
    StaticEntry { name: "accept-language", value: "" },                          // 72
    StaticEntry {
        name: "access-control-allow-credentials",
        value: "FALSE",
    }, // 73
    StaticEntry {
        name: "access-control-allow-credentials",
        value: "TRUE",
    }, // 74
    StaticEntry { name: "access-control-allow-headers", value: "*" },            // 75
    StaticEntry { name: "access-control-allow-methods", value: "get" },          // 76
    StaticEntry {
        name: "access-control-allow-methods",
        value: "get, post, options",
    }, // 77
    StaticEntry { name: "access-control-allow-methods", value: "options" },      // 78
    StaticEntry {
        name: "access-control-expose-headers",
        value: "content-length",
    }, // 79
    StaticEntry {
        name: "access-control-request-headers",
        value: "content-type",
    }, // 80
    StaticEntry { name: "access-control-request-method", value: "get" },         // 81
    StaticEntry { name: "access-control-request-method", value: "post" },        // 82
    StaticEntry { name: "alt-svc", value: "clear" },                             // 83
    StaticEntry { name: "authorization", value: "" },                            // 84
    StaticEntry {
        name: "content-security-policy",
        value: "script-src 'none'; object-src 'none'; base-uri 'none'",
    }, // 85
    StaticEntry { name: "early-data", value: "1" },                              // 86
    StaticEntry { name: "expect-ct", value: "" },                                // 87
    StaticEntry { name: "forwarded", value: "" },                                // 88
    StaticEntry { name: "if-range", value: "" },                                 // 89
    StaticEntry { name: "origin", value: "" },                                   // 90
    StaticEntry { name: "purpose", value: "prefetch" },                          // 91
    StaticEntry { name: "server", value: "" },                                   // 92
    StaticEntry { name: "timing-allow-origin", value: "*" },                     // 93
    StaticEntry { name: "upgrade-insecure-requests", value: "1" },               // 94
    StaticEntry { name: "user-agent", value: "" },                               // 95
    StaticEntry { name: "x-forwarded-for", value: "" },                          // 96
    StaticEntry { name: "x-frame-options", value: "deny" },                      // 97
    StaticEntry { name: "x-frame-options", value: "sameorigin" },                // 98
];

/// Look up an exact static entry.
pub fn find(name: &str, value: &str) -> Option<usize> {
    STATIC_TABLE
        .iter()
        .position(|entry| entry.name == name && entry.value == value)
}

/// Look up a static name (first matching index; any index with that name is
/// valid for an Indexed Name With Literal Value reference).
pub fn find_name(name: &str) -> Option<usize> {
    STATIC_TABLE.iter().position(|entry| entry.name == name)
}

/// RFC 9204 §3.2.1 dynamic-table entry size: name+value lengths plus 32
/// bytes of accounting overhead (identical formula to HPACK, RFC 7541
/// §4.1).
pub(crate) fn entry_size(name: &str, value: &str) -> usize {
    name.len() + value.len() + 32
}

/// Resolve an index.
pub fn get(index: usize) -> Option<StaticEntry> {
    STATIC_TABLE.get(index).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exact RFC 9204 Appendix A table — kept inline so a drift in
    /// `STATIC_TABLE` fails this test rather than silently breaking interop
    /// with browsers/curl (the old truncated table collided from index 30).
    const RFC_9204_APPENDIX_A: &[(&str, &str)] = &[
        (":authority", ""),
        (":path", "/"),
        ("age", "0"),
        ("content-disposition", ""),
        ("content-length", "0"),
        ("cookie", ""),
        ("date", ""),
        ("etag", ""),
        ("if-modified-since", ""),
        ("if-none-match", ""),
        ("last-modified", ""),
        ("link", ""),
        ("location", ""),
        ("referer", ""),
        ("set-cookie", ""),
        (":method", "CONNECT"),
        (":method", "DELETE"),
        (":method", "GET"),
        (":method", "HEAD"),
        (":method", "OPTIONS"),
        (":method", "POST"),
        (":method", "PUT"),
        (":scheme", "http"),
        (":scheme", "https"),
        (":status", "103"),
        (":status", "200"),
        (":status", "304"),
        (":status", "404"),
        (":status", "503"),
        ("accept", "*/*"),
        ("accept", "application/dns-message"),
        ("accept-encoding", "gzip, deflate, br"),
        ("accept-ranges", "bytes"),
        ("access-control-allow-headers", "cache-control"),
        ("access-control-allow-headers", "content-type"),
        ("access-control-allow-origin", "*"),
        ("cache-control", "max-age=0"),
        ("cache-control", "max-age=2592000"),
        ("cache-control", "max-age=604800"),
        ("cache-control", "no-cache"),
        ("cache-control", "no-store"),
        ("cache-control", "public, max-age=31536000"),
        ("content-encoding", "br"),
        ("content-encoding", "gzip"),
        ("content-type", "application/dns-message"),
        ("content-type", "application/javascript"),
        ("content-type", "application/json"),
        ("content-type", "application/x-www-form-urlencoded"),
        ("content-type", "image/gif"),
        ("content-type", "image/jpeg"),
        ("content-type", "image/png"),
        ("content-type", "text/css"),
        ("content-type", "text/html; charset=utf-8"),
        ("content-type", "text/plain"),
        ("content-type", "text/plain;charset=utf-8"),
        ("range", "bytes=0-"),
        ("strict-transport-security", "max-age=31536000"),
        (
            "strict-transport-security",
            "max-age=31536000; includesubdomains",
        ),
        (
            "strict-transport-security",
            "max-age=31536000; includesubdomains; preload",
        ),
        ("vary", "accept-encoding"),
        ("vary", "origin"),
        ("x-content-type-options", "nosniff"),
        ("x-xss-protection", "1; mode=block"),
        (":status", "100"),
        (":status", "204"),
        (":status", "206"),
        (":status", "302"),
        (":status", "400"),
        (":status", "403"),
        (":status", "421"),
        (":status", "425"),
        (":status", "500"),
        ("accept-language", ""),
        ("access-control-allow-credentials", "FALSE"),
        ("access-control-allow-credentials", "TRUE"),
        ("access-control-allow-headers", "*"),
        ("access-control-allow-methods", "get"),
        ("access-control-allow-methods", "get, post, options"),
        ("access-control-allow-methods", "options"),
        ("access-control-expose-headers", "content-length"),
        ("access-control-request-headers", "content-type"),
        ("access-control-request-method", "get"),
        ("access-control-request-method", "post"),
        ("alt-svc", "clear"),
        ("authorization", ""),
        (
            "content-security-policy",
            "script-src 'none'; object-src 'none'; base-uri 'none'",
        ),
        ("early-data", "1"),
        ("expect-ct", ""),
        ("forwarded", ""),
        ("if-range", ""),
        ("origin", ""),
        ("purpose", "prefetch"),
        ("server", ""),
        ("timing-allow-origin", "*"),
        ("upgrade-insecure-requests", "1"),
        ("user-agent", ""),
        ("x-forwarded-for", ""),
        ("x-frame-options", "deny"),
        ("x-frame-options", "sameorigin"),
    ];

    #[test]
    fn static_table_matches_rfc_9204_appendix_a_index_by_index() {
        assert_eq!(STATIC_TABLE.len(), 99, "Appendix A has indices 0..=98");
        assert_eq!(RFC_9204_APPENDIX_A.len(), 99);
        for (i, ((name, value), entry)) in RFC_9204_APPENDIX_A
            .iter()
            .zip(STATIC_TABLE.iter())
            .enumerate()
        {
            assert_eq!(
                (entry.name, entry.value),
                (*name, *value),
                "mismatch at static index {i}"
            );
        }
    }

    #[test]
    fn former_collision_indices_are_spec_entries_not_fake_name_only() {
        // The old table put content-type/content-length/server/user-agent
        // name-only stubs at 30–33; those indices must be the Appendix A
        // entries instead.
        assert_eq!(get(30).unwrap().name, "accept");
        assert_eq!(get(30).unwrap().value, "application/dns-message");
        assert_eq!(get(31).unwrap().name, "accept-encoding");
        assert_eq!(find("server", ""), Some(92));
        assert_eq!(find("user-agent", ""), Some(95));
        assert_eq!(find_name("content-type"), Some(44));
    }
}
