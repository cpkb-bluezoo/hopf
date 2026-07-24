// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Frequently used entries from RFC 9204 Appendix A.

/// A QPACK static-table entry (indices are zero-based).
#[derive(Clone, Copy)]
pub struct StaticEntry {
    /// Header name.
    pub name: &'static str,
    /// Header value.
    pub value: &'static str,
}

/// Static entries needed by common HTTP/3 requests and responses.
pub static STATIC_TABLE: &[StaticEntry] = &[
    StaticEntry {
        name: ":authority",
        value: "",
    }, // 0
    StaticEntry {
        name: ":path",
        value: "/",
    }, // 1
    StaticEntry {
        name: "age",
        value: "0",
    }, // 2
    StaticEntry {
        name: "content-disposition",
        value: "",
    }, // 3
    StaticEntry {
        name: "content-length",
        value: "0",
    }, // 4
    StaticEntry {
        name: "cookie",
        value: "",
    }, // 5
    StaticEntry {
        name: "date",
        value: "",
    }, // 6
    StaticEntry {
        name: "etag",
        value: "",
    }, // 7
    StaticEntry {
        name: "if-modified-since",
        value: "",
    }, // 8
    StaticEntry {
        name: "if-none-match",
        value: "",
    }, // 9
    StaticEntry {
        name: "last-modified",
        value: "",
    }, // 10
    StaticEntry {
        name: "link",
        value: "",
    }, // 11
    StaticEntry {
        name: "location",
        value: "",
    }, // 12
    StaticEntry {
        name: "referer",
        value: "",
    }, // 13
    StaticEntry {
        name: "set-cookie",
        value: "",
    }, // 14
    StaticEntry {
        name: ":method",
        value: "CONNECT",
    }, // 15
    StaticEntry {
        name: ":method",
        value: "DELETE",
    }, // 16
    StaticEntry {
        name: ":method",
        value: "GET",
    }, // 17
    StaticEntry {
        name: ":method",
        value: "HEAD",
    }, // 18
    StaticEntry {
        name: ":method",
        value: "OPTIONS",
    }, // 19
    StaticEntry {
        name: ":method",
        value: "POST",
    }, // 20
    StaticEntry {
        name: ":method",
        value: "PUT",
    }, // 21
    StaticEntry {
        name: ":scheme",
        value: "http",
    }, // 22
    StaticEntry {
        name: ":scheme",
        value: "https",
    }, // 23
    StaticEntry {
        name: ":status",
        value: "103",
    }, // 24
    StaticEntry {
        name: ":status",
        value: "200",
    }, // 25
    StaticEntry {
        name: ":status",
        value: "304",
    }, // 26
    StaticEntry {
        name: ":status",
        value: "404",
    }, // 27
    StaticEntry {
        name: ":status",
        value: "503",
    }, // 28
    StaticEntry {
        name: "accept",
        value: "*/*",
    }, // 29
    StaticEntry {
        name: "content-type",
        value: "",
    }, // name reference
    StaticEntry {
        name: "content-length",
        value: "",
    }, // name reference
    StaticEntry {
        name: "server",
        value: "",
    }, // name reference
    StaticEntry {
        name: "user-agent",
        value: "",
    }, // name reference
];

/// Look up an exact static entry.
pub fn find(name: &str, value: &str) -> Option<usize> {
    STATIC_TABLE
        .iter()
        .position(|entry| entry.name == name && entry.value == value)
}

/// Look up a static name.
pub fn find_name(name: &str) -> Option<usize> {
    STATIC_TABLE.iter().position(|entry| entry.name == name)
}

/// Resolve an index.
pub fn get(index: usize) -> Option<StaticEntry> {
    STATIC_TABLE.get(index).copied()
}
