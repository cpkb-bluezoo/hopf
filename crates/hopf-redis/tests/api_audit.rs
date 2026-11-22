// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! The crate offers no call that returns, or passes to a callback, a value whose
//! size depends on what a server holds.
//!
//! This is the rule the crate is built on (payloads stream, identifiers are
//! bounded, scalars are values), and it is easy to break by adding one helpful
//! method, so it is checked: every public function's signature is read from the
//! source, and each type a callback is given, and each type a function returns,
//! must be on a short list of types that cannot be large, each with its reason.
//! A new type means a decision, made here, in review.

use std::fs;
use std::path::Path;

/// What a callback may be given: nothing whose size a server decides.
const CALLBACK_ARGS: &[(&str, &str)] = &[
    ("Reply", "a single value (ScalarValue): a number, OK, nil"),
    ("Result<(),RedisError>", "OK"),
    ("Result<bool,RedisError>", "a flag"),
    ("Result<i64,RedisError>", "a count"),
    ("Result<f64,RedisError>", "a number"),
    ("Result<Option<f64>,RedisError>", "a number or nil"),
    ("Result<u32,RedisError>", "a replica count"),
    ("Result<(u32,u32),RedisError>", "a pair of counts"),
    ("Result<String,RedisError>", "SCRIPT LOAD: a SHA-1, read under a cap of 256 bytes"),
    ("NodeAddr,Reply", "a node, and its single-value reply"),
    ("RedisConfig", "a configuration the caller is building"),
    ("", "a callback that is given nothing"),
    ("NodeAddr", "a node of the layout"),
    ("&NodeAddr", "a node of the layout"),
];

/// What a public function may return, besides the types that hold no data.
const RETURNS: &[(&str, &str)] = &[
    ("Option<(String,u16)>", "owner_of: a node of the cluster's layout, whose size is the cluster's"),
    ("Vec<(String,u16)>", "masters: the nodes of the layout, a number the operator chose"),
    ("(Vec<Bytes>,Vec<Bytes>,Vec<Bytes>)", "subscriptions: what the application itself subscribed to"),
    ("&[Vec<u8>]", "Command::words: the command the application built"),
    ("Option<Vec<u8>>", "Command::name-like accessors over what the application built"),
    ("&str", "a name"),
    ("&[u8]", "a field of what the caller built, or a header the library bounded"),
    ("String", "a name or an address"),
    ("Vec<u8>", "an encoding of a command the application built"),
    ("Option<&str>", "text of a scalar or an error"),
    ("Option<&[u8]>", "a field of what the caller built, or a header the library bounded"),
    ("&Self", "a builder"),
    ("(Vec<Bytes>,Vec<Bytes>,Vec<Bytes>,Vec<Bytes>)", "RedisClusterSubscriber::subscriptions: what the application itself subscribed to"),
    ("Vec<(NodeAddr,bool)>", "RedisClusterSubscriber::connections: the nodes in use, a number the layout sets"),
    ("&'a[u8]", "MessageHeader: the channel, an identifier bounded by max_field"),
    ("Option<&'a[u8]>", "MessageHeader: the pattern, an identifier bounded by max_field"),
    ("SubscriptionKind", "a tag"),
    ("&H", "InvalidationSink::handler: the application's own handler"),
    ("SourceWaker", "a handle that wakes the connection"),
    ("Result<Option<u16>,CrossSlot>", "command_slot: a slot, computed from a command the caller built"),
    ("Vec<usize>", "key_indexes: positions in a command the caller built"),
    ("Option<NodeAddr>", "a node of the layout"),
    ("Option<i64>", "a number, from a scalar"),
    ("Option<f64>", "a number, from a scalar"),
    ("Option<u16>", "a slot"),
    ("Option<&Self>", "an accessor"),
    ("Option<NodeAddr>", "a node of the layout"),
];

fn read(name: &str) -> String {
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(name)).unwrap()
}

/// The text of every `pub fn` declaration in `src`, from `pub fn` to its `{` or `;`.
fn signatures(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = src.as_bytes();
    let mut from = 0;
    while let Some(at) = src[from..].find("pub fn ") {
        let start = from + at;
        let mut depth = 0i32;
        let mut end = start;
        for (i, &b) in bytes[start..].iter().enumerate() {
            match b {
                b'(' | b'<' | b'[' => depth += 1,
                // `->` is not a closing angle bracket.
                b'>' if i > 0 && bytes[start + i - 1] == b'-' => {}
                b')' | b'>' | b']' => depth -= 1,
                b'{' | b';' if depth <= 0 => {
                    end = start + i;
                    break;
                }
                _ => {}
            }
        }
        out.push(src[start..end].split_whitespace().collect::<Vec<_>>().join(" "));
        from = end.max(start + 1);
    }
    out
}

/// The argument lists of the `FnOnce(...)` and `FnMut(...)` callbacks in a signature.
fn callbacks(sig: &str) -> Vec<String> {
    let mut out = Vec::new();
    for marker in ["FnOnce(", "FnMut("] {
        let mut from = 0;
        while let Some(at) = sig[from..].find(marker) {
            let open = from + at + marker.len();
            let mut depth = 1;
            let mut close = open;
            for (i, c) in sig[open..].char_indices() {
                match c {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            close = open + i;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            out.push(sig[open..close].replace(' ', ""));
            from = close;
        }
    }
    out
}

/// The type after `->`, if there is one: after the parameter list, not inside it.
fn returns(sig: &str) -> Option<String> {
    let open = sig.find('(')?;
    let mut depth = 0;
    let mut close = open;
    for (i, c) in sig[open..].char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    close = open + i;
                    break;
                }
            }
            _ => {}
        }
    }
    let rest = sig[close + 1..].trim_start();
    let ret = rest.strip_prefix("-> ")?;
    // Without a `where` clause that follows.
    let ret = ret.split(" where ").next().unwrap_or(ret);
    Some(ret.replace(' ', ""))
}

/// Types that hold nothing a server decides the size of.
fn is_small_return(t: &str) -> bool {
    matches!(
        t,
        "Self" | "bool" | "u16" | "u32" | "u64" | "usize" | "i64" | "f64" | "()" | "StreamHandle" | "Option<Arc<Cmd>>"
    ) || t.starts_with("Result<Self,") || t.starts_with("impl ") || t == "Option<Self>"
}

fn audited_files() -> Vec<&'static str> {
    vec!["client.rs", "cluster.rs", "commands.rs", "sinks.rs", "pubsub.rs", "config.rs", "argstream.rs", "keys.rs", "topology.rs", "clustersub.rs"]
}

#[test]
fn no_public_callback_is_given_a_value_a_server_sizes() {
    let allowed: Vec<&str> = CALLBACK_ARGS.iter().map(|(t, _)| *t).collect();
    let mut seen = 0;
    for file in audited_files() {
        for sig in signatures(&read(file)) {
            // Crate-internal functions are not the API.
            if sig.starts_with("pub(crate)") {
                continue;
            }
            for args in callbacks(&sig) {
                seen += 1;
                assert!(
                    allowed.contains(&args.as_str()),
                    "{file}: a public callback is given `{args}`, which is not on the list of types that cannot be large \
                     (see CALLBACK_ARGS): `{sig}`"
                );
            }
        }
    }
    assert!(seen > 40, "the audit found {seen} callbacks: it has stopped reading the source");
}

#[test]
fn no_public_function_returns_a_value_a_server_sizes() {
    let allowed: Vec<&str> = RETURNS.iter().map(|(t, _)| *t).collect();
    let mut seen = 0;
    for file in audited_files() {
        for sig in signatures(&read(file)) {
            if sig.starts_with("pub(crate)") {
                continue;
            }
            let Some(ret) = returns(&sig) else { continue };
            seen += 1;
            assert!(
                is_small_return(&ret) || allowed.contains(&ret.as_str()),
                "{file}: a public function returns `{ret}`, which is not on the list of types that cannot be large \
                 (see RETURNS): `{sig}`"
            );
        }
    }
    assert!(seen > 20, "the audit found {seen} return types: it has stopped reading the source");
}

#[test]
fn the_unbounded_types_and_limits_are_not_public() {
    let lib = read("lib.rs");
    let resp = read("resp.rs");
    // The crate does not export a value type, and has no limit that exists to size a buffer.
    assert!(
        !lib.split(|c: char| !c.is_alphanumeric()).any(|w| w == "Value"),
        "lib.rs mentions a whole-reply value type"
    );
    assert!(resp.contains("pub(crate) enum Value"), "Value is public");
    for gone in ["pub max_bulk", "pub max_aggregate", "pub max_reply_bytes", "pub fn feed_values"] {
        assert!(!resp.contains(gone), "`{gone}` is back");
    }
}

#[test]
fn the_audit_catches_what_it_is_for() {
    // A helper that returned a whole value would fail it.
    let sigs = signatures("pub fn get(&self, key: impl AsRef<[u8]>, callback: impl FnOnce(Result<Option<Bytes>, RedisError>) + Send + 'static) {");
    assert_eq!(callbacks(&sigs[0]), vec!["Result<Option<Bytes>,RedisError>"]);
    assert!(!CALLBACK_ARGS.iter().any(|(t, _)| *t == "Result<Option<Bytes>,RedisError>"));
    let sigs = signatures("pub fn lrange(&self, key: &str) -> Vec<Bytes> {");
    assert_eq!(returns(&sigs[0]).as_deref(), Some("Vec<Bytes>"));
    assert!(!is_small_return("Vec<Bytes>") && !RETURNS.iter().any(|(t, _)| *t == "Vec<Bytes>"));
}
