// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Reading what a cluster tells a client about itself: `CLUSTER SHARDS`,
//! `CLUSTER SLOTS`, and the `MOVED` and `ASK` redirections.

use crate::error::RedisError;
use crate::resp::Value;

/// Where a node can be reached.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NodeAddr {
    /// A host name or an address.
    pub host: String,
    /// The port.
    pub port: u16,
}

impl std::fmt::Display for NodeAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

/// A run of slots and the master that serves it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SlotRange {
    pub start: u16,
    pub end: u16,
    pub master: NodeAddr,
}

fn bad(msg: &str) -> RedisError {
    RedisError::Unexpected(format!("cluster topology: {msg}"))
}

/// A host the server may or may not have named: nil, empty and `?` mean it did
/// not, and the client uses the address it asked.
fn named_host(v: &Value) -> Option<String> {
    match v.as_str() {
        Some(s) if !s.is_empty() && s != "?" => Some(s.to_string()),
        _ => None,
    }
}

/// Read a `CLUSTER SHARDS` reply: each shard has `slots` (start, end, start,
/// end, ...) and `nodes`, each with a `role`, an `endpoint` or `ip`, a `port`
/// and, with TLS, a `tls-port`. `tls` says the connection is to be made over
/// TLS, so a node's TLS port is the one to use. `queried` is the node that
/// answered, for a node whose address it does not give.
pub(crate) fn parse_shards(reply: Value, tls: bool, queried: &NodeAddr) -> Result<Vec<SlotRange>, RedisError> {
    let shards = reply.into_array().ok_or_else(|| bad("CLUSTER SHARDS is not an array"))?;
    let mut ranges = Vec::new();
    for shard in shards {
        let fields = shard.into_pairs().ok_or_else(|| bad("a shard is not a map"))?;
        let mut slots = Vec::new();
        let mut master = None;
        for (k, v) in fields {
            match k.as_str() {
                Some("slots") => {
                    let ints = v.into_array().ok_or_else(|| bad("slots is not an array"))?;
                    for i in &ints {
                        slots.push(i.as_int().ok_or_else(|| bad("a slot is not a number"))?);
                    }
                }
                Some("nodes") => {
                    for node in v.into_array().ok_or_else(|| bad("nodes is not an array"))? {
                        let attrs = node.into_pairs().ok_or_else(|| bad("a node is not a map"))?;
                        if let Some(addr) = master_of(&attrs, tls, queried)? {
                            master = Some(addr);
                        }
                    }
                }
                _ => {}
            }
        }
        // A shard with no slots (a node not yet given any) serves nothing.
        if slots.is_empty() {
            continue;
        }
        let master = master.ok_or_else(|| bad("a shard with slots has no master"))?;
        if slots.len() % 2 != 0 {
            return Err(bad("a slot range is missing its end"));
        }
        for pair in slots.chunks(2) {
            let (start, end) = (slot(pair[0])?, slot(pair[1])?);
            if start > end {
                return Err(bad("a slot range runs backwards"));
            }
            ranges.push(SlotRange {
                start,
                end,
                master: master.clone(),
            });
        }
    }
    Ok(ranges)
}

/// The address of a node's attributes if it is a master, `None` if a replica.
fn master_of(attrs: &[(Value, Value)], tls: bool, queried: &NodeAddr) -> Result<Option<NodeAddr>, RedisError> {
    let get = |name: &str| attrs.iter().find(|(k, _)| k.as_str() == Some(name)).map(|(_, v)| v);
    if get("role").and_then(Value::as_str) != Some("master") {
        return Ok(None);
    }
    let host = [get("endpoint"), get("ip"), get("hostname")]
        .into_iter()
        .flatten()
        .find_map(named_host)
        .unwrap_or_else(|| queried.host.clone());
    let port = if tls { get("tls-port").and_then(Value::as_int) } else { None }
        .or_else(|| get("port").and_then(Value::as_int))
        .ok_or_else(|| bad("a master has no port"))?;
    Ok(Some(NodeAddr {
        host,
        port: u16::try_from(port).map_err(|_| bad("a port is out of range"))?,
    }))
}

fn slot(n: i64) -> Result<u16, RedisError> {
    match u16::try_from(n) {
        Ok(s) if (s as usize) < crate::keys::SLOTS => Ok(s),
        _ => Err(bad("a slot is out of range")),
    }
}

/// Read a `CLUSTER SLOTS` reply: ranges, each with its master first and then
/// its replicas, as `[host, port, id, ...]`.
pub(crate) fn parse_slots(reply: Value, queried: &NodeAddr) -> Result<Vec<SlotRange>, RedisError> {
    let entries = reply.into_array().ok_or_else(|| bad("CLUSTER SLOTS is not an array"))?;
    let mut ranges = Vec::new();
    for entry in entries {
        let items = entry.into_array().ok_or_else(|| bad("a slot range is not an array"))?;
        let [start, end, master, ..] = &items[..] else {
            return Err(bad("a slot range is too short"));
        };
        let node = master.as_array().ok_or_else(|| bad("a master is not an array"))?;
        let [host, port, ..] = node else {
            return Err(bad("a master has no port"));
        };
        let port = port.as_int().and_then(|p| u16::try_from(p).ok()).ok_or_else(|| bad("a port is not valid"))?;
        let (start, end) = (
            slot(start.as_int().ok_or_else(|| bad("a slot is not a number"))?)?,
            slot(end.as_int().ok_or_else(|| bad("a slot is not a number"))?)?,
        );
        ranges.push(SlotRange {
            start,
            end,
            master: NodeAddr {
                host: named_host(host).unwrap_or_else(|| queried.host.clone()),
                port,
            },
        });
    }
    Ok(ranges)
}

/// The slot and node a `MOVED` or `ASK` error's text names: `3999 127.0.0.1:6381`.
pub(crate) fn parse_redirect(message: &str) -> Option<(u16, NodeAddr)> {
    let mut parts = message.split_whitespace();
    let slot: u16 = parts.next()?.parse().ok()?;
    if slot as usize >= crate::keys::SLOTS {
        return None;
    }
    let target = parts.next()?;
    let (host, port) = target.rsplit_once(':')?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    Some((
        slot,
        NodeAddr {
            host: host.to_string(),
            port: port.parse().ok()?,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hopf_core::Bytes;

    fn s(x: &str) -> Value {
        Value::Bulk(Bytes::copy_from_slice(x.as_bytes()))
    }

    fn queried() -> NodeAddr {
        NodeAddr {
            host: "asked.example".into(),
            port: 7000,
        }
    }

    /// One node as `CLUSTER SHARDS` describes it, as a RESP3 map.
    fn node(role: &str, ip: &str, endpoint: &str, port: i64, tls_port: Option<i64>) -> Value {
        let mut pairs = vec![
            (s("id"), s("deadbeef")),
            (s("port"), Value::Int(port)),
            (s("ip"), s(ip)),
            (s("endpoint"), s(endpoint)),
            (s("role"), s(role)),
            (s("replication-offset"), Value::Int(14)),
            (s("health"), s("online")),
        ];
        if let Some(t) = tls_port {
            pairs.push((s("tls-port"), Value::Int(t)));
        }
        Value::Map(pairs)
    }

    fn shard(slots: &[i64], nodes: Vec<Value>) -> Value {
        Value::Map(vec![
            (s("slots"), Value::Array(slots.iter().map(|n| Value::Int(*n)).collect())),
            (s("nodes"), Value::Array(nodes)),
        ])
    }

    /// The same shard as RESP2 sends it: maps are flat arrays.
    fn flatten(v: Value) -> Value {
        match v {
            Value::Map(pairs) => Value::Array(pairs.into_iter().flat_map(|(k, v)| [flatten(k), flatten(v)]).collect()),
            Value::Array(items) => Value::Array(items.into_iter().map(flatten).collect()),
            other => other,
        }
    }

    fn two_shards() -> Value {
        Value::Array(vec![
            shard(
                &[0, 5460, 9000, 9100],
                vec![node("replica", "10.0.0.2", "10.0.0.2", 7001, None), node("master", "10.0.0.1", "10.0.0.1", 7000, None)],
            ),
            shard(&[5461, 8999], vec![node("master", "10.0.0.3", "node3.example", 7002, None)]),
        ])
    }

    #[test]
    fn shards_are_read_as_ranges_with_their_master_in_resp3_and_resp2() {
        let want = vec![
            SlotRange {
                start: 0,
                end: 5460,
                master: NodeAddr {
                    host: "10.0.0.1".into(),
                    port: 7000,
                },
            },
            SlotRange {
                start: 9000,
                end: 9100,
                master: NodeAddr {
                    host: "10.0.0.1".into(),
                    port: 7000,
                },
            },
            SlotRange {
                start: 5461,
                end: 8999,
                master: NodeAddr {
                    host: "node3.example".into(),
                    port: 7002,
                },
            },
        ];
        assert_eq!(parse_shards(two_shards(), false, &queried()).unwrap(), want);
        assert_eq!(parse_shards(flatten(two_shards()), false, &queried()).unwrap(), want, "RESP2's flat arrays");
    }

    #[test]
    fn the_tls_port_is_used_over_tls_and_only_then() {
        let reply = || Value::Array(vec![shard(&[0, 16383], vec![node("master", "10.0.0.1", "10.0.0.1", 7000, Some(7443))])]);
        assert_eq!(parse_shards(reply(), true, &queried()).unwrap()[0].master.port, 7443);
        assert_eq!(parse_shards(reply(), false, &queried()).unwrap()[0].master.port, 7000);
        // With TLS wanted but no TLS port, the plain one.
        let plain = Value::Array(vec![shard(&[0, 16383], vec![node("master", "10.0.0.1", "10.0.0.1", 7000, None)])]);
        assert_eq!(parse_shards(plain, true, &queried()).unwrap()[0].master.port, 7000);
    }

    #[test]
    fn a_node_that_does_not_name_itself_is_reached_where_it_was_asked() {
        for empty in ["", "?"] {
            let reply = Value::Array(vec![shard(&[0, 1], vec![node("master", empty, empty, 7005, None)])]);
            assert_eq!(parse_shards(reply, false, &queried()).unwrap()[0].master.host, "asked.example");
        }
    }

    #[test]
    fn a_shard_with_no_slots_is_skipped_and_one_with_slots_but_no_master_is_an_error() {
        let empty = Value::Array(vec![shard(&[], vec![node("master", "a", "a", 1, None)])]);
        assert!(parse_shards(empty, false, &queried()).unwrap().is_empty());
        let headless = Value::Array(vec![shard(&[0, 10], vec![node("replica", "a", "a", 1, None)])]);
        assert!(parse_shards(headless, false, &queried()).is_err());
        for odd in [shard(&[0], vec![node("master", "a", "a", 1, None)]), shard(&[10, 5], vec![node("master", "a", "a", 1, None)])] {
            assert!(parse_shards(Value::Array(vec![odd]), false, &queried()).is_err());
        }
        assert!(parse_shards(Value::Array(vec![shard(&[0, 16384], vec![node("master", "a", "a", 1, None)])]), false, &queried()).is_err());
        assert!(parse_shards(Value::Int(1), false, &queried()).is_err());
    }

    #[test]
    fn cluster_slots_is_read_too_and_an_empty_host_means_the_node_asked() {
        let reply = Value::Array(vec![
            Value::Array(vec![
                Value::Int(0),
                Value::Int(5460),
                Value::Array(vec![s("10.0.0.1"), Value::Int(7000), s("id1"), Value::Array(vec![])]),
                Value::Array(vec![s("10.0.0.2"), Value::Int(7001), s("id2"), Value::Array(vec![])]),
            ]),
            Value::Array(vec![
                Value::Int(5461),
                Value::Int(16383),
                Value::Array(vec![s(""), Value::Int(7002), s("id3")]),
            ]),
        ]);
        let got = parse_slots(reply, &queried()).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].master, NodeAddr { host: "10.0.0.1".into(), port: 7000 });
        assert_eq!((got[0].start, got[0].end), (0, 5460));
        assert_eq!(got[1].master, NodeAddr { host: "asked.example".into(), port: 7002 });
        assert!(parse_slots(Value::Array(vec![Value::Array(vec![Value::Int(0)])]), &queried()).is_err());
    }

    #[test]
    fn moved_and_ask_name_a_slot_and_a_node() {
        let (slot, node) = parse_redirect("3999 127.0.0.1:6381").unwrap();
        assert_eq!(slot, 3999);
        assert_eq!(node, NodeAddr { host: "127.0.0.1".into(), port: 6381 });
        let (_, node) = parse_redirect("12 [::1]:7000").unwrap();
        assert_eq!(node.host, "::1");
        assert_eq!(node.to_string(), "[::1]:7000");
        assert_eq!(parse_redirect("5 host.example:7").unwrap().1.to_string(), "host.example:7");
        for bad in ["", "x host:1", "5", "5 hostnoport", "5 host:x", "99999 h:1"] {
            assert!(parse_redirect(bad).is_none(), "{bad}");
        }
    }
}
