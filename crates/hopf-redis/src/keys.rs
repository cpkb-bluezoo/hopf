// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Which cluster slot a key lives in, and which words of a command are keys.

/// Slots in a cluster.
pub const SLOTS: usize = 16384;

/// CRC-16/XMODEM (polynomial 0x1021, initial value 0), the checksum Redis
/// Cluster hashes keys with.
const fn crc16_table() -> [u16; 256] {
    let mut table = [0u16; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = (i as u16) << 8;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 0x8000 != 0 { (crc << 1) ^ 0x1021 } else { crc << 1 };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

static CRC16: [u16; 256] = crc16_table();

/// CRC-16/XMODEM of `data`.
pub fn crc16(data: &[u8]) -> u16 {
    let mut crc = 0u16;
    for &b in data {
        crc = (crc << 8) ^ CRC16[((crc >> 8) as u8 ^ b) as usize];
    }
    crc
}

/// The slot `key` hashes to. If the key holds `{tag}` with something between
/// the first `{` and the first `}` after it, only the tag is hashed, so related
/// keys can be made to share a slot: `{user1000}.following` and
/// `{user1000}.followers` do.
pub fn key_slot(key: &[u8]) -> u16 {
    let hashed = match key.iter().position(|&b| b == b'{') {
        Some(open) => match key[open + 1..].iter().position(|&b| b == b'}') {
            Some(len) if len > 0 => &key[open + 1..open + 1 + len],
            _ => key,
        },
        None => key,
    };
    crc16(hashed) & (SLOTS as u16 - 1)
}

/// Where the keys are in a command's words, by command name (upper case). A
/// command not listed has its key, if it has one, as its first argument, which
/// is right for the great majority of commands.
enum Layout {
    /// No key: any node will do.
    None,
    /// Every argument after the name.
    AllArgs,
    /// Every argument but the last (`BLPOP`, `BRPOP`: the last is a timeout).
    AllButLast,
    /// Alternate arguments, starting with the first (`MSET`).
    EveryOther,
    /// The first two arguments (`RENAME`, `SMOVE`, `LMOVE`, ...).
    FirstTwo,
    /// `numkeys` at this word, then that many keys (`EVAL`, `FCALL`).
    NumKeysAt(usize),
    /// A destination, then `numkeys`, then that many keys (`ZUNIONSTORE`).
    DestNumKeys,
    /// `numkeys` at word 1, then that many keys, then options (`LMPOP`, `ZUNION`).
    NumKeysFirst,
    /// An operation, a destination, then keys (`BITOP`).
    Bitop,
    /// `XREAD` and `XREADGROUP`: the keys after `STREAMS`.
    Streams,
    /// The key is the second argument (`OBJECT ENCODING key`, `XINFO STREAM key`).
    SecondArg,
    /// Only for what the second argument says: `SCRIPT`, `CLIENT` and so on
    /// are keyless; `MEMORY USAGE key` has a key.
    MemoryUsage,
}

fn layout(name: &str) -> Option<Layout> {
    Some(match name {
        // Keyless: they act on a node, or on the whole cluster.
        "PING" | "ECHO" | "INFO" | "TIME" | "DBSIZE" | "FLUSHALL" | "FLUSHDB" | "KEYS" | "SCAN" | "RANDOMKEY"
        | "SCRIPT" | "CLIENT" | "CONFIG" | "CLUSTER" | "COMMAND" | "AUTH" | "HELLO" | "SELECT" | "QUIT" | "LASTSAVE"
        | "SAVE" | "BGSAVE" | "ROLE" | "WAIT" | "WAITAOF" | "PUBLISH" | "PUBSUB" | "FUNCTION" | "ACL" | "SLOWLOG"
        | "LATENCY" | "READONLY" | "READWRITE" | "ASKING" | "RESET" | "DEBUG" | "MONITOR" | "SHUTDOWN" | "REPLICAOF"
        | "SLAVEOF" | "FAILOVER" | "MULTI" | "EXEC" | "DISCARD" | "UNWATCH" => Layout::None,
        "DEL" | "EXISTS" | "UNLINK" | "MGET" | "WATCH" | "TOUCH" | "SINTER" | "SUNION" | "SDIFF" | "SINTERSTORE"
        | "SUNIONSTORE" | "SDIFFSTORE" | "PFMERGE" | "PFCOUNT" => Layout::AllArgs,
        "BLPOP" | "BRPOP" | "BZPOPMIN" | "BZPOPMAX" => Layout::AllButLast,
        "MSET" | "MSETNX" => Layout::EveryOther,
        "RENAME" | "RENAMENX" | "SMOVE" | "LMOVE" | "BLMOVE" | "RPOPLPUSH" | "BRPOPLPUSH" | "COPY" => Layout::FirstTwo,
        "EVAL" | "EVALSHA" | "EVAL_RO" | "EVALSHA_RO" | "FCALL" | "FCALL_RO" | "BLMPOP" | "BZMPOP" => Layout::NumKeysAt(2),
        "ZUNIONSTORE" | "ZINTERSTORE" | "ZDIFFSTORE" => Layout::DestNumKeys,
        "ZUNION" | "ZINTER" | "ZDIFF" | "SINTERCARD" | "ZINTERCARD" | "LMPOP" | "ZMPOP" => Layout::NumKeysFirst,
        "BITOP" => Layout::Bitop,
        "XREAD" | "XREADGROUP" => Layout::Streams,
        "OBJECT" | "XINFO" | "XGROUP" => Layout::SecondArg,
        "MEMORY" => Layout::MemoryUsage,
        _ => return None,
    })
}

/// The indexes into `words` (the command name first) of the command's keys.
///
/// This is a table of the commands applications use, not the server's own
/// knowledge of every command, and a command it does not list is taken to have
/// one key, its first argument. For anything else, name the key yourself with
/// [`RedisCluster::command_for_key`](crate::RedisCluster::command_for_key).
pub fn key_indexes(words: &[Vec<u8>]) -> Vec<usize> {
    let Some(name) = words.first() else {
        return Vec::new();
    };
    let name = String::from_utf8_lossy(name).to_ascii_uppercase();
    let n = words.len();
    let number = |i: usize| -> Option<usize> {
        words.get(i).and_then(|w| std::str::from_utf8(w).ok()).and_then(|s| s.parse().ok())
    };
    match layout(&name) {
        None => {
            // Not in the table: the first argument, if there is one.
            if n > 1 {
                vec![1]
            } else {
                Vec::new()
            }
        }
        Some(Layout::None) => Vec::new(),
        Some(Layout::AllArgs) => (1..n).collect(),
        Some(Layout::AllButLast) => (1..n.saturating_sub(1)).collect(),
        Some(Layout::EveryOther) => (1..n).step_by(2).collect(),
        Some(Layout::FirstTwo) => (1..n.min(3)).collect(),
        Some(Layout::NumKeysAt(at)) => match number(at) {
            Some(k) => (at + 1..(at + 1 + k).min(n)).collect(),
            None => Vec::new(),
        },
        Some(Layout::DestNumKeys) => match number(2) {
            Some(k) => std::iter::once(1).chain(3..(3 + k).min(n)).collect(),
            None => Vec::new(),
        },
        Some(Layout::NumKeysFirst) => match number(1) {
            Some(k) => (2..(2 + k).min(n)).collect(),
            None => Vec::new(),
        },
        Some(Layout::Bitop) => (2..n).collect(),
        Some(Layout::Streams) => {
            let Some(pos) = words.iter().position(|w| w.eq_ignore_ascii_case(b"STREAMS")) else {
                return Vec::new();
            };
            let rest = n - (pos + 1);
            (pos + 1..pos + 1 + rest / 2).collect()
        }
        Some(Layout::SecondArg) => {
            if n > 2 {
                vec![2]
            } else {
                Vec::new()
            }
        }
        Some(Layout::MemoryUsage) => {
            if n > 2 && words[1].eq_ignore_ascii_case(b"USAGE") {
                vec![2]
            } else {
                Vec::new()
            }
        }
    }
}

/// Why a command cannot be routed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrossSlot;

/// The one slot a command's keys share: `None` for a command with no keys,
/// [`CrossSlot`] if they are in different slots.
pub fn command_slot(words: &[Vec<u8>]) -> Result<Option<u16>, CrossSlot> {
    let mut slot = None;
    for i in key_indexes(words) {
        let s = key_slot(&words[i]);
        match slot {
            None => slot = Some(s),
            Some(prev) if prev == s => {}
            Some(_) => return Err(CrossSlot),
        }
    }
    Ok(slot)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(s: &str) -> Vec<Vec<u8>> {
        s.split_whitespace().map(|w| w.as_bytes().to_vec()).collect()
    }

    #[test]
    fn crc16_matches_the_published_check_value() {
        // The standard check string for CRC-16/XMODEM.
        assert_eq!(crc16(b"123456789"), 0x31C3);
        assert_eq!(crc16(b""), 0);
    }

    #[test]
    fn keys_hash_to_the_slots_a_cluster_gives_them() {
        // From the Redis Cluster specification and `CLUSTER KEYSLOT`.
        assert_eq!(key_slot(b"foo"), 12182);
        assert_eq!(key_slot(b"bar"), 5061);
        assert_eq!(key_slot(b"hello"), 866);
        assert_eq!(key_slot(b"somekey"), 11058);
        assert_eq!(key_slot(b""), 0);
    }

    #[test]
    fn a_hash_tag_decides_the_slot() {
        assert_eq!(key_slot(b"{user1000}.following"), key_slot(b"{user1000}.followers"));
        assert_eq!(key_slot(b"{user1000}.following"), key_slot(b"user1000"));
        assert_eq!(key_slot(b"a{b}c{d}"), key_slot(b"b"), "the first tag only");
        // An empty tag is no tag: the whole key is hashed.
        assert_eq!(key_slot(b"foo{}bar"), crc16(b"foo{}bar") & 16383);
        // An unclosed tag is no tag.
        assert_eq!(key_slot(b"foo{bar"), crc16(b"foo{bar") & 16383);
        // Only the first `{` counts, even if it closes on nothing.
        assert_eq!(key_slot(b"{}{x}"), crc16(b"{}{x}") & 16383);
    }

    #[test]
    fn a_single_key_command_has_its_first_argument_as_the_key() {
        assert_eq!(key_indexes(&words("GET k")), vec![1]);
        assert_eq!(key_indexes(&words("set k v EX 10")), vec![1]);
        assert_eq!(key_indexes(&words("HSET h f v")), vec![1]);
        assert_eq!(key_indexes(&words("SPUBLISH shard msg")), vec![1], "a shard channel hashes like a key");
        assert!(key_indexes(&words("PING")).is_empty());
        assert!(key_indexes(&words("GET")).is_empty());
    }

    #[test]
    fn keyless_commands_have_no_keys() {
        for c in ["PING", "INFO server", "CLIENT LIST", "SCRIPT LOAD x", "CLUSTER SHARDS", "PUBLISH ch msg", "FLUSHALL"] {
            assert!(key_indexes(&words(c)).is_empty(), "{c}");
        }
    }

    #[test]
    fn multi_key_commands_name_all_their_keys() {
        assert_eq!(key_indexes(&words("DEL a b c")), vec![1, 2, 3]);
        assert_eq!(key_indexes(&words("MGET a b")), vec![1, 2]);
        assert_eq!(key_indexes(&words("MSET a 1 b 2")), vec![1, 3]);
        assert_eq!(key_indexes(&words("RENAME a b")), vec![1, 2]);
        assert_eq!(key_indexes(&words("SINTERSTORE dst a b")), vec![1, 2, 3]);
        assert_eq!(key_indexes(&words("BLPOP a b 0")), vec![1, 2], "not the timeout");
        assert_eq!(key_indexes(&words("BITOP AND dst a b")), vec![2, 3, 4], "not the operation");
    }

    #[test]
    fn scripts_and_counted_key_lists_are_read_by_their_numkeys() {
        assert_eq!(key_indexes(&words("EVAL script 2 k1 k2 arg1")), vec![3, 4]);
        assert_eq!(key_indexes(&words("EVALSHA sha 1 k a b")), vec![3]);
        assert!(key_indexes(&words("EVAL script 0 a")).is_empty());
        assert_eq!(key_indexes(&words("ZUNIONSTORE dst 2 a b WEIGHTS 1 2")), vec![1, 3, 4]);
        assert_eq!(key_indexes(&words("LMPOP 2 a b LEFT")), vec![2, 3]);
        assert_eq!(key_indexes(&words("FCALL f 1 k")), vec![3]);
        // A numkeys that runs past the end is cut to what is there.
        assert_eq!(key_indexes(&words("EVAL s 5 a b")), vec![3, 4]);
        assert!(key_indexes(&words("EVAL s notanumber a")).is_empty());
    }

    #[test]
    fn stream_reads_take_the_keys_before_the_ids() {
        assert_eq!(key_indexes(&words("XREAD COUNT 2 STREAMS s1 s2 0 0")), vec![4, 5]);
        assert_eq!(key_indexes(&words("XREADGROUP GROUP g c STREAMS s1 >")), vec![5]);
    }

    #[test]
    fn subcommand_commands_find_their_key_after_the_subcommand() {
        assert_eq!(key_indexes(&words("OBJECT ENCODING k")), vec![2]);
        assert_eq!(key_indexes(&words("XINFO STREAM s")), vec![2]);
        assert_eq!(key_indexes(&words("MEMORY USAGE k")), vec![2]);
        assert!(key_indexes(&words("MEMORY STATS")).is_empty());
    }

    #[test]
    fn keys_in_one_slot_route_and_keys_in_two_do_not() {
        assert_eq!(command_slot(&words("GET foo")), Ok(Some(12182)));
        assert_eq!(command_slot(&words("PING")), Ok(None));
        assert_eq!(command_slot(&words("MGET {t}a {t}b")), Ok(Some(key_slot(b"t"))));
        assert_eq!(command_slot(&words("MGET foo bar")), Err(CrossSlot));
        assert_eq!(command_slot(&words("EVAL s 2 {t}a {t}b")), Ok(Some(key_slot(b"t"))));
        assert_eq!(command_slot(&words("EVAL s 2 foo bar")), Err(CrossSlot));
        // Arguments that are not keys do not count.
        assert_eq!(command_slot(&words("EVAL s 1 foo bar baz")), Ok(Some(12182)));
    }
}
