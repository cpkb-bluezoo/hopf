// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Typed helpers for the commonly used commands.
//!
//! A helper that hands the caller a value exists only where the reply cannot
//! be larger than a line: a count, a flag, `OK`. Each is a command with the
//! arguments laid out and the reply read as the type the command returns, under
//! a cap that refuses anything bigger (see [`ScalarValue`](crate::ScalarValue)).
//! A command whose reply is a string or a collection, whose size is the
//! application's data (`GET`, `LRANGE`, `EVAL`), is sent with a sink instead
//! (`get`, `lrange`, `eval`, `send_streaming`), so that nothing holds it whole.
//! All of them return at once and call back on the client's reactor.

use crate::client::{Command, Deadline, RedisClient, StreamHandle, ValueReply};
use crate::collect::Cap;
use crate::error::RedisError;
use crate::resp::{ReplySink, Value};

/// Options for [`RedisClient::set_with`] (`SET`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SetOptions {
    /// Only set the key if it does not exist (`NX`).
    pub nx: bool,
    /// Only set the key if it exists (`XX`).
    pub xx: bool,
    /// Expire after this many seconds (`EX`).
    pub ex: Option<u64>,
    /// Expire after this many milliseconds (`PX`).
    pub px: Option<u64>,
    /// Expire at this Unix time in seconds (`EXAT`).
    pub exat: Option<u64>,
    /// Expire at this Unix time in milliseconds (`PXAT`).
    pub pxat: Option<u64>,
    /// Keep the key's existing expiry (`KEEPTTL`).
    pub keepttl: bool,
}

impl SetOptions {
    fn append(&self, cmd: Command) -> Command {
        let mut cmd = cmd;
        if self.nx {
            cmd = cmd.arg("NX");
        }
        if self.xx {
            cmd = cmd.arg("XX");
        }
        for (flag, v) in [("EX", self.ex), ("PX", self.px), ("EXAT", self.exat), ("PXAT", self.pxat)] {
            if let Some(n) = v {
                cmd = cmd.arg(flag).arg(n.to_string());
            }
        }
        if self.keepttl {
            cmd = cmd.arg("KEEPTTL");
        }
        cmd
    }
}

fn unexpected<T>(what: &str, got: &Value) -> Result<T, RedisError> {
    Err(RedisError::Unexpected(format!("expected {what}, got {got:?}")))
}

fn ok(v: Value) -> Result<(), RedisError> {
    match &v {
        Value::Simple(s) if s == "OK" => Ok(()),
        other => unexpected("OK", other),
    }
}

fn int(v: Value) -> Result<i64, RedisError> {
    match v.as_int() {
        Some(n) => Ok(n),
        None => unexpected("an integer", &v),
    }
}

fn boolean(v: Value) -> Result<bool, RedisError> {
    match v {
        Value::Bool(b) => Ok(b),
        other => match other.as_int() {
            Some(n) => Ok(n != 0),
            None => unexpected("0 or 1", &other),
        },
    }
}

fn text(v: Value) -> Result<String, RedisError> {
    match v {
        Value::Bulk(b) => String::from_utf8(b.to_vec()).map_err(|_| RedisError::Unexpected("the reply is not UTF-8".into())),
        Value::Simple(s) => Ok(s),
        other => unexpected("a string", &other),
    }
}

fn array(v: Value) -> Result<Vec<Value>, RedisError> {
    match v.into_array() {
        Some(items) => Ok(items),
        None => Err(RedisError::Unexpected("expected an array".into())),
    }
}

fn opt_f64(v: Value) -> Result<Option<f64>, RedisError> {
    match v {
        Value::Null => Ok(None),
        other => match other.as_f64() {
            Some(d) => Ok(Some(d)),
            None => unexpected("a number or nil", &other),
        },
    }
}

fn float(v: Value) -> Result<f64, RedisError> {
    match v.as_f64() {
        Some(d) => Ok(d),
        None => unexpected("a number", &v),
    }
}

fn keyed(name: &str, keys: &[impl AsRef<[u8]>]) -> Command {
    Command::new(name).args(keys)
}

/// The typed helpers, written once and expanded in both [`RedisClient`] and
/// [`RedisCluster`](crate::RedisCluster): each is [`send`](RedisClient::send)
/// of the command with the reply read as the type it returns.
macro_rules! typed_commands {
    () => {
        // ---- connection ----

        /// `PING`.
        pub fn ping(&self, callback: impl FnOnce(Result<(), RedisError>) + Send + 'static) {
            self.typed(Command::new("PING"), |v| match &v {
                Value::Simple(s) if s == "PONG" => Ok(()),
                other => unexpected("PONG", other),
            }, callback);
        }




        // ---- strings ----

        /// `SET key value`.
        pub fn set(&self, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>, callback: impl FnOnce(Result<(), RedisError>) + Send + 'static) {
            self.typed(Command::new("SET").arg(key).arg(value), ok, callback);
        }

        /// `SET` with options: whether it took effect (`false` when an `NX` or
        /// `XX` condition was not met).
        pub fn set_with(
            &self,
            key: impl AsRef<[u8]>,
            value: impl AsRef<[u8]>,
            options: &SetOptions,
            callback: impl FnOnce(Result<bool, RedisError>) + Send + 'static,
        ) {
            let cmd = options.append(Command::new("SET").arg(key).arg(value));
            self.typed(
                cmd,
                |v| match v {
                    Value::Null => Ok(false),
                    other => ok(other).map(|()| true),
                },
                callback,
            );
        }

        /// `SETNX`: whether the key was set.
        pub fn setnx(&self, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>, callback: impl FnOnce(Result<bool, RedisError>) + Send + 'static) {
            self.typed(Command::new("SETNX").arg(key).arg(value), boolean, callback);
        }

        /// `MSET`.
        pub fn mset<K: AsRef<[u8]>, V: AsRef<[u8]>>(&self, pairs: &[(K, V)], callback: impl FnOnce(Result<(), RedisError>) + Send + 'static) {
            let mut cmd = Command::new("MSET");
            for (k, v) in pairs {
                cmd = cmd.arg(k).arg(v);
            }
            self.typed(cmd, ok, callback);
        }

        /// `INCR`: the new value.
        pub fn incr(&self, key: impl AsRef<[u8]>, callback: impl FnOnce(Result<i64, RedisError>) + Send + 'static) {
            self.typed(Command::new("INCR").arg(key), int, callback);
        }

        /// `INCRBY`.
        pub fn incrby(&self, key: impl AsRef<[u8]>, by: i64, callback: impl FnOnce(Result<i64, RedisError>) + Send + 'static) {
            self.typed(Command::new("INCRBY").arg(key).arg(by.to_string()), int, callback);
        }

        /// `DECR`.
        pub fn decr(&self, key: impl AsRef<[u8]>, callback: impl FnOnce(Result<i64, RedisError>) + Send + 'static) {
            self.typed(Command::new("DECR").arg(key), int, callback);
        }

        /// `DECRBY`.
        pub fn decrby(&self, key: impl AsRef<[u8]>, by: i64, callback: impl FnOnce(Result<i64, RedisError>) + Send + 'static) {
            self.typed(Command::new("DECRBY").arg(key).arg(by.to_string()), int, callback);
        }

        /// `APPEND`: the new length.
        pub fn append(&self, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>, callback: impl FnOnce(Result<i64, RedisError>) + Send + 'static) {
            self.typed(Command::new("APPEND").arg(key).arg(value), int, callback);
        }

        /// `STRLEN`.
        pub fn strlen(&self, key: impl AsRef<[u8]>, callback: impl FnOnce(Result<i64, RedisError>) + Send + 'static) {
            self.typed(Command::new("STRLEN").arg(key), int, callback);
        }

        // ---- keys ----

        /// `DEL`: how many keys were removed.
        pub fn del(&self, keys: &[impl AsRef<[u8]>], callback: impl FnOnce(Result<i64, RedisError>) + Send + 'static) {
            self.typed(keyed("DEL", keys), int, callback);
        }

        /// `EXISTS`: how many of the keys exist.
        pub fn exists(&self, keys: &[impl AsRef<[u8]>], callback: impl FnOnce(Result<i64, RedisError>) + Send + 'static) {
            self.typed(keyed("EXISTS", keys), int, callback);
        }

        /// `EXPIRE`: whether the key exists and got a timeout.
        pub fn expire(&self, key: impl AsRef<[u8]>, seconds: u64, callback: impl FnOnce(Result<bool, RedisError>) + Send + 'static) {
            self.typed(Command::new("EXPIRE").arg(key).arg(seconds.to_string()), boolean, callback);
        }

        /// `PEXPIRE`.
        pub fn pexpire(&self, key: impl AsRef<[u8]>, millis: u64, callback: impl FnOnce(Result<bool, RedisError>) + Send + 'static) {
            self.typed(Command::new("PEXPIRE").arg(key).arg(millis.to_string()), boolean, callback);
        }

        /// `TTL`: seconds left, `-1` for no timeout, `-2` for a missing key.
        pub fn ttl(&self, key: impl AsRef<[u8]>, callback: impl FnOnce(Result<i64, RedisError>) + Send + 'static) {
            self.typed(Command::new("TTL").arg(key), int, callback);
        }

        /// `PTTL`.
        pub fn pttl(&self, key: impl AsRef<[u8]>, callback: impl FnOnce(Result<i64, RedisError>) + Send + 'static) {
            self.typed(Command::new("PTTL").arg(key), int, callback);
        }

        /// `PERSIST`: whether a timeout was removed.
        pub fn persist(&self, key: impl AsRef<[u8]>, callback: impl FnOnce(Result<bool, RedisError>) + Send + 'static) {
            self.typed(Command::new("PERSIST").arg(key), boolean, callback);
        }

        // ---- hashes ----

        /// `HSET`: how many fields were added.
        pub fn hset<F: AsRef<[u8]>, V: AsRef<[u8]>>(
            &self,
            key: impl AsRef<[u8]>,
            fields: &[(F, V)],
            callback: impl FnOnce(Result<i64, RedisError>) + Send + 'static,
        ) {
            let mut cmd = Command::new("HSET").arg(key);
            for (f, v) in fields {
                cmd = cmd.arg(f).arg(v);
            }
            self.typed(cmd, int, callback);
        }

        /// `HDEL`: how many fields were removed.
        pub fn hdel(&self, key: impl AsRef<[u8]>, fields: &[impl AsRef<[u8]>], callback: impl FnOnce(Result<i64, RedisError>) + Send + 'static) {
            self.typed(Command::new("HDEL").arg(key).args(fields), int, callback);
        }

        /// `HEXISTS`.
        pub fn hexists(&self, key: impl AsRef<[u8]>, field: impl AsRef<[u8]>, callback: impl FnOnce(Result<bool, RedisError>) + Send + 'static) {
            self.typed(Command::new("HEXISTS").arg(key).arg(field), boolean, callback);
        }

        /// `HINCRBY`.
        pub fn hincrby(&self, key: impl AsRef<[u8]>, field: impl AsRef<[u8]>, by: i64, callback: impl FnOnce(Result<i64, RedisError>) + Send + 'static) {
            self.typed(Command::new("HINCRBY").arg(key).arg(field).arg(by.to_string()), int, callback);
        }

        /// `HLEN`.
        pub fn hlen(&self, key: impl AsRef<[u8]>, callback: impl FnOnce(Result<i64, RedisError>) + Send + 'static) {
            self.typed(Command::new("HLEN").arg(key), int, callback);
        }

        // ---- lists ----

        /// `LPUSH`: the list's new length.
        pub fn lpush(&self, key: impl AsRef<[u8]>, values: &[impl AsRef<[u8]>], callback: impl FnOnce(Result<i64, RedisError>) + Send + 'static) {
            self.typed(Command::new("LPUSH").arg(key).args(values), int, callback);
        }

        /// `RPUSH`.
        pub fn rpush(&self, key: impl AsRef<[u8]>, values: &[impl AsRef<[u8]>], callback: impl FnOnce(Result<i64, RedisError>) + Send + 'static) {
            self.typed(Command::new("RPUSH").arg(key).args(values), int, callback);
        }

        /// `LLEN`.
        pub fn llen(&self, key: impl AsRef<[u8]>, callback: impl FnOnce(Result<i64, RedisError>) + Send + 'static) {
            self.typed(Command::new("LLEN").arg(key), int, callback);
        }

        // ---- sets ----

        /// `SADD`: how many members were added.
        pub fn sadd(&self, key: impl AsRef<[u8]>, members: &[impl AsRef<[u8]>], callback: impl FnOnce(Result<i64, RedisError>) + Send + 'static) {
            self.typed(Command::new("SADD").arg(key).args(members), int, callback);
        }

        /// `SREM`.
        pub fn srem(&self, key: impl AsRef<[u8]>, members: &[impl AsRef<[u8]>], callback: impl FnOnce(Result<i64, RedisError>) + Send + 'static) {
            self.typed(Command::new("SREM").arg(key).args(members), int, callback);
        }

        /// `SISMEMBER`.
        pub fn sismember(&self, key: impl AsRef<[u8]>, member: impl AsRef<[u8]>, callback: impl FnOnce(Result<bool, RedisError>) + Send + 'static) {
            self.typed(Command::new("SISMEMBER").arg(key).arg(member), boolean, callback);
        }

        /// `SCARD`.
        pub fn scard(&self, key: impl AsRef<[u8]>, callback: impl FnOnce(Result<i64, RedisError>) + Send + 'static) {
            self.typed(Command::new("SCARD").arg(key), int, callback);
        }

        // ---- sorted sets ----

        /// `ZADD`: how many members were added.
        pub fn zadd<M: AsRef<[u8]>>(&self, key: impl AsRef<[u8]>, members: &[(f64, M)], callback: impl FnOnce(Result<i64, RedisError>) + Send + 'static) {
            let mut cmd = Command::new("ZADD").arg(key);
            for (score, member) in members {
                cmd = cmd.arg(score.to_string()).arg(member);
            }
            self.typed(cmd, int, callback);
        }

        /// `ZREM`.
        pub fn zrem(&self, key: impl AsRef<[u8]>, members: &[impl AsRef<[u8]>], callback: impl FnOnce(Result<i64, RedisError>) + Send + 'static) {
            self.typed(Command::new("ZREM").arg(key).args(members), int, callback);
        }

        /// `ZSCORE`.
        pub fn zscore(&self, key: impl AsRef<[u8]>, member: impl AsRef<[u8]>, callback: impl FnOnce(Result<Option<f64>, RedisError>) + Send + 'static) {
            self.typed_cap(Command::new("ZSCORE").arg(key).arg(member), Cap::SHORT, opt_f64, callback);
        }

        /// `ZINCRBY`: the member's new score.
        pub fn zincrby(&self, key: impl AsRef<[u8]>, by: f64, member: impl AsRef<[u8]>, callback: impl FnOnce(Result<f64, RedisError>) + Send + 'static) {
            self.typed_cap(Command::new("ZINCRBY").arg(key).arg(by.to_string()).arg(member), Cap::SHORT, float, callback);
        }

        /// `ZCARD`.
        pub fn zcard(&self, key: impl AsRef<[u8]>, callback: impl FnOnce(Result<i64, RedisError>) + Send + 'static) {
            self.typed(Command::new("ZCARD").arg(key), int, callback);
        }

        // ---- publish ----

        /// `PUBLISH`: how many subscribers received the message. Subscribing is
        /// done with a [`RedisSubscriber`](crate::RedisSubscriber).
        pub fn publish(&self, channel: impl AsRef<[u8]>, message: impl AsRef<[u8]>, callback: impl FnOnce(Result<i64, RedisError>) + Send + 'static) {
            self.typed(Command::new("PUBLISH").arg(channel).arg(message), int, callback);
        }

        /// `SPUBLISH` (Redis 7): publish to a shard channel.
        pub fn spublish(&self, channel: impl AsRef<[u8]>, message: impl AsRef<[u8]>, callback: impl FnOnce(Result<i64, RedisError>) + Send + 'static) {
            self.typed(Command::new("SPUBLISH").arg(channel).arg(message), int, callback);
        }

        // ---- scripts ----

        /// `SCRIPT LOAD`: the script's SHA-1, as hex.
        pub fn script_load(&self, script: impl AsRef<[u8]>, callback: impl FnOnce(Result<String, RedisError>) + Send + 'static) {
            self.typed_cap(Command::new("SCRIPT").arg("LOAD").arg(script), Cap::SHORT, text, callback);
        }

    };
}

macro_rules! typed_fn {
    () => {
        /// Send `cmd` and read its reply, which must be a single value, with `read`.
        pub(crate) fn typed<T: Send + 'static>(
            &self,
            cmd: Command,
            read: fn(Value) -> Result<T, RedisError>,
            callback: impl FnOnce(Result<T, RedisError>) + Send + 'static,
        ) {
            self.typed_cap(cmd, Cap::SCALAR, read, callback);
        }
    };
}

impl RedisClient {
    typed_fn!();

    /// Send `cmd` and read its reply, assembled under `cap`, with `read`.
    pub(crate) fn typed_cap<T: Send + 'static>(
        &self,
        cmd: Command,
        cap: Cap,
        read: fn(Value) -> Result<T, RedisError>,
        callback: impl FnOnce(Result<T, RedisError>) + Send + 'static,
    ) {
        self.send_value(&cmd, Deadline::Default, cap, move |reply: ValueReply| callback(reply.and_then(read)));
    }

    typed_commands!();

    /// `AUTH password`, on the current connection. A client configured with a
    /// password authenticates by itself every time it connects.
    pub fn auth(&self, password: impl AsRef<[u8]>, callback: impl FnOnce(Result<(), RedisError>) + Send + 'static) {
        self.typed(Command::new("AUTH").arg(password), ok, callback);
    }

    /// `AUTH username password`, on the current connection.
    pub fn auth_user(
        &self,
        username: impl AsRef<[u8]>,
        password: impl AsRef<[u8]>,
        callback: impl FnOnce(Result<(), RedisError>) + Send + 'static,
    ) {
        self.typed(Command::new("AUTH").arg(username).arg(password), ok, callback);
    }

    /// `SELECT db`, on the current connection (and not remembered over a
    /// reconnect: set [`RedisConfig::database`](crate::RedisConfig::database)
    /// for that).
    pub fn select(&self, db: u32, callback: impl FnOnce(Result<(), RedisError>) + Send + 'static) {
        self.typed(Command::new("SELECT").arg(db.to_string()), ok, callback);
    }

    // ---- transactions ----

    /// Run `commands` as one transaction: `MULTI`, the commands, `EXEC`, written
    /// together so no other command can come between them on this connection.
    /// `sink` is told the reply to `EXEC`, as the events of a reply, as it
    /// arrives: an array with the result of each command in order (a command
    /// that fails when it runs is an error element of it), or nil if `EXEC` was
    /// aborted because a key watched with [`watch`](Self::watch) changed. The
    /// replies to `MULTI` and to the queued commands are read by the client, and
    /// a command refused when queued (a syntax error) is the error `sink` is
    /// told in place of `EXECABORT`. See
    /// [`send_streaming`](RedisClient::send_streaming) for flow control,
    /// cancellation and timeouts.
    pub fn transaction(&self, commands: Vec<Command>, sink: impl ReplySink + Send + 'static) -> StreamHandle {
        self.transaction_streaming(false, commands, Deadline::Default, sink)
    }

    /// `WATCH`: have the next `EXEC` on this connection abort if one of `keys`
    /// changes first. Like [`multi`](Self::multi) and
    /// [`discard`](Self::discard) it acts on the **connection**, and a client's
    /// connection is shared by everything that uses it, so another caller's
    /// commands can run between yours. Use a client of your own for a
    /// watch-and-transact sequence; [`transaction`](Self::transaction) is safe
    /// to share.
    pub fn watch(&self, keys: &[impl AsRef<[u8]>], callback: impl FnOnce(Result<(), RedisError>) + Send + 'static) {
        self.typed(keyed("WATCH", keys), ok, callback);
    }

    /// `UNWATCH`.
    pub fn unwatch(&self, callback: impl FnOnce(Result<(), RedisError>) + Send + 'static) {
        self.typed(Command::new("UNWATCH"), ok, callback);
    }

    /// `MULTI`: start queueing commands on this connection. See
    /// [`watch`](Self::watch) for the warning about sharing.
    pub fn multi(&self, callback: impl FnOnce(Result<(), RedisError>) + Send + 'static) {
        self.typed(Command::new("MULTI"), ok, callback);
    }

    /// `DISCARD`.
    pub fn discard(&self, callback: impl FnOnce(Result<(), RedisError>) + Send + 'static) {
        self.typed(Command::new("DISCARD"), ok, callback);
    }
}

impl crate::cluster::RedisCluster {
    typed_fn!();

    /// Send `cmd` and read its reply, assembled under `cap`, with `read`.
    pub(crate) fn typed_cap<T: Send + 'static>(
        &self,
        cmd: Command,
        cap: Cap,
        read: fn(Value) -> Result<T, RedisError>,
        callback: impl FnOnce(Result<T, RedisError>) + Send + 'static,
    ) {
        self.submit(&cmd, None, Deadline::Default, cap, Box::new(move |reply: ValueReply| callback(reply.and_then(read))));
    }

    typed_commands!();
}

// ---- WAIT and WAITAOF ----

/// `WAIT numreplicas timeout`.
pub(crate) fn wait_command(num_replicas: u32, timeout_ms: u64) -> Command {
    Command::new("WAIT").arg(num_replicas.to_string()).arg(timeout_ms.to_string())
}

/// `WAITAOF numlocal numreplicas timeout`.
pub(crate) fn waitaof_command(num_local: u32, num_replicas: u32, timeout_ms: u64) -> Command {
    Command::new("WAITAOF")
        .arg(num_local.to_string())
        .arg(num_replicas.to_string())
        .arg(timeout_ms.to_string())
}

/// How long the client waits for a `WAIT` the server holds for `timeout_ms`:
/// its own command timeout on top of that, and no limit for a server that is
/// asked to wait for ever.
pub(crate) fn wait_deadline(timeout_ms: u64) -> Deadline {
    if timeout_ms == 0 {
        Deadline::Never
    } else {
        Deadline::Extra(std::time::Duration::from_millis(timeout_ms))
    }
}

/// Whether `name` is a command whose meaning is bound to the connection it runs
/// on.
pub(crate) fn is_connection_scoped(name: &[u8]) -> bool {
    name.eq_ignore_ascii_case(b"WAIT") || name.eq_ignore_ascii_case(b"WAITAOF")
}

/// The server-side timeout of a `WAIT` or `WAITAOF` written out in `words`.
pub(crate) fn server_timeout_ms(words: &[Vec<u8>]) -> u64 {
    let at = if words.first().is_some_and(|w| w.eq_ignore_ascii_case(b"WAITAOF")) { 3 } else { 2 };
    words
        .get(at)
        .and_then(|w| std::str::from_utf8(w).ok())
        .and_then(|w| w.parse().ok())
        .unwrap_or(0)
}

pub(crate) fn wait_count(v: Value) -> Result<u32, RedisError> {
    let n = int(v)?;
    u32::try_from(n).map_err(|_| RedisError::Unexpected(format!("{n} is not a replica count")))
}

pub(crate) fn aof_counts(v: Value) -> Result<(u32, u32), RedisError> {
    let items = array(v)?;
    match items.as_slice() {
        [local, replicas] => Ok((wait_count(local.clone())?, wait_count(replicas.clone())?)),
        _ => Err(RedisError::Unexpected(format!("WAITAOF answered {} elements, not 2", items.len()))),
    }
}

/// The error for `WAIT` run where it cannot mean anything.
pub(crate) fn wait_in_multi() -> RedisError {
    RedisError::Unexpected(
        "WAIT or WAITAOF inside MULTI is queued, not run, so it would confirm nothing: send it after EXEC".into(),
    )
}

impl RedisClient {
    /// `WAIT numreplicas timeout_ms`: block until `num_replicas` replicas have
    /// acknowledged every write made on **this connection**, or `timeout_ms`
    /// passes, and call back with how many did. Fewer than asked for is
    /// `Ok(n)`, not an error. `slot_key` says nothing on a single server and is
    /// ignored: the parameter is there so code can be written once for this and
    /// for [`RedisCluster::wait_replicas`](crate::RedisCluster::wait_replicas).
    ///
    /// The server holds the reply for up to `timeout_ms`, so the client's
    /// deadline is its command timeout plus `timeout_ms`; with `timeout_ms` 0
    /// the server waits for ever and there is no client deadline, so pass a
    /// positive value. The connection is shared by every user of this client, so
    /// the writes confirmed are all of theirs before the `WAIT`, which is more
    /// than yours and never fewer.
    ///
    /// Fails at once, without sending anything, if a `MULTI` is open on the
    /// connection: the server would queue the `WAIT` instead of running it.
    pub fn wait_replicas(
        &self,
        slot_key: impl AsRef<[u8]>,
        num_replicas: u32,
        timeout_ms: u64,
        callback: impl FnOnce(Result<u32, RedisError>) + Send + 'static,
    ) {
        let _ = slot_key;
        self.wait_typed(wait_command(num_replicas, timeout_ms), timeout_ms, Cap::SCALAR, wait_count, callback);
    }

    /// `WAITAOF numlocal numreplicas timeout_ms`: block until this connection's
    /// writes are fsynced to the local append-only file (`num_local` 0 or 1) and
    /// to `num_replicas` replicas' files, or `timeout_ms` passes. The callback
    /// gets `(local, replicas)` acknowledged. Everything said of
    /// [`wait_replicas`](Self::wait_replicas) applies. A server answers an
    /// error if `num_local` is 1 and it is not running with `appendonly yes`.
    pub fn wait_aof(
        &self,
        slot_key: impl AsRef<[u8]>,
        num_local: u32,
        num_replicas: u32,
        timeout_ms: u64,
        callback: impl FnOnce(Result<(u32, u32), RedisError>) + Send + 'static,
    ) {
        let _ = slot_key;
        self.wait_typed(waitaof_command(num_local, num_replicas, timeout_ms), timeout_ms, Cap::PAIR, aof_counts, callback);
    }

    fn wait_typed<T: Send + 'static>(
        &self,
        command: Command,
        timeout_ms: u64,
        cap: Cap,
        read: fn(Value) -> Result<T, RedisError>,
        callback: impl FnOnce(Result<T, RedisError>) + Send + 'static,
    ) {
        if self.in_multi() {
            self.inner.reactor.execute(Box::new(move || callback(Err(wait_in_multi()))));
            return;
        }
        self.send_value(&command, wait_deadline(timeout_ms), cap, move |reply| callback(reply.and_then(read)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bulk(s: &str) -> Value {
        Value::Bulk(hopf_core::Bytes::copy_from_slice(s.as_bytes()))
    }

    #[test]
    fn converters_accept_the_forms_a_server_may_use_and_refuse_the_rest() {
        assert!(ok(Value::Simple("OK".into())).is_ok());
        assert!(ok(Value::Simple("QUEUED".into())).is_err());
        assert_eq!(int(Value::Int(4)).unwrap(), 4);
        assert_eq!(int(bulk("7")).unwrap(), 7, "a number sent as a string, which a short cap allows");
        assert!(int(Value::Null).is_err());
        assert!(boolean(Value::Int(1)).unwrap());
        assert!(!boolean(Value::Bool(false)).unwrap());
        assert!(!boolean(Value::Int(0)).unwrap());
        assert_eq!(opt_f64(Value::Null).unwrap(), None);
        assert_eq!(opt_f64(bulk("3.5")).unwrap(), Some(3.5));
        assert_eq!(opt_f64(Value::Double(3.5)).unwrap(), Some(3.5));
        assert_eq!(text(bulk("abc")).unwrap(), "abc");
        assert!(text(Value::Int(1)).is_err());
    }

    #[test]
    fn set_options_lay_out_their_flags() {
        let opts = SetOptions {
            nx: true,
            ex: Some(60),
            keepttl: false,
            ..Default::default()
        };
        let cmd = opts.append(Command::new("SET").arg("k").arg("v"));
        let words: Vec<String> = cmd.words().iter().map(|w| String::from_utf8_lossy(w).into_owned()).collect();
        assert_eq!(words, ["SET", "k", "v", "NX", "EX", "60"]);
        let cmd = SetOptions {
            xx: true,
            px: Some(5),
            keepttl: true,
            ..Default::default()
        }
        .append(Command::new("SET").arg("k").arg("v"));
        let words: Vec<String> = cmd.words().iter().map(|w| String::from_utf8_lossy(w).into_owned()).collect();
        assert_eq!(words, ["SET", "k", "v", "XX", "PX", "5", "KEEPTTL"]);
    }

    #[test]
    fn wait_replies_are_counts_and_nothing_else() {
        assert_eq!(wait_count(Value::Int(2)).unwrap(), 2);
        assert!(wait_count(Value::Int(-1)).is_err());
        assert!(wait_count(Value::Null).is_err());
        assert_eq!(aof_counts(Value::Array(vec![Value::Int(1), Value::Int(0)])).unwrap(), (1, 0));
        assert!(aof_counts(Value::Array(vec![Value::Int(1)])).is_err());
        assert!(aof_counts(Value::Int(1)).is_err());
    }

    #[test]
    fn the_server_timeout_is_read_from_where_each_command_keeps_it() {
        let words = |s: &str| s.split(' ').map(|w| w.as_bytes().to_vec()).collect::<Vec<_>>();
        assert_eq!(server_timeout_ms(&words("WAIT 1 250")), 250);
        assert_eq!(server_timeout_ms(&words("waitaof 0 1 75")), 75);
        assert_eq!(server_timeout_ms(&words("WAIT 1")), 0);
        assert!(is_connection_scoped(b"wait") && is_connection_scoped(b"WAITAOF") && !is_connection_scoped(b"GET"));
        assert_eq!(wait_command(2, 100).words().iter().map(|w| w.as_slice()).collect::<Vec<_>>(), [&b"WAIT"[..], b"2", b"100"]);
    }
}
