// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! What a test does to read a reply whole: it accumulates it in a sink of its
//! own. The library offers no call that does this, so that nobody holds a value
//! of unbounded size by habit; a test knows its values are small, and says so by
//! writing the sink here, where the cost and the limit are visible.

#![allow(dead_code)]

use std::sync::mpsc;
use std::time::Duration;

use hopf_core::Bytes;
use hopf_redis::{
    AggKind, Command, Flow, RedisClient, RedisCluster, RedisError, ReplySink, Scalar, ServerError, StrKind, StreamHandle,
};

/// A reply, whole.
#[derive(Debug, Clone, PartialEq)]
pub enum Tree {
    Null,
    Int(i64),
    Double(f64),
    Bool(bool),
    Big(String),
    Simple(String),
    Bulk(Vec<u8>),
    /// An error inside a reply (a command's result in a transaction); an error as
    /// the whole reply is an `Err`.
    Error(ServerError),
    Array(Vec<Tree>),
    Set(Vec<Tree>),
    Map(Vec<(Tree, Tree)>),
    Push(Vec<Tree>),
}

impl Tree {
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Tree::Bulk(b) => Some(b),
            Tree::Simple(s) => Some(s.as_bytes()),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        self.as_bytes().and_then(|b| std::str::from_utf8(b).ok())
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            Tree::Int(n) => Some(*n),
            other => other.as_str().and_then(|s| s.parse().ok()),
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Tree::Double(d) => Some(*d),
            Tree::Int(n) => Some(*n as f64),
            other => other.as_str().and_then(|s| s.parse().ok()),
        }
    }

    pub fn as_array(&self) -> Option<&[Tree]> {
        match self {
            Tree::Array(v) | Tree::Set(v) | Tree::Push(v) => Some(v),
            _ => None,
        }
    }

    pub fn into_array(self) -> Option<Vec<Tree>> {
        match self {
            Tree::Array(v) | Tree::Set(v) | Tree::Push(v) => Some(v),
            _ => None,
        }
    }

    pub fn bulk(s: &str) -> Tree {
        Tree::Bulk(s.as_bytes().to_vec())
    }
}

type Done = Box<dyn FnOnce(Result<Tree, RedisError>) + Send>;

/// A sink that builds the reply it is told, and calls back with it.
pub struct TreeSink {
    open: Vec<(AggKind, Vec<Tree>)>,
    text: Option<(StrKind, Vec<u8>)>,
    done: Option<Tree>,
    finish: Option<Done>,
}

impl TreeSink {
    pub fn new(finish: impl FnOnce(Result<Tree, RedisError>) + Send + 'static) -> Self {
        Self {
            open: Vec::new(),
            text: None,
            done: None,
            finish: Some(Box::new(finish)),
        }
    }

    fn place(&mut self, v: Tree) {
        match self.open.last_mut() {
            Some((_, items)) => items.push(v),
            None => self.done = Some(v),
        }
    }
}

impl ReplySink for TreeSink {
    fn scalar(&mut self, v: Scalar<'_>) -> Flow {
        self.place(match v {
            Scalar::Null => Tree::Null,
            Scalar::Int(n) => Tree::Int(n),
            Scalar::Double(d) => Tree::Double(d),
            Scalar::Bool(b) => Tree::Bool(b),
            Scalar::BigNumber(s) => Tree::Big(s.to_string()),
            Scalar::Simple(s) => Tree::Simple(s.to_string()),
        });
        Flow::Continue
    }

    fn error(&mut self, line: &str) -> Flow {
        self.place(Tree::Error(ServerError::parse(line)));
        Flow::Continue
    }

    fn begin_aggregate(&mut self, kind: AggKind, _len: Option<usize>) -> Flow {
        self.open.push((kind, Vec::new()));
        Flow::Continue
    }

    fn end_aggregate(&mut self) -> Flow {
        if let Some((kind, items)) = self.open.pop() {
            let v = match kind {
                AggKind::Array => Tree::Array(items),
                AggKind::Set => Tree::Set(items),
                AggKind::Push => Tree::Push(items),
                AggKind::Map => {
                    let mut it = items.into_iter();
                    let mut pairs = Vec::new();
                    while let (Some(k), Some(v)) = (it.next(), it.next()) {
                        pairs.push((k, v));
                    }
                    Tree::Map(pairs)
                }
            };
            self.place(v);
        }
        Flow::Continue
    }

    fn begin_string(&mut self, kind: StrKind, _len: Option<usize>) -> Flow {
        self.text = Some((kind, Vec::new()));
        Flow::Continue
    }

    fn string_chunk(&mut self, data: &[u8]) -> Flow {
        if let Some((_, buf)) = self.text.as_mut() {
            buf.extend_from_slice(data);
        }
        Flow::Continue
    }

    fn end_string(&mut self) -> Flow {
        if let Some((kind, buf)) = self.text.take() {
            self.place(match kind {
                StrKind::Error => Tree::Error(ServerError::parse(&String::from_utf8_lossy(&buf))),
                _ => Tree::Bulk(buf),
            });
        }
        Flow::Continue
    }

    fn finished(&mut self, outcome: Result<(), RedisError>) {
        let Some(finish) = self.finish.take() else {
            return;
        };
        finish(match outcome {
            Err(e) => Err(e),
            // An error as the whole reply is an error.
            Ok(()) => match self.done.take() {
                Some(Tree::Error(e)) => Err(RedisError::Server(e)),
                Some(t) => Ok(t),
                None => Err(RedisError::Protocol("the reply was empty".into())),
            },
        });
    }
}

/// What can send a command to a sink: a client or a cluster.
pub trait Streams {
    fn stream(&self, command: &Command, sink: TreeSink) -> StreamHandle;
    fn txn(&self, commands: Vec<Command>, sink: TreeSink) -> StreamHandle;
}

impl Streams for RedisClient {
    fn stream(&self, command: &Command, sink: TreeSink) -> StreamHandle {
        self.send_streaming(command, sink)
    }
    fn txn(&self, commands: Vec<Command>, sink: TreeSink) -> StreamHandle {
        self.transaction(commands, sink)
    }
}

impl Streams for RedisCluster {
    fn stream(&self, command: &Command, sink: TreeSink) -> StreamHandle {
        self.send_streaming(command, sink)
    }
    fn txn(&self, commands: Vec<Command>, sink: TreeSink) -> StreamHandle {
        self.transaction(commands, sink)
    }
}

/// Send `command` and call back with its reply, whole.
pub fn run<C: Streams>(c: &C, command: &Command, done: impl FnOnce(Result<Tree, RedisError>) + Send + 'static) {
    c.stream(command, TreeSink::new(done));
}

/// Send `command` and wait for its reply, whole.
pub fn tree<C: Streams>(c: &C, command: &Command) -> Result<Tree, RedisError> {
    let (tx, rx) = mpsc::channel();
    run(c, command, move |r| {
        let _ = tx.send(r);
    });
    rx.recv_timeout(Duration::from_secs(10)).expect("the reply came")
}

/// The command made of `words`, and its reply, whole.
pub fn command<C: Streams>(c: &C, words: &[&[u8]]) -> Result<Tree, RedisError> {
    let cmd = Command::new(words[0]).args(words.iter().skip(1));
    tree(c, &cmd)
}

fn opt_bytes(t: Tree) -> Result<Option<Bytes>, RedisError> {
    match t {
        Tree::Null => Ok(None),
        Tree::Bulk(b) => Ok(Some(Bytes::from(b))),
        other => Err(RedisError::Unexpected(format!("expected a string or nil, got {other:?}"))),
    }
}

fn bytes_vec(t: Tree) -> Result<Vec<Bytes>, RedisError> {
    t.into_array()
        .ok_or_else(|| RedisError::Unexpected("expected an array".into()))?
        .into_iter()
        .map(|e| opt_bytes(e)?.ok_or_else(|| RedisError::Unexpected("a nil element".into())))
        .collect()
}

/// `GET`, whole, with a callback.
pub fn get_with<C: Streams>(
    c: &C,
    key: impl AsRef<[u8]>,
    done: impl FnOnce(Result<Option<Bytes>, RedisError>) + Send + 'static,
) {
    run(c, &Command::new("GET").arg(key), move |r| done(r.and_then(opt_bytes)));
}

/// `GET`, whole.
pub fn get<C: Streams>(c: &C, key: impl AsRef<[u8]>) -> Result<Option<Bytes>, RedisError> {
    tree(c, &Command::new("GET").arg(key)).and_then(opt_bytes)
}

pub fn getdel<C: Streams>(c: &C, key: impl AsRef<[u8]>) -> Result<Option<Bytes>, RedisError> {
    tree(c, &Command::new("GETDEL").arg(key)).and_then(opt_bytes)
}

pub fn hget<C: Streams>(c: &C, key: impl AsRef<[u8]>, field: impl AsRef<[u8]>) -> Result<Option<Bytes>, RedisError> {
    tree(c, &Command::new("HGET").arg(key).arg(field)).and_then(opt_bytes)
}

pub fn lpop<C: Streams>(c: &C, key: impl AsRef<[u8]>) -> Result<Option<Bytes>, RedisError> {
    tree(c, &Command::new("LPOP").arg(key)).and_then(opt_bytes)
}

pub fn rpop<C: Streams>(c: &C, key: impl AsRef<[u8]>) -> Result<Option<Bytes>, RedisError> {
    tree(c, &Command::new("RPOP").arg(key)).and_then(opt_bytes)
}

pub fn lindex<C: Streams>(c: &C, key: impl AsRef<[u8]>, index: i64) -> Result<Option<Bytes>, RedisError> {
    tree(c, &Command::new("LINDEX").arg(key).arg(index.to_string())).and_then(opt_bytes)
}

pub fn mget<C: Streams>(c: &C, keys: &[impl AsRef<[u8]>]) -> Result<Vec<Option<Bytes>>, RedisError> {
    tree(c, &Command::new("MGET").args(keys))?
        .into_array()
        .ok_or_else(|| RedisError::Unexpected("expected an array".into()))?
        .into_iter()
        .map(opt_bytes)
        .collect()
}

pub fn hmget<C: Streams>(
    c: &C,
    key: impl AsRef<[u8]>,
    fields: &[impl AsRef<[u8]>],
) -> Result<Vec<Option<Bytes>>, RedisError> {
    tree(c, &Command::new("HMGET").arg(key).args(fields))?
        .into_array()
        .ok_or_else(|| RedisError::Unexpected("expected an array".into()))?
        .into_iter()
        .map(opt_bytes)
        .collect()
}

pub fn lrange<C: Streams>(c: &C, key: impl AsRef<[u8]>, start: i64, stop: i64) -> Result<Vec<Bytes>, RedisError> {
    tree(c, &Command::new("LRANGE").arg(key).arg(start.to_string()).arg(stop.to_string())).and_then(bytes_vec)
}

pub fn smembers<C: Streams>(c: &C, key: impl AsRef<[u8]>) -> Result<Vec<Bytes>, RedisError> {
    tree(c, &Command::new("SMEMBERS").arg(key)).and_then(bytes_vec)
}

pub fn zrange<C: Streams>(c: &C, key: impl AsRef<[u8]>, start: i64, stop: i64) -> Result<Vec<Bytes>, RedisError> {
    tree(c, &Command::new("ZRANGE").arg(key).arg(start.to_string()).arg(stop.to_string())).and_then(bytes_vec)
}

/// Members with scores: RESP2 sends one flat array, RESP3 an array of pairs.
pub fn zrange_withscores<C: Streams>(
    c: &C,
    key: impl AsRef<[u8]>,
    start: i64,
    stop: i64,
) -> Result<Vec<(Bytes, f64)>, RedisError> {
    let t = tree(
        c,
        &Command::new("ZRANGE").arg(key).arg(start.to_string()).arg(stop.to_string()).arg("WITHSCORES"),
    )?;
    let items = t.into_array().ok_or_else(|| RedisError::Unexpected("expected an array".into()))?;
    let bad = || RedisError::Unexpected("a member without a score".into());
    let mut out = Vec::new();
    if items.first().is_some_and(|i| i.as_array().is_some()) {
        for item in items {
            let pair = item.into_array().ok_or_else(bad)?;
            match pair.as_slice() {
                [m, s] => out.push((Bytes::copy_from_slice(m.as_bytes().ok_or_else(bad)?), s.as_f64().ok_or_else(bad)?)),
                _ => return Err(bad()),
            }
        }
    } else {
        let mut it = items.into_iter();
        while let Some(m) = it.next() {
            let s = it.next().ok_or_else(bad)?;
            out.push((Bytes::copy_from_slice(m.as_bytes().ok_or_else(bad)?), s.as_f64().ok_or_else(bad)?));
        }
    }
    Ok(out)
}

/// `HGETALL`: RESP3 sends a map, RESP2 a flat array.
pub fn hgetall<C: Streams>(c: &C, key: impl AsRef<[u8]>) -> Result<Vec<(Bytes, Bytes)>, RedisError> {
    let bad = || RedisError::Unexpected("expected a map".into());
    let pairs: Vec<(Tree, Tree)> = match tree(c, &Command::new("HGETALL").arg(key))? {
        Tree::Map(m) => m,
        Tree::Array(v) if v.len() % 2 == 0 => {
            let mut it = v.into_iter();
            let mut out = Vec::new();
            while let (Some(k), Some(v)) = (it.next(), it.next()) {
                out.push((k, v));
            }
            out
        }
        _ => return Err(bad()),
    };
    pairs
        .into_iter()
        .map(|(k, v)| match (k, v) {
            (Tree::Bulk(k), Tree::Bulk(v)) => Ok((Bytes::from(k), Bytes::from(v))),
            _ => Err(bad()),
        })
        .collect()
}

/// `EVAL`, whole.
pub fn eval<C: Streams>(
    c: &C,
    script: impl AsRef<[u8]>,
    keys: &[impl AsRef<[u8]>],
    args: &[impl AsRef<[u8]>],
) -> Result<Tree, RedisError> {
    tree(c, &Command::new("EVAL").arg(script).arg(keys.len().to_string()).args(keys).args(args))
}

/// `EVALSHA`, whole.
pub fn evalsha<C: Streams>(
    c: &C,
    sha: impl AsRef<[u8]>,
    keys: &[impl AsRef<[u8]>],
    args: &[impl AsRef<[u8]>],
) -> Result<Tree, RedisError> {
    tree(c, &Command::new("EVALSHA").arg(sha).arg(keys.len().to_string()).args(keys).args(args))
}

/// What `EXEC` answered: each command's result, or `None` if it was aborted.
pub fn results(t: Tree) -> Result<Option<Vec<Tree>>, RedisError> {
    match t {
        Tree::Null => Ok(None),
        Tree::Array(v) => Ok(Some(v)),
        other => Err(RedisError::Unexpected(format!("expected the results, got {other:?}"))),
    }
}

/// `EXEC` on the connection, whole.
pub fn exec<C: Streams>(c: &C) -> Result<Option<Vec<Tree>>, RedisError> {
    tree(c, &Command::new("EXEC")).and_then(results)
}

/// A transaction, whole.
pub fn transaction<C: Streams>(c: &C, commands: Vec<Command>) -> Result<Option<Vec<Tree>>, RedisError> {
    let (tx, rx) = mpsc::channel();
    c.txn(
        commands,
        TreeSink::new(move |r| {
            let _ = tx.send(r);
        }),
    );
    rx.recv_timeout(Duration::from_secs(10)).expect("the reply came").and_then(results)
}
