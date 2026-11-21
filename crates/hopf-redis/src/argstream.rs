// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Streamed command arguments: a value that is never held whole.
//!
//! RESP puts each argument's length before its bytes, so a streamed argument
//! declares its length up front ([`StreamArg::new`]) and is then pulled, block
//! by block, as the connection can take it: never more than one block is
//! outstanding, so a value of any size costs a constant amount of memory.
//!
//! A source runs on the connection's reactor and must not block. One that has
//! nothing yet (it is waiting for a file read on the storage pool, or for a
//! producer) returns [`SourceRead::Pending`] after arranging for
//! [`SourceWaker::wake`] to be called when it has, which is the outbound mirror of
//! a reply sink's `Flow::Pause` and `StreamHandle::resume`.
//!
//! A command may be sent more than once: a cluster follows `MOVED` and `ASK`, and
//! a client reconnects. So an argument is a *factory* that opens a fresh
//! [`ArgSource`] for each attempt (a file reopens, a generator restarts). A
//! source that cannot be repeated is [`StreamArg::once`]: the second attempt
//! fails with [`RedisError::NotRepeatable`] instead of sending a short value.

use std::sync::Arc;

use crate::error::RedisError;

/// What [`ArgSource::read`] found.
#[derive(Debug, Clone, PartialEq)]
pub enum SourceRead {
    /// This many bytes (more than none, and no more than the buffer held) were
    /// written to the start of the buffer.
    Data(usize),
    /// Nothing yet. [`SourceWaker::wake`] has been arranged for when there is.
    Pending,
    /// The source has failed. Part of the command is already on the wire, so
    /// the connection is closed (the only way to recover); the command fails with
    /// this error and what was pipelined behind it with `ConnectionLost`.
    Failed(RedisError),
}

/// Wakes the connection to read a source that said it was
/// [`Pending`](SourceRead::Pending). Cheap to clone, and may be called from any
/// thread, any number of times: a spurious wake just reads the source again.
#[derive(Clone)]
pub struct SourceWaker(Arc<dyn Fn() + Send + Sync>);

impl SourceWaker {
    pub(crate) fn new(wake: impl Fn() + Send + Sync + 'static) -> Self {
        Self(Arc::new(wake))
    }

    /// Ask for the source to be read again.
    pub fn wake(&self) {
        (self.0)();
    }
}

impl std::fmt::Debug for SourceWaker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SourceWaker(..)")
    }
}

/// What a source is given with each read, to get a waker from.
pub struct SourceCtl<'a> {
    waker: &'a SourceWaker,
}

impl<'a> SourceCtl<'a> {
    pub(crate) fn new(waker: &'a SourceWaker) -> Self {
        Self { waker }
    }

    /// A waker for this connection, to be kept if the source returns
    /// [`SourceRead::Pending`].
    pub fn waker(&self) -> SourceWaker {
        self.waker.clone()
    }
}

/// The bytes of one streamed argument, for one attempt at sending it.
pub trait ArgSource: Send {
    /// Write up to `out.len()` of the next bytes to the start of `out`. Called
    /// on the connection's reactor, and must not block. The connection asks for
    /// no more than the length the argument declared.
    fn read(&mut self, out: &mut [u8], ctl: &mut SourceCtl<'_>) -> SourceRead;
}

/// Opens an [`ArgSource`] for each attempt at sending a command.
pub trait ArgFactory: Send + Sync {
    /// A source positioned at the start. Called on the connection's reactor when
    /// the command reaches the front of what is to be written. An error fails the
    /// command, and nothing of it has been written.
    fn open(&self) -> Result<Box<dyn ArgSource>, RedisError>;
}

struct FnFactory<F>(F);

impl<F: Fn() -> Result<Box<dyn ArgSource>, RedisError> + Send + Sync> ArgFactory for FnFactory<F> {
    fn open(&self) -> Result<Box<dyn ArgSource>, RedisError> {
        (self.0)()
    }
}

struct Once(std::sync::Mutex<Option<Box<dyn ArgSource>>>);

impl ArgFactory for Once {
    fn open(&self) -> Result<Box<dyn ArgSource>, RedisError> {
        self.0.lock().unwrap().take().ok_or(RedisError::NotRepeatable)
    }
}

/// An argument whose bytes are pulled from a source as the connection takes
/// them. Add it to a command with [`Command::arg_stream`](crate::Command::arg_stream).
#[derive(Clone)]
pub struct StreamArg {
    len: u64,
    factory: Arc<dyn ArgFactory>,
}

impl StreamArg {
    /// An argument of exactly `len` bytes, opened afresh for each attempt by
    /// `factory`. A source that gives fewer bytes fails the command; one is never
    /// asked for more.
    pub fn new(len: u64, factory: impl ArgFactory + 'static) -> Self {
        Self {
            len,
            factory: Arc::new(factory),
        }
    }

    /// [`new`](Self::new), with a function that opens a source.
    pub fn from_fn(len: u64, open: impl Fn() -> Result<Box<dyn ArgSource>, RedisError> + Send + Sync + 'static) -> Self {
        Self::new(len, FnFactory(open))
    }

    /// An argument that can be sent once: the first attempt reads `source`, and
    /// any later one (a redirection, a reconnection) fails with
    /// [`RedisError::NotRepeatable`].
    pub fn once(len: u64, source: impl ArgSource + 'static) -> Self {
        Self::new(len, Once(std::sync::Mutex::new(Some(Box::new(source)))))
    }

    /// The declared length in bytes.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether the declared length is none.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub(crate) fn factory(&self) -> &Arc<dyn ArgFactory> {
        &self.factory
    }
}

impl std::fmt::Debug for StreamArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "StreamArg({} bytes)", self.len)
    }
}

impl PartialEq for StreamArg {
    fn eq(&self, other: &Self) -> bool {
        self.len == other.len && Arc::ptr_eq(&self.factory, &other.factory)
    }
}

impl Eq for StreamArg {}
