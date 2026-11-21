// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Async RESP2/RESP3 Redis and Valkey client for Hopf.
//!
//! [`RedisClient`] is one pipelined connection, bound to a reactor: commands
//! may be issued from any thread, go out at once without waiting for earlier
//! replies, and each reply is told to a callback or a sink on the reactor. It
//! negotiates RESP3 (`HELLO 3`) and falls back to RESP2, authenticates,
//! selects a database, resolves host names through `hopf-dns` and speaks TLS
//! through a `hopf-core` connector. [`RedisSubscriber`] is a connection for
//! publish/subscribe that reconnects and subscribes again by itself.
//! [`RedisCluster`] sends each command to the master of a Redis Cluster or
//! Valkey Cluster that owns its key's slot, and follows the cluster as slots
//! move and nodes fail over.
//!
//! # Payloads stream; identifiers are bounded
//!
//! The crate offers no call that hands back a value whose size depends on what
//! the server holds, so memory per connection is set by configuration and never
//! by data: a connection costs its ring, one line and one identifier, however
//! large a value is. A value (a string, a list element, a hash value, a message
//! body, a script result) arrives as chunks, to a sink, with flow control; an
//! identifier (a key, a hash field name, a channel) is delivered whole up to
//! [`DEFAULT_MAX_FIELD`] (64 KiB, `max_field`); a scalar (a count, `OK`, nil) is
//! a value. This is the split HTTP makes between a body and a header field.
//!
//! A command with a scalar reply takes a callback:
//!
//! ```no_run
//! use hopf_core::{Runtime, RuntimeConfig};
//! use hopf_redis::{RedisClient, RedisConfig};
//!
//! let rt = Runtime::start(RuntimeConfig::default()).unwrap();
//! let redis = RedisClient::connect(rt.pick_worker(), RedisConfig::new("127.0.0.1", 6379));
//! redis.set("greeting", "hello", |r| assert!(r.is_ok()));
//! redis.incr("visits", |r| println!("{:?}", r));
//! ```
//!
//! One with a string or a collection in its reply takes a sink, told the reply
//! chunk by chunk in constant memory (see [`BulkSink`], [`ElementsSink`],
//! [`KeysSink`], [`FieldsSink`] and [`RedisClient::send_streaming`] for any
//! other shape):
//!
//! ```no_run
//! use hopf_redis::{BulkHandler, Flow, RedisClient, RedisError};
//!
//! struct Count(usize);
//!
//! impl BulkHandler for Count {
//!     fn chunk(&mut self, data: &[u8]) -> Flow {
//!         self.0 += data.len();
//!         Flow::Continue
//!     }
//!     fn finished(&mut self, outcome: Result<(), RedisError>) {
//!         println!("{} bytes: {outcome:?}", self.0);
//!     }
//! }
//!
//! # fn demo(redis: &RedisClient) {
//! redis.get("big", Count(0));
//! # }
//! ```
//!
//! A value can be streamed out as well, pulled from an [`ArgSource`] a block at a
//! time: see [`Command::arg_stream`] and [`StreamArg`]. A handler that wants a
//! value it knows to be small accumulates it in its own sink, with its own limit
//! and [`Flow::Skip`] for one that exceeds it; the crate offers no call that does
//! so for it.

mod argstream;
mod client;
mod cluster;
mod collect;
mod commands;
mod config;
mod error;
mod keys;
mod pubsub;
pub mod resp;
mod sinks;
mod topology;

pub use argstream::{ArgFactory, ArgSource, SourceCtl, SourceRead, SourceWaker, StreamArg};
pub use client::{Callback, Command, Deadline, RedisClient, Reply, ScalarValue, StreamHandle};
pub use cluster::{ClusterConfig, RedisCluster};
pub use commands::SetOptions;
pub use config::RedisConfig;
pub use sinks::{
    BulkHandler, BulkSink, ElementsHandler, ElementsSink, FieldsHandler, FieldsSink, KeysHandler, KeysSink,
    DEFAULT_MAX_FIELD,
};
pub use error::RedisError;
pub use keys::{command_slot, crc16, key_indexes, key_slot, CrossSlot, SLOTS};
pub use topology::NodeAddr;
pub use pubsub::{
    InvalidationHandler, InvalidationSink, MessageHeader, RedisSubscriber, SubscriberHandler, SubscriptionChange,
    SubscriptionKind,
};
pub use resp::{
    encode_command, AggKind, Feed, Flow, ReplyKind, ReplySink, RespError, RespLimits, RespParser, Scalar, ServerError,
    StrKind,
};
