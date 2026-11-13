// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Async RESP2/RESP3 Redis and Valkey client for Hopf.
//!
//! [`RedisClient`] is one pipelined connection, bound to a reactor: commands
//! may be issued from any thread, go out at once without waiting for earlier
//! replies, and each reply comes back as a callback on the reactor. It
//! negotiates RESP3 (`HELLO 3`) and falls back to RESP2, authenticates,
//! selects a database, resolves host names through `hopf-dns` and speaks TLS
//! through a `hopf-core` connector. [`RedisSubscriber`] is a connection for
//! publish/subscribe that reconnects and subscribes again by itself.
//! [`RedisCluster`] sends each command to the master of a Redis Cluster or
//! Valkey Cluster that owns its key's slot, and follows the cluster as slots
//! move and nodes fail over.
//!
//! ```no_run
//! use hopf_core::{Runtime, RuntimeConfig};
//! use hopf_redis::{RedisClient, RedisConfig};
//!
//! let rt = Runtime::start(RuntimeConfig::default()).unwrap();
//! let redis = RedisClient::connect(rt.pick_worker(), RedisConfig::new("127.0.0.1", 6379));
//! redis.set("greeting", "hello", |r| assert!(r.is_ok()));
//! redis.get("greeting", |r| println!("{:?}", r));
//! ```

mod client;
mod cluster;
mod commands;
mod config;
mod error;
mod keys;
mod pubsub;
pub mod resp;
mod topology;

pub use client::{Callback, Command, RedisClient, Reply};
pub use cluster::{ClusterConfig, RedisCluster};
pub use commands::SetOptions;
pub use config::RedisConfig;
pub use error::RedisError;
pub use keys::{command_slot, crc16, key_indexes, key_slot, CrossSlot, SLOTS};
pub use topology::NodeAddr;
pub use pubsub::{
    Invalidation, Message, Push, RedisSubscriber, SubscriberHandler, SubscriptionChange, SubscriptionKind,
};
pub use resp::{encode_command, RespError, RespLimits, RespParser, ServerError, Value};
