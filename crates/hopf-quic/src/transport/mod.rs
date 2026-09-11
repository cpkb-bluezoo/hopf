// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! In-tree RFC 9000 QUIC transport (Gumdrop-shaped; Phase 3).

#![allow(dead_code)]

pub mod cid;
pub mod connection;
pub mod endpoint;
pub mod frame;
pub mod packet;
pub mod recovery;
pub mod stream;
pub mod tls_bridge;
pub mod types;
pub mod varint;

