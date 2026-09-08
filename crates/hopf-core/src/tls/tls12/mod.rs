// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! TLS 1.2 (RFC 5246) — legacy mail/FTPS interop only, ECDHE cipher suites
//! only (no static-RSA key exchange, no client certificates, no
//! renegotiation). Fully self-contained from the TLS 1.3 engine in
//! [`super::engine`] beyond the shared crypto floor — see [`messages`]'s
//! module doc for why.

pub mod engine;
pub mod messages;
pub mod record;
