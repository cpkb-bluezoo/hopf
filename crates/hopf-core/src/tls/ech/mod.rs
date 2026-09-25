// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! TLS Encrypted Client Hello (RFC 9849).
//!
//! * [`config`] - `ECHConfig` / `ECHConfigList` encoding, parsing, and HPKE
//!   cipher-suite selection.

pub mod config;

pub use config::{
    select_config, EchConfig, EchConfigError, EchSelection, HpkeCipherSuite, ECH_VERSION,
    SUPPORTED_HPKE_SUITES,
};
