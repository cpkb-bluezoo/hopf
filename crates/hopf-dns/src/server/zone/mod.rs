// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Authoritative zone data: BIND-style zone files, the in-memory zone model
//! and its serialisation.

mod acl;
mod authoritative;
pub mod client;
mod error;
mod lexer;
mod loader;
mod model;
mod maintain;
mod options;
mod parser;
mod rdata;
mod update;
mod xfr;

pub use authoritative::{AuthoritativeZoneHandler, AuthoritativeZoneHandlerBuilder};
pub use acl::{Acl, Cidr};
pub use error::ZoneError;
pub use options::{ZoneFileMode, ZoneOptions};
pub use model::Zone;
mod writer;
