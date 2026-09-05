// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Open-relay MX forwarder (Gumdrop `SimpleRelayService` / `SimpleRelayHandler`).
//!
//! **Security warning:** accepts mail from any sender to any recipient and
//! forwards it. Intended for development, testing, and closed networks only.

mod dane;
mod handler;
mod service;

pub use handler::{SimpleRelayHandler, SimpleRelayHandlerFactory};
pub use service::SimpleRelayService;
