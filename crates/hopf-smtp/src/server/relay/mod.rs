// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Open-relay MX forwarder (Gumdrop `SimpleRelayService` / `SimpleRelayHandler`).
//!
//! **Security warning:** accepts mail from any sender to any recipient and
//! forwards it. Intended for development, testing, and closed networks only.
//!
//! A message is accepted once it is in the on-disk [`RelayQueue`] and is
//! delivered from there, per recipient: a 4xx reply (or no reply) from the next
//! hop leaves the recipient queued for a retry with backoff, until the queue
//! lifetime ends and it is bounced; a 5xx reply bounces it at once (RFC 5321
//! section 4.5.4.1). See [`RelayOptions`] for the queue directory, backoff and
//! lifetime. Messages left in the queue are delivered when the relay starts.

mod dane;
mod engine;
mod handler;
mod queue;
mod service;

pub use engine::RelayOptions;
pub use handler::{SimpleRelayHandler, SimpleRelayHandlerFactory};
pub use queue::{QueueScan, QueuedMessage, QueuedRecipient, RecipientStatus, RelayQueue};
pub use service::SimpleRelayService;

#[cfg(test)]
mod tests;
