// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Local mailbox delivery (Gumdrop `LocalDeliveryService` / `LocalDeliveryHandler`).
//!
//! Accepts mail only for recipients in a configured local domain and APPENDs
//! each message to the recipient's INBOX via [`hopf_mailbox::MailboxFactory`].

mod handler;
mod service;

pub use handler::{LocalDeliveryHandler, LocalDeliveryHandlerFactory};
pub use service::LocalDeliveryService;
