// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! SMTP / SMTPS server and async client (Gumdrop `org.bluezoo.gumdrop.smtp` port).
//!
//! The protocol engine talks to a staged handler SPI ([`SmtpClientConnected`] →
//! [`HelloHandler`] → [`MailFromHandler`] → …). Stock handlers:
//! [`AcceptAllSmtpHandler`] (discard), [`SimpleRelayService`] (open MX relay),
//! and [`LocalDeliveryService`] (APPEND to local mailboxes).
//!
//! The async client ([`SmtpClient`] + [`client::SmtpSend`]) uses the
//! `hopf-core` `Runtime`/`ProtocolHandler` SPI for non-blocking delivery.

#![warn(missing_docs)]

pub mod client;

mod codec;
mod control;
mod data;
mod delivery;
mod handler;
mod mailbox;
mod metrics;
mod pipeline;
mod relay;
mod reply;
mod service;
mod session;

pub use client::{
    dot_stuff, SmtpCapabilities, SmtpClient, SmtpClientDriver, SmtpClientEndpoint,
    SmtpClientHandlerFactory, SmtpClientTimeouts, SmtpError, SmtpReply, SmtpResult, SmtpSend,
};
pub use codec::{SmtpCommand, SmtpServerLexer};
pub use control::SmtpControlHandler;
pub use data::{BdatAccumulator, DotUnstuffer};
pub use delivery::{
    parse_mail_from_arg, parse_rcpt_to_arg, BodyType, DeliverBy, DeliveryRequirements, DsnNotify,
    DsnRecipientParams, DsnReturn, MailFromParse, ParamParseError,
};
pub use handler::{
    AcceptAllSmtpHandler, AcceptAllSmtpHandlerFactory, AuthenticateState, ConnectedState,
    DeferredDelivery, HelloHandler, HelloState, MailFromHandler, MailFromState, MessageDataHandler,
    MessageEndState, MessageStartState, RecipientHandler, RecipientState, ResetState,
    SmtpClientConnected, SmtpConnectionMetadata, SmtpHandlerFactory,
};
pub use metrics::SmtpServerMetrics;
pub use pipeline::{DiscardPipeline, NullPipeline, SmtpPipeline};
pub use mailbox::{
    LocalDeliveryHandler, LocalDeliveryHandlerFactory, LocalDeliveryService,
};
pub use relay::{
    MessageBufferPipeline, SimpleRelayHandler, SimpleRelayHandlerFactory, SimpleRelayService,
};
pub use reply::{reply, reply_ehlo, reply_enhanced, reply_multiline};
pub use service::{SmtpConfig, SmtpService, DEFAULT_MAX_MESSAGE_SIZE, DEFAULT_MAX_RECIPIENTS};
pub use session::{DataDotState, SmtpSessionState};

#[cfg(all(test, feature = "integration"))]
mod integration;

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
