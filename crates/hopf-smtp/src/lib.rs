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

pub mod auth;
pub mod client;

mod server;

pub use auth::{AuthPipeline, AuthPipelineBuilder, AuthResultsHandle, AuthVerdict, AuthVerdictHandle};
pub use client::{
    dot_stuff, MailFromParams, SmtpCapabilities, SmtpClient, SmtpClientDriver, SmtpClientEndpoint,
    SmtpEvent, SmtpClientHandlerFactory, SmtpClientTimeouts, SmtpError, SmtpReplyLexer,
    SmtpReplyShape, SmtpResult, SmtpSend, MAX_REPLY_LINE,
};
pub use server::{
    parse_mail_from_arg, parse_rcpt_to_arg, reply, reply_ehlo, reply_enhanced, reply_multiline,
    AcceptAllSmtpHandler, AcceptAllSmtpHandlerFactory, AuthenticateState, BdatAccumulator,
    BodyType, ConnectedState, DataDotState, DeferredDelivery, DeliverBy, DeliveryRequirements,
    DiscardPipeline, DotUnstuffer, DsnNotify, DsnRecipientParams, DsnReturn, HelloHandler,
    HelloState, LocalDeliveryHandler, LocalDeliveryHandlerFactory, LocalDeliveryService,
    MailFromHandler, MailFromParse, MailFromState, MessageDataHandler,
    MessageEndState, MessageStartState, MimeAnalysisPipeline, NullPipeline, ParamParseError, RecipientHandler,
    RecipientState, ResetState, SimpleRelayHandler, SimpleRelayHandlerFactory,
    SimpleRelayService, SmtpClientConnected, SmtpCommand, SmtpConfig, SmtpConnectionMetadata,
    SmtpControlHandler, SmtpHandlerFactory, SmtpPipeline, SmtpServerLexer, SmtpServerMetrics,
    SmtpService, SmtpSessionState, DEFAULT_MAX_MESSAGE_SIZE, DEFAULT_MAX_RECIPIENTS,
    MAX_COMMAND_LINE,
};

#[cfg(all(test, feature = "integration"))]
mod integration;

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
