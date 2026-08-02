// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! SMTP server: control, codec, session, service, and pluggable delivery
//! backends ([`mailbox`] local delivery, [`relay`] open MX relay).

mod codec;
mod control;
mod data;
mod delivery;
mod dsn;
mod handler;
mod mailbox;
mod metrics;
mod mime_pipeline;
mod pipeline;
mod relay;
mod reply;
mod service;
mod session;
mod spool;
mod xclient;

pub use codec::{SmtpCommand, SmtpServerLexer, MAX_COMMAND_LINE};
pub use control::SmtpControlHandler;
pub use data::{BdatAccumulator, DotUnstuffer};
pub use delivery::{
    parse_mail_from_arg, parse_rcpt_to_arg, BodyType, DeliverBy, DeliveryRequirements, DsnNotify,
    DsnRecipientParams, DsnReturn, MailFromParse, ParamParseError,
};
pub use dsn::{DeliveryStatusNotification, DsnAction, DsnRecipientReport};
pub use handler::{
    AcceptAllSmtpHandler, AcceptAllSmtpHandlerFactory, AuthenticateState, ConnectedState,
    DeferredDelivery, HelloHandler, HelloState, MailFromHandler, MailFromState, MessageDataHandler,
    MessageEndState, MessageStartState, RecipientHandler, RecipientState, ResetState,
    SmtpClientConnected, SmtpConnectionMetadata, SmtpHandlerFactory,
};
pub use metrics::SmtpServerMetrics;
pub use mime_pipeline::MimeAnalysisPipeline;
pub use pipeline::{DiscardPipeline, NullPipeline, SmtpPipeline};
pub use mailbox::{LocalDeliveryHandler, LocalDeliveryHandlerFactory, LocalDeliveryService};
pub use relay::{SimpleRelayHandler, SimpleRelayHandlerFactory, SimpleRelayService};
pub use reply::{reply, reply_ehlo, reply_enhanced, reply_multiline};
pub use service::{
    SmtpConfig, SmtpService, DEFAULT_MAX_MAIL_TRANSACTIONS, DEFAULT_MAX_MESSAGE_SIZE,
    DEFAULT_MAX_RECIPIENTS,
};
pub use session::{DataDotState, SmtpSessionState};
pub use xclient::{decode_xtext, parse_xclient_args, XclientOverrides, XclientParseError};
