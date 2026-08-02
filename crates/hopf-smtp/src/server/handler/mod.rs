// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Staged SMTP connection-handler SPI (Gumdrop `handler` package).

mod accept_all;
mod state;

pub use accept_all::{AcceptAllSmtpHandler, AcceptAllSmtpHandlerFactory};
pub use state::{
    AuthenticateState, ConnectedState, DeferredDelivery, HelloState, MailFromState,
    MessageEndState, MessageStartState, RecipientState, ResetState,
};
pub(crate) use state::DeferredSlot;

use std::net::SocketAddr;

use rmimeparser::EmailAddress;

use crate::server::delivery::{DeliveryRequirements, DsnRecipientParams};
use crate::server::pipeline::SmtpPipeline;

/// Per-connection metadata visible to handlers.
#[derive(Clone)]
pub struct SmtpConnectionMetadata {
    /// Effective client address (may be overridden by XCLIENT ADDR/PORT).
    pub peer: SocketAddr,
    /// Effective local address (may be overridden by XCLIENT DESTADDR/DESTPORT).
    pub local: SocketAddr,
    /// TLS is active.
    pub tls: bool,
    /// Authenticated username, if any (local SASL only — never from XCLIENT LOGIN).
    pub authenticated_user: Option<String>,
    /// SMTPUTF8 negotiated for the current transaction.
    pub smtputf8: bool,
    /// Control-connection handle (for deferred delivery / off-reactor work).
    pub control_handle: Option<hopf_core::ConnHandle>,
    /// Negotiated TLS parameters (cipher suite, protocol version, peer
    /// certificate chain for mTLS). [`hopf_core::SecurityInfo::plaintext`]
    /// until TLS is established.
    pub security_info: hopf_core::SecurityInfo,
    /// Client reverse hostname from XCLIENT `NAME`, if asserted.
    pub reverse_name: Option<String>,
    /// Informational proxied login from XCLIENT `LOGIN` (not SASL AUTH).
    pub xclient_login: Option<String>,
}

/// Factory for the initial [`SmtpClientConnected`] stage.
pub trait SmtpHandlerFactory: Send + Sync {
    /// Create a handler for a new connection.
    fn create(&self) -> Box<dyn SmtpClientConnected>;
}

/// Entry-point stage after TCP (and optional implicit TLS) accept.
pub trait SmtpClientConnected: Send {
    /// New connection; call accept/reject on `state`.
    fn connected(&mut self, state: &mut dyn ConnectedState, meta: &SmtpConnectionMetadata);
    /// Connection closed.
    fn disconnected(&mut self);
}

/// HELO/EHLO, STARTTLS notification, AUTH policy.
pub trait HelloHandler: Send {
    /// Client greeting.
    fn hello(&mut self, state: &mut dyn HelloState, extended: bool, hostname: &str);
    /// TLS established after STARTTLS (or implicit).
    fn tls_established(&mut self, info: &hopf_core::SecurityInfo);
    /// SASL completed; decide accept/reject.
    fn authenticated(&mut self, state: &mut dyn AuthenticateState, user: &str);
    /// QUIT.
    fn quit(&mut self);
}

/// Ready for MAIL FROM.
pub trait MailFromHandler: Send {
    /// Optional processing pipeline for this transaction.
    fn pipeline(&mut self) -> Option<Box<dyn SmtpPipeline>> {
        None
    }
    /// MAIL FROM received.
    fn mail_from(
        &mut self,
        state: &mut dyn MailFromState,
        sender: Option<&EmailAddress>,
        smtputf8: bool,
        delivery: &DeliveryRequirements,
    );
    /// RSET.
    fn reset(&mut self, state: &mut dyn ResetState);
    /// QUIT.
    fn quit(&mut self);
}

/// RCPT TO and DATA/BDAT start.
pub trait RecipientHandler: Send {
    /// RCPT TO received.
    fn rcpt_to(
        &mut self,
        state: &mut dyn RecipientState,
        recipient: &EmailAddress,
        dsn: &DsnRecipientParams,
    );
    /// DATA or first BDAT — begin message transfer.
    fn start_message(&mut self, state: &mut dyn MessageStartState);
    /// RSET.
    fn reset(&mut self, state: &mut dyn ResetState);
    /// QUIT.
    fn quit(&mut self);
}

/// Message content and completion.
pub trait MessageDataHandler: Send {
    /// Content chunk (dot-unstuffed).
    fn message_content(&mut self, chunk: &[u8]);
    /// Transfer complete — accept or reject delivery.
    fn message_complete(&mut self, state: &mut dyn MessageEndState);
    /// Transfer aborted.
    fn message_aborted(&mut self);
}
