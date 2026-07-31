// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! POP3 server: control, codec, session, and service.

mod auth;
mod codec;
mod control;
mod egress;
mod handler;
mod metrics;
mod reply;
mod service;
mod session;

pub use codec::{Pop3Command, Pop3ServerLexer, MAX_COMMAND_LINE};
pub use control::Pop3ControlHandler;
pub use egress::Pop3DotStuffer;
pub use handler::{
    AuthorizationHandler, ClientConnected, DefaultPop3Handler, DefaultPop3HandlerFactory,
    Pop3HandlerFactory, TransactionHandler,
};
pub use handler::{
    AuthenticateState, ConnectedState, ListState, ListWriter, MailboxStatusState, MarkDeletedState,
    ResetState, RetrieveState, TopState, UidlState, UidlWriter, UpdateState,
};
pub use metrics::Pop3ServerMetrics;
pub use service::{Pop3Config, Pop3Service, DEFAULT_TRANSACTION_TIMEOUT};
pub use session::Pop3SessionState;
