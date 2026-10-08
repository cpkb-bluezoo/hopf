// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! NNTP client: facade, connection driver, session handle and reply parsing.

mod endpoint;
mod error;
mod facade;
mod handlers;
pub(crate) mod reply;
mod session;
mod timeout;

pub use error::NntpClientError;
pub use facade::NntpClient;
pub use handlers::{NntpClientHandler, NntpClientHandlerFactory, NntpGreeting};
pub use reply::{
    dot_stuff, parse_group_response, parse_newsgroup_line, parse_overview_line, parse_status,
    GroupResult, NewsgroupEntry, NntpStatus, OverviewEntry,
};
pub use session::{CompletionCallback, LineCallback, NntpSession};
pub use timeout::NntpClientTimeouts;
