// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! WebDAV filesystem handler for Hopf HTTP servers (RFC 4918).

mod constants;
mod dead_props;
mod factory;
mod handler;
mod if_header;
mod lock;
mod multistatus;
mod parser;
mod path;
mod xml_out;

#[cfg(all(test, feature = "integration"))]
mod integration;

pub use constants::*;
pub use dead_props::{DeadPropMode, DeadProperty, DeadPropertyStore};
pub use factory::{WebDavConfig, WebDavFactory};
pub use lock::{LockScope, LockType, WebDavLock, WebDavLockManager};
pub use multistatus::{
    parse_multistatus, MultiStatusHandler, MultiStatusParseError, MultiStatusParser,
    MultistatusWriter, ResponseWriter,
};
pub use parser::{
    parse_webdav_body, LockRequest, PropfindRequest, PropfindType, ProppatchRequest,
    PropertyRef, PropertyUpdate, WebDavParsed, WebDavRequestParser,
};
pub use path::{canonicalize_path, resolve_path_lexical};
