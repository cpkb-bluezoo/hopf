// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! LDAPv3 client on the Hopf [`Runtime`](hopf_core::Runtime).
//!
//! Ports Gumdrop `LDAPClient` / `LDAPClientProtocolHandler`: bind, search,
//! unbind, STARTTLS, and referral URL delivery for chase.

mod control;
mod endpoint;
mod facade;
mod filter;
mod message;
mod replica;
mod session;
mod sync;
#[cfg(test)]
mod sync_tests;
mod types;
mod url;

pub use control::Control;
pub use facade::LdapClient;
pub use filter::encode_filter;
pub use message::{
    encode_abandon_request, encode_bind_request, encode_extended_request, encode_search_request,
    encode_search_request_with_controls, encode_starttls_request, encode_unbind_request,
};
pub use replica::{ReplicaError, SyncReplica};
pub use session::{LdapSession, SyncHandle};
pub use sync::{
    SyncDone, SyncDoneValue, SyncEvent, SyncInfo, SyncMode, SyncRequest, SyncState, SyncStateValue,
    OID_SYNC_DONE_CONTROL, OID_SYNC_INFO_MESSAGE, OID_SYNC_REQUEST_CONTROL, OID_SYNC_STATE_CONTROL,
    SYNC_UUID_LEN,
};
pub use types::{
    BindResult, DerefAliases, LdapClientConfig, LdapError, LdapResultCode, SearchDone, SearchEntry,
    SearchRequest, SearchScope, DEFAULT_LDAP_PORT, DEFAULT_LDAPS_PORT, DEFAULT_MAX_REFERRAL_HOPS,
    OID_STARTTLS,
};
pub use url::LdapUrl;
