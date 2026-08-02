// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! LDAPv3 client on the Hopf [`Runtime`](hopf_core::Runtime).
//!
//! Ports Gumdrop `LDAPClient` / `LDAPClientProtocolHandler`: bind, search,
//! unbind, STARTTLS, and referral URL delivery for chase.

mod endpoint;
mod facade;
mod filter;
mod message;
mod session;
mod types;
mod url;

pub use facade::LdapClient;
pub use filter::encode_filter;
pub use message::{
    encode_bind_request, encode_extended_request, encode_search_request, encode_starttls_request,
    encode_unbind_request,
};
pub use session::LdapSession;
pub use types::{
    BindResult, DerefAliases, LdapClientConfig, LdapError, LdapResultCode, SearchDone, SearchEntry,
    SearchRequest, SearchScope, DEFAULT_LDAP_PORT, DEFAULT_LDAPS_PORT, DEFAULT_MAX_REFERRAL_HOPS,
    OID_STARTTLS,
};
pub use url::LdapUrl;
