// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! LDAPv3 client and [`CredentialStore`](hopf_auth::CredentialStore) for Hopf.
//!
//! Ports Gumdrop's `org.bluezoo.gumdrop.ldap` BER codec and client, plus
//! `LDAPRealm` as [`LdapCredentialStore`]. The BER codec itself now lives in
//! [`hopf_core::asn1`] — shared with X.509/PKCS8 DER parsing elsewhere in
//! this workspace — and is re-exported here under its old names for
//! existing callers.

#![warn(missing_docs)]

pub mod client;
pub mod store;

pub use client::{
    BindResult, LdapClient, LdapClientConfig, LdapError, LdapResultCode, LdapSession, LdapUrl,
    SearchDone, SearchEntry, SearchRequest, SearchScope, DEFAULT_LDAP_PORT, DEFAULT_LDAPS_PORT,
    DEFAULT_MAX_REFERRAL_HOPS, OID_STARTTLS,
};
pub use store::{escape_ldap_filter, LdapCredentialStore, LdapStoreConfig};

pub use hopf_core::asn1::{Asn1Element, Asn1Error, Asn1Type, BerDecoder, BerEncoder};
pub use hopf_core::VERSION;
