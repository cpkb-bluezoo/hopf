// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! WebDAV (RFC 4918) constants.

/// The DAV: namespace URI (RFC 4918 §12).
pub const NAMESPACE: &str = "DAV:";

/// Default namespace prefix for DAV elements in serialized XML.
pub const PREFIX: &str = "D";

pub const HEADER_DAV: &str = "DAV";
pub const HEADER_DEPTH: &str = "Depth";
pub const HEADER_DESTINATION: &str = "Destination";
pub const HEADER_IF: &str = "If";
pub const HEADER_LOCK_TOKEN: &str = "Lock-Token";
pub const HEADER_OVERWRITE: &str = "Overwrite";
pub const HEADER_TIMEOUT: &str = "Timeout";

pub const DEPTH_0: i32 = 0;
pub const DEPTH_1: i32 = 1;
pub const DEPTH_INFINITY: i32 = i32::MAX;

pub const ELEM_PROPFIND: &str = "propfind";
pub const ELEM_PROPERTYUPDATE: &str = "propertyupdate";
pub const ELEM_LOCKINFO: &str = "lockinfo";
pub const ELEM_ALLPROP: &str = "allprop";
pub const ELEM_INCLUDE: &str = "include";
pub const ELEM_PROPNAME: &str = "propname";
pub const ELEM_PROP: &str = "prop";
pub const ELEM_SET: &str = "set";
pub const ELEM_REMOVE: &str = "remove";
pub const ELEM_MULTISTATUS: &str = "multistatus";
pub const ELEM_RESPONSE: &str = "response";
pub const ELEM_HREF: &str = "href";
pub const ELEM_PROPSTAT: &str = "propstat";
pub const ELEM_STATUS: &str = "status";
pub const ELEM_ERROR: &str = "error";
pub const ELEM_RESPONSEDESCRIPTION: &str = "responsedescription";
pub const ELEM_LOCATION: &str = "location";
pub const ELEM_LOCKSCOPE: &str = "lockscope";
pub const ELEM_LOCKTYPE: &str = "locktype";
pub const ELEM_OWNER: &str = "owner";
pub const ELEM_LOCKDISCOVERY: &str = "lockdiscovery";
pub const ELEM_ACTIVELOCK: &str = "activelock";
pub const ELEM_LOCKTOKEN: &str = "locktoken";
pub const ELEM_TIMEOUT: &str = "timeout";
pub const ELEM_DEPTH: &str = "depth";
pub const ELEM_LOCKROOT: &str = "lockroot";
pub const ELEM_EXCLUSIVE: &str = "exclusive";
pub const ELEM_SHARED: &str = "shared";
pub const ELEM_WRITE: &str = "write";
pub const ELEM_SUPPORTEDLOCK: &str = "supportedlock";
pub const ELEM_LOCKENTRY: &str = "lockentry";
pub const ELEM_COLLECTION: &str = "collection";

pub const PROP_CREATIONDATE: &str = "creationdate";
pub const PROP_DISPLAYNAME: &str = "displayname";
pub const PROP_GETCONTENTLANGUAGE: &str = "getcontentlanguage";
pub const PROP_GETCONTENTLENGTH: &str = "getcontentlength";
pub const PROP_GETCONTENTTYPE: &str = "getcontenttype";
pub const PROP_GETETAG: &str = "getetag";
pub const PROP_GETLASTMODIFIED: &str = "getlastmodified";
pub const PROP_LOCKDISCOVERY: &str = "lockdiscovery";
pub const PROP_RESOURCETYPE: &str = "resourcetype";
pub const PROP_SOURCE: &str = "source";
pub const PROP_SUPPORTEDLOCK: &str = "supportedlock";

pub const TIMEOUT_INFINITE: &str = "Infinite";
pub const TIMEOUT_SECOND_PREFIX: &str = "Second-";
pub const DEFAULT_LOCK_TIMEOUT_SECONDS: i64 = 3600;
pub const MAX_LOCK_TIMEOUT_SECONDS: i64 = 604_800;

pub const CONTENT_TYPE_XML: &str = "application/xml; charset=utf-8";

pub const LOCK_TOKEN_SCHEME: &str = "opaquelocktoken:";

/// Maximum WebDAV control-document body size (1 MiB) — PROPFIND / PROPPATCH
/// / LOCK request bodies, which stay small XML documents.
pub const MAX_WEBDAV_REQUEST_BODY: usize = 1 << 20;

/// Maximum PUT upload size (16 MiB) — matches the default
/// [`hopf_http::HttpLimits::max_request_body`]. Checked incrementally as
/// chunks arrive; raise both knobs together for larger uploads.
pub const MAX_WEBDAV_PUT_BODY: u64 = 16 << 20;

/// Default cap on resources visited during Depth: infinity PROPFIND or
/// recursive COPY.
pub const DEFAULT_MAX_TREE_ENTRIES: usize = 10_000;
