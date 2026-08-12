// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! WebDAV request XML body parser (PROPFIND / PROPPATCH / LOCK).

use std::cell::UnsafeCell;

use bytes::Bytes;
use tractrix::{FeatureSet, ParseError, ParseResult, Parser, XmlHandler};

use crate::constants::{self, NAMESPACE};
use crate::lock::{LockScope, LockType};

/// PROPFIND request shape (RFC 4918 §14.20).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PropfindType {
    Allprop,
    Propname,
    Prop,
}

#[derive(Debug, Clone)]
pub struct PropfindRequest {
    pub kind: PropfindType,
    pub properties: Vec<PropertyRef>,
    pub include: Vec<PropertyRef>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropertyRef {
    pub namespace_uri: String,
    pub local_name: String,
}

impl Default for PropfindRequest {
    fn default() -> Self {
        Self {
            kind: PropfindType::Allprop,
            properties: Vec::new(),
            include: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProppatchOp {
    Set,
    Remove,
}

#[derive(Debug, Clone)]
pub struct PropertyUpdate {
    pub operation: ProppatchOp,
    pub namespace_uri: String,
    pub local_name: String,
    pub value: String,
    pub is_xml: bool,
}

#[derive(Debug, Default, Clone)]
pub struct ProppatchRequest {
    pub updates: Vec<PropertyUpdate>,
}

#[derive(Debug, Clone)]
pub struct LockRequest {
    pub scope: LockScope,
    pub ty: LockType,
    pub owner: Option<String>,
}

impl Default for LockRequest {
    fn default() -> Self {
        Self {
            scope: LockScope::Exclusive,
            ty: LockType::Write,
            owner: None,
        }
    }
}

#[derive(Debug, Default)]
pub struct WebDavParsed {
    pub propfind: Option<PropfindRequest>,
    pub proppatch: Option<ProppatchRequest>,
    pub lock: Option<LockRequest>,
}

#[derive(Debug, Clone)]
pub enum ParseWebDavError {
    Parse(String),
    TooLarge,
}

impl std::fmt::Display for ParseWebDavError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(m) => write!(f, "{m}"),
            Self::TooLarge => write!(f, "WebDAV request body too large"),
        }
    }
}

impl std::error::Error for ParseWebDavError {}

/// Interior-mutable cell holding the [`XmlHandler`] tractrix's [`Parser`]
/// writes SAX events into. [`self_cell`]'s builder closure only ever gets a
/// shared `&Owner` (never `&mut`), but `Parser::new` needs `&mut dyn
/// XmlHandler` to construct itself — this cell bridges the two.
struct HandlerCell(UnsafeCell<WebDavXmlHandler>);

impl HandlerCell {
    fn new() -> Self {
        Self(UnsafeCell::new(WebDavXmlHandler::default()))
    }

    /// # Safety
    /// The returned `&mut` must not overlap with, or outlive, any other
    /// live reference into this cell. Upheld here because the only caller
    /// is `StreamingParser`'s builder closure (see
    /// `WebDavRequestParser::new`), invoked exactly once per `HandlerCell`
    /// and handing the `&mut` straight to the one `Parser` this cell is
    /// permanently paired with — nothing else ever reaches into the cell
    /// while that `Parser` (the `self_cell` dependent) is alive, and
    /// `self_cell` heap-pins the owner so this pointer stays valid for as
    /// long as the `Parser` borrowing it does.
    unsafe fn handler_mut(&self) -> &mut WebDavXmlHandler {
        unsafe { &mut *self.0.get() }
    }
}

self_cell::self_cell!(
    struct StreamingParser {
        owner: HandlerCell,

        #[not_covariant]
        dependent: Parser,
    }
);

// SAFETY: `StreamingParser` (via `WebDavRequestParser`) is owned exclusively
// by one `WebDavHandler` and only ever accessed through `&mut self` from
// whichever single thread currently holds that handler — never shared
// across threads concurrently, only moved between them, which is exactly
// what `Send` (unlike `Sync`) promises. The parts that aren't auto-`Send`
// are `tractrix::Parser`'s `&mut dyn XmlHandler` (our own `WebDavXmlHandler`,
// a plain owned, already-`Send` type) and its `Option<Box<dyn
// EntityResolver>>` (always `None` here — `WebDavRequestParser::new` never
// supplies one).
unsafe impl Send for StreamingParser {}

/// Incremental parser for a single WebDAV XML request body.
///
/// Holds one [`tractrix::Parser`] alive across [`Self::feed`] calls (issue
/// #191): a prior version constructed a fresh `Parser` — and closed it —
/// on every `feed()` call, discarding the scanner's low-level token
/// position between chunks, which silently broke correctness for any
/// chunk boundary that split a tag, attribute, or entity reference.
/// `Parser` borrows its handler (`&'a mut dyn XmlHandler`), which can't be
/// stored alongside an owned handler in a plain struct without leaking
/// that lifetime — [`self_cell`] pins the handler on the heap so the
/// borrow stays valid for as long as `Self` does.
pub struct WebDavRequestParser {
    parser: StreamingParser,
    bytes_received: usize,
    max_bytes: usize,
    /// Set by the first `feed()` error and returned by every call
    /// afterward without touching `parser` again — unlike the old
    /// buffer-then-reparse design, a genuine incremental `Parser` isn't
    /// safe to keep feeding once it's reported an error.
    error: Option<ParseWebDavError>,
}

impl WebDavRequestParser {
    pub fn new(max_bytes: usize) -> Self {
        let features = FeatureSet::default();
        let parser = StreamingParser::try_new(HandlerCell::new(), |owner: &HandlerCell| {
            // SAFETY: see `HandlerCell::handler_mut`.
            let handler = unsafe { owner.handler_mut() };
            Parser::new(handler, &features, None, None, None)
        })
        // A fresh handler with no entity resolver/public/system IDs never
        // actually fails to construct.
        .expect("Parser::new with a fresh handler cannot fail");
        Self {
            parser,
            bytes_received: 0,
            max_bytes,
            error: None,
        }
    }

    pub fn feed(&mut self, data: &[u8]) -> Result<(), ParseWebDavError> {
        if let Some(err) = &self.error {
            return Err(err.clone());
        }
        self.bytes_received += data.len();
        if self.bytes_received > self.max_bytes {
            let err = ParseWebDavError::TooLarge;
            self.error = Some(err.clone());
            return Err(err);
        }
        let result = self
            .parser
            .with_dependent_mut(|_owner, parser| parser.receive(Bytes::copy_from_slice(data)))
            .map_err(|e| ParseWebDavError::Parse(e.to_string()));
        if let Err(err) = &result {
            self.error = Some(err.clone());
        }
        result
    }

    pub fn finish(mut self) -> Result<WebDavParsed, ParseWebDavError> {
        if let Some(err) = self.error {
            return Err(err);
        }
        self.parser
            .with_dependent_mut(|_owner, parser| parser.close())
            .map_err(|e| ParseWebDavError::Parse(e.to_string()))?;
        // The `Parser` (self_cell's dependent) is dropped by `into_owner`
        // before it returns the owner, so nothing still borrows `handler`
        // here — `UnsafeCell::into_inner` needs no unsafe.
        let handler = self.parser.into_owner().0.into_inner();
        Ok(WebDavParsed {
            propfind: handler.propfind,
            proppatch: handler.proppatch,
            lock: handler.lock,
        })
    }
}

pub fn parse_webdav_body(body: &[u8]) -> Result<WebDavParsed, ParseWebDavError> {
    let mut p = WebDavRequestParser::new(constants::MAX_WEBDAV_REQUEST_BODY);
    p.feed(body)?;
    p.finish()
}

#[derive(Default)]
struct WebDavXmlHandler {
    stack: Vec<String>,
    text: String,
    propfind: Option<PropfindRequest>,
    proppatch: Option<ProppatchRequest>,
    lock: Option<LockRequest>,
    in_prop: bool,
    in_include: bool,
    in_set: bool,
    in_remove: bool,
    in_owner: bool,
    cur_ns: Option<String>,
    cur_name: Option<String>,
    cur_value: String,
    prop_value_depth: i32,
    current_ns: String,
    element_ns: Vec<String>,
}

impl WebDavXmlHandler {
    fn handle_dav_start(&mut self, local: &str) -> ParseResult<()> {
        match local {
            constants::ELEM_PROPFIND => {
                self.propfind = Some(PropfindRequest {
                    kind: PropfindType::Allprop,
                    ..Default::default()
                });
            }
            constants::ELEM_ALLPROP => {
                if let Some(p) = self.propfind.as_mut() {
                    p.kind = PropfindType::Allprop;
                }
            }
            constants::ELEM_PROPNAME => {
                if let Some(p) = self.propfind.as_mut() {
                    p.kind = PropfindType::Propname;
                }
            }
            constants::ELEM_PROP => {
                if let Some(p) = self.propfind.as_mut() {
                    p.kind = PropfindType::Prop;
                }
                self.in_prop = true;
            }
            constants::ELEM_INCLUDE => self.in_include = true,
            constants::ELEM_PROPERTYUPDATE => {
                self.proppatch = Some(ProppatchRequest::default());
            }
            constants::ELEM_SET => self.in_set = true,
            constants::ELEM_REMOVE => self.in_remove = true,
            constants::ELEM_LOCKINFO => {
                self.lock = Some(LockRequest::default());
            }
            constants::ELEM_EXCLUSIVE => {
                if let Some(l) = self.lock.as_mut() {
                    l.scope = LockScope::Exclusive;
                }
            }
            constants::ELEM_SHARED => {
                if let Some(l) = self.lock.as_mut() {
                    l.scope = LockScope::Shared;
                }
            }
            constants::ELEM_WRITE => {
                if let Some(l) = self.lock.as_mut() {
                    l.ty = LockType::Write;
                }
            }
            constants::ELEM_OWNER => self.in_owner = true,
            _ if self.in_prop || self.in_include => {
                self.handle_property_element(NAMESPACE, local);
            }
            _ => {}
        }
        Ok(())
    }

    fn handle_property_element(&mut self, ns: &str, local: &str) {
        if self.in_prop {
            if let Some(p) = self.propfind.as_mut() {
                p.properties.push(PropertyRef {
                    namespace_uri: ns.to_string(),
                    local_name: local.to_string(),
                });
            }
        } else if self.in_include {
            if let Some(p) = self.propfind.as_mut() {
                p.include.push(PropertyRef {
                    namespace_uri: ns.to_string(),
                    local_name: local.to_string(),
                });
            }
        } else if self.in_set || self.in_remove {
            self.cur_ns = Some(ns.to_string());
            self.cur_name = Some(local.to_string());
            self.cur_value.clear();
            self.prop_value_depth = 1;
        }
    }

    fn handle_dav_end(&mut self, local: &str) -> ParseResult<()> {
        match local {
            constants::ELEM_PROP => self.in_prop = false,
            constants::ELEM_INCLUDE => self.in_include = false,
            constants::ELEM_SET => self.in_set = false,
            constants::ELEM_REMOVE => self.in_remove = false,
            constants::ELEM_OWNER => {
                if self.in_owner {
                    if let Some(l) = self.lock.as_mut() {
                        let t = self.text.trim();
                        if !t.is_empty() {
                            l.owner = Some(t.to_string());
                        }
                    }
                    self.in_owner = false;
                    self.text.clear();
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn finish_property_update(&mut self) {
        if let (Some(ns), Some(name)) = (self.cur_ns.take(), self.cur_name.take()) {
            if let Some(patch) = self.proppatch.as_mut() {
                let value = std::mem::take(&mut self.cur_value);
                patch.updates.push(PropertyUpdate {
                    operation: if self.in_set {
                        ProppatchOp::Set
                    } else {
                        ProppatchOp::Remove
                    },
                    namespace_uri: ns,
                    local_name: name,
                    is_xml: value.contains('<'),
                    value,
                });
            }
        }
        self.prop_value_depth = 0;
    }
}

impl XmlHandler for WebDavXmlHandler {
    fn start_element(&mut self, q_name: &str) -> ParseResult<()> {
        let local = q_name
            .rsplit(':')
            .next()
            .unwrap_or(q_name)
            .to_string();
        self.element_ns.push(self.current_ns.clone());
        self.stack.push(local.clone());
        self.text.clear();

        if self.cur_name.is_some() && self.prop_value_depth > 0 {
            self.prop_value_depth += 1;
            self.cur_value.push('<');
            self.cur_value.push_str(q_name);
            self.cur_value.push('>');
            return Ok(());
        }

        if is_dav_local(&local) {
            self.handle_dav_start(&local)?;
        } else if self.in_prop || self.in_include {
            self.handle_property_element(NAMESPACE, &local);
        }
        Ok(())
    }

    fn namespace(&mut self, prefix: &str, uri: &str) -> ParseResult<()> {
        if prefix.is_empty() || uri == NAMESPACE {
            self.current_ns = uri.to_string();
        }
        Ok(())
    }

    fn start_attribute(
        &mut self,
        _name: &str,
        _ty: &str,
        _declared: bool,
        _specified: bool,
    ) -> ParseResult<()> {
        Ok(())
    }

    fn attribute_value_content(&mut self, _value: &str, _end: bool) -> ParseResult<()> {
        Ok(())
    }

    fn end_attributes(&mut self) -> ParseResult<()> {
        Ok(())
    }

    fn characters(&mut self, text: &str, _ignorable: bool, _end: bool) -> ParseResult<()> {
        if self.cur_name.is_some() && self.prop_value_depth > 0 {
            self.cur_value.push_str(text);
        } else if self.in_owner {
            self.text.push_str(text);
        }
        Ok(())
    }

    fn end_element(&mut self) -> ParseResult<()> {
        let local = self
            .stack
            .pop()
            .ok_or_else(|| ParseError::new("unbalanced element"))?;
    let _ = self.element_ns.pop();

        if self.cur_name.is_some() && self.prop_value_depth > 0 {
            self.prop_value_depth -= 1;
            if self.prop_value_depth > 0 {
                self.cur_value.push_str("</");
                self.cur_value.push_str(&local);
                self.cur_value.push('>');
                return Ok(());
            }
            self.finish_property_update();
            return Ok(());
        }

        if is_dav_local(&local) || local == constants::ELEM_OWNER {
            self.handle_dav_end(&local)?;
        }
        Ok(())
    }
}

fn is_dav_local(local: &str) -> bool {
    matches!(
        local,
        constants::ELEM_PROPFIND
            | constants::ELEM_ALLPROP
            | constants::ELEM_PROPNAME
            | constants::ELEM_PROP
            | constants::ELEM_INCLUDE
            | constants::ELEM_PROPERTYUPDATE
            | constants::ELEM_SET
            | constants::ELEM_REMOVE
            | constants::ELEM_LOCKINFO
            | constants::ELEM_EXCLUSIVE
            | constants::ELEM_SHARED
            | constants::ELEM_WRITE
            | constants::ELEM_OWNER
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_propfind_allprop() {
        let body = br#"<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>"#;
        let parsed = parse_webdav_body(body).unwrap();
        let pf = parsed.propfind.unwrap();
        assert_eq!(pf.kind, PropfindType::Allprop);
    }

    #[test]
    fn parse_propfind_named_props() {
        let body = br#"<?xml version="1.0"?>
<propfind xmlns="DAV:"><prop><displayname/></prop></propfind>"#;
        let parsed = parse_webdav_body(body).unwrap();
        let pf = parsed.propfind.unwrap();
        assert_eq!(pf.kind, PropfindType::Prop);
        assert_eq!(pf.properties.len(), 1);
        assert_eq!(pf.properties[0].local_name, "displayname");
    }

    /// Issue #191: `WebDavRequestParser` must hold one real `Parser` alive
    /// across `feed()` calls, not construct-and-close a fresh one each
    /// time — otherwise a chunk boundary that splits a tag name (as here,
    /// mid-`propfind`/mid-`allprop`) would either error or silently lose
    /// the split token, depending on how the halves happen to look on
    /// their own.
    #[test]
    fn feed_across_a_chunk_boundary_that_splits_a_tag_name() {
        let whole = br#"<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>"#;
        for split in 1..whole.len() {
            let (a, b) = whole.split_at(split);
            let mut p = WebDavRequestParser::new(constants::MAX_WEBDAV_REQUEST_BODY);
            p.feed(a).unwrap();
            p.feed(b).unwrap();
            let parsed = p.finish().unwrap();
            let pf = parsed.propfind.unwrap();
            assert_eq!(pf.kind, PropfindType::Allprop, "split at byte {split}");
        }
    }

    /// Same body, fed one byte at a time — the extreme case of a token
    /// split across many chunks.
    #[test]
    fn feed_one_byte_at_a_time() {
        let whole = br#"<?xml version="1.0"?>
<propfind xmlns="DAV:"><prop><displayname/></prop></propfind>"#;
        let mut p = WebDavRequestParser::new(constants::MAX_WEBDAV_REQUEST_BODY);
        for &b in whole {
            p.feed(&[b]).unwrap();
        }
        let parsed = p.finish().unwrap();
        let pf = parsed.propfind.unwrap();
        assert_eq!(pf.kind, PropfindType::Prop);
        assert_eq!(pf.properties[0].local_name, "displayname");
    }

    /// A malformed body's error is latched — once `feed()` reports it,
    /// further `feed()`/`finish()` calls return the same error without
    /// re-entering the (now-errored) `Parser`.
    #[test]
    fn error_is_latched_after_first_failure() {
        let mut p = WebDavRequestParser::new(constants::MAX_WEBDAV_REQUEST_BODY);
        p.feed(b"<propfind>").unwrap();
        let err1 = p.feed(b"</wrongclose>").unwrap_err();
        let err2 = p.feed(b"more data").unwrap_err();
        assert!(matches!(err1, ParseWebDavError::Parse(_)));
        assert!(matches!(err2, ParseWebDavError::Parse(_)));
        assert!(matches!(p.finish().unwrap_err(), ParseWebDavError::Parse(_)));
    }

    #[test]
    fn too_large_is_latched_and_reported_by_finish() {
        let mut p = WebDavRequestParser::new(4);
        assert!(matches!(p.feed(b"12345").unwrap_err(), ParseWebDavError::TooLarge));
        assert!(matches!(p.finish().unwrap_err(), ParseWebDavError::TooLarge));
    }
}
