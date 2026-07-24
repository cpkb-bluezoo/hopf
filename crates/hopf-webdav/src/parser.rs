// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! WebDAV request XML body parser (PROPFIND / PROPPATCH / LOCK).

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

#[derive(Debug)]
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

/// Incremental parser for a single WebDAV XML request body.
pub struct WebDavRequestParser {
    inner: WebDavXmlHandler,
    bytes_received: usize,
    max_bytes: usize,
}

impl WebDavRequestParser {
    pub fn new(max_bytes: usize) -> Self {
        Self {
            inner: WebDavXmlHandler::default(),
            bytes_received: 0,
            max_bytes,
        }
    }

    pub fn feed(&mut self, data: &[u8]) -> Result<(), ParseWebDavError> {
        self.bytes_received += data.len();
        if self.bytes_received > self.max_bytes {
            return Err(ParseWebDavError::TooLarge);
        }
        let features = FeatureSet::default();
        let mut handler = std::mem::take(&mut self.inner);
        {
            let mut parser = Parser::new(&mut handler, &features, None, None, None)
                .map_err(|e| ParseWebDavError::Parse(e.to_string()))?;
            parser
                .parse_all(Bytes::copy_from_slice(data))
                .map_err(|e| ParseWebDavError::Parse(e.to_string()))?;
        }
        self.inner = handler;
        if let Some(err) = self.inner.error.take() {
            return Err(ParseWebDavError::Parse(err));
        }
        Ok(())
    }

    pub fn finish(mut self) -> Result<WebDavParsed, ParseWebDavError> {
        if let Some(err) = self.inner.error.take() {
            return Err(ParseWebDavError::Parse(err));
        }
        Ok(WebDavParsed {
            propfind: self.inner.propfind.take(),
            proppatch: self.inner.proppatch.take(),
            lock: self.inner.lock.take(),
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
    error: Option<String>,
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
        if self.error.is_some() {
            return Err(ParseError::new("webdav xml error"));
        }
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
}
