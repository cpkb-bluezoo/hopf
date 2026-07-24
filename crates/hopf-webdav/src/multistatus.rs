// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Symmetric Multi-Status write/parse API (RFC 4918 §13).

use std::io;

use bytes::Bytes;
use tractrix::{
    FeatureSet, NamespaceFilter, ParseError, ParseResult, Parser, XmlHandler, XmlWriter,
};

use crate::constants::{self, NAMESPACE, PREFIX};
use crate::xml_out::{dav_element_text, dav_end, dav_start, write_prop_end, write_prop_start};

type DavWriter = XmlWriter<Vec<u8>>;

/// Streaming `207 Multi-Status` document builder over one [`XmlWriter`].
pub struct MultistatusWriter {
    w: DavWriter,
    open: bool,
}

impl MultistatusWriter {
    pub fn new() -> Self {
        Self {
            w: XmlWriter::new_vec(),
            open: false,
        }
    }

    fn ensure_open(&mut self) -> io::Result<()> {
        if self.open {
            return Ok(());
        }
        self.w
            .write_processing_instruction_data("xml", Some("version=\"1.0\" encoding=\"utf-8\""))?;
        dav_start(&mut self.w, constants::ELEM_MULTISTATUS)?;
        self.w.write_namespace(PREFIX, NAMESPACE)?;
        self.open = true;
        Ok(())
    }

    /// Open a `<response>` for `href`, write children via `f`, then close it.
    pub fn response(
        &mut self,
        href: &str,
        f: impl FnOnce(&mut ResponseWriter<'_>) -> io::Result<()>,
    ) -> io::Result<()> {
        self.ensure_open()?;
        dav_start(&mut self.w, constants::ELEM_RESPONSE)?;
        dav_element_text(&mut self.w, constants::ELEM_HREF, href)?;
        {
            let mut rw = ResponseWriter { w: &mut self.w };
            f(&mut rw)?;
        }
        dav_end(&mut self.w)
    }

    /// Finish the document and return UTF-8 bytes.
    pub fn finish(mut self) -> Vec<u8> {
        let _ = self.ensure_open();
        let _ = dav_end(&mut self.w);
        let _ = self.w.flush();
        self.w.into_inner()
    }
}

impl Default for MultistatusWriter {
    fn default() -> Self {
        Self::new()
    }
}

/// Writer for children of a single Multi-Status `<response>`.
pub struct ResponseWriter<'a> {
    w: &'a mut DavWriter,
}

impl ResponseWriter<'_> {
    /// Response-level `<status>` (method-level outcome).
    pub fn status(&mut self, status_line: &str) -> io::Result<()> {
        dav_element_text(self.w, constants::ELEM_STATUS, status_line)
    }

    /// One `<propstat>` with `<prop>` body from `write_props`, then status.
    pub fn propstat(
        &mut self,
        status_line: &str,
        write_props: impl FnOnce(&mut DavWriter) -> io::Result<()>,
    ) -> io::Result<()> {
        dav_start(self.w, constants::ELEM_PROPSTAT)?;
        write_prop_start(self.w)?;
        write_props(self.w)?;
        write_prop_end(self.w)?;
        dav_element_text(self.w, constants::ELEM_STATUS, status_line)?;
        dav_end(self.w)
    }

    /// Response-level `<error>` whose children are written by `write_body`.
    pub fn error(
        &mut self,
        write_body: impl FnOnce(&mut DavWriter) -> io::Result<()>,
    ) -> io::Result<()> {
        dav_start(self.w, constants::ELEM_ERROR)?;
        write_body(self.w)?;
        dav_end(self.w)
    }

    /// `<responsedescription>`.
    pub fn description(&mut self, text: &str) -> io::Result<()> {
        dav_element_text(self.w, constants::ELEM_RESPONSEDESCRIPTION, text)
    }

    /// `<location><href>…</href></location>`.
    pub fn location(&mut self, href: &str) -> io::Result<()> {
        dav_start(self.w, constants::ELEM_LOCATION)?;
        dav_element_text(self.w, constants::ELEM_HREF, href)?;
        dav_end(self.w)
    }
}

/// Callback surface for streaming Multi-Status parse events.
pub trait MultiStatusHandler {
    fn start_response(&mut self, href: &str);
    fn response_status(&mut self, status_line: &str) {
        let _ = status_line;
    }
    fn start_propstat(&mut self) {}
    fn propstat_status(&mut self, status_line: &str) {
        let _ = status_line;
    }
    fn start_property(&mut self, namespace_uri: &str, local_name: &str) {
        let _ = (namespace_uri, local_name);
    }
    fn characters(&mut self, text: &str) {
        let _ = text;
    }
    fn end_property(&mut self, namespace_uri: &str, local_name: &str) {
        let _ = (namespace_uri, local_name);
    }
    fn end_propstat(&mut self) {}
    fn start_error(&mut self) {}
    fn end_error(&mut self) {}
    fn response_description(&mut self, text: &str) {
        let _ = text;
    }
    fn location(&mut self, href: &str) {
        let _ = href;
    }
    fn end_response(&mut self) {}
}

/// Error from Multi-Status parsing.
#[derive(Debug)]
pub enum MultiStatusParseError {
    Parse(String),
    TooLarge,
}

impl std::fmt::Display for MultiStatusParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(m) => write!(f, "{m}"),
            Self::TooLarge => write!(f, "Multi-Status body too large"),
        }
    }
}

impl std::error::Error for MultiStatusParseError {}

/// Incremental Multi-Status parser: `feed` accumulates, `finish` runs tractrix once.
pub struct MultiStatusParser<H: MultiStatusHandler> {
    handler: H,
    buffer: Vec<u8>,
    max_bytes: usize,
}

impl<H: MultiStatusHandler> MultiStatusParser<H> {
    pub fn new(handler: H) -> Self {
        Self::with_limit(handler, constants::MAX_WEBDAV_REQUEST_BODY)
    }

    pub fn with_limit(handler: H, max_bytes: usize) -> Self {
        Self {
            handler,
            buffer: Vec::new(),
            max_bytes,
        }
    }

    pub fn feed(&mut self, data: &[u8]) -> Result<(), MultiStatusParseError> {
        if self.buffer.len().saturating_add(data.len()) > self.max_bytes {
            return Err(MultiStatusParseError::TooLarge);
        }
        self.buffer.extend_from_slice(data);
        Ok(())
    }

    /// Parse the accumulated document and return the handler.
    pub fn finish(mut self) -> Result<H, MultiStatusParseError> {
        let features = FeatureSet::default();
        let mut adapter = MultistatusXmlAdapter::new(&mut self.handler);
        {
            let mut filter = NamespaceFilter::new(&mut adapter, false);
            let mut parser = Parser::new(&mut filter, &features, None, None, None)
                .map_err(|e| MultiStatusParseError::Parse(e.to_string()))?;
            parser
                .parse_all(Bytes::copy_from_slice(&self.buffer))
                .map_err(|e| MultiStatusParseError::Parse(e.to_string()))?;
        }
        if let Some(err) = adapter.error.take() {
            return Err(MultiStatusParseError::Parse(err));
        }
        Ok(self.handler)
    }
}

/// Parse a complete Multi-Status document in one shot.
pub fn parse_multistatus<H: MultiStatusHandler>(
    body: &[u8],
    handler: H,
) -> Result<H, MultiStatusParseError> {
    let mut p = MultiStatusParser::new(handler);
    p.feed(body)?;
    p.finish()
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Frame {
    Multistatus,
    Response,
    Propstat,
    Prop,
    Property,
    Status,
    Href,
    Error,
    Description,
    Location,
    LocationHref,
    Other,
}

struct MultistatusXmlAdapter<'a, H: MultiStatusHandler> {
    handler: &'a mut H,
    stack: Vec<Frame>,
    ns_stack: Vec<Vec<(String, String)>>,
    text: String,
    pending_href: Option<String>,
    response_started: bool,
    status_in_propstat: bool,
    /// Property start deferred until `end_attributes` so xmlns on the element is visible.
    pending_property: Option<(String, String)>,
    property_stack: Vec<(String, String)>,
    error: Option<String>,
}

impl<'a, H: MultiStatusHandler> MultistatusXmlAdapter<'a, H> {
    fn new(handler: &'a mut H) -> Self {
        Self {
            handler,
            stack: Vec::new(),
            ns_stack: Vec::new(),
            text: String::new(),
            pending_href: None,
            response_started: false,
            status_in_propstat: false,
            pending_property: None,
            property_stack: Vec::new(),
            error: None,
        }
    }

    fn resolve_ns(&self, prefix: &str) -> String {
        for scope in self.ns_stack.iter().rev() {
            for (p, uri) in scope.iter().rev() {
                if p == prefix {
                    return uri.clone();
                }
            }
        }
        String::new()
    }

    fn split_qname(q_name: &str) -> (&str, &str) {
        match q_name.find(':') {
            Some(i) => (&q_name[..i], &q_name[i + 1..]),
            None => ("", q_name),
        }
    }

    fn parent_frame(&self) -> Option<Frame> {
        self.stack.last().copied()
    }

    fn ensure_response_started(&mut self) {
        if !self.response_started {
            let href = self.pending_href.take().unwrap_or_default();
            self.handler.start_response(&href);
            self.response_started = true;
        }
    }

    fn flush_pending_property(&mut self) {
        if let Some((prefix, local)) = self.pending_property.take() {
            let ns = self.resolve_ns(&prefix);
            self.handler.start_property(&ns, &local);
            self.property_stack.push((ns, local));
        }
    }
}

impl<H: MultiStatusHandler> XmlHandler for MultistatusXmlAdapter<'_, H> {
    fn start_element(&mut self, q_name: &str) -> ParseResult<()> {
        if self.error.is_some() {
            return Err(ParseError::new("multistatus xml error"));
        }
        self.ns_stack.push(Vec::new());
        self.text.clear();
        let (prefix, local) = Self::split_qname(q_name);
        let parent = self.parent_frame();

        let frame = match (parent, local) {
            (_, constants::ELEM_MULTISTATUS)
                if parent.is_none() || matches!(parent, Some(Frame::Other)) =>
            {
                Frame::Multistatus
            }
            (Some(Frame::Multistatus), constants::ELEM_RESPONSE) => {
                self.pending_href = None;
                self.response_started = false;
                Frame::Response
            }
            (Some(Frame::Response), constants::ELEM_HREF) => Frame::Href,
            (Some(Frame::Response), constants::ELEM_STATUS) => {
                self.status_in_propstat = false;
                Frame::Status
            }
            (Some(Frame::Response), constants::ELEM_PROPSTAT) => {
                self.ensure_response_started();
                self.handler.start_propstat();
                Frame::Propstat
            }
            (Some(Frame::Propstat), constants::ELEM_PROP) => Frame::Prop,
            (Some(Frame::Propstat), constants::ELEM_STATUS) => {
                self.status_in_propstat = true;
                Frame::Status
            }
            (Some(Frame::Propstat), constants::ELEM_ERROR)
            | (Some(Frame::Response), constants::ELEM_ERROR) => {
                self.ensure_response_started();
                self.handler.start_error();
                Frame::Error
            }
            (Some(Frame::Propstat), constants::ELEM_RESPONSEDESCRIPTION)
            | (Some(Frame::Response), constants::ELEM_RESPONSEDESCRIPTION) => Frame::Description,
            (Some(Frame::Response), constants::ELEM_LOCATION) => Frame::Location,
            (Some(Frame::Location), constants::ELEM_HREF) => Frame::LocationHref,
            (Some(Frame::Prop), _)
            | (Some(Frame::Property), _)
            | (Some(Frame::Error), _) => {
                self.ensure_response_started();
                self.pending_property = Some((prefix.to_string(), local.to_string()));
                Frame::Property
            }
            _ => Frame::Other,
        };

        self.stack.push(frame);
        Ok(())
    }

    fn namespace(&mut self, prefix: &str, uri: &str) -> ParseResult<()> {
        if let Some(scope) = self.ns_stack.last_mut() {
            scope.push((prefix.to_string(), uri.to_string()));
        }
        Ok(())
    }

    fn end_attributes(&mut self) -> ParseResult<()> {
        self.flush_pending_property();
        Ok(())
    }

    fn characters(&mut self, text: &str, _ignorable: bool, _end: bool) -> ParseResult<()> {
        match self.parent_frame() {
            Some(Frame::Href)
            | Some(Frame::Status)
            | Some(Frame::Description)
            | Some(Frame::LocationHref) => {
                self.text.push_str(text);
            }
            Some(Frame::Property) => {
                self.handler.characters(text);
            }
            _ => {}
        }
        Ok(())
    }

    fn end_element(&mut self) -> ParseResult<()> {
        // Empty elements: end_attributes may not run before end in some paths —
        // flush any deferred property start.
        self.flush_pending_property();

        let frame = self
            .stack
            .pop()
            .ok_or_else(|| ParseError::new("unbalanced element"))?;
        let _ = self.ns_stack.pop();

        match frame {
            Frame::Href => {
                self.pending_href = Some(std::mem::take(&mut self.text).trim().to_string());
            }
            Frame::Status => {
                let status = std::mem::take(&mut self.text).trim().to_string();
                self.ensure_response_started();
                if self.status_in_propstat {
                    self.handler.propstat_status(&status);
                } else {
                    self.handler.response_status(&status);
                }
            }
            Frame::Description => {
                let t = std::mem::take(&mut self.text).trim().to_string();
                self.ensure_response_started();
                self.handler.response_description(&t);
            }
            Frame::LocationHref => {
                let href = std::mem::take(&mut self.text).trim().to_string();
                self.ensure_response_started();
                self.handler.location(&href);
            }
            Frame::Propstat => {
                self.handler.end_propstat();
            }
            Frame::Error => {
                self.handler.end_error();
            }
            Frame::Property => {
                if let Some((ns, local)) = self.property_stack.pop() {
                    self.handler.end_property(&ns, &local);
                }
            }
            Frame::Response => {
                self.ensure_response_started();
                self.handler.end_response();
                self.response_started = false;
                self.pending_href = None;
            }
            _ => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xml_out::write_live_property;

    #[derive(Default)]
    struct RecordingHandler {
        events: Vec<String>,
    }

    impl MultiStatusHandler for RecordingHandler {
        fn start_response(&mut self, href: &str) {
            self.events.push(format!("start_response:{href}"));
        }
        fn response_status(&mut self, status_line: &str) {
            self.events.push(format!("response_status:{status_line}"));
        }
        fn start_propstat(&mut self) {
            self.events.push("start_propstat".into());
        }
        fn propstat_status(&mut self, status_line: &str) {
            self.events.push(format!("propstat_status:{status_line}"));
        }
        fn start_property(&mut self, namespace_uri: &str, local_name: &str) {
            self.events
                .push(format!("start_property:{{{namespace_uri}}}{local_name}"));
        }
        fn characters(&mut self, text: &str) {
            if !text.trim().is_empty() {
                self.events.push(format!("characters:{text}"));
            }
        }
        fn end_property(&mut self, namespace_uri: &str, local_name: &str) {
            self.events
                .push(format!("end_property:{{{namespace_uri}}}{local_name}"));
        }
        fn end_propstat(&mut self) {
            self.events.push("end_propstat".into());
        }
        fn start_error(&mut self) {
            self.events.push("start_error".into());
        }
        fn end_error(&mut self) {
            self.events.push("end_error".into());
        }
        fn response_description(&mut self, text: &str) {
            self.events.push(format!("description:{text}"));
        }
        fn location(&mut self, href: &str) {
            self.events.push(format!("location:{href}"));
        }
        fn end_response(&mut self) {
            self.events.push("end_response".into());
        }
    }

    #[test]
    fn write_multi_propstat_and_status_only() {
        let mut ms = MultistatusWriter::new();
        ms.response("/file", |r| {
            r.propstat("HTTP/1.1 200 OK", |w| {
                write_live_property(w, NAMESPACE, constants::PROP_DISPLAYNAME, "file")
            })?;
            r.propstat("HTTP/1.1 404 Not Found", |w| {
                write_live_property(w, "http://example.com/", "tag", "")
            })?;
            Ok(())
        })
        .unwrap();
        ms.response("/gone", |r| {
            r.status("HTTP/1.1 404 Not Found")?;
            r.description("missing")?;
            Ok(())
        })
        .unwrap();
        let s = String::from_utf8(ms.finish()).unwrap();
        assert!(s.contains("propstat"));
        assert!(s.contains("displayname"));
        assert!(s.contains("404 Not Found"));
        assert!(s.contains("responsedescription"));
        assert_eq!(s.matches("<D:propstat>").count() + s.matches("<propstat").count(), 2);
    }

    #[test]
    fn parse_roundtrip_events() {
        let mut ms = MultistatusWriter::new();
        ms.response("/a", |r| {
            r.propstat("HTTP/1.1 200 OK", |w| {
                write_live_property(w, NAMESPACE, constants::PROP_DISPLAYNAME, "A")
            })
        })
        .unwrap();
        let xml = ms.finish();

        let h = parse_multistatus(&xml, RecordingHandler::default()).unwrap();
        assert!(h.events.iter().any(|e| e == "start_response:/a"));
        assert!(h.events.iter().any(|e| e == "start_propstat"));
        assert!(h
            .events
            .iter()
            .any(|e| e == "propstat_status:HTTP/1.1 200 OK"));
        assert!(h.events.iter().any(|e| e.contains("displayname")));
        assert!(h.events.iter().any(|e| e == "characters:A"));
        assert!(h.events.iter().any(|e| e == "end_propstat"));
        assert!(h.events.iter().any(|e| e == "end_response"));
    }

    #[test]
    fn parse_split_feeds() {
        let mut ms = MultistatusWriter::new();
        ms.response("/x", |r| r.status("HTTP/1.1 403 Forbidden"))
            .unwrap();
        let xml = ms.finish();
        let mid = xml.len() / 2;

        let mut p = MultiStatusParser::new(RecordingHandler::default());
        p.feed(&xml[..mid]).unwrap();
        p.feed(&xml[mid..]).unwrap();
        let h = p.finish().unwrap();
        assert!(h.events.iter().any(|e| e == "start_response:/x"));
        assert!(h
            .events
            .iter()
            .any(|e| e == "response_status:HTTP/1.1 403 Forbidden"));
        assert!(h.events.iter().any(|e| e == "end_response"));
    }
}
