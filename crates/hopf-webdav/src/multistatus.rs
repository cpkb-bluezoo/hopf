// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Symmetric Multi-Status write/parse API (RFC 4918 §13).

use std::io;

use loopbuf::LoopBuf;
use tractrix::{FeatureSet, NamespaceFilter, ParseError, ParseResult, Parser, XmlHandler};

use crate::constants::{self, NAMESPACE, PREFIX};
use crate::xml_out::{
    dav_element_text, dav_end, dav_start, write_prop_end, write_prop_start, DavWriter,
};

/// Streaming `207 Multi-Status` document builder over one [`PropXmlWriter`](crate::xml_out::PropXmlWriter).
pub struct MultistatusWriter {
    w: DavWriter,
    open: bool,
}

impl MultistatusWriter {
    pub fn new() -> Self {
        Self {
            w: DavWriter::new_vec(),
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

    /// Drain whatever's been written so far, leaving the document open to
    /// keep writing `<response>` elements — unlike [`Self::finish`], does
    /// *not* close `<multistatus>` (issue #193: lets a caller stream the
    /// document out in pieces as each `<response>` is generated, instead of
    /// buffering the whole thing before sending anything). Call
    /// [`Self::finish`] once at the end for the closing tag.
    pub fn take_written(&mut self) -> Vec<u8> {
        self.w.take_output()
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
    /// A further `<href>` of the same response, after the first one given to
    /// [`Self::start_response`]. RFC 4918 section 14.24 allows several
    /// before a response's single status, for one status that applies to
    /// each of those resources.
    fn additional_href(&mut self, href: &str) {
        let _ = href;
    }
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

/// How much of a document the parser holds at once: only a token still
/// incomplete at the end of a `feed` stays in the ring for the next one.
const PARSE_RING: usize = 64 * 1024;

type Pipeline<H> = Parser<NamespaceFilter<MultistatusXmlAdapter<H>>>;

/// Incremental Multi-Status parser: each `feed` delivers the events of the
/// bytes it is given to the handler, holding none of the document but an
/// unfinished token; `finish` ends the document and returns the handler.
pub struct MultiStatusParser<H: MultiStatusHandler> {
    parser: Pipeline<H>,
    ring: LoopBuf,
    fed: usize,
    max_bytes: usize,
    /// The first parse error, kept so every later call reports it too.
    failed: Option<String>,
}

impl<H: MultiStatusHandler> MultiStatusParser<H> {
    pub fn new(handler: H) -> Self {
        Self::with_limit(handler, constants::MAX_WEBDAV_REQUEST_BODY)
    }

    pub fn with_limit(handler: H, max_bytes: usize) -> Self {
        let features = FeatureSet::default();
        let filter = NamespaceFilter::new(MultistatusXmlAdapter::new(handler), false);
        // Building a parser from the default feature set does not fail.
        let parser = Parser::new(filter, &features, None, None, None)
            .expect("a parser for the default feature set");
        Self {
            parser,
            ring: LoopBuf::with_capacity(PARSE_RING),
            fed: 0,
            max_bytes,
            failed: None,
        }
    }

    pub fn feed(&mut self, data: &[u8]) -> Result<(), MultiStatusParseError> {
        if let Some(e) = &self.failed {
            return Err(MultiStatusParseError::Parse(e.clone()));
        }
        if self.fed.saturating_add(data.len()) > self.max_bytes {
            return Err(MultiStatusParseError::TooLarge);
        }
        self.fed += data.len();
        let mut rest = data;
        while !rest.is_empty() {
            let before = self.ring.len();
            let taken = self.ring.extend_from_slice(rest);
            rest = &rest[taken..];
            if let Err(e) = self.parser.receive(&mut self.ring) {
                return Err(self.fail(e.to_string()));
            }
            // A full ring that parsing did not make room in holds one token
            // that will never fit.
            if taken == 0 && self.ring.len() >= before {
                return Err(self.fail("XML token too large for the Multi-Status parser".into()));
            }
        }
        Ok(())
    }

    fn fail(&mut self, message: String) -> MultiStatusParseError {
        self.failed = Some(message.clone());
        MultiStatusParseError::Parse(message)
    }

    /// End the document and return the handler.
    pub fn finish(mut self) -> Result<H, MultiStatusParseError> {
        if let Some(e) = self.failed.take() {
            return Err(MultiStatusParseError::Parse(e));
        }
        self.parser
            .close(&mut self.ring)
            .map_err(|e| MultiStatusParseError::Parse(e.to_string()))?;
        Ok(self.parser.into_handler().into_delegate().into_handler())
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

struct MultistatusXmlAdapter<H: MultiStatusHandler> {
    handler: H,
    stack: Vec<Frame>,
    ns_stack: Vec<Vec<(String, String)>>,
    text: String,
    pending_href: Option<String>,
    /// Further hrefs read before the response's status or propstat.
    extra_hrefs: Vec<String>,
    response_started: bool,
    status_in_propstat: bool,
    /// The element just opened, to be classified once its attributes (and so
    /// its `xmlns` declarations) have been read: `(prefix, local name)`.
    pending_element: Option<(String, String)>,
    property_stack: Vec<(String, String)>,
}

impl<H: MultiStatusHandler> MultistatusXmlAdapter<H> {
    fn new(handler: H) -> Self {
        Self {
            handler,
            stack: Vec::new(),
            ns_stack: Vec::new(),
            text: String::new(),
            pending_href: None,
            extra_hrefs: Vec::new(),
            response_started: false,
            status_in_propstat: false,
            pending_element: None,
            property_stack: Vec::new(),
        }
    }

    fn into_handler(self) -> H {
        self.handler
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

    fn ensure_response_started(&mut self) {
        if !self.response_started {
            let href = self.pending_href.take().unwrap_or_default();
            self.handler.start_response(&href);
            for extra in std::mem::take(&mut self.extra_hrefs) {
                self.handler.additional_href(&extra);
            }
            self.response_started = true;
        }
    }

    /// Decide what the element opened last is, now that its namespace
    /// declarations are known, and report whatever it starts.
    fn classify_pending(&mut self) {
        let Some((prefix, local)) = self.pending_element.take() else {
            return;
        };
        // The element itself is the top of the stack; its parent is below.
        let parent = self.stack.len().checked_sub(2).map(|i| self.stack[i]);
        let ns = self.resolve_ns(&prefix);
        let dav = ns == NAMESPACE;
        let frame = match (parent, local.as_str()) {
            // Anything below a property, or an error's conditions, is content
            // to report, in whatever namespace it is.
            (Some(Frame::Prop), _) | (Some(Frame::Property), _) | (Some(Frame::Error), _) => {
                self.ensure_response_started();
                self.handler.start_property(&ns, &local);
                self.property_stack.push((ns, local));
                Frame::Property
            }
            // The structure is DAV: elements only; a look-alike in another
            // namespace is somebody's extension.
            _ if !dav => Frame::Other,
            (None, constants::ELEM_MULTISTATUS) | (Some(Frame::Other), constants::ELEM_MULTISTATUS) => {
                Frame::Multistatus
            }
            (Some(Frame::Multistatus), constants::ELEM_RESPONSE) => {
                self.pending_href = None;
                self.extra_hrefs.clear();
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
            (Some(Frame::Propstat), constants::ELEM_ERROR) | (Some(Frame::Response), constants::ELEM_ERROR) => {
                self.ensure_response_started();
                self.handler.start_error();
                Frame::Error
            }
            (Some(Frame::Propstat), constants::ELEM_RESPONSEDESCRIPTION)
            | (Some(Frame::Response), constants::ELEM_RESPONSEDESCRIPTION) => Frame::Description,
            (Some(Frame::Response), constants::ELEM_LOCATION) => Frame::Location,
            (Some(Frame::Location), constants::ELEM_HREF) => Frame::LocationHref,
            _ => Frame::Other,
        };
        if let Some(top) = self.stack.last_mut() {
            *top = frame;
        }
    }
}

impl<H: MultiStatusHandler> XmlHandler for MultistatusXmlAdapter<H> {
    fn start_element(&mut self, q_name: &str) -> ParseResult<()> {
        // An element opened without a call to `end_attributes` in between
        // still has to be classified before its first child.
        self.classify_pending();
        self.ns_stack.push(Vec::new());
        self.text.clear();
        let (prefix, local) = Self::split_qname(q_name);
        self.pending_element = Some((prefix.to_string(), local.to_string()));
        self.stack.push(Frame::Other);
        Ok(())
    }

    fn namespace(&mut self, prefix: &str, uri: &str) -> ParseResult<()> {
        if let Some(scope) = self.ns_stack.last_mut() {
            scope.push((prefix.to_string(), uri.to_string()));
        }
        Ok(())
    }

    fn end_attributes(&mut self) -> ParseResult<()> {
        self.classify_pending();
        Ok(())
    }

    fn characters(&mut self, text: &str, _ignorable: bool) -> ParseResult<()> {
        self.classify_pending();
        match self.stack.last().copied() {
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
        // An empty element ends before anything else has classified it.
        self.classify_pending();

        let frame = self
            .stack
            .pop()
            .ok_or_else(|| ParseError::new("unbalanced element"))?;
        let _ = self.ns_stack.pop();

        match frame {
            Frame::Href => {
                let href = std::mem::take(&mut self.text).trim().to_string();
                if self.response_started {
                    self.handler.additional_href(&href);
                } else if self.pending_href.is_none() {
                    self.pending_href = Some(href);
                } else {
                    self.extra_hrefs.push(href);
                }
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

    // The parser ------------------------------------------------------------

    /// A recording handler the test can still read while the parser owns it.
    #[derive(Clone, Default)]
    struct Shared(std::sync::Arc<std::sync::Mutex<RecordingHandler>>);

    impl Shared {
        fn events(&self) -> Vec<String> {
            self.0.lock().unwrap().events.clone()
        }
    }

    macro_rules! forward {
        ($($name:ident($($arg:ident: $ty:ty),*)),* $(,)?) => {
            $(fn $name(&mut self, $($arg: $ty),*) { self.0.lock().unwrap().$name($($arg),*); })*
        };
    }

    impl MultiStatusHandler for Shared {
        forward!(
            start_response(href: &str),
            response_status(s: &str),
            start_propstat(),
            propstat_status(s: &str),
            start_property(ns: &str, local: &str),
            characters(t: &str),
            end_property(ns: &str, local: &str),
            end_propstat(),
            start_error(),
            end_error(),
            response_description(t: &str),
            location(h: &str),
            end_response(),
        );
    }

    fn two_responses() -> (Vec<u8>, Vec<u8>) {
        let mut ms = MultistatusWriter::new();
        ms.response("/a", |r| r.status("HTTP/1.1 200 OK")).unwrap();
        let first = ms.take_written();
        ms.response("/b", |r| r.status("HTTP/1.1 404 Not Found")).unwrap();
        let second = ms.finish();
        (first, second)
    }

    #[test]
    fn events_are_delivered_as_the_document_arrives_not_when_it_ends() {
        let (first, second) = two_responses();
        let seen = Shared::default();
        let mut p = MultiStatusParser::new(seen.clone());
        p.feed(&first).unwrap();
        let events = seen.events();
        assert!(events.contains(&"start_response:/a".to_string()), "{events:?}");
        assert!(events.contains(&"end_response".to_string()), "{events:?}");
        assert!(!events.iter().any(|e| e.contains("/b")), "the second response has not been sent");
        p.feed(&second).unwrap();
        p.finish().unwrap();
        assert!(seen.events().contains(&"start_response:/b".to_string()));
    }

    #[test]
    fn the_events_are_the_same_whatever_the_chunking() {
        let mut ms = MultistatusWriter::new();
        ms.response("/a", |r| {
            r.propstat("HTTP/1.1 200 OK", |w| {
                write_live_property(w, NAMESPACE, constants::PROP_DISPLAYNAME, "A&B")
            })
        })
        .unwrap();
        ms.response("/b", |r| {
            r.status("HTTP/1.1 424 Failed Dependency")?;
            r.description("because of /a")
        })
        .unwrap();
        let xml = ms.finish();
        let run = |chunk: usize| {
            let seen = Shared::default();
            let mut p = MultiStatusParser::new(seen.clone());
            for piece in xml.chunks(chunk) {
                p.feed(piece).unwrap();
            }
            p.finish().unwrap();
            seen.events()
        };
        let whole = run(xml.len());
        assert!(whole.iter().any(|e| e.starts_with("characters:A")), "{whole:?}");
        for chunk in [1, 2, 3, 7, 64] {
            // Text may arrive in pieces; compare what it adds up to.
            let join = |ev: Vec<String>| {
                let mut out: Vec<String> = Vec::new();
                for e in ev {
                    match (e.strip_prefix("characters:"), out.last_mut()) {
                        (Some(t), Some(last)) if last.starts_with("characters:") => last.push_str(t),
                        _ => out.push(e),
                    }
                }
                out
            };
            assert_eq!(join(run(chunk)), join(whole.clone()), "chunk {chunk}");
        }
    }

    #[test]
    fn a_very_large_document_streams_through_a_bounded_buffer() {
        let mut ms = MultistatusWriter::new();
        let mut doc = Vec::new();
        for i in 0..3000 {
            ms.response(&format!("/collection/member-{i}"), |r| {
                r.propstat("HTTP/1.1 200 OK", |w| {
                    write_live_property(w, NAMESPACE, constants::PROP_DISPLAYNAME, &format!("name {i}"))
                })
            })
            .unwrap();
            doc.extend(ms.take_written());
        }
        doc.extend(ms.finish());
        assert!(doc.len() > 300_000, "bigger than any one buffer: {}", doc.len());

        #[derive(Default)]
        struct Count(usize);
        impl MultiStatusHandler for Count {
            fn start_response(&mut self, _href: &str) {
                self.0 += 1;
            }
        }
        let mut p = MultiStatusParser::with_limit(Count::default(), 10_000_000);
        for piece in doc.chunks(1000) {
            p.feed(piece).unwrap();
        }
        assert_eq!(p.finish().unwrap().0, 3000);
    }

    #[test]
    fn the_size_limit_counts_everything_fed() {
        let mut p = MultiStatusParser::with_limit(RecordingHandler::default(), 10);
        p.feed(b"<a>").unwrap();
        p.feed(b"<b>xy").unwrap();
        p.feed(b"zz").unwrap();
        assert!(matches!(p.feed(b"z"), Err(MultiStatusParseError::TooLarge)));
        assert_eq!(MultiStatusParseError::TooLarge.to_string(), "Multi-Status body too large");
    }

    #[test]
    fn mismatched_tags_are_a_parse_error() {
        let r = parse_multistatus(b"<D:multistatus xmlns:D=\"DAV:\"><D:response></D:multistatus>", RecordingHandler::default());
        assert!(matches!(r, Err(MultiStatusParseError::Parse(_))), "{:?}", r.map(|_| ()));
    }

    #[test]
    fn a_truncated_document_is_a_parse_error() {
        let (first, _) = two_responses();
        let cut = &first[..first.len() - 10];
        let r = parse_multistatus(cut, RecordingHandler::default());
        assert!(matches!(r, Err(MultiStatusParseError::Parse(_))), "{:?}", r.map(|_| ()));
    }

    #[test]
    fn nothing_at_all_is_a_parse_error() {
        assert!(matches!(parse_multistatus(b"", RecordingHandler::default()), Err(MultiStatusParseError::Parse(_))));
        assert!(matches!(parse_multistatus(b"   ", RecordingHandler::default()), Err(MultiStatusParseError::Parse(_))));
    }

    #[test]
    fn text_that_is_not_xml_is_a_parse_error() {
        assert!(matches!(
            parse_multistatus(b"HTTP/1.1 500 oops", RecordingHandler::default()),
            Err(MultiStatusParseError::Parse(_))
        ));
    }

    // What the document means ---------------------------------------------------

    fn events_of(xml: &str) -> Vec<String> {
        parse_multistatus(xml.as_bytes(), RecordingHandler::default()).unwrap().events
    }

    const DAV: &str = "xmlns:D=\"DAV:\"";

    #[test]
    fn a_full_response_reports_each_part_in_order() {
        let xml = format!(
            "<D:multistatus {DAV}><D:response><D:href>/dir/</D:href>\
             <D:propstat><D:prop><D:displayname>Dir</D:displayname><D:getcontentlength/></D:prop>\
             <D:status>HTTP/1.1 200 OK</D:status></D:propstat>\
             <D:propstat><D:prop><D:quota/></D:prop><D:status>HTTP/1.1 404 Not Found</D:status>\
             <D:error><D:no-quota/></D:error><D:responsedescription>no quota here</D:responsedescription></D:propstat>\
             <D:responsedescription>done</D:responsedescription>\
             <D:location><D:href>/elsewhere/</D:href></D:location>\
             </D:response></D:multistatus>"
        );
        assert_eq!(
            events_of(&xml),
            [
                "start_response:/dir/",
                "start_propstat",
                "start_property:{DAV:}displayname",
                "characters:Dir",
                "end_property:{DAV:}displayname",
                "start_property:{DAV:}getcontentlength",
                "end_property:{DAV:}getcontentlength",
                "propstat_status:HTTP/1.1 200 OK",
                "end_propstat",
                "start_propstat",
                "start_property:{DAV:}quota",
                "end_property:{DAV:}quota",
                "propstat_status:HTTP/1.1 404 Not Found",
                "start_error",
                "start_property:{DAV:}no-quota",
                "end_property:{DAV:}no-quota",
                "end_error",
                "description:no quota here",
                "end_propstat",
                "description:done",
                "location:/elsewhere/",
                "end_response",
            ]
        );
    }

    #[test]
    fn a_response_level_status_and_error_are_reported_as_such() {
        let xml = format!(
            "<D:multistatus {DAV}><D:response><D:href>/x</D:href><D:status>HTTP/1.1 423 Locked</D:status>\
             <D:error><D:lock-token-submitted><D:href>/x</D:href></D:lock-token-submitted></D:error>\
             </D:response></D:multistatus>"
        );
        let ev = events_of(&xml);
        assert_eq!(ev[0], "start_response:/x");
        assert!(ev.contains(&"response_status:HTTP/1.1 423 Locked".to_string()), "{ev:?}");
        assert!(ev.contains(&"start_error".to_string()) && ev.contains(&"end_error".to_string()), "{ev:?}");
        assert!(ev.contains(&"start_property:{DAV:}lock-token-submitted".to_string()), "{ev:?}");
    }

    #[test]
    fn several_responses_come_one_after_another() {
        let xml = format!(
            "<D:multistatus {DAV}><D:response><D:href>/1</D:href><D:status>HTTP/1.1 200 OK</D:status></D:response>\
             <D:response><D:href>/2</D:href><D:status>HTTP/1.1 404 Not Found</D:status></D:response></D:multistatus>"
        );
        let starts: Vec<String> = events_of(&xml).into_iter().filter(|e| e.starts_with("start_response")).collect();
        assert_eq!(starts, ["start_response:/1", "start_response:/2"]);
    }

    #[test]
    fn a_property_value_with_nested_xml_is_reported_element_by_element() {
        let xml = format!(
            "<D:multistatus {DAV}><D:response><D:href>/f</D:href><D:propstat><D:prop>\
             <D:resourcetype><D:collection/></D:resourcetype>\
             <x:custom xmlns:x=\"urn:example\"><x:inner>deep</x:inner></x:custom>\
             </D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response></D:multistatus>"
        );
        let ev = events_of(&xml);
        for expect in [
            "start_property:{DAV:}resourcetype",
            "start_property:{DAV:}collection",
            "end_property:{DAV:}collection",
            "end_property:{DAV:}resourcetype",
            "start_property:{urn:example}custom",
            "start_property:{urn:example}inner",
            "characters:deep",
            "end_property:{urn:example}inner",
            "end_property:{urn:example}custom",
        ] {
            assert!(ev.contains(&expect.to_string()), "missing {expect} in {ev:?}");
        }
    }

    #[test]
    fn a_default_namespace_and_a_prefix_bound_on_a_property_are_both_resolved() {
        let xml = "<multistatus xmlns=\"DAV:\"><response><href>/f</href><propstat>\
                   <prop><displayname>n</displayname><z:flag xmlns:z=\"urn:z\"/></prop>\
                   <status>HTTP/1.1 200 OK</status></propstat></response></multistatus>";
        let ev = events_of(xml);
        assert!(ev.contains(&"start_property:{DAV:}displayname".to_string()), "{ev:?}");
        assert!(ev.contains(&"start_property:{urn:z}flag".to_string()), "{ev:?}");
    }

    #[test]
    fn xml_entities_and_cdata_in_a_value_are_decoded() {
        let xml = format!(
            "<D:multistatus {DAV}><D:response><D:href>/a%20b&amp;c</D:href><D:propstat><D:prop>\
             <D:displayname>x &lt; y <![CDATA[<raw>]]></D:displayname></D:prop>\
             <D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response></D:multistatus>"
        );
        let ev = events_of(&xml);
        assert_eq!(ev[0], "start_response:/a%20b&c");
        let text: String = ev.iter().filter_map(|e| e.strip_prefix("characters:")).collect();
        assert_eq!(text, "x < y <raw>");
    }

    #[test]
    fn whitespace_around_a_status_or_href_is_trimmed() {
        let xml = format!(
            "<D:multistatus {DAV}><D:response><D:href>\n  /spaced  \n</D:href>\
             <D:status>\n  HTTP/1.1 200 OK \n</D:status></D:response></D:multistatus>"
        );
        let ev = events_of(&xml);
        assert_eq!(ev[0], "start_response:/spaced");
        assert!(ev.contains(&"response_status:HTTP/1.1 200 OK".to_string()), "{ev:?}");
    }

    #[test]
    fn a_response_with_only_an_href_is_still_reported() {
        let xml = format!("<D:multistatus {DAV}><D:response><D:href>/lonely</D:href></D:response></D:multistatus>");
        assert_eq!(events_of(&xml), ["start_response:/lonely", "end_response"]);
    }

    #[test]
    fn every_href_of_a_status_only_response_is_reported() {
        // RFC 4918 section 14.24: `href*` before the status, for one status
        // that applies to several resources.
        #[derive(Default)]
        struct Hrefs(Vec<String>);
        impl MultiStatusHandler for Hrefs {
            fn start_response(&mut self, href: &str) {
                self.0.push(href.to_string());
            }
            fn additional_href(&mut self, href: &str) {
                self.0.push(href.to_string());
            }
        }
        let xml = format!(
            "<D:multistatus {DAV}><D:response><D:href>/a</D:href><D:href>/b</D:href><D:href>/c</D:href>\
             <D:status>HTTP/1.1 424 Failed Dependency</D:status></D:response></D:multistatus>"
        );
        let h = parse_multistatus(xml.as_bytes(), Hrefs::default()).unwrap();
        assert_eq!(h.0, ["/a", "/b", "/c"]);
    }

    #[test]
    fn elements_that_only_look_like_multistatus_ones_in_another_namespace_are_not_taken_for_them() {
        let xml = format!(
            "<D:multistatus {DAV} xmlns:x=\"urn:other\"><D:response><D:href>/a</D:href>\
             <x:status>HTTP/1.1 500 Not The Status</x:status>\
             <D:status>HTTP/1.1 200 OK</D:status></D:response></D:multistatus>"
        );
        let statuses: Vec<String> =
            events_of(&xml).into_iter().filter(|e| e.starts_with("response_status")).collect();
        assert_eq!(statuses, ["response_status:HTTP/1.1 200 OK"]);
    }

    #[test]
    fn the_root_may_be_wrapped_or_preceded_by_a_declaration_and_comments() {
        let xml = format!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?><!-- hello --><D:multistatus {DAV}>\
             <D:response><D:href>/a</D:href><D:status>HTTP/1.1 200 OK</D:status></D:response></D:multistatus>"
        );
        assert_eq!(events_of(&xml)[0], "start_response:/a");
    }

    #[test]
    fn a_document_in_utf16_is_read() {
        let xml = format!(
            "<?xml version=\"1.0\" encoding=\"utf-16\"?><D:multistatus {DAV}><D:response><D:href>/\u{e9}</D:href>\
             <D:status>HTTP/1.1 200 OK</D:status></D:response></D:multistatus>"
        );
        let mut bytes = vec![0xFF, 0xFE];
        for u in xml.encode_utf16() {
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        let ev = parse_multistatus(&bytes, RecordingHandler::default()).unwrap().events;
        assert_eq!(ev[0], "start_response:/\u{e9}");
    }

    #[test]
    fn what_the_writer_writes_the_parser_reads_back() {
        let mut ms = MultistatusWriter::new();
        ms.response("/dir/file", |r| {
            r.propstat("HTTP/1.1 200 OK", |w| {
                write_live_property(w, NAMESPACE, constants::PROP_DISPLAYNAME, "file")
            })?;
            r.status("HTTP/1.1 207 Multi-Status")?;
            r.error(|w| write_live_property(w, NAMESPACE, "cannot-modify-protected-property", ""))?;
            r.description("round trip")?;
            r.location("/moved")
        })
        .unwrap();
        let ev = events_of(&String::from_utf8(ms.finish()).unwrap());
        for expect in [
            "start_response:/dir/file",
            "propstat_status:HTTP/1.1 200 OK",
            "response_status:HTTP/1.1 207 Multi-Status",
            "start_error",
            "description:round trip",
            "location:/moved",
            "end_response",
        ] {
            assert!(ev.contains(&expect.to_string()), "missing {expect} in {ev:?}");
        }
    }
}
