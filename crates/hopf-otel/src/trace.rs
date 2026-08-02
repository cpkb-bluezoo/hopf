// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! W3C Trace Context + spans (Gumdrop `Trace` / `Span` / `SpanContext` parity).

use std::sync::{Arc, Mutex};

use crate::batch::ExportHandle;
use crate::crypto_ids::{generate_span_id, generate_trace_id, to_hex, TRACE_ID_LEN, SPAN_ID_LEN};

/// Span kind (OTLP).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum SpanKind {
    /// Unspecified.
    Unspecified = 0,
    /// Internal.
    Internal = 1,
    /// Server.
    Server = 2,
    /// Client.
    Client = 3,
    /// Producer.
    Producer = 4,
    /// Consumer.
    Consumer = 5,
}

/// Span status code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum SpanStatusCode {
    /// Unset.
    Unset = 0,
    /// Ok.
    Ok = 1,
    /// Error.
    Error = 2,
}

/// Immutable span identity for propagation.
#[derive(Debug, Clone)]
pub struct SpanContext {
    /// 16-byte trace id.
    pub trace_id: [u8; TRACE_ID_LEN],
    /// 8-byte span id.
    pub span_id: [u8; SPAN_ID_LEN],
    /// Trace flags (`0x01` = sampled).
    pub trace_flags: u8,
}

impl SpanContext {
    /// New sampled context with fresh ids.
    pub fn new_sampled() -> Self {
        Self {
            trace_id: generate_trace_id(),
            span_id: generate_span_id(),
            trace_flags: 0x01,
        }
    }

    /// Parse W3C `traceparent` (`version-traceid-spanid-flags`). Invalid → `None`.
    pub fn from_traceparent(header: &str) -> Option<Self> {
        let parts: Vec<&str> = header.trim().split('-').collect();
        if parts.len() != 4 || parts[0] != "00" {
            return None;
        }
        let trace_id = parse_hex16(parts[1])?;
        let span_id = parse_hex8(parts[2])?;
        let flags = u8::from_str_radix(parts[3], 16).ok()?;
        if trace_id.iter().all(|&b| b == 0) || span_id.iter().all(|&b| b == 0) {
            return None;
        }
        Some(Self {
            trace_id,
            span_id,
            trace_flags: flags,
        })
    }

    /// Format as W3C `traceparent`.
    pub fn to_traceparent(&self) -> String {
        format!(
            "00-{}-{}-{:02x}",
            to_hex(&self.trace_id),
            to_hex(&self.span_id),
            self.trace_flags
        )
    }

    /// Whether sampled.
    pub fn is_sampled(&self) -> bool {
        self.trace_flags & 0x01 != 0
    }
}

fn parse_hex16(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 {
        return None;
    }
    let v = from_hex(s)?;
    let mut out = [0u8; 16];
    out.copy_from_slice(&v);
    Some(out)
}

fn parse_hex8(s: &str) -> Option<[u8; 8]> {
    if s.len() != 16 {
        return None;
    }
    let v = from_hex(s)?;
    let mut out = [0u8; 8];
    out.copy_from_slice(&v);
    Some(out)
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let hi = hex_nibble(b[i])?;
        let lo = hex_nibble(b[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Ended span ready for export.
#[derive(Debug, Clone)]
pub struct FinishedSpan {
    /// Context of this span.
    pub context: SpanContext,
    /// Parent span id (remote or local), if any.
    pub parent_span_id: Option<[u8; SPAN_ID_LEN]>,
    /// Name.
    pub name: String,
    /// Kind.
    pub kind: SpanKind,
    /// Start unix nanos.
    pub start_time_unix_nano: u64,
    /// End unix nanos.
    pub end_time_unix_nano: u64,
    /// Attributes.
    pub attributes: Vec<(String, String)>,
    /// Status.
    pub status_code: SpanStatusCode,
    /// Status message.
    pub status_message: String,
}

/// Active span handle.
pub struct Span {
    trace: Arc<Mutex<TraceInner>>,
    index: usize,
}

impl Span {
    /// Span context (for `traceparent`).
    pub fn context(&self) -> SpanContext {
        let g = self.trace.lock().unwrap();
        g.spans[self.index].context.clone()
    }

    /// Add string attribute.
    pub fn set_attribute(&self, key: impl Into<String>, value: impl Into<String>) {
        let mut g = self.trace.lock().unwrap();
        if let Some(s) = g.spans.get_mut(self.index) {
            if !s.ended {
                s.attributes.push((key.into(), value.into()));
            }
        }
    }

    /// Mark OK.
    pub fn set_status_ok(&self) {
        let mut g = self.trace.lock().unwrap();
        if let Some(s) = g.spans.get_mut(self.index) {
            s.status_code = SpanStatusCode::Ok;
            s.status_message.clear();
        }
    }

    /// Mark error.
    pub fn set_status_error(&self, message: impl Into<String>) {
        let mut g = self.trace.lock().unwrap();
        if let Some(s) = g.spans.get_mut(self.index) {
            s.status_code = SpanStatusCode::Error;
            s.status_message = message.into();
        }
    }

    /// End this span.
    pub fn end(self) {
        let mut g = self.trace.lock().unwrap();
        if let Some(s) = g.spans.get_mut(self.index) {
            if !s.ended {
                s.ended = true;
                s.end_time_unix_nano = now_nanos();
            }
        }
        if g.current_index == Some(self.index) {
            g.current_index = g.spans[self.index].parent_index;
        }
    }
}

struct LiveSpan {
    context: SpanContext,
    parent_span_id: Option<[u8; SPAN_ID_LEN]>,
    parent_index: Option<usize>,
    name: String,
    kind: SpanKind,
    start_time_unix_nano: u64,
    end_time_unix_nano: u64,
    attributes: Vec<(String, String)>,
    status_code: SpanStatusCode,
    status_message: String,
    ended: bool,
}

struct TraceInner {
    sampled: bool,
    spans: Vec<LiveSpan>,
    current_index: Option<usize>,
    exporter: Option<ExportHandle>,
    exported: bool,
}

/// Distributed trace (Gumdrop `Trace`).
#[derive(Clone)]
pub struct Trace {
    inner: Arc<Mutex<TraceInner>>,
}

impl Trace {
    /// New local trace with root span.
    pub fn new(root_name: impl Into<String>, kind: SpanKind) -> Self {
        let ctx = SpanContext::new_sampled();
        Self::with_root(ctx, None, root_name.into(), kind)
    }

    /// Continue from remote `traceparent`, or new if invalid.
    pub fn from_traceparent(header: Option<&str>, root_name: impl Into<String>, kind: SpanKind) -> Self {
        if let Some(h) = header {
            if let Some(parent) = SpanContext::from_traceparent(h) {
                let mut ctx = SpanContext {
                    trace_id: parent.trace_id,
                    span_id: generate_span_id(),
                    trace_flags: parent.trace_flags,
                };
                if ctx.trace_flags == 0 {
                    ctx.trace_flags = 0x01;
                }
                return Self::with_root(ctx, Some(parent.span_id), root_name.into(), kind);
            }
        }
        Self::new(root_name, kind)
    }

    fn with_root(
        ctx: SpanContext,
        parent_span_id: Option<[u8; SPAN_ID_LEN]>,
        name: String,
        kind: SpanKind,
    ) -> Self {
        let root = LiveSpan {
            context: ctx,
            parent_span_id,
            parent_index: None,
            name,
            kind,
            start_time_unix_nano: now_nanos(),
            end_time_unix_nano: 0,
            attributes: Vec::new(),
            status_code: SpanStatusCode::Unset,
            status_message: String::new(),
            ended: false,
        };
        Self {
            inner: Arc::new(Mutex::new(TraceInner {
                sampled: root.context.is_sampled(),
                spans: vec![root],
                current_index: Some(0),
                exporter: None,
                exported: false,
            })),
        }
    }

    /// Attach exporter used by [`Self::end`].
    pub fn set_exporter(&self, exporter: ExportHandle) {
        self.inner.lock().unwrap().exporter = Some(exporter);
    }

    /// Root / current span context for propagation.
    pub fn span_context(&self) -> SpanContext {
        let g = self.inner.lock().unwrap();
        let idx = g.current_index.unwrap_or(0);
        g.spans[idx].context.clone()
    }

    /// W3C `traceparent` for the current span.
    pub fn traceparent(&self) -> String {
        self.span_context().to_traceparent()
    }

    /// Start a child under the current span.
    pub fn start_span(&self, name: impl Into<String>, kind: SpanKind) -> Span {
        let mut g = self.inner.lock().unwrap();
        let parent_idx = g.current_index.unwrap_or(0);
        let parent_ctx = g.spans[parent_idx].context.clone();
        let ctx = SpanContext {
            trace_id: parent_ctx.trace_id,
            span_id: generate_span_id(),
            trace_flags: parent_ctx.trace_flags,
        };
        let child = LiveSpan {
            context: ctx,
            parent_span_id: Some(parent_ctx.span_id),
            parent_index: Some(parent_idx),
            name: name.into(),
            kind,
            start_time_unix_nano: now_nanos(),
            end_time_unix_nano: 0,
            attributes: Vec::new(),
            status_code: SpanStatusCode::Unset,
            status_message: String::new(),
            ended: false,
        };
        let index = g.spans.len();
        g.spans.push(child);
        g.current_index = Some(index);
        Span {
            trace: Arc::clone(&self.inner),
            index,
        }
    }

    /// Root span as a handle (index 0).
    pub fn root_span(&self) -> Span {
        Span {
            trace: Arc::clone(&self.inner),
            index: 0,
        }
    }

    /// End root (and any still-open spans), enqueue for OTLP export.
    pub fn end(&self) {
        let finished = {
            let mut g = self.inner.lock().unwrap();
            if g.exported {
                return;
            }
            let now = now_nanos();
            for s in &mut g.spans {
                if !s.ended {
                    s.ended = true;
                    s.end_time_unix_nano = now;
                }
            }
            g.exported = true;
            let spans: Vec<FinishedSpan> = g
                .spans
                .iter()
                .map(|s| FinishedSpan {
                    context: s.context.clone(),
                    parent_span_id: s.parent_span_id,
                    name: s.name.clone(),
                    kind: s.kind,
                    start_time_unix_nano: s.start_time_unix_nano,
                    end_time_unix_nano: s.end_time_unix_nano,
                    attributes: s.attributes.clone(),
                    status_code: s.status_code,
                    status_message: s.status_message.clone(),
                })
                .collect();
            let exporter = g.exporter.clone();
            (spans, exporter, g.sampled)
        };
        if finished.2 {
            if let Some(exp) = finished.1 {
                exp.try_send_spans(finished.0);
            }
        }
    }
}

fn now_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traceparent_roundtrip() {
        let t = Trace::new("HTTP GET", SpanKind::Server);
        let tp = t.traceparent();
        let parsed = SpanContext::from_traceparent(&tp).unwrap();
        assert_eq!(parsed.trace_id, t.span_context().trace_id);
        let child = Trace::from_traceparent(Some(&tp), "HTTP GET", SpanKind::Server);
        assert_eq!(child.span_context().trace_id, parsed.trace_id);
        assert_ne!(child.span_context().span_id, parsed.span_id);
    }

    #[test]
    fn child_span_shares_trace_id_and_updates_traceparent() {
        let t = Trace::new("SMTP connection", SpanKind::Server);
        let parent_tp = t.traceparent();
        let parent_ctx = SpanContext::from_traceparent(&parent_tp).unwrap();
        let child = t.start_span("SMTP transaction", SpanKind::Server);
        let child_tp = t.traceparent();
        let child_ctx = SpanContext::from_traceparent(&child_tp).unwrap();
        assert_eq!(child_ctx.trace_id, parent_ctx.trace_id);
        assert_ne!(child_ctx.span_id, parent_ctx.span_id);
        child.end();
        let after = SpanContext::from_traceparent(&t.traceparent()).unwrap();
        assert_eq!(after.span_id, parent_ctx.span_id);
    }
}
