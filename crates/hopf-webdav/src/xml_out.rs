// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Lock-discovery and property XML helpers via [`tractrix::XmlWriter`].

use std::io;

use loopbuf::{LoopBuf, WriteError, WriteResult};
use tractrix::{IndentConfig, XmlWriter};

use crate::constants::{self, NAMESPACE, PREFIX};
use crate::dead_props::DeadProperty;
use crate::lock::{LockScope, WebDavLock};

/// What the ring [`PropXmlWriter`] writes through holds: one write's worth
/// before it is moved to the output.
const RING_BYTES: usize = 8192;

/// An [`XmlWriter`] with the ring it writes into and the `Vec` the document
/// collects in: each write goes through the ring, and what is in it moves to
/// the `Vec` whenever it is full, so a document of any size is written
/// whole.
pub struct PropXmlWriter {
    writer: XmlWriter,
    ring: LoopBuf,
    out: Vec<u8>,
}

impl PropXmlWriter {
    pub fn new_vec() -> Self {
        Self::around(XmlWriter::new())
    }

    pub fn with_indent(indent: IndentConfig) -> Self {
        Self::around(XmlWriter::with_indent(indent))
    }

    fn around(writer: XmlWriter) -> Self {
        Self {
            writer,
            ring: LoopBuf::with_capacity(RING_BYTES),
            out: Vec::new(),
        }
    }

    /// Moves what is in the ring to the output.
    fn drain(&mut self) {
        let (a, b) = self.ring.readable_spans();
        self.out.extend_from_slice(a);
        self.out.extend_from_slice(b);
        self.ring.advance(self.ring.len());
    }

    /// Runs `write`, once more after draining the ring if it had no room.
    /// The writer's calls are atomic, so a run that failed left nothing.
    fn run<T>(
        &mut self,
        mut write: impl FnMut(&mut XmlWriter, &mut LoopBuf) -> WriteResult<T>,
    ) -> io::Result<T> {
        match write(&mut self.writer, &mut self.ring) {
            Err(e) if e.is_would_block() && !self.ring.is_empty() => {
                self.drain();
                write(&mut self.writer, &mut self.ring).map_err(WriteError::into_io_error)
            }
            result => result.map_err(WriteError::into_io_error),
        }
    }

    /// Writes all of `text` with `write`, which takes as much as fits.
    fn run_text(
        &mut self,
        text: &str,
        write: impl Fn(&mut XmlWriter, &mut LoopBuf, &str) -> WriteResult<usize>,
    ) -> io::Result<()> {
        let mut rest = text;
        while !rest.is_empty() {
            let taken = self.run(|w, ring| write(w, ring, rest))?;
            rest = &rest[taken..];
            if !rest.is_empty() {
                self.drain();
            }
        }
        Ok(())
    }

    pub fn write_start_element(&mut self, local_name: &str) -> io::Result<()> {
        self.run(|w, ring| w.write_start_element(ring, local_name))
    }

    pub fn write_start_element_prefixed(
        &mut self,
        prefix: &str,
        local_name: &str,
        namespace_uri: &str,
    ) -> io::Result<()> {
        self.run(|w, ring| w.write_start_element_prefixed(ring, prefix, local_name, namespace_uri))
    }

    pub fn write_end_element(&mut self) -> io::Result<()> {
        self.run(|w, ring| w.write_end_element(ring))
    }

    pub fn write_attribute(&mut self, local_name: &str, value: &str) -> io::Result<()> {
        self.run(|w, ring| w.write_attribute(ring, local_name, value))
    }

    pub fn write_namespace(&mut self, prefix: &str, namespace_uri: &str) -> io::Result<()> {
        self.run(|w, ring| w.write_namespace(ring, prefix, namespace_uri))
    }

    pub fn write_default_namespace(&mut self, namespace_uri: &str) -> io::Result<()> {
        self.run(|w, ring| w.write_default_namespace(ring, namespace_uri))
    }

    pub fn write_processing_instruction_data(
        &mut self,
        target: &str,
        data: Option<&str>,
    ) -> io::Result<()> {
        self.run(|w, ring| w.write_processing_instruction_data(ring, target, data))
    }

    pub fn write_characters(&mut self, text: &str) -> io::Result<()> {
        self.run_text(text, |w, ring, text| w.write_characters(ring, text))
    }

    pub fn write_raw(&mut self, text: &str) -> io::Result<()> {
        self.run_text(text, |w, ring, text| w.write_raw(ring, text))
    }

    /// Everything written so far is in the output: there is nothing else to
    /// flush.
    pub fn flush(&mut self) -> io::Result<()> {
        self.drain();
        Ok(())
    }

    /// Takes the output so far, leaving the document open to go on.
    pub fn take_output(&mut self) -> Vec<u8> {
        self.drain();
        std::mem::take(&mut self.out)
    }

    pub fn into_inner(mut self) -> Vec<u8> {
        self.drain();
        self.out
    }
}

pub(crate) type DavWriter = PropXmlWriter;

fn dav_writer() -> DavWriter {
    PropXmlWriter::new_vec()
}

fn finish(mut w: DavWriter) -> Vec<u8> {
    let _ = w.flush();
    w.into_inner()
}

pub(crate) fn dav_start(w: &mut DavWriter, local: &str) -> io::Result<()> {
    w.write_start_element_prefixed(PREFIX, local, NAMESPACE)
}

pub(crate) fn dav_end(w: &mut DavWriter) -> io::Result<()> {
    w.write_end_element()
}

pub(crate) fn dav_empty(w: &mut DavWriter, local: &str) -> io::Result<()> {
    dav_start(w, local)?;
    dav_end(w)
}

pub(crate) fn dav_element_text(w: &mut DavWriter, local: &str, text: &str) -> io::Result<()> {
    dav_start(w, local)?;
    w.write_characters(text)?;
    dav_end(w)
}

/// Write an opening `<D:prop>` into `w`.
pub fn write_prop_start(w: &mut DavWriter) -> io::Result<()> {
    dav_start(w, constants::ELEM_PROP)
}

/// Write a closing `</D:prop>`.
pub fn write_prop_end(w: &mut DavWriter) -> io::Result<()> {
    dav_end(w)
}

pub fn write_dead_property(w: &mut DavWriter, prop: &DeadProperty) -> io::Result<()> {
    if prop.is_xml {
        // Stored value is already XML markup.
        w.write_raw(&prop.value)
    } else if prop.namespace_uri.is_empty() || prop.namespace_uri == NAMESPACE {
        dav_element_text(w, &prop.local_name, &prop.value)
    } else {
        w.write_start_element(&prop.local_name)?;
        w.write_default_namespace(&prop.namespace_uri)?;
        w.write_characters(&prop.value)?;
        w.write_end_element()
    }
}

pub fn write_supported_lock(w: &mut DavWriter) -> io::Result<()> {
    dav_start(w, constants::ELEM_SUPPORTEDLOCK)?;
    for scope in [constants::ELEM_EXCLUSIVE, constants::ELEM_SHARED] {
        dav_start(w, constants::ELEM_LOCKENTRY)?;
        dav_start(w, constants::ELEM_LOCKSCOPE)?;
        dav_empty(w, scope)?;
        dav_end(w)?;
        dav_start(w, constants::ELEM_LOCKTYPE)?;
        dav_empty(w, constants::ELEM_WRITE)?;
        dav_end(w)?;
        dav_end(w)?;
    }
    dav_end(w)
}

pub fn write_lock_discovery(w: &mut DavWriter, locks: &[WebDavLock], href: &str) -> io::Result<()> {
    dav_start(w, constants::ELEM_LOCKDISCOVERY)?;
    for lock in locks {
        write_active_lock_into(w, lock, href)?;
    }
    dav_end(w)
}

pub fn write_active_lock(lock: &WebDavLock, lock_root_href: &str) -> Vec<u8> {
    let mut w = dav_writer();
    write_active_lock_into(&mut w, lock, lock_root_href).expect("XmlWriter");
    finish(w)
}

fn write_active_lock_into(w: &mut DavWriter, lock: &WebDavLock, lock_root_href: &str) -> io::Result<()> {
    dav_start(w, constants::ELEM_ACTIVELOCK)?;
    // Declared on the root when this is a standalone LOCK body; suppressed when
    // nested under a document that already bound `D` → `DAV:`.
    w.write_namespace(PREFIX, NAMESPACE)?;
    dav_start(w, constants::ELEM_LOCKTYPE)?;
    dav_empty(w, constants::ELEM_WRITE)?;
    dav_end(w)?;
    dav_start(w, constants::ELEM_LOCKSCOPE)?;
    dav_empty(
        w,
        match lock.scope() {
            LockScope::Exclusive => constants::ELEM_EXCLUSIVE,
            LockScope::Shared => constants::ELEM_SHARED,
        },
    )?;
    dav_end(w)?;
    dav_element_text(w, constants::ELEM_DEPTH, &depth_text(lock.depth()))?;
    if !lock.owner().is_empty() {
        dav_element_text(w, constants::ELEM_OWNER, lock.owner())?;
    }
    dav_element_text(w, constants::ELEM_TIMEOUT, &lock.timeout_header_value())?;
    dav_start(w, constants::ELEM_LOCKTOKEN)?;
    dav_element_text(w, constants::ELEM_HREF, lock.token())?;
    dav_end(w)?;
    dav_start(w, constants::ELEM_LOCKROOT)?;
    dav_element_text(w, constants::ELEM_HREF, lock_root_href)?;
    dav_end(w)?;
    dav_end(w)
}

fn depth_text(depth: i32) -> String {
    if depth == constants::DEPTH_INFINITY {
        "infinity".to_string()
    } else {
        depth.to_string()
    }
}

pub fn write_collection_resourcetype(w: &mut DavWriter) -> io::Result<()> {
    dav_start(w, constants::PROP_RESOURCETYPE)?;
    dav_empty(w, constants::ELEM_COLLECTION)?;
    dav_end(w)
}

pub fn write_empty_resourcetype(w: &mut DavWriter) -> io::Result<()> {
    dav_empty(w, constants::PROP_RESOURCETYPE)
}

pub fn write_live_property(w: &mut DavWriter, ns: &str, local: &str, value: &str) -> io::Result<()> {
    if ns == NAMESPACE || ns.is_empty() {
        dav_element_text(w, local, value)
    } else {
        w.write_start_element(local)?;
        w.write_default_namespace(ns)?;
        w.write_characters(value)?;
        w.write_end_element()
    }
}

pub fn href_for_path(request_path: &str) -> String {
    if request_path.is_empty() || !request_path.starts_with('/') {
        format!("/{request_path}")
    } else {
        request_path.to_string()
    }
}

pub fn ensure_trailing_slash_for_collection(href: &str, is_dir: bool) -> String {
    if is_dir && !href.ends_with('/') {
        format!("{href}/")
    } else {
        href.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lock::{LockScope, LockType, WebDavLock};
    use std::path::PathBuf;

    #[test]
    fn activelock_contains_token() {
        let lock = WebDavLock::new(
            PathBuf::from("/x"),
            LockScope::Exclusive,
            LockType::Write,
            0,
            "owner".to_string(),
            3600,
        );
        let xml = String::from_utf8(write_active_lock(&lock, "/x")).unwrap();
        assert!(xml.contains("opaquelocktoken:"));
        assert!(xml.contains("owner"));
        assert!(xml.contains("xmlns:D=\"DAV:\"") || xml.contains("xmlns:D='DAV:'"));
    }

    #[test]
    fn text_and_raw_larger_than_the_ring_are_written_whole() {
        let big = "a&b".repeat(RING_BYTES);
        let mut w = PropXmlWriter::new_vec();
        w.write_start_element("t").unwrap();
        w.write_characters(&big).unwrap();
        w.write_end_element().unwrap();
        let xml = String::from_utf8(w.into_inner()).unwrap();
        assert_eq!(xml, format!("<t>{}</t>", "a&amp;b".repeat(RING_BYTES)));

        let markup = "<x/>".repeat(RING_BYTES);
        let mut w = PropXmlWriter::new_vec();
        w.write_raw(&markup).unwrap();
        assert_eq!(String::from_utf8(w.into_inner()).unwrap(), markup);
    }
}
