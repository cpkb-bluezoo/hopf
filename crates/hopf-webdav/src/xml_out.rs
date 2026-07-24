// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Lock-discovery and property XML helpers via [`tractrix::XmlWriter`].

use std::io;

use tractrix::XmlWriter;

use crate::constants::{self, NAMESPACE, PREFIX};
use crate::dead_props::DeadProperty;
use crate::lock::{LockScope, WebDavLock};

pub(crate) type DavWriter = XmlWriter<Vec<u8>>;

fn dav_writer() -> DavWriter {
    XmlWriter::new_vec()
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

fn dav_empty(w: &mut DavWriter, local: &str) -> io::Result<()> {
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

/// Re-export for callers that build prop trees.
pub use tractrix::XmlWriter as PropXmlWriter;

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
}
