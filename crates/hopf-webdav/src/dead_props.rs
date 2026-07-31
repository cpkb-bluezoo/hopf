// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Dead property storage (RFC 4918 §4): xattr, sidecar, auto, none.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// Sidecar file prefix (Gumdrop-compatible).
pub const SIDECAR_PREFIX: &str = ".webdav_";

/// Sidecar XML namespace.
pub const PROPS_NAMESPACE: &str = "urn:gumdrop:webdav-props";

#[cfg(all(unix, feature = "xattr"))]
const XATTR_PREFIX: &str = "user.webdav.";
const MAX_SIDECAR_SIZE: u64 = 1024 * 1024;

/// Dead property storage mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum DeadPropMode {
    #[default]
    Auto,
    Xattr,
    Sidecar,
    None,
}

/// A WebDAV dead (custom) property.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeadProperty {
    pub namespace_uri: String,
    pub local_name: String,
    pub value: String,
    pub is_xml: bool,
}

impl DeadProperty {
    pub fn key(&self) -> String {
        make_key(&self.namespace_uri, &self.local_name)
    }
}

pub fn make_key(ns: &str, name: &str) -> String {
    if ns.is_empty() {
        name.to_string()
    } else {
        format!("{{{ns}}}{name}")
    }
}

/// Blocking dead property store — invoke only from storage threads.
#[derive(Debug, Clone)]
pub struct DeadPropertyStore {
    mode: DeadPropMode,
    xattr_supported: Option<bool>,
}

impl Default for DeadPropertyStore {
    fn default() -> Self {
        Self {
            mode: DeadPropMode::Auto,
            xattr_supported: None,
        }
    }
}

impl DeadPropertyStore {
    pub fn new(mode: DeadPropMode) -> Self {
        Self {
            mode,
            xattr_supported: None,
        }
    }

    pub fn mode(&self) -> DeadPropMode {
        self.mode
    }

    pub fn get_properties(
        &mut self,
        resource: &Path,
        is_directory: Option<bool>,
    ) -> io::Result<HashMap<String, DeadProperty>> {
        if self.mode == DeadPropMode::None {
            return Ok(HashMap::new());
        }
        let is_dir = match is_directory {
            Some(d) => d,
            None => resource.is_dir(),
        };

        let mut merged = HashMap::new();
        if self.use_xattr(resource) {
            merged = self.load_xattr_properties(resource)?;
        }
        if self.use_sidecar() {
            let sidecar = sidecar_path(resource, is_dir);
            if sidecar.is_file() {
                let side = self.read_sidecar_file(&sidecar)?;
                for (k, v) in side {
                    merged.entry(k).or_insert(v);
                }
            }
        }
        Ok(merged)
    }

    pub fn set_property(
        &mut self,
        resource: &Path,
        ns: &str,
        name: &str,
        value: &str,
        is_xml: bool,
    ) -> io::Result<()> {
        if self.mode == DeadPropMode::None {
            return Ok(());
        }
        if self.use_xattr(resource) {
            match self.write_xattr_property(resource, ns, name, value, is_xml) {
                Ok(()) => return Ok(()),
                Err(e) if self.mode == DeadPropMode::Auto => {
                    let _ = e;
                }
                Err(e) => return Err(e),
            }
        }
        if self.use_sidecar() {
            let is_dir = resource.is_dir();
            let mut props = self.get_properties(resource, Some(is_dir))?;
            props.insert(
                make_key(ns, name),
                DeadProperty {
                    namespace_uri: ns.to_string(),
                    local_name: name.to_string(),
                    value: value.to_string(),
                    is_xml,
                },
            );
            self.write_sidecar(resource, is_dir, &props)?;
        }
        Ok(())
    }

    pub fn remove_property(&mut self, resource: &Path, ns: &str, name: &str) -> io::Result<()> {
        if self.mode == DeadPropMode::None {
            return Ok(());
        }
        if self.use_xattr(resource) {
            let _ = self.remove_xattr_property(resource, ns, name);
        }
        if self.use_sidecar() {
            let is_dir = resource.is_dir();
            let mut props = self.get_properties(resource, Some(is_dir))?;
            props.remove(&make_key(ns, name));
            if props.is_empty() {
                let side = sidecar_path(resource, is_dir);
                let _ = fs::remove_file(side);
            } else {
                self.write_sidecar(resource, is_dir, &props)?;
            }
        }
        Ok(())
    }

    pub fn copy_properties(&mut self, source: &Path, target: &Path) -> io::Result<()> {
        if self.mode == DeadPropMode::None {
            return Ok(());
        }
        let src_dir = source.is_dir();
        let src_side = sidecar_path(source, src_dir);
        if src_side.is_file() {
            let tgt_dir = target.is_dir();
            let dst_side = sidecar_path(target, tgt_dir);
            if let Some(parent) = dst_side.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(&src_side, &dst_side)?;
        }
        if self.use_xattr(source) && self.use_xattr(target) {
            let props = self.load_xattr_properties(source)?;
            for prop in props.values() {
                let _ = self.write_xattr_property(
                    target,
                    &prop.namespace_uri,
                    &prop.local_name,
                    &prop.value,
                    prop.is_xml,
                );
            }
        }
        Ok(())
    }

    pub fn delete_properties(&mut self, resource: &Path) -> io::Result<()> {
        if self.mode == DeadPropMode::None {
            return Ok(());
        }
        let is_dir = resource.is_dir();
        let side = sidecar_path(resource, is_dir);
        let _ = fs::remove_file(side);
        if self.use_xattr(resource) {
            let props = self.load_xattr_properties(resource)?;
            for prop in props.values() {
                let _ = self.remove_xattr_property(resource, &prop.namespace_uri, &prop.local_name);
            }
        }
        Ok(())
    }

    fn use_sidecar(&self) -> bool {
        matches!(self.mode, DeadPropMode::Auto | DeadPropMode::Sidecar)
    }

    fn use_xattr(&mut self, resource: &Path) -> bool {
        match self.mode {
            DeadPropMode::Sidecar | DeadPropMode::None => false,
            DeadPropMode::Xattr => self.check_xattr(resource),
            DeadPropMode::Auto => self.check_xattr(resource),
        }
    }

    fn check_xattr(&mut self, resource: &Path) -> bool {
        if let Some(v) = self.xattr_supported {
            return v;
        }
        #[cfg(all(unix, feature = "xattr"))]
        {
            let ok = xattr::SUPPORTED_EXTENSIONS
                .iter()
                .any(|_| resource.exists())
                && std::panic::catch_unwind(|| xattr::list(resource)).is_ok();
            self.xattr_supported = Some(ok);
            return ok;
        }
        #[cfg(not(all(unix, feature = "xattr")))]
        {
            let _ = resource;
            self.xattr_supported = Some(false);
            false
        }
    }

    fn load_xattr_properties(&self, resource: &Path) -> io::Result<HashMap<String, DeadProperty>> {
        #[allow(unused_mut)]
        let mut props = HashMap::new();
        #[cfg(all(unix, feature = "xattr"))]
        {
            if let Ok(list) = xattr::list(resource) {
                for name in list {
                    let name = name.to_string_lossy();
                    if !name.starts_with(XATTR_PREFIX) {
                        continue;
                    }
                    if let Ok(Some(raw)) = xattr::get(resource, name.as_ref()) {
                        if let Ok(s) = String::from_utf8(raw) {
                            if let Some(prop) = decode_xattr_value(&s) {
                                props.insert(prop.key(), prop);
                            }
                        }
                    }
                }
            }
        }
        let _ = resource;
        Ok(props)
    }

    fn write_xattr_property(
        &self,
        resource: &Path,
        ns: &str,
        name: &str,
        value: &str,
        is_xml: bool,
    ) -> io::Result<()> {
        #[cfg(all(unix, feature = "xattr"))]
        {
            let attr = xattr_name(ns, name);
            let encoded = encode_xattr_value(ns, name, value, is_xml);
            xattr::set(resource, &attr, encoded.as_bytes())?;
            return Ok(());
        }
        #[cfg(not(all(unix, feature = "xattr")))]
        {
            let _ = (resource, ns, name, value, is_xml);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "xattr not available",
            ))
        }
    }

    fn remove_xattr_property(&self, resource: &Path, ns: &str, name: &str) -> io::Result<()> {
        #[cfg(all(unix, feature = "xattr"))]
        {
            let attr = xattr_name(ns, name);
            xattr::remove(resource, &attr)?;
        }
        let _ = (resource, ns, name);
        Ok(())
    }

    fn read_sidecar_file(&self, sidecar: &Path) -> io::Result<HashMap<String, DeadProperty>> {
        let meta = fs::metadata(sidecar)?;
        if meta.len() > MAX_SIDECAR_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "sidecar too large",
            ));
        }
        let data = fs::read_to_string(sidecar)?;
        parse_sidecar_xml(&data)
    }

    fn write_sidecar(
        &self,
        resource: &Path,
        is_directory: bool,
        props: &HashMap<String, DeadProperty>,
    ) -> io::Result<()> {
        let side = sidecar_path(resource, is_directory);
        if let Some(parent) = side.parent() {
            fs::create_dir_all(parent)?;
        }
        let xml = serialize_sidecar_xml(props);
        fs::write(side, xml)
    }
}

pub fn is_sidecar_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(is_sidecar_name)
        .unwrap_or(false)
}

pub fn is_sidecar_name(name: &str) -> bool {
    name.starts_with(SIDECAR_PREFIX)
}

pub fn sidecar_path(resource: &Path, is_directory: bool) -> PathBuf {
    if is_directory {
        resource.join(format!("{SIDECAR_PREFIX}."))
    } else {
        let parent = resource.parent().unwrap_or_else(|| Path::new("."));
        let file_name = resource.file_name().and_then(|n| n.to_str()).unwrap_or("");
        parent.join(format!("{SIDECAR_PREFIX}{file_name}"))
    }
}

#[cfg(feature = "xattr")]
fn xattr_name(ns: &str, name: &str) -> String {
    format!("{XATTR_PREFIX}{}.{}", namespace_hash(ns), name)
}

#[cfg(feature = "xattr")]
fn encode_xattr_value(ns: &str, name: &str, value: &str, is_xml: bool) -> String {
    format!(
        "{ns}\n{name}\n{}\n{value}",
        if is_xml { "1" } else { "0" }
    )
}

#[cfg(feature = "xattr")]
fn decode_xattr_value(raw: &str) -> Option<DeadProperty> {
    let mut parts = raw.splitn(4, '\n');
    let ns = parts.next()?.to_string();
    let name = parts.next()?.to_string();
    let xml_flag = parts.next()?;
    let value = parts.next().unwrap_or("").to_string();
    Some(DeadProperty {
        namespace_uri: ns,
        local_name: name,
        value,
        is_xml: xml_flag == "1",
    })
}

#[allow(dead_code)]
pub fn namespace_hash(ns: &str) -> String {
    if ns.is_empty() {
        return "00000000".to_string();
    }
    let digest = Sha256::digest(ns.as_bytes());
    format!("{:02x}{:02x}{:02x}{:02x}", digest[0], digest[1], digest[2], digest[3])
}

fn serialize_sidecar_xml(props: &HashMap<String, DeadProperty>) -> String {
    use tractrix::{IndentConfig, XmlWriter};

    let mut w = XmlWriter::with_indent(Vec::new(), IndentConfig::spaces2());
    w.write_processing_instruction_data("xml", Some("version=\"1.0\" encoding=\"utf-8\""))
        .expect("XmlWriter");
    w.write_start_element("properties").expect("XmlWriter");
    w.write_default_namespace(PROPS_NAMESPACE).expect("XmlWriter");
    for prop in props.values() {
        w.write_start_element("property").expect("XmlWriter");
        w.write_attribute("ns", &prop.namespace_uri).expect("XmlWriter");
        w.write_attribute("name", &prop.local_name).expect("XmlWriter");
        w.write_attribute("xml", if prop.is_xml { "1" } else { "0" })
            .expect("XmlWriter");
        if prop.is_xml {
            // Stored value is already XML markup.
            w.write_raw(&prop.value).expect("XmlWriter");
        } else {
            w.write_characters(&prop.value).expect("XmlWriter");
        }
        w.write_end_element().expect("XmlWriter");
    }
    w.write_end_element().expect("XmlWriter");
    w.flush().expect("XmlWriter");
    String::from_utf8(w.into_inner()).expect("Utf8 XmlWriter")
}

fn parse_sidecar_xml(data: &str) -> io::Result<HashMap<String, DeadProperty>> {
    #[allow(unused_mut)]
        let mut props = HashMap::new();
    let mut i = 0;
    let bytes = data.as_bytes();
    while i < bytes.len() {
        if let Some(start) = data[i..].find("<property ") {
            let abs = i + start;
            let rest = &data[abs..];
            let end_tag = rest.find("</property>").ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "bad sidecar xml")
            })?;
            let chunk = &rest[..end_tag + "</property>".len()];
            if let Some(prop) = parse_property_element(chunk) {
                props.insert(prop.key(), prop);
            }
            i = abs + end_tag + "</property>".len();
        } else {
            break;
        }
    }
    Ok(props)
}

fn parse_property_element(chunk: &str) -> Option<DeadProperty> {
    let ns = extract_attr(chunk, "ns")?;
    let name = extract_attr(chunk, "name")?;
    let xml_flag = extract_attr(chunk, "xml").unwrap_or_else(|| "0".into());
    let gt = chunk.find('>')? + 1;
    let end = chunk.rfind("</property>")?;
    let value = chunk[gt..end].to_string();
    Some(DeadProperty {
        namespace_uri: ns,
        local_name: name,
        value,
        is_xml: xml_flag == "1",
    })
}

fn extract_attr(s: &str, key: &str) -> Option<String> {
    let needle = format!("{key}=\"");
    let start = s.find(&needle)? + needle.len();
    let end = s[start..].find('"')? + start;
    Some(unescape_xml(&s[start..end]))
}

fn unescape_xml(s: &str) -> String {
    s.replace("&quot;", "\"")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn sidecar_roundtrip() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("doc.txt");
        fs::write(&file, b"data").unwrap();
        let mut store = DeadPropertyStore::new(DeadPropMode::Sidecar);
        store
            .set_property(&file, "http://ex/", "tag", "value", false)
            .unwrap();
        let props = store.get_properties(&file, Some(false)).unwrap();
        assert_eq!(props.len(), 1);
        let p = props.values().next().unwrap();
        assert_eq!(p.value, "value");
        assert!(sidecar_path(&file, false).is_file());
    }
}
