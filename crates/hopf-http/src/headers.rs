// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Ordered HTTP header map with case-insensitive lookup.

use std::fmt;

/// A single header field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Field name (may include leading `:` for pseudo-headers).
    pub name: String,
    /// Field value (OWS-trimmed).
    pub value: String,
}

impl Header {
    /// Construct a header.
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

/// Ordered list of headers; lookups are case-insensitive on the name.
#[derive(Debug, Clone, Default)]
pub struct Headers {
    fields: Vec<Header>,
}

impl Headers {
    /// Empty header set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of fields.
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// Whether empty.
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// Append a field (preserves order; duplicates allowed).
    pub fn add(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.fields.push(Header::new(name, value));
    }

    /// Insert a pseudo-header field, keeping all pseudo-headers before any
    /// regular fields (RFC 9113 §8.3.1 / RFC 9114 §4.3.1 require
    /// pseudo-header fields to precede regular ones). Use this instead of
    /// [`add`](Self::add) when appending a pseudo-header (name starting
    /// with `:`) to a set that may already contain regular fields — e.g.
    /// auto-filling `:scheme`/`:authority` after the caller already set a
    /// regular `host` header.
    pub fn add_pseudo(&mut self, name: impl Into<String>, value: impl Into<String>) {
        let pos = self
            .fields
            .iter()
            .position(|h| !h.name.starts_with(':'))
            .unwrap_or(self.fields.len());
        self.fields.insert(pos, Header::new(name, value));
    }

    /// Set `:status` pseudo-header (response).
    pub fn status(&mut self, code: u16) {
        self.set(":status", code.to_string());
    }

    /// Replace the first field with this name, or append.
    pub fn set(&mut self, name: impl Into<String>, value: impl Into<String>) {
        let name = name.into();
        let value = value.into();
        if let Some(h) = self
            .fields
            .iter_mut()
            .find(|h| h.name.eq_ignore_ascii_case(&name))
        {
            h.value = value;
        } else {
            self.fields.push(Header::new(name, value));
        }
    }

    /// First value for `name`, case-insensitive.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
    }

    /// Whether a field name is present.
    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    /// Remove all fields with this name.
    pub fn remove(&mut self, name: &str) {
        self.fields.retain(|h| !h.name.eq_ignore_ascii_case(name));
    }

    /// Iterate fields in order.
    pub fn iter(&self) -> impl Iterator<Item = &Header> {
        self.fields.iter()
    }

    /// Pseudo `:method`.
    pub fn method(&self) -> Option<&str> {
        self.get(":method")
    }

    /// Pseudo `:path`.
    pub fn path(&self) -> Option<&str> {
        self.get(":path")
    }

    /// Pseudo `:scheme`.
    pub fn scheme(&self) -> Option<&str> {
        self.get(":scheme")
    }

    /// Pseudo `:authority` or `Host`.
    pub fn authority(&self) -> Option<&str> {
        self.get(":authority").or_else(|| self.get("host"))
    }

    /// Status code from `:status`, default 200.
    pub fn status_code(&self) -> u16 {
        self.get(":status")
            .and_then(|s| s.parse().ok())
            .unwrap_or(200)
    }
}

impl fmt::Display for Headers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for h in &self.fields {
            writeln!(f, "{}: {}", h.name, h.value)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_get_case_insensitive_and_pseudos() {
        let mut h = Headers::new();
        assert!(h.is_empty());
        h.set("Content-Type", "text/plain");
        assert_eq!(h.get("content-type"), Some("text/plain"));
        assert!(h.contains("CONTENT-TYPE"));
        h.set("content-type", "text/html");
        assert_eq!(h.len(), 1);
        h.add("X-A", "1");
        h.add("X-A", "2");
        assert_eq!(h.get("x-a"), Some("1"));
        h.remove("x-a");
        assert!(!h.contains("x-a"));

        h.set(":method", "GET");
        h.set(":path", "/x");
        h.set(":scheme", "https");
        h.set("Host", "ex.test");
        h.status(201);
        assert_eq!(h.method(), Some("GET"));
        assert_eq!(h.path(), Some("/x"));
        assert_eq!(h.scheme(), Some("https"));
        assert_eq!(h.authority(), Some("ex.test"));
        assert_eq!(h.status_code(), 201);
        assert!(h.to_string().contains("201"));
    }

    #[test]
    fn add_pseudo_stays_before_regular_fields() {
        let mut h = Headers::new();
        h.set(":method", "GET");
        h.set(":path", "/");
        h.set("host", "example.test"); // a regular field added first
        h.add_pseudo(":scheme", "https");
        h.add_pseudo(":authority", "example.test");

        let names: Vec<&str> = h.iter().map(|hd| hd.name.as_str()).collect();
        assert_eq!(names, [":method", ":path", ":scheme", ":authority", "host"]);
    }

    #[test]
    fn add_pseudo_on_all_pseudo_set_appends_at_end() {
        let mut h = Headers::new();
        h.set(":method", "GET");
        h.add_pseudo(":path", "/");
        let names: Vec<&str> = h.iter().map(|hd| hd.name.as_str()).collect();
        assert_eq!(names, [":method", ":path"]);
    }
}

