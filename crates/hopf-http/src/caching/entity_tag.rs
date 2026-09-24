// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

use std::fmt;

/// An entity-tag (RFC 9110 §8.8.3): a validator that identifies one
/// version of a representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityTag {
    weak: bool,
    opaque: String,
}

/// Bytes allowed inside the quotes (`etagc`): visible ASCII except `"`,
/// plus obs-text.
fn is_etagc(b: u8) -> bool {
    b == 0x21 || (0x23..=0x7e).contains(&b) || b >= 0x80
}

impl EntityTag {
    /// A strong tag: the representation is byte-for-byte identical whenever
    /// the tag matches. `opaque` must not contain `"` or control characters
    /// (see [`Self::parse`] for the exact rule); anything else is stripped.
    pub fn strong(opaque: impl Into<String>) -> Self {
        Self::new(false, opaque.into())
    }

    /// A weak tag: the representation is semantically equivalent whenever the
    /// tag matches.
    pub fn weak(opaque: impl Into<String>) -> Self {
        Self::new(true, opaque.into())
    }

    fn new(weak: bool, opaque: String) -> Self {
        let opaque = if opaque.bytes().all(is_etagc) {
            opaque
        } else {
            opaque.chars().filter(|c| !c.is_ascii() || is_etagc(*c as u8)).collect()
        };
        Self { weak, opaque }
    }

    /// Whether this is a weak tag.
    pub fn is_weak(&self) -> bool {
        self.weak
    }

    /// The opaque value between the quotes.
    pub fn opaque(&self) -> &str {
        &self.opaque
    }

    /// Parse one `ETag` field value (`"x"` or `W/"x"`). `None` if malformed.
    pub fn parse(value: &str) -> Option<Self> {
        let s = value.trim();
        let (weak, rest) = match s.strip_prefix("W/") {
            Some(r) => (true, r),
            None => (false, s),
        };
        let inner = rest.strip_prefix('"')?.strip_suffix('"')?;
        inner.bytes().all(is_etagc).then(|| Self {
            weak,
            opaque: inner.to_string(),
        })
    }

    /// Strong comparison (RFC 9110 §8.8.3.2): both tags strong and equal.
    /// Used by `If-Match`.
    pub fn strong_eq(&self, other: &Self) -> bool {
        !self.weak && !other.weak && self.opaque == other.opaque
    }

    /// Weak comparison: the opaque values are equal, weakness ignored. Used
    /// by `If-None-Match`.
    pub fn weak_eq(&self, other: &Self) -> bool {
        self.opaque == other.opaque
    }
}

impl fmt::Display for EntityTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.weak {
            f.write_str("W/")?;
        }
        write!(f, "\"{}\"", self.opaque)
    }
}

/// The value of an `If-Match` / `If-None-Match` field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntityTagList {
    /// `*`: matches any current representation.
    Any,
    /// A list of entity-tags.
    Tags(Vec<EntityTag>),
}

/// Parse an `If-Match` / `If-None-Match` value. `None` if malformed (a
/// recipient then ignores the field).
///
/// Entity-tags may contain commas, so the list is scanned quote-aware
/// rather than split on `,`.
pub fn parse_entity_tag_list(value: &str) -> Option<EntityTagList> {
    let s = value.trim();
    if s == "*" {
        return Some(EntityTagList::Any);
    }
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut tags = Vec::new();
    loop {
        while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t' || bytes[i] == b',') {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let start = i;
        if bytes[i..].starts_with(b"W/") {
            i += 2;
        }
        if bytes.get(i) != Some(&b'"') {
            return None;
        }
        i += 1;
        while i < bytes.len() && bytes[i] != b'"' {
            i += 1;
        }
        if i >= bytes.len() {
            return None;
        }
        i += 1;
        tags.push(EntityTag::parse(&s[start..i])?);
        // What follows a tag must be OWS then `,` or the end.
        while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
            i += 1;
        }
        if i < bytes.len() && bytes[i] != b',' {
            return None;
        }
    }
    if tags.is_empty() {
        None
    } else {
        Some(EntityTagList::Tags(tags))
    }
}
