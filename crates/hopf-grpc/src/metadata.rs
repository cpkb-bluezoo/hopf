// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! gRPC call metadata (custom headers and trailers).

use hopf_http::Headers;

use crate::proto::base64;

const BINARY_SUFFIX: &str = "-bin";

/// Ordered multimap of gRPC metadata keys and values.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GrpcMetadata {
    keys: Vec<String>,
    /// Wire form: base64 text for `-bin` keys.
    values: Vec<String>,
}

impl GrpcMetadata {
    /// Empty metadata.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether there are no entries.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Number of entries (duplicate keys count separately).
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Key at `index` (0..[`Self::len()`]).
    pub fn key_at(&self, index: usize) -> &str {
        &self.keys[index]
    }

    /// Value at `index`, as sent on the wire.
    pub fn wire_value_at(&self, index: usize) -> &str {
        &self.values[index]
    }

    /// Distinct keys in first-seen order.
    pub fn keys(&self) -> Vec<&str> {
        let mut out = Vec::new();
        for k in &self.keys {
            if !out.iter().any(|x| *x == k.as_str()) {
                out.push(k.as_str());
            }
        }
        out
    }

    /// First text value for `key`, or `None`.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.keys
            .iter()
            .zip(self.values.iter())
            .find(|(k, _)| k.as_str() == key)
            .map(|(_, v)| v.as_str())
    }

    /// All text values for `key`, in order.
    pub fn get_all(&self, key: &str) -> Vec<&str> {
        self.keys
            .iter()
            .zip(self.values.iter())
            .filter(|(k, _)| k.as_str() == key)
            .map(|(_, v)| v.as_str())
            .collect()
    }

    /// First decoded binary value for a `-bin` key.
    pub fn get_binary(&self, key: &str) -> Option<Vec<u8>> {
        self.get(key).and_then(|v| decode_wire_binary(v))
    }

    /// All decoded binary values for a `-bin` key.
    pub fn get_all_binary(&self, key: &str) -> Vec<Vec<u8>> {
        self.get_all(key)
            .into_iter()
            .filter_map(decode_wire_binary)
            .collect()
    }

    /// Add a printable-ASCII text value.
    pub fn add(&mut self, key: &str, value: &str) -> Result<(), MetadataError> {
        check_key(key)?;
        if key.ends_with(BINARY_SUFFIX) {
            return Err(MetadataError::UseAddBinary(key.to_string()));
        }
        for c in value.chars() {
            if c < '\x20' || c > '\x7e' {
                return Err(MetadataError::InvalidValue(key.to_string()));
            }
        }
        self.keys.push(key.to_string());
        self.values.push(value.to_string());
        Ok(())
    }

    /// Add a binary value (key must end in `-bin`).
    pub fn add_binary(&mut self, key: &str, value: &[u8]) -> Result<(), MetadataError> {
        check_key(key)?;
        if !key.ends_with(BINARY_SUFFIX) {
            return Err(MetadataError::BinaryKeySuffix(key.to_string()));
        }
        self.keys.push(key.to_string());
        self.values.push(base64::encode(value));
        Ok(())
    }

    /// Add one entry from the wire; invalid entries are dropped.
    pub fn add_received(&mut self, key: &str, wire_value: &str) -> bool {
        if key.ends_with(BINARY_SUFFIX) {
            match decode_wire_binary(wire_value) {
                Some(bytes) => self.add_binary(key, &bytes).is_ok(),
                None => false,
            }
        } else {
            self.add(key, wire_value).is_ok()
        }
    }

    /// Keys used by the protocol (`grpc-*`, `content-type`, `te`).
    pub fn is_reserved(key: &str) -> bool {
        key.starts_with("grpc-") || key == "content-type" || key == "te"
    }

    /// Append every entry to `headers` (wire values, including base64 for `-bin`).
    pub fn apply_to(&self, headers: &mut Headers) {
        for i in 0..self.len() {
            headers.add(self.key_at(i), self.wire_value_at(i));
        }
    }

    /// Collect custom metadata from HTTP headers (skips pseudo-headers and
    /// reserved keys). Invalid entries are dropped.
    pub fn collect_from_headers(headers: &Headers) -> Self {
        let mut md = Self::new();
        for h in headers.iter() {
            if h.name.starts_with(':') {
                continue;
            }
            let key = h.name.to_ascii_lowercase();
            if Self::is_reserved(&key) {
                continue;
            }
            md.add_received(&key, &h.value);
        }
        md
    }
}

/// Metadata validation error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataError {
    /// Empty or malformed key.
    InvalidKey(String),
    /// Reserved protocol key.
    ReservedKey(String),
    /// Text value out of range.
    InvalidValue(String),
    /// `-bin` key requires [`GrpcMetadata::add_binary`].
    UseAddBinary(String),
    /// Binary add requires `-bin` suffix.
    BinaryKeySuffix(String),
}

impl std::fmt::Display for MetadataError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidKey(k) => write!(f, "invalid metadata key: {k}"),
            Self::ReservedKey(k) => write!(f, "reserved metadata key: {k}"),
            Self::InvalidValue(k) => write!(f, "invalid metadata value for key: {k}"),
            Self::UseAddBinary(k) => write!(f, "use add_binary for key: {k}"),
            Self::BinaryKeySuffix(k) => write!(f, "binary key must end in -bin: {k}"),
        }
    }
}

impl std::error::Error for MetadataError {}

fn check_key(key: &str) -> Result<(), MetadataError> {
    if key.is_empty() {
        return Err(MetadataError::InvalidKey(key.to_string()));
    }
    for c in key.chars() {
        let ok = c.is_ascii_lowercase()
            || c.is_ascii_digit()
            || c == '-'
            || c == '_'
            || c == '.';
        if !ok {
            return Err(MetadataError::InvalidKey(key.to_string()));
        }
    }
    if GrpcMetadata::is_reserved(key) {
        return Err(MetadataError::ReservedKey(key.to_string()));
    }
    Ok(())
}

fn decode_wire_binary(wire: &str) -> Option<Vec<u8>> {
    base64::decode(wire)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_round_trip_unpadded_on_wire() {
        let mut md = GrpcMetadata::new();
        md.add_binary("x-auth-bin", b"\x01\x02\xff").unwrap();
        let wire = md.wire_value_at(0);
        assert!(!wire.ends_with('='));
        let back = md.get_binary("x-auth-bin").unwrap();
        assert_eq!(back, b"\x01\x02\xff");
    }

    #[test]
    fn reserved_keys_rejected_on_add() {
        let mut md = GrpcMetadata::new();
        assert!(md.add("grpc-status", "0").is_err());
        assert!(md.add("content-type", "x").is_err());
    }

    #[test]
    fn add_received_drops_invalid() {
        let mut md = GrpcMetadata::new();
        assert!(!md.add_received("bad key", "x"));
        assert!(md.is_empty());
    }
}
