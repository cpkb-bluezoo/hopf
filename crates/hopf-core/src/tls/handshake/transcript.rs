// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Handshake transcript hash (RFC 8446 §4.4.1).

use bytes::BytesMut;

use crate::crypto::{hash, HashAlgorithm};

/// Running transcript for Derive-Secret inputs.
#[derive(Debug, Default, Clone)]
pub struct Transcript {
    messages: BytesMut,
}

impl Transcript {
    /// New empty transcript.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a serialized handshake message (with type/length header).
    pub fn add_message(&mut self, encoded: &[u8]) {
        self.messages.extend_from_slice(encoded);
    }

    /// Transcript-Hash = Hash(messages).
    pub fn hash(&self) -> [u8; 32] {
        hash(HashAlgorithm::Sha256, &self.messages).as_bytes().try_into().unwrap()
    }
}
