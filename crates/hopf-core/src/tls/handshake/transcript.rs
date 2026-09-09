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

    /// RFC 8446 §4.4.1: when a `HelloRetryRequest` happens, the transcript
    /// used for every subsequent hash replaces the literal first
    /// `ClientHello` with a synthetic `message_hash` message (handshake
    /// type 254) wrapping `Hash(ClientHello1)` — never sent or parsed off
    /// the wire, only ever a `Transcript`-internal stand-in. Call this once,
    /// with nothing but `ClientHello1` added so far (`ch1_hash` is that
    /// message's own hash, computed by the caller); the `HelloRetryRequest`
    /// and the followup `ClientHello2` are appended normally afterwards.
    pub fn retry(&mut self, ch1_hash: [u8; 32]) {
        self.messages.clear();
        self.messages.extend_from_slice(&[254, 0, 0, 32]);
        self.messages.extend_from_slice(&ch1_hash);
    }
}
