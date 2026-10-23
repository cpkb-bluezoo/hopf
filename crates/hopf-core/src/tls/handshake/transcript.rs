// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Handshake transcript hash (RFC 8446 §4.4.1).

use bytes::{Bytes, BytesMut};

use crate::crypto::Tls13Hash;

use super::key_schedule::TranscriptHash;

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

    /// First appended handshake message (type/length/body), if any.
    pub(crate) fn first_message(&self) -> Option<Bytes> {
        if self.messages.is_empty() {
            None
        } else {
            Some(self.messages.clone().freeze())
        }
    }

    /// Transcript-Hash = Hash(messages), with the negotiated suite's `hash`.
    /// The messages are kept raw, so the hash can be chosen after the
    /// ClientHello was added (the suite is only known at ServerHello).
    pub fn hash(&self, hash: Tls13Hash) -> TranscriptHash {
        TranscriptHash::from_bytes(hash.hash(&self.messages))
    }

    /// RFC 8446 §4.4.1: when a `HelloRetryRequest` happens, the transcript
    /// used for every subsequent hash replaces the literal first
    /// `ClientHello` with a synthetic `message_hash` message (handshake
    /// type 254) wrapping `Hash(ClientHello1)` — never sent or parsed off
    /// the wire, only ever a `Transcript`-internal stand-in. Call this once,
    /// with nothing but `ClientHello1` added so far (`ch1_hash` is that
    /// message's own hash, computed by the caller); the `HelloRetryRequest`
    /// and the followup `ClientHello2` are appended normally afterwards.
    pub fn retry(&mut self, ch1_hash: TranscriptHash) {
        self.messages.clear();
        self.messages.extend_from_slice(&[254, 0, 0, ch1_hash.as_bytes().len() as u8]);
        self.messages.extend_from_slice(ch1_hash.as_bytes());
    }
}
