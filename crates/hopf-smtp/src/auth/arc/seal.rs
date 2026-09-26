// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! ARC sealing (RFC 8617 section 5.1): adding this hop's set to a message.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rmimeparser::dkim::RawHeader;

use super::validate::seal_signing_input;
use super::{ArcCv, ArcSet, ArcValidationResult, MAX_INSTANCE};
use crate::auth::dkim::canon::{self, Canonicalization};
use crate::auth::dkim::sign::{base64_encode, canon_name, select_headers};
use crate::auth::dkim::{BodyHashMap, DkimPrivateKey};

/// Why a set could not be sealed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArcSealError {
    /// The incoming `ARC-*` headers were malformed, so the next instance
    /// number is unknowable; RFC 8617 forbids adding to such a chain.
    MalformedChain,
    /// An earlier hop already sealed with `cv=fail`; the chain is dead and
    /// must not be extended (RFC 8617 section 5.1.1).
    ChainAlreadyFailed,
    /// The chain already has [`MAX_INSTANCE`] sets.
    TooManyInstances,
    /// `body_hashes` has no hash for the sealer's body canonicalization
    /// (see [`ArcSealer::body_canonicalization`]).
    MissingBodyHash,
    /// The private key failed to sign.
    SigningFailed,
}

/// The three header fields of one ARC set, each a complete
/// `Name: value` line ending in CRLF.
#[derive(Debug, Clone)]
pub struct ArcSetHeaders {
    /// `ARC-Authentication-Results`.
    pub authentication_results: String,
    /// `ARC-Message-Signature`.
    pub message_signature: String,
    /// `ARC-Seal`.
    pub seal: String,
}

impl ArcSetHeaders {
    /// The set as one block to prepend to the message's header section, in
    /// the order RFC 8617 Appendix B shows: seal, message signature,
    /// authentication results.
    pub fn to_prepend(&self) -> String {
        format!("{}{}{}", self.seal, self.message_signature, self.authentication_results)
    }
}

/// Builds this hop's ARC set for a message being forwarded.
///
/// Configure once per signing identity (same shape as DKIM signing:
/// private key, `d=`, `s=`), then call [`Self::seal`] per message.
pub struct ArcSealer {
    key: Arc<DkimPrivateKey>,
    domain: String,
    selector: String,
    authserv_id: String,
    header_canon: Canonicalization,
    body_canon: Canonicalization,
    signed_headers: Vec<String>,
    timestamp: Option<u64>,
}

impl ArcSealer {
    /// New sealer signing as `domain`/`selector`, with `authserv_id` (this
    /// server's identity, RFC 8601 section 2.3) in the recorded results.
    /// Defaults to relaxed/relaxed canonicalization and signing `From`,
    /// `To`, `Subject`, `Date`, `Message-ID`.
    pub fn new(
        key: Arc<DkimPrivateKey>,
        domain: impl Into<String>,
        selector: impl Into<String>,
        authserv_id: impl Into<String>,
    ) -> Self {
        Self {
            key,
            domain: domain.into(),
            selector: selector.into(),
            authserv_id: authserv_id.into(),
            header_canon: Canonicalization::Relaxed,
            body_canon: Canonicalization::Relaxed,
            signed_headers: ["From", "To", "Subject", "Date", "Message-ID"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            timestamp: None,
        }
    }

    /// Header canonicalization for the `ARC-Message-Signature`. (The
    /// `ARC-Seal` is always relaxed.)
    pub fn header_canonicalization(mut self, c: Canonicalization) -> Self {
        self.header_canon = c;
        self
    }

    /// Body canonicalization for the `ARC-Message-Signature`.
    pub fn body_canonicalization(mut self, c: Canonicalization) -> Self {
        self.body_canon = c;
        self
    }

    /// The exact ordered `h=` header list for the message signature. Must
    /// not name `ARC-Seal`.
    pub fn signed_headers(mut self, headers: Vec<String>) -> Self {
        self.signed_headers = headers;
        self
    }

    /// Fixed `t=` timestamp; defaults to now.
    pub fn timestamp(mut self, t: u64) -> Self {
        self.timestamp = Some(t);
        self
    }

    /// The authserv-id placed in `ARC-Authentication-Results`.
    pub fn authserv_id(&self) -> &str {
        &self.authserv_id
    }

    /// The body canonicalization a caller must hash the body with
    /// (no `l=`) and supply in `body_hashes` to [`Self::seal`].
    pub fn body_canonicalization_key(&self) -> (Canonicalization, Option<u64>) {
        (self.body_canon, None)
    }

    /// Build the next ARC set.
    ///
    /// * `headers` - the message's header fields as received (all of them,
    ///   including any existing `ARC-*`).
    /// * `body_hashes` - must contain [`Self::body_canonicalization_key`].
    /// * `existing` - the result of [`super::validate`] on those headers;
    ///   its `cv` becomes this seal's `cv=`.
    /// * `authentication_results` - this hop's verdict as an RFC 8601
    ///   `Authentication-Results` field (with or without the field name);
    ///   it is re-labelled with the new instance number.
    pub fn seal(
        &self,
        headers: &[RawHeader],
        body_hashes: &BodyHashMap,
        existing: &ArcValidationResult,
        authentication_results: &str,
    ) -> Result<ArcSetHeaders, ArcSealError> {
        if existing.malformed.is_some() {
            return Err(ArcSealError::MalformedChain);
        }
        let prior = &existing.chain.sets;
        if prior.last().is_some_and(|s| s.seal_cv == ArcCv::Fail) {
            return Err(ArcSealError::ChainAlreadyFailed);
        }
        let instance = prior.len() as u32 + 1;
        if instance > MAX_INSTANCE {
            return Err(ArcSealError::TooManyInstances);
        }
        let cv = if prior.is_empty() { ArcCv::None } else { existing.cv };
        let bh = body_hashes
            .get(&self.body_canonicalization_key())
            .ok_or(ArcSealError::MissingBodyHash)?;
        let t = self.timestamp.unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        });

        // AAR: this hop's verdict, tagged with the instance.
        let results = authentication_results
            .trim()
            .strip_prefix_ci("Authentication-Results:")
            .trim();
        let aar_line = format!("ARC-Authentication-Results: i={instance}; {results}\r\n");

        // AMS: signs the message as received (headers per h=, then itself).
        let unsigned_ams = format!(
            "i={instance}; a={}; c={}/{}; d={}; s={}; t={t}; h={}; bh={}; b=",
            self.key.algorithm_tag(),
            canon_name(self.header_canon),
            canon_name(self.body_canon),
            self.domain,
            self.selector,
            self.signed_headers.join(":"),
            base64_encode(bh),
        );
        let unsigned_ams_line = format!("ARC-Message-Signature: {unsigned_ams}");
        let mut ams_input = Vec::new();
        for h in select_headers(headers, &self.signed_headers) {
            ams_input.extend_from_slice(&canon::canon_header(h, self.header_canon));
        }
        ams_input.extend_from_slice(&canon::canon_signature_header(
            "ARC-Message-Signature",
            unsigned_ams_line.as_bytes(),
            self.header_canon,
        ));
        let ams_sig = self
            .key
            .sign(&ams_input)
            .map_err(|_| ArcSealError::SigningFailed)?;
        let ams_line = format!("{unsigned_ams_line}{}\r\n", base64_encode(ams_sig));

        // AS: signs the whole chain including this hop's AAR and AMS.
        let unsigned_seal_line = format!(
            "ARC-Seal: i={instance}; a={}; t={t}; cv={}; d={}; s={}; b=",
            self.key.algorithm_tag(),
            cv.as_str(),
            self.domain,
            self.selector,
        );
        let mut sets: Vec<ArcSet> = prior.clone();
        sets.push(ArcSet {
            instance,
            authentication_results: raw("ARC-Authentication-Results", &aar_line),
            message_signature: raw("ARC-Message-Signature", &ams_line),
            seal: raw("ARC-Seal", &format!("{unsigned_seal_line}\r\n")),
            seal_cv: cv,
        });
        let seal_input = seal_signing_input(&sets, cv == ArcCv::Fail);
        let seal_sig = self
            .key
            .sign(&seal_input)
            .map_err(|_| ArcSealError::SigningFailed)?;
        let seal_line = format!("{unsigned_seal_line}{}\r\n", base64_encode(seal_sig));

        Ok(ArcSetHeaders {
            authentication_results: aar_line,
            message_signature: ams_line,
            seal: seal_line,
        })
    }
}

fn raw(name: &str, line: &str) -> RawHeader {
    RawHeader::new(name, line.as_bytes().to_vec())
}

trait StripPrefixCi {
    fn strip_prefix_ci(&self, prefix: &str) -> &str;
}

impl StripPrefixCi for str {
    fn strip_prefix_ci(&self, prefix: &str) -> &str {
        match self.get(..prefix.len()) {
            Some(head) if head.eq_ignore_ascii_case(prefix) => &self[prefix.len()..],
            _ => self,
        }
    }
}
