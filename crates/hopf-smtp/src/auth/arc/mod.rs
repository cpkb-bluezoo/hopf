// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! ARC - Authenticated Received Chain (RFC 8617).
//!
//! An intermediary (mailing list, forwarder) that breaks SPF or DKIM by
//! relaying a message can *seal* what it saw into an ARC set: an
//! `ARC-Authentication-Results` (AAR) recording its SPF/DKIM/DMARC verdict,
//! an `ARC-Message-Signature` (AMS) over the message as received, and an
//! `ARC-Seal` (AS) chaining it to every earlier set. A later receiver can
//! then *validate* the chain and, if it trusts the sealers, evaluate DMARC
//! against what the first hop saw instead of the (legitimately) broken
//! results at its own hop.
//!
//! * [`ArcChain::from_headers`] groups the `ARC-*` headers by instance and
//!   checks well-formedness.
//! * [`validate`] verifies the newest `ARC-Message-Signature` and every
//!   `ARC-Seal` (RFC 8617 section 5.2), looking keys up the same way DKIM does.
//! * [`ArcSealer`] adds a hop's set.
//! * [`ArcDmarcPolicy`] is the hook that decides, given a validated chain,
//!   which SPF/DKIM results DMARC should evaluate. hopf supplies the
//!   mechanism; which sealers to trust is the caller's decision.
//!
//! [`crate::auth::AuthPipelineBuilder`] wires all three into the SMTP
//! authentication pipeline.

mod seal;
mod validate;

#[cfg(test)]
mod tests;

pub use seal::{ArcSealError, ArcSealer, ArcSetHeaders};
pub use validate::{required_body_hash_keys, validate, ArcCallback};

use rmimeparser::dkim::RawHeader;

use crate::auth::dkim::{DkimResult, DkimSignatureResult};
use crate::auth::spf::SpfResult;

/// RFC 8617 section 4.2.1 upper bound on instance numbers.
pub const MAX_INSTANCE: u32 = 50;

/// `cv=` chain validation status (RFC 8617 section 4.1.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArcCv {
    /// No chain was present (only valid in the `i=1` seal).
    None,
    /// The chain validated when this hop received the message.
    Pass,
    /// The chain failed validation.
    Fail,
}

impl ArcCv {
    /// The `cv=` tag value.
    pub fn as_str(&self) -> &'static str {
        match self {
            ArcCv::None => "none",
            ArcCv::Pass => "pass",
            ArcCv::Fail => "fail",
        }
    }

    fn parse(s: &str) -> Option<ArcCv> {
        match s.to_ascii_lowercase().as_str() {
            "none" => Some(ArcCv::None),
            "pass" => Some(ArcCv::Pass),
            "fail" => Some(ArcCv::Fail),
            _ => None,
        }
    }
}

/// One hop's `ARC-Authentication-Results`, `ARC-Message-Signature` and
/// `ARC-Seal` headers.
#[derive(Debug, Clone)]
pub struct ArcSet {
    /// The `i=` instance number, starting at 1.
    pub instance: u32,
    /// The `ARC-Authentication-Results` header.
    pub authentication_results: RawHeader,
    /// The `ARC-Message-Signature` header.
    pub message_signature: RawHeader,
    /// The `ARC-Seal` header.
    pub seal: RawHeader,
    /// The `cv=` value the sealer recorded in its seal.
    pub seal_cv: ArcCv,
}

impl ArcSet {
    /// The sealer's `d=` domain from its `ARC-Seal`, lowercased.
    pub fn sealer_domain(&self) -> Option<String> {
        tag_value(&self.seal, "d").map(|d| d.trim_end_matches('.').to_ascii_lowercase())
    }

    /// The `s=` selector from its `ARC-Seal`.
    pub fn sealer_selector(&self) -> Option<String> {
        tag_value(&self.seal, "s")
    }

    /// The SPF and DKIM results the sealer recorded in its
    /// `ARC-Authentication-Results` - the raw material an
    /// [`ArcDmarcPolicy`] typically builds an [`ArcAuthSnapshot`] from.
    pub fn recorded_results(&self) -> ArcRecordedResults {
        ArcRecordedResults::parse(&self.authentication_results.as_string_unfolded())
    }
}

/// SPF/DKIM verdicts extracted from an `ARC-Authentication-Results` header.
///
/// Only the fields DMARC alignment needs are extracted; unknown methods and
/// properties are ignored.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArcRecordedResults {
    /// `spf=` result and the `smtp.mailfrom` / `smtp.helo` domain it
    /// authenticated, if reported.
    pub spf: Option<(SpfResult, Option<String>)>,
    /// One entry per `dkim=` result: the result and its `header.d` domain.
    pub dkim: Vec<(DkimResult, Option<String>)>,
}

impl ArcRecordedResults {
    fn parse(header_line: &str) -> Self {
        let value = header_line.split_once(':').map(|(_, v)| v).unwrap_or("");
        let mut out = ArcRecordedResults::default();
        // Skip `i=N` and the authserv-id, then one resinfo per `;` segment.
        for segment in value.split(';').skip(2) {
            let mut parts = segment.split_whitespace();
            let Some((method, result)) = parts.next().and_then(|p| p.split_once('=')) else {
                continue;
            };
            let domain_of = |prop: &[&str], parts: std::str::SplitWhitespace<'_>| {
                parts
                    .filter_map(|p| p.split_once('='))
                    .find(|(k, _)| prop.iter().any(|w| k.eq_ignore_ascii_case(w)))
                    .map(|(_, v)| domain_part(v))
            };
            match method.to_ascii_lowercase().as_str() {
                "spf" => {
                    if let Some(r) = parse_spf_result(result) {
                        let dom = domain_of(&["smtp.mailfrom", "smtp.helo"], parts);
                        out.spf = Some((r, dom));
                    }
                }
                "dkim" => {
                    if let Some(r) = parse_dkim_result(result) {
                        out.dkim.push((r, domain_of(&["header.d"], parts)));
                    }
                }
                _ => {}
            }
        }
        out
    }
}

fn domain_part(v: &str) -> String {
    v.rsplit_once('@')
        .map(|(_, d)| d)
        .unwrap_or(v)
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn parse_spf_result(s: &str) -> Option<SpfResult> {
    Some(match s.to_ascii_lowercase().as_str() {
        "pass" => SpfResult::Pass,
        "fail" => SpfResult::Fail,
        "softfail" => SpfResult::SoftFail,
        "neutral" => SpfResult::Neutral,
        "none" => SpfResult::None,
        "temperror" => SpfResult::TempError,
        "permerror" => SpfResult::PermError,
        _ => return None,
    })
}

fn parse_dkim_result(s: &str) -> Option<DkimResult> {
    Some(match s.to_ascii_lowercase().as_str() {
        "pass" => DkimResult::Pass,
        "fail" => DkimResult::Fail,
        "none" => DkimResult::None,
        "temperror" => DkimResult::TempError,
        "permerror" => DkimResult::PermError,
        "policy" => DkimResult::Policy,
        "neutral" => DkimResult::Neutral,
        _ => return None,
    })
}

/// Why a message's `ARC-*` headers could not be grouped into a chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArcMalformed {
    /// An ARC header has a missing, non-numeric or out-of-range (`1..=50`) `i=`.
    BadInstance,
    /// An instance has more than one header of a kind.
    DuplicateHeader,
    /// An instance is missing one of its three headers, or instances are
    /// not contiguous from 1.
    IncompleteSet,
    /// An `ARC-Seal` has a missing or unrecognised `cv=`.
    BadSealCv,
}

/// A message's ARC sets in instance order (`i=1` first).
#[derive(Debug, Clone, Default)]
pub struct ArcChain {
    /// Sets ordered by `instance`, contiguous from 1.
    pub sets: Vec<ArcSet>,
}

impl ArcChain {
    /// Group the `ARC-*` headers among `headers` (RFC 8617 section 5.2 step 1).
    /// A message with no ARC headers yields an empty chain.
    pub fn from_headers(headers: &[RawHeader]) -> Result<ArcChain, ArcMalformed> {
        #[derive(Default)]
        struct Slot {
            aar: Option<RawHeader>,
            ams: Option<RawHeader>,
            seal: Option<(RawHeader, ArcCv)>,
        }
        let mut slots: std::collections::BTreeMap<u32, Slot> = Default::default();
        for h in headers {
            let kind = if h.name().eq_ignore_ascii_case("ARC-Authentication-Results") {
                0
            } else if h.name().eq_ignore_ascii_case("ARC-Message-Signature") {
                1
            } else if h.name().eq_ignore_ascii_case("ARC-Seal") {
                2
            } else {
                continue;
            };
            let i = tag_value(h, "i")
                .and_then(|v| v.parse::<u32>().ok())
                .filter(|i| (1..=MAX_INSTANCE).contains(i))
                .ok_or(ArcMalformed::BadInstance)?;
            let slot = slots.entry(i).or_default();
            match kind {
                0 => {
                    if slot.aar.replace(h.clone()).is_some() {
                        return Err(ArcMalformed::DuplicateHeader);
                    }
                }
                1 => {
                    if slot.ams.replace(h.clone()).is_some() {
                        return Err(ArcMalformed::DuplicateHeader);
                    }
                }
                _ => {
                    let cv = tag_value(h, "cv")
                        .and_then(|v| ArcCv::parse(&v))
                        .ok_or(ArcMalformed::BadSealCv)?;
                    if slot.seal.replace((h.clone(), cv)).is_some() {
                        return Err(ArcMalformed::DuplicateHeader);
                    }
                }
            }
        }
        let mut sets = Vec::with_capacity(slots.len());
        for (expected, (instance, slot)) in (1u32..).zip(slots) {
            let (Some(aar), Some(ams), Some((seal, seal_cv))) = (slot.aar, slot.ams, slot.seal)
            else {
                return Err(ArcMalformed::IncompleteSet);
            };
            if instance != expected {
                return Err(ArcMalformed::IncompleteSet);
            }
            sets.push(ArcSet {
                instance,
                authentication_results: aar,
                message_signature: ams,
                seal,
                seal_cv,
            });
        }
        Ok(ArcChain { sets })
    }
}

/// Outcome of validating a message's ARC chain (RFC 8617 section 5.2).
#[derive(Debug, Clone)]
pub struct ArcValidationResult {
    /// Overall chain status: [`ArcCv::None`] when there is no chain,
    /// [`ArcCv::Pass`] when every check succeeded, [`ArcCv::Fail`]
    /// otherwise (including transient DNS failures - a caller that needs
    /// to distinguish those can re-run validation).
    pub cv: ArcCv,
    /// `Some` when the headers could not be grouped into a chain at all.
    pub malformed: Option<ArcMalformed>,
    /// The chain that was validated (empty when malformed or absent).
    pub chain: ArcChain,
    /// The instance whose check first failed, if any.
    pub failed_instance: Option<u32>,
}

/// SPF/DKIM inputs a trusted ARC chain substitutes for this hop's own
/// results when evaluating DMARC.
#[derive(Debug, Clone, Default)]
pub struct ArcAuthSnapshot {
    /// SPF result and the domain it authenticated, or `None` to keep this
    /// hop's own SPF result.
    pub spf: Option<(SpfResult, Option<String>)>,
    /// DKIM results, or `None` to keep this hop's own DKIM results.
    pub dkim: Option<Vec<DkimSignatureResult>>,
}

/// Decides which SPF/DKIM results DMARC evaluates when an ARC chain is
/// present. This is where a deployment's trust decisions live: hopf does not
/// hard-code which sealers to believe.
pub trait ArcDmarcPolicy: Send + Sync {
    /// Called once per message, after [`validate`] and before DMARC.
    /// Return `None` to evaluate DMARC against this hop's own results.
    fn auth_snapshot(
        &self,
        chain: &ArcValidationResult,
        from_domain: &str,
        local_spf: SpfResult,
        local_spf_domain: Option<&str>,
        local_dkim: &[DkimSignatureResult],
    ) -> Option<ArcAuthSnapshot>;
}

/// The value of tag `name` in the header's tag-list, if present.
pub(crate) fn tag_value(header: &RawHeader, name: &str) -> Option<String> {
    let line = header.as_string_unfolded();
    let value = line.split_once(':').map(|(_, v)| v)?;
    value.split(';').find_map(|part| {
        let (k, v) = part.trim().split_once('=')?;
        (k.trim() == name).then(|| v.trim().to_string())
    })
}
