// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! ARC chain validation (RFC 8617 section 5.2).

use std::sync::Arc;

use rmimeparser::dkim::RawHeader;

use super::{
    ArcChain, ArcCv, ArcMalformed, ArcSet, ArcValidationResult,
};
use crate::auth::dkim::canon::{self, Canonicalization};
use crate::auth::dkim::verify::{
    arc_message_signature_body_key, verify_arc_message_signature, verify_arc_seal,
};
use crate::auth::dkim::{BodyHashMap, DkimResult};
use crate::auth::dns_lookup::DnsLookup;

/// Callback receiving the [`ArcValidationResult`].
pub type ArcCallback = Box<dyn FnOnce(ArcValidationResult) + Send>;

/// The `(c=body-side, l=)` pair validation needs a body hash for: only the
/// newest `ARC-Message-Signature` is verified (RFC 8617 section 5.2), since
/// earlier hops may legitimately have modified the body afterwards. Empty
/// when there is no usable chain. A streaming caller feeds one
/// [`crate::auth::dkim::IncrementalBodyCanon`] per key.
pub fn required_body_hash_keys(headers: &[RawHeader]) -> Vec<(Canonicalization, Option<u64>)> {
    let Ok(chain) = ArcChain::from_headers(headers) else {
        return Vec::new();
    };
    chain
        .sets
        .last()
        .and_then(|s| arc_message_signature_body_key(&s.message_signature))
        .into_iter()
        .collect()
}

/// Validate the message's ARC chain: structure and `cv=` sequencing, the
/// newest `ARC-Message-Signature` against the body hashes in `body_hashes`
/// (see [`required_body_hash_keys`]), then every `ARC-Seal` from newest to
/// oldest.
pub fn validate(
    dns: Arc<dyn DnsLookup>,
    headers: Arc<Vec<RawHeader>>,
    body_hashes: Arc<BodyHashMap>,
    cb: ArcCallback,
) {
    let chain = match ArcChain::from_headers(&headers) {
        Ok(c) => c,
        Err(m) => return cb(failed(ArcChain::default(), Some(m), None)),
    };
    let Some(newest) = chain.sets.last() else {
        return cb(ArcValidationResult {
            cv: ArcCv::None,
            malformed: None,
            chain,
            failed_instance: None,
        });
    };

    // Step 2: cv sequencing. The first seal must say `none`, later ones
    // `pass`; a `fail` anywhere means an earlier hop already gave up.
    if newest.seal_cv == ArcCv::Fail {
        let i = newest.instance;
        return cb(failed(chain, None, Some(i)));
    }
    for set in &chain.sets {
        let expected = if set.instance == 1 { ArcCv::None } else { ArcCv::Pass };
        if set.seal_cv != expected {
            let i = set.instance;
            return cb(failed(chain, None, Some(i)));
        }
    }

    let newest_ams = newest.message_signature.clone();
    let newest_instance = newest.instance;
    let dns2 = Arc::clone(&dns);
    verify_arc_message_signature(
        dns,
        headers,
        body_hashes,
        newest_ams,
        Box::new(move |r| {
            if r.result != DkimResult::Pass {
                return cb(failed(chain, None, Some(newest_instance)));
            }
            verify_seal_from(dns2, Arc::new(chain), newest_instance as usize, cb);
        }),
    );
}

fn failed(chain: ArcChain, malformed: Option<ArcMalformed>, instance: Option<u32>) -> ArcValidationResult {
    ArcValidationResult {
        cv: ArcCv::Fail,
        malformed,
        chain,
        failed_instance: instance,
    }
}

/// Verify seals `n`, `n-1`, ... `1` (1-based) in turn.
fn verify_seal_from(dns: Arc<dyn DnsLookup>, chain: Arc<ArcChain>, n: usize, cb: ArcCallback) {
    if n == 0 {
        return cb(ArcValidationResult {
            cv: ArcCv::Pass,
            malformed: None,
            chain: (*chain).clone(),
            failed_instance: None,
        });
    }
    let set = &chain.sets[n - 1];
    let signed = seal_signing_input(&chain.sets[..n], false);
    let dns2 = Arc::clone(&dns);
    let chain2 = Arc::clone(&chain);
    verify_arc_seal(
        dns,
        &set.seal,
        signed,
        Box::new(move |r| {
            if r.result != DkimResult::Pass {
                return cb(failed((*chain2).clone(), None, Some(n as u32)));
            }
            verify_seal_from(dns2, chain2, n - 1, cb);
        }),
    );
}

/// The bytes an `ARC-Seal` signs (RFC 8617 section 5.1.1): every set up to and
/// including the sealing one, each as AAR, AMS, AS in relaxed header
/// canonicalization, with the final seal's `b=` blanked. When
/// `own_set_only` (a `cv=fail` seal) only the sealing set is covered.
pub(super) fn seal_signing_input(sets: &[ArcSet], own_set_only: bool) -> Vec<u8> {
    let start = if own_set_only { sets.len() - 1 } else { 0 };
    let mut out = Vec::new();
    for (idx, set) in sets.iter().enumerate().skip(start) {
        let c = Canonicalization::Relaxed;
        out.extend_from_slice(&canon::canon_header(&set.authentication_results, c));
        out.extend_from_slice(&canon::canon_header(&set.message_signature, c));
        if idx + 1 == sets.len() {
            out.extend_from_slice(&canon::canon_signature_header(
                "ARC-Seal",
                &set.seal.bytes_unfolded(),
                c,
            ));
        } else {
            out.extend_from_slice(&canon::canon_header(&set.seal, c));
        }
    }
    out
}
