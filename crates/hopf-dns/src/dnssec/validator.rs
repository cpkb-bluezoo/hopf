// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! RRSIG / DS verification (RFC 4034).

use std::time::{SystemTime, UNIX_EPOCH};

use crate::wire::{encode_name, normalize_name, DnsMessage, DnsResourceRecord, DnsType};

use super::algorithm::DnssecAlgorithm;
use super::crypto::{compute_ds_digest, verify_signature};
use super::status::DnssecStatus;
use super::trust_anchor::DnssecTrustAnchor;

/// Core DNSSEC validation engine (CPU-bound; safe on the reactor).
pub struct DnssecValidator {
    trust: DnssecTrustAnchor,
}

impl DnssecValidator {
    /// With trust anchors.
    pub fn new(trust: DnssecTrustAnchor) -> Self {
        Self { trust }
    }

    /// Trust anchor store.
    pub fn trust_anchors(&self) -> &DnssecTrustAnchor {
        &self.trust
    }

    /// Validate answer RRsets in `msg` using DNSKEYs present in the message
    /// and configured DS trust anchors (direct trust; no async parent fetch).
    pub fn validate_message(&self, msg: &DnsMessage) -> DnssecStatus {
        if self.trust.is_empty() {
            return DnssecStatus::Indeterminate;
        }

        let rrsigs: Vec<&DnsResourceRecord> = msg
            .answers
            .iter()
            .chain(msg.authorities.iter())
            .chain(msg.additionals.iter())
            .filter(|rr| rr.rtype == Some(DnsType::Rrsig))
            .collect();
        if rrsigs.is_empty() {
            return DnssecStatus::Insecure;
        }

        let dnskeys: Vec<&DnsResourceRecord> = msg
            .answers
            .iter()
            .chain(msg.authorities.iter())
            .chain(msg.additionals.iter())
            .filter(|rr| rr.rtype == Some(DnsType::Dnskey))
            .collect();

        // Group non-RRSIG answers by (name, type).
        let mut saw_signed = false;
        let mut types: Vec<(String, u16)> = Vec::new();
        for rr in &msg.answers {
            if rr.rtype == Some(DnsType::Rrsig) {
                continue;
            }
            let key = (normalize_name(&rr.name), rr.raw_type);
            if !types.iter().any(|t| t == &key) {
                types.push(key);
            }
        }

        for (name, covered) in types {
            let rrset: Vec<&DnsResourceRecord> = msg
                .answers
                .iter()
                .filter(|rr| {
                    normalize_name(&rr.name) == name
                        && rr.raw_type == covered
                        && rr.rtype != Some(DnsType::Rrsig)
                })
                .collect();
            if rrset.is_empty() {
                continue;
            }
            let covering: Vec<&DnsResourceRecord> = rrsigs
                .iter()
                .copied()
                .filter(|sig| {
                    normalize_name(&sig.name) == name
                        && sig.rrsig_type_covered() == Some(covered)
                })
                .collect();
            if covering.is_empty() {
                continue;
            }
            saw_signed = true;
            let mut ok = false;
            for sig in &covering {
                if !is_rrsig_current(sig) {
                    continue;
                }
                let Some(key) = find_matching_dnskey(sig, &dnskeys) else {
                    continue;
                };
                if !verify_rrsig(&rrset, sig, key) {
                    return DnssecStatus::Bogus;
                }
                let signer = sig.rrsig_signer_name().unwrap_or_default();
                if self.trust.is_dnskey_trusted(&signer, key) {
                    ok = true;
                    break;
                }
                // Key verified cryptographically but not (yet) chained to an
                // anchor — treat as indeterminate unless another sig is trusted.
            }
            if !ok {
                // Signed RRset but no trusted key in-message.
                return DnssecStatus::Indeterminate;
            }
        }

        if saw_signed {
            DnssecStatus::Secure
        } else {
            DnssecStatus::Insecure
        }
    }
}

/// Verify RRSIG over `rrset` with `dnskey` (RFC 4034 §3.1.8).
pub fn verify_rrsig(
    rrset: &[&DnsResourceRecord],
    rrsig: &DnsResourceRecord,
    dnskey: &DnsResourceRecord,
) -> bool {
    let Some(alg_num) = rrsig.rrsig_algorithm() else {
        return false;
    };
    let Some(algorithm) = DnssecAlgorithm::from_u8(alg_num) else {
        return false;
    };
    let Some(pub_key) = dnskey.dnskey_public_key() else {
        return false;
    };
    let Some(sig_bytes) = rrsig.rrsig_signature() else {
        return false;
    };
    let Some(signed) = build_signed_data(rrset, rrsig) else {
        return false;
    };
    verify_signature(algorithm, pub_key, &signed, sig_bytes)
}

/// Temporal validity of an RRSIG.
pub fn is_rrsig_current(rrsig: &DnsResourceRecord) -> bool {
    let Some(inception) = rrsig.rrsig_inception() else {
        return false;
    };
    let Some(expiration) = rrsig.rrsig_expiration() else {
        return false;
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);
    now >= inception && now <= expiration
}

/// Verify DNSKEY matches DS digest (RFC 4034 §5.1.4).
pub fn verify_ds(dnskey: &DnsResourceRecord, ds: &DnsResourceRecord) -> bool {
    let Some(digest_type) = ds.ds_digest_type() else {
        return false;
    };
    let Some(expected) = ds.ds_digest() else {
        return false;
    };
    let owner = normalize_name(&dnskey.name);
    let Ok(owner_wire) = encode_name(if owner.is_empty() { "." } else { &owner }) else {
        return false;
    };
    // Root apex: encode_name(".") → [0]; encode_name("") also [0].
    let owner_wire = if owner.is_empty() || owner == "." {
        vec![0u8]
    } else {
        owner_wire
    };
    let Some(computed) = compute_ds_digest(&owner_wire, &dnskey.rdata, digest_type) else {
        return false;
    };
    computed.as_slice() == expected
}

/// Find DNSKEY matching RRSIG key tag + algorithm.
pub fn find_matching_dnskey<'a>(
    rrsig: &DnsResourceRecord,
    dnskeys: &[&'a DnsResourceRecord],
) -> Option<&'a DnsResourceRecord> {
    let tag = rrsig.rrsig_key_tag()?;
    let alg = rrsig.rrsig_algorithm()?;
    let signer = normalize_name(&rrsig.rrsig_signer_name()?);
    dnskeys.iter().copied().find(|k| {
        k.rtype == Some(DnsType::Dnskey)
            && normalize_name(&k.name) == signer
            && k.dnskey_algorithm() == Some(alg)
            && k.dnskey_key_tag() == Some(tag)
    })
}

/// RRSIGs covering a type.
pub fn find_rrsigs<'a>(
    records: &'a [DnsResourceRecord],
    covered_type: u16,
) -> Vec<&'a DnsResourceRecord> {
    records
        .iter()
        .filter(|rr| {
            rr.rtype == Some(DnsType::Rrsig) && rr.rrsig_type_covered() == Some(covered_type)
        })
        .collect()
}

fn build_signed_data(
    rrset: &[&DnsResourceRecord],
    rrsig: &DnsResourceRecord,
) -> Option<Vec<u8>> {
    let header = rrsig.rrsig_header_bytes()?;
    let mut out = Vec::new();
    out.extend_from_slice(header);
    for rec in build_canonical_rrset(rrset, rrsig)? {
        out.extend_from_slice(&rec);
    }
    Some(out)
}

fn build_canonical_rrset(
    rrset: &[&DnsResourceRecord],
    rrsig: &DnsResourceRecord,
) -> Option<Vec<Vec<u8>>> {
    if rrset.is_empty() {
        return None;
    }
    let owner_lower = normalize_name(&rrset[0].name);
    let owner_wire = if owner_lower.is_empty() {
        vec![0u8]
    } else {
        encode_name(&owner_lower).ok()?
    };
    let type_covered = rrsig.rrsig_type_covered()?;
    let original_ttl = rrsig.rrsig_original_ttl()?;
    let mut records = Vec::with_capacity(rrset.len());
    for rr in rrset {
        let mut rec = Vec::new();
        rec.extend_from_slice(&owner_wire);
        rec.extend_from_slice(&type_covered.to_be_bytes());
        rec.extend_from_slice(&1u16.to_be_bytes()); // IN
        rec.extend_from_slice(&original_ttl.to_be_bytes());
        let rdlen = rr.rdata.len() as u16;
        rec.extend_from_slice(&rdlen.to_be_bytes());
        rec.extend_from_slice(&rr.rdata);
        records.push(rec);
    }
    records.sort();
    Some(records)
}

/// Result of feeding a response into an in-progress [`DnssecChainWalk`].
/// I/O-agnostic by design (mirrors [`DnssecValidator`]): the caller issues
/// whatever query each `Need*` step asks for and feeds the response back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainStep {
    /// Query DNSKEY for this zone and feed the response to
    /// [`DnssecChainWalk::on_dnskey_response`].
    NeedDnskey(String),
    /// Query DS for this zone and feed the response to
    /// [`DnssecChainWalk::on_ds_response`].
    NeedDs(String),
    /// The chain of trust is validated down to `zone`, using `key` — the
    /// caller can now validate the original target message's own RRSIGs
    /// against it (e.g. build a [`DnssecTrustAnchor`] anchored at `zone`
    /// with a DS digest of `key`, and run it through [`DnssecValidator`]).
    Done {
        /// The deepest zone this walk actually validated a key for.
        zone: String,
        /// That zone's trusted DNSKEY.
        key: Box<DnsResourceRecord>,
    },
    /// The chain could not be validated (RFC 4035 §4.3), or no configured
    /// trust anchor covers the target name at all.
    Failed(DnssecStatus),
}

/// Drives one DNSSEC chain-of-trust walk (RFC 4035 §5.3.1): starting from
/// the closest configured trust anchor, resolve and validate DS + DNSKEY
/// at each zone cut down toward a target name, so validation works for any
/// signed name under a signed root — not just zones with a directly
/// pre-configured trust anchor (see [`DnssecValidator`], which only checks
/// the single message it's given).
///
/// A zone-cut candidate with no DS record isn't treated as a hard failure
/// — it's skipped as "not independently delegated", and the walk keeps
/// descending under the current key. Authenticating that a missing DS is
/// itself genuine (rather than stripped by an attacker) needs NSEC/NSEC3
/// denial-of-existence, which this walker doesn't yet verify.
pub struct DnssecChainWalk {
    trust: DnssecTrustAnchor,
    /// Zone-cut candidates still to investigate, closest-to-root first.
    remaining: std::collections::VecDeque<String>,
    /// The zone currently being investigated (whatever `Need*` step is
    /// outstanding).
    current_zone: String,
    /// The deepest zone actually validated so far, and its trusted key.
    trusted: Option<(String, DnsResourceRecord)>,
    /// DS records fetched for `current_zone`, awaiting its DNSKEY response.
    pending_ds: Vec<DnsResourceRecord>,
}

impl DnssecChainWalk {
    /// Start a walk toward `qname`. Returns the walk plus its first step —
    /// `Failed(Indeterminate)` immediately if no configured anchor covers
    /// `qname` at all (mirrors [`DnssecValidator::validate_message`]).
    pub fn start(trust: DnssecTrustAnchor, qname: &str) -> (Self, ChainStep) {
        let chain = zone_chain_from_root(qname);
        let Some(anchor_idx) = chain.iter().position(|z| !trust.anchors_for(z).is_empty()) else {
            let walk = Self {
                trust,
                remaining: std::collections::VecDeque::new(),
                current_zone: String::new(),
                trusted: None,
                pending_ds: Vec::new(),
            };
            return (walk, ChainStep::Failed(DnssecStatus::Indeterminate));
        };
        let anchor_zone = chain[anchor_idx].clone();
        let remaining: std::collections::VecDeque<String> =
            chain[anchor_idx + 1..].iter().cloned().collect();
        let step = ChainStep::NeedDnskey(anchor_zone.clone());
        let walk = Self {
            trust,
            remaining,
            current_zone: anchor_zone,
            trusted: None,
            pending_ds: Vec::new(),
        };
        (walk, step)
    }

    /// Feed a DNSKEY response for the zone named in the most recently
    /// issued `NeedDnskey` step.
    pub fn on_dnskey_response(&mut self, msg: &DnsMessage) -> ChainStep {
        let dnskeys: Vec<&DnsResourceRecord> =
            msg.answers.iter().filter(|rr| rr.rtype == Some(DnsType::Dnskey)).collect();

        let trusted_key = if self.pending_ds.is_empty() {
            // First (anchor) step: validate directly against the
            // configured trust anchor for this zone.
            dnskeys.iter().find(|k| self.trust.is_dnskey_trusted(&self.current_zone, k))
        } else {
            // Descent step: validate against the DS fetched for this zone.
            dnskeys.iter().find(|k| self.pending_ds.iter().any(|ds| verify_ds(k, ds)))
        };
        let Some(&key) = trusted_key else {
            return ChainStep::Failed(DnssecStatus::Bogus);
        };

        // The DNSKEY RRset must be self-signed by this specific key
        // (RFC 4035 §5.2) — not just any key present in the response.
        let rrsigs = find_rrsigs(&msg.answers, DnsType::Dnskey.value());
        let key_tag = key.dnskey_key_tag();
        let key_alg = key.dnskey_algorithm();
        let signed = rrsigs.iter().any(|sig| {
            is_rrsig_current(sig)
                && sig.rrsig_key_tag() == key_tag
                && sig.rrsig_algorithm() == key_alg
                && verify_rrsig(&dnskeys, sig, key)
        });
        if !signed {
            return ChainStep::Failed(DnssecStatus::Bogus);
        }

        self.trusted = Some((self.current_zone.clone(), key.clone()));
        self.pending_ds.clear();
        self.advance()
    }

    /// Feed a DS response for the zone named in the most recently issued
    /// `NeedDs` step.
    pub fn on_ds_response(&mut self, msg: &DnsMessage) -> ChainStep {
        let ds_records: Vec<DnsResourceRecord> =
            msg.answers.iter().filter(|rr| rr.rtype == Some(DnsType::Ds)).cloned().collect();
        if ds_records.is_empty() {
            // No DS at this label: not an independently delegated zone —
            // skip it and keep descending under the current key.
            return self.advance();
        }
        let Some((_, ref parent_key)) = self.trusted else {
            return ChainStep::Failed(DnssecStatus::Bogus);
        };
        let ds_refs: Vec<&DnsResourceRecord> = ds_records.iter().collect();
        let rrsigs = find_rrsigs(&msg.answers, DnsType::Ds.value());
        let signed = rrsigs
            .iter()
            .any(|sig| is_rrsig_current(sig) && verify_rrsig(&ds_refs, sig, parent_key));
        if !signed {
            return ChainStep::Failed(DnssecStatus::Bogus);
        }
        self.pending_ds = ds_records;
        ChainStep::NeedDnskey(self.current_zone.clone())
    }

    fn advance(&mut self) -> ChainStep {
        match self.remaining.pop_front() {
            Some(zone) => {
                self.current_zone = zone.clone();
                ChainStep::NeedDs(zone)
            }
            None => {
                let (zone, key) = self.trusted.clone().expect("advance only reached once a key is trusted");
                ChainStep::Done { zone, key: Box::new(key) }
            }
        }
    }
}

/// Every ancestor zone name from the root down to and including `name`
/// itself, e.g. `"www.example.com"` → `[".", "com.", "example.com.",
/// "www.example.com."]` (RFC 4035 §5.3.1's candidate zone cuts).
fn zone_chain_from_root(name: &str) -> Vec<String> {
    let normalized = normalize_name(name);
    let mut out = vec![".".to_string()];
    if normalized.is_empty() {
        return out;
    }
    let labels: Vec<&str> = normalized.split('.').collect();
    for i in (0..labels.len()).rev() {
        out.push(labels[i..].join("."));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{DnsClass, DnsType};
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    #[test]
    fn ed25519_rrsig_verifies() {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let pub_bytes = pair.public_key().as_ref().to_vec();

        let dnskey = DnsResourceRecord::dnskey("example.com", 3600, 257, 15, &pub_bytes);
        let a = DnsResourceRecord::a("example.com", 3600, std::net::Ipv4Addr::new(192, 0, 2, 1));

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        let key_tag = dnskey.dnskey_key_tag().unwrap();

        // Build RRSIG header + signer, then sign.
        let mut rrsig_rdata = Vec::new();
        rrsig_rdata.extend_from_slice(&DnsType::A.value().to_be_bytes());
        rrsig_rdata.push(15); // Ed25519
        rrsig_rdata.push(2); // labels
        rrsig_rdata.extend_from_slice(&3600u32.to_be_bytes());
        rrsig_rdata.extend_from_slice(&(now + 3600).to_be_bytes());
        rrsig_rdata.extend_from_slice(&(now - 60).to_be_bytes());
        rrsig_rdata.extend_from_slice(&key_tag.to_be_bytes());
        rrsig_rdata.extend_from_slice(&encode_name("example.com").unwrap());

        let mut rrsig = DnsResourceRecord::new(
            "example.com",
            DnsType::Rrsig,
            DnsClass::In,
            3600,
            rrsig_rdata.clone(),
        );
        // Temporary signature empty so header_bytes works — append after signing.
        let header_len = rrsig_rdata.len();
        let signed = {
            let header = &rrsig_rdata[..header_len];
            let mut out = header.to_vec();
            let canon = build_canonical_rrset(&[&a], &rrsig).unwrap();
            for c in canon {
                out.extend_from_slice(&c);
            }
            out
        };
        let sig = pair.sign(&signed);
        rrsig.rdata.extend_from_slice(sig.as_ref());

        assert!(verify_rrsig(&[&a], &rrsig, &dnskey));
        assert!(is_rrsig_current(&rrsig));
    }

    #[test]
    fn root_ds_matches_known_ksk_20326() {
        // Root KSK-2017 public key (RFC 3110 RSA).
        let pub_key: &[u8] = &[
            0x03, 0x01, 0x00, 0x01, 0xac, 0xff, 0xb4, 0x09, 0xbc, 0xc9, 0x39, 0xf8, 0x31, 0xf7,
            0xa1, 0xe5, 0xec, 0x88, 0xf7, 0xa5, 0x92, 0x55, 0xec, 0x53, 0x04, 0x0b, 0xe4, 0x32,
            0x02, 0x73, 0x90, 0xa4, 0xce, 0x89, 0x6d, 0x6f, 0x90, 0x86, 0xf3, 0xc5, 0xe1, 0x77,
            0xfb, 0xfe, 0x11, 0x81, 0x63, 0xaa, 0xec, 0x7a, 0xf1, 0x46, 0x2c, 0x47, 0x94, 0x59,
            0x44, 0xc4, 0xe2, 0xc0, 0x26, 0xbe, 0x5e, 0x98, 0xbb, 0xcd, 0xed, 0x25, 0x97, 0x82,
            0x72, 0xe1, 0xe3, 0xe0, 0x79, 0xc5, 0x09, 0x4d, 0x57, 0x3f, 0x0e, 0x83, 0xc9, 0x2f,
            0x02, 0xb3, 0x2d, 0x35, 0x13, 0xb1, 0x55, 0x0b, 0x82, 0x69, 0x29, 0xc8, 0x0d, 0xd0,
            0xf9, 0x2c, 0xac, 0x96, 0x6d, 0x17, 0x76, 0x9f, 0xd5, 0x86, 0x7b, 0x64, 0x7c, 0x3f,
            0x38, 0x02, 0x9a, 0xbd, 0xc4, 0x81, 0x52, 0xeb, 0x8f, 0x20, 0x71, 0x59, 0xec, 0xc5,
            0xd2, 0x32, 0xc7, 0xc1, 0x53, 0x7c, 0x79, 0xf4, 0xb7, 0xac, 0x28, 0xff, 0x11, 0x68,
            0x2f, 0x21, 0x68, 0x1b, 0xf6, 0xd6, 0xab, 0xa5, 0x55, 0x03, 0x2b, 0xf6, 0xf9, 0xf0,
            0x36, 0xbe, 0xb2, 0xaa, 0xa5, 0xb3, 0x77, 0x8d, 0x6e, 0xeb, 0xfb, 0xa6, 0xbf, 0x9e,
            0xa1, 0x91, 0xbe, 0x4a, 0xb0, 0xca, 0xea, 0x75, 0x9e, 0x2f, 0x77, 0x3a, 0x1f, 0x90,
            0x29, 0xc7, 0x3e, 0xcb, 0x8d, 0x57, 0x35, 0xb9, 0x32, 0x1d, 0xb0, 0x85, 0xf1, 0xb8,
            0xe2, 0xd8, 0x03, 0x8f, 0xe2, 0x94, 0x19, 0x92, 0x54, 0x8c, 0xee, 0x0d, 0x67, 0xdd,
            0x45, 0x47, 0xe1, 0x1d, 0xd6, 0x3a, 0xf9, 0xc9, 0xfc, 0x1c, 0x54, 0x66, 0xfb, 0x68,
            0x4c, 0xf0, 0x09, 0xd7, 0x19, 0x7c, 0x2c, 0xf7, 0x9e, 0x79, 0x2a, 0xb5, 0x01, 0xe6,
            0xa8, 0xa1, 0xca, 0x51, 0x9a, 0xf2, 0xcb, 0x9b, 0x5f, 0x63, 0x67, 0xe9, 0x4c, 0x0d,
            0x47, 0x50, 0x24, 0x51, 0x35, 0x7b, 0xe1, 0xb5,
        ];
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&257u16.to_be_bytes());
        rdata.push(3);
        rdata.push(8);
        rdata.extend_from_slice(pub_key);
        let dnskey = DnsResourceRecord::opaque(".", DnsType::Dnskey.value(), 1, 3600, rdata);
        assert_eq!(dnskey.dnskey_key_tag(), Some(20326));

        let trust = DnssecTrustAnchor::with_iana_root();
        assert!(trust.is_dnskey_trusted(".", &dnskey));
    }

    /// Sign `rrset` (all owned by `name`, of `rtype`) with `pair`, matching
    /// the RRSIG construction already proven in `ed25519_rrsig_verifies`.
    fn sign_rrset(
        rrset: &[&DnsResourceRecord],
        name: &str,
        rtype: DnsType,
        key_tag: u16,
        pair: &Ed25519KeyPair,
    ) -> DnsResourceRecord {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;
        let labels = if name == "." { 0 } else { name.split('.').filter(|s| !s.is_empty()).count() as u8 };
        let mut rrsig_rdata = Vec::new();
        rrsig_rdata.extend_from_slice(&rtype.value().to_be_bytes());
        rrsig_rdata.push(15); // Ed25519
        rrsig_rdata.push(labels);
        rrsig_rdata.extend_from_slice(&3600u32.to_be_bytes());
        rrsig_rdata.extend_from_slice(&(now + 3600).to_be_bytes());
        rrsig_rdata.extend_from_slice(&(now - 60).to_be_bytes());
        rrsig_rdata.extend_from_slice(&key_tag.to_be_bytes());
        rrsig_rdata.extend_from_slice(&encode_name(name).unwrap());
        let mut rrsig = DnsResourceRecord::new(name, DnsType::Rrsig, DnsClass::In, 3600, rrsig_rdata);
        let signed = build_signed_data(rrset, &rrsig).unwrap();
        let sig = pair.sign(&signed);
        rrsig.rdata.extend_from_slice(sig.as_ref());
        rrsig
    }

    fn generate_ed25519() -> (Ed25519KeyPair, Vec<u8>) {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        // Safety-free: PKCS8 doc owns the key material for the pair's lifetime.
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let pub_bytes = pair.public_key().as_ref().to_vec();
        (pair, pub_bytes)
    }

    /// Real two-level chain walk: root (the trust anchor) delegates to
    /// "example.com" via a DS record; "com" has no DS at all (must be
    /// skipped, not treated as a failure) — proves the walker actually
    /// authenticates each hop rather than just trusting whatever DNSKEY
    /// shows up.
    #[test]
    fn chain_walk_validates_two_level_delegation_and_skips_undelegated_labels() {
        let (root_pair, root_pub) = generate_ed25519();
        let (example_pair, example_pub) = generate_ed25519();

        let root_dnskey = DnsResourceRecord::dnskey(".", 3600, 257, 15, &root_pub);
        let root_key_tag = root_dnskey.dnskey_key_tag().unwrap();
        let root_dnskey_rrsig = sign_rrset(&[&root_dnskey], ".", DnsType::Dnskey, root_key_tag, &root_pair);

        let example_dnskey = DnsResourceRecord::dnskey("example.com", 3600, 257, 15, &example_pub);
        let example_key_tag = example_dnskey.dnskey_key_tag().unwrap();
        let example_dnskey_rrsig =
            sign_rrset(&[&example_dnskey], "example.com", DnsType::Dnskey, example_key_tag, &example_pair);

        let owner_wire = encode_name("example.com").unwrap();
        let ds_digest = compute_ds_digest(&owner_wire, &example_dnskey.rdata, 2).unwrap();
        let example_ds = DnsResourceRecord::ds("example.com", 3600, example_key_tag, 15, 2, &ds_digest);
        let example_ds_rrsig = sign_rrset(&[&example_ds], "example.com", DnsType::Ds, root_key_tag, &root_pair);

        // Trust anchor for "." matching the root key.
        let root_digest = compute_ds_digest(&[0u8], &root_dnskey.rdata, 2).unwrap();
        let mut trust = DnssecTrustAnchor::empty();
        trust.add_anchor(".", root_key_tag, 15, 2, &root_digest);

        let (mut walk, step) = DnssecChainWalk::start(trust, "example.com");
        assert_eq!(step, ChainStep::NeedDnskey(".".to_string()));

        let root_dnskey_msg = DnsMessage::new(1, 0, vec![], vec![root_dnskey, root_dnskey_rrsig], vec![], vec![]);
        let step = walk.on_dnskey_response(&root_dnskey_msg);
        assert_eq!(step, ChainStep::NeedDs("com".to_string()));

        // No DS at "com." — must be skipped, not fail the whole walk.
        let empty_msg = DnsMessage::new(2, 0, vec![], vec![], vec![], vec![]);
        let step = walk.on_ds_response(&empty_msg);
        assert_eq!(step, ChainStep::NeedDs("example.com".to_string()));

        let ds_msg = DnsMessage::new(3, 0, vec![], vec![example_ds, example_ds_rrsig], vec![], vec![]);
        let step = walk.on_ds_response(&ds_msg);
        assert_eq!(step, ChainStep::NeedDnskey("example.com".to_string()));

        let example_dnskey_msg =
            DnsMessage::new(4, 0, vec![], vec![example_dnskey.clone(), example_dnskey_rrsig], vec![], vec![]);
        let step = walk.on_dnskey_response(&example_dnskey_msg);
        match step {
            ChainStep::Done { zone, key } => {
                assert_eq!(zone, "example.com");
                assert_eq!(*key, example_dnskey);
            }
            other => panic!("expected Done, got {other:?}"),
        }
    }

    /// A DS RRset that claims to be signed but isn't actually verifiable
    /// against the parent's trusted key must fail the walk (Bogus), not
    /// silently be accepted.
    #[test]
    fn chain_walk_rejects_a_ds_rrset_with_a_bad_signature() {
        let (root_pair, root_pub) = generate_ed25519();
        let (_wrong_pair, _wrong_pub) = generate_ed25519();
        let (forger_pair, _) = generate_ed25519(); // signs with the WRONG key

        let root_dnskey = DnsResourceRecord::dnskey(".", 3600, 257, 15, &root_pub);
        let root_key_tag = root_dnskey.dnskey_key_tag().unwrap();
        let root_dnskey_rrsig = sign_rrset(&[&root_dnskey], ".", DnsType::Dnskey, root_key_tag, &root_pair);

        let example_ds = DnsResourceRecord::ds("example.com", 3600, 12345, 15, 2, &[0xaa; 32]);
        // Signed by an unrelated key, not the trusted root key.
        let bogus_rrsig = sign_rrset(&[&example_ds], "example.com", DnsType::Ds, root_key_tag, &forger_pair);

        let root_digest = compute_ds_digest(&[0u8], &root_dnskey.rdata, 2).unwrap();
        let mut trust = DnssecTrustAnchor::empty();
        trust.add_anchor(".", root_key_tag, 15, 2, &root_digest);

        let (mut walk, _step) = DnssecChainWalk::start(trust, "example.com");
        let root_dnskey_msg = DnsMessage::new(1, 0, vec![], vec![root_dnskey, root_dnskey_rrsig], vec![], vec![]);
        walk.on_dnskey_response(&root_dnskey_msg);
        walk.on_ds_response(&DnsMessage::new(2, 0, vec![], vec![], vec![], vec![])); // skip "com."

        let ds_msg = DnsMessage::new(3, 0, vec![], vec![example_ds, bogus_rrsig], vec![], vec![]);
        assert_eq!(walk.on_ds_response(&ds_msg), ChainStep::Failed(DnssecStatus::Bogus));
    }

    #[test]
    fn chain_walk_is_indeterminate_with_no_covering_trust_anchor() {
        let (_walk, step) = DnssecChainWalk::start(DnssecTrustAnchor::empty(), "example.com");
        assert_eq!(step, ChainStep::Failed(DnssecStatus::Indeterminate));
    }
}
