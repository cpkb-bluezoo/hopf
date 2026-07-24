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

/// Async chain walker stub — currently delegates to in-message validation.
pub struct DnssecChainValidator {
    validator: DnssecValidator,
}

impl DnssecChainValidator {
    /// Wrap a validator.
    pub fn new(validator: DnssecValidator) -> Self {
        Self { validator }
    }

    /// Validate using records present in `msg`.
    pub fn validate(&self, msg: &DnsMessage) -> DnssecStatus {
        self.validator.validate_message(msg)
    }

    /// Access inner validator.
    pub fn inner(&self) -> &DnssecValidator {
        &self.validator
    }
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
}
