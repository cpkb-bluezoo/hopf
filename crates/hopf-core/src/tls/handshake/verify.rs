// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! TLS 1.3 CertificateVerify signing and verification (RFC 8446 §4.4.3).

use bytes::{Bytes, BytesMut};

use crate::asn1::{parse_sequence, read_bit_string_content, read_oid};
use crate::crypto::cert::extract_spki;
use crate::crypto::signature::{
    ecdsa_p256_sha256_verify_spki, ecdsa_p256_sign, ecdsa_p384_sha384_verify_spki, ecdsa_p384_sign,
    ed25519_sign, ed25519_verify, ml_dsa_sign, ml_dsa_verify_spki, rsa_pss_sha256_verify_spki,
    rsa_sign_pss_sha256, EcdsaP256PrivateKey, EcdsaP384PrivateKey, Ed25519PrivateKey, MlDsaLevel,
    MlDsaPrivateKey, RsaPrivateKey, SignatureBytes,
};

use super::key_schedule::TranscriptHash;

/// IANA `SignatureScheme` for Ed25519 (RFC 8446 §4.2.3).
pub const SIG_ED25519: u16 = 0x0807;
/// IANA `SignatureScheme` for ECDSA P-256 + SHA-256 (RFC 8446 §4.2.3).
pub const SIG_ECDSA_SECP256R1_SHA256: u16 = 0x0403;
/// IANA `SignatureScheme` for ECDSA P-384 + SHA-384 (RFC 8446 §4.2.3).
pub const SIG_ECDSA_SECP384R1_SHA384: u16 = 0x0503;
/// IANA `SignatureScheme` for RSA-PSS-RSAE + SHA-256 (RFC 8446 §4.2.3) — TLS 1.3
/// forbids PKCS#1 v1.5 (`rsa_pkcs1_*`) in `CertificateVerify`; RSA certs use this instead.
pub const SIG_RSA_PSS_RSAE_SHA256: u16 = 0x0804;

/// Schemes advertised in ClientHello's `signature_algorithms` (RFC 8446 §4.2.3) and
/// accepted when verifying a peer's `CertificateVerify`, in preference order.
/// P-384 and RSA-PSS cover real-world WebPKI leaves; the pure ML-DSA schemes
/// (`mldsa44`/`mldsa65`/`mldsa87`, FIPS 204) let a peer with a post-quantum key
/// authenticate; broader RSA hash widths are not implemented yet.
pub const SUPPORTED_SIGNATURE_SCHEMES: &[u16] = &[
    SIG_ED25519,
    SIG_ECDSA_SECP256R1_SHA256,
    SIG_ECDSA_SECP384R1_SHA384,
    SIG_RSA_PSS_RSAE_SHA256,
    MlDsaLevel::MlDsa44.signature_scheme(),
    MlDsaLevel::MlDsa65.signature_scheme(),
    MlDsaLevel::MlDsa87.signature_scheme(),
];

/// Build the signed payload for CertificateVerify.
pub fn certificate_verify_message(is_client: bool, transcript_hash: &TranscriptHash) -> Bytes {
    let context = if is_client {
        b"TLS 1.3, client CertificateVerify"
    } else {
        b"TLS 1.3, server CertificateVerify"
    };
    let mut out = BytesMut::with_capacity(64 + context.len() + 1 + 32);
    out.extend(core::iter::repeat_n(0x20u8, 64));
    out.extend_from_slice(context);
    out.extend_from_slice(&[0]);
    out.extend_from_slice(transcript_hash.as_bytes());
    out.freeze()
}

/// Sign CertificateVerify with whichever [`SUPPORTED_SIGNATURE_SCHEMES`] scheme
/// matches `signing_key_pkcs8`'s own key type (sniffed from the PKCS#8
/// `AlgorithmIdentifier` — server credentials carry a bare key, not a declared
/// scheme). Returns `None` for a key type or curve this crate doesn't sign with.
pub fn sign_certificate_verify(
    is_client: bool,
    signing_key_pkcs8: &[u8],
    transcript_hash: &TranscriptHash,
) -> Option<(u16, SignatureBytes)> {
    let msg = certificate_verify_message(is_client, transcript_hash);
    // ML-DSA keys have no TLS 1.2 form, so they live outside `KeyKind`.
    if let Some(level) = pkcs8_ml_dsa_level(signing_key_pkcs8) {
        let key = MlDsaPrivateKey::from_pkcs8(level, signing_key_pkcs8).ok()?;
        return Some((level.signature_scheme(), ml_dsa_sign(&key, &msg).ok()?));
    }
    match pkcs8_key_kind(signing_key_pkcs8)? {
        KeyKind::Ed25519 => {
            let key = Ed25519PrivateKey::from_pkcs8(signing_key_pkcs8).ok()?;
            Some((SIG_ED25519, ed25519_sign(&key, &msg)))
        }
        KeyKind::EcdsaP256 => {
            let key = EcdsaP256PrivateKey::from_pkcs8(signing_key_pkcs8).ok()?;
            Some((SIG_ECDSA_SECP256R1_SHA256, ecdsa_p256_sign(&key, &msg).ok()?))
        }
        KeyKind::EcdsaP384 => {
            let key = EcdsaP384PrivateKey::from_pkcs8(signing_key_pkcs8).ok()?;
            Some((SIG_ECDSA_SECP384R1_SHA384, ecdsa_p384_sign(&key, &msg).ok()?))
        }
        KeyKind::Rsa => {
            let key = RsaPrivateKey::from_pkcs8(signing_key_pkcs8).ok()?;
            Some((SIG_RSA_PSS_RSAE_SHA256, rsa_sign_pss_sha256(&key, &msg).ok()?))
        }
    }
}

/// Verify a peer CertificateVerify signature against a leaf certificate DER.
pub fn verify_certificate_verify(
    peer_is_client: bool,
    leaf_cert_der: &[u8],
    scheme: u16,
    signature: &[u8],
    transcript_hash: &TranscriptHash,
) -> bool {
    let Some(spki) = extract_spki(leaf_cert_der) else {
        return false;
    };
    let msg = certificate_verify_message(peer_is_client, transcript_hash);
    let signature = SignatureBytes::from_bytes(Bytes::copy_from_slice(signature));
    match scheme {
        SIG_ED25519 => {
            let Some(pk) = ed25519_public_key_from_spki(spki.as_ref()) else {
                return false;
            };
            ed25519_verify(&pk, &msg, &signature)
        }
        SIG_ECDSA_SECP256R1_SHA256 => ecdsa_p256_sha256_verify_spki(&spki, &msg, &signature),
        SIG_ECDSA_SECP384R1_SHA384 => ecdsa_p384_sha384_verify_spki(&spki, &msg, &signature),
        SIG_RSA_PSS_RSAE_SHA256 => rsa_pss_sha256_verify_spki(&spki, &msg, &signature),
        _ => match MlDsaLevel::from_signature_scheme(scheme) {
            Some(level) => ml_dsa_verify_spki(level, spki.as_ref(), &msg, &signature),
            None => false,
        },
    }
}

/// Key type sniffed from a PKCS#8 `AlgorithmIdentifier`, to pick a
/// `CertificateVerify` scheme without requiring the caller to declare one
/// alongside their PEM-loaded key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyKind {
    Ed25519,
    EcdsaP256,
    EcdsaP384,
    Rsa,
}

const OID_RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];
const OID_SECP256R1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_SECP384R1: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];

/// `PrivateKeyInfo ::= SEQUENCE { version INTEGER, algorithm AlgorithmIdentifier, ... }`
/// (RFC 5958) — reads just the algorithm OID (and, for EC keys, the curve OID) to
/// classify the key; never touches the private key material itself.
pub(crate) fn pkcs8_key_kind(pkcs8_der: &[u8]) -> Option<KeyKind> {
    let mut outer = parse_sequence(pkcs8_der)?;
    let _version = outer.next()?;
    let algorithm = outer.next()?;
    let mut algo_seq = parse_sequence(algorithm)?;
    let oid = read_oid(algo_seq.next()?)?;
    match oid {
        OID_ED25519 => Some(KeyKind::Ed25519),
        OID_RSA_ENCRYPTION => Some(KeyKind::Rsa),
        OID_EC_PUBLIC_KEY => match read_oid(algo_seq.next()?)? {
            OID_SECP256R1 => Some(KeyKind::EcdsaP256),
            OID_SECP384R1 => Some(KeyKind::EcdsaP384),
            _ => None,
        },
        _ => None,
    }
}

/// The ML-DSA parameter set of a PKCS#8 key, read from its `AlgorithmIdentifier`
/// alone. `None` for any other key type (including malformed input).
pub(crate) fn pkcs8_ml_dsa_level(pkcs8_der: &[u8]) -> Option<MlDsaLevel> {
    let mut outer = parse_sequence(pkcs8_der)?;
    let _version = outer.next()?;
    let mut algo_seq = parse_sequence(outer.next()?)?;
    MlDsaLevel::from_oid(read_oid(algo_seq.next()?)?)
}

/// Extract a 32-byte Ed25519 public key from SPKI DER.
pub(crate) fn ed25519_public_key_from_spki(spki: &[u8]) -> Option<[u8; 32]> {
    // SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey BIT STRING }
    let mut outer = parse_sequence(spki)?;
    let _alg = outer.next()?;
    let bit_string = outer.next()?;
    let key = read_bit_string_content(bit_string)?;
    <[u8; 32]>::try_from(key).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::signature::{Ed25519PrivateKey, MlDsaLevel};

    #[test]
    fn ed25519_certificate_verify_roundtrip() {
        let doc = Ed25519PrivateKey::generate_pkcs8().unwrap();
        let key = Ed25519PrivateKey::from_pkcs8(&doc).unwrap();
        let th = TranscriptHash::from_bytes([0xabu8; 32]);
        let (scheme, sig) = sign_certificate_verify(false, &doc, &th).expect("Ed25519 key recognized");
        assert_eq!(scheme, SIG_ED25519);
        let msg = certificate_verify_message(false, &th);
        assert_eq!(msg.len(), 64 + 32 + 1 + "TLS 1.3, server CertificateVerify".len());
        assert!(ed25519_verify(key.public_key_bytes(), msg.as_ref(), &sig));
    }

    fn ml_dsa_identity(level: MlDsaLevel) -> crate::crypto::x509::MlDsaIdentity {
        crate::crypto::x509::generate_ml_dsa_self_signed(&["localhost"], level).unwrap()
    }

    /// A server (or client) holding an ML-DSA key signs `CertificateVerify`
    /// under the matching `mldsaNN` scheme and a peer verifies it against the
    /// certificate - at every parameter set, and only for the right scheme,
    /// role and transcript.
    #[test]
    fn ml_dsa_certificate_verify_round_trips_at_every_level() {
        let th = TranscriptHash::from_bytes([0x5au8; 32]);
        for level in MlDsaLevel::ALL {
            let id = ml_dsa_identity(level);
            let (scheme, sig) =
                sign_certificate_verify(false, &id.pkcs8_der, &th).unwrap_or_else(|| panic!("{level:?} key not signable"));
            assert_eq!(scheme, level.signature_scheme());
            assert!(verify_certificate_verify(false, &id.cert_der, scheme, sig.as_bytes(), &th), "{level:?}");

            // Wrong role context, wrong transcript, flipped bit, other level's scheme.
            assert!(!verify_certificate_verify(true, &id.cert_der, scheme, sig.as_bytes(), &th));
            let other_th = TranscriptHash::from_bytes([0x5bu8; 32]);
            assert!(!verify_certificate_verify(false, &id.cert_der, scheme, sig.as_bytes(), &other_th));
            let mut bad = sig.as_bytes().to_vec();
            bad[10] ^= 1;
            assert!(!verify_certificate_verify(false, &id.cert_der, scheme, &bad, &th));
            for other in MlDsaLevel::ALL.into_iter().filter(|l| *l != level) {
                assert!(!verify_certificate_verify(false, &id.cert_der, other.signature_scheme(), sig.as_bytes(), &th));
            }
        }
    }

    /// The ML-DSA schemes are offered in `signature_algorithms`, so a peer
    /// holding such a key knows we can verify it.
    #[test]
    fn ml_dsa_schemes_are_advertised() {
        for level in MlDsaLevel::ALL {
            assert!(SUPPORTED_SIGNATURE_SCHEMES.contains(&level.signature_scheme()), "{level:?}");
        }
    }
}
