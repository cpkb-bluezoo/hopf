// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Trust anchor storage and TLS server chain verification.

use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;

use super::x509::{matches_hostname, parse_certificate, verify_cert_signature, ParsedCertificate};

/// Collection of DER-encoded trust anchors (typically self-signed root CAs).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrustStore {
    anchors: Vec<Bytes>,
}

/// Chain or hostname verification failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    /// No certificates in the peer chain.
    EmptyChain,
    /// Certificate could not be parsed.
    MalformedCertificate,
    /// No trusted issuer found for the chain.
    UnknownIssuer,
    /// Signature check failed.
    SignatureInvalid,
    /// Certificate is not yet valid.
    NotYetValid,
    /// Certificate has expired.
    Expired,
    /// SNI hostname does not match the leaf certificate.
    HostnameMismatch,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyChain => write!(f, "empty certificate chain"),
            Self::MalformedCertificate => write!(f, "malformed certificate"),
            Self::UnknownIssuer => write!(f, "unknown issuer"),
            Self::SignatureInvalid => write!(f, "invalid certificate signature"),
            Self::NotYetValid => write!(f, "certificate not yet valid"),
            Self::Expired => write!(f, "certificate expired"),
            Self::HostnameMismatch => write!(f, "hostname mismatch"),
        }
    }
}

impl TrustStore {
    /// Empty store — caller must add anchors before verification.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a DER-encoded trust anchor.
    pub fn add_anchor(&mut self, der: Bytes) {
        self.anchors.push(der);
    }

    /// Add a DER-encoded trust anchor from an owned byte vector.
    pub fn add_anchor_der(&mut self, der: Vec<u8>) {
        self.add_anchor(Bytes::from(der));
    }

    /// Immutable view of stored anchors.
    pub fn anchors(&self) -> &[Bytes] {
        &self.anchors
    }

    /// Number of anchors.
    pub fn len(&self) -> usize {
        self.anchors.len()
    }

    /// Whether the store has no anchors.
    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }

    /// Verify a TLS server certificate chain and optional SNI hostname.
    pub fn verify_server_chain(
        &self,
        chain: &[Bytes],
        server_name: Option<&str>,
    ) -> Result<(), VerifyError> {
        verify_server_chain(self, chain, server_name, SystemTime::now())
    }
}

/// Verify a TLS server chain against `store` at `now`.
pub fn verify_server_chain(
    store: &TrustStore,
    chain: &[Bytes],
    server_name: Option<&str>,
    now: SystemTime,
) -> Result<(), VerifyError> {
    if chain.is_empty() {
        return Err(VerifyError::EmptyChain);
    }
    if store.is_empty() {
        return Err(VerifyError::UnknownIssuer);
    }

    let now_secs = now
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let leaf = parse_certificate(&chain[0]).ok_or(VerifyError::MalformedCertificate)?;
    check_validity(&leaf, now_secs)?;

    if let Some(name) = server_name {
        if !name.is_empty() && !matches_hostname(&leaf, name) {
            return Err(VerifyError::HostnameMismatch);
        }
    }

    let intermediates: Vec<ParsedCertificate> = chain[1..]
        .iter()
        .filter_map(|der| parse_certificate(der))
        .collect();

    let anchors: Vec<ParsedCertificate> = store
        .anchors()
        .iter()
        .filter_map(|der| parse_certificate(der))
        .collect();

    build_and_verify_chain(&leaf, &intermediates, &anchors)?;
    Ok(())
}

fn check_validity(cert: &ParsedCertificate, now: u64) -> Result<(), VerifyError> {
    if now < cert.not_before {
        return Err(VerifyError::NotYetValid);
    }
    if now > cert.not_after {
        return Err(VerifyError::Expired);
    }
    Ok(())
}

fn build_and_verify_chain(
    leaf: &ParsedCertificate,
    intermediates: &[ParsedCertificate],
    anchors: &[ParsedCertificate],
) -> Result<(), VerifyError> {
    let mut current = leaf;
    let mut pool: Vec<&ParsedCertificate> = intermediates.iter().collect();

    loop {
        if anchors.iter().any(|a| a.der == current.der) {
            return Ok(());
        }

        let issuer = find_issuer(current, &pool, anchors).ok_or(VerifyError::UnknownIssuer)?;
        if !verify_cert_signature(current, &issuer.spki_der) {
            return Err(VerifyError::SignatureInvalid);
        }

        if anchors.iter().any(|a| a.subject_der == issuer.subject_der) {
            return Ok(());
        }

        pool.retain(|c| c.der != issuer.der);
        current = issuer;
    }
}

fn find_issuer<'a>(
    child: &ParsedCertificate,
    pool: &[&'a ParsedCertificate],
    anchors: &'a [ParsedCertificate],
) -> Option<&'a ParsedCertificate> {
    for cert in pool {
        if cert.subject_der == child.issuer_der {
            return Some(cert);
        }
    }
    for anchor in anchors {
        if anchor.subject_der == child.issuer_der {
            return Some(anchor);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ed25519_cert(dns: &str) -> (Vec<u8>, rcgen::KeyPair) {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut params = rcgen::CertificateParams::new(vec![dns.into()]).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, dns);
        let cert = params.self_signed(&key).unwrap();
        (cert.der().to_vec(), key)
    }

    #[test]
    fn self_signed_anchor_accepts_leaf() {
        let (der, _) = ed25519_cert("localhost");
        let mut store = TrustStore::new();
        store.add_anchor(Bytes::copy_from_slice(&der));
        store
            .verify_server_chain(&[Bytes::copy_from_slice(&der)], Some("localhost"))
            .expect("valid");
    }

    #[test]
    fn wrong_hostname_rejected() {
        let (der, _) = ed25519_cert("example.com");
        let mut store = TrustStore::new();
        store.add_anchor(Bytes::copy_from_slice(&der));
        assert_eq!(
            store.verify_server_chain(&[Bytes::copy_from_slice(&der)], Some("localhost")),
            Err(VerifyError::HostnameMismatch)
        );
    }

    #[test]
    fn ca_signed_chain_to_trusted_root() {
        let root_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut root_params = rcgen::CertificateParams::new(vec![]).unwrap();
        root_params.distinguished_name = rcgen::DistinguishedName::new();
        root_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Hopf Test Root CA");
        root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let root = root_params.self_signed(&root_key).unwrap();

        let intermediate_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut intermediate_params = rcgen::CertificateParams::new(vec![]).unwrap();
        intermediate_params.distinguished_name = rcgen::DistinguishedName::new();
        intermediate_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Hopf Test Intermediate CA");
        intermediate_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        let intermediate = intermediate_params
            .signed_by(&intermediate_key, &root, &root_key)
            .unwrap();

        let leaf_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let leaf_params = rcgen::CertificateParams::new(vec!["secure.example".into()]).unwrap();
        let leaf = leaf_params
            .signed_by(&leaf_key, &intermediate, &intermediate_key)
            .unwrap();

        let mut store = TrustStore::new();
        store.add_anchor(Bytes::copy_from_slice(root.der()));

        store
            .verify_server_chain(
                &[
                    Bytes::copy_from_slice(leaf.der()),
                    Bytes::copy_from_slice(intermediate.der()),
                ],
                Some("secure.example"),
            )
            .expect("valid chain");
    }

    #[test]
    fn unrelated_leaf_rejected() {
        let root_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut root_params = rcgen::CertificateParams::new(vec![]).unwrap();
        root_params.distinguished_name = rcgen::DistinguishedName::new();
        root_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Hopf Test Root CA");
        root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let root = root_params.self_signed(&root_key).unwrap();

        let (bad_leaf, _) = ed25519_cert("bad.example");

        let mut store = TrustStore::new();
        store.add_anchor(Bytes::copy_from_slice(root.der()));

        assert_eq!(
            store.verify_server_chain(&[Bytes::copy_from_slice(&bad_leaf)], Some("bad.example")),
            Err(VerifyError::UnknownIssuer)
        );
    }
}
