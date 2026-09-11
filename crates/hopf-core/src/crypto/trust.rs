// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Trust anchor storage and TLS server chain verification.

use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;

use super::x509::{matches_hostname, parse_certificate, verify_cert_signature, ParsedCertificate};

/// A certificate's Subject field, DER-encoded (RDNSequence). Distinct from
/// [`SpkiDer`] so [`TrustStore::add_component_anchor`]'s two same-shaped
/// DER blobs can't be passed in the wrong order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubjectDer(Bytes);

impl SubjectDer {
    /// Wrap already-encoded Subject DER bytes.
    pub fn from_bytes(der: Bytes) -> Self {
        Self(der)
    }

    /// Borrow the DER bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A certificate's SubjectPublicKeyInfo, DER-encoded. See [`SubjectDer`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpkiDer(Bytes);

impl SpkiDer {
    /// Wrap already-encoded SubjectPublicKeyInfo DER bytes.
    pub fn from_bytes(der: Bytes) -> Self {
        Self(der)
    }

    /// Borrow the DER bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A trust anchor known only by its subject and public key — no full
/// certificate. This is what compiled-in root bundles (e.g. `webpki-roots`)
/// provide, since a self-trusted anchor never needs its own signature or
/// validity checked to terminate chain building; it just can't participate
/// in the "the peer presented the anchor certificate itself" exact-match
/// shortcut that a full-DER anchor can (see [`TrustStore::add_anchor`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComponentAnchor {
    /// Anchor's Subject DER (as it appears in a cert it issued).
    pub subject_der: SubjectDer,
    /// Anchor's SubjectPublicKeyInfo DER.
    pub spki_der: SpkiDer,
}

/// Collection of trust anchors (typically self-signed root CAs) — either
/// full DER certificates or subject+SPKI-only [`ComponentAnchor`]s.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrustStore {
    anchors: Vec<Bytes>,
    component_anchors: Vec<ComponentAnchor>,
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

    /// Add a subject+SPKI-only trust anchor (see [`ComponentAnchor`]).
    pub fn add_component_anchor(&mut self, subject_der: SubjectDer, spki_der: SpkiDer) {
        self.component_anchors.push(ComponentAnchor { subject_der, spki_der });
    }

    /// Immutable view of stored full-DER anchors.
    pub fn anchors(&self) -> &[Bytes] {
        &self.anchors
    }

    /// Immutable view of stored component (subject+SPKI-only) anchors.
    pub fn component_anchors(&self) -> &[ComponentAnchor] {
        &self.component_anchors
    }

    /// Number of anchors (both full-DER and component).
    pub fn len(&self) -> usize {
        self.anchors.len() + self.component_anchors.len()
    }

    /// Whether the store has no anchors at all.
    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty() && self.component_anchors.is_empty()
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

/// The public WebPKI root set: the OS's own trust store
/// ([`rustls_native_certs`]) when it can be read, falling back to a
/// vendored copy of Mozilla's CA root list ([`webpki_roots`]) otherwise.
pub fn public_trust_store() -> TrustStore {
    let native = rustls_native_certs::load_native_certs()
        .certs
        .into_iter()
        .map(|c| Bytes::copy_from_slice(c.as_ref()))
        .collect();
    public_trust_store_from(native)
}

/// [`public_trust_store`], given already-loaded native certs (full DER) —
/// split out so the fallback behavior is testable without depending on
/// what happens to be trusted on the machine running the test. A handful of
/// platform trust stores carry anchors this crate's minimal X.509 parser
/// can't parse (e.g. non-conformant self-issued roots); those are silently
/// skipped at verification time ([`verify_server_chain`]'s `filter_map`),
/// not here — an anchor that fails to parse is simply never matched, rather
/// than aborting the whole load over one bad entry.
pub fn public_trust_store_from(native_certs: Vec<Bytes>) -> TrustStore {
    let mut store = TrustStore::new();
    for der in native_certs {
        store.add_anchor(der);
    }
    if store.is_empty() {
        for anchor in webpki_roots::TLS_SERVER_ROOTS {
            store.add_component_anchor(
                SubjectDer::from_bytes(Bytes::copy_from_slice(anchor.subject.as_ref())),
                SpkiDer::from_bytes(Bytes::copy_from_slice(anchor.subject_public_key_info.as_ref())),
            );
        }
    }
    store
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

    let parsed_anchors: Vec<ParsedCertificate> = store
        .anchors()
        .iter()
        .filter_map(|der| parse_certificate(der))
        .collect();
    let anchors: Vec<AnchorRef<'_>> = parsed_anchors
        .iter()
        .map(|a| AnchorRef {
            subject_der: &a.subject_der,
            spki_der: &a.spki_der,
            full_der: Some(&a.der),
        })
        .chain(store.component_anchors().iter().map(|a| AnchorRef {
            subject_der: a.subject_der.as_bytes(),
            spki_der: a.spki_der.as_bytes(),
            full_der: None,
        }))
        .collect();

    build_and_verify_chain(&leaf, &intermediates, &anchors)?;
    Ok(())
}

/// A trust anchor as chain-building sees it — either a full parsed
/// certificate ([`TrustStore::add_anchor`]) or a [`ComponentAnchor`]; only
/// the former can satisfy the "peer presented the anchor itself" shortcut.
struct AnchorRef<'a> {
    subject_der: &'a [u8],
    spki_der: &'a [u8],
    full_der: Option<&'a [u8]>,
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
    anchors: &[AnchorRef<'_>],
) -> Result<(), VerifyError> {
    let mut current = leaf;
    let mut pool: Vec<&ParsedCertificate> = intermediates.iter().collect();

    loop {
        if anchors.iter().any(|a| a.full_der == Some(current.der.as_ref())) {
            return Ok(());
        }

        match find_issuer(current, &pool, anchors) {
            None => return Err(VerifyError::UnknownIssuer),
            Some(Issuer::Anchor(anchor)) => {
                if !verify_cert_signature(current, anchor.spki_der) {
                    return Err(VerifyError::SignatureInvalid);
                }
                return Ok(());
            }
            Some(Issuer::Intermediate(cert)) => {
                if !verify_cert_signature(current, &cert.spki_der) {
                    return Err(VerifyError::SignatureInvalid);
                }
                pool.retain(|c| c.der != cert.der);
                current = cert;
            }
        }
    }
}

enum Issuer<'a> {
    Intermediate(&'a ParsedCertificate),
    Anchor(&'a AnchorRef<'a>),
}

fn find_issuer<'a>(
    child: &ParsedCertificate,
    pool: &[&'a ParsedCertificate],
    anchors: &'a [AnchorRef<'a>],
) -> Option<Issuer<'a>> {
    for cert in pool {
        if cert.subject_der == child.issuer_der {
            return Some(Issuer::Intermediate(cert));
        }
    }
    for anchor in anchors {
        if anchor.subject_der == child.issuer_der {
            return Some(Issuer::Anchor(anchor));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// When native loading yields nothing usable (simulated here by passing
    /// an empty cert list, which is exactly what a native-certs read
    /// failure or an empty OS store degrades to), the public-trust store
    /// must fall back to the vendored webpki-roots list rather than
    /// silently trusting nothing at all.
    #[test]
    fn public_trust_store_falls_back_to_webpki_roots_when_native_yields_nothing() {
        let store = public_trust_store_from(Vec::new());
        assert_eq!(store.component_anchors().len(), webpki_roots::TLS_SERVER_ROOTS.len());
        assert!(store.anchors().is_empty());
        assert!(!store.is_empty());
    }

    /// Companion to the fallback test above: when native certs *are*
    /// present, they must be preferred outright — the fallback list must
    /// not also be merged in alongside them.
    #[test]
    fn public_trust_store_prefers_native_certs_over_the_fallback() {
        let (der, _) = ed25519_cert("example.invalid");
        let store = public_trust_store_from(vec![Bytes::copy_from_slice(&der)]);
        assert_eq!(store.anchors().len(), 1);
        assert!(store.component_anchors().is_empty());
    }

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

    /// Same chain as [`ca_signed_chain_to_trusted_root`], but the root is
    /// registered as a [`ComponentAnchor`] (subject + SPKI only, no full
    /// DER) — the shape `webpki-roots`-style compiled-in bundles provide,
    /// since `TrustStore::add_anchor` needs a real parseable certificate.
    #[test]
    fn ca_signed_chain_to_component_anchor_root() {
        let root_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut root_params = rcgen::CertificateParams::new(vec![]).unwrap();
        root_params.distinguished_name = rcgen::DistinguishedName::new();
        root_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Hopf Test Root CA");
        root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let root = root_params.self_signed(&root_key).unwrap();

        let leaf_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let leaf_params = rcgen::CertificateParams::new(vec!["secure.example".into()]).unwrap();
        let leaf = leaf_params.signed_by(&leaf_key, &root, &root_key).unwrap();

        let parsed_root = parse_certificate(root.der()).unwrap();
        let mut store = TrustStore::new();
        store.add_component_anchor(
            SubjectDer::from_bytes(parsed_root.subject_der.clone()),
            SpkiDer::from_bytes(parsed_root.spki_der.clone()),
        );

        store
            .verify_server_chain(&[Bytes::copy_from_slice(leaf.der())], Some("secure.example"))
            .expect("valid chain via component anchor");
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
