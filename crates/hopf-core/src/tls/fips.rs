// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! The approved ("FIPS") TLS profile: which cipher suites, key-exchange groups
//! and signature algorithms a handshake in FIPS mode may use.
//!
//! The profile is AES-GCM with SHA-256 or SHA-384, ECDHE on secp256r1 and
//! secp384r1, and ECDSA or RSA signatures. ChaCha20-Poly1305, X25519,
//! Ed25519, ML-DSA and the hybrid ML-KEM groups are outside it, Encrypted
//! Client Hello is refused, and key logging records nothing.
//!
//! [`HandshakeConfig::with_fips_profile`] and [`Tls12Config::with_fips_profile`]
//! apply the profile to a config. A restriction left unset becomes the
//! profile; a config that is already narrower keeps its narrowing; one that
//! names anything outside the profile is rejected with a
//! [`FipsProfileError`] listing every offender.
//!
//! This module restricts what the handshake *negotiates*. Whether the
//! cryptography underneath is a validated module is a property of how the
//! crypto backend is built, not of this configuration.

use std::fmt;

use super::engine::{HandshakeConfig, AES_128_GCM_SHA256, AES_256_GCM_SHA384};
use super::tls12::engine::{
    Config as Tls12Config, ECDHE_ECDSA_AES128_GCM_SHA256, ECDHE_ECDSA_AES256_GCM_SHA384,
    ECDHE_RSA_AES128_GCM_SHA256, ECDHE_RSA_AES256_GCM_SHA384,
};
use super::tls12::messages::{NAMED_CURVE_SECP256R1, NAMED_CURVE_SECP384R1};
use crate::crypto::kx::NamedGroup;
use crate::crypto::kx_policy::KxPolicy;

/// TLS 1.3 cipher suites in the profile.
pub const TLS13_CIPHER_SUITES: &[u16] = &[AES_128_GCM_SHA256, AES_256_GCM_SHA384];

/// TLS 1.2 cipher suites in the profile.
pub const TLS12_CIPHER_SUITES: &[u16] = &[
    ECDHE_ECDSA_AES128_GCM_SHA256,
    ECDHE_RSA_AES128_GCM_SHA256,
    ECDHE_ECDSA_AES256_GCM_SHA384,
    ECDHE_RSA_AES256_GCM_SHA384,
];

/// TLS 1.3 key-exchange groups in the profile.
pub const GROUPS: &[NamedGroup] = &[NamedGroup::SecP256r1, NamedGroup::SecP384r1];

/// TLS 1.2 named curves in the profile.
pub const TLS12_CURVES: &[u16] = &[NAMED_CURVE_SECP256R1, NAMED_CURVE_SECP384R1];

/// TLS 1.3 `CertificateVerify` schemes in the profile: ECDSA P-256 / SHA-256,
/// ECDSA P-384 / SHA-384 and RSASSA-PSS (rsae) / SHA-256.
pub const TLS13_SIGNATURE_SCHEMES: &[u16] = &[0x0403, 0x0503, 0x0804];

/// TLS 1.2 signature algorithms in the profile: the TLS 1.3 ones plus RSA
/// PKCS#1 v1.5 / SHA-256, which TLS 1.2 still uses.
pub const TLS12_SIGNATURE_SCHEMES: &[u16] = &[0x0403, 0x0503, 0x0401, 0x0804];

/// Certificate-chain signature schemes in the profile: ECDSA P-256 / P-384
/// and RSA PKCS#1 v1.5 with SHA-256, SHA-384 and SHA-512.
pub const CERT_SIGNATURE_SCHEMES: &[u16] = &[0x0403, 0x0503, 0x0401, 0x0501, 0x0601];

/// A config outside the FIPS profile: one entry per offending item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FipsProfileError {
    /// What is outside the profile, e.g. `cipher_suites: 0x1303`.
    pub violations: Vec<String>,
}

impl FipsProfileError {
    /// FIPS mode was requested after the handshake had already started.
    pub(crate) fn too_late() -> Self {
        Self { violations: vec!["FIPS mode must be set before the handshake starts".into()] }
    }
}

impl From<FipsProfileError> for std::io::Error {
    fn from(err: FipsProfileError) -> Self {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, err)
    }
}

impl fmt::Display for FipsProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "configuration is outside the FIPS profile: {}", self.violations.join("; "))
    }
}

impl std::error::Error for FipsProfileError {}

/// Violations for each entry of `configured` that is not in `allowed`.
fn outside(field: &str, configured: &[u16], allowed: &[u16], out: &mut Vec<String>) {
    for code in configured.iter().filter(|c| !allowed.contains(c)) {
        out.push(format!("{field}: 0x{code:04x}"));
    }
}

/// The configured list narrowed to the profile, or the profile when unset.
fn narrowed(configured: &Option<Vec<u16>>, profile: &[u16]) -> Vec<u16> {
    configured.clone().unwrap_or_else(|| profile.to_vec())
}

impl HandshakeConfig {
    /// A TLS 1.3 config on the FIPS profile: its default, with the profile
    /// applied (see [`Self::with_fips_profile`]).
    pub fn fips_profile() -> Self {
        Self::default()
            .with_fips_profile()
            .expect("the default config names nothing outside the profile")
    }

    /// Hold this config to the FIPS profile.
    ///
    /// `cipher_suites`, `signature_schemes`, `cert_signature_schemes` and the
    /// TLS 1.2 fallback suites are set to the profile when unset and must be
    /// subsets of it otherwise. `kx_policy` becomes [`KxPolicy::nist_only`]
    /// when it is one of the two stock policies (`default` / `classical_only`)
    /// and must otherwise name only secp256r1 and secp384r1. `ech_client`,
    /// `ech_server` and `key_log` must be unset. Narrowing is therefore
    /// allowed and widening is an error naming every offender.
    ///
    /// The result has [`Self::fips`] set, which also keeps the process-wide
    /// default key log from recording anything.
    pub fn with_fips_profile(mut self) -> Result<Self, FipsProfileError> {
        let mut violations = Vec::new();
        if let Some(suites) = &self.cipher_suites {
            outside("cipher_suites", suites, TLS13_CIPHER_SUITES, &mut violations);
        }
        if let Some(schemes) = &self.signature_schemes {
            outside("signature_schemes", schemes, TLS13_SIGNATURE_SCHEMES, &mut violations);
        }
        if let Some(schemes) = &self.cert_signature_schemes {
            outside("cert_signature_schemes", schemes, CERT_SIGNATURE_SCHEMES, &mut violations);
        }
        if let Some(suites) = &self.tls12_cipher_suites {
            outside("tls12_cipher_suites", suites, TLS12_CIPHER_SUITES, &mut violations);
        }
        let stock_kx = self.kx_policy == KxPolicy::default() || self.kx_policy == KxPolicy::classical_only();
        if !stock_kx {
            for group in self.kx_policy.groups().iter().filter(|g| !GROUPS.contains(g)) {
                violations.push(format!("kx_policy: {group:?}"));
            }
        }
        if self.ech_client.is_some() {
            violations.push("ech_client: Encrypted Client Hello is not permitted".into());
        }
        if self.ech_server.is_some() {
            violations.push("ech_server: Encrypted Client Hello is not permitted".into());
        }
        if self.key_log.is_some() {
            violations.push("key_log: key logging is not permitted".into());
        }
        if !violations.is_empty() {
            return Err(FipsProfileError { violations });
        }

        self.cipher_suites = Some(narrowed(&self.cipher_suites, TLS13_CIPHER_SUITES));
        self.signature_schemes = Some(narrowed(&self.signature_schemes, TLS13_SIGNATURE_SCHEMES));
        self.cert_signature_schemes = Some(narrowed(&self.cert_signature_schemes, CERT_SIGNATURE_SCHEMES));
        self.tls12_cipher_suites = Some(narrowed(&self.tls12_cipher_suites, TLS12_CIPHER_SUITES));
        if stock_kx {
            self.kx_policy = KxPolicy::nist_only();
        }
        self.fips = true;
        Ok(self)
    }
}

impl Tls12Config {
    /// A TLS 1.2 config on the FIPS profile: its default, with the profile
    /// applied (see [`Self::with_fips_profile`]).
    pub fn fips_profile() -> Self {
        Self::default()
            .with_fips_profile()
            .expect("the default config names nothing outside the profile")
    }

    /// Hold this config to the FIPS profile, as
    /// [`HandshakeConfig::with_fips_profile`] does for TLS 1.3: unset
    /// `cipher_suites`, `curves`, `signature_schemes` and
    /// `cert_signature_schemes` become the profile, set ones must be subsets
    /// of it, and anything outside is an error naming every offender.
    pub fn with_fips_profile(mut self) -> Result<Self, FipsProfileError> {
        let mut violations = Vec::new();
        if let Some(suites) = &self.cipher_suites {
            outside("cipher_suites", suites, TLS12_CIPHER_SUITES, &mut violations);
        }
        if let Some(curves) = &self.curves {
            for curve in curves.iter().filter(|c| !TLS12_CURVES.contains(c)) {
                violations.push(format!("curves: {curve}"));
            }
        }
        if let Some(schemes) = &self.signature_schemes {
            outside("signature_schemes", schemes, TLS12_SIGNATURE_SCHEMES, &mut violations);
        }
        if let Some(schemes) = &self.cert_signature_schemes {
            outside("cert_signature_schemes", schemes, CERT_SIGNATURE_SCHEMES, &mut violations);
        }
        if !violations.is_empty() {
            return Err(FipsProfileError { violations });
        }
        self.cipher_suites = Some(narrowed(&self.cipher_suites, TLS12_CIPHER_SUITES));
        self.curves = Some(narrowed(&self.curves, TLS12_CURVES));
        self.signature_schemes = Some(narrowed(&self.signature_schemes, TLS12_SIGNATURE_SCHEMES));
        self.cert_signature_schemes = Some(narrowed(&self.cert_signature_schemes, CERT_SIGNATURE_SCHEMES));
        Ok(self)
    }
}
