// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Ephemeral key agreement (X25519 + hybrid ML-KEM) via AWS-LC.

use aws_lc_rs::agreement::{
    self, EphemeralPrivateKey, PrivateKey, UnparsedPublicKey, ECDH_P256, ECDH_P384, X25519,
};
use aws_lc_rs::error::{KeyRejected, Unspecified};
use aws_lc_rs::kem::{self, ML_KEM_1024, ML_KEM_768};
use bytes::{Bytes, BytesMut};

/// ML-KEM-768 encapsulation key length (client key share PQ component).
pub const MLKEM768_ENCAP_LEN: usize = 1184;
/// ML-KEM-768 ciphertext length (server key share PQ component).
pub const MLKEM768_CIPHERTEXT_LEN: usize = 1088;
/// ML-KEM-1024 encapsulation key length (client key share PQ component).
pub const MLKEM1024_ENCAP_LEN: usize = 1568;
/// ML-KEM-1024 ciphertext length (server key share PQ component).
pub const MLKEM1024_CIPHERTEXT_LEN: usize = 1568;
/// X25519 public key length.
pub const X25519_PUBLIC_LEN: usize = 32;
/// NIST P-256 uncompressed point length (`0x04 || X || Y`).
pub const P256_PUBLIC_LEN: usize = 65;
/// NIST P-384 uncompressed point length (`0x04 || X || Y`).
pub const P384_PUBLIC_LEN: usize = 97;

/// Named group for TLS 1.3 key shares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamedGroup {
    /// X25519 (RFC 8446 §4.2.7).
    X25519,
    /// Hybrid X25519 + ML-KEM-768 (RFC 10024, IANA 0x11ec). Concatenation
    /// order is PQ-first (ML-KEM share, then X25519 share) — an explicit,
    /// documented exception to the naming convention the other two hybrid
    /// groups below follow, kept "for historical reasons" (RFC 10024).
    X25519MLKEM768,
    /// Hybrid secp256r1 + ML-KEM-768 (RFC 10024, IANA 0x11eb).
    /// Concatenation order is classical-first (ECDHE share, then ML-KEM
    /// share) — matches the group's name, unlike `X25519MLKEM768`.
    SecP256r1MLKEM768,
    /// Hybrid secp384r1 + ML-KEM-1024 (RFC 10024, IANA 0x11ed).
    /// Classical-first, same as `SecP256r1MLKEM768`.
    SecP384r1MLKEM1024,
}

impl NamedGroup {
    /// IANA `NamedGroup` code point.
    pub fn code(self) -> u16 {
        match self {
            NamedGroup::X25519 => 0x001d,
            NamedGroup::X25519MLKEM768 => 0x11ec,
            NamedGroup::SecP256r1MLKEM768 => 0x11eb,
            NamedGroup::SecP384r1MLKEM1024 => 0x11ed,
        }
    }

    /// Parse from IANA code point.
    pub fn from_code(code: u16) -> Option<Self> {
        match code {
            0x001d => Some(NamedGroup::X25519),
            0x11ec => Some(NamedGroup::X25519MLKEM768),
            0x11eb => Some(NamedGroup::SecP256r1MLKEM768),
            0x11ed => Some(NamedGroup::SecP384r1MLKEM1024),
            _ => None,
        }
    }

    /// `true` if this hybrid group's wire concatenation and secret
    /// combiner both put the ML-KEM component first. Only
    /// `X25519MLKEM768` does (RFC 10024's documented historical
    /// exception) — the other two hybrid groups are classical-first, and
    /// plain `X25519` doesn't have an ML-KEM component at all (unused
    /// here, `false` is an arbitrary don't-care).
    fn pq_first(self) -> bool {
        matches!(self, NamedGroup::X25519MLKEM768)
    }

    /// Classical (non-PQ) component's public key length for a hybrid
    /// group. Unused for plain `X25519`.
    fn classical_public_len(self) -> usize {
        match self {
            NamedGroup::X25519 | NamedGroup::X25519MLKEM768 => X25519_PUBLIC_LEN,
            NamedGroup::SecP256r1MLKEM768 => P256_PUBLIC_LEN,
            NamedGroup::SecP384r1MLKEM1024 => P384_PUBLIC_LEN,
        }
    }

    /// ML-KEM algorithm backing this hybrid group. Unused for plain `X25519`.
    fn mlkem_algorithm(self) -> &'static kem::Algorithm<kem::AlgorithmId> {
        match self {
            NamedGroup::X25519 | NamedGroup::X25519MLKEM768 | NamedGroup::SecP256r1MLKEM768 => &ML_KEM_768,
            NamedGroup::SecP384r1MLKEM1024 => &ML_KEM_1024,
        }
    }

    /// ML-KEM encapsulation key length for this hybrid group's ML-KEM
    /// parameter set. Unused for plain `X25519`.
    fn mlkem_encap_len(self) -> usize {
        match self {
            NamedGroup::X25519 | NamedGroup::X25519MLKEM768 | NamedGroup::SecP256r1MLKEM768 => MLKEM768_ENCAP_LEN,
            NamedGroup::SecP384r1MLKEM1024 => MLKEM1024_ENCAP_LEN,
        }
    }

    /// ML-KEM ciphertext length for this hybrid group's ML-KEM parameter
    /// set. Unused for plain `X25519`.
    fn mlkem_ciphertext_len(self) -> usize {
        match self {
            NamedGroup::X25519 | NamedGroup::X25519MLKEM768 | NamedGroup::SecP256r1MLKEM768 => {
                MLKEM768_CIPHERTEXT_LEN
            }
            NamedGroup::SecP384r1MLKEM1024 => MLKEM1024_CIPHERTEXT_LEN,
        }
    }

    /// Expected client `KeyShareEntry` length for this group.
    pub fn client_share_len(self) -> usize {
        match self {
            NamedGroup::X25519 => X25519_PUBLIC_LEN,
            NamedGroup::X25519MLKEM768 | NamedGroup::SecP256r1MLKEM768 | NamedGroup::SecP384r1MLKEM1024 => {
                self.classical_public_len() + self.mlkem_encap_len()
            }
        }
    }

    /// Expected server `KeyShareEntry` length for this group.
    pub fn server_share_len(self) -> usize {
        match self {
            NamedGroup::X25519 => X25519_PUBLIC_LEN,
            NamedGroup::X25519MLKEM768 | NamedGroup::SecP256r1MLKEM768 | NamedGroup::SecP384r1MLKEM1024 => {
                self.classical_public_len() + self.mlkem_ciphertext_len()
            }
        }
    }
}

/// Ephemeral key pair for one handshake (classical X25519).
pub struct EphemeralKeyPair {
    group: NamedGroup,
    private: EphemeralPrivateKey,
    public: Bytes,
}

impl EphemeralKeyPair {
    /// Generate a fresh ephemeral key pair.
    pub fn generate() -> Result<Self, Unspecified> {
        let private = EphemeralPrivateKey::generate(&X25519, &aws_lc_rs::rand::SystemRandom::new())?;
        let public = Bytes::copy_from_slice(private.compute_public_key()?.as_ref());
        Ok(Self {
            group: NamedGroup::X25519,
            private,
            public,
        })
    }

    /// Named group (`X25519`).
    pub fn group(&self) -> NamedGroup {
        self.group
    }

    /// Ephemeral public key bytes.
    pub fn public_key(&self) -> &[u8] {
        &self.public
    }

    /// ECDH shared secret (consumes this key pair).
    pub fn agree(self, peer_public: &[u8]) -> Result<Bytes, Unspecified> {
        let peer = UnparsedPublicKey::new(&X25519, peer_public);
        let mut out = vec![0u8; 32];
        agreement::agree_ephemeral(self.private, &peer, Unspecified, |secret| {
            if secret.len() != 32 {
                return Err(Unspecified);
            }
            out.copy_from_slice(secret);
            Ok(())
        })?;
        Ok(Bytes::from(out))
    }
}

/// Ephemeral NIST P-256 key pair — used both by TLS 1.2 ECDHE (RFC 8422)
/// and as the classical component of TLS 1.3's `SecP256r1MLKEM768` hybrid
/// group (RFC 10024). Public key is the uncompressed point encoding
/// (`0x04 || X || Y`, 65 bytes) — the exact `ECPoint` wire format TLS
/// 1.2's `ServerECDHParams`/`ClientECDHParams` use, no re-encoding needed.
pub struct EphemeralP256KeyPair {
    private: EphemeralPrivateKey,
    public: Bytes,
}

impl EphemeralP256KeyPair {
    /// Generate a fresh ephemeral key pair.
    pub fn generate() -> Result<Self, Unspecified> {
        let private = EphemeralPrivateKey::generate(&ECDH_P256, &aws_lc_rs::rand::SystemRandom::new())?;
        let public = Bytes::copy_from_slice(private.compute_public_key()?.as_ref());
        Ok(Self { private, public })
    }

    /// Uncompressed point public key bytes (65 bytes: `0x04 || X || Y`).
    pub fn public_key(&self) -> &[u8] {
        &self.public
    }

    /// ECDH shared secret (X coordinate only, per RFC 8422 §5.10 — consumes this key pair).
    pub fn agree(self, peer_public: &[u8]) -> Result<Bytes, Unspecified> {
        let peer = UnparsedPublicKey::new(&ECDH_P256, peer_public);
        let mut out = vec![0u8; 32];
        agreement::agree_ephemeral(self.private, &peer, Unspecified, |secret| {
            if secret.len() != 32 {
                return Err(Unspecified);
            }
            out.copy_from_slice(secret);
            Ok(())
        })?;
        Ok(Bytes::from(out))
    }
}

/// Ephemeral NIST P-384 key pair — the classical component of TLS 1.3's
/// `SecP384r1MLKEM1024` hybrid group (RFC 10024). Public key is the
/// uncompressed point encoding (`0x04 || X || Y`, 97 bytes). Unlike
/// [`EphemeralP256KeyPair`]'s 32-byte output, P-384's ECDH shared secret
/// is naturally 48 bytes (the curve's field size) — not truncated or
/// padded to match the other groups.
pub struct EphemeralP384KeyPair {
    private: EphemeralPrivateKey,
    public: Bytes,
}

impl EphemeralP384KeyPair {
    /// Generate a fresh ephemeral key pair.
    pub fn generate() -> Result<Self, Unspecified> {
        let private = EphemeralPrivateKey::generate(&ECDH_P384, &aws_lc_rs::rand::SystemRandom::new())?;
        let public = Bytes::copy_from_slice(private.compute_public_key()?.as_ref());
        Ok(Self { private, public })
    }

    /// Uncompressed point public key bytes (97 bytes: `0x04 || X || Y`).
    pub fn public_key(&self) -> &[u8] {
        &self.public
    }

    /// ECDH shared secret (48 bytes — consumes this key pair).
    pub fn agree(self, peer_public: &[u8]) -> Result<Bytes, Unspecified> {
        let peer = UnparsedPublicKey::new(&ECDH_P384, peer_public);
        let mut out = vec![0u8; 48];
        agreement::agree_ephemeral(self.private, &peer, Unspecified, |secret| {
            if secret.len() != 48 {
                return Err(Unspecified);
            }
            out.copy_from_slice(secret);
            Ok(())
        })?;
        Ok(Bytes::from(out))
    }
}

/// Classical component of a hybrid key exchange (the non-PQ half).
enum ClassicalKeyPair {
    X25519(EphemeralKeyPair),
    P256(EphemeralP256KeyPair),
    P384(EphemeralP384KeyPair),
}

impl ClassicalKeyPair {
    fn generate(group: NamedGroup) -> Result<Self, Unspecified> {
        match group {
            NamedGroup::X25519MLKEM768 => EphemeralKeyPair::generate().map(ClassicalKeyPair::X25519),
            NamedGroup::SecP256r1MLKEM768 => EphemeralP256KeyPair::generate().map(ClassicalKeyPair::P256),
            NamedGroup::SecP384r1MLKEM1024 => EphemeralP384KeyPair::generate().map(ClassicalKeyPair::P384),
            NamedGroup::X25519 => unreachable!("classical-only group has no hybrid ClassicalKeyPair"),
        }
    }

    fn public_key(&self) -> &[u8] {
        match self {
            ClassicalKeyPair::X25519(kp) => kp.public_key(),
            ClassicalKeyPair::P256(kp) => kp.public_key(),
            ClassicalKeyPair::P384(kp) => kp.public_key(),
        }
    }

    fn agree(self, peer_public: &[u8]) -> Result<Bytes, Unspecified> {
        match self {
            ClassicalKeyPair::X25519(kp) => kp.agree(peer_public),
            ClassicalKeyPair::P256(kp) => kp.agree(peer_public),
            ClassicalKeyPair::P384(kp) => kp.agree(peer_public),
        }
    }
}

/// Hybrid client key material for any of the three RFC 10024 groups.
pub struct HybridKeyPair {
    group: NamedGroup,
    classical: ClassicalKeyPair,
    mlkem_decaps: kem::DecapsulationKey<kem::AlgorithmId>,
    mlkem_encaps_bytes: Bytes,
}

impl HybridKeyPair {
    /// Generate hybrid client key shares for `group`.
    pub fn generate(group: NamedGroup) -> Result<Self, Unspecified> {
        let classical = ClassicalKeyPair::generate(group)?;
        let mlkem_decaps = kem::DecapsulationKey::generate(group.mlkem_algorithm()).map_err(|_| Unspecified)?;
        let mlkem_encaps_bytes = Bytes::copy_from_slice(
            mlkem_decaps
                .encapsulation_key()
                .map_err(|_| Unspecified)?
                .key_bytes()
                .map_err(|_| Unspecified)?
                .as_ref(),
        );
        Ok(Self {
            group,
            classical,
            mlkem_decaps,
            mlkem_encaps_bytes,
        })
    }

    /// Combined client key share, in the group's own concatenation order
    /// (PQ-first for `X25519MLKEM768`, classical-first otherwise).
    pub fn client_share(&self) -> Bytes {
        let classical_pub = self.classical.public_key();
        let mut out = BytesMut::with_capacity(classical_pub.len() + self.mlkem_encaps_bytes.len());
        if self.group.pq_first() {
            out.extend_from_slice(&self.mlkem_encaps_bytes);
            out.extend_from_slice(classical_pub);
        } else {
            out.extend_from_slice(classical_pub);
            out.extend_from_slice(&self.mlkem_encaps_bytes);
        }
        out.freeze()
    }

    /// Complete hybrid handshake as client (consumes self).
    pub fn agree_client(self, server_share: &[u8]) -> Result<Bytes, Unspecified> {
        if server_share.len() != self.group.server_share_len() {
            return Err(Unspecified);
        }
        let (pq, classical) = if self.group.pq_first() {
            let (pq, classical) = server_share.split_at(self.group.mlkem_ciphertext_len());
            (pq, classical)
        } else {
            let (classical, pq) = server_share.split_at(self.group.classical_public_len());
            (pq, classical)
        };
        let pq_secret = self
            .mlkem_decaps
            .decapsulate(pq.into())
            .map_err(|_| Unspecified)?;
        let x_secret = self.classical.agree(classical)?;
        Ok(combine_hybrid_secret(
            PqSharedSecret(pq_secret.as_ref()),
            ClassicalSharedSecret(x_secret.as_ref()),
            self.group.pq_first(),
        ))
    }
}

/// Server-side hybrid response to a client key share for `group`.
pub fn server_agree_hybrid(group: NamedGroup, client_share: &[u8]) -> Result<(Bytes, Bytes), Unspecified> {
    if client_share.len() != group.client_share_len() {
        return Err(Unspecified);
    }
    let (pq_pub, classical_peer) = if group.pq_first() {
        let (pq, classical) = client_share.split_at(group.mlkem_encap_len());
        (pq, classical)
    } else {
        let (classical, pq) = client_share.split_at(group.classical_public_len());
        (pq, classical)
    };
    let encaps = kem::EncapsulationKey::new(group.mlkem_algorithm(), pq_pub).map_err(|_| Unspecified)?;
    let (ciphertext, pq_secret) = encaps.encapsulate().map_err(|_| Unspecified)?;
    let server_classical = ClassicalKeyPair::generate(group)?;
    let server_classical_pub = Bytes::copy_from_slice(server_classical.public_key());
    let x_secret = server_classical.agree(classical_peer)?;
    let mut server_share = BytesMut::with_capacity(server_classical_pub.len() + ciphertext.as_ref().len());
    if group.pq_first() {
        server_share.extend_from_slice(ciphertext.as_ref());
        server_share.extend_from_slice(&server_classical_pub);
    } else {
        server_share.extend_from_slice(&server_classical_pub);
        server_share.extend_from_slice(ciphertext.as_ref());
    }
    let shared = combine_hybrid_secret(
        PqSharedSecret(pq_secret.as_ref()),
        ClassicalSharedSecret(x_secret.as_ref()),
        group.pq_first(),
    );
    Ok((server_share.freeze(), shared))
}

/// Local key-share state for either classical or hybrid groups.
pub enum LocalKeyShare {
    /// X25519 only.
    X25519(EphemeralKeyPair),
    /// One of the RFC 10024 hybrid groups.
    Hybrid(HybridKeyPair),
}

impl LocalKeyShare {
    /// Generate key material for `group`.
    pub fn generate(group: NamedGroup) -> Result<Self, Unspecified> {
        match group {
            NamedGroup::X25519 => EphemeralKeyPair::generate().map(LocalKeyShare::X25519),
            NamedGroup::X25519MLKEM768 | NamedGroup::SecP256r1MLKEM768 | NamedGroup::SecP384r1MLKEM1024 => {
                HybridKeyPair::generate(group).map(LocalKeyShare::Hybrid)
            }
        }
    }

    /// Group for this key share.
    pub fn group(&self) -> NamedGroup {
        match self {
            LocalKeyShare::X25519(kp) => kp.group(),
            LocalKeyShare::Hybrid(h) => h.group,
        }
    }

    /// Client `KeyShareEntry` bytes.
    pub fn client_share_bytes(&self) -> Bytes {
        match self {
            LocalKeyShare::X25519(kp) => kp.public.clone(),
            LocalKeyShare::Hybrid(h) => h.client_share(),
        }
    }

    /// Complete agreement as client (consumes self).
    pub fn agree_client(self, group: NamedGroup, peer_share: &[u8]) -> Result<Bytes, Unspecified> {
        match (self, group) {
            (LocalKeyShare::X25519(kp), NamedGroup::X25519) => kp.agree(peer_share),
            (LocalKeyShare::Hybrid(h), _) if h.group == group => h.agree_client(peer_share),
            _ => Err(Unspecified),
        }
    }
}

/// Server completes ECDHE / hybrid with a client key share.
pub fn server_agree(group: NamedGroup, client_share: &[u8]) -> Result<(Bytes, Bytes), Unspecified> {
    match group {
        NamedGroup::X25519 => {
            let server = EphemeralKeyPair::generate()?;
            let pub_key = server.public.clone();
            let shared = server.agree(client_share)?;
            Ok((pub_key, shared))
        }
        NamedGroup::X25519MLKEM768 | NamedGroup::SecP256r1MLKEM768 | NamedGroup::SecP384r1MLKEM1024 => {
            server_agree_hybrid(group, client_share)
        }
    }
}

/// The post-quantum (ML-KEM) half of a hybrid key-exchange shared secret.
/// A distinct type from [`ClassicalSharedSecret`] so the two halves can't
/// be transposed when calling `combine_hybrid_secret`.
struct PqSharedSecret<'a>(&'a [u8]);

/// The classical (ECDH) half of a hybrid key-exchange shared secret. See
/// [`PqSharedSecret`].
struct ClassicalSharedSecret<'a>(&'a [u8]);

/// Concatenate the ML-KEM and classical shared secrets in `group`'s own
/// combiner order (matches its wire concatenation order — RFC 10024
/// keeps the two consistent per group, even though `X25519MLKEM768`'s
/// order differs from the other two groups'). Each half's length is
/// already fixed by the `aws-lc-rs` algorithm that produced it, so
/// there's nothing to validate here.
fn combine_hybrid_secret(pq: PqSharedSecret<'_>, classical: ClassicalSharedSecret<'_>, pq_first: bool) -> Bytes {
    let mut out = BytesMut::with_capacity(pq.0.len() + classical.0.len());
    if pq_first {
        out.extend_from_slice(pq.0);
        out.extend_from_slice(classical.0);
    } else {
        out.extend_from_slice(classical.0);
        out.extend_from_slice(pq.0);
    }
    out.freeze()
}

/// Fixed key pair for RFC 8448 / unit tests (does not use the OS RNG).
pub struct StaticKeyPair {
    private: PrivateKey,
    public: Bytes,
}

impl StaticKeyPair {
    /// Load from raw private key bytes (X25519: 32 octets).
    pub fn from_private_key(private_key: &[u8]) -> Result<Self, KeyRejected> {
        let private = PrivateKey::from_private_key(&X25519, private_key)?;
        let public = Bytes::copy_from_slice(private.compute_public_key()?.as_ref());
        Ok(Self { private, public })
    }

    /// Public key bytes.
    pub fn public_key(&self) -> &[u8] {
        &self.public
    }

    /// ECDH shared secret.
    pub fn agree(&self, peer_public: &[u8]) -> Result<Bytes, Unspecified> {
        let peer = UnparsedPublicKey::new(&X25519, peer_public);
        let mut out = vec![0u8; 32];
        agreement::agree(&self.private, &peer, Unspecified, |secret| {
            if secret.len() != 32 {
                return Err(Unspecified);
            }
            out.copy_from_slice(secret);
            Ok(())
        })?;
        Ok(Bytes::from(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p256_agree_roundtrip() {
        let a = EphemeralP256KeyPair::generate().unwrap();
        let b = EphemeralP256KeyPair::generate().unwrap();
        assert_eq!(a.public_key().len(), 65);
        assert_eq!(a.public_key()[0], 0x04);
        let pub_b = b.public_key().to_vec();
        let pub_a = a.public_key().to_vec();
        let shared_a = a.agree(&pub_b).unwrap();
        let shared_b = b.agree(&pub_a).unwrap();
        assert_eq!(shared_a, shared_b);
        assert_eq!(shared_a.len(), 32);
    }

    #[test]
    fn x25519_agree_roundtrip() {
        let a = EphemeralKeyPair::generate().unwrap();
        let b = EphemeralKeyPair::generate().unwrap();
        let pub_b = b.public.clone();
        let shared = a.agree(&pub_b).unwrap();
        assert_eq!(shared.len(), 32);
    }

    #[test]
    fn hybrid_agree_roundtrip() {
        let client = LocalKeyShare::generate(NamedGroup::X25519MLKEM768).unwrap();
        let share = client.client_share_bytes();
        let (server_share, s_server) = server_agree(NamedGroup::X25519MLKEM768, share.as_ref()).unwrap();
        let s_client = client
            .agree_client(NamedGroup::X25519MLKEM768, server_share.as_ref())
            .unwrap();
        assert_eq!(s_client, s_server);
        assert_eq!(s_client.len(), 64);
    }

    #[test]
    fn p384_agree_roundtrip() {
        let a = EphemeralP384KeyPair::generate().unwrap();
        let b = EphemeralP384KeyPair::generate().unwrap();
        assert_eq!(a.public_key().len(), 97);
        assert_eq!(a.public_key()[0], 0x04);
        let pub_b = b.public_key().to_vec();
        let pub_a = a.public_key().to_vec();
        let shared_a = a.agree(&pub_b).unwrap();
        let shared_b = b.agree(&pub_a).unwrap();
        assert_eq!(shared_a, shared_b);
        assert_eq!(shared_a.len(), 48);
    }

    /// `SecP256r1MLKEM768` is classical-first (RFC 10024) — the opposite
    /// order from `X25519MLKEM768` above — so this also proves the
    /// per-group `pq_first` branch actually engages differently.
    #[test]
    fn secp256r1_mlkem768_agree_roundtrip() {
        let client = LocalKeyShare::generate(NamedGroup::SecP256r1MLKEM768).unwrap();
        let share = client.client_share_bytes();
        assert_eq!(share.len(), NamedGroup::SecP256r1MLKEM768.client_share_len());
        // Classical-first: the leading 65 bytes are the P-256 uncompressed point.
        assert_eq!(share[0], 0x04);
        let (server_share, s_server) = server_agree(NamedGroup::SecP256r1MLKEM768, share.as_ref()).unwrap();
        assert_eq!(server_share.len(), NamedGroup::SecP256r1MLKEM768.server_share_len());
        assert_eq!(server_share[0], 0x04);
        let s_client = client
            .agree_client(NamedGroup::SecP256r1MLKEM768, server_share.as_ref())
            .unwrap();
        assert_eq!(s_client, s_server);
        assert_eq!(s_client.len(), 64);
    }

    #[test]
    fn secp384r1_mlkem1024_agree_roundtrip() {
        let client = LocalKeyShare::generate(NamedGroup::SecP384r1MLKEM1024).unwrap();
        let share = client.client_share_bytes();
        assert_eq!(share.len(), NamedGroup::SecP384r1MLKEM1024.client_share_len());
        // Classical-first: the leading 97 bytes are the P-384 uncompressed point.
        assert_eq!(share[0], 0x04);
        let (server_share, s_server) = server_agree(NamedGroup::SecP384r1MLKEM1024, share.as_ref()).unwrap();
        assert_eq!(server_share.len(), NamedGroup::SecP384r1MLKEM1024.server_share_len());
        assert_eq!(server_share[0], 0x04);
        let s_client = client
            .agree_client(NamedGroup::SecP384r1MLKEM1024, server_share.as_ref())
            .unwrap();
        assert_eq!(s_client, s_server);
        // P-384's 48-byte ECDH secret + ML-KEM-1024's 32-byte secret.
        assert_eq!(s_client.len(), 80);
    }

    /// A client offering `X25519MLKEM768` must not be accepted as having
    /// agreed on `SecP256r1MLKEM768` (or vice versa) even though both are
    /// `LocalKeyShare::Hybrid` — the group mismatch guard in
    /// `LocalKeyShare::agree_client` is what enforces this.
    #[test]
    fn agree_client_rejects_mismatched_hybrid_group() {
        let client = LocalKeyShare::generate(NamedGroup::X25519MLKEM768).unwrap();
        let share = client.client_share_bytes();
        let (server_share, _) = server_agree(NamedGroup::X25519MLKEM768, share.as_ref()).unwrap();
        assert!(client
            .agree_client(NamedGroup::SecP256r1MLKEM768, server_share.as_ref())
            .is_err());
    }
}
