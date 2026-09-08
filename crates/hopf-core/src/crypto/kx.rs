// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Ephemeral key agreement (X25519 + hybrid ML-KEM) via AWS-LC.

use aws_lc_rs::agreement::{self, EphemeralPrivateKey, PrivateKey, UnparsedPublicKey, ECDH_P256, X25519};
use aws_lc_rs::error::{KeyRejected, Unspecified};
use aws_lc_rs::kem::{self, ML_KEM_768};
use bytes::{Bytes, BytesMut};

/// ML-KEM-768 encapsulation key length (client key share PQ component).
pub const MLKEM768_ENCAP_LEN: usize = 1184;
/// ML-KEM-768 ciphertext length (server key share PQ component).
pub const MLKEM768_CIPHERTEXT_LEN: usize = 1088;
/// X25519 public key length.
pub const X25519_PUBLIC_LEN: usize = 32;

/// Named group for TLS 1.3 key shares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamedGroup {
    /// X25519 (RFC 8446 §4.2.7).
    X25519,
    /// Hybrid X25519 + ML-KEM-768 (draft-ietf-tls-ecdhe-mlkem, IANA 0x11ec).
    X25519MLKEM768,
}

impl NamedGroup {
    /// IANA `NamedGroup` code point.
    pub fn code(self) -> u16 {
        match self {
            NamedGroup::X25519 => 0x001d,
            NamedGroup::X25519MLKEM768 => 0x11ec,
        }
    }

    /// Parse from IANA code point.
    pub fn from_code(code: u16) -> Option<Self> {
        match code {
            0x001d => Some(NamedGroup::X25519),
            0x11ec => Some(NamedGroup::X25519MLKEM768),
            _ => None,
        }
    }

    /// Expected client `KeyShareEntry` length for this group.
    pub fn client_share_len(self) -> usize {
        match self {
            NamedGroup::X25519 => X25519_PUBLIC_LEN,
            NamedGroup::X25519MLKEM768 => MLKEM768_ENCAP_LEN + X25519_PUBLIC_LEN,
        }
    }

    /// Expected server `KeyShareEntry` length for this group.
    pub fn server_share_len(self) -> usize {
        match self {
            NamedGroup::X25519 => X25519_PUBLIC_LEN,
            NamedGroup::X25519MLKEM768 => MLKEM768_CIPHERTEXT_LEN + X25519_PUBLIC_LEN,
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

/// Ephemeral NIST P-256 key pair (TLS 1.2 ECDHE — RFC 8422; TLS 1.3 doesn't
/// use this curve, only classical/hybrid X25519 above). Public key is the
/// uncompressed point encoding (`0x04 || X || Y`, 65 bytes) — the exact
/// `ECPoint` wire format TLS 1.2's `ServerECDHParams`/`ClientECDHParams`
/// use, no re-encoding needed.
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

/// Hybrid X25519MLKEM768 client key material.
pub struct HybridKeyPair {
    x25519: EphemeralKeyPair,
    mlkem_decaps: kem::DecapsulationKey<kem::AlgorithmId>,
    mlkem_encaps_bytes: Bytes,
}

impl HybridKeyPair {
    /// Generate hybrid client key shares.
    pub fn generate() -> Result<Self, Unspecified> {
        let x25519 = EphemeralKeyPair::generate()?;
        let mlkem_decaps = kem::DecapsulationKey::generate(&ML_KEM_768).map_err(|_| Unspecified)?;
        let mlkem_encaps_bytes = Bytes::copy_from_slice(
            mlkem_decaps
                .encapsulation_key()
                .map_err(|_| Unspecified)?
                .key_bytes()
                .map_err(|_| Unspecified)?
                .as_ref(),
        );
        Ok(Self {
            x25519,
            mlkem_decaps,
            mlkem_encaps_bytes,
        })
    }

    /// Combined client key share: ML-KEM encapsulation key || X25519 public (PQ-first).
    pub fn client_share(&self) -> Bytes {
        let mut out = BytesMut::with_capacity(MLKEM768_ENCAP_LEN + X25519_PUBLIC_LEN);
        out.extend_from_slice(&self.mlkem_encaps_bytes);
        out.extend_from_slice(self.x25519.public_key());
        out.freeze()
    }

    /// Complete hybrid handshake as client (consumes self).
    pub fn agree_client(self, server_share: &[u8]) -> Result<Bytes, Unspecified> {
        if server_share.len() != NamedGroup::X25519MLKEM768.server_share_len() {
            return Err(Unspecified);
        }
        let (pq, classical) = server_share.split_at(MLKEM768_CIPHERTEXT_LEN);
        let pq_secret = self
            .mlkem_decaps
            .decapsulate(pq.into())
            .map_err(|_| Unspecified)?;
        let x_secret = self.x25519.agree(classical)?;
        concat_hybrid_secret(pq_secret.as_ref(), x_secret.as_ref())
    }
}

/// Server-side hybrid response to a client key share.
pub fn server_agree_hybrid(client_share: &[u8]) -> Result<(Bytes, Bytes), Unspecified> {
    if client_share.len() != NamedGroup::X25519MLKEM768.client_share_len() {
        return Err(Unspecified);
    }
    let (pq, classical) = client_share.split_at(MLKEM768_ENCAP_LEN);
    let encaps = kem::EncapsulationKey::new(&ML_KEM_768, pq).map_err(|_| Unspecified)?;
    let (ciphertext, pq_secret) = encaps.encapsulate().map_err(|_| Unspecified)?;
    let server_x25519 = EphemeralKeyPair::generate()?;
    let server_x_pub = Bytes::copy_from_slice(server_x25519.public_key());
    let x_secret = server_x25519.agree(classical)?;
    let mut server_share = BytesMut::with_capacity(MLKEM768_CIPHERTEXT_LEN + X25519_PUBLIC_LEN);
    server_share.extend_from_slice(ciphertext.as_ref());
    server_share.extend_from_slice(&server_x_pub);
    let shared = concat_hybrid_secret(pq_secret.as_ref(), x_secret.as_ref())?;
    Ok((server_share.freeze(), shared))
}

/// Local key-share state for either classical or hybrid groups.
pub enum LocalKeyShare {
    /// X25519 only.
    X25519(EphemeralKeyPair),
    /// X25519 + ML-KEM-768 hybrid.
    Hybrid(HybridKeyPair),
}

impl LocalKeyShare {
    /// Generate key material for `group`.
    pub fn generate(group: NamedGroup) -> Result<Self, Unspecified> {
        match group {
            NamedGroup::X25519 => EphemeralKeyPair::generate().map(LocalKeyShare::X25519),
            NamedGroup::X25519MLKEM768 => HybridKeyPair::generate().map(LocalKeyShare::Hybrid),
        }
    }

    /// Group for this key share.
    pub fn group(&self) -> NamedGroup {
        match self {
            LocalKeyShare::X25519(kp) => kp.group(),
            LocalKeyShare::Hybrid(_) => NamedGroup::X25519MLKEM768,
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
            (LocalKeyShare::Hybrid(h), NamedGroup::X25519MLKEM768) => h.agree_client(peer_share),
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
        NamedGroup::X25519MLKEM768 => server_agree_hybrid(client_share),
    }
}

fn concat_hybrid_secret(pq: &[u8], classical: &[u8]) -> Result<Bytes, Unspecified> {
    if pq.len() != 32 || classical.len() != 32 {
        return Err(Unspecified);
    }
    let mut out = BytesMut::with_capacity(64);
    out.extend_from_slice(pq);
    out.extend_from_slice(classical);
    Ok(out.freeze())
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
}
