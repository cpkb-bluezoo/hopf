// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Hybrid Public Key Encryption, base mode (RFC 9180), as needed by TLS
//! Encrypted Client Hello (RFC 9849).
//!
//! AWS-LC's Rust bindings do not expose HPKE, so the RFC 9180 key schedule is
//! composed here from the primitives this crate already wraps: ECDH from
//! `aws-lc-rs`, HMAC-based HKDF, and the [`aead`](super::aead) keys.
//!
//! Supported algorithms:
//!
//! | Role | Identifiers |
//! |------|-------------|
//! | KEM  | `0x0010` DHKEM(P-256, HKDF-SHA256), `0x0020` DHKEM(X25519, HKDF-SHA256) |
//! | KDF  | `0x0001` HKDF-SHA256, `0x0002` HKDF-SHA384, `0x0003` HKDF-SHA512 |
//! | AEAD | `0x0001` AES-128-GCM, `0x0002` AES-256-GCM, `0x0003` ChaCha20-Poly1305 |
//!
//! Only base mode (no PSK, no sender authentication) is provided; that is the
//! only mode ECH uses. Export-only AEAD (`0xFFFF`) is not supported.

use aws_lc_rs::agreement::{self, PrivateKey, UnparsedPublicKey, ECDH_P256, X25519};
use aws_lc_rs::hkdf::{self, KeyType, Prk};
use aws_lc_rs::hmac;

use super::aead::{AesGcmKey, ChaCha20Poly1305Key};

const VERSION_LABEL: &[u8] = b"HPKE-v1";
const NONCE_LEN: usize = 12;
/// Length of the KEM shared secret for every supported KEM (RFC 9180 §7.1).
const KEM_SECRET_LEN: usize = 32;

/// HPKE operation failed. Deliberately carries no detail: decryption and
/// decapsulation failures must not be distinguishable to a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HpkeError;

/// HPKE KEM (RFC 9180 §7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kem {
    /// DHKEM(P-256, HKDF-SHA256), `0x0010`.
    DhkemP256HkdfSha256,
    /// DHKEM(X25519, HKDF-SHA256), `0x0020`.
    DhkemX25519HkdfSha256,
}

impl Kem {
    /// IANA HPKE KEM identifier.
    pub fn id(self) -> u16 {
        match self {
            Kem::DhkemP256HkdfSha256 => 0x0010,
            Kem::DhkemX25519HkdfSha256 => 0x0020,
        }
    }

    /// Look up a supported KEM by identifier.
    pub fn from_id(id: u16) -> Option<Self> {
        match id {
            0x0010 => Some(Kem::DhkemP256HkdfSha256),
            0x0020 => Some(Kem::DhkemX25519HkdfSha256),
            _ => None,
        }
    }

    /// Length of a serialised public key / encapsulated key (`Npk`, `Nenc`).
    pub fn public_key_len(self) -> usize {
        match self {
            Kem::DhkemP256HkdfSha256 => 65,
            Kem::DhkemX25519HkdfSha256 => 32,
        }
    }

    fn agreement(self) -> &'static agreement::Algorithm {
        match self {
            Kem::DhkemP256HkdfSha256 => &ECDH_P256,
            Kem::DhkemX25519HkdfSha256 => &X25519,
        }
    }
}

/// HPKE KDF (RFC 9180 §7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kdf {
    /// HKDF-SHA256, `0x0001`.
    HkdfSha256,
    /// HKDF-SHA384, `0x0002`.
    HkdfSha384,
    /// HKDF-SHA512, `0x0003`.
    HkdfSha512,
}

impl Kdf {
    /// IANA HPKE KDF identifier.
    pub fn id(self) -> u16 {
        match self {
            Kdf::HkdfSha256 => 0x0001,
            Kdf::HkdfSha384 => 0x0002,
            Kdf::HkdfSha512 => 0x0003,
        }
    }

    /// Look up a supported KDF by identifier.
    pub fn from_id(id: u16) -> Option<Self> {
        match id {
            0x0001 => Some(Kdf::HkdfSha256),
            0x0002 => Some(Kdf::HkdfSha384),
            0x0003 => Some(Kdf::HkdfSha512),
            _ => None,
        }
    }

    /// Hash output length (`Nh`).
    pub fn hash_len(self) -> usize {
        match self {
            Kdf::HkdfSha256 => 32,
            Kdf::HkdfSha384 => 48,
            Kdf::HkdfSha512 => 64,
        }
    }

    fn hkdf(self) -> hkdf::Algorithm {
        match self {
            Kdf::HkdfSha256 => hkdf::HKDF_SHA256,
            Kdf::HkdfSha384 => hkdf::HKDF_SHA384,
            Kdf::HkdfSha512 => hkdf::HKDF_SHA512,
        }
    }

    fn hmac(self) -> hmac::Algorithm {
        match self {
            Kdf::HkdfSha256 => hmac::HMAC_SHA256,
            Kdf::HkdfSha384 => hmac::HMAC_SHA384,
            Kdf::HkdfSha512 => hmac::HMAC_SHA512,
        }
    }
}

/// HPKE AEAD (RFC 9180 §7.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Aead {
    /// AES-128-GCM, `0x0001`.
    Aes128Gcm,
    /// AES-256-GCM, `0x0002`.
    Aes256Gcm,
    /// ChaCha20-Poly1305, `0x0003`.
    ChaCha20Poly1305,
}

impl Aead {
    /// IANA HPKE AEAD identifier.
    pub fn id(self) -> u16 {
        match self {
            Aead::Aes128Gcm => 0x0001,
            Aead::Aes256Gcm => 0x0002,
            Aead::ChaCha20Poly1305 => 0x0003,
        }
    }

    /// Look up a supported AEAD by identifier.
    pub fn from_id(id: u16) -> Option<Self> {
        match id {
            0x0001 => Some(Aead::Aes128Gcm),
            0x0002 => Some(Aead::Aes256Gcm),
            0x0003 => Some(Aead::ChaCha20Poly1305),
            _ => None,
        }
    }

    /// Key length (`Nk`).
    pub fn key_len(self) -> usize {
        match self {
            Aead::Aes128Gcm => 16,
            Aead::Aes256Gcm | Aead::ChaCha20Poly1305 => 32,
        }
    }

    /// Authentication tag length (`Nt`).
    pub fn tag_len(self) -> usize {
        16
    }
}

/// A KEM/KDF/AEAD combination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Suite {
    /// Key encapsulation mechanism.
    pub kem: Kem,
    /// Key derivation function.
    pub kdf: Kdf,
    /// AEAD.
    pub aead: Aead,
}

impl Suite {
    fn suite_id(self) -> Vec<u8> {
        let mut id = Vec::with_capacity(10);
        id.extend_from_slice(b"HPKE");
        id.extend_from_slice(&self.kem.id().to_be_bytes());
        id.extend_from_slice(&self.kdf.id().to_be_bytes());
        id.extend_from_slice(&self.aead.id().to_be_bytes());
        id
    }
}

/// A KEM private key (recipient static key, or sender ephemeral key).
pub struct HpkePrivateKey {
    kem: Kem,
    key: PrivateKey,
}

impl HpkePrivateKey {
    /// Generate a fresh key pair.
    pub fn generate(kem: Kem) -> Result<Self, HpkeError> {
        let key = PrivateKey::generate(kem.agreement()).map_err(|_| HpkeError)?;
        Ok(Self { kem, key })
    }

    /// Load from the raw private key octets (`SerializePrivateKey`, RFC 9180
    /// §7.1.1: 32 octets for both supported KEMs).
    pub fn from_bytes(kem: Kem, bytes: &[u8]) -> Result<Self, HpkeError> {
        let key = PrivateKey::from_private_key(kem.agreement(), bytes).map_err(|_| HpkeError)?;
        Ok(Self { kem, key })
    }

    /// KEM this key belongs to.
    pub fn kem(&self) -> Kem {
        self.kem
    }

    /// Serialised public key (`SerializePublicKey`).
    pub fn public_key(&self) -> Result<Vec<u8>, HpkeError> {
        let public = self.key.compute_public_key().map_err(|_| HpkeError)?;
        Ok(public.as_ref().to_vec())
    }

    fn dh(&self, peer_public: &[u8]) -> Result<Vec<u8>, HpkeError> {
        if peer_public.len() != self.kem.public_key_len() {
            return Err(HpkeError);
        }
        let peer = UnparsedPublicKey::new(self.kem.agreement(), peer_public);
        agreement::agree(&self.key, &peer, HpkeError, |secret| Ok(secret.to_vec()))
    }
}

struct Len(usize);

impl KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

/// HKDF-Extract (RFC 5869) as HMAC(salt, ikm); an empty salt is equivalent to
/// `HashLen` zero octets because HMAC zero-pads its key.
fn extract(kdf: Kdf, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    let key = hmac::Key::new(kdf.hmac(), salt);
    hmac::sign(&key, ikm).as_ref().to_vec()
}

fn expand(kdf: Kdf, prk: &[u8], info: &[&[u8]], len: usize) -> Result<Vec<u8>, HpkeError> {
    let prk = Prk::new_less_safe(kdf.hkdf(), prk);
    let okm = prk.expand(info, Len(len)).map_err(|_| HpkeError)?;
    let mut out = vec![0u8; len];
    okm.fill(&mut out).map_err(|_| HpkeError)?;
    Ok(out)
}

fn labeled_extract(kdf: Kdf, suite_id: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> Vec<u8> {
    let mut labeled = Vec::with_capacity(VERSION_LABEL.len() + suite_id.len() + label.len() + ikm.len());
    labeled.extend_from_slice(VERSION_LABEL);
    labeled.extend_from_slice(suite_id);
    labeled.extend_from_slice(label);
    labeled.extend_from_slice(ikm);
    extract(kdf, salt, &labeled)
}

fn labeled_expand(
    kdf: Kdf,
    suite_id: &[u8],
    prk: &[u8],
    label: &[u8],
    info: &[u8],
    len: usize,
) -> Result<Vec<u8>, HpkeError> {
    let len16 = u16::try_from(len).map_err(|_| HpkeError)?.to_be_bytes();
    expand(kdf, prk, &[&len16, VERSION_LABEL, suite_id, label, info], len)
}

fn kem_suite_id(kem: Kem) -> Vec<u8> {
    let mut id = Vec::with_capacity(5);
    id.extend_from_slice(b"KEM");
    id.extend_from_slice(&kem.id().to_be_bytes());
    id
}

/// `ExtractAndExpand` of the DHKEM (RFC 9180 §4.1); both supported KEMs use
/// HKDF-SHA256.
fn kem_shared_secret(kem: Kem, dh: &[u8], kem_context: &[u8]) -> Result<Vec<u8>, HpkeError> {
    let suite_id = kem_suite_id(kem);
    let eae_prk = labeled_extract(Kdf::HkdfSha256, &suite_id, b"", b"eae_prk", dh);
    labeled_expand(
        Kdf::HkdfSha256,
        &suite_id,
        &eae_prk,
        b"shared_secret",
        kem_context,
        KEM_SECRET_LEN,
    )
}

/// One direction of an HPKE encryption context (RFC 9180 §5.2).
///
/// A sender context only [`seal`](Self::seal)s and a recipient context only
/// [`open`](Self::open)s; each call consumes one sequence number.
pub struct Context {
    suite: Suite,
    key: Vec<u8>,
    base_nonce: [u8; NONCE_LEN],
    exporter_secret: Vec<u8>,
    seq: u64,
}

impl Context {
    fn key_schedule(suite: Suite, shared_secret: &[u8], info: &[u8]) -> Result<Self, HpkeError> {
        let suite_id = suite.suite_id();
        let kdf = suite.kdf;
        let psk_id_hash = labeled_extract(kdf, &suite_id, b"", b"psk_id_hash", b"");
        let info_hash = labeled_extract(kdf, &suite_id, b"", b"info_hash", info);
        // mode_base = 0x00.
        let mut ks_context = vec![0u8];
        ks_context.extend_from_slice(&psk_id_hash);
        ks_context.extend_from_slice(&info_hash);

        let secret = labeled_extract(kdf, &suite_id, shared_secret, b"secret", b"");
        let key = labeled_expand(kdf, &suite_id, &secret, b"key", &ks_context, suite.aead.key_len())?;
        let nonce = labeled_expand(kdf, &suite_id, &secret, b"base_nonce", &ks_context, NONCE_LEN)?;
        let exporter_secret =
            labeled_expand(kdf, &suite_id, &secret, b"exp", &ks_context, kdf.hash_len())?;
        let mut base_nonce = [0u8; NONCE_LEN];
        base_nonce.copy_from_slice(&nonce);
        Ok(Self {
            suite,
            key,
            base_nonce,
            exporter_secret,
            seq: 0,
        })
    }

    fn next_nonce(&mut self) -> Result<[u8; NONCE_LEN], HpkeError> {
        let seq = self.seq;
        self.seq = seq.checked_add(1).ok_or(HpkeError)?;
        let mut nonce = self.base_nonce;
        let seq_bytes = seq.to_be_bytes();
        for (n, s) in nonce[NONCE_LEN - 8..].iter_mut().zip(seq_bytes) {
            *n ^= s;
        }
        Ok(nonce)
    }

    /// Encrypt `plaintext`; returns ciphertext with the tag appended.
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, HpkeError> {
        let nonce = self.next_nonce()?;
        let mut buf = plaintext.to_vec();
        match self.suite.aead {
            Aead::Aes128Gcm | Aead::Aes256Gcm => AesGcmKey::new(&self.key)
                .map_err(|_| HpkeError)?
                .seal_in_place_append_tag(nonce, aad, &mut buf),
            Aead::ChaCha20Poly1305 => ChaCha20Poly1305Key::new(&self.key)
                .map_err(|_| HpkeError)?
                .seal_in_place_append_tag(nonce, aad, &mut buf),
        }
        .map_err(|_| HpkeError)?;
        Ok(buf)
    }

    /// Decrypt `ciphertext` (tag included). A failed open still consumes the
    /// sequence number only if the nonce was derived, matching RFC 9180
    /// §5.2 (`IncrementSeq` happens after a successful `Open`), so a
    /// rejected message does not advance the context.
    pub fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, HpkeError> {
        let saved = self.seq;
        let nonce = self.next_nonce()?;
        let mut buf = ciphertext.to_vec();
        let result = match self.suite.aead {
            Aead::Aes128Gcm | Aead::Aes256Gcm => AesGcmKey::new(&self.key)
                .map_err(|_| HpkeError)
                .and_then(|k| k.open_in_place(nonce, aad, &mut buf).map_err(|_| HpkeError)),
            Aead::ChaCha20Poly1305 => ChaCha20Poly1305Key::new(&self.key)
                .map_err(|_| HpkeError)
                .and_then(|k| k.open_in_place(nonce, aad, &mut buf).map_err(|_| HpkeError)),
        };
        match result {
            Ok(len) => {
                buf.truncate(len);
                Ok(buf)
            }
            Err(e) => {
                self.seq = saved;
                Err(e)
            }
        }
    }

    /// Secret export interface (RFC 9180 §5.3).
    pub fn export(&self, exporter_context: &[u8], len: usize) -> Result<Vec<u8>, HpkeError> {
        labeled_expand(
            self.suite.kdf,
            &self.suite.suite_id(),
            &self.exporter_secret,
            b"sec",
            exporter_context,
            len,
        )
    }
}

/// `SetupBaseS`: encapsulate to `recipient_public` with a fresh ephemeral key.
/// Returns the encapsulated key `enc` and the sender context.
pub fn setup_base_sender(
    suite: Suite,
    recipient_public: &[u8],
    info: &[u8],
) -> Result<(Vec<u8>, Context), HpkeError> {
    let ephemeral = HpkePrivateKey::generate(suite.kem)?;
    setup_base_sender_with_key(suite, recipient_public, info, &ephemeral)
}

/// `SetupBaseS` with a caller-supplied ephemeral key (deterministic; used by
/// the RFC 9180 test vectors).
fn setup_base_sender_with_key(
    suite: Suite,
    recipient_public: &[u8],
    info: &[u8],
    ephemeral: &HpkePrivateKey,
) -> Result<(Vec<u8>, Context), HpkeError> {
    if ephemeral.kem != suite.kem {
        return Err(HpkeError);
    }
    let dh = ephemeral.dh(recipient_public)?;
    let enc = ephemeral.public_key()?;
    let mut kem_context = enc.clone();
    kem_context.extend_from_slice(recipient_public);
    let shared = kem_shared_secret(suite.kem, &dh, &kem_context)?;
    Ok((enc, Context::key_schedule(suite, &shared, info)?))
}

/// `SetupBaseR`: decapsulate `enc` with the recipient's private key.
pub fn setup_base_recipient(
    suite: Suite,
    enc: &[u8],
    recipient: &HpkePrivateKey,
    info: &[u8],
) -> Result<Context, HpkeError> {
    if recipient.kem != suite.kem {
        return Err(HpkeError);
    }
    let dh = recipient.dh(enc)?;
    let mut kem_context = enc.to_vec();
    kem_context.extend_from_slice(&recipient.public_key()?);
    let shared = kem_shared_secret(suite.kem, &dh, &kem_context)?;
    Context::key_schedule(suite, &shared, info)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    struct Vector {
        suite: Suite,
        info: &'static str,
        sk_em: &'static str,
        pk_rm: &'static str,
        sk_rm: &'static str,
        enc: &'static str,
        key: &'static str,
        base_nonce: &'static str,
        ct0: &'static str,
        ct1: &'static str,
        export_empty: &'static str,
    }

    const PT: &str = "4265617574792069732074727574682c20747275746820626561757479";

    fn check(v: &Vector) {
        let info = unhex(v.info);
        let pk_rm = unhex(v.pk_rm);
        let ephemeral = HpkePrivateKey::from_bytes(v.suite.kem, &unhex(v.sk_em)).unwrap();
        let (enc, mut sender) =
            setup_base_sender_with_key(v.suite, &pk_rm, &info, &ephemeral).unwrap();
        assert_eq!(enc, unhex(v.enc));
        assert_eq!(sender.key, unhex(v.key));
        assert_eq!(sender.base_nonce.to_vec(), unhex(v.base_nonce));
        let pt = unhex(PT);
        assert_eq!(sender.seal(&unhex("436f756e742d30"), &pt).unwrap(), unhex(v.ct0));
        assert_eq!(sender.seal(&unhex("436f756e742d31"), &pt).unwrap(), unhex(v.ct1));
        assert_eq!(sender.export(b"", 32).unwrap(), unhex(v.export_empty));

        let sk_rm = HpkePrivateKey::from_bytes(v.suite.kem, &unhex(v.sk_rm)).unwrap();
        assert_eq!(sk_rm.public_key().unwrap(), pk_rm);
        let mut recipient = setup_base_recipient(v.suite, &enc, &sk_rm, &info).unwrap();
        assert_eq!(recipient.open(&unhex("436f756e742d30"), &unhex(v.ct0)).unwrap(), pt);
        assert_eq!(recipient.open(&unhex("436f756e742d31"), &unhex(v.ct1)).unwrap(), pt);
    }

    #[test]
    fn rfc9180_a1_x25519_sha256_aes128gcm() {
        check(&Vector {
            suite: Suite { kem: Kem::DhkemX25519HkdfSha256, kdf: Kdf::HkdfSha256, aead: Aead::Aes128Gcm },
            info: "4f6465206f6e2061204772656369616e2055726e",
            sk_em: "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736",
            pk_rm: "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d",
            sk_rm: "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8",
            enc: "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
            key: "4531685d41d65f03dc48f6b8302c05b0",
            base_nonce: "56d890e5accaaf011cff4b7d",
            ct0: "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a",
            ct1: "af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84",
            export_empty: "3853fe2b4035195a573ffc53856e77058e15d9ea064de3e59f4961d0095250ee",
        });
    }

    #[test]
    fn rfc9180_a2_x25519_sha256_chacha20poly1305() {
        check(&Vector {
            suite: Suite { kem: Kem::DhkemX25519HkdfSha256, kdf: Kdf::HkdfSha256, aead: Aead::ChaCha20Poly1305 },
            info: "4f6465206f6e2061204772656369616e2055726e",
            sk_em: "f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600",
            pk_rm: "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a",
            sk_rm: "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb",
            enc: "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a",
            key: "ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91",
            base_nonce: "5c4d98150661b848853b547f",
            ct0: "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28",
            ct1: "6b53c051e4199c518de79594e1c4ab18b96f081549d45ce015be002090bb119e85285337cc95ba5f59992dc98c",
            export_empty: "4bbd6243b8bb54cec311fac9df81841b6fd61f56538a775e7c80a9f40160606e",
        });
    }

    #[test]
    fn rfc9180_a3_p256_sha256_aes128gcm() {
        check(&Vector {
            suite: Suite { kem: Kem::DhkemP256HkdfSha256, kdf: Kdf::HkdfSha256, aead: Aead::Aes128Gcm },
            info: "4f6465206f6e2061204772656369616e2055726e",
            sk_em: "4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb",
            pk_rm: "04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0",
            sk_rm: "f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2",
            enc: "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4",
            key: "868c066ef58aae6dc589b6cfdd18f97e",
            base_nonce: "4e0bc5018beba4bf004cca59",
            ct0: "5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434",
            ct1: "fa6f037b47fc21826b610172ca9637e82d6e5801eb31cbd3748271affd4ecb06646e0329cbdf3c3cd655b28e82",
            export_empty: "5e9bc3d236e1911d95e65b576a8a86d478fb827e8bdfe77b741b289890490d4d",
        });
    }

    #[test]
    fn generated_roundtrip_all_suites() {
        for kem in [Kem::DhkemP256HkdfSha256, Kem::DhkemX25519HkdfSha256] {
            for kdf in [Kdf::HkdfSha256, Kdf::HkdfSha384, Kdf::HkdfSha512] {
                for aead in [Aead::Aes128Gcm, Aead::Aes256Gcm, Aead::ChaCha20Poly1305] {
                    let suite = Suite { kem, kdf, aead };
                    let sk = HpkePrivateKey::generate(kem).unwrap();
                    let (enc, mut s) =
                        setup_base_sender(suite, &sk.public_key().unwrap(), b"info").unwrap();
                    let mut r = setup_base_recipient(suite, &enc, &sk, b"info").unwrap();
                    let ct = s.seal(b"aad", b"hello").unwrap();
                    assert_eq!(r.open(b"aad", &ct).unwrap(), b"hello");
                    assert_eq!(s.export(b"x", 16).unwrap(), r.export(b"x", 16).unwrap());
                }
            }
        }
    }

    #[test]
    fn tampered_or_mismatched_input_is_rejected() {
        let suite = Suite {
            kem: Kem::DhkemX25519HkdfSha256,
            kdf: Kdf::HkdfSha256,
            aead: Aead::Aes128Gcm,
        };
        let sk = HpkePrivateKey::generate(suite.kem).unwrap();
        let (enc, mut s) = setup_base_sender(suite, &sk.public_key().unwrap(), b"i").unwrap();
        let mut r = setup_base_recipient(suite, &enc, &sk, b"i").unwrap();
        let ct = s.seal(b"aad", b"hello").unwrap();
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert!(r.open(b"aad", &bad).is_err());
        assert!(r.open(b"other", &ct).is_err());
        // A rejected open does not advance the sequence number.
        assert_eq!(r.open(b"aad", &ct).unwrap(), b"hello");
        // Wrong-length encapsulated key.
        assert!(setup_base_recipient(suite, &enc[..31], &sk, b"i").is_err());
        // KEM mismatch between suite and key.
        let p256 = HpkePrivateKey::generate(Kem::DhkemP256HkdfSha256).unwrap();
        assert!(setup_base_recipient(suite, &enc, &p256, b"i").is_err());
    }
}
