// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! `ECHConfig` and `ECHConfigList` (RFC 9849 §4) plus HPKE suite selection.
//!
//! # Supported HPKE suites
//!
//! hopf offers and accepts the following for ECH (see
//! [`SUPPORTED_HPKE_SUITES`], in client preference order). All use base mode
//! (RFC 9180).
//!
//! | KEM | KDF | AEAD |
//! |-----|-----|------|
//! | DHKEM(X25519, HKDF-SHA256) `0x0020`, DHKEM(P-256, HKDF-SHA256) `0x0010` | HKDF-SHA256 `0x0001` | AES-128-GCM `0x0001`, ChaCha20-Poly1305 `0x0003`, AES-256-GCM `0x0002` |
//! | (same KEMs) | HKDF-SHA384 `0x0002`, HKDF-SHA512 `0x0003` | (same AEADs) |
//!
//! The KEM is fixed by the config's key; the KDF/AEAD pair is chosen from the
//! config's `cipher_suites` list.

use crate::crypto::hpke::{Aead, HpkeError, HpkePrivateKey, Kdf, Kem, Suite};

/// `ECHConfig.version` and `encrypted_client_hello` extension code point.
pub const ECH_VERSION: u16 = 0xfe0d;

/// Client preference order for the KDF/AEAD pair, applied to whichever of
/// these a config advertises. SHA-256 with AES-128-GCM leads; ChaCha20 next
/// for hardware without AES acceleration.
pub const SUPPORTED_HPKE_SUITES: [(Kdf, Aead); 9] = [
    (Kdf::HkdfSha256, Aead::Aes128Gcm),
    (Kdf::HkdfSha256, Aead::ChaCha20Poly1305),
    (Kdf::HkdfSha256, Aead::Aes256Gcm),
    (Kdf::HkdfSha384, Aead::Aes128Gcm),
    (Kdf::HkdfSha384, Aead::ChaCha20Poly1305),
    (Kdf::HkdfSha384, Aead::Aes256Gcm),
    (Kdf::HkdfSha512, Aead::Aes128Gcm),
    (Kdf::HkdfSha512, Aead::ChaCha20Poly1305),
    (Kdf::HkdfSha512, Aead::Aes256Gcm),
];

/// Why an `ECHConfig` / `ECHConfigList` could not be parsed or built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EchConfigError {
    /// Truncated, over-long, or otherwise structurally invalid encoding.
    Malformed,
    /// A field violates a bound in RFC 9849 §4 (e.g. empty `public_name`).
    InvalidField(&'static str),
    /// HPKE key generation failed.
    Crypto,
}

impl From<HpkeError> for EchConfigError {
    fn from(_: HpkeError) -> Self {
        EchConfigError::Crypto
    }
}

/// A KDF/AEAD identifier pair (`HpkeSymmetricCipherSuite`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HpkeCipherSuite {
    /// `HpkeKdfId`.
    pub kdf_id: u16,
    /// `HpkeAeadId`.
    pub aead_id: u16,
}

/// One parsed `ECHConfig` of version [`ECH_VERSION`].
///
/// [`Self::encoded`] holds the exact wire bytes (version and length included):
/// they are an input to the HPKE `info` string, so they are kept verbatim
/// rather than re-serialised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchConfig {
    /// `HpkeKeyConfig.config_id`.
    pub config_id: u8,
    /// `HpkeKeyConfig.kem_id`.
    pub kem_id: u16,
    /// `HpkeKeyConfig.public_key`.
    pub public_key: Vec<u8>,
    /// `HpkeKeyConfig.cipher_suites`, in the server's order.
    pub cipher_suites: Vec<HpkeCipherSuite>,
    /// `maximum_name_length`.
    pub maximum_name_length: u8,
    /// `public_name`.
    pub public_name: String,
    /// `extensions` as `(type, data)`.
    pub extensions: Vec<(u16, Vec<u8>)>,
    encoded: Vec<u8>,
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], EchConfigError> {
        if self.0.len() < n {
            return Err(EchConfigError::Malformed);
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, EchConfigError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, EchConfigError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn vec16(&mut self) -> Result<&'a [u8], EchConfigError> {
        let n = usize::from(self.u16()?);
        self.take(n)
    }

    fn vec8(&mut self) -> Result<&'a [u8], EchConfigError> {
        let n = usize::from(self.u8()?);
        self.take(n)
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl EchConfig {
    /// Build a config (and its wire encoding) from its parts.
    pub fn new(
        config_id: u8,
        kem_id: u16,
        public_key: Vec<u8>,
        cipher_suites: Vec<HpkeCipherSuite>,
        maximum_name_length: u8,
        public_name: &str,
        extensions: Vec<(u16, Vec<u8>)>,
    ) -> Result<Self, EchConfigError> {
        let mut cfg = Self {
            config_id,
            kem_id,
            public_key,
            cipher_suites,
            maximum_name_length,
            public_name: public_name.to_owned(),
            extensions,
            encoded: Vec::new(),
        };
        cfg.encoded = cfg.encode_body()?;
        Ok(cfg)
    }

    /// Generate a fresh HPKE key pair for `kem` and the matching config. The
    /// private key is returned separately: it is the server's secret and is
    /// never part of the published config.
    pub fn generate(
        config_id: u8,
        kem: Kem,
        cipher_suites: Vec<HpkeCipherSuite>,
        maximum_name_length: u8,
        public_name: &str,
    ) -> Result<(Self, HpkePrivateKey), EchConfigError> {
        let key = HpkePrivateKey::generate(kem)?;
        let cfg = Self::new(
            config_id,
            kem.id(),
            key.public_key()?,
            cipher_suites,
            maximum_name_length,
            public_name,
            Vec::new(),
        )?;
        Ok((cfg, key))
    }

    fn encode_body(&self) -> Result<Vec<u8>, EchConfigError> {
        let suites_len = self.cipher_suites.len() * 4;
        if self.public_key.is_empty() || self.public_key.len() > 0xffff {
            return Err(EchConfigError::InvalidField("public_key"));
        }
        if self.cipher_suites.is_empty() || suites_len > 0xffff - 3 {
            return Err(EchConfigError::InvalidField("cipher_suites"));
        }
        if self.public_name.is_empty() || self.public_name.len() > 255 {
            return Err(EchConfigError::InvalidField("public_name"));
        }
        let mut seen = Vec::new();
        let mut ext = Vec::new();
        for (ty, data) in &self.extensions {
            if seen.contains(ty) {
                return Err(EchConfigError::InvalidField("extensions"));
            }
            seen.push(*ty);
            let len = u16::try_from(data.len()).map_err(|_| EchConfigError::InvalidField("extensions"))?;
            ext.extend_from_slice(&ty.to_be_bytes());
            ext.extend_from_slice(&len.to_be_bytes());
            ext.extend_from_slice(data);
        }
        let ext_len = u16::try_from(ext.len()).map_err(|_| EchConfigError::InvalidField("extensions"))?;

        let mut body = Vec::new();
        body.push(self.config_id);
        body.extend_from_slice(&self.kem_id.to_be_bytes());
        body.extend_from_slice(&(self.public_key.len() as u16).to_be_bytes());
        body.extend_from_slice(&self.public_key);
        body.extend_from_slice(&(suites_len as u16).to_be_bytes());
        for s in &self.cipher_suites {
            body.extend_from_slice(&s.kdf_id.to_be_bytes());
            body.extend_from_slice(&s.aead_id.to_be_bytes());
        }
        body.push(self.maximum_name_length);
        body.push(self.public_name.len() as u8);
        body.extend_from_slice(self.public_name.as_bytes());
        body.extend_from_slice(&ext_len.to_be_bytes());
        body.extend_from_slice(&ext);

        let body_len = u16::try_from(body.len()).map_err(|_| EchConfigError::Malformed)?;
        let mut out = Vec::with_capacity(4 + body.len());
        out.extend_from_slice(&ECH_VERSION.to_be_bytes());
        out.extend_from_slice(&body_len.to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    fn parse_body(encoded: &[u8], body: &[u8]) -> Result<Self, EchConfigError> {
        let mut r = Reader(body);
        let config_id = r.u8()?;
        let kem_id = r.u16()?;
        let public_key = r.vec16()?.to_vec();
        if public_key.is_empty() {
            return Err(EchConfigError::InvalidField("public_key"));
        }
        let suites = r.vec16()?;
        if suites.len() < 4 || suites.len() % 4 != 0 {
            return Err(EchConfigError::InvalidField("cipher_suites"));
        }
        let cipher_suites = suites
            .chunks_exact(4)
            .map(|c| HpkeCipherSuite {
                kdf_id: u16::from_be_bytes([c[0], c[1]]),
                aead_id: u16::from_be_bytes([c[2], c[3]]),
            })
            .collect();
        let maximum_name_length = r.u8()?;
        let name = r.vec8()?;
        if name.is_empty() {
            return Err(EchConfigError::InvalidField("public_name"));
        }
        let public_name = std::str::from_utf8(name)
            .map_err(|_| EchConfigError::InvalidField("public_name"))?
            .to_owned();
        let mut ext_reader = Reader(r.vec16()?);
        if !r.is_empty() {
            return Err(EchConfigError::Malformed);
        }
        let mut extensions: Vec<(u16, Vec<u8>)> = Vec::new();
        while !ext_reader.is_empty() {
            let ty = ext_reader.u16()?;
            let data = ext_reader.vec16()?.to_vec();
            if extensions.iter().any(|(t, _)| *t == ty) {
                return Err(EchConfigError::InvalidField("extensions"));
            }
            extensions.push((ty, data));
        }
        Ok(Self {
            config_id,
            kem_id,
            public_key,
            cipher_suites,
            maximum_name_length,
            public_name,
            extensions,
            encoded: encoded.to_vec(),
        })
    }

    /// Parse a single `ECHConfig` of version [`ECH_VERSION`] (for example one
    /// loaded from operator configuration). Other versions are an error here;
    /// use [`Self::parse_list`] to skip them.
    pub fn parse(bytes: &[u8]) -> Result<Self, EchConfigError> {
        let mut r = Reader(bytes);
        let version = r.u16()?;
        let body = r.vec16()?;
        if !r.is_empty() || version != ECH_VERSION {
            return Err(EchConfigError::Malformed);
        }
        Self::parse_body(bytes, body)
    }

    /// Parse an `ECHConfigList`. Configs of an unknown version are skipped,
    /// as RFC 9849 §4 requires; a malformed list or a malformed config of the
    /// supported version is an error. Order (server preference) is kept.
    pub fn parse_list(bytes: &[u8]) -> Result<Vec<Self>, EchConfigError> {
        let mut r = Reader(bytes);
        let list = r.vec16()?;
        if !r.is_empty() || list.len() < 4 {
            return Err(EchConfigError::Malformed);
        }
        let mut r = Reader(list);
        let mut out = Vec::new();
        while !r.is_empty() {
            let start = r.0;
            let version = r.u16()?;
            let body = r.vec16()?;
            if version == ECH_VERSION {
                let encoded = &start[..start.len() - r.0.len()];
                out.push(Self::parse_body(encoded, body)?);
            }
        }
        Ok(out)
    }

    /// Encode configs as an `ECHConfigList`.
    pub fn encode_list(configs: &[Self]) -> Result<Vec<u8>, EchConfigError> {
        let len: usize = configs.iter().map(|c| c.encoded.len()).sum();
        let len = u16::try_from(len).map_err(|_| EchConfigError::Malformed)?;
        if len < 4 {
            return Err(EchConfigError::Malformed);
        }
        let mut out = Vec::with_capacity(2 + usize::from(len));
        out.extend_from_slice(&len.to_be_bytes());
        for c in configs {
            out.extend_from_slice(&c.encoded);
        }
        Ok(out)
    }

    /// The exact `ECHConfig` wire bytes (version and length included).
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    /// HPKE `info` for this config: `"tls ech" || 0x00 || ECHConfig`
    /// (RFC 9849 §6.1).
    pub fn hpke_info(&self) -> Vec<u8> {
        let mut info = Vec::with_capacity(8 + self.encoded.len());
        info.extend_from_slice(b"tls ech\0");
        info.extend_from_slice(&self.encoded);
        info
    }

    /// Whether the config advertises this KDF/AEAD pair. A server uses this
    /// to reject a client that picked a suite the config never offered.
    pub fn advertises(&self, kdf_id: u16, aead_id: u16) -> bool {
        self.cipher_suites
            .iter()
            .any(|s| s.kdf_id == kdf_id && s.aead_id == aead_id)
    }

    /// The configured KEM, if hopf supports it.
    pub fn kem(&self) -> Option<Kem> {
        Kem::from_id(self.kem_id)
    }

    /// Whether a client may use this config (RFC 9849 §4.2, §6.1, §6.1.7):
    /// supported KEM with a correctly sized key, a valid `public_name`, and no
    /// unsupported mandatory extension. hopf defines no ECH config extensions,
    /// so any extension with the high bit set (mandatory) disqualifies it.
    pub fn is_usable_by_client(&self) -> bool {
        let Some(kem) = self.kem() else {
            return false;
        };
        self.public_key.len() == kem.public_key_len()
            && is_valid_public_name(&self.public_name)
            && !self.extensions.iter().any(|(ty, _)| ty & 0x8000 != 0)
    }
}

/// RFC 9849 §6.1.7 `public_name` validation: dot-separated LDH labels of at
/// most 63 octets, no leading or trailing dot, and a final label that cannot
/// be read as an IPv4 literal (all digits, or `0x` followed by hex digits).
fn is_valid_public_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 255 || name.starts_with('.') || name.ends_with('.') {
        return false;
    }
    let mut last = "";
    for label in name.split('.') {
        let ldh = !label.is_empty()
            && label.len() <= 63
            && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-');
        if !ldh {
            return false;
        }
        last = label;
    }
    let all_digits = last.bytes().all(|b| b.is_ascii_digit());
    let hex_literal = last
        .strip_prefix("0x")
        .or_else(|| last.strip_prefix("0X"))
        .is_some_and(|rest| rest.bytes().all(|b| b.is_ascii_hexdigit()));
    !(all_digits || hex_literal)
}

/// The config and HPKE suite a client will use.
#[derive(Debug, Clone, Copy)]
pub struct EchSelection<'a> {
    /// The chosen config.
    pub config: &'a EchConfig,
    /// The negotiated KEM/KDF/AEAD.
    pub suite: Suite,
}

/// Choose an `ECHConfig` and HPKE suite (RFC 9849 §6.1).
///
/// Configs are considered in the server's order; the first usable one whose
/// `cipher_suites` include a pair from `preference` wins, and the pair is the
/// first in `preference` that the config advertises. Nothing outside the
/// config's advertised list is ever chosen. `None` means the client should
/// fall back to GREASE ECH or a plain handshake (RFC 9849 §6.2).
pub fn select_config<'a>(
    configs: &'a [EchConfig],
    preference: &[(Kdf, Aead)],
) -> Option<EchSelection<'a>> {
    configs.iter().find_map(|config| {
        if !config.is_usable_by_client() {
            return None;
        }
        let kem = config.kem()?;
        preference
            .iter()
            .find(|(kdf, aead)| config.advertises(kdf.id(), aead.id()))
            .map(|&(kdf, aead)| EchSelection {
                config,
                suite: Suite { kem, kdf, aead },
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// config_id 7, X25519, suites {SHA256/ChaCha20, SHA384/AES-256}, name
    /// `public.example.com`, no extensions.
    const CONFIG_A: &str = "fe0d00450700200020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000800010003000200022a127075626c69632e6578616d706c652e636f6d0000";
    /// A list of CONFIG_A, then config_id 9 {SHA256/AES-128} carrying a
    /// mandatory (0x8001) extension this stack does not implement.
    const LIST_AB: &str = "0091fe0d00450700200020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000800010003000200022a127075626c69632e6578616d706c652e636f6d0000fe0d00440900200020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00040001000100116f746865722e6578616d706c652e6e6574000480010000";

    #[test]
    fn parses_fixed_config_blob() {
        let bytes = unhex(CONFIG_A);
        let cfg = EchConfig::parse(&bytes).unwrap();
        assert_eq!(cfg.config_id, 7);
        assert_eq!(cfg.kem_id, 0x20);
        assert_eq!(cfg.public_key, (0u8..32).collect::<Vec<_>>());
        assert_eq!(
            cfg.cipher_suites,
            vec![
                HpkeCipherSuite { kdf_id: 1, aead_id: 3 },
                HpkeCipherSuite { kdf_id: 2, aead_id: 2 },
            ]
        );
        assert_eq!(cfg.maximum_name_length, 42);
        assert_eq!(cfg.public_name, "public.example.com");
        assert_eq!(cfg.encoded(), &bytes[..]);
        assert_eq!(&cfg.hpke_info()[..8], b"tls ech\0");
        assert_eq!(&cfg.hpke_info()[8..], &bytes[..]);
    }

    #[test]
    fn encoding_round_trips_the_fixed_blob() {
        let built = EchConfig::new(
            7,
            0x20,
            (0u8..32).collect(),
            vec![
                HpkeCipherSuite { kdf_id: 1, aead_id: 3 },
                HpkeCipherSuite { kdf_id: 2, aead_id: 2 },
            ],
            42,
            "public.example.com",
            Vec::new(),
        )
        .unwrap();
        assert_eq!(built.encoded(), &unhex(CONFIG_A)[..]);
    }

    #[test]
    fn parse_list_keeps_order_and_skips_unknown_versions() {
        let mut list = unhex(LIST_AB);
        let configs = EchConfig::parse_list(&list).unwrap();
        assert_eq!(configs.len(), 2);
        assert_eq!(configs[0].config_id, 7);
        assert_eq!(configs[1].config_id, 9);
        assert_eq!(EchConfig::encode_list(&configs).unwrap(), list);

        // Prepend an unknown-version config (0xfe0c, 5 opaque bytes).
        let unknown = [0xfe, 0x0c, 0x00, 0x05, 1, 2, 3, 4, 5];
        let body = list.split_off(2);
        let mut with_unknown = Vec::new();
        with_unknown.extend_from_slice(&((body.len() + unknown.len()) as u16).to_be_bytes());
        with_unknown.extend_from_slice(&unknown);
        with_unknown.extend_from_slice(&body);
        let configs = EchConfig::parse_list(&with_unknown).unwrap();
        assert_eq!(configs.len(), 2);
        assert_eq!(configs[0].config_id, 7);
    }

    #[test]
    fn malformed_encodings_are_rejected() {
        let bytes = unhex(CONFIG_A);
        for cut in [0, 1, 3, 10, bytes.len() - 1] {
            assert!(EchConfig::parse(&bytes[..cut]).is_err(), "cut {cut}");
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(EchConfig::parse(&trailing).is_err());
        assert!(EchConfig::parse_list(&[0, 0]).is_err());
        assert!(EchConfig::parse_list(&unhex(LIST_AB)[..20]).is_err());
        // Cipher-suite list not a multiple of four octets.
        let mut bad = bytes.clone();
        bad[4 + 1 + 2 + 2 + 32 + 1] = 7;
        assert!(EchConfig::parse(&bad).is_err());
    }

    #[test]
    fn selection_picks_client_preferred_advertised_suite() {
        let cfg = EchConfig::parse(&unhex(CONFIG_A)).unwrap();
        let configs = [cfg];
        // AES-128-GCM is preferred but not advertised: rejected. ChaCha20 is.
        let sel = select_config(&configs, &SUPPORTED_HPKE_SUITES).unwrap();
        assert_eq!(sel.suite.kem, Kem::DhkemX25519HkdfSha256);
        assert_eq!((sel.suite.kdf, sel.suite.aead), (Kdf::HkdfSha256, Aead::ChaCha20Poly1305));
        assert_eq!(sel.config.config_id, 7);

        // Client order decides between two advertised suites.
        let prefer_384 = [(Kdf::HkdfSha384, Aead::Aes256Gcm), (Kdf::HkdfSha256, Aead::ChaCha20Poly1305)];
        let sel = select_config(&configs, &prefer_384).unwrap();
        assert_eq!((sel.suite.kdf, sel.suite.aead), (Kdf::HkdfSha384, Aead::Aes256Gcm));

        // A client supporting none of the advertised pairs gets nothing.
        assert!(select_config(&configs, &[(Kdf::HkdfSha256, Aead::Aes128Gcm)]).is_none());
        assert!(!configs[0].advertises(1, 1));
        assert!(configs[0].advertises(1, 3));
    }

    #[test]
    fn selection_skips_unusable_configs() {
        let configs = EchConfig::parse_list(&unhex(LIST_AB)).unwrap();
        // Config 9 carries an unsupported mandatory extension.
        assert!(!configs[1].is_usable_by_client());
        let only_b = &configs[1..];
        assert!(select_config(only_b, &SUPPORTED_HPKE_SUITES).is_none());

        let key = vec![1u8; 32];
        let suites = vec![HpkeCipherSuite { kdf_id: 1, aead_id: 1 }];
        // Unsupported KEM (DHKEM(X448)).
        let x448 = EchConfig::new(1, 0x21, vec![1; 56], suites.clone(), 0, "a.example", vec![]).unwrap();
        // Right KEM, wrong key length.
        let short = EchConfig::new(2, 0x20, vec![1; 31], suites.clone(), 0, "a.example", vec![]).unwrap();
        // Public name that reads as an IPv4 literal.
        let ip = EchConfig::new(3, 0x20, key.clone(), suites.clone(), 0, "1.2.3.4", vec![]).unwrap();
        let good = EchConfig::new(4, 0x20, key, suites, 0, "a.example", vec![]).unwrap();
        let all = [x448, short, ip, good];
        let sel = select_config(&all, &SUPPORTED_HPKE_SUITES).unwrap();
        assert_eq!(sel.config.config_id, 4);
    }

    #[test]
    fn public_name_validation() {
        for ok in ["example.com", "a-b.example", "xn--bcher-kva.example", "a.b1"] {
            assert!(is_valid_public_name(ok), "{ok}");
        }
        for bad in [
            "", ".example.com", "example.com.", "a..b", "-a.example", "a-.example",
            "under_score.example", "1.2.3.4", "example.0x1f", "example.0X", "a.example ",
        ] {
            assert!(!is_valid_public_name(bad), "{bad}");
        }
        assert!(!is_valid_public_name(&format!("{}.example", "a".repeat(64))));
    }

    #[test]
    fn builder_enforces_field_bounds() {
        let suites = vec![HpkeCipherSuite { kdf_id: 1, aead_id: 1 }];
        let build = |name: &str, key: Vec<u8>, s: Vec<HpkeCipherSuite>, ext: Vec<(u16, Vec<u8>)>| {
            EchConfig::new(0, 0x20, key, s, 0, name, ext)
        };
        assert!(build("", vec![1; 32], suites.clone(), vec![]).is_err());
        assert!(build(&"a".repeat(256), vec![1; 32], suites.clone(), vec![]).is_err());
        assert!(build("a.example", vec![], suites.clone(), vec![]).is_err());
        assert!(build("a.example", vec![1; 32], vec![], vec![]).is_err());
        assert!(build("a.example", vec![1; 32], suites.clone(), vec![(1, vec![]), (1, vec![])]).is_err());
    }

    #[test]
    fn generated_config_round_trips_and_matches_key() {
        let suites = vec![HpkeCipherSuite { kdf_id: 1, aead_id: 1 }];
        let (cfg, key) = EchConfig::generate(3, Kem::DhkemP256HkdfSha256, suites, 32, "front.example").unwrap();
        assert_eq!(cfg.public_key, key.public_key().unwrap());
        let list = EchConfig::encode_list(std::slice::from_ref(&cfg)).unwrap();
        let parsed = EchConfig::parse_list(&list).unwrap();
        assert_eq!(parsed, vec![cfg]);
        assert!(parsed[0].is_usable_by_client());
    }
}
