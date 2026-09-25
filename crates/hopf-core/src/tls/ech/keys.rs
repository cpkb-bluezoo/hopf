// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Loading ECH server keys from PEM.
//!
//! The accepted layout is the one `openssl ech` and most ECH key generators
//! write: a PKCS#8 `PRIVATE KEY` block for the HPKE key, and an `ECHCONFIG`
//! block holding the base64 of an `ECHConfigList`. A file may hold several
//! keys and several configs; each config is paired with the private key
//! whose public key it carries.
//!
//! # Rotation
//!
//! Give each key its own file (or block) and rebuild the [`EchServerConfig`]
//! from the current set:
//!
//! 1. Generate a new key with a fresh `config_id` and publish its config
//!    (DNS HTTPS/SVCB `ech` parameter) alongside the old one.
//! 2. Load both. New connections may use either; `retry_configs` advertises
//!    both.
//! 3. Once the old config's DNS records have expired everywhere, mark the old
//!    key [`retired`](EchServerKey::retired): it still decrypts, but is no
//!    longer advertised.
//! 4. After a further overlap, drop it. Clients still holding it are then
//!    refused ECH, told the current configs in `retry_configs`, and
//!    reconnect.
//!
//! Choose `config_id`s distinct from every key still loaded, so a lookup
//! matches one key instead of trial-decrypting several (RFC 9849 §4.1).

use crate::asn1::{parse_sequence, read_oid, read_tlv_content};
use crate::crypto::hpke::{HpkePrivateKey, Kem};
use crate::pem::parse_pem_blocks;

use super::{EchConfig, EchConfigError, EchServerConfig, EchServerKey};

const OID_X25519: &[u8] = &[0x2b, 0x65, 0x6e];
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_PRIME256V1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

/// The KEM and raw private-key octets inside a PKCS#8 `PrivateKeyInfo`
/// (X25519 or P-256), or `None` for anything else.
fn pkcs8_hpke_key(der: &[u8]) -> Option<(Kem, Vec<u8>)> {
    let mut info = parse_sequence(der)?;
    info.next()?; // version
    let mut alg = parse_sequence(info.next()?)?;
    let oid = read_oid(alg.next()?)?;
    let key_octets = read_tlv_content(info.next()?, 0x04)?;
    if oid == OID_X25519 {
        // CurvePrivateKey ::= OCTET STRING
        let raw = read_tlv_content(key_octets, 0x04)?;
        return Some((Kem::DhkemX25519HkdfSha256, raw.to_vec()));
    }
    if oid == OID_EC_PUBLIC_KEY && read_oid(alg.next()?)? == OID_PRIME256V1 {
        // ECPrivateKey ::= SEQUENCE { version, privateKey OCTET STRING, ... }
        let mut ec = parse_sequence(key_octets)?;
        ec.next()?;
        let raw = read_tlv_content(ec.next()?, 0x04)?;
        return Some((Kem::DhkemP256HkdfSha256, raw.to_vec()));
    }
    None
}

impl EchServerKey {
    /// Load every key described by `pem`: each config in an `ECHCONFIG` block
    /// paired with the `PRIVATE KEY` whose public key it carries. Configs of
    /// an unknown ECH version are skipped (as clients skip them); a config
    /// with no matching private key, or a PEM with no config at all, is an
    /// error, so a mismatched key file cannot silently publish nothing.
    pub fn from_pem(pem: &[u8]) -> Result<Vec<Self>, EchConfigError> {
        let blocks = parse_pem_blocks(pem);
        // (kem, raw private key, public key) for every usable PRIVATE KEY.
        let keys: Vec<(Kem, Vec<u8>, Vec<u8>)> = blocks
            .iter()
            .filter(|b| b.label == "PRIVATE KEY")
            .filter_map(|b| pkcs8_hpke_key(&b.der))
            .filter_map(|(kem, raw)| {
                let public = HpkePrivateKey::from_bytes(kem, &raw).ok()?.public_key().ok()?;
                Some((kem, raw, public))
            })
            .collect();
        let mut out = Vec::new();
        let mut configs = 0usize;
        for block in blocks.iter().filter(|b| b.label == "ECHCONFIG") {
            for config in EchConfig::parse_list(&block.der)? {
                configs += 1;
                let (kem, raw, _) = keys
                    .iter()
                    .find(|(_, _, public)| *public == config.public_key)
                    .ok_or(EchConfigError::InvalidField("no private key for ECHConfig"))?;
                out.push(Self::new(config, HpkePrivateKey::from_bytes(*kem, raw)?)?);
            }
        }
        if configs == 0 {
            return Err(EchConfigError::InvalidField("no ECHCONFIG block"));
        }
        Ok(out)
    }
}

impl EchServerConfig {
    /// Build a server configuration from one PEM document (see
    /// [`EchServerKey::from_pem`]); every key it yields is advertised.
    pub fn from_pem(pem: &[u8]) -> Result<Self, EchConfigError> {
        Ok(Self::new(EchServerKey::from_pem(pem)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::ech::HpkeCipherSuite;

    fn b64(data: &[u8]) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let n = (u32::from(chunk[0]) << 16)
                | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
                | u32::from(*chunk.get(2).unwrap_or(&0));
            for i in 0..4 {
                if i <= chunk.len() {
                    out.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    fn pem(label: &str, der: &[u8]) -> String {
        format!("-----BEGIN {label}-----\n{}\n-----END {label}-----\n", b64(der))
    }

    fn x25519_pkcs8(raw: &[u8; 32]) -> Vec<u8> {
        let mut v = vec![0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20];
        v.extend_from_slice(raw);
        v
    }

    fn p256_pkcs8(raw: &[u8; 32]) -> Vec<u8> {
        let mut v = vec![0x30, 0x41, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07];
        v.extend_from_slice(OID_EC_PUBLIC_KEY);
        v.extend_from_slice(&[0x06, 0x08]);
        v.extend_from_slice(OID_PRIME256V1);
        v.extend_from_slice(&[0x04, 0x27, 0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20]);
        v.extend_from_slice(raw);
        v
    }

    fn config_for(kem: Kem, raw: &[u8; 32], id: u8) -> EchConfig {
        let public = HpkePrivateKey::from_bytes(kem, raw).unwrap().public_key().unwrap();
        EchConfig::new(id, kem.id(), public, vec![HpkeCipherSuite { kdf_id: 1, aead_id: 1 }], 0, "public.example", vec![])
            .unwrap()
    }

    #[test]
    fn loads_an_x25519_key_and_its_config() {
        let raw = [7u8; 32];
        let config = config_for(Kem::DhkemX25519HkdfSha256, &raw, 3);
        let text = format!(
            "{}{}",
            pem("PRIVATE KEY", &x25519_pkcs8(&raw)),
            pem("ECHCONFIG", &EchConfig::encode_list(std::slice::from_ref(&config)).unwrap())
        );
        let keys = EchServerKey::from_pem(text.as_bytes()).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].config(), &config);
        let server = EchServerConfig::from_pem(text.as_bytes()).unwrap();
        assert_eq!(server.retry_configs().unwrap(), EchConfig::encode_list(&[config]).unwrap());
    }

    #[test]
    fn loads_a_p256_key_and_several_configs() {
        let (a, b) = ([1u8; 32], [2u8; 32]);
        let (ca, cb) = (config_for(Kem::DhkemP256HkdfSha256, &a, 1), config_for(Kem::DhkemX25519HkdfSha256, &b, 2));
        let text = format!(
            "{}{}{}",
            pem("PRIVATE KEY", &p256_pkcs8(&a)),
            pem("PRIVATE KEY", &x25519_pkcs8(&b)),
            pem("ECHCONFIG", &EchConfig::encode_list(&[ca.clone(), cb.clone()]).unwrap())
        );
        let keys = EchServerKey::from_pem(text.as_bytes()).unwrap();
        assert_eq!(keys.iter().map(|k| k.config().config_id).collect::<Vec<_>>(), vec![1, 2]);
    }

    /// Keys written by `openssl genpkey`, with the public keys OpenSSL derived
    /// from them, so the PKCS#8 parsing is checked against a real encoder.
    #[test]
    fn parses_keys_written_by_openssl() {
        let cases = [
            (
                "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VuBCIEIAhKmmbB3+foeXrbYeGfcJqXnEzpqBjdnsuVmHwhGORX\n-----END PRIVATE KEY-----\n",
                Kem::DhkemX25519HkdfSha256,
                "b9194f89cd91472f729e706c3bf9116d7eac91c2fc3143a13181f41204a95b41",
            ),
            (
                "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgFgthGqOfSCY2qeVM\nePvAqPBCFrZapAXRahGX6f8iy8WhRANCAAQBqWdLKe4yIZCo+Wx4bAwsYwIRuJt1\noChM2OiLjl/2x2i3E533cvrHskn4bbEOSKryGUxrufYIAauCh56aiMsJ\n-----END PRIVATE KEY-----\n",
                Kem::DhkemP256HkdfSha256,
                "0401a9674b29ee322190a8f96c786c0c2c630211b89b75a0284cd8e88b8e5ff6c768b7139df772fac7b249f86db10e48aaf2194c6bb9f60801ab82879e9a88cb09",
            ),
        ];
        for (text, kem, public_hex) in cases {
            let der = &parse_pem_blocks(text.as_bytes())[0].der;
            let (got_kem, raw) = pkcs8_hpke_key(der).expect("recognised");
            assert_eq!(got_kem, kem);
            let public = HpkePrivateKey::from_bytes(kem, &raw).unwrap().public_key().unwrap();
            let expected: Vec<u8> = (0..public_hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&public_hex[i..i + 2], 16).unwrap())
                .collect();
            assert_eq!(public, expected);
        }
    }

    #[test]
    fn a_config_without_its_private_key_is_an_error() {
        let config = config_for(Kem::DhkemX25519HkdfSha256, &[7; 32], 3);
        let other = x25519_pkcs8(&[9; 32]);
        let text = format!(
            "{}{}",
            pem("PRIVATE KEY", &other),
            pem("ECHCONFIG", &EchConfig::encode_list(&[config]).unwrap())
        );
        assert!(EchServerKey::from_pem(text.as_bytes()).is_err());
    }

    #[test]
    fn a_pem_with_no_config_or_junk_is_an_error() {
        assert!(EchServerKey::from_pem(b"").is_err());
        assert!(EchServerKey::from_pem(pem("PRIVATE KEY", &x25519_pkcs8(&[7; 32])).as_bytes()).is_err());
        assert!(EchServerKey::from_pem(pem("ECHCONFIG", &[0, 1, 2]).as_bytes()).is_err());
        assert!(pkcs8_hpke_key(&[0x30, 0x00]).is_none());
    }
}
