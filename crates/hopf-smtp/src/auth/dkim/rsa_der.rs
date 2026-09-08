// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Minimal DER reader for the one shape DKIM needs: an X.509
//! `SubjectPublicKeyInfo` wrapping an RSA `RSAPublicKey`, as published by
//! DNS `p=` (untrusted input — no panics, every length is bounds-checked).
//! Built on [`hopf_core::asn1`]'s shared zero-copy DER reader; only the
//! DKIM-specific "unused-bits count must be exactly zero" check (stricter
//! than that shared reader — reasonable here since `p=` is attacker-
//! controlled DNS content) stays local.

use hopf_core::asn1::{parse_sequence, read_tlv_content, strip_integer_padding};

/// Extract `(modulus, exponent)` big-endian bytes (leading `0x00` sign byte
/// stripped) from a DER-encoded RSA `SubjectPublicKeyInfo`.
pub fn parse_rsa_spki(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ()> {
    let mut outer = parse_sequence(der).ok_or(())?;
    let _alg_id = outer.next().ok_or(())?;
    let bitstring_tlv = outer.next().ok_or(())?;
    let bitstring = read_tlv_content(bitstring_tlv, 0x03).ok_or(())?;
    if bitstring.is_empty() || bitstring[0] != 0 {
        return Err(());
    }
    let rsa_pub = &bitstring[1..];
    let mut inner = parse_sequence(rsa_pub).ok_or(())?;
    let n = read_tlv_content(inner.next().ok_or(())?, 0x02).ok_or(())?;
    let e = read_tlv_content(inner.next().ok_or(())?, 0x02).ok_or(())?;
    Ok((strip_integer_padding(n).to_vec(), strip_integer_padding(e).to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // A real 2048-bit RSA SPKI (test key, not used anywhere else) to exercise
    // both single- and multi-byte DER length encodings.
    #[test]
    fn parses_real_spki() {
        let der = base64_decode(TEST_RSA_SPKI_B64);
        let (n, e) = parse_rsa_spki(&der).expect("valid SPKI");
        assert_eq!(n.len(), 256); // 2048 bits
        assert_eq!(e, vec![0x01, 0x00, 0x01]); // 65537
    }

    #[test]
    fn rejects_truncated_der() {
        assert!(parse_rsa_spki(&[0x30, 0x05, 0x30, 0x03, 0x02]).is_err());
    }

    #[test]
    fn rejects_wrong_outer_tag() {
        assert!(parse_rsa_spki(&[0x31, 0x00]).is_err());
    }

    fn base64_decode(s: &str) -> Vec<u8> {
        rmimeparser::charset::base64::decode(s).unwrap()
    }

    // 2048-bit RSA public key, DER SPKI, base64 — freshly generated for this
    // test only (`openssl genrsa 2048 | openssl rsa -pubout -outform DER`).
    const TEST_RSA_SPKI_B64: &str = concat!(
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArOmINJ0/Sot0K+84PUHI",
        "OA3kg6iT7U7fTY67r91nrW7JOEo9YVrMxxhQ2zgF7igM0iSbvUzBC41+EN+bYpBv",
        "GqFpUdqxW/tvT3fc9oJ4I606uyTtnt4fKZAP3IarYHOw6hgRmJcjaoOaveO2Xjst",
        "WwuXYq8TaMCni9it99XP1UxpHjOz2xgygSQyvDlk2C6Sn8AyhVl3CfBgwkgChrT1",
        "kC1kgCwFPJmM2fDkU9zbe8G9e5HiJBNolzEqK0ob51cvaauhMGYQic1FFdA2nFLG",
        "qZibZisEhmU35UACbyxvK8d/zsBzZuskH1CTukibPnHmOJilfPlE96JsPY5EFWxe",
        "aQIDAQAB"
    );
}
