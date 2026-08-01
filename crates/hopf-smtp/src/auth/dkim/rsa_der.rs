// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Minimal DER reader for the one shape DKIM needs: an X.509
//! `SubjectPublicKeyInfo` wrapping an RSA `RSAPublicKey`, as published by
//! DNS `p=` (untrusted input — no panics, every length is bounds-checked).

/// Extract `(modulus, exponent)` big-endian bytes (leading `0x00` sign byte
/// stripped) from a DER-encoded RSA `SubjectPublicKeyInfo`.
pub fn parse_rsa_spki(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ()> {
    let (spki, _) = read_tlv(der, 0, 0x30)?;
    let (_alg_id, after_alg) = read_tlv(spki, 0, 0x30)?;
    let (bitstring, _) = read_tlv(spki, after_alg, 0x03)?;
    if bitstring.is_empty() || bitstring[0] != 0 {
        return Err(());
    }
    let rsa_pub = &bitstring[1..];
    let (inner, _) = read_tlv(rsa_pub, 0, 0x30)?;
    let (n, after_n) = read_tlv(inner, 0, 0x02)?;
    let (e, _) = read_tlv(inner, after_n, 0x02)?;
    Ok((strip_leading_zero(n), strip_leading_zero(e)))
}

fn strip_leading_zero(b: &[u8]) -> Vec<u8> {
    if b.len() > 1 && b[0] == 0 {
        b[1..].to_vec()
    } else {
        b.to_vec()
    }
}

/// Read one TLV starting at `pos`, requiring `tag`. Returns `(content, pos_after)`.
fn read_tlv(data: &[u8], pos: usize, tag: u8) -> Result<(&[u8], usize), ()> {
    if pos >= data.len() || data[pos] != tag {
        return Err(());
    }
    let mut i = pos + 1;
    if i >= data.len() {
        return Err(());
    }
    let len_byte = data[i];
    i += 1;
    let len = if len_byte & 0x80 == 0 {
        len_byte as usize
    } else {
        let n = (len_byte & 0x7f) as usize;
        if n == 0 || n > 4 || i + n > data.len() {
            return Err(());
        }
        let mut l: usize = 0;
        for k in 0..n {
            l = (l << 8) | data[i + k] as usize;
        }
        i += n;
        l
    };
    if i + len > data.len() {
        return Err(());
    }
    Ok((&data[i..i + len], i + len))
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
