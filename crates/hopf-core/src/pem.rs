// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! RFC 7468 PEM ("Textual Encodings of PKIX, PKCS, and CMS Structures")
//! parsing — certificates and PKCS#8 private keys only, the two block
//! types this crate's TLS stack (and `hopf-quic`'s own PEM loaders) need.
//! The format itself is a `-----BEGIN <label>-----` / base64 body /
//! `-----END <label>-----` wrapper around DER, simple enough not to
//! warrant an external dependency.

/// One decoded PEM block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PemBlock {
    /// The label between the BEGIN/END markers (e.g. `"CERTIFICATE"`, `"PRIVATE KEY"`).
    pub label: String,
    /// Base64-decoded body (the DER content).
    pub der: Vec<u8>,
}

/// Parse every well-formed `-----BEGIN <label>-----`/`-----END <label>-----`
/// block in `pem`, in order. A block whose BEGIN/END labels don't match,
/// or whose body doesn't base64-decode, is skipped rather than failing
/// the whole parse — a PEM bundle commonly carries entries a given caller
/// doesn't care about (e.g. `EC PARAMETERS` alongside a certificate
/// chain), and only the labels a caller actually filters for matter.
pub fn parse_pem_blocks(pem: &[u8]) -> Vec<PemBlock> {
    let text = String::from_utf8_lossy(pem);
    let mut blocks = Vec::new();
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        let Some(label) = begin_label(line) else {
            continue;
        };
        let mut body = String::new();
        let mut ended = false;
        for line in lines.by_ref() {
            if let Some(end_label) = end_label(line) {
                ended = end_label == label;
                break;
            }
            body.push_str(line.trim());
        }
        if !ended {
            continue;
        }
        if let Some(der) = base64_decode(&body) {
            blocks.push(PemBlock { label: label.to_string(), der });
        }
    }
    blocks
}

fn begin_label(line: &str) -> Option<&str> {
    line.trim().strip_prefix("-----BEGIN ")?.strip_suffix("-----")
}

fn end_label(line: &str) -> Option<&str> {
    line.trim().strip_prefix("-----END ")?.strip_suffix("-----")
}

/// Every DER-encoded `CERTIFICATE` block in `pem`, in order.
pub fn parse_certs(pem: &[u8]) -> Vec<Vec<u8>> {
    parse_pem_blocks(pem)
        .into_iter()
        .filter(|b| b.label == "CERTIFICATE")
        .map(|b| b.der)
        .collect()
}

/// Every DER-encoded `PRIVATE KEY` (PKCS#8) block in `pem`, in order.
/// `RSA PRIVATE KEY` (PKCS#1) and `EC PRIVATE KEY` (SEC1) blocks are not
/// recognized — this crate's TLS stack only ever loads PKCS#8 keys (see
/// `tls::pem`'s own module doc for the re-encoding instructions that implies
/// for a legacy key).
pub fn parse_pkcs8_keys(pem: &[u8]) -> Vec<Vec<u8>> {
    parse_pem_blocks(pem)
        .into_iter()
        .filter(|b| b.label == "PRIVATE KEY")
        .map(|b| b.der)
        .collect()
}

/// Standard base64 (RFC 4648 §4) decode. Padding (`=`) is tolerated but
/// not required — decoding simply stops at the first `=`.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let mut bits: u32 = 0;
    let mut bit_count: u32 = 0;
    for c in s.bytes() {
        if c == b'=' {
            break;
        }
        let val = ALPHABET.iter().position(|&b| b == c)? as u32;
        bits = (bits << 6) | val;
        bit_count += 6;
        if bit_count >= 8 {
            bit_count -= 8;
            out.push((bits >> bit_count) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_single_certificate_block() {
        // "hello" base64-encoded, just to prove the decode path — real
        // certs are DER, but the PEM framing doesn't care what's inside.
        let pem = b"-----BEGIN CERTIFICATE-----\naGVsbG8=\n-----END CERTIFICATE-----\n";
        let certs = parse_certs(pem);
        assert_eq!(certs, vec![b"hello".to_vec()]);
    }

    #[test]
    fn parses_multiple_blocks_in_order() {
        let pem = b"-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n\
                    -----BEGIN CERTIFICATE-----\nAQ==\n-----END CERTIFICATE-----\n";
        let certs = parse_certs(pem);
        assert_eq!(certs, vec![vec![0u8], vec![1u8]]);
    }

    #[test]
    fn ignores_blocks_with_a_different_label() {
        let pem = b"-----BEGIN EC PARAMETERS-----\nBgUrgQQAIg==\n-----END EC PARAMETERS-----\n\
                    -----BEGIN CERTIFICATE-----\naGVsbG8=\n-----END CERTIFICATE-----\n";
        let certs = parse_certs(pem);
        assert_eq!(certs, vec![b"hello".to_vec()]);
    }

    #[test]
    fn base64_body_may_be_wrapped_across_multiple_lines() {
        // 48 'A' bytes base64-encoded, deliberately wrapped mid-quantum
        // (line break not on a 4-character boundary) to prove line-joining
        // happens before decoding, not after.
        let body_bytes = vec![0x41u8; 48];
        let mut encoded = String::new();
        {
            const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            for chunk in body_bytes.chunks(3) {
                let b0 = chunk[0] as u32;
                let b1 = *chunk.get(1).unwrap_or(&0) as u32;
                let b2 = *chunk.get(2).unwrap_or(&0) as u32;
                let n = (b0 << 16) | (b1 << 8) | b2;
                encoded.push(ALPHABET[(n >> 18 & 0x3f) as usize] as char);
                encoded.push(ALPHABET[(n >> 12 & 0x3f) as usize] as char);
                encoded.push(ALPHABET[(n >> 6 & 0x3f) as usize] as char);
                encoded.push(ALPHABET[(n & 0x3f) as usize] as char);
            }
        }
        let (first, second) = encoded.split_at(17); // arbitrary, not aligned to 4
        let pem = format!("-----BEGIN PRIVATE KEY-----\n{first}\n{second}\n-----END PRIVATE KEY-----\n");
        let keys = parse_pkcs8_keys(pem.as_bytes());
        assert_eq!(keys, vec![body_bytes]);
    }

    #[test]
    fn mismatched_begin_end_labels_are_skipped() {
        let pem = b"-----BEGIN CERTIFICATE-----\naGVsbG8=\n-----END PRIVATE KEY-----\n";
        assert!(parse_certs(pem).is_empty());
        assert!(parse_pkcs8_keys(pem).is_empty());
    }

    #[test]
    fn no_blocks_at_all_returns_empty() {
        assert!(parse_certs(b"not a pem file\njust some text\n").is_empty());
    }

    #[test]
    fn private_key_label_is_not_confused_with_pkcs1_or_sec1() {
        let pem = b"-----BEGIN RSA PRIVATE KEY-----\naGVsbG8=\n-----END RSA PRIVATE KEY-----\n\
                    -----BEGIN EC PRIVATE KEY-----\naGVsbG8=\n-----END EC PRIVATE KEY-----\n\
                    -----BEGIN PRIVATE KEY-----\nd29ybGQ=\n-----END PRIVATE KEY-----\n";
        assert_eq!(parse_pkcs8_keys(pem), vec![b"world".to_vec()]);
    }
}
