// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Pick TLS 1.2 vs 1.3 from the first handshake flight (no mid-connection
//! version change afterward).

use crate::tls::handshake::messages::ext;
use crate::tls::tls12::messages::parse_client_hello;

const TLS12: u16 = 0x0303;
const TLS13: u16 = 0x0304;
const DTLS12: u16 = 0xfefd;
const DTLS13: u16 = 0xfefc;

fn offers_v13(versions: &[u16]) -> bool {
    versions.iter().any(|v| *v == TLS13 || *v == DTLS13)
}

fn offers_v12(versions: &[u16]) -> bool {
    versions.iter().any(|v| *v == TLS12 || *v == DTLS12)
}

fn wire_version_is_v13(ver: u16) -> bool {
    ver == TLS13 || ver == DTLS13
}

fn wire_version_is_v12(ver: u16) -> bool {
    ver == TLS12 || ver == DTLS12
}

const RECORD_HANDSHAKE: u8 = 22;

/// Negotiated wire protocol for one TCP connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PickedTls {
    V13,
    V12,
}

/// Prefer TLS 1.3 when the peer's `ClientHello` advertises it.
pub(crate) fn pick_server_version(client_hello_body: &[u8]) -> Option<PickedTls> {
    if client_hello_body.len() < 2 {
        return None;
    }
    let legacy = u16::from_be_bytes([client_hello_body[0], client_hello_body[1]]);
    if let Some(parsed) = parse_client_hello(client_hello_body) {
        if let Some(versions) = &parsed.supported_versions {
            if offers_v13(versions) {
                return Some(PickedTls::V13);
            }
            if offers_v12(versions) {
                return Some(PickedTls::V12);
            }
            if legacy >= TLS12 || legacy == DTLS12 {
                return Some(PickedTls::V12);
            }
            return None;
        }
    }
    if legacy >= TLS12 || legacy == DTLS12 {
        Some(PickedTls::V12)
    } else {
        None
    }
}

/// Inspect the first `ServerHello` body after our `ClientHello` was sent.
pub(crate) fn pick_client_version(server_hello_body: &[u8]) -> Option<PickedTls> {
    if let Some(ver) = supported_version_in_server_hello(server_hello_body) {
        if wire_version_is_v13(ver) {
            return Some(PickedTls::V13);
        }
        if wire_version_is_v12(ver) {
            return Some(PickedTls::V12);
        }
        return None;
    }
    Some(PickedTls::V12)
}

fn supported_version_in_server_hello(body: &[u8]) -> Option<u16> {
    if body.len() < 2 + 32 + 1 {
        return None;
    }
    let mut i = 2usize + 32;
    let sid_len = *body.get(i)? as usize;
    i += 1 + sid_len + 2 + 1;
    if i + 2 > body.len() {
        return None;
    }
    let ext_len = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
    i += 2;
    if body.len() < i + ext_len {
        return None;
    }
    let ext_block = &body[i..i + ext_len];
    let mut k = 0;
    while k + 4 <= ext_block.len() {
        let et = u16::from_be_bytes([ext_block[k], ext_block[k + 1]]);
        let el = u16::from_be_bytes([ext_block[k + 2], ext_block[k + 3]]) as usize;
        k += 4;
        if k + el > ext_block.len() {
            break;
        }
        if et == ext::SUPPORTED_VERSIONS && el == 2 {
            let data = &ext_block[k..k + el];
            return Some(u16::from_be_bytes([data[0], data[1]]));
        }
        k += el;
    }
    None
}

/// Buffer until the first complete `ClientHello` handshake message is present
/// in cleartext TLS records. Returns how many bytes from `buf` were consumed
/// for detection (the whole prefix should be fed to the chosen engine).
pub(crate) fn find_client_hello_in_records(buf: &[u8]) -> Result<Option<(PickedTls, usize)>, ()> {
    let mut off = 0;
    while off + 5 <= buf.len() {
        let typ = buf[off];
        let rec_len = u16::from_be_bytes([buf[off + 3], buf[off + 4]]) as usize;
        if off + 5 + rec_len > buf.len() {
            return Ok(None);
        }
        if typ == RECORD_HANDSHAKE {
            let payload = &buf[off + 5..off + 5 + rec_len];
            let mut p = 0;
            while p + 4 <= payload.len() {
                let htyp = payload[p];
                let hlen = handshake_len(&payload[p + 1..p + 4])?;
                if p + 4 + hlen > payload.len() {
                    return Ok(None);
                }
                if htyp == 1 {
                    let body = &payload[p + 4..p + 4 + hlen];
                    let pick = pick_server_version(body).ok_or(())?;
                    return Ok(Some((pick, off + 5 + rec_len)));
                }
                p += 4 + hlen;
            }
        }
        off += 5 + rec_len;
    }
    Ok(None)
}

/// After the client has sent `ClientHello`, buffer server records until
/// `ServerHello` is complete.
pub(crate) fn find_server_hello_in_records(buf: &[u8]) -> Result<Option<(PickedTls, usize)>, ()> {
    let mut off = 0;
    while off + 5 <= buf.len() {
        let typ = buf[off];
        let rec_len = u16::from_be_bytes([buf[off + 3], buf[off + 4]]) as usize;
        if off + 5 + rec_len > buf.len() {
            return Ok(None);
        }
        if typ == RECORD_HANDSHAKE {
            let payload = &buf[off + 5..off + 5 + rec_len];
            let mut p = 0;
            while p + 4 <= payload.len() {
                let htyp = payload[p];
                let hlen = handshake_len(&payload[p + 1..p + 4])?;
                if p + 4 + hlen > payload.len() {
                    return Ok(None);
                }
                if htyp == 2 {
                    let body = &payload[p + 4..p + 4 + hlen];
                    let pick = pick_client_version(body).ok_or(())?;
                    return Ok(Some((pick, buf.len())));
                }
                p += 4 + hlen;
            }
        }
        off += 5 + rec_len;
    }
    Ok(None)
}

pub(crate) fn handshake_len(b: &[u8]) -> Result<usize, ()> {
    if b.len() < 3 {
        return Err(());
    }
    Ok(((b[0] as usize) << 16) | ((b[1] as usize) << 8) | (b[2] as usize))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::handshake::messages::{build_client_hello, ClientHelloParams, KeyShareEntry};
    use crate::tls::engine::SUPPORTED_CIPHER_SUITES;
    use crate::tls::tls12::messages::build_client_hello as build_client_hello12;

    #[test]
    fn picks_tls13_when_client_offers_0304() {
        let body = build_client_hello(&ClientHelloParams {
            random: [0; 32],
            cipher_suites: SUPPORTED_CIPHER_SUITES.to_vec(),
            key_share: KeyShareEntry { group: 0x001d, share: bytes::Bytes::from(vec![1, 2, 3]) },
            supported_groups: vec![0x001d],
            alpn: vec![],
            server_name: None,
            transport_parameters: None,
            early_data: false,
            psk: None,
            cookie: None,
            record_size_limit: None,
            legacy_version: 0x0303,
            compress_certificate: false,
            offer_tls12_fallback: false,
            extra_key_shares: Vec::new(),
        })
        .encode();
        let inner = body[4..].to_vec();
        assert_eq!(pick_server_version(&inner), Some(PickedTls::V13));
    }

    #[test]
    fn picks_tls12_for_tls12_client_hello() {
        let wire = build_client_hello12(&crate::tls::tls12::messages::ClientHelloParams {
            random: [7; 32],
            session_id: &[],
            cipher_suites: crate::tls::tls12::engine::SUPPORTED_CIPHER_SUITES,
            server_name: None,
            session_ticket: None,
            alpn: &[],
            legacy_version: 0x0303,
            cookie: &[],
        });
        let body = &wire[4..];
        assert_eq!(u16::from_be_bytes([body[0], body[1]]), TLS12);
        assert_eq!(
            parse_client_hello(body).and_then(|p| p.supported_versions),
            Some(vec![TLS12])
        );
        assert_eq!(pick_server_version(body), Some(PickedTls::V12));
    }
}
