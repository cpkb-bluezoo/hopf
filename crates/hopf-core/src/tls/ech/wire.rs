// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! ECH wire handling that the streaming handshake parser does not do:
//! the `ECHClientHello` extension body (RFC 9849 §5), locating and blanking
//! its payload to form `ClientHelloOuterAAD` (§5.2), padding (§6.1.3), and
//! reconstructing `ClientHelloInner` from `EncodedClientHelloInner`,
//! including `ech_outer_extensions` expansion (§5.1).
//!
//! Everything here works on a ClientHello *body* (no four-byte handshake
//! header), which is what the RFC's AAD and encoded-inner structures use.

use crate::tls::handshake::messages::ext;

/// A structural failure. Where RFC 9849 mandates an alert, the variant says
/// which one the caller must send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WireError {
    /// Malformed encoding: `decode_error`.
    Decode,
    /// A semantic violation of §5.1 / §7: `illegal_parameter`.
    Illegal,
}

/// Upper bound on a reconstructed ClientHelloInner body. A handshake message
/// is limited to 2^24-1 by its header, but nothing legitimate approaches
/// that; this also bounds amplification from `ech_outer_extensions`
/// (RFC 9849 §10.12.4).
const MAX_INNER_BODY: usize = 1 << 16;

#[derive(Debug, Clone, Copy)]
pub(crate) struct Ext<'a> {
    pub ty: u16,
    pub data: &'a [u8],
    /// Offset of `data` within the ClientHello body.
    pub data_off: usize,
}

/// A ClientHello body split into the fields ECH needs.
#[derive(Debug)]
pub(crate) struct ClientHelloView<'a> {
    pub legacy_version: [u8; 2],
    pub random: [u8; 32],
    pub session_id: &'a [u8],
    /// DTLS `legacy_cookie` (RFC 9147 §5.3); `None` for TLS.
    pub legacy_cookie: Option<&'a [u8]>,
    /// Raw cipher suite bytes (without the length prefix).
    pub cipher_suites: &'a [u8],
    /// Raw compression methods (without the length prefix).
    pub compression: &'a [u8],
    pub extensions: Vec<Ext<'a>>,
    /// Bytes of `body` the structure occupies. Anything after this is
    /// padding in an `EncodedClientHelloInner`.
    pub len: usize,
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let end = self.pos.checked_add(n).ok_or(WireError::Decode)?;
        let out = self.buf.get(self.pos..end).ok_or(WireError::Decode)?;
        self.pos = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, WireError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
}

impl<'a> ClientHelloView<'a> {
    /// Parse a ClientHello body. `dtls` selects the DTLS 1.3 layout, which
    /// has a `legacy_cookie` after the session ID.
    pub fn parse(body: &'a [u8], dtls: bool) -> Result<Self, WireError> {
        let mut c = Cursor { buf: body, pos: 0 };
        let version = c.take(2)?;
        let random = c.take(32)?;
        let sid_len = usize::from(c.u8()?);
        let session_id = c.take(sid_len)?;
        let legacy_cookie = if dtls {
            let n = usize::from(c.u8()?);
            Some(c.take(n)?)
        } else {
            None
        };
        let cs_len = usize::from(c.u16()?);
        let cipher_suites = c.take(cs_len)?;
        let comp_len = usize::from(c.u8()?);
        let compression = c.take(comp_len)?;
        let ext_len = usize::from(c.u16()?);
        let ext_start = c.pos;
        let ext_block = c.take(ext_len)?;
        let mut e = Cursor { buf: ext_block, pos: 0 };
        let mut extensions = Vec::new();
        while e.pos < ext_block.len() {
            let ty = e.u16()?;
            let len = usize::from(e.u16()?);
            let data_off = ext_start + e.pos;
            let data = e.take(len)?;
            extensions.push(Ext { ty, data, data_off });
        }
        Ok(Self {
            legacy_version: [version[0], version[1]],
            random: random.try_into().map_err(|_| WireError::Decode)?,
            session_id,
            legacy_cookie,
            cipher_suites,
            compression,
            extensions,
            len: c.pos,
        })
    }

    pub fn find(&self, ty: u16) -> Option<&Ext<'a>> {
        self.extensions.iter().find(|e| e.ty == ty)
    }
}

/// Serialise a ClientHello body from parts.
fn build_body(
    v: &ClientHelloView<'_>,
    session_id: &[u8],
    extensions: &[(u16, &[u8])],
) -> Result<Vec<u8>, WireError> {
    let mut out = Vec::new();
    out.extend_from_slice(&v.legacy_version);
    out.extend_from_slice(&v.random);
    out.push(u8::try_from(session_id.len()).map_err(|_| WireError::Illegal)?);
    out.extend_from_slice(session_id);
    if let Some(cookie) = v.legacy_cookie {
        out.push(u8::try_from(cookie.len()).map_err(|_| WireError::Illegal)?);
        out.extend_from_slice(cookie);
    }
    out.extend_from_slice(&(v.cipher_suites.len() as u16).to_be_bytes());
    out.extend_from_slice(v.cipher_suites);
    out.push(v.compression.len() as u8);
    out.extend_from_slice(v.compression);
    let ext_len: usize = extensions.iter().map(|(_, d)| 4 + d.len()).sum();
    out.extend_from_slice(&u16::try_from(ext_len).map_err(|_| WireError::Illegal)?.to_be_bytes());
    for (ty, data) in extensions {
        out.extend_from_slice(&ty.to_be_bytes());
        out.extend_from_slice(&u16::try_from(data.len()).map_err(|_| WireError::Illegal)?.to_be_bytes());
        out.extend_from_slice(data);
    }
    if out.len() > MAX_INNER_BODY {
        return Err(WireError::Illegal);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// ECHClientHello extension body (RFC 9849 §5)
// ---------------------------------------------------------------------------

/// `ECHClientHelloType`.
const TYPE_OUTER: u8 = 0;
const TYPE_INNER: u8 = 1;

/// The `encrypted_client_hello` extension body in a ClientHello.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum EchClientHello<'a> {
    /// `inner`: empty.
    Inner,
    /// `outer`.
    Outer(EchOuter<'a>),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct EchOuter<'a> {
    pub kdf_id: u16,
    pub aead_id: u16,
    pub config_id: u8,
    pub enc: &'a [u8],
    pub payload: &'a [u8],
    /// Offset of `payload` within the extension body.
    pub payload_off: usize,
}

/// Body of the `inner` variant.
pub(crate) const INNER_EXTENSION_BODY: [u8; 1] = [TYPE_INNER];

/// Parse an `ECHClientHello`. An unknown type or trailing/short data is
/// [`WireError::Illegal`] / [`WireError::Decode`] per RFC 9849 §7.
pub(crate) fn parse_ech_client_hello(data: &[u8]) -> Result<EchClientHello<'_>, WireError> {
    let mut c = Cursor { buf: data, pos: 0 };
    match c.u8()? {
        TYPE_INNER => {
            if c.pos != data.len() {
                return Err(WireError::Decode);
            }
            Ok(EchClientHello::Inner)
        }
        TYPE_OUTER => {
            let kdf_id = c.u16()?;
            let aead_id = c.u16()?;
            let config_id = c.u8()?;
            let enc_len = usize::from(c.u16()?);
            let enc = c.take(enc_len)?;
            let payload_len = usize::from(c.u16()?);
            let payload_off = c.pos;
            let payload = c.take(payload_len)?;
            if payload.is_empty() || c.pos != data.len() {
                return Err(WireError::Decode);
            }
            Ok(EchClientHello::Outer(EchOuter {
                kdf_id,
                aead_id,
                config_id,
                enc,
                payload,
                payload_off,
            }))
        }
        _ => Err(WireError::Illegal),
    }
}

/// Encode the `outer` variant.
pub(crate) fn encode_ech_outer(kdf_id: u16, aead_id: u16, config_id: u8, enc: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 5 + 2 + enc.len() + 2 + payload.len());
    out.push(TYPE_OUTER);
    out.extend_from_slice(&kdf_id.to_be_bytes());
    out.extend_from_slice(&aead_id.to_be_bytes());
    out.push(config_id);
    out.extend_from_slice(&(enc.len() as u16).to_be_bytes());
    out.extend_from_slice(enc);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// `ClientHelloOuterAAD` (RFC 9849 §5.2): the outer ClientHello body with the
/// ECH payload replaced by zeros of the same length.
pub(crate) fn outer_aad(outer_body: &[u8], ech_ext: &Ext<'_>, outer: &EchOuter<'_>) -> Vec<u8> {
    let mut aad = outer_body.to_vec();
    let start = ech_ext.data_off + outer.payload_off;
    aad[start..start + outer.payload.len()].fill(0);
    aad
}

// ---------------------------------------------------------------------------
// Padding (RFC 9849 §6.1.3)
// ---------------------------------------------------------------------------

/// Number of zero octets to append to an `EncodedClientHelloInner` whose
/// unpadded length is `len`, given the inner `server_name` length (if any) and
/// the config's `maximum_name_length`.
pub(crate) fn padding_len(len: usize, sni_len: Option<usize>, max_name_len: u8) -> usize {
    let m = usize::from(max_name_len);
    let name_pad = match sni_len {
        Some(d) => m.saturating_sub(d),
        None => m + 9,
    };
    let l = len + name_pad;
    // Round the total up to a multiple of 32.
    let round = (32 - (l % 32)) % 32;
    name_pad + round
}

// ---------------------------------------------------------------------------
// ClientHelloInner reconstruction (RFC 9849 §5.1)
// ---------------------------------------------------------------------------

/// Reverse `EncodedClientHelloInner` into a `ClientHelloInner` body:
/// reject non-zero padding, take `legacy_session_id` from the outer, and
/// expand `ech_outer_extensions` from the outer's extensions. Every failure
/// is [`WireError::Illegal`] (`illegal_parameter`) except a structurally
/// undecodable encoding.
pub(crate) fn decode_inner(
    encoded: &[u8],
    outer: &ClientHelloView<'_>,
    dtls: bool,
) -> Result<Vec<u8>, WireError> {
    let inner = ClientHelloView::parse(encoded, dtls)?;
    if encoded[inner.len..].iter().any(|&b| b != 0) {
        return Err(WireError::Illegal);
    }

    let mut exts: Vec<(u16, &[u8])> = Vec::with_capacity(inner.extensions.len());
    let mut expanded = false;
    // Next outer extension eligible to be referenced: enforces ordering.
    let mut outer_cursor = 0usize;
    for e in &inner.extensions {
        if e.ty != ext::ECH_OUTER_EXTENSIONS {
            exts.push((e.ty, e.data));
            continue;
        }
        // Only one ech_outer_extensions is meaningful, and it must be
        // contiguous with what it replaces.
        if expanded {
            return Err(WireError::Illegal);
        }
        expanded = true;
        let (&n, list) = e.data.split_first().ok_or(WireError::Decode)?;
        if usize::from(n) != list.len() || n < 2 || n % 2 != 0 {
            return Err(WireError::Decode);
        }
        let mut seen: Vec<u16> = Vec::new();
        for pair in list.chunks_exact(2) {
            let ty = u16::from_be_bytes([pair[0], pair[1]]);
            if ty == ext::ENCRYPTED_CLIENT_HELLO || ty == ext::ECH_OUTER_EXTENSIONS || seen.contains(&ty) {
                return Err(WireError::Illegal);
            }
            seen.push(ty);
            let found = outer.extensions[outer_cursor..].iter().position(|o| o.ty == ty);
            let Some(idx) = found else {
                // Missing from the outer, or out of order.
                return Err(WireError::Illegal);
            };
            let o = &outer.extensions[outer_cursor + idx];
            exts.push((o.ty, o.data));
            outer_cursor += idx + 1;
        }
    }
    build_body(&inner, outer.session_id, &exts)
}

// ---------------------------------------------------------------------------
// ServerHello / HelloRetryRequest acceptance signal (RFC 9849 §7.2, §7.2.1)
// ---------------------------------------------------------------------------

/// Offset in a full ServerHello handshake message (four-byte header
/// included) of the last 8 octets of `random`, which carry the acceptance
/// confirmation.
const SH_CONFIRMATION_OFFSET: usize = 4 + 2 + 24;

/// A copy of a ServerHello message with the last 8 octets of `random` zeroed
/// (the input to `accept_confirmation`).
pub(crate) fn server_hello_with_zeroed_confirmation(wire: &[u8]) -> Option<Vec<u8>> {
    if wire.len() < SH_CONFIRMATION_OFFSET + 8 {
        return None;
    }
    let mut out = wire.to_vec();
    out[SH_CONFIRMATION_OFFSET..SH_CONFIRMATION_OFFSET + 8].fill(0);
    Some(out)
}

/// The acceptance confirmation carried in a ServerHello's `random`.
pub(crate) fn server_hello_confirmation(wire: &[u8]) -> Option<[u8; 8]> {
    wire.get(SH_CONFIRMATION_OFFSET..SH_CONFIRMATION_OFFSET + 8)?.try_into().ok()
}

/// A copy of a HelloRetryRequest message with the 8-octet
/// `encrypted_client_hello` payload zeroed (the input to
/// `hrr_accept_confirmation`), or `None` if it has no such extension.
pub(crate) fn hello_retry_request_with_zeroed_confirmation(wire: &[u8]) -> Option<Vec<u8>> {
    let body = wire.get(4..)?;
    let mut c = Cursor { buf: body, pos: 0 };
    c.take(2 + 32).ok()?;
    let sid = usize::from(c.u8().ok()?);
    c.take(sid + 2 + 1).ok()?;
    let ext_len = usize::from(c.u16().ok()?);
    let ext_start = c.pos;
    let block = c.take(ext_len).ok()?;
    let mut e = Cursor { buf: block, pos: 0 };
    while e.pos < block.len() {
        let ty = e.u16().ok()?;
        let len = usize::from(e.u16().ok()?);
        let off = ext_start + e.pos;
        e.take(len).ok()?;
        if ty == ext::ENCRYPTED_CLIENT_HELLO {
            if len != 8 {
                return None;
            }
            let mut out = wire.to_vec();
            out[4 + off..4 + off + 8].fill(0);
            return Some(out);
        }
    }
    None
}

/// Constant-time equality of two acceptance confirmations.
pub(crate) fn confirmation_eq(a: &[u8; 8], b: &[u8; 8]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ext_bytes(ty: u16, data: &[u8]) -> Vec<u8> {
        let mut v = ty.to_be_bytes().to_vec();
        v.extend_from_slice(&(data.len() as u16).to_be_bytes());
        v.extend_from_slice(data);
        v
    }

    /// TLS ClientHello body with the given session id and extensions.
    fn body(session_id: &[u8], exts: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut b = vec![3, 3];
        b.extend_from_slice(&[7u8; 32]);
        b.push(session_id.len() as u8);
        b.extend_from_slice(session_id);
        b.extend_from_slice(&[0, 2, 0x13, 0x01]);
        b.extend_from_slice(&[1, 0]);
        let block: Vec<u8> = exts.iter().flat_map(|(t, d)| ext_bytes(*t, d)).collect();
        b.extend_from_slice(&(block.len() as u16).to_be_bytes());
        b.extend_from_slice(&block);
        b
    }

    fn types(body: &[u8]) -> Vec<u16> {
        ClientHelloView::parse(body, false).unwrap().extensions.iter().map(|e| e.ty).collect()
    }

    #[test]
    fn parses_view_and_reports_consumed_length() {
        let mut b = body(&[1, 2, 3], &[(0x0a, vec![9, 9]), (0x2b, vec![])]);
        let real = b.len();
        b.extend_from_slice(&[0; 5]);
        let v = ClientHelloView::parse(&b, false).unwrap();
        assert_eq!(v.session_id, &[1, 2, 3]);
        assert_eq!(v.len, real);
        assert_eq!(v.extensions.len(), 2);
        assert_eq!(v.extensions[0].data, &[9, 9]);
        assert_eq!(&b[v.extensions[0].data_off..][..2], &[9, 9]);
        assert!(ClientHelloView::parse(&b[..40], false).is_err());
    }

    #[test]
    fn ech_client_hello_round_trip_and_errors() {
        let enc = encode_ech_outer(1, 3, 42, &[5; 32], &[6; 20]);
        let EchClientHello::Outer(o) = parse_ech_client_hello(&enc).unwrap() else {
            panic!("expected outer");
        };
        assert_eq!((o.kdf_id, o.aead_id, o.config_id), (1, 3, 42));
        assert_eq!(o.enc, &[5; 32]);
        assert_eq!(o.payload, &[6; 20]);
        assert_eq!(&enc[o.payload_off..][..20], &[6; 20]);

        assert_eq!(parse_ech_client_hello(&INNER_EXTENSION_BODY).unwrap(), EchClientHello::Inner);
        assert_eq!(parse_ech_client_hello(&[1, 0]), Err(WireError::Decode));
        assert_eq!(parse_ech_client_hello(&[2]), Err(WireError::Illegal));
        assert_eq!(parse_ech_client_hello(&enc[..enc.len() - 1]), Err(WireError::Decode));
        // Empty payload is not permitted.
        assert_eq!(parse_ech_client_hello(&encode_ech_outer(1, 1, 0, &[], &[])), Err(WireError::Decode));
        // An empty enc is (HelloRetryRequest second flight).
        assert!(parse_ech_client_hello(&encode_ech_outer(1, 1, 0, &[], &[1])).is_ok());
    }

    #[test]
    fn aad_blanks_only_the_payload() {
        let ech = encode_ech_outer(1, 1, 9, &[5; 32], &[0xAB; 40]);
        let b = body(&[], &[(0x0a, vec![1, 2, 3]), (ext::ENCRYPTED_CLIENT_HELLO, ech.clone()), (0x2b, vec![7])]);
        let view = ClientHelloView::parse(&b, false).unwrap();
        let e = view.find(ext::ENCRYPTED_CLIENT_HELLO).unwrap();
        let EchClientHello::Outer(o) = parse_ech_client_hello(e.data).unwrap() else { panic!() };
        let aad = outer_aad(&b, e, &o);
        assert_eq!(aad.len(), b.len());
        let diff: Vec<usize> = (0..b.len()).filter(|&i| aad[i] != b[i]).collect();
        assert_eq!(diff.len(), 40);
        assert!(aad[diff[0]..diff[0] + 40].iter().all(|&x| x == 0));
        // Everything else, including enc and neighbouring extensions, is intact.
        assert_eq!(types(&aad), vec![0x0a, ext::ENCRYPTED_CLIENT_HELLO, 0x2b]);
    }

    #[test]
    fn padding_rounds_to_32_and_covers_sni() {
        // With an SNI of 11 and M=20: 9 name-pad, then round up to 32.
        let p = padding_len(100, Some(11), 20);
        assert_eq!(p, 9 + ((32 - (109 % 32)) % 32));
        assert_eq!((100 + p) % 32, 0);
        // No SNI: M + 9.
        assert_eq!(padding_len(64, None, 10), 19 + ((32 - (83 % 32)) % 32));
        // Longer name than M adds no name padding; still rounds.
        assert_eq!(padding_len(60, Some(50), 20) % 32, 4);
        assert_eq!((60 + padding_len(60, Some(50), 20)) % 32, 0);
        assert_eq!(padding_len(64, Some(5), 0), 0);
    }

    #[test]
    fn decode_inner_takes_session_id_from_outer_and_checks_padding() {
        let outer = body(&[9, 9, 9], &[(0x00, vec![1]), (ext::ENCRYPTED_CLIENT_HELLO, vec![0; 4])]);
        let outer_v = ClientHelloView::parse(&outer, false).unwrap();
        let mut encoded = body(&[], &[(0x00, vec![2]), (ext::ENCRYPTED_CLIENT_HELLO, INNER_EXTENSION_BODY.to_vec())]);
        encoded.extend_from_slice(&[0; 17]);
        let inner = decode_inner(&encoded, &outer_v, false).unwrap();
        let v = ClientHelloView::parse(&inner, false).unwrap();
        assert_eq!(v.session_id, &[9, 9, 9]);
        assert_eq!(inner.len(), v.len, "padding must be gone");
        assert_eq!(types(&inner), vec![0x00, ext::ENCRYPTED_CLIENT_HELLO]);

        // Non-zero padding is illegal_parameter.
        let mut bad = encoded.clone();
        *bad.last_mut().unwrap() = 1;
        assert_eq!(decode_inner(&bad, &outer_v, false), Err(WireError::Illegal));
    }

    fn outer_ref(types: &[u16]) -> Vec<u8> {
        let mut d = vec![(types.len() * 2) as u8];
        for t in types {
            d.extend_from_slice(&t.to_be_bytes());
        }
        d
    }

    #[test]
    fn outer_extensions_are_expanded_in_place() {
        // Outer has A, D, B, C, E in that order; inner references A, B, C.
        let outer = body(&[], &[(0xa1, vec![1]), (0xd4, vec![4]), (0xb2, vec![2]), (0xc3, vec![3]), (0xe5, vec![5])]);
        let ov = ClientHelloView::parse(&outer, false).unwrap();
        let encoded = body(
            &[],
            &[
                (0x00, vec![0]),
                (ext::ECH_OUTER_EXTENSIONS, outer_ref(&[0xa1, 0xb2, 0xc3])),
                (ext::ENCRYPTED_CLIENT_HELLO, INNER_EXTENSION_BODY.to_vec()),
            ],
        );
        let inner = decode_inner(&encoded, &ov, false).unwrap();
        assert_eq!(types(&inner), vec![0x00, 0xa1, 0xb2, 0xc3, ext::ENCRYPTED_CLIENT_HELLO]);
        let iv = ClientHelloView::parse(&inner, false).unwrap();
        assert_eq!(iv.find(0xb2).unwrap().data, &[2]);
    }

    #[test]
    fn outer_extensions_violations_are_illegal_parameter() {
        let outer = body(&[], &[(0xa1, vec![1]), (0xb2, vec![2]), (ext::ENCRYPTED_CLIENT_HELLO, vec![0; 3])]);
        let ov = ClientHelloView::parse(&outer, false).unwrap();
        let with_ref = |refs: &[u16]| {
            body(&[], &[(ext::ECH_OUTER_EXTENSIONS, outer_ref(refs)), (ext::ENCRYPTED_CLIENT_HELLO, INNER_EXTENSION_BODY.to_vec())])
        };
        // Missing from the outer.
        assert_eq!(decode_inner(&with_ref(&[0xa1, 0xff]), &ov, false), Err(WireError::Illegal));
        // Out of order.
        assert_eq!(decode_inner(&with_ref(&[0xb2, 0xa1]), &ov, false), Err(WireError::Illegal));
        // Referenced twice.
        assert_eq!(decode_inner(&with_ref(&[0xa1, 0xa1]), &ov, false), Err(WireError::Illegal));
        // encrypted_client_hello itself referenced.
        assert_eq!(
            decode_inner(&with_ref(&[0xa1, ext::ENCRYPTED_CLIENT_HELLO]), &ov, false),
            Err(WireError::Illegal)
        );
        // A second ech_outer_extensions.
        let twice = body(
            &[],
            &[(ext::ECH_OUTER_EXTENSIONS, outer_ref(&[0xa1, 0xb2])), (ext::ECH_OUTER_EXTENSIONS, outer_ref(&[0xa1, 0xb2]))],
        );
        assert_eq!(decode_inner(&twice, &ov, false), Err(WireError::Illegal));
        // Odd or wrong list length.
        let bad_len = body(&[], &[(ext::ECH_OUTER_EXTENSIONS, vec![3, 0, 0xa1, 0])]);
        assert_eq!(decode_inner(&bad_len, &ov, false), Err(WireError::Decode));
        let too_short = body(&[], &[(ext::ECH_OUTER_EXTENSIONS, vec![0])]);
        assert_eq!(decode_inner(&too_short, &ov, false), Err(WireError::Decode));
    }

    #[test]
    fn hrr_confirmation_is_zeroed_in_place() {
        let mut body = vec![3, 3];
        body.extend_from_slice(&[9u8; 32]);
        body.push(0); // session id
        body.extend_from_slice(&[0x13, 0x01, 0]);
        let exts: Vec<u8> = [ext_bytes(0x2b, &[3, 4]), ext_bytes(ext::ENCRYPTED_CLIENT_HELLO, &[0xAA; 8]), ext_bytes(0x33, &[0, 29])].concat();
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);
        let mut wire = vec![2, 0, 0, body.len() as u8];
        wire.extend_from_slice(&body);
        let zeroed = hello_retry_request_with_zeroed_confirmation(&wire).unwrap();
        assert_eq!(zeroed.len(), wire.len());
        let diff: Vec<usize> = (0..wire.len()).filter(|&i| zeroed[i] != wire[i]).collect();
        assert_eq!(diff.len(), 8);
        assert!(zeroed[diff[0]..diff[0] + 8].iter().all(|&b| b == 0));
        // No ECH extension, or a wrong-sized one, yields None.
        let mut plain = wire.clone();
        let pos = plain.windows(2).position(|w| w == [0xfe, 0x0d]).unwrap();
        plain[pos] = 0x00;
        assert!(hello_retry_request_with_zeroed_confirmation(&plain).is_none());
    }

    #[test]
    fn server_hello_confirmation_zeroing_and_comparison() {
        let mut wire = vec![2, 0, 0, 40, 3, 3];
        wire.extend((0u8..32).collect::<Vec<_>>());
        let conf = server_hello_confirmation(&wire).unwrap();
        assert_eq!(conf, [24, 25, 26, 27, 28, 29, 30, 31]);
        let z = server_hello_with_zeroed_confirmation(&wire).unwrap();
        assert_eq!(&z[..30], &wire[..30]);
        assert_eq!(&z[30..38], &[0; 8]);
        assert!(confirmation_eq(&conf, &conf));
        assert!(!confirmation_eq(&conf, &[0; 8]));
        assert!(server_hello_confirmation(&wire[..20]).is_none());
    }

    #[test]
    fn dtls_layout_round_trips_the_legacy_cookie() {
        let mut b = vec![0xfe, 0xfd];
        b.extend_from_slice(&[7u8; 32]);
        b.push(0); // session id
        b.extend_from_slice(&[2, 0xaa, 0xbb]); // legacy_cookie
        b.extend_from_slice(&[0, 2, 0x13, 0x01, 1, 0, 0, 0]);
        let v = ClientHelloView::parse(&b, true).unwrap();
        assert_eq!(v.legacy_cookie, Some(&[0xaa, 0xbb][..]));
        let rebuilt = build_body(&v, &[], &[]).unwrap();
        assert_eq!(rebuilt, b);
    }
}
