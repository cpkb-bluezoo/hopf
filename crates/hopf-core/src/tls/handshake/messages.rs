// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! TLS 1.3 handshake message framing (RFC 8446 §4) — no record layer.

use bytes::{Bytes, BytesMut};

/// Handshake message type (RFC 8446 §B.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HandshakeType {
    /// ClientHello.
    ClientHello = 1,
    /// ServerHello.
    ServerHello = 2,
    /// EncryptedExtensions.
    EncryptedExtensions = 8,
    /// Certificate.
    Certificate = 11,
    /// CertificateVerify.
    CertificateVerify = 15,
    /// Finished.
    Finished = 20,
}

impl HandshakeType {
    /// Handshake type byte on the wire.
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// One TLS handshake message (type + body, without the 4-byte header).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeMessage {
    /// Message type.
    pub msg_type: HandshakeType,
    /// Message body (not including type/length header).
    pub body: Bytes,
}

impl HandshakeMessage {
    /// Serialize with 1-byte type + 3-byte length prefix (RFC 8446 §4).
    pub fn encode(&self) -> Bytes {
        let mut out = BytesMut::with_capacity(4 + self.body.len());
        out.extend_from_slice(&[self.msg_type as u8]);
        let len = self.body.len();
        out.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        out.extend_from_slice(&self.body);
        out.freeze()
    }
}

/// TLS extension type constants used in Phase 2.
pub mod ext {
    /// Server Name Indication (RFC 6066).
    pub const SERVER_NAME: u16 = 0;
    /// Application-Layer Protocol Negotiation (RFC 7301).
    pub const ALPN: u16 = 16;
    /// Supported Groups (RFC 8446 §4.2.7).
    pub const SUPPORTED_GROUPS: u16 = 10;
    /// Key Share (RFC 8446 §4.2.8).
    pub const KEY_SHARE: u16 = 51;
    /// QUIC transport parameters (RFC 9001 §8.2).
    pub const QUIC_TRANSPORT_PARAMETERS: u16 = 0x0039;
    /// Supported Versions (RFC 8446 §4.2.1).
    pub const SUPPORTED_VERSIONS: u16 = 43;
}

/// One offered key share in ClientHello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyShareEntry {
    /// IANA group id.
    pub group: u16,
    /// Key exchange bytes.
    pub share: Bytes,
}

/// Inputs for building a TLS 1.3 ClientHello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHelloParams {
    /// Client random.
    pub random: [u8; 32],
    /// Key share for the preferred group.
    pub key_share: KeyShareEntry,
    /// Supported groups in preference order.
    pub supported_groups: Vec<u16>,
    /// ALPN protocol names.
    pub alpn: Vec<Bytes>,
    /// SNI hostname.
    pub server_name: Option<String>,
    /// QUIC transport parameters extension (RFC 9001), if any.
    pub transport_parameters: Option<Bytes>,
}

/// Build a TLS 1.3 `ClientHello`.
pub fn build_client_hello(params: &ClientHelloParams) -> HandshakeMessage {
    let mut body = BytesMut::new();
    body.extend_from_slice(&0x0303u16.to_be_bytes());
    body.extend_from_slice(&params.random);
    body.extend_from_slice(&[0]);
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&0x1301u16.to_be_bytes());
    body.extend_from_slice(&[1, 0]);

    let mut extensions = BytesMut::new();
    push_extension(&mut extensions, ext::SUPPORTED_VERSIONS, &[0x02, 0x03, 0x04]);
    push_extension(
        &mut extensions,
        ext::SUPPORTED_GROUPS,
        &encode_group_list(&params.supported_groups),
    );
    push_extension(
        &mut extensions,
        ext::KEY_SHARE,
        &encode_key_share_list(std::slice::from_ref(&params.key_share)),
    );
    if !params.alpn.is_empty() {
        let mut alpn_list = BytesMut::new();
        for proto in &params.alpn {
            alpn_list.extend_from_slice(&[proto.len() as u8]);
            alpn_list.extend_from_slice(proto);
        }
        push_extension(&mut extensions, ext::ALPN, &alpn_list);
    }
    if let Some(name) = &params.server_name {
        let host = name.as_bytes();
        let mut sni = BytesMut::new();
        sni.extend_from_slice(&((host.len() as u16 + 3)).to_be_bytes());
        sni.extend_from_slice(&0u16.to_be_bytes());
        sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni.extend_from_slice(host);
        push_extension(&mut extensions, ext::SERVER_NAME, &sni);
    }
    if let Some(tp) = &params.transport_parameters {
        push_extension(&mut extensions, ext::QUIC_TRANSPORT_PARAMETERS, tp);
    }
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    HandshakeMessage {
        msg_type: HandshakeType::ClientHello,
        body: body.freeze(),
    }
}

/// Build a TLS 1.3 `ServerHello` for the selected group + key share.
pub fn build_server_hello(random: &[u8; 32], group: u16, key_share: &[u8]) -> HandshakeMessage {
    let mut body = BytesMut::new();
    body.extend_from_slice(&0x0303u16.to_be_bytes());
    body.extend_from_slice(random);
    body.extend_from_slice(&[0]);
    body.extend_from_slice(&0x1301u16.to_be_bytes());
    body.extend_from_slice(&[0]);

    let mut extensions = BytesMut::new();
    push_extension(&mut extensions, ext::SUPPORTED_VERSIONS, &[0x03, 0x04]);
    let mut ks = BytesMut::new();
    ks.extend_from_slice(&group.to_be_bytes());
    ks.extend_from_slice(&(key_share.len() as u16).to_be_bytes());
    ks.extend_from_slice(key_share);
    push_extension(&mut extensions, ext::KEY_SHARE, &ks);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    HandshakeMessage {
        msg_type: HandshakeType::ServerHello,
        body: body.freeze(),
    }
}

/// Build `EncryptedExtensions` with ALPN and optional QUIC transport parameters.
pub fn build_encrypted_extensions(alpn: &[u8], transport_parameters: Option<&[u8]>) -> HandshakeMessage {
    let mut extensions = BytesMut::new();
    let mut alpn_list = BytesMut::new();
    alpn_list.extend_from_slice(&[alpn.len() as u8]);
    alpn_list.extend_from_slice(alpn);
    push_extension(&mut extensions, ext::ALPN, &alpn_list);
    if let Some(tp) = transport_parameters {
        push_extension(&mut extensions, ext::QUIC_TRANSPORT_PARAMETERS, tp);
    }
    let mut body = BytesMut::new();
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    HandshakeMessage {
        msg_type: HandshakeType::EncryptedExtensions,
        body: body.freeze(),
    }
}

/// Build a TLS 1.3 `Certificate` message (empty context, DER chain leaf-first).
pub fn build_certificate(chain: &[&[u8]]) -> HandshakeMessage {
    let mut cert_list = BytesMut::new();
    for cert in chain {
        cert_list.extend_from_slice(&(cert.len() as u32).to_be_bytes()[1..]);
        cert_list.extend_from_slice(cert);
        cert_list.extend_from_slice(&0u16.to_be_bytes());
    }
    let mut body = BytesMut::new();
    body.extend_from_slice(&[0]);
    body.extend_from_slice(&(cert_list.len() as u32).to_be_bytes()[1..]);
    body.extend_from_slice(&cert_list);
    HandshakeMessage {
        msg_type: HandshakeType::Certificate,
        body: body.freeze(),
    }
}

/// Build a `CertificateVerify` message.
pub fn build_certificate_verify(scheme: u16, signature: &[u8]) -> HandshakeMessage {
    let mut body = BytesMut::new();
    body.extend_from_slice(&scheme.to_be_bytes());
    body.extend_from_slice(&(signature.len() as u16).to_be_bytes());
    body.extend_from_slice(signature);
    HandshakeMessage {
        msg_type: HandshakeType::CertificateVerify,
        body: body.freeze(),
    }
}

/// Build a `Finished` message.
pub fn build_finished(verify_data: &[u8]) -> HandshakeMessage {
    HandshakeMessage {
        msg_type: HandshakeType::Finished,
        body: Bytes::copy_from_slice(verify_data),
    }
}

fn push_extension(out: &mut BytesMut, ext_type: u16, data: &[u8]) {
    out.extend_from_slice(&ext_type.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
}

fn encode_group_list(groups: &[u16]) -> Bytes {
    let mut out = BytesMut::with_capacity(2 + groups.len() * 2);
    out.extend_from_slice(&((groups.len() * 2) as u16).to_be_bytes());
    for g in groups {
        out.extend_from_slice(&g.to_be_bytes());
    }
    out.freeze()
}

fn encode_key_share_list(entries: &[KeyShareEntry]) -> Bytes {
    let mut body = BytesMut::new();
    for e in entries {
        body.extend_from_slice(&e.group.to_be_bytes());
        body.extend_from_slice(&(e.share.len() as u16).to_be_bytes());
        body.extend_from_slice(&e.share);
    }
    let mut out = BytesMut::with_capacity(2 + body.len());
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(&body);
    out.freeze()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::handshake::collect::parse_client_hello;

    #[test]
    fn client_hello_key_share_roundtrip() {
        use crate::crypto::kx::{EphemeralKeyPair, NamedGroup};
        let kp = EphemeralKeyPair::generate().unwrap();
        let random = [1u8; 32];
        let hello = build_client_hello(&ClientHelloParams {
            random,
            key_share: KeyShareEntry {
                group: NamedGroup::X25519.code(),
                share: Bytes::copy_from_slice(&kp.public_key()),
            },
            supported_groups: vec![NamedGroup::X25519.code()],
            alpn: vec![Bytes::from_static(b"h3")],
            server_name: Some("localhost".into()),
            transport_parameters: None,
        });
        let parsed = parse_client_hello(&hello.body).expect("parse client hello");
        assert!(parsed.peer_key_share.is_some());
        assert_eq!(parsed.key_share_group, Some(NamedGroup::X25519.code()));
    }
}
