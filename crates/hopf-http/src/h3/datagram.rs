// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HTTP/3 Datagrams (RFC 9297 §2.1) over QUIC DATAGRAM (RFC 9221).

use super::varint;

/// `SETTINGS_H3_DATAGRAM` (RFC 9297 §2.1.1) — willingness to receive
/// HTTP/3 Datagrams. Value must be 0 or 1.
pub const SETTINGS_H3_DATAGRAM: u64 = 0x33;

/// `H3_DATAGRAM_ERROR` (RFC 9297) — stream or connection error for HTTP
/// Datagram protocol violations. Distinct from the 0x0100-range codes in
/// RFC 9114 §8.1.
pub const H3_DATAGRAM_ERROR: u32 = 0x33;

/// Largest legal quarter-stream-ID (RFC 9297 §2.1): `(2^62 - 1) / 4`.
const MAX_QUARTER_STREAM_ID: u64 = (1u64 << 60) - 1;

/// Encode an HTTP/3 Datagram: quarter-stream-ID varint + payload.
pub fn encode(stream_id: u64, payload: &[u8]) -> Option<Vec<u8>> {
    if stream_id % 4 != 0 {
        return None;
    }
    let quarter = stream_id / 4;
    if quarter > MAX_QUARTER_STREAM_ID {
        return None;
    }
    let mut out = Vec::with_capacity(8 + payload.len());
    varint::encode(&mut out, quarter);
    out.extend_from_slice(payload);
    Some(out)
}

/// Decode an HTTP/3 Datagram into `(stream_id, payload)`.
pub fn decode(data: &[u8]) -> Result<(u64, &[u8]), ()> {
    let (quarter, n) = varint::decode(data).ok_or(())?;
    if quarter > MAX_QUARTER_STREAM_ID {
        return Err(());
    }
    // Client-initiated bidirectional stream IDs are 0 mod 4.
    let stream_id = quarter.checked_mul(4).ok_or(())?;
    Ok((stream_id, &data[n..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_empty_payload() {
        let encoded = encode(0, b"").unwrap();
        let (sid, payload) = decode(&encoded).unwrap();
        assert_eq!(sid, 0);
        assert!(payload.is_empty());
    }

    #[test]
    fn round_trip_with_payload() {
        let encoded = encode(8, b"hello").unwrap();
        let (sid, payload) = decode(&encoded).unwrap();
        assert_eq!(sid, 8);
        assert_eq!(payload, b"hello");
    }

    #[test]
    fn rejects_non_client_bi_stream_id() {
        assert!(encode(1, b"x").is_none());
    }

    #[test]
    fn decode_truncated_is_err() {
        assert!(decode(&[]).is_err());
    }

    #[test]
    fn settings_and_error_code_match_rfc() {
        assert_eq!(SETTINGS_H3_DATAGRAM, 0x33);
        assert_eq!(H3_DATAGRAM_ERROR, 0x33);
    }

    #[test]
    fn peer_accepts_only_when_setting_is_one() {
        assert!(!peer_accepts_h3_datagram(None));
        assert!(!peer_accepts_h3_datagram(Some(false)));
        assert!(peer_accepts_h3_datagram(Some(true)));
    }

    #[derive(Default)]
    struct RecordingEndpoint {
        datagrams: Vec<Vec<u8>>,
    }

    impl hopf_core::Endpoint for RecordingEndpoint {
        fn send(&mut self, _data: &[u8]) {}
        fn is_open(&self) -> bool {
            true
        }
        fn is_closing(&self) -> bool {
            false
        }
        fn close(&mut self) {}
        fn abort(&mut self, _error_code: u32) {}
        fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
            unimplemented!()
        }
        fn remote_addr(&self) -> std::io::Result<std::net::SocketAddr> {
            unimplemented!()
        }
        fn security_info(&self) -> &hopf_core::SecurityInfo {
            unimplemented!()
        }
        fn start_tls(&mut self) -> Result<(), hopf_core::StartTlsError> {
            unimplemented!()
        }
        fn pause_read(&mut self) {}
        fn resume_read(&mut self) {}
        fn on_write_ready(&mut self, _callback: Option<hopf_core::WriteReadyCallback>) {}
        fn execute(&self, _task: Box<dyn FnOnce() + Send>) {
            unimplemented!()
        }
        fn schedule_timer(
            &self,
            _delay: std::time::Duration,
            _callback: Box<dyn FnOnce() + Send>,
        ) -> hopf_core::TimerHandle {
            unimplemented!()
        }
        fn handle(&self) -> hopf_core::ConnHandle {
            unimplemented!()
        }
        fn send_datagram(&mut self, payload: &[u8]) -> std::io::Result<()> {
            self.datagrams.push(payload.to_vec());
            Ok(())
        }
    }

    #[test]
    fn send_rejected_before_peer_settings() {
        let mut ep = RecordingEndpoint::default();
        let err = send(&mut ep, None, 0, b"x").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(ep.datagrams.is_empty());
    }

    #[test]
    fn send_rejected_when_peer_disabled_datagrams() {
        let mut ep = RecordingEndpoint::default();
        let err = send(&mut ep, Some(false), 0, b"x").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(ep.datagrams.is_empty());
    }

    #[test]
    fn send_succeeds_when_peer_advertised_datagrams() {
        let mut ep = RecordingEndpoint::default();
        send(&mut ep, Some(true), 8, b"hello").unwrap();
        assert_eq!(ep.datagrams.len(), 1);
        let (sid, payload) = decode(&ep.datagrams[0]).unwrap();
        assert_eq!(sid, 8);
        assert_eq!(payload, b"hello");
    }
}

/// Whether the peer has advertised willingness to receive HTTP/3 Datagrams
/// (RFC 9297 §2.1.1). Pass the value from [`crate::h3::endpoint::H3PeerState::peer_h3_datagram`].
pub fn peer_accepts_h3_datagram(peer_h3_datagram: Option<bool>) -> bool {
    peer_h3_datagram == Some(true)
}

/// Encode and send an HTTP/3 Datagram on `endpoint` for `stream_id`
/// (RFC 9297 §2.1). `peer_h3_datagram` must be `Some(true)` — i.e. the
/// peer's SETTINGS frame included `SETTINGS_H3_DATAGRAM=1`.
pub fn send(
    endpoint: &mut dyn hopf_core::Endpoint,
    peer_h3_datagram: Option<bool>,
    stream_id: u64,
    payload: &[u8],
) -> std::io::Result<()> {
    if !peer_accepts_h3_datagram(peer_h3_datagram) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "peer has not advertised SETTINGS_H3_DATAGRAM=1",
        ));
    }
    let Some(encoded) = encode(stream_id, payload) else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "stream_id must be a client-initiated bidirectional QUIC stream id",
        ));
    };
    endpoint.send_datagram(&encoded)
}
