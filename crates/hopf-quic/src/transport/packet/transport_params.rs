// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! QUIC transport parameters (RFC 9000 §18) — minimal encode/decode.

use crate::transport::types::ConnectionId;
use crate::transport::varint;

/// The `version_information` transport parameter (RFC 9368 section 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionInformation {
    /// The version the sender chose to use (a client: its first flight's).
    pub chosen: u32,
    /// Client: versions its first flight is compatible with, by descending
    /// preference. Server: the versions of its deployment. May be empty for
    /// a server.
    pub available: Vec<u32>,
}

/// Transport parameters exchanged in TLS.
#[derive(Debug, Clone)]
pub struct TransportParameters {
    /// initial_max_data
    pub initial_max_data: u64,
    /// initial_max_stream_data_bidi_local
    pub initial_max_stream_data_bidi_local: u64,
    /// initial_max_stream_data_bidi_remote
    pub initial_max_stream_data_bidi_remote: u64,
    /// initial_max_stream_data_uni
    pub initial_max_stream_data_uni: u64,
    /// initial_max_streams_bidi
    pub initial_max_streams_bidi: u64,
    /// initial_max_streams_uni
    pub initial_max_streams_uni: u64,
    /// max_idle_timeout (ms)
    pub max_idle_timeout: u64,
    /// max_udp_payload_size
    pub max_udp_payload_size: u64,
    /// ack_delay_exponent
    pub ack_delay_exponent: u64,
    /// max_ack_delay (ms)
    pub max_ack_delay: u64,
    /// disable_active_migration
    pub disable_active_migration: bool,
    /// active_connection_id_limit
    pub active_connection_id_limit: u64,
    /// initial_source_connection_id
    pub initial_src_cid: Option<ConnectionId>,
    /// original_destination_connection_id (server)
    pub original_dst_cid: Option<ConnectionId>,
    /// retry_source_connection_id (server, after Retry)
    pub retry_src_cid: Option<ConnectionId>,
    /// max_datagram_frame_size (RFC 9221); `None` = omit (DATAGRAM disabled).
    pub max_datagram_frame_size: Option<u64>,
    /// version_information (RFC 9368); `None` = omitted.
    pub version_information: Option<VersionInformation>,
    /// Decoding only: a `version_information` was present but malformed
    /// (RFC 9368 section 4: too short, ragged, or containing a zero version),
    /// which the receiver must treat as a fatal transport parameter error.
    pub version_information_invalid: bool,
}

impl Default for TransportParameters {
    fn default() -> Self {
        Self {
            initial_max_data: 10 * 1024 * 1024,
            initial_max_stream_data_bidi_local: 1 * 1024 * 1024,
            initial_max_stream_data_bidi_remote: 1 * 1024 * 1024,
            initial_max_stream_data_uni: 1 * 1024 * 1024,
            initial_max_streams_bidi: 100,
            initial_max_streams_uni: 100,
            max_idle_timeout: 30_000,
            max_udp_payload_size: 1452,
            ack_delay_exponent: 3,
            max_ack_delay: 25,
            disable_active_migration: true,
            active_connection_id_limit: 2,
            initial_src_cid: None,
            original_dst_cid: None,
            retry_src_cid: None,
            max_datagram_frame_size: Some(1452),
            version_information: None,
            version_information_invalid: false,
        }
    }
}

const ORIGINAL_DESTINATION_CONNECTION_ID: u64 = 0x00;
const MAX_IDLE_TIMEOUT: u64 = 0x01;
const MAX_UDP_PAYLOAD_SIZE: u64 = 0x03;
const INITIAL_MAX_DATA: u64 = 0x04;
const INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u64 = 0x05;
const INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u64 = 0x06;
const INITIAL_MAX_STREAM_DATA_UNI: u64 = 0x07;
const INITIAL_MAX_STREAMS_BIDI: u64 = 0x08;
const INITIAL_MAX_STREAMS_UNI: u64 = 0x09;
const ACK_DELAY_EXPONENT: u64 = 0x0a;
const MAX_ACK_DELAY: u64 = 0x0b;
const DISABLE_ACTIVE_MIGRATION: u64 = 0x0c;
const ACTIVE_CONNECTION_ID_LIMIT: u64 = 0x0e;
const INITIAL_SOURCE_CONNECTION_ID: u64 = 0x0f;
const RETRY_SOURCE_CONNECTION_ID: u64 = 0x10;
const VERSION_INFORMATION: u64 = 0x11;
const MAX_DATAGRAM_FRAME_SIZE: u64 = 0x20;

impl TransportParameters {
    /// Encode to TLS extension payload.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        fn put_var(out: &mut Vec<u8>, id: u64, value: u64) {
            varint::encode(id, out);
            let mut tmp = Vec::new();
            varint::encode(value, &mut tmp);
            varint::encode(tmp.len() as u64, out);
            out.extend_from_slice(&tmp);
        }
        fn put_bytes(out: &mut Vec<u8>, id: u64, bytes: &[u8]) {
            varint::encode(id, out);
            varint::encode(bytes.len() as u64, out);
            out.extend_from_slice(bytes);
        }
        if let Some(ref cid) = self.original_dst_cid {
            put_bytes(&mut out, ORIGINAL_DESTINATION_CONNECTION_ID, cid.as_slice());
        }
        put_var(&mut out, MAX_IDLE_TIMEOUT, self.max_idle_timeout);
        put_var(&mut out, MAX_UDP_PAYLOAD_SIZE, self.max_udp_payload_size);
        put_var(&mut out, INITIAL_MAX_DATA, self.initial_max_data);
        put_var(
            &mut out,
            INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
            self.initial_max_stream_data_bidi_local,
        );
        put_var(
            &mut out,
            INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
            self.initial_max_stream_data_bidi_remote,
        );
        put_var(
            &mut out,
            INITIAL_MAX_STREAM_DATA_UNI,
            self.initial_max_stream_data_uni,
        );
        put_var(
            &mut out,
            INITIAL_MAX_STREAMS_BIDI,
            self.initial_max_streams_bidi,
        );
        put_var(
            &mut out,
            INITIAL_MAX_STREAMS_UNI,
            self.initial_max_streams_uni,
        );
        put_var(&mut out, ACK_DELAY_EXPONENT, self.ack_delay_exponent);
        put_var(&mut out, MAX_ACK_DELAY, self.max_ack_delay);
        if self.disable_active_migration {
            varint::encode(DISABLE_ACTIVE_MIGRATION, &mut out);
            varint::encode(0, &mut out);
        }
        put_var(
            &mut out,
            ACTIVE_CONNECTION_ID_LIMIT,
            self.active_connection_id_limit,
        );
        if let Some(ref cid) = self.initial_src_cid {
            put_bytes(&mut out, INITIAL_SOURCE_CONNECTION_ID, cid.as_slice());
        }
        if let Some(ref cid) = self.retry_src_cid {
            put_bytes(&mut out, RETRY_SOURCE_CONNECTION_ID, cid.as_slice());
        }
        if let Some(vi) = &self.version_information {
            let mut value = Vec::with_capacity(4 + 4 * vi.available.len());
            value.extend_from_slice(&vi.chosen.to_be_bytes());
            for v in &vi.available {
                value.extend_from_slice(&v.to_be_bytes());
            }
            put_bytes(&mut out, VERSION_INFORMATION, &value);
        }
        if let Some(max) = self.max_datagram_frame_size {
            put_var(&mut out, MAX_DATAGRAM_FRAME_SIZE, max);
        }
        out
    }

    /// Decode from TLS extension payload (unknown IDs skipped).
    pub fn decode(mut buf: &[u8]) -> Option<Self> {
        let mut tp = Self::default();
        // Omitted means peer does not support DATAGRAM (RFC 9221).
        tp.max_datagram_frame_size = None;
        while !buf.is_empty() {
            let id = varint::decode(&mut buf)?;
            let len = varint::decode(&mut buf)? as usize;
            if buf.len() < len {
                return None;
            }
            let mut value = &buf[..len];
            buf = &buf[len..];
            match id {
                ORIGINAL_DESTINATION_CONNECTION_ID => {
                    tp.original_dst_cid = Some(ConnectionId::from_slice(value));
                }
                MAX_IDLE_TIMEOUT => {
                    tp.max_idle_timeout = varint::decode(&mut value)?;
                }
                MAX_UDP_PAYLOAD_SIZE => {
                    tp.max_udp_payload_size = varint::decode(&mut value)?;
                }
                INITIAL_MAX_DATA => {
                    tp.initial_max_data = varint::decode(&mut value)?;
                }
                INITIAL_MAX_STREAM_DATA_BIDI_LOCAL => {
                    tp.initial_max_stream_data_bidi_local = varint::decode(&mut value)?;
                }
                INITIAL_MAX_STREAM_DATA_BIDI_REMOTE => {
                    tp.initial_max_stream_data_bidi_remote = varint::decode(&mut value)?;
                }
                INITIAL_MAX_STREAM_DATA_UNI => {
                    tp.initial_max_stream_data_uni = varint::decode(&mut value)?;
                }
                INITIAL_MAX_STREAMS_BIDI => {
                    tp.initial_max_streams_bidi = varint::decode(&mut value)?;
                }
                INITIAL_MAX_STREAMS_UNI => {
                    tp.initial_max_streams_uni = varint::decode(&mut value)?;
                }
                ACK_DELAY_EXPONENT => {
                    tp.ack_delay_exponent = varint::decode(&mut value)?;
                }
                MAX_ACK_DELAY => {
                    tp.max_ack_delay = varint::decode(&mut value)?;
                }
                DISABLE_ACTIVE_MIGRATION => {
                    tp.disable_active_migration = true;
                }
                ACTIVE_CONNECTION_ID_LIMIT => {
                    tp.active_connection_id_limit = varint::decode(&mut value)?;
                }
                INITIAL_SOURCE_CONNECTION_ID => {
                    tp.initial_src_cid = Some(ConnectionId::from_slice(value));
                }
                RETRY_SOURCE_CONNECTION_ID => {
                    tp.retry_src_cid = Some(ConnectionId::from_slice(value));
                }
                MAX_DATAGRAM_FRAME_SIZE => {
                    tp.max_datagram_frame_size = Some(varint::decode(&mut value)?);
                }
                VERSION_INFORMATION => match decode_version_information(value) {
                    Some(vi) => tp.version_information = Some(vi),
                    None => tp.version_information_invalid = true,
                },
                _ => {}
            }
        }
        Some(tp)
    }
}

/// RFC 9368 section 3/4: a Chosen Version then Available Versions, each 32
/// bits and non-zero; `None` if malformed.
fn decode_version_information(value: &[u8]) -> Option<VersionInformation> {
    if value.len() < 4 || value.len() % 4 != 0 {
        return None;
    }
    let mut versions = value.chunks_exact(4).map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]));
    let chosen = versions.next()?;
    let available: Vec<u32> = versions.collect();
    if chosen == 0 || available.contains(&0) {
        return None;
    }
    Some(VersionInformation { chosen, available })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let mut tp = TransportParameters::default();
        tp.initial_src_cid = Some(ConnectionId::from_slice(&[1, 2, 3, 4]));
        let enc = tp.encode();
        let dec = TransportParameters::decode(&enc).unwrap();
        assert_eq!(dec.initial_max_data, tp.initial_max_data);
        assert_eq!(
            dec.initial_src_cid.as_ref().map(|c| c.as_slice().to_vec()),
            Some(vec![1, 2, 3, 4])
        );
    }

    /// RFC 9368 section 3: `version_information` is a Chosen Version and
    /// zero or more Available Versions, all 32-bit and non-zero.
    #[test]
    fn version_information_round_trips() {
        let mut tp = TransportParameters::default();
        tp.version_information = Some(VersionInformation { chosen: 0x6b33_43cf, available: vec![0x6b33_43cf, 1] });
        let dec = TransportParameters::decode(&tp.encode()).unwrap();
        assert_eq!(dec.version_information, tp.version_information);
        assert!(!dec.version_information_invalid);
        // Absent stays absent.
        let none = TransportParameters::decode(&TransportParameters::default().encode()).unwrap();
        assert!(none.version_information.is_none() && !none.version_information_invalid);
        // An empty Available Versions list is legal (a server may send it).
        let mut empty = TransportParameters::default();
        empty.version_information = Some(VersionInformation { chosen: 1, available: vec![] });
        let dec = TransportParameters::decode(&empty.encode()).unwrap();
        assert_eq!(dec.version_information, empty.version_information);
    }

    /// Too short, ragged, a zero Chosen Version, or any zero Available Version
    /// is a parsing failure the endpoint must close the connection over.
    #[test]
    fn malformed_version_information_is_flagged() {
        fn raw(value: &[u8]) -> Vec<u8> {
            let mut out = TransportParameters::default().encode();
            varint::encode(0x11, &mut out);
            varint::encode(value.len() as u64, &mut out);
            out.extend_from_slice(value);
            out
        }
        for bad in [
            &[][..],
            &[0, 0, 0][..],                             // shorter than a version
            &[0, 0, 0, 1, 0, 0][..],                    // ragged
            &[0, 0, 0, 0][..],                          // Chosen Version zero
            &[0, 0, 0, 1, 0, 0, 0, 0][..],              // an Available Version zero
        ] {
            let dec = TransportParameters::decode(&raw(bad)).expect("still decodes the rest");
            assert!(dec.version_information_invalid, "{bad:?}");
            assert!(dec.version_information.is_none());
        }
    }
}
