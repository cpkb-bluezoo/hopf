// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! QUIC transport parameters (RFC 9000 §18) — minimal encode/decode.

use crate::transport::types::ConnectionId;
use crate::transport::varint;

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
                _ => {}
            }
        }
        Some(tp)
    }
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
}
