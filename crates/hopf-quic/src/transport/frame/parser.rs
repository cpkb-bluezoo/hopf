// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! QUIC frame decode (every RFC 9000 frame type, plus RFC 9221 DATAGRAM).

use bytes::Bytes;

use crate::transport::types::{ConnectionId, StreamId};
use crate::transport::varint;

/// Frame type constants (RFC 9000 §19).
pub mod ty {
    /// PADDING
    pub const PADDING: u64 = 0x00;
    /// PING
    pub const PING: u64 = 0x01;
    /// ACK
    pub const ACK: u64 = 0x02;
    /// ACK with ECN
    pub const ACK_ECN: u64 = 0x03;
    /// RESET_STREAM
    pub const RESET_STREAM: u64 = 0x04;
    /// STOP_SENDING
    pub const STOP_SENDING: u64 = 0x05;
    /// CRYPTO
    pub const CRYPTO: u64 = 0x06;
    /// NEW_TOKEN
    pub const NEW_TOKEN: u64 = 0x07;
    /// STREAM base (0x08–0x0f)
    pub const STREAM_MIN: u64 = 0x08;
    /// MAX_DATA
    pub const MAX_DATA: u64 = 0x10;
    /// MAX_STREAM_DATA
    pub const MAX_STREAM_DATA: u64 = 0x11;
    /// MAX_STREAMS_BIDI
    pub const MAX_STREAMS_BIDI: u64 = 0x12;
    /// MAX_STREAMS (unidirectional)
    pub const MAX_STREAMS_UNI: u64 = 0x13;
    /// DATA_BLOCKED
    pub const DATA_BLOCKED: u64 = 0x14;
    /// STREAM_DATA_BLOCKED
    pub const STREAM_DATA_BLOCKED: u64 = 0x15;
    /// STREAMS_BLOCKED (bidirectional)
    pub const STREAMS_BLOCKED_BIDI: u64 = 0x16;
    /// STREAMS_BLOCKED (unidirectional)
    pub const STREAMS_BLOCKED_UNI: u64 = 0x17;
    /// NEW_CONNECTION_ID
    pub const NEW_CONNECTION_ID: u64 = 0x18;
    /// RETIRE_CONNECTION_ID
    pub const RETIRE_CONNECTION_ID: u64 = 0x19;
    /// PATH_CHALLENGE
    pub const PATH_CHALLENGE: u64 = 0x1a;
    /// PATH_RESPONSE
    pub const PATH_RESPONSE: u64 = 0x1b;
    /// CONNECTION_CLOSE transport
    pub const CONNECTION_CLOSE: u64 = 0x1c;
    /// CONNECTION_CLOSE application
    pub const CONNECTION_CLOSE_APP: u64 = 0x1d;
    /// HANDSHAKE_DONE
    pub const HANDSHAKE_DONE: u64 = 0x1e;
    /// DATAGRAM without length (to end of packet)
    pub const DATAGRAM: u64 = 0x30;
    /// DATAGRAM with length
    pub const DATAGRAM_LEN: u64 = 0x31;
}

/// Parsed frame.
#[derive(Debug, Clone)]
pub enum Frame {
    /// Padding of `len` bytes.
    Padding {
        /// Number of consecutive padding bytes.
        len: usize,
    },
    /// Ping.
    Ping,
    /// ACK (ranges descending: each (low, high) inclusive).
    Ack {
        /// Largest acknowledged.
        largest: u64,
        /// ACK delay.
        delay: u64,
        /// Ranges.
        ranges: Vec<(u64, u64)>,
    },
    /// CRYPTO.
    Crypto {
        /// Offset.
        offset: u64,
        /// Data.
        data: Bytes,
    },
    /// STREAM.
    Stream {
        /// Stream ID.
        id: StreamId,
        /// Offset.
        offset: u64,
        /// Data.
        data: Bytes,
        /// FIN bit.
        fin: bool,
    },
    /// MAX_DATA.
    MaxData {
        /// Maximum data.
        max: u64,
    },
    /// MAX_STREAM_DATA.
    MaxStreamData {
        /// Stream ID.
        id: StreamId,
        /// Maximum stream data.
        max: u64,
    },
    /// MAX_STREAMS (bidi).
    MaxStreamsBidi {
        /// Maximum streams.
        max: u64,
    },
    /// DATA_BLOCKED: the peer has data to send but is at our connection
    /// limit (RFC 9000 section 19.12).
    DataBlocked {
        /// The limit the peer is blocked at.
        max: u64,
    },
    /// STREAM_DATA_BLOCKED: the peer is at our limit for one stream
    /// (RFC 9000 section 19.13).
    StreamDataBlocked {
        /// Stream ID.
        id: StreamId,
        /// The limit the peer is blocked at.
        max: u64,
    },
    /// MAX_STREAMS (unidirectional).
    MaxStreamsUni {
        /// Maximum streams.
        max: u64,
    },
    /// STREAMS_BLOCKED: the peer wants to open more streams than we allow
    /// (RFC 9000 section 19.14).
    StreamsBlocked {
        /// Bidirectional (0x16) rather than unidirectional (0x17).
        bidi: bool,
        /// The stream limit the peer is blocked at.
        max: u64,
    },
    /// NEW_TOKEN (RFC 9000 section 19.7): a token for a later Initial.
    NewToken {
        /// Opaque token.
        token: Bytes,
    },
    /// NEW_CONNECTION_ID (RFC 9000 section 19.15).
    NewConnectionId {
        /// Sequence number of this connection ID.
        seq: u64,
        /// Connection IDs below this sequence number are to be retired.
        retire_prior_to: u64,
        /// The connection ID.
        cid: ConnectionId,
        /// Stateless reset token for packets with this ID.
        reset_token: [u8; 16],
    },
    /// RETIRE_CONNECTION_ID (RFC 9000 section 19.16).
    RetireConnectionId {
        /// Sequence number of the connection ID being retired.
        seq: u64,
    },
    /// PATH_CHALLENGE (RFC 9000 section 19.17).
    PathChallenge {
        /// Arbitrary data to echo in a PATH_RESPONSE.
        data: [u8; 8],
    },
    /// PATH_RESPONSE (RFC 9000 section 19.18).
    PathResponse {
        /// The PATH_CHALLENGE data echoed.
        data: [u8; 8],
    },
    /// CONNECTION_CLOSE.
    ConnectionClose {
        /// Application vs transport.
        application: bool,
        /// Error code.
        error_code: u64,
        /// Frame type that caused it (transport only).
        frame_type: u64,
        /// Reason phrase.
        reason: Bytes,
    },
    /// HANDSHAKE_DONE.
    HandshakeDone,
    /// RESET_STREAM.
    ResetStream {
        /// Stream ID.
        id: StreamId,
        /// Application error.
        error_code: u64,
        /// Final size.
        final_size: u64,
    },
    /// STOP_SENDING.
    StopSending {
        /// Stream ID.
        id: StreamId,
        /// Application error.
        error_code: u64,
    },
    /// DATAGRAM (RFC 9221).
    Datagram {
        /// Payload.
        data: Bytes,
    },
}

fn parse_ack(buf: &mut &[u8], with_ecn: bool) -> Result<Frame, ()> {
    let largest = varint::decode(buf).ok_or(())?;
    let delay = varint::decode(buf).ok_or(())?;
    let range_count = varint::decode(buf).ok_or(())?;
    let first_range = varint::decode(buf).ok_or(())?;
    let mut ranges = Vec::with_capacity(1 + range_count as usize);
    let mut high = largest;
    let mut low = high.checked_sub(first_range).ok_or(())?;
    ranges.push((low, high));
    for _ in 0..range_count {
        let gap = varint::decode(buf).ok_or(())?;
        let range_len = varint::decode(buf).ok_or(())?;
        high = low.checked_sub(gap + 2).ok_or(())?;
        low = high.checked_sub(range_len).ok_or(())?;
        ranges.push((low, high));
    }
    if with_ecn {
        let _ = varint::decode(buf).ok_or(())?;
        let _ = varint::decode(buf).ok_or(())?;
        let _ = varint::decode(buf).ok_or(())?;
    }
    Ok(Frame::Ack {
        largest,
        delay,
        ranges,
    })
}

/// Parse all frames from a decrypted packet payload.
pub fn parse_all(mut buf: &[u8]) -> Result<Vec<Frame>, ()> {
    let mut frames = Vec::new();
    while !buf.is_empty() {
        if buf[0] == 0 {
            let mut len = 0;
            while !buf.is_empty() && buf[0] == 0 {
                len += 1;
                buf = &buf[1..];
            }
            frames.push(Frame::Padding { len });
            continue;
        }
        let frame_ty = varint::decode(&mut buf).ok_or(())?;
        match frame_ty {
            ty::PING => frames.push(Frame::Ping),
            ty::ACK => frames.push(parse_ack(&mut buf, false)?),
            ty::ACK_ECN => frames.push(parse_ack(&mut buf, true)?),
            ty::CRYPTO => {
                let offset = varint::decode(&mut buf).ok_or(())?;
                let len = varint::decode(&mut buf).ok_or(())? as usize;
                if buf.len() < len {
                    return Err(());
                }
                let data = Bytes::copy_from_slice(&buf[..len]);
                buf = &buf[len..];
                frames.push(Frame::Crypto { offset, data });
            }
            t if (ty::STREAM_MIN..=0x0f).contains(&t) => {
                let off_bit = t & 0x04 != 0;
                let len_bit = t & 0x02 != 0;
                let fin = t & 0x01 != 0;
                let id = StreamId::from_wire(varint::decode(&mut buf).ok_or(())?);
                let offset = if off_bit {
                    varint::decode(&mut buf).ok_or(())?
                } else {
                    0
                };
                let data = if len_bit {
                    let len = varint::decode(&mut buf).ok_or(())? as usize;
                    if buf.len() < len {
                        return Err(());
                    }
                    let d = Bytes::copy_from_slice(&buf[..len]);
                    buf = &buf[len..];
                    d
                } else {
                    let d = Bytes::copy_from_slice(buf);
                    buf = &[];
                    d
                };
                frames.push(Frame::Stream {
                    id,
                    offset,
                    data,
                    fin,
                });
            }
            ty::MAX_DATA => {
                let max = varint::decode(&mut buf).ok_or(())?;
                frames.push(Frame::MaxData { max });
            }
            ty::MAX_STREAM_DATA => {
                let id = StreamId::from_wire(varint::decode(&mut buf).ok_or(())?);
                let max = varint::decode(&mut buf).ok_or(())?;
                frames.push(Frame::MaxStreamData { id, max });
            }
            ty::MAX_STREAMS_BIDI => {
                let max = varint::decode(&mut buf).ok_or(())?;
                frames.push(Frame::MaxStreamsBidi { max });
            }
            ty::DATA_BLOCKED => {
                let max = varint::decode(&mut buf).ok_or(())?;
                frames.push(Frame::DataBlocked { max });
            }
            ty::MAX_STREAMS_UNI => {
                let max = varint::decode(&mut buf).ok_or(())?;
                frames.push(Frame::MaxStreamsUni { max });
            }
            ty::STREAMS_BLOCKED_BIDI | ty::STREAMS_BLOCKED_UNI => {
                let max = varint::decode(&mut buf).ok_or(())?;
                frames.push(Frame::StreamsBlocked { bidi: frame_ty == ty::STREAMS_BLOCKED_BIDI, max });
            }
            ty::NEW_TOKEN => {
                let len = varint::decode(&mut buf).ok_or(())? as usize;
                // Section 19.7: an empty token is a FRAME_ENCODING_ERROR.
                if len == 0 || buf.len() < len {
                    return Err(());
                }
                let token = Bytes::copy_from_slice(&buf[..len]);
                buf = &buf[len..];
                frames.push(Frame::NewToken { token });
            }
            ty::NEW_CONNECTION_ID => {
                let seq = varint::decode(&mut buf).ok_or(())?;
                let retire_prior_to = varint::decode(&mut buf).ok_or(())?;
                let len = *buf.first().ok_or(())? as usize;
                buf = &buf[1..];
                // Section 19.15: 1 to 20 bytes, and Retire Prior To never
                // above the sequence number.
                if !(1..=20).contains(&len) || retire_prior_to > seq || buf.len() < len + 16 {
                    return Err(());
                }
                let cid = ConnectionId::from_slice(&buf[..len]);
                let mut reset_token = [0u8; 16];
                reset_token.copy_from_slice(&buf[len..len + 16]);
                buf = &buf[len + 16..];
                frames.push(Frame::NewConnectionId { seq, retire_prior_to, cid, reset_token });
            }
            ty::RETIRE_CONNECTION_ID => {
                let seq = varint::decode(&mut buf).ok_or(())?;
                frames.push(Frame::RetireConnectionId { seq });
            }
            ty::PATH_CHALLENGE | ty::PATH_RESPONSE => {
                if buf.len() < 8 {
                    return Err(());
                }
                let mut data = [0u8; 8];
                data.copy_from_slice(&buf[..8]);
                buf = &buf[8..];
                frames.push(if frame_ty == ty::PATH_CHALLENGE {
                    Frame::PathChallenge { data }
                } else {
                    Frame::PathResponse { data }
                });
            }
            ty::STREAM_DATA_BLOCKED => {
                let id = StreamId::from_wire(varint::decode(&mut buf).ok_or(())?);
                let max = varint::decode(&mut buf).ok_or(())?;
                frames.push(Frame::StreamDataBlocked { id, max });
            }
            ty::CONNECTION_CLOSE | ty::CONNECTION_CLOSE_APP => {
                let application = frame_ty == ty::CONNECTION_CLOSE_APP;
                let error_code = varint::decode(&mut buf).ok_or(())?;
                let frame_type = if application {
                    0
                } else {
                    varint::decode(&mut buf).ok_or(())?
                };
                let reason_len = varint::decode(&mut buf).ok_or(())? as usize;
                if buf.len() < reason_len {
                    return Err(());
                }
                let reason = Bytes::copy_from_slice(&buf[..reason_len]);
                buf = &buf[reason_len..];
                frames.push(Frame::ConnectionClose {
                    application,
                    error_code,
                    frame_type,
                    reason,
                });
            }
            ty::HANDSHAKE_DONE => frames.push(Frame::HandshakeDone),
            ty::RESET_STREAM => {
                let id = StreamId::from_wire(varint::decode(&mut buf).ok_or(())?);
                let error_code = varint::decode(&mut buf).ok_or(())?;
                let final_size = varint::decode(&mut buf).ok_or(())?;
                frames.push(Frame::ResetStream {
                    id,
                    error_code,
                    final_size,
                });
            }
            ty::STOP_SENDING => {
                let id = StreamId::from_wire(varint::decode(&mut buf).ok_or(())?);
                let error_code = varint::decode(&mut buf).ok_or(())?;
                frames.push(Frame::StopSending { id, error_code });
            }
            ty::DATAGRAM => {
                let data = Bytes::copy_from_slice(buf);
                buf = &[];
                frames.push(Frame::Datagram { data });
            }
            ty::DATAGRAM_LEN => {
                let len = varint::decode(&mut buf).ok_or(())? as usize;
                if buf.len() < len {
                    return Err(());
                }
                let data = Bytes::copy_from_slice(&buf[..len]);
                buf = &buf[len..];
                frames.push(Frame::Datagram { data });
            }
            _ => return Err(()),
        }
    }
    Ok(frames)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::frame::writer;

    /// Every frame the writer can produce decodes back to the same frame.
    #[test]
    fn every_frame_type_round_trips() {
        let id = StreamId::from_wire(4);
        let cid = ConnectionId::from_slice(&[1, 2, 3, 4, 5]);
        let mut buf = Vec::new();
        writer::new_token(&mut buf, b"tok");
        writer::max_streams_uni(&mut buf, 7);
        writer::streams_blocked(&mut buf, true, 8);
        writer::streams_blocked(&mut buf, false, 9);
        writer::new_connection_id(&mut buf, 3, 1, &cid, &[0xaa; 16]);
        writer::retire_connection_id(&mut buf, 2);
        writer::path_challenge(&mut buf, &[1, 2, 3, 4, 5, 6, 7, 8]);
        writer::path_response(&mut buf, &[8, 7, 6, 5, 4, 3, 2, 1]);
        writer::reset_stream(&mut buf, id, 0x11, 1234);
        writer::stop_sending(&mut buf, id, 0x22);
        writer::data_blocked(&mut buf, 10);
        writer::stream_data_blocked(&mut buf, id, 11);
        writer::max_data(&mut buf, 12);
        writer::max_stream_data(&mut buf, id, 13);
        let frames = parse_all(&buf).unwrap();
        assert!(matches!(&frames[0], Frame::NewToken { token } if token.as_ref() == b"tok"));
        assert!(matches!(frames[1], Frame::MaxStreamsUni { max: 7 }));
        assert!(matches!(frames[2], Frame::StreamsBlocked { bidi: true, max: 8 }));
        assert!(matches!(frames[3], Frame::StreamsBlocked { bidi: false, max: 9 }));
        assert!(matches!(&frames[4], Frame::NewConnectionId { seq: 3, retire_prior_to: 1, cid: c, reset_token } if *c == cid && *reset_token == [0xaa; 16]));
        assert!(matches!(frames[5], Frame::RetireConnectionId { seq: 2 }));
        assert!(matches!(frames[6], Frame::PathChallenge { data: [1, 2, 3, 4, 5, 6, 7, 8] }));
        assert!(matches!(frames[7], Frame::PathResponse { data: [8, 7, 6, 5, 4, 3, 2, 1] }));
        assert!(matches!(frames[8], Frame::ResetStream { id: i, error_code: 0x11, final_size: 1234 } if i == id));
        assert!(matches!(frames[9], Frame::StopSending { id: i, error_code: 0x22 } if i == id));
        assert!(matches!(frames[10], Frame::DataBlocked { max: 10 }));
        assert!(matches!(frames[11], Frame::StreamDataBlocked { id: i, max: 11 } if i == id));
        assert!(matches!(frames[12], Frame::MaxData { max: 12 }));
        assert!(matches!(frames[13], Frame::MaxStreamData { id: i, max: 13 } if i == id));
        assert_eq!(frames.len(), 14);
    }

    /// RFC 9000 section 19.15: a zero-length or over-long connection ID,
    /// or Retire Prior To above the sequence number, is malformed.
    #[test]
    fn malformed_new_connection_id_is_rejected() {
        let cid = ConnectionId::from_slice(&[1; 8]);
        let mut buf = Vec::new();
        writer::new_connection_id(&mut buf, 1, 2, &cid, &[0; 16]);
        assert!(parse_all(&buf).is_err(), "retire_prior_to above seq");
        let mut buf = Vec::new();
        writer::new_connection_id(&mut buf, 1, 0, &ConnectionId::from_slice(&[]), &[0; 16]);
        assert!(parse_all(&buf).is_err(), "zero-length id");
    }

    /// A multi-range ACK encodes gaps and lengths as RFC 9000 section 19.3
    /// defines them and decodes back to the same ranges.
    #[test]
    fn multi_range_ack_round_trips() {
        let mut buf = Vec::new();
        writer::ack(&mut buf, 5, &[(7, 7), (4, 5), (1, 2)]);
        let frames = parse_all(&buf).unwrap();
        assert!(matches!(&frames[0], Frame::Ack { largest: 7, delay: 5, ranges } if *ranges == vec![(7, 7), (4, 5), (1, 2)]));
        let mut buf = Vec::new();
        writer::ack(&mut buf, 0, &[(10, 12)]);
        let frames = parse_all(&buf).unwrap();
        assert!(matches!(&frames[0], Frame::Ack { largest: 12, ranges, .. } if *ranges == vec![(10, 12)]));
    }

    #[test]
    fn crypto_round_trip() {
        let mut buf = Vec::new();
        writer::crypto(&mut buf, 0, b"hello");
        let frames = parse_all(&buf).unwrap();
        assert_eq!(frames.len(), 1);
        match &frames[0] {
            Frame::Crypto { offset, data } => {
                assert_eq!(*offset, 0);
                assert_eq!(data.as_ref(), b"hello");
            }
            _ => panic!("expected crypto"),
        }
    }
}
