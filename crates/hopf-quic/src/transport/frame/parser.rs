// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! QUIC frame decode (subset for echo milestone).

use bytes::Bytes;

use crate::transport::types::StreamId;
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
    /// STREAM base (0x08–0x0f)
    pub const STREAM_MIN: u64 = 0x08;
    /// MAX_DATA
    pub const MAX_DATA: u64 = 0x10;
    /// MAX_STREAM_DATA
    pub const MAX_STREAM_DATA: u64 = 0x11;
    /// MAX_STREAMS_BIDI
    pub const MAX_STREAMS_BIDI: u64 = 0x12;
    /// CONNECTION_CLOSE transport
    pub const CONNECTION_CLOSE: u64 = 0x1c;
    /// CONNECTION_CLOSE application
    pub const CONNECTION_CLOSE_APP: u64 = 0x1d;
    /// HANDSHAKE_DONE
    pub const HANDSHAKE_DONE: u64 = 0x1e;
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
                let id = StreamId(varint::decode(&mut buf).ok_or(())?);
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
                let id = StreamId(varint::decode(&mut buf).ok_or(())?);
                let max = varint::decode(&mut buf).ok_or(())?;
                frames.push(Frame::MaxStreamData { id, max });
            }
            ty::MAX_STREAMS_BIDI => {
                let max = varint::decode(&mut buf).ok_or(())?;
                frames.push(Frame::MaxStreamsBidi { max });
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
                let id = StreamId(varint::decode(&mut buf).ok_or(())?);
                let error_code = varint::decode(&mut buf).ok_or(())?;
                let final_size = varint::decode(&mut buf).ok_or(())?;
                frames.push(Frame::ResetStream {
                    id,
                    error_code,
                    final_size,
                });
            }
            ty::STOP_SENDING => {
                let id = StreamId(varint::decode(&mut buf).ok_or(())?);
                let error_code = varint::decode(&mut buf).ok_or(())?;
                frames.push(Frame::StopSending { id, error_code });
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
