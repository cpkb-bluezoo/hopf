// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Outstanding sent-packet record (RFC 9002 Appendix A.1.1).

use std::time::Instant;

use bytes::Bytes;

use crate::transport::types::StreamId;

/// Frame payload that can be retransmitted after loss detection.
#[derive(Debug, Clone)]
pub enum RecoverableFrame {
    /// CRYPTO frame at a fixed offset.
    Crypto {
        /// CRYPTO stream offset.
        offset: u64,
        /// Frame payload.
        data: Bytes,
    },
    /// STREAM frame.
    Stream {
        /// Stream identifier.
        id: StreamId,
        /// Stream offset.
        offset: u64,
        /// Frame payload.
        data: Bytes,
        /// FIN bit.
        fin: bool,
    },
    /// PING (PTO probe).
    Ping,
}

/// A tracked outstanding (sent, not yet acknowledged or declared lost) packet.
#[derive(Debug, Clone)]
pub struct SentPacket {
    /// Packet number.
    pub packet_number: u64,
    /// Send time.
    pub time_sent: Instant,
    /// Whether an acknowledgment is expected.
    pub ack_eliciting: bool,
    /// Whether this packet counts toward bytes in flight.
    pub in_flight: bool,
    /// Bytes sent (QUIC framing included, UDP/IP overhead excluded).
    pub sent_bytes: usize,
    /// Recoverable frames carried for retransmission on loss.
    pub frames: Vec<RecoverableFrame>,
}

impl SentPacket {
    /// Create a sent-packet record.
    pub fn new(
        packet_number: u64,
        time_sent: Instant,
        ack_eliciting: bool,
        in_flight: bool,
        sent_bytes: usize,
        frames: Vec<RecoverableFrame>,
    ) -> Self {
        Self {
            packet_number,
            time_sent,
            ack_eliciting,
            in_flight,
            sent_bytes,
            frames,
        }
    }
}
