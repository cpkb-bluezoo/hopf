// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! RFC 9002 loss recovery (Gumdrop-shaped).

mod congestion;
mod loss_detector;
mod rtt;
mod sent_packet;

pub use congestion::CongestionController;
pub use loss_detector::{AckResult, LossDetector, TimeoutResult, K_PACKET_THRESHOLD};
pub use rtt::{RttEstimator, K_INITIAL_RTT};
pub use sent_packet::{RecoverableFrame, SentPacket};
