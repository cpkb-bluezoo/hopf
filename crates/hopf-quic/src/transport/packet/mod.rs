// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Packet codecs and protection.

pub mod long_header;
pub mod pn;
pub mod protection;
pub mod retry;
pub mod short_header;
pub mod transport_params;

pub use long_header::{LongHeaderPrefix, TYPE_HANDSHAKE, TYPE_INITIAL, TYPE_RETRY};
pub use retry::{RetryPacket, INTEGRITY_TAG_LEN};
pub use protection::{initial_keys, initial_secrets, KeyPair, PacketKeys};
pub use short_header::ShortHeaderPrefix;
pub use transport_params::TransportParameters;
