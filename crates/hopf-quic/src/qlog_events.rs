// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! qlog event and field names (draft-ietf-quic-qlog-quic-events-13).

pub const CONNECTION_STARTED: &str = "quic:connection_started";
pub const CONNECTION_CLOSED: &str = "quic:connection_closed";
pub const PARAMETERS_SET: &str = "quic:parameters_set";
pub const RECOVERY_METRICS_UPDATED: &str = "quic:recovery_metrics_updated";
pub const PACKET_LOST: &str = "quic:packet_lost";
pub const PACKET_SENT: &str = "quic:packet_sent";
pub const PACKET_RECEIVED: &str = "quic:packet_received";

pub const IP_VERSION: &str = "ip_version";
pub const SRC_IP: &str = "src_ip";
pub const DST_IP: &str = "dst_ip";
pub const SRC_PORT: &str = "src_port";
pub const DST_PORT: &str = "dst_port";
pub const SRC_CID: &str = "src_cid";
pub const DST_CID: &str = "dcid";

pub const OWNER: &str = "owner";
pub const TRIGGER: &str = "trigger";
pub const HEADER: &str = "header";
pub const PACKET_TYPE: &str = "packet_type";
pub const PACKET_NUMBER: &str = "packet_number";
pub const RAW: &str = "raw";
pub const LENGTH: &str = "length";
pub const FRAMES: &str = "frames";
pub const VERSION: &str = "version";
pub const SCID: &str = "scid";

pub const MIN_RTT: &str = "min_rtt";
pub const SMOOTHED_RTT: &str = "smoothed_rtt";
pub const LATEST_RTT: &str = "latest_rtt";
pub const RTT_VARIANCE: &str = "rtt_variance";
pub const CONGESTION_WINDOW: &str = "congestion_window";
pub const BYTES_IN_FLIGHT: &str = "bytes_in_flight";
pub const SSTHRESH: &str = "ssthresh";
pub const PACING_RATE: &str = "pacing_rate";

pub const ORIGINAL_DESTINATION_CONNECTION_ID: &str = "original_destination_connection_id";
pub const INITIAL_SOURCE_CONNECTION_ID: &str = "initial_source_connection_id";
pub const RETRY_SOURCE_CONNECTION_ID: &str = "retry_source_connection_id";
pub const MAX_IDLE_TIMEOUT: &str = "max_idle_timeout";
pub const MAX_UDP_PAYLOAD_SIZE: &str = "max_udp_payload_size";
pub const ACK_DELAY_EXPONENT: &str = "ack_delay_exponent";
pub const MAX_ACK_DELAY: &str = "max_ack_delay";
pub const INITIAL_MAX_DATA: &str = "initial_max_data";
pub const INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: &str = "initial_max_stream_data_bidi_local";
pub const INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: &str = "initial_max_stream_data_bidi_remote";
pub const INITIAL_MAX_STREAM_DATA_UNI: &str = "initial_max_stream_data_uni";
pub const INITIAL_MAX_STREAMS_BIDI: &str = "initial_max_streams_bidi";
pub const INITIAL_MAX_STREAMS_UNI: &str = "initial_max_streams_uni";

pub const OWNER_LOCAL: &str = "local";
pub const OWNER_REMOTE: &str = "remote";

pub const PACKET_TYPE_INITIAL: &str = "initial";
pub const PACKET_TYPE_HANDSHAKE: &str = "handshake";
pub const PACKET_TYPE_1RTT: &str = "1RTT";
pub const PACKET_TYPE_0RTT: &str = "0RTT";

pub const TRIGGER_TIME_THRESHOLD: &str = "time_threshold";
pub const TRIGGER_CLEAN: &str = "clean";
pub const TRIGGER_ERROR: &str = "error";
