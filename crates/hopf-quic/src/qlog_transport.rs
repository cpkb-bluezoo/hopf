// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! qlog event payloads (built only when export is enabled).

use std::net::SocketAddr;

use hopf_core::QLOG_SCHEMA_QUIC;

use crate::qlog_events::{
    ACK_DELAY_EXPONENT, BYTES_IN_FLIGHT, CONGESTION_WINDOW, DST_CID, FRAMES, HEADER,
    INITIAL_MAX_DATA, INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
    INITIAL_MAX_STREAM_DATA_UNI, INITIAL_MAX_STREAMS_BIDI, INITIAL_MAX_STREAMS_UNI, IP_VERSION,
    LENGTH, MAX_ACK_DELAY, MAX_IDLE_TIMEOUT, MAX_UDP_PAYLOAD_SIZE, MIN_RTT, ORIGINAL_DESTINATION_CONNECTION_ID,
    INITIAL_SOURCE_CONNECTION_ID, RETRY_SOURCE_CONNECTION_ID, OWNER, PACKET_NUMBER, PACKET_TYPE,
    PACING_RATE,
    RAW, RTT_VARIANCE, SCID, SMOOTHED_RTT, SSTHRESH, TRIGGER, VERSION, LATEST_RTT,
};
use crate::qlog_frames;
use crate::qlog_json::QlogJson;
use crate::transport::packet::TransportParameters;
use crate::transport::recovery::RecoverableFrame;
use crate::transport::frame::Frame;
use crate::transport::types::SpaceId;
use crate::transport::version::QuicVersion;

pub(crate) fn schema_quic() -> &'static str {
    QLOG_SCHEMA_QUIC
}

pub(crate) fn build_connection_started(
    local: SocketAddr,
    remote: SocketAddr,
    src_cid: &[u8],
    dst_cid: &[u8],
) -> String {
    let ip_version = if local.is_ipv6() || remote.is_ipv6() {
        "v6"
    } else {
        "v4"
    };
    QlogJson::object()
        .put(IP_VERSION, ip_version)
        .put(crate::qlog_events::SRC_IP, &local.ip().to_string())
        .put_u64(crate::qlog_events::SRC_PORT, local.port() as u64)
        .put(crate::qlog_events::DST_IP, &remote.ip().to_string())
        .put_u64(crate::qlog_events::DST_PORT, remote.port() as u64)
        .put_hex(crate::qlog_events::SRC_CID, src_cid)
        .put_hex(DST_CID, dst_cid)
        .build()
}

pub(crate) fn build_parameters_set(owner: &str, tp: &TransportParameters) -> String {
    let mut o = QlogJson::object().put(OWNER, owner);
    if let Some(v) = &tp.original_dst_cid {
        o = o.put_hex(ORIGINAL_DESTINATION_CONNECTION_ID, v.as_slice());
    }
    if let Some(v) = &tp.initial_src_cid {
        o = o.put_hex(INITIAL_SOURCE_CONNECTION_ID, v.as_slice());
    }
    if let Some(v) = &tp.retry_src_cid {
        o = o.put_hex(RETRY_SOURCE_CONNECTION_ID, v.as_slice());
    }
    o.put_u64(MAX_IDLE_TIMEOUT, tp.max_idle_timeout)
        .put_u64(MAX_UDP_PAYLOAD_SIZE, tp.max_udp_payload_size)
        .put_u64(ACK_DELAY_EXPONENT, tp.ack_delay_exponent as u64)
        .put_u64(MAX_ACK_DELAY, tp.max_ack_delay)
        .put_u64(INITIAL_MAX_DATA, tp.initial_max_data)
        .put_u64(
            INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
            tp.initial_max_stream_data_bidi_local,
        )
        .put_u64(
            INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
            tp.initial_max_stream_data_bidi_remote,
        )
        .put_u64(INITIAL_MAX_STREAM_DATA_UNI, tp.initial_max_stream_data_uni)
        .put_u64(INITIAL_MAX_STREAMS_BIDI, tp.initial_max_streams_bidi)
        .put_u64(INITIAL_MAX_STREAMS_UNI, tp.initial_max_streams_uni)
        .build()
}

pub(crate) fn build_packet_sent(
    packet_type: &str,
    packet_number: u64,
    length: usize,
    long_header: bool,
    version: QuicVersion,
    scid: &[u8],
    dcid: &[u8],
    frames: &[RecoverableFrame],
) -> String {
    let qf = qlog_frames::from_recoverable(frames);
    let mut o = QlogJson::object()
        .begin_object(HEADER)
        .put(PACKET_TYPE, packet_type)
        .put_u64(PACKET_NUMBER, packet_number);
    if long_header {
        o = o
            .put(VERSION, &qlog_version(version.wire()))
            .put_hex(SCID, scid);
    }
    o = o.put_hex(DST_CID, dcid).end_object();
    o.begin_object(RAW)
        .put_u64(LENGTH, length as u64)
        .end_object()
        .put_raw(FRAMES, &qf.array())
        .build()
}

pub(crate) fn build_packet_received(
    packet_type: &str,
    packet_number: u64,
    length: usize,
    frames: &[Frame],
) -> String {
    let qf = qlog_frames::from_parsed(frames);
    QlogJson::object()
        .begin_object(HEADER)
        .put(PACKET_TYPE, packet_type)
        .put_u64(PACKET_NUMBER, packet_number)
        .end_object()
        .begin_object(RAW)
        .put_u64(LENGTH, length as u64)
        .end_object()
        .put_raw(FRAMES, &qf.array())
        .build()
}

pub(crate) fn build_packet_lost(packet_type: &str, packet_number: u64, trigger: Option<&str>) -> String {
    let mut o = QlogJson::object()
        .begin_object(HEADER)
        .put(PACKET_TYPE, packet_type)
        .put_u64(PACKET_NUMBER, packet_number)
        .end_object();
    if let Some(t) = trigger {
        o = o.put(TRIGGER, t);
    }
    o.build()
}

pub(crate) fn build_recovery_metrics(
    min_rtt_micros: i64,
    smoothed_micros: i64,
    latest_micros: i64,
    rttvar_micros: i64,
    cwnd: u64,
    bytes_in_flight: u64,
    ssthresh: u64,
    pacing_rate: Option<u64>,
    has_rtt: bool,
) -> String {
    let mut o = QlogJson::object();
    if has_rtt {
        o = o
            .put_millis_from_micros(MIN_RTT, min_rtt_micros)
            .put_millis_from_micros(SMOOTHED_RTT, smoothed_micros)
            .put_millis_from_micros(LATEST_RTT, latest_micros)
            .put_millis_from_micros(RTT_VARIANCE, rttvar_micros);
    }
    o = o
        .put_u64(CONGESTION_WINDOW, cwnd)
        .put_u64(BYTES_IN_FLIGHT, bytes_in_flight);
    if ssthresh < u64::MAX / 2 {
        o = o.put_u64(SSTHRESH, ssthresh);
    }
    if let Some(rate) = pacing_rate {
        o = o.put_u64(PACING_RATE, rate);
    }
    o.build()
}

pub(crate) fn build_connection_closed(trigger: &str) -> String {
    QlogJson::object().put(TRIGGER, trigger).build()
}

pub(crate) fn space_packet_type(space: SpaceId, use_0rtt: bool) -> &'static str {
    match space {
        SpaceId::Initial => crate::qlog_events::PACKET_TYPE_INITIAL,
        SpaceId::Handshake => crate::qlog_events::PACKET_TYPE_HANDSHAKE,
        SpaceId::Data if use_0rtt => crate::qlog_events::PACKET_TYPE_0RTT,
        SpaceId::Data => crate::qlog_events::PACKET_TYPE_1RTT,
    }
}

pub(crate) fn qlog_version(wire: u32) -> String {
    format!("{wire:x}")
}

pub use crate::qlog_events::{
    CONNECTION_CLOSED, CONNECTION_STARTED, PACKET_LOST, PACKET_RECEIVED, PACKET_SENT,
    PARAMETERS_SET, RECOVERY_METRICS_UPDATED,
};
