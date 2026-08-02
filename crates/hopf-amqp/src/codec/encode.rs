// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Frame encode helpers.

use super::properties::BasicProperties;
use super::types::{
    class, FRAME_BODY, FRAME_END, FRAME_HEADER, FRAME_HEARTBEAT, FRAME_METHOD, PROTOCOL_HEADER,
};
use super::AmqpError;

/// Encode a complete frame: type, channel, size, payload, frame-end.
pub fn encode_frame(frame_type: u8, channel: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + payload.len());
    out.push(frame_type);
    out.extend_from_slice(&channel.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out.push(FRAME_END);
    out
}

/// Protocol header bytes.
pub fn encode_protocol_header() -> &'static [u8; 8] {
    PROTOCOL_HEADER
}

/// Method frame from class/method ids + arguments payload.
pub fn encode_method(channel: u16, class_id: u16, method_id: u16, args: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(4 + args.len());
    payload.extend_from_slice(&class_id.to_be_bytes());
    payload.extend_from_slice(&method_id.to_be_bytes());
    payload.extend_from_slice(args);
    encode_frame(FRAME_METHOD, channel, &payload)
}

/// Content header frame for the Basic class.
pub fn encode_content_header(
    channel: u16,
    body_size: u64,
    properties: &BasicProperties,
) -> Result<Vec<u8>, AmqpError> {
    let prop_bytes = properties.encode()?;
    let mut payload = Vec::with_capacity(14 + prop_bytes.len());
    payload.extend_from_slice(&class::BASIC.to_be_bytes());
    payload.extend_from_slice(&0u16.to_be_bytes()); // weight
    payload.extend_from_slice(&body_size.to_be_bytes());
    payload.extend_from_slice(&prop_bytes);
    Ok(encode_frame(FRAME_HEADER, channel, &payload))
}

/// One content body frame (caller splits by frame_max).
pub fn encode_content_body(channel: u16, chunk: &[u8]) -> Vec<u8> {
    encode_frame(FRAME_BODY, channel, chunk)
}

/// Heartbeat frame (channel 0, empty payload).
pub fn encode_heartbeat() -> Vec<u8> {
    encode_frame(FRAME_HEARTBEAT, 0, &[])
}

/// Maximum body bytes per content body frame given negotiated `frame_max`.
///
/// Frame overhead is 8 bytes (type+channel+size+end). `frame_max` is the
/// maximum *frame* size including that overhead; when 0, use a large default
/// from the caller.
pub fn max_body_per_frame(frame_max: u32) -> usize {
    let fm = if frame_max == 0 {
        super::types::DEFAULT_FRAME_MAX
    } else {
        frame_max
    };
    fm.saturating_sub(8) as usize
}

/// Encode a full Basic content (header + body frames), splitting by `frame_max`.
pub fn encode_content(
    channel: u16,
    properties: &BasicProperties,
    body: &[u8],
    frame_max: u32,
) -> Result<Vec<u8>, AmqpError> {
    let mut out = encode_content_header(channel, body.len() as u64, properties)?;
    let max = max_body_per_frame(frame_max).max(1);
    let mut offset = 0;
    while offset < body.len() {
        let end = (offset + max).min(body.len());
        out.extend_from_slice(&encode_content_body(channel, &body[offset..end]));
        offset = end;
    }
    // Zero-length body: still valid — only header, no body frames.
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::types::FRAME_END;

    #[test]
    fn method_frame_shape() {
        let f = encode_method(1, 60, 40, &[0, 0]);
        assert_eq!(f[0], FRAME_METHOD);
        assert_eq!(u16::from_be_bytes([f[1], f[2]]), 1);
        assert_eq!(*f.last().unwrap(), FRAME_END);
    }

    #[test]
    fn content_splits_on_frame_max() {
        let props = BasicProperties::new();
        // Tiny frame_max forces multiple body frames.
        let body = vec![0u8; 100];
        let frames = encode_content(1, &props, &body, 32).unwrap();
        let body_frames = frames.iter().filter(|&&b| b == FRAME_BODY).count();
        assert!(body_frames > 1);
    }

    #[test]
    fn heartbeat_empty() {
        let h = encode_heartbeat();
        assert_eq!(h, vec![FRAME_HEARTBEAT, 0, 0, 0, 0, 0, 0, FRAME_END]);
    }
}
