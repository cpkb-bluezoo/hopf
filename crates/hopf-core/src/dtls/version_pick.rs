// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Pick DTLS 1.2 vs 1.3 from epoch-0 `DTLSPlaintext` records (RFC 6347 /
//! RFC 9147 share the same cleartext record shape).

use crate::tls::version_pick::{pick_client_version, pick_server_version, PickedTls};

use super::reassembly::Reassembler;
use super::record::{read_plaintext_record, PlaintextReadOutcome};

const CONTENT_HANDSHAKE: u8 = 22;
const HANDSHAKE_CLIENT_HELLO: u8 = 1;
const HANDSHAKE_SERVER_HELLO: u8 = 2;

/// Scan buffered datagram bytes for the first complete `ClientHello`.
pub(crate) fn find_client_hello_in_dtls(buf: &[u8]) -> Result<Option<PickedTls>, ()> {
    find_handshake(buf, HANDSHAKE_CLIENT_HELLO, pick_server_version)
}

/// After the client has sent `ClientHello`, scan for `ServerHello`.
pub(crate) fn find_server_hello_in_dtls(buf: &[u8]) -> Result<Option<PickedTls>, ()> {
    find_handshake(buf, HANDSHAKE_SERVER_HELLO, pick_client_version)
}

fn find_handshake(
    buf: &[u8],
    want_type: u8,
    pick: fn(&[u8]) -> Option<PickedTls>,
) -> Result<Option<PickedTls>, ()> {
    let mut off = 0;
    let mut reasm = Reassembler::new();
    while off < buf.len() {
        match read_plaintext_record(&buf[off..]) {
            PlaintextReadOutcome::Incomplete => return Ok(None),
            PlaintextReadOutcome::NotPlaintext => return Err(()),
            PlaintextReadOutcome::Invalid => return Err(()),
            PlaintextReadOutcome::Record { content_type, payload, consumed } => {
                off += consumed;
                if content_type != CONTENT_HANDSHAKE {
                    continue;
                }
                for msg in reasm.receive_fragment(&payload) {
                    if msg.first() != Some(&want_type) || msg.len() < 4 {
                        continue;
                    }
                    match pick(&msg[4..]) {
                        Some(p) => return Ok(Some(p)),
                        None => return Err(()),
                    }
                }
            }
        }
    }
    Ok(None)
}
