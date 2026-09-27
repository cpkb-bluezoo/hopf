// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Per-session and per-link connection state (core spec 2.5 / 2.6).
//!
//! Kept as plain data + a few pure helpers here; the wire dispatch and
//! [`crate::client::handlers::Amqp1ClientDriver`] callbacks that read and
//! mutate it live in [`super::endpoint`].

use std::collections::HashMap;

use crate::codec::message::MessageParser;

/// One session's flow-control and link-registry state.
pub(super) struct SessionState {
    /// Channel number this side chose for the session.
    pub(super) local_channel: u16,
    /// Channel number the peer chose, once its `begin` arrives.
    pub(super) remote_channel: Option<u16>,
    /// Transfer-id this side will assign to its next outgoing transfer.
    pub(super) next_outgoing_id: u32,
    /// Transfer-id this side expects for the peer's next transfer, once known.
    pub(super) next_incoming_id: u32,
    /// Remaining transfer frames this side will accept before re-flowing.
    pub(super) incoming_window: u32,
    /// Value [`Self::incoming_window`] is reset to on re-flow.
    pub(super) initial_incoming_window: u32,
    /// This side's advertised outgoing-window.
    pub(super) outgoing_window: u32,
    /// Transfer frames the peer will still accept from this side, per the
    /// peer's last `flow` (core spec 2.5.6).
    pub(super) remote_incoming_window: u32,
    /// Whether the peer's `begin` has arrived.
    pub(super) active: bool,
    /// Whether this side has sent `end`.
    pub(super) end_sent: bool,
    /// Links on this session, by the local handle this side chose.
    pub(super) links: HashMap<u32, LinkState>,
    /// Local handle, by the peer's own handle for the same link — populated
    /// once the peer's `attach` arrives (spec: `handle` is chosen
    /// independently by each side).
    pub(super) links_by_remote_handle: HashMap<u32, u32>,
    /// Local handle, by link name — used to correlate the peer's `attach`
    /// reply with the attach this side sent.
    pub(super) links_by_name: HashMap<String, u32>,
    /// Next local handle to hand out.
    pub(super) next_local_handle: u32,
    /// Outstanding deliveries this side sent and hasn't seen settled yet:
    /// delivery-id -> (link handle, delivery-tag).
    pub(super) unsettled_sent: HashMap<u32, (u32, Vec<u8>)>,
}

/// Deliveries and window accounting are all initialized to this on a fresh
/// session — generous enough that a modest client rarely needs to re-flow.
pub(super) const INITIAL_WINDOW: u32 = 2048;

impl SessionState {
    pub(super) fn new(local_channel: u16) -> Self {
        Self {
            local_channel,
            remote_channel: None,
            next_outgoing_id: 0,
            next_incoming_id: 0,
            incoming_window: INITIAL_WINDOW,
            initial_incoming_window: INITIAL_WINDOW,
            outgoing_window: INITIAL_WINDOW,
            remote_incoming_window: 0,
            active: false,
            end_sent: false,
            links: HashMap::new(),
            links_by_remote_handle: HashMap::new(),
            links_by_name: HashMap::new(),
            next_local_handle: 0,
            unsettled_sent: HashMap::new(),
        }
    }

    pub(super) fn add_link(&mut self, name: String, is_receiver: bool) -> u32 {
        let handle = self.next_local_handle;
        self.next_local_handle += 1;
        self.links_by_name.insert(link_key(&name, is_receiver), handle);
        self.links.insert(handle, LinkState::new(name, is_receiver));
        handle
    }
}

/// Link names are only unique per direction — a session may have a sender
/// and a receiver both named e.g. `"orders"` (core spec 2.6.3 note).
fn link_key(name: &str, is_receiver: bool) -> String {
    if is_receiver {
        format!("r:{name}")
    } else {
        format!("s:{name}")
    }
}

/// One link's attach/flow-control state. The peer's own handle for this
/// link, once its `attach` arrives, is tracked separately in
/// [`SessionState::links_by_remote_handle`] (the direction dispatch needs
/// handle -> link lookups, not link -> handle).
pub(super) struct LinkState {
    /// Link name.
    pub(super) name: String,
    /// `true` if this side is the receiver, `false` if the sender.
    pub(super) is_receiver: bool,
    /// This side's current delivery-count (core spec 2.6.7).
    pub(super) delivery_count: u32,
    /// Sender: credit available to send. Receiver: credit granted to the peer.
    pub(super) link_credit: u32,
    /// Receiver only: message-section parser for the delivery in progress.
    pub(super) parser: MessageParser,
    /// Receiver only: `(delivery_id, delivery_tag)` of the delivery in progress.
    pub(super) current_delivery: Option<(u32, Vec<u8>)>,
}

impl LinkState {
    fn new(name: String, is_receiver: bool) -> Self {
        Self {
            name,
            is_receiver,
            delivery_count: 0,
            link_credit: 0,
            parser: MessageParser::new(),
            current_delivery: None,
        }
    }
}
