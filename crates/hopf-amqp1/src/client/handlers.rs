// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Driver / Control SPI — application-facing callback and command traits.

use std::io;

use crate::codec::{Amqp1CompositeError, DeliveryState, MessageHeader, MessageProperties, Source, Target, Value};

/// Creates a fresh [`Amqp1ClientDriver`] for each dialed connection (a
/// [`crate::client::Amqp1Client`] may be reused to dial more than once, e.g.
/// after a failure).
pub trait Amqp1ClientHandlerFactory: Send + Sync {
    /// Create a new driver instance for one connection.
    fn create(&self) -> Box<dyn Amqp1ClientDriver>;
}

/// Commands sent back to the connection, passed to
/// [`Amqp1ClientDriver`] methods as `&mut dyn Amqp1ClientControl`.
pub trait Amqp1ClientControl {
    /// Begin a new session. Returns the local channel number to use for
    /// subsequent [`Self::attach_sender`]/[`Self::attach_receiver`] calls
    /// on it — the session isn't usable until
    /// [`Amqp1ClientDriver::on_session_begin`] confirms the peer's `begin`.
    fn begin_session(&mut self) -> u16;

    /// Attach a sending link (this side is the sender) on `channel`,
    /// targeting `target`. Returns the link handle to use for
    /// [`Self::send`] — not usable until
    /// [`Amqp1ClientDriver::on_link_attached`] confirms the peer's `attach`.
    fn attach_sender(&mut self, channel: u16, name: &str, target: Target) -> u32;

    /// Attach a receiving link (this side is the receiver) on `channel`,
    /// from `source`. Returns the link handle. Call [`Self::add_credit`]
    /// once attached to start receiving deliveries — a freshly attached
    /// receiver has zero link-credit.
    fn attach_receiver(&mut self, channel: u16, name: &str, source: Source) -> u32;

    /// Send one message on a sending link identified by `handle`.
    /// `delivery_tag` must be unique among this link's unsettled deliveries.
    /// Splits into multiple `transfer` frames automatically if the encoded
    /// message exceeds the peer's max-frame-size. Fails with
    /// [`crate::client::Amqp1ClientError::NoLinkCredit`] if this link
    /// currently has no link-credit (wait for
    /// [`Amqp1ClientDriver::on_credit`]).
    #[allow(clippy::too_many_arguments)]
    fn send(
        &mut self,
        handle: u32,
        delivery_tag: &[u8],
        header: Option<&MessageHeader>,
        properties: Option<&MessageProperties>,
        application_properties: &[(String, Value)],
        body: &[u8],
        settled: bool,
    ) -> Result<(), crate::client::Amqp1ClientError>;

    /// Grant additional link-credit to the peer on a receiving link.
    fn add_credit(&mut self, handle: u32, credit: u32);

    /// Settle a received delivery as accepted.
    fn accept(&mut self, handle: u32, delivery_id: u32);

    /// Settle a received delivery as rejected.
    fn reject(&mut self, handle: u32, delivery_id: u32, error: Option<Amqp1CompositeError>);

    /// Settle a received delivery as released (redeliverable elsewhere).
    fn release(&mut self, handle: u32, delivery_id: u32);

    /// Settle a received delivery as modified.
    fn modify(&mut self, handle: u32, delivery_id: u32, delivery_failed: bool, undeliverable_here: bool);

    /// Detach a link. `closed = true` for a permanent close (per core spec
    /// 2.6.10, a detach with `closed = false` merely suspends the link).
    fn detach_link(&mut self, handle: u32, closed: bool, error: Option<Amqp1CompositeError>);

    /// End a session.
    fn end_session(&mut self, channel: u16, error: Option<Amqp1CompositeError>);

    /// Close the connection.
    fn close(&mut self, error: Option<Amqp1CompositeError>);
}

/// Application callbacks for one AMQP 1.0 connection's lifecycle. Every
/// method has a no-op default so implementers only override what they need.
#[allow(unused_variables)]
pub trait Amqp1ClientDriver: Send {
    /// The connection is open (both `open` performatives exchanged).
    fn on_connection_open(&mut self, control: &mut dyn Amqp1ClientControl) {}

    /// The connection closed, with the peer's error if it gave one.
    fn on_connection_close(&mut self, error: Option<&Amqp1CompositeError>) {}

    /// A session this side began is now active (peer's `begin` arrived).
    fn on_session_begin(&mut self, control: &mut dyn Amqp1ClientControl, channel: u16) {}

    /// A session ended.
    fn on_session_end(&mut self, channel: u16, error: Option<&Amqp1CompositeError>) {}

    /// A link this side attached is now active (peer's `attach` arrived).
    fn on_link_attached(&mut self, control: &mut dyn Amqp1ClientControl, handle: u32, is_receiver: bool) {}

    /// A sending link's available credit changed (the peer sent `flow`).
    /// Call [`Amqp1ClientControl::send`] in response, up to the amount of
    /// credit now available.
    fn on_credit(&mut self, control: &mut dyn Amqp1ClientControl, handle: u32) {}

    /// A new delivery is starting on a receiving link.
    fn on_delivery_start(&mut self, handle: u32, delivery_id: u32, delivery_tag: &[u8]) {}

    /// The current delivery's `header` section, if it had one.
    fn on_message_header(&mut self, handle: u32, header: &MessageHeader) {}

    /// The current delivery's `properties` section, if it had one.
    fn on_message_properties(&mut self, handle: u32, properties: &MessageProperties) {}

    /// The current delivery's `application-properties` section, if it had one.
    fn on_message_application_properties(&mut self, handle: u32, properties: &[(String, Value)]) {}

    /// A chunk of the current delivery's `data` section body (zero-copy
    /// view, valid for this call only).
    fn on_message_data(&mut self, handle: u32, data: &[u8]) {}

    /// The current delivery is fully received. Call
    /// [`Amqp1ClientControl::accept`] (or reject/release/modify) in
    /// response, unless the sender already pre-settled it.
    fn on_delivery_complete(&mut self, control: &mut dyn Amqp1ClientControl, handle: u32, delivery_id: u32) {}

    /// The peer reported a new state (e.g. `accepted`) for a delivery this
    /// side sent.
    fn on_delivery_outcome(&mut self, handle: u32, delivery_tag: &[u8], state: &DeliveryState, settled: bool) {}

    /// A link detached.
    fn on_link_detached(&mut self, handle: u32, error: Option<&Amqp1CompositeError>, closed: bool) {}

    /// Unrecoverable I/O or protocol error.
    fn on_error(&mut self, err: &io::Error);

    /// The connection's transport closed.
    fn on_disconnected(&mut self);
}
