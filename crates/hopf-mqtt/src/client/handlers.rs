// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! MQTT client handler factory and driver traits.
//!
//! Unlike the staged POP3 / IMAP client drivers (which expose a different
//! state trait per protocol phase, plus raw `Endpoint` access), MQTT has
//! only one phase once CONNACK arrives — a connected client may publish /
//! subscribe / unsubscribe / ping freely — so [`MqttClientDriver`] is a
//! flat set of "consolidated" callbacks (per the MQTT implementation plan)
//! over just [`MqttClientControl`]; there's no separate `Endpoint`
//! parameter because `MqttClientControl` already covers everything a
//! driver legitimately needs to do (publish, subscribe, unsubscribe,
//! disconnect).

use crate::codec::{Properties, QoS, SubscribeFilter};

/// Creates the connection driver for each new MQTT client connection.
pub trait MqttClientHandlerFactory: Send + Sync {
    /// Produce a fresh driver for one connection.
    fn create(&self) -> Box<dyn MqttClientDriver>;
}

/// Actions available to a connected client — implemented by
/// [`super::endpoint::MqttClientEndpoint`] and passed to driver callbacks.
pub trait MqttClientControl {
    /// Publish a message. Returns the packet id used (0 for QoS 0, which
    /// has no acknowledgment).
    fn publish(&mut self, topic: &str, payload: &[u8], qos: QoS, retain: bool, properties: &Properties) -> u16;

    /// Subscribe to one or more topic filters in a single SUBSCRIBE packet.
    /// Returns the packet id (correlates with [`MqttClientDriver::on_suback`]).
    fn subscribe(&mut self, filters: &[SubscribeFilter]) -> u16;

    /// Unsubscribe from one or more topic filters in a single UNSUBSCRIBE
    /// packet. Returns the packet id (correlates with
    /// [`MqttClientDriver::on_unsuback`]).
    fn unsubscribe(&mut self, topic_filters: &[String]) -> u16;

    /// Send an AUTH packet (MQTT 5.0 enhanced authentication).
    fn auth(&mut self, reason_code: u8, properties: &Properties);

    /// Send DISCONNECT and close gracefully (no Will Message published).
    fn disconnect(&mut self, reason_code: u8);
}

/// Receives all MQTT protocol callbacks for a single client connection.
///
/// One driver instance lives for the lifetime of one connection. QoS 1/2
/// acknowledgment of *incoming* messages (PUBACK / PUBREC-then-PUBREL) and
/// the PUBREC→PUBREL leg of the client's *own* QoS 2 publishes are handled
/// automatically by the endpoint — the driver only sees the final outcome
/// ([`on_message_complete`](Self::on_message_complete) /
/// [`on_publish_acked`](Self::on_publish_acked)).
pub trait MqttClientDriver: Send {
    /// CONNACK received. `reason_code` is 0 (Success/Accepted) on success;
    /// any other value means the broker refused the connection and the
    /// endpoint will close right after this call.
    fn on_connack(&mut self, client: &mut dyn MqttClientControl, session_present: bool, reason_code: u8, properties: &Properties);

    /// An incoming PUBLISH is starting; `on_message_data` follows for
    /// `payload_len` bytes total (zero or more calls), then
    /// `on_message_complete`. Payload is never buffered in full by the
    /// endpoint — see `codec::parser::MqttFrameParser`.
    fn on_message_start(&mut self, topic: &str, qos: QoS, retain: bool, packet_id: u16, properties: &Properties, payload_len: u32);

    /// A chunk of the current incoming message's payload (zero-copy view,
    /// valid for this call only).
    fn on_message_data(&mut self, data: &[u8]);

    /// The current incoming message is complete (any required PUBACK /
    /// PUBREC has already been sent by the endpoint).
    fn on_message_complete(&mut self, client: &mut dyn MqttClientControl);

    /// SUBACK received for a prior [`MqttClientControl::subscribe`].
    fn on_suback(&mut self, client: &mut dyn MqttClientControl, packet_id: u16, reason_codes: &[u8]);

    /// UNSUBACK received for a prior [`MqttClientControl::unsubscribe`].
    fn on_unsuback(&mut self, client: &mut dyn MqttClientControl, packet_id: u16, reason_codes: &[u8]);

    /// A QoS 1 or QoS 2 publish the client sent completed (PUBACK, or
    /// PUBCOMP at the end of the QoS 2 handshake).
    fn on_publish_acked(&mut self, client: &mut dyn MqttClientControl, packet_id: u16);

    /// PINGRESP received (keepalive round-trip confirmed).
    fn on_ping_resp(&mut self, client: &mut dyn MqttClientControl);

    /// The broker sent a server-initiated DISCONNECT (MQTT 5.0).
    fn on_server_disconnect(&mut self, reason_code: u8, properties: &Properties);

    /// Enhanced AUTH challenge / continuation (MQTT 5.0 §4.12). Default is
    /// a no-op — override to continue the exchange via
    /// [`MqttClientControl::auth`].
    fn on_auth(&mut self, _client: &mut dyn MqttClientControl, _reason_code: u8, _properties: &Properties) {}

    /// Unrecoverable I/O or protocol error (including CONNACK / PINGRESP
    /// timeouts, surfaced with [`std::io::ErrorKind::TimedOut`]).
    fn on_error(&mut self, err: &std::io::Error);

    /// Connection closed by peer or after `disconnect()`.
    fn on_disconnected(&mut self);
}
