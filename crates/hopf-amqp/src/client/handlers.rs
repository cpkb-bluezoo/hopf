// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! AMQP client handler factory and driver traits.

use crate::codec::{BasicProperties, FieldTable};

/// Creates the connection driver for each new AMQP client connection.
pub trait AmqpClientHandlerFactory: Send + Sync {
    /// Produce a fresh driver for one connection.
    fn create(&self) -> Box<dyn AmqpClientDriver>;
}

/// Actions available to a connected client — implemented by
/// [`super::endpoint::AmqpClientEndpoint`] and passed to driver callbacks.
pub trait AmqpClientControl {
    /// Open a channel (`channel_id` must be ≥ 1 and ≤ negotiated channel_max).
    fn channel_open(&mut self, channel_id: u16);

    /// Close a channel.
    fn channel_close(&mut self, channel_id: u16, reply_code: u16, reply_text: &str);

    /// Declare an exchange.
    #[allow(clippy::too_many_arguments)]
    fn exchange_declare(
        &mut self,
        channel: u16,
        exchange: &str,
        exchange_type: &str,
        passive: bool,
        durable: bool,
        auto_delete: bool,
        internal: bool,
        arguments: &FieldTable,
    );

    /// Delete an exchange.
    fn exchange_delete(&mut self, channel: u16, exchange: &str, if_unused: bool);

    /// Declare a queue.
    #[allow(clippy::too_many_arguments)]
    fn queue_declare(
        &mut self,
        channel: u16,
        queue: &str,
        passive: bool,
        durable: bool,
        exclusive: bool,
        auto_delete: bool,
        arguments: &FieldTable,
    );

    /// Bind a queue to an exchange.
    fn queue_bind(
        &mut self,
        channel: u16,
        queue: &str,
        exchange: &str,
        routing_key: &str,
        arguments: &FieldTable,
    );

    /// Unbind a queue from an exchange.
    fn queue_unbind(
        &mut self,
        channel: u16,
        queue: &str,
        exchange: &str,
        routing_key: &str,
        arguments: &FieldTable,
    );

    /// Purge a queue.
    fn queue_purge(&mut self, channel: u16, queue: &str);

    /// Delete a queue.
    fn queue_delete(&mut self, channel: u16, queue: &str, if_unused: bool, if_empty: bool);

    /// Enable publisher confirms on a channel.
    fn confirm_select(&mut self, channel: u16);

    /// Publish a message (opaque body + basic properties).
    #[allow(clippy::too_many_arguments)]
    fn basic_publish(
        &mut self,
        channel: u16,
        exchange: &str,
        routing_key: &str,
        mandatory: bool,
        immediate: bool,
        properties: &BasicProperties,
        body: &[u8],
    );

    /// Start a streaming publish: sends `basic.publish` plus the content
    /// header declaring `body_len` bytes to follow. Feed the body via one
    /// or more [`Self::basic_publish_body`] calls whose chunk lengths sum
    /// to exactly `body_len` (a mismatch produces a malformed message the
    /// broker will reject) — this is the streaming counterpart to
    /// [`Self::basic_publish`] for large bodies the caller doesn't want to
    /// materialize as one contiguous buffer (e.g. reading a large file in
    /// fixed-size chunks).
    #[allow(clippy::too_many_arguments)]
    fn basic_publish_start(
        &mut self,
        channel: u16,
        exchange: &str,
        routing_key: &str,
        mandatory: bool,
        immediate: bool,
        properties: &BasicProperties,
        body_len: u64,
    );

    /// Feed the next chunk of a streaming publish started with
    /// [`Self::basic_publish_start`]. `chunk` is split into wire frames at
    /// the negotiated frame size automatically — it doesn't need to align
    /// with any particular boundary. An empty `chunk` is a harmless no-op.
    fn basic_publish_body(&mut self, channel: u16, chunk: &[u8]);

    /// Set QoS / prefetch.
    fn basic_qos(&mut self, channel: u16, prefetch_size: u32, prefetch_count: u16, global: bool);

    /// Start a consumer (`basic.consume`). Empty `consumer_tag` lets the server assign one.
    #[allow(clippy::too_many_arguments)]
    fn basic_consume(
        &mut self,
        channel: u16,
        queue: &str,
        consumer_tag: &str,
        no_local: bool,
        no_ack: bool,
        exclusive: bool,
        arguments: &FieldTable,
    );

    /// Cancel a consumer.
    fn basic_cancel(&mut self, channel: u16, consumer_tag: &str);

    /// Acknowledge a delivery.
    fn basic_ack(&mut self, channel: u16, delivery_tag: u64, multiple: bool);

    /// Negative-acknowledge a delivery (RabbitMQ extension).
    fn basic_nack(&mut self, channel: u16, delivery_tag: u64, multiple: bool, requeue: bool);

    /// Reject a delivery.
    fn basic_reject(&mut self, channel: u16, delivery_tag: u64, requeue: bool);

    /// Poll-fetch a single message (`basic.get`), as an alternative to a
    /// push `basic.consume` subscription.
    fn basic_get(&mut self, channel: u16, queue: &str, no_ack: bool);

    /// Ask the broker to redeliver all unacknowledged messages on this
    /// channel (`basic.recover`).
    fn basic_recover(&mut self, channel: u16, requeue: bool);

    /// Pause (`active = false`) or resume (`active = true`) delivery on a
    /// channel (`channel.flow`, client-initiated).
    ///
    /// Mainstream RabbitMQ does not implement the client-initiated
    /// `active = false` direction: it rejects the request with a hard
    /// connection-level exception (reply-code 540, `NOT_IMPLEMENTED`) and
    /// closes the connection rather than replying `flow-ok` — surfaced
    /// promptly via [`AmqpClientDriver::on_connection_close`]. Don't wait
    /// on a `flow-ok` after calling this against a real broker; check for
    /// `on_connection_close`/`on_error` too.
    fn flow(&mut self, channel: u16, active: bool);

    /// Select transaction mode for a channel (`tx.select`).
    fn tx_select(&mut self, channel: u16);

    /// Commit the current transaction (`tx.commit`).
    fn tx_commit(&mut self, channel: u16);

    /// Roll back the current transaction (`tx.rollback`).
    fn tx_rollback(&mut self, channel: u16);

    /// Close the connection gracefully.
    fn connection_close(&mut self, reply_code: u16, reply_text: &str);
}

/// Receives all AMQP protocol callbacks for a single client connection.
pub trait AmqpClientDriver: Send {
    /// Connection is open (`connection.open-ok`). Open channels from here.
    fn on_connection_open(&mut self, client: &mut dyn AmqpClientControl);

    /// Channel opened.
    fn on_channel_open(&mut self, client: &mut dyn AmqpClientControl, channel: u16);

    /// Channel closed by peer or after `channel_close`.
    fn on_channel_close(
        &mut self,
        client: &mut dyn AmqpClientControl,
        channel: u16,
        reply_code: u16,
        reply_text: &str,
    );

    /// `exchange.declare-ok`.
    fn on_exchange_declare_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16);

    /// `exchange.delete-ok`.
    fn on_exchange_delete_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        let _ = (client, channel);
    }

    /// `queue.declare-ok`.
    fn on_queue_declare_ok(
        &mut self,
        client: &mut dyn AmqpClientControl,
        channel: u16,
        queue: &str,
        message_count: u32,
        consumer_count: u32,
    );

    /// `queue.bind-ok`.
    fn on_queue_bind_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        let _ = (client, channel);
    }

    /// `queue.unbind-ok`.
    fn on_queue_unbind_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        let _ = (client, channel);
    }

    /// `queue.purge-ok`.
    fn on_queue_purge_ok(
        &mut self,
        client: &mut dyn AmqpClientControl,
        channel: u16,
        message_count: u32,
    ) {
        let _ = (client, channel, message_count);
    }

    /// `queue.delete-ok`.
    fn on_queue_delete_ok(
        &mut self,
        client: &mut dyn AmqpClientControl,
        channel: u16,
        message_count: u32,
    ) {
        let _ = (client, channel, message_count);
    }

    /// `confirm.select-ok`.
    fn on_confirm_select_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        let _ = (client, channel);
    }

    /// `basic.qos-ok`.
    fn on_basic_qos_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        let _ = (client, channel);
    }

    /// `basic.consume-ok`.
    fn on_consume_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16, consumer_tag: &str);

    /// `basic.cancel-ok`.
    fn on_cancel_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16, consumer_tag: &str) {
        let _ = (client, channel, consumer_tag);
    }

    /// Incoming delivery starting (payload streamed via `on_delivery_data`).
    #[allow(clippy::too_many_arguments)]
    fn on_delivery_start(
        &mut self,
        channel: u16,
        consumer_tag: &str,
        delivery_tag: u64,
        redelivered: bool,
        exchange: &str,
        routing_key: &str,
        properties: &BasicProperties,
        body_len: u64,
    );

    /// Chunk of the current delivery body on `channel` (valid for this call
    /// only). `channel` disambiguates interleaved deliveries: AMQP 0-9-1
    /// permits the broker to interleave content frames from *different*
    /// channels on one connection, so a driver tracking multiple
    /// concurrent deliveries must not assume chunks arrive contiguously
    /// for a single delivery.
    fn on_delivery_data(&mut self, channel: u16, data: &[u8]);

    /// Current delivery complete.
    fn on_delivery_complete(&mut self, client: &mut dyn AmqpClientControl, channel: u16);

    /// Undeliverable mandatory/immediate publish (`basic.return` + content).
    fn on_return_start(
        &mut self,
        channel: u16,
        reply_code: u16,
        reply_text: &str,
        exchange: &str,
        routing_key: &str,
        properties: &BasicProperties,
        body_len: u64,
    ) {
        let _ = (
            channel,
            reply_code,
            reply_text,
            exchange,
            routing_key,
            properties,
            body_len,
        );
    }

    /// Chunk of a returned message body on `channel` (see [`Self::on_delivery_data`]
    /// on why `channel` matters for interleaved content).
    fn on_return_data(&mut self, _channel: u16, _data: &[u8]) {}

    /// Returned message complete.
    fn on_return_complete(&mut self, _client: &mut dyn AmqpClientControl, _channel: u16) {}

    /// Publisher confirm ack.
    fn on_ack(&mut self, client: &mut dyn AmqpClientControl, channel: u16, delivery_tag: u64, multiple: bool) {
        let _ = (client, channel, delivery_tag, multiple);
    }

    /// Publisher confirm nack.
    fn on_nack(
        &mut self,
        client: &mut dyn AmqpClientControl,
        channel: u16,
        delivery_tag: u64,
        multiple: bool,
        requeue: bool,
    ) {
        let _ = (client, channel, delivery_tag, multiple, requeue);
    }

    /// `basic.get` found a message (`basic.get-ok`). Content follows via the
    /// same [`Self::on_delivery_data`] / [`Self::on_delivery_complete`]
    /// callbacks used for a pushed `basic.deliver`.
    #[allow(clippy::too_many_arguments)]
    fn on_get_ok(
        &mut self,
        client: &mut dyn AmqpClientControl,
        channel: u16,
        delivery_tag: u64,
        redelivered: bool,
        exchange: &str,
        routing_key: &str,
        message_count: u32,
        properties: &BasicProperties,
        body_len: u64,
    ) {
        let _ = (
            client,
            channel,
            delivery_tag,
            redelivered,
            exchange,
            routing_key,
            message_count,
            properties,
            body_len,
        );
    }

    /// `basic.get` found the queue empty (`basic.get-empty`).
    fn on_get_empty(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        let _ = (client, channel);
    }

    /// `basic.recover-ok` — the broker will redeliver unacked messages.
    fn on_recover_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        let _ = (client, channel);
    }

    /// Reply to a client-initiated [`AmqpClientControl::flow`] request.
    fn on_flow_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16, active: bool) {
        let _ = (client, channel, active);
    }

    /// Broker-initiated `channel.flow` — the endpoint always auto-replies
    /// with `flow-ok` (required by the protocol); this callback lets the
    /// driver observe and react (e.g. pause publishing) to the requested
    /// state.
    fn on_flow(&mut self, client: &mut dyn AmqpClientControl, channel: u16, active: bool) {
        let _ = (client, channel, active);
    }

    /// Broker-initiated consumer-cancel-notify (RabbitMQ extension, e.g.
    /// the consumer's queue was deleted). The endpoint auto-replies with
    /// `cancel-ok` unless the broker set `no_wait`.
    fn on_consumer_cancelled(
        &mut self,
        client: &mut dyn AmqpClientControl,
        channel: u16,
        consumer_tag: &str,
    ) {
        let _ = (client, channel, consumer_tag);
    }

    /// `tx.select-ok` — the channel is now in transactional mode.
    fn on_tx_select_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        let _ = (client, channel);
    }

    /// `tx.commit-ok`.
    fn on_tx_commit_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        let _ = (client, channel);
    }

    /// `tx.rollback-ok`.
    fn on_tx_rollback_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        let _ = (client, channel);
    }

    /// RabbitMQ extension: the broker will block/has blocked publishers
    /// (e.g. low on resources). `reason` is broker-supplied free text.
    fn on_connection_blocked(&mut self, reason: &str) {
        let _ = reason;
    }

    /// RabbitMQ extension: a previous [`Self::on_connection_blocked`]
    /// condition has cleared.
    fn on_connection_unblocked(&mut self) {}

    /// Connection closed by peer or after `connection_close`.
    fn on_connection_close(&mut self, reply_code: u16, reply_text: &str) {
        let _ = (reply_code, reply_text);
    }

    /// Unrecoverable I/O or protocol error.
    fn on_error(&mut self, err: &std::io::Error);

    /// Connection closed.
    fn on_disconnected(&mut self);
}
