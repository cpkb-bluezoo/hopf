// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Automatic reconnection with topology/consumer replay, modeled on
//! Gumdrop's `AMQPClientRecovery`.
//!
//! [`AmqpRecoveringClient`] wraps an [`AmqpClient`] and a caller-supplied
//! [`AmqpClientHandlerFactory`]. It reconnects with exponential backoff
//! ([`RecoveryPolicy`]) whenever the connection drops, and transparently
//! redeclares every exchange/queue/binding and re-registers every consumer
//! the caller had set up, in the order it originally issued them, so the
//! application doesn't have to redo that choreography on every reconnect.
//! [`RecoveryListener`] surfaces the reconnect lifecycle.
//!
//! Two behaviors worth calling out explicitly:
//! - [`AmqpClientDriver::on_connection_open`] fires **once**, on the very
//!   first successful connection — that's where the caller does its
//!   one-time declare/consume setup. Reconnects replay that transparently
//!   and are only surfaced via [`RecoveryListener::on_recovered`].
//! - The broker's genuine `*-ok` replies for each replayed item **do**
//!   reach the caller's normal [`AmqpClientDriver`] callbacks again (e.g.
//!   `on_queue_declare_ok` fires once per reconnect, same as on first
//!   connect) — there's no reply-suppression machinery. Driver callbacks
//!   with side effects should be idempotent.
//! - [`AmqpRecoveringHandle::close`] stops future reconnect attempts and
//!   cancels a pending backoff wait, but does **not** forcibly tear down
//!   an already-live connection — `AmqpClientControl` doesn't expose the
//!   raw endpoint handle needed for that. Close a live connection from
//!   within your own driver via [`AmqpClientControl::connection_close`].

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hopf_core::Runtime;

use crate::codec::{BasicProperties, FieldTable};

use super::facade::AmqpClient;
use super::handlers::{AmqpClientControl, AmqpClientDriver, AmqpClientHandlerFactory};

/// Exponential backoff policy for reconnect attempts.
#[derive(Debug, Clone)]
pub struct RecoveryPolicy {
    initial_delay: Duration,
    max_delay: Duration,
    max_attempts: Option<u32>,
}

impl RecoveryPolicy {
    /// Gumdrop's defaults: 1s initial delay, doubling each attempt, capped
    /// at 30s, unlimited attempts.
    pub fn exponential_backoff() -> Self {
        Self {
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(30),
            max_attempts: None,
        }
    }

    /// Delay before the first reconnect attempt (default 1s).
    pub fn with_initial_delay(mut self, delay: Duration) -> Self {
        self.initial_delay = delay;
        self
    }

    /// Cap on the backoff delay (default 30s).
    pub fn with_max_delay(mut self, delay: Duration) -> Self {
        self.max_delay = delay;
        self
    }

    /// Stop after `attempts` consecutive failed attempts (default:
    /// unlimited — see [`Self::unlimited_attempts`] to restore that after
    /// calling this).
    pub fn with_max_attempts(mut self, attempts: u32) -> Self {
        self.max_attempts = Some(attempts);
        self
    }

    /// Never give up reconnecting (the default).
    pub fn unlimited_attempts(mut self) -> Self {
        self.max_attempts = None;
        self
    }

    /// Delay before reconnect attempt number `attempt` (1-indexed):
    /// `min(initial_delay * 2^(attempt-1), max_delay)`.
    fn delay_for_attempt(&self, attempt: u32) -> Duration {
        let shift = attempt.saturating_sub(1).min(32);
        let multiplier = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
        let millis = self.initial_delay.as_millis() as u64;
        let scaled = millis.saturating_mul(multiplier);
        let capped = scaled.min(self.max_delay.as_millis() as u64);
        Duration::from_millis(capped)
    }
}

impl Default for RecoveryPolicy {
    fn default() -> Self {
        Self::exponential_backoff()
    }
}

/// Reconnect lifecycle events. All methods default to no-ops.
pub trait RecoveryListener: Send + Sync {
    /// The connection was lost (broker restart, network blip, ...).
    /// `cause` is the most recent error message, if any was reported.
    fn on_connection_lost(&self, cause: &str) {
        let _ = cause;
    }

    /// About to sleep `delay` before reconnect attempt number `attempt`
    /// (1-indexed).
    fn on_reconnecting(&self, attempt: u32, delay: Duration) {
        let _ = (attempt, delay);
    }

    /// Reconnected and finished replaying topology/consumers.
    fn on_recovered(&self) {}

    /// Gave up after [`RecoveryPolicy`]'s `max_attempts` was reached.
    fn on_recovery_failed(&self, cause: &str) {
        let _ = cause;
    }
}

// ---------------------------------------------------------------------
// Topology tracking
// ---------------------------------------------------------------------

#[derive(Debug, Clone)]
struct ExchangeDeclare {
    exchange: String,
    exchange_type: String,
    passive: bool,
    durable: bool,
    auto_delete: bool,
    internal: bool,
    arguments: FieldTable,
}

#[derive(Debug, Clone)]
struct QueueDeclare {
    queue: String,
    passive: bool,
    durable: bool,
    exclusive: bool,
    auto_delete: bool,
    arguments: FieldTable,
}

#[derive(Debug, Clone)]
struct QueueBind {
    queue: String,
    exchange: String,
    routing_key: String,
    arguments: FieldTable,
}

#[derive(Debug, Clone)]
struct BasicConsume {
    queue: String,
    consumer_tag: String,
    no_local: bool,
    no_ack: bool,
    exclusive: bool,
    arguments: FieldTable,
}

#[derive(Debug, Clone, Default)]
struct ChannelTopology {
    exchanges: Vec<ExchangeDeclare>,
    queues: Vec<QueueDeclare>,
    bindings: Vec<QueueBind>,
    consumers: Vec<BasicConsume>,
}

/// Declared exchanges/queues/bindings/consumers, per channel, in original
/// declare order — replayed transparently after a reconnect.
#[derive(Debug, Clone, Default)]
struct Topology {
    channels: HashMap<u16, ChannelTopology>,
}

impl Topology {
    fn open_channel(&mut self, channel: u16) {
        self.channels.entry(channel).or_default();
    }

    fn close_channel(&mut self, channel: u16) {
        self.channels.remove(&channel);
    }

    fn declare_exchange(
        &mut self,
        channel: u16,
        exchange: &str,
        exchange_type: &str,
        passive: bool,
        durable: bool,
        auto_delete: bool,
        internal: bool,
        arguments: &FieldTable,
    ) {
        self.channels.entry(channel).or_default().exchanges.push(ExchangeDeclare {
            exchange: exchange.to_owned(),
            exchange_type: exchange_type.to_owned(),
            passive,
            durable,
            auto_delete,
            internal,
            arguments: arguments.clone(),
        });
    }

    /// Exchange deletion is broker-global; the delete request itself may
    /// arrive on any channel, so search all of them.
    fn delete_exchange(&mut self, exchange: &str) {
        for ch in self.channels.values_mut() {
            ch.exchanges.retain(|e| e.exchange != exchange);
        }
    }

    fn declare_queue(
        &mut self,
        channel: u16,
        queue: &str,
        passive: bool,
        durable: bool,
        exclusive: bool,
        auto_delete: bool,
        arguments: &FieldTable,
    ) {
        self.channels.entry(channel).or_default().queues.push(QueueDeclare {
            queue: queue.to_owned(),
            passive,
            durable,
            exclusive,
            auto_delete,
            arguments: arguments.clone(),
        });
    }

    /// Queue deletion also drops any binding/consumer still referencing
    /// it, so replay never tries to bind/consume a queue that's gone.
    fn delete_queue(&mut self, queue: &str) {
        for ch in self.channels.values_mut() {
            ch.queues.retain(|q| q.queue != queue);
            ch.bindings.retain(|b| b.queue != queue);
            ch.consumers.retain(|c| c.queue != queue);
        }
    }

    fn bind_queue(
        &mut self,
        channel: u16,
        queue: &str,
        exchange: &str,
        routing_key: &str,
        arguments: &FieldTable,
    ) {
        self.channels.entry(channel).or_default().bindings.push(QueueBind {
            queue: queue.to_owned(),
            exchange: exchange.to_owned(),
            routing_key: routing_key.to_owned(),
            arguments: arguments.clone(),
        });
    }

    /// An unbind isn't guaranteed to arrive on the same channel the bind
    /// did, so search all of them for the first matching triple.
    fn unbind_queue(&mut self, queue: &str, exchange: &str, routing_key: &str) {
        for ch in self.channels.values_mut() {
            if let Some(pos) = ch.bindings.iter().position(|b| {
                b.queue == queue && b.exchange == exchange && b.routing_key == routing_key
            }) {
                ch.bindings.remove(pos);
                return;
            }
        }
    }

    fn consume(
        &mut self,
        channel: u16,
        queue: &str,
        consumer_tag: &str,
        no_local: bool,
        no_ack: bool,
        exclusive: bool,
        arguments: &FieldTable,
    ) {
        self.channels.entry(channel).or_default().consumers.push(BasicConsume {
            queue: queue.to_owned(),
            consumer_tag: consumer_tag.to_owned(),
            no_local,
            no_ack,
            exclusive,
            arguments: arguments.clone(),
        });
    }

    /// A cancel isn't guaranteed to arrive on the same channel the consume
    /// did, so search all of them.
    fn cancel(&mut self, consumer_tag: &str) {
        for ch in self.channels.values_mut() {
            if let Some(pos) = ch.consumers.iter().position(|c| c.consumer_tag == consumer_tag) {
                ch.consumers.remove(pos);
                return;
            }
        }
    }

    /// Re-issue every recorded entry against `client` (the *raw* control,
    /// not a [`TrackingControl`], so replay doesn't re-record itself) in
    /// channel-open → exchanges → queues → bindings → consumers order —
    /// safe to pipeline without waiting for individual `-ok`s, since AMQP
    /// method delivery is strictly ordered per channel and replay never
    /// depends on a broker-assigned name (it resends the original request
    /// verbatim, including an empty/auto-generated `consumer_tag`).
    fn replay(&self, client: &mut dyn AmqpClientControl) {
        let mut channels: Vec<_> = self.channels.keys().copied().collect();
        channels.sort_unstable();
        for channel in channels {
            let Some(ch) = self.channels.get(&channel) else {
                continue;
            };
            client.channel_open(channel);
            for e in &ch.exchanges {
                client.exchange_declare(
                    channel,
                    &e.exchange,
                    &e.exchange_type,
                    e.passive,
                    e.durable,
                    e.auto_delete,
                    e.internal,
                    &e.arguments,
                );
            }
            for q in &ch.queues {
                client.queue_declare(
                    channel, &q.queue, q.passive, q.durable, q.exclusive, q.auto_delete,
                    &q.arguments,
                );
            }
            for b in &ch.bindings {
                client.queue_bind(channel, &b.queue, &b.exchange, &b.routing_key, &b.arguments);
            }
            for c in &ch.consumers {
                client.basic_consume(
                    channel, &c.queue, &c.consumer_tag, c.no_local, c.no_ack, c.exclusive,
                    &c.arguments,
                );
            }
        }
    }
}

// ---------------------------------------------------------------------
// TrackingControl — records topology mutations as the caller makes them
// ---------------------------------------------------------------------

struct TrackingControl<'a> {
    inner: &'a mut dyn AmqpClientControl,
    topology: &'a Arc<Mutex<Topology>>,
}

impl AmqpClientControl for TrackingControl<'_> {
    fn channel_open(&mut self, channel_id: u16) {
        self.topology.lock().unwrap().open_channel(channel_id);
        self.inner.channel_open(channel_id);
    }

    fn channel_close(&mut self, channel_id: u16, reply_code: u16, reply_text: &str) {
        self.topology.lock().unwrap().close_channel(channel_id);
        self.inner.channel_close(channel_id, reply_code, reply_text);
    }

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
    ) {
        self.topology.lock().unwrap().declare_exchange(
            channel, exchange, exchange_type, passive, durable, auto_delete, internal, arguments,
        );
        self.inner.exchange_declare(
            channel, exchange, exchange_type, passive, durable, auto_delete, internal, arguments,
        );
    }

    fn exchange_delete(&mut self, channel: u16, exchange: &str, if_unused: bool) {
        self.topology.lock().unwrap().delete_exchange(exchange);
        self.inner.exchange_delete(channel, exchange, if_unused);
    }

    fn queue_declare(
        &mut self,
        channel: u16,
        queue: &str,
        passive: bool,
        durable: bool,
        exclusive: bool,
        auto_delete: bool,
        arguments: &FieldTable,
    ) {
        self.topology
            .lock()
            .unwrap()
            .declare_queue(channel, queue, passive, durable, exclusive, auto_delete, arguments);
        self.inner
            .queue_declare(channel, queue, passive, durable, exclusive, auto_delete, arguments);
    }

    fn queue_bind(
        &mut self,
        channel: u16,
        queue: &str,
        exchange: &str,
        routing_key: &str,
        arguments: &FieldTable,
    ) {
        self.topology
            .lock()
            .unwrap()
            .bind_queue(channel, queue, exchange, routing_key, arguments);
        self.inner.queue_bind(channel, queue, exchange, routing_key, arguments);
    }

    fn queue_unbind(
        &mut self,
        channel: u16,
        queue: &str,
        exchange: &str,
        routing_key: &str,
        arguments: &FieldTable,
    ) {
        self.topology.lock().unwrap().unbind_queue(queue, exchange, routing_key);
        self.inner.queue_unbind(channel, queue, exchange, routing_key, arguments);
    }

    fn queue_purge(&mut self, channel: u16, queue: &str) {
        self.inner.queue_purge(channel, queue);
    }

    fn queue_delete(&mut self, channel: u16, queue: &str, if_unused: bool, if_empty: bool) {
        self.topology.lock().unwrap().delete_queue(queue);
        self.inner.queue_delete(channel, queue, if_unused, if_empty);
    }

    fn confirm_select(&mut self, channel: u16) {
        self.inner.confirm_select(channel);
    }

    fn basic_publish(
        &mut self,
        channel: u16,
        exchange: &str,
        routing_key: &str,
        mandatory: bool,
        immediate: bool,
        properties: &BasicProperties,
        body: &[u8],
    ) {
        self.inner
            .basic_publish(channel, exchange, routing_key, mandatory, immediate, properties, body);
    }

    fn basic_publish_start(
        &mut self,
        channel: u16,
        exchange: &str,
        routing_key: &str,
        mandatory: bool,
        immediate: bool,
        properties: &BasicProperties,
        body_len: u64,
    ) {
        self.inner.basic_publish_start(
            channel, exchange, routing_key, mandatory, immediate, properties, body_len,
        );
    }

    fn basic_publish_body(&mut self, channel: u16, chunk: &[u8]) {
        self.inner.basic_publish_body(channel, chunk);
    }

    fn basic_qos(&mut self, channel: u16, prefetch_size: u32, prefetch_count: u16, global: bool) {
        self.inner.basic_qos(channel, prefetch_size, prefetch_count, global);
    }

    fn basic_consume(
        &mut self,
        channel: u16,
        queue: &str,
        consumer_tag: &str,
        no_local: bool,
        no_ack: bool,
        exclusive: bool,
        arguments: &FieldTable,
    ) {
        self.topology.lock().unwrap().consume(
            channel, queue, consumer_tag, no_local, no_ack, exclusive, arguments,
        );
        self.inner
            .basic_consume(channel, queue, consumer_tag, no_local, no_ack, exclusive, arguments);
    }

    fn basic_cancel(&mut self, channel: u16, consumer_tag: &str) {
        self.topology.lock().unwrap().cancel(consumer_tag);
        self.inner.basic_cancel(channel, consumer_tag);
    }

    fn basic_ack(&mut self, channel: u16, delivery_tag: u64, multiple: bool) {
        self.inner.basic_ack(channel, delivery_tag, multiple);
    }

    fn basic_nack(&mut self, channel: u16, delivery_tag: u64, multiple: bool, requeue: bool) {
        self.inner.basic_nack(channel, delivery_tag, multiple, requeue);
    }

    fn basic_reject(&mut self, channel: u16, delivery_tag: u64, requeue: bool) {
        self.inner.basic_reject(channel, delivery_tag, requeue);
    }

    fn basic_get(&mut self, channel: u16, queue: &str, no_ack: bool) {
        self.inner.basic_get(channel, queue, no_ack);
    }

    fn basic_recover(&mut self, channel: u16, requeue: bool) {
        self.inner.basic_recover(channel, requeue);
    }

    fn flow(&mut self, channel: u16, active: bool) {
        self.inner.flow(channel, active);
    }

    fn tx_select(&mut self, channel: u16) {
        self.inner.tx_select(channel);
    }

    fn tx_commit(&mut self, channel: u16) {
        self.inner.tx_commit(channel);
    }

    fn tx_rollback(&mut self, channel: u16) {
        self.inner.tx_rollback(channel);
    }

    fn connection_close(&mut self, reply_code: u16, reply_text: &str) {
        self.inner.connection_close(reply_code, reply_text);
    }
}

// ---------------------------------------------------------------------
// RecoveringDriver — wraps the caller's driver, orchestrates replay/reconnect
// ---------------------------------------------------------------------

/// Cross-reconnect state shared by every [`RecoveringDriver`] instance
/// [`RecoveringHandlerFactory::create`] produces (a new `RecoveringDriver`
/// is built per physical connection, but this state persists across all of
/// them for one [`AmqpRecoveringClient::connect`] call).
struct SharedState {
    user_driver: Arc<Mutex<Option<Box<dyn AmqpClientDriver>>>>,
    topology: Arc<Mutex<Topology>>,
    ever_connected: Arc<AtomicBool>,
    attempt: Arc<AtomicU32>,
    last_error: Arc<Mutex<Option<String>>>,
    closing: Arc<AtomicBool>,
    backoff_cancel: Arc<Mutex<Option<Arc<AtomicBool>>>>,
    reconnect_trigger: Arc<Mutex<Option<Arc<dyn Fn() + Send + Sync>>>>,
    rt: Arc<Runtime>,
    policy: RecoveryPolicy,
    listener: Option<Arc<dyn RecoveryListener>>,
}

impl SharedState {
    fn with_user_driver<R>(&self, f: impl FnOnce(&mut dyn AmqpClientDriver) -> R) -> R {
        let mut guard = self.user_driver.lock().unwrap();
        let driver = guard.as_deref_mut().expect("user driver initialized by create()");
        f(driver)
    }

    fn schedule_reconnect(&self) {
        if self.closing.load(Ordering::Acquire) {
            return;
        }
        let attempt = self.attempt.fetch_add(1, Ordering::AcqRel) + 1;
        if let Some(max) = self.policy.max_attempts {
            if attempt > max {
                let cause = self
                    .last_error
                    .lock()
                    .unwrap()
                    .clone()
                    .unwrap_or_else(|| "connection lost".to_owned());
                if let Some(l) = &self.listener {
                    l.on_recovery_failed(&cause);
                }
                return;
            }
        }
        let delay = self.policy.delay_for_attempt(attempt);
        if let Some(l) = &self.listener {
            l.on_reconnecting(attempt, delay);
        }
        let trigger = self.reconnect_trigger.lock().unwrap().clone();
        let Some(trigger) = trigger else {
            return;
        };
        let cancel = self.rt.pick_worker().schedule_timer(
            delay,
            Box::new(move || {
                trigger();
            }),
        );
        *self.backoff_cancel.lock().unwrap() = Some(cancel);
    }
}

struct RecoveringDriver {
    shared: SharedState,
}

impl AmqpClientDriver for RecoveringDriver {
    fn on_connection_open(&mut self, client: &mut dyn AmqpClientControl) {
        let first_connect = !self.shared.ever_connected.swap(true, Ordering::AcqRel);
        self.shared.attempt.store(0, Ordering::Release);
        *self.shared.backoff_cancel.lock().unwrap() = None;
        if first_connect {
            let mut tracked = TrackingControl { inner: client, topology: &self.shared.topology };
            self.shared.with_user_driver(|d| d.on_connection_open(&mut tracked));
        } else {
            self.shared.topology.lock().unwrap().replay(client);
            if let Some(l) = &self.shared.listener {
                l.on_recovered();
            }
        }
    }

    fn on_channel_open(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        let mut tracked = TrackingControl { inner: client, topology: &self.shared.topology };
        self.shared.with_user_driver(|d| d.on_channel_open(&mut tracked, channel));
    }

    fn on_channel_close(
        &mut self,
        client: &mut dyn AmqpClientControl,
        channel: u16,
        reply_code: u16,
        reply_text: &str,
    ) {
        let mut tracked = TrackingControl { inner: client, topology: &self.shared.topology };
        self.shared
            .with_user_driver(|d| d.on_channel_close(&mut tracked, channel, reply_code, reply_text));
    }

    fn on_exchange_declare_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        let mut tracked = TrackingControl { inner: client, topology: &self.shared.topology };
        self.shared.with_user_driver(|d| d.on_exchange_declare_ok(&mut tracked, channel));
    }

    fn on_exchange_delete_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        let mut tracked = TrackingControl { inner: client, topology: &self.shared.topology };
        self.shared.with_user_driver(|d| d.on_exchange_delete_ok(&mut tracked, channel));
    }

    fn on_queue_declare_ok(
        &mut self,
        client: &mut dyn AmqpClientControl,
        channel: u16,
        queue: &str,
        message_count: u32,
        consumer_count: u32,
    ) {
        let mut tracked = TrackingControl { inner: client, topology: &self.shared.topology };
        self.shared.with_user_driver(|d| {
            d.on_queue_declare_ok(&mut tracked, channel, queue, message_count, consumer_count)
        });
    }

    fn on_queue_bind_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        let mut tracked = TrackingControl { inner: client, topology: &self.shared.topology };
        self.shared.with_user_driver(|d| d.on_queue_bind_ok(&mut tracked, channel));
    }

    fn on_queue_unbind_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        let mut tracked = TrackingControl { inner: client, topology: &self.shared.topology };
        self.shared.with_user_driver(|d| d.on_queue_unbind_ok(&mut tracked, channel));
    }

    fn on_queue_purge_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16, message_count: u32) {
        let mut tracked = TrackingControl { inner: client, topology: &self.shared.topology };
        self.shared.with_user_driver(|d| d.on_queue_purge_ok(&mut tracked, channel, message_count));
    }

    fn on_queue_delete_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16, message_count: u32) {
        let mut tracked = TrackingControl { inner: client, topology: &self.shared.topology };
        self.shared.with_user_driver(|d| d.on_queue_delete_ok(&mut tracked, channel, message_count));
    }

    fn on_confirm_select_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        let mut tracked = TrackingControl { inner: client, topology: &self.shared.topology };
        self.shared.with_user_driver(|d| d.on_confirm_select_ok(&mut tracked, channel));
    }

    fn on_basic_qos_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        let mut tracked = TrackingControl { inner: client, topology: &self.shared.topology };
        self.shared.with_user_driver(|d| d.on_basic_qos_ok(&mut tracked, channel));
    }

    fn on_consume_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16, consumer_tag: &str) {
        let mut tracked = TrackingControl { inner: client, topology: &self.shared.topology };
        self.shared.with_user_driver(|d| d.on_consume_ok(&mut tracked, channel, consumer_tag));
    }

    fn on_cancel_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16, consumer_tag: &str) {
        let mut tracked = TrackingControl { inner: client, topology: &self.shared.topology };
        self.shared.with_user_driver(|d| d.on_cancel_ok(&mut tracked, channel, consumer_tag));
    }

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
    ) {
        self.shared.with_user_driver(|d| {
            d.on_delivery_start(
                channel, consumer_tag, delivery_tag, redelivered, exchange, routing_key,
                properties, body_len,
            )
        });
    }

    fn on_delivery_data(&mut self, data: &[u8]) {
        self.shared.with_user_driver(|d| d.on_delivery_data(data));
    }

    fn on_delivery_complete(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        let mut tracked = TrackingControl { inner: client, topology: &self.shared.topology };
        self.shared.with_user_driver(|d| d.on_delivery_complete(&mut tracked, channel));
    }

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
        self.shared.with_user_driver(|d| {
            d.on_return_start(channel, reply_code, reply_text, exchange, routing_key, properties, body_len)
        });
    }

    fn on_return_data(&mut self, data: &[u8]) {
        self.shared.with_user_driver(|d| d.on_return_data(data));
    }

    fn on_return_complete(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        let mut tracked = TrackingControl { inner: client, topology: &self.shared.topology };
        self.shared.with_user_driver(|d| d.on_return_complete(&mut tracked, channel));
    }

    fn on_ack(&mut self, client: &mut dyn AmqpClientControl, channel: u16, delivery_tag: u64, multiple: bool) {
        let mut tracked = TrackingControl { inner: client, topology: &self.shared.topology };
        self.shared.with_user_driver(|d| d.on_ack(&mut tracked, channel, delivery_tag, multiple));
    }

    fn on_nack(
        &mut self,
        client: &mut dyn AmqpClientControl,
        channel: u16,
        delivery_tag: u64,
        multiple: bool,
        requeue: bool,
    ) {
        let mut tracked = TrackingControl { inner: client, topology: &self.shared.topology };
        self.shared
            .with_user_driver(|d| d.on_nack(&mut tracked, channel, delivery_tag, multiple, requeue));
    }

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
        let mut tracked = TrackingControl { inner: client, topology: &self.shared.topology };
        self.shared.with_user_driver(|d| {
            d.on_get_ok(
                &mut tracked, channel, delivery_tag, redelivered, exchange, routing_key,
                message_count, properties, body_len,
            )
        });
    }

    fn on_get_empty(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        let mut tracked = TrackingControl { inner: client, topology: &self.shared.topology };
        self.shared.with_user_driver(|d| d.on_get_empty(&mut tracked, channel));
    }

    fn on_recover_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        let mut tracked = TrackingControl { inner: client, topology: &self.shared.topology };
        self.shared.with_user_driver(|d| d.on_recover_ok(&mut tracked, channel));
    }

    fn on_flow_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16, active: bool) {
        let mut tracked = TrackingControl { inner: client, topology: &self.shared.topology };
        self.shared.with_user_driver(|d| d.on_flow_ok(&mut tracked, channel, active));
    }

    fn on_flow(&mut self, client: &mut dyn AmqpClientControl, channel: u16, active: bool) {
        let mut tracked = TrackingControl { inner: client, topology: &self.shared.topology };
        self.shared.with_user_driver(|d| d.on_flow(&mut tracked, channel, active));
    }

    fn on_consumer_cancelled(&mut self, client: &mut dyn AmqpClientControl, channel: u16, consumer_tag: &str) {
        let mut tracked = TrackingControl { inner: client, topology: &self.shared.topology };
        self.shared
            .with_user_driver(|d| d.on_consumer_cancelled(&mut tracked, channel, consumer_tag));
    }

    fn on_tx_select_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        let mut tracked = TrackingControl { inner: client, topology: &self.shared.topology };
        self.shared.with_user_driver(|d| d.on_tx_select_ok(&mut tracked, channel));
    }

    fn on_tx_commit_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        let mut tracked = TrackingControl { inner: client, topology: &self.shared.topology };
        self.shared.with_user_driver(|d| d.on_tx_commit_ok(&mut tracked, channel));
    }

    fn on_tx_rollback_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        let mut tracked = TrackingControl { inner: client, topology: &self.shared.topology };
        self.shared.with_user_driver(|d| d.on_tx_rollback_ok(&mut tracked, channel));
    }

    fn on_connection_blocked(&mut self, reason: &str) {
        self.shared.with_user_driver(|d| d.on_connection_blocked(reason));
    }

    fn on_connection_unblocked(&mut self) {
        self.shared.with_user_driver(|d| d.on_connection_unblocked());
    }

    fn on_connection_close(&mut self, reply_code: u16, reply_text: &str) {
        self.shared.with_user_driver(|d| d.on_connection_close(reply_code, reply_text));
    }

    fn on_error(&mut self, err: &io::Error) {
        *self.shared.last_error.lock().unwrap() = Some(err.to_string());
        self.shared.with_user_driver(|d| d.on_error(err));
    }

    fn on_disconnected(&mut self) {
        self.shared.with_user_driver(|d| d.on_disconnected());
        if !self.shared.closing.load(Ordering::Acquire) {
            let cause = self
                .shared
                .last_error
                .lock()
                .unwrap()
                .clone()
                .unwrap_or_else(|| "connection lost".to_owned());
            if let Some(l) = &self.shared.listener {
                l.on_connection_lost(&cause);
            }
            self.shared.schedule_reconnect();
        }
    }
}

// ---------------------------------------------------------------------
// RecoveringHandlerFactory — builds the (persistent) user driver once
// ---------------------------------------------------------------------

struct RecoveringHandlerFactory {
    user_factory: Arc<dyn AmqpClientHandlerFactory>,
    user_driver: Arc<Mutex<Option<Box<dyn AmqpClientDriver>>>>,
    topology: Arc<Mutex<Topology>>,
    ever_connected: Arc<AtomicBool>,
    attempt: Arc<AtomicU32>,
    last_error: Arc<Mutex<Option<String>>>,
    closing: Arc<AtomicBool>,
    backoff_cancel: Arc<Mutex<Option<Arc<AtomicBool>>>>,
    reconnect_trigger: Arc<Mutex<Option<Arc<dyn Fn() + Send + Sync>>>>,
    rt: Arc<Runtime>,
    policy: RecoveryPolicy,
    listener: Option<Arc<dyn RecoveryListener>>,
}

impl AmqpClientHandlerFactory for RecoveringHandlerFactory {
    fn create(&self) -> Box<dyn AmqpClientDriver> {
        {
            let mut guard = self.user_driver.lock().unwrap();
            if guard.is_none() {
                *guard = Some(self.user_factory.create());
            }
        }
        Box::new(RecoveringDriver {
            shared: SharedState {
                user_driver: Arc::clone(&self.user_driver),
                topology: Arc::clone(&self.topology),
                ever_connected: Arc::clone(&self.ever_connected),
                attempt: Arc::clone(&self.attempt),
                last_error: Arc::clone(&self.last_error),
                closing: Arc::clone(&self.closing),
                backoff_cancel: Arc::clone(&self.backoff_cancel),
                reconnect_trigger: Arc::clone(&self.reconnect_trigger),
                rt: Arc::clone(&self.rt),
                policy: self.policy.clone(),
                listener: self.listener.clone(),
            },
        })
    }
}

// ---------------------------------------------------------------------
// Public facade
// ---------------------------------------------------------------------

/// Wraps an [`AmqpClient`] with automatic reconnection: exponential
/// backoff ([`RecoveryPolicy`]) and transparent topology/consumer replay.
/// See the module docs for the exact reconnect semantics.
pub struct AmqpRecoveringClient {
    client: AmqpClient,
    rt: Arc<Runtime>,
    policy: RecoveryPolicy,
    listener: Option<Arc<dyn RecoveryListener>>,
}

impl AmqpRecoveringClient {
    /// Wrap `client` (configured with host/port/credentials/TLS as usual)
    /// with automatic reconnection, driven by `rt`.
    pub fn new(client: AmqpClient, rt: Arc<Runtime>) -> Self {
        Self { client, rt, policy: RecoveryPolicy::exponential_backoff(), listener: None }
    }

    /// Override the reconnect backoff policy (default:
    /// [`RecoveryPolicy::exponential_backoff`]).
    pub fn recovery_policy(mut self, policy: RecoveryPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Observe reconnect lifecycle events.
    pub fn recovery_listener(mut self, listener: Arc<dyn RecoveryListener>) -> Self {
        self.listener = Some(listener);
        self
    }

    /// Connect, wrapping `factory`'s driver with automatic recovery.
    /// Returns immediately (like [`AmqpClient::connect`]); the returned
    /// handle can later stop further reconnect attempts.
    pub fn connect(self, factory: Arc<dyn AmqpClientHandlerFactory>) -> io::Result<AmqpRecoveringHandle> {
        let closing = Arc::new(AtomicBool::new(false));
        let backoff_cancel = Arc::new(Mutex::new(None));
        let reconnect_trigger: Arc<Mutex<Option<Arc<dyn Fn() + Send + Sync>>>> =
            Arc::new(Mutex::new(None));

        let recovering_factory = Arc::new(RecoveringHandlerFactory {
            user_factory: factory,
            user_driver: Arc::new(Mutex::new(None)),
            topology: Arc::new(Mutex::new(Topology::default())),
            ever_connected: Arc::new(AtomicBool::new(false)),
            attempt: Arc::new(AtomicU32::new(0)),
            last_error: Arc::new(Mutex::new(None)),
            closing: Arc::clone(&closing),
            backoff_cancel: Arc::clone(&backoff_cancel),
            reconnect_trigger: Arc::clone(&reconnect_trigger),
            rt: Arc::clone(&self.rt),
            policy: self.policy.clone(),
            listener: self.listener.clone(),
        });

        // Fill in the reconnect trigger now that `recovering_factory` is
        // behind an `Arc` — every retry just calls `connect()` again with
        // the same factory, so all its shared state carries forward.
        let rt_for_retry = Arc::clone(&self.rt);
        let client_config = self.client.clone();
        let factory_for_retry: Arc<dyn AmqpClientHandlerFactory> = Arc::clone(&recovering_factory) as _;
        *reconnect_trigger.lock().unwrap() = Some(Arc::new(move || {
            let _ = client_config.connect(&rt_for_retry, Arc::clone(&factory_for_retry));
        }));

        let factory_for_connect: Arc<dyn AmqpClientHandlerFactory> = recovering_factory as _;
        self.client.connect(&self.rt, factory_for_connect)?;

        Ok(AmqpRecoveringHandle { closing, backoff_cancel })
    }
}

/// Handle returned by [`AmqpRecoveringClient::connect`].
pub struct AmqpRecoveringHandle {
    closing: Arc<AtomicBool>,
    backoff_cancel: Arc<Mutex<Option<Arc<AtomicBool>>>>,
}

impl AmqpRecoveringHandle {
    /// Stop all future reconnect attempts and cancel a pending backoff
    /// wait, if one is in progress. Does **not** forcibly close an
    /// already-live connection (see the module docs) — close that from
    /// your own driver via [`AmqpClientControl::connection_close`].
    pub fn close(&self) {
        self.closing.store(true, Ordering::Release);
        if let Some(cancel) = self.backoff_cancel.lock().unwrap().take() {
            cancel.store(true, Ordering::Release);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_and_caps() {
        let p = RecoveryPolicy::exponential_backoff();
        assert_eq!(p.delay_for_attempt(1), Duration::from_secs(1));
        assert_eq!(p.delay_for_attempt(2), Duration::from_secs(2));
        assert_eq!(p.delay_for_attempt(3), Duration::from_secs(4));
        assert_eq!(p.delay_for_attempt(4), Duration::from_secs(8));
        assert_eq!(p.delay_for_attempt(5), Duration::from_secs(16));
        assert_eq!(p.delay_for_attempt(6), Duration::from_secs(30)); // 32s capped to 30s
        assert_eq!(p.delay_for_attempt(50), Duration::from_secs(30)); // stays capped
    }

    #[test]
    fn custom_initial_and_cap() {
        let p = RecoveryPolicy::exponential_backoff()
            .with_initial_delay(Duration::from_millis(100))
            .with_max_delay(Duration::from_secs(2));
        assert_eq!(p.delay_for_attempt(1), Duration::from_millis(100));
        assert_eq!(p.delay_for_attempt(2), Duration::from_millis(200));
        assert_eq!(p.delay_for_attempt(5), Duration::from_millis(1600)); // not yet capped
        assert_eq!(p.delay_for_attempt(6), Duration::from_secs(2)); // 3.2s capped to 2s
    }

    #[test]
    fn max_attempts_builder() {
        let p = RecoveryPolicy::exponential_backoff().with_max_attempts(5);
        assert_eq!(p.max_attempts, Some(5));
        let p = p.unlimited_attempts();
        assert_eq!(p.max_attempts, None);
    }

    fn ft() -> FieldTable {
        FieldTable::new()
    }

    #[test]
    fn topology_replay_order_is_exchanges_then_queues_then_bindings_then_consumers() {
        let mut t = Topology::default();
        t.open_channel(1);
        t.declare_queue(1, "q", false, false, false, false, &ft());
        t.declare_exchange(1, "ex", "topic", false, false, false, false, &ft());
        t.bind_queue(1, "q", "ex", "rk", &ft());
        t.consume(1, "q", "ctag", false, false, false, &ft());

        struct Rec(Vec<String>);
        impl AmqpClientControl for Rec {
            fn channel_open(&mut self, channel_id: u16) {
                self.0.push(format!("channel_open({channel_id})"));
            }
            fn channel_close(&mut self, _: u16, _: u16, _: &str) {}
            fn exchange_declare(&mut self, _: u16, exchange: &str, _: &str, _: bool, _: bool, _: bool, _: bool, _: &FieldTable) {
                self.0.push(format!("exchange_declare({exchange})"));
            }
            fn exchange_delete(&mut self, _: u16, _: &str, _: bool) {}
            fn queue_declare(&mut self, _: u16, queue: &str, _: bool, _: bool, _: bool, _: bool, _: &FieldTable) {
                self.0.push(format!("queue_declare({queue})"));
            }
            fn queue_bind(&mut self, _: u16, queue: &str, exchange: &str, _: &str, _: &FieldTable) {
                self.0.push(format!("queue_bind({queue},{exchange})"));
            }
            fn queue_unbind(&mut self, _: u16, _: &str, _: &str, _: &str, _: &FieldTable) {}
            fn queue_purge(&mut self, _: u16, _: &str) {}
            fn queue_delete(&mut self, _: u16, _: &str, _: bool, _: bool) {}
            fn confirm_select(&mut self, _: u16) {}
            fn basic_publish(&mut self, _: u16, _: &str, _: &str, _: bool, _: bool, _: &BasicProperties, _: &[u8]) {}
            fn basic_publish_start(&mut self, _: u16, _: &str, _: &str, _: bool, _: bool, _: &BasicProperties, _: u64) {}
            fn basic_publish_body(&mut self, _: u16, _: &[u8]) {}
            fn basic_qos(&mut self, _: u16, _: u32, _: u16, _: bool) {}
            fn basic_consume(&mut self, _: u16, queue: &str, consumer_tag: &str, _: bool, _: bool, _: bool, _: &FieldTable) {
                self.0.push(format!("basic_consume({queue},{consumer_tag})"));
            }
            fn basic_cancel(&mut self, _: u16, _: &str) {}
            fn basic_ack(&mut self, _: u16, _: u64, _: bool) {}
            fn basic_nack(&mut self, _: u16, _: u64, _: bool, _: bool) {}
            fn basic_reject(&mut self, _: u16, _: u64, _: bool) {}
            fn basic_get(&mut self, _: u16, _: &str, _: bool) {}
            fn basic_recover(&mut self, _: u16, _: bool) {}
            fn flow(&mut self, _: u16, _: bool) {}
            fn tx_select(&mut self, _: u16) {}
            fn tx_commit(&mut self, _: u16) {}
            fn tx_rollback(&mut self, _: u16) {}
            fn connection_close(&mut self, _: u16, _: &str) {}
        }

        let mut rec = Rec(Vec::new());
        t.replay(&mut rec);
        assert_eq!(
            rec.0,
            vec![
                "channel_open(1)".to_string(),
                "exchange_declare(ex)".to_string(),
                "queue_declare(q)".to_string(),
                "queue_bind(q,ex)".to_string(),
                "basic_consume(q,ctag)".to_string(),
            ]
        );
    }

    #[test]
    fn queue_delete_cascades_to_bindings_and_consumers() {
        let mut t = Topology::default();
        t.open_channel(1);
        t.declare_queue(1, "q", false, false, false, false, &ft());
        t.declare_exchange(1, "ex", "topic", false, false, false, false, &ft());
        t.bind_queue(1, "q", "ex", "rk", &ft());
        t.consume(1, "q", "ctag", false, false, false, &ft());

        t.delete_queue("q");

        let ch = t.channels.get(&1).unwrap();
        assert!(ch.queues.is_empty());
        assert!(ch.bindings.is_empty());
        assert!(ch.consumers.is_empty());
        assert_eq!(ch.exchanges.len(), 1); // exchange itself is untouched
    }

    #[test]
    fn unbind_removes_only_the_matching_binding() {
        let mut t = Topology::default();
        t.open_channel(1);
        t.bind_queue(1, "q1", "ex", "rk1", &ft());
        t.bind_queue(1, "q2", "ex", "rk2", &ft());

        t.unbind_queue("q1", "ex", "rk1");

        let ch = t.channels.get(&1).unwrap();
        assert_eq!(ch.bindings.len(), 1);
        assert_eq!(ch.bindings[0].queue, "q2");
    }

    #[test]
    fn cancel_removes_only_the_matching_consumer() {
        let mut t = Topology::default();
        t.open_channel(1);
        t.consume(1, "q1", "ctag1", false, false, false, &ft());
        t.consume(1, "q2", "ctag2", false, false, false, &ft());

        t.cancel("ctag1");

        let ch = t.channels.get(&1).unwrap();
        assert_eq!(ch.consumers.len(), 1);
        assert_eq!(ch.consumers[0].consumer_tag, "ctag2");
    }

    // Minimal recording fake `AmqpClientControl` — pushes a formatted
    // string per call into a shared log, so tests can assert both *what*
    // was called and in *what order*, without a real socket.
    #[derive(Clone, Default)]
    struct FakeControl {
        log: Arc<Mutex<Vec<String>>>,
    }
    impl AmqpClientControl for FakeControl {
        fn channel_open(&mut self, channel_id: u16) {
            self.log.lock().unwrap().push(format!("channel_open({channel_id})"));
        }
        fn channel_close(&mut self, _: u16, _: u16, _: &str) {}
        fn exchange_declare(&mut self, _: u16, exchange: &str, _: &str, _: bool, _: bool, _: bool, _: bool, _: &FieldTable) {
            self.log.lock().unwrap().push(format!("exchange_declare({exchange})"));
        }
        fn exchange_delete(&mut self, _: u16, _: &str, _: bool) {}
        fn queue_declare(&mut self, _: u16, queue: &str, _: bool, _: bool, _: bool, _: bool, _: &FieldTable) {
            self.log.lock().unwrap().push(format!("queue_declare({queue})"));
        }
        fn queue_bind(&mut self, _: u16, queue: &str, exchange: &str, _: &str, _: &FieldTable) {
            self.log.lock().unwrap().push(format!("queue_bind({queue},{exchange})"));
        }
        fn queue_unbind(&mut self, _: u16, _: &str, _: &str, _: &str, _: &FieldTable) {}
        fn queue_purge(&mut self, _: u16, _: &str) {}
        fn queue_delete(&mut self, _: u16, _: &str, _: bool, _: bool) {}
        fn confirm_select(&mut self, _: u16) {}
        fn basic_publish(&mut self, _: u16, _: &str, _: &str, _: bool, _: bool, _: &BasicProperties, _: &[u8]) {}
        fn basic_publish_start(&mut self, _: u16, _: &str, _: &str, _: bool, _: bool, _: &BasicProperties, _: u64) {}
        fn basic_publish_body(&mut self, _: u16, _: &[u8]) {}
        fn basic_qos(&mut self, _: u16, _: u32, _: u16, _: bool) {}
        fn basic_consume(&mut self, _: u16, queue: &str, consumer_tag: &str, _: bool, _: bool, _: bool, _: &FieldTable) {
            self.log.lock().unwrap().push(format!("basic_consume({queue},{consumer_tag})"));
        }
        fn basic_cancel(&mut self, _: u16, _: &str) {}
        fn basic_ack(&mut self, _: u16, _: u64, _: bool) {}
        fn basic_nack(&mut self, _: u16, _: u64, _: bool, _: bool) {}
        fn basic_reject(&mut self, _: u16, _: u64, _: bool) {}
        fn basic_get(&mut self, _: u16, _: &str, _: bool) {}
        fn basic_recover(&mut self, _: u16, _: bool) {}
        fn flow(&mut self, _: u16, _: bool) {}
        fn tx_select(&mut self, _: u16) {}
        fn tx_commit(&mut self, _: u16) {}
        fn tx_rollback(&mut self, _: u16) {}
        fn connection_close(&mut self, _: u16, _: &str) {}
    }

    // Fake "user" driver: on first connect, declares one queue and one
    // consumer (exactly what a real app would do), and counts how many
    // times on_connection_open actually reached it.
    struct FakeUserDriver {
        open_count: Arc<AtomicU32>,
    }
    impl AmqpClientDriver for FakeUserDriver {
        fn on_connection_open(&mut self, client: &mut dyn AmqpClientControl) {
            self.open_count.fetch_add(1, Ordering::SeqCst);
            client.channel_open(1);
        }
        fn on_channel_open(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
            client.queue_declare(channel, "q", false, false, false, false, &FieldTable::new());
            client.basic_consume(channel, "q", "ctag", false, false, false, &FieldTable::new());
        }
        fn on_channel_close(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: u16, _: &str) {}
        fn on_exchange_declare_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16) {}
        fn on_queue_declare_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: &str, _: u32, _: u32) {}
        fn on_consume_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: &str) {}
        fn on_delivery_start(&mut self, _: u16, _: &str, _: u64, _: bool, _: &str, _: &str, _: &BasicProperties, _: u64) {}
        fn on_delivery_data(&mut self, _: &[u8]) {}
        fn on_delivery_complete(&mut self, _: &mut dyn AmqpClientControl, _: u16) {}
        fn on_error(&mut self, _: &io::Error) {}
        fn on_disconnected(&mut self) {}
    }
    struct FakeUserFactory {
        open_count: Arc<AtomicU32>,
    }
    impl AmqpClientHandlerFactory for FakeUserFactory {
        fn create(&self) -> Box<dyn AmqpClientDriver> {
            Box::new(FakeUserDriver { open_count: Arc::clone(&self.open_count) })
        }
    }

    #[derive(Default)]
    struct FakeListener {
        recovered: Arc<AtomicBool>,
    }
    impl RecoveryListener for FakeListener {
        fn on_recovered(&self) {
            self.recovered.store(true, Ordering::SeqCst);
        }
    }

    /// End-to-end (minus real sockets): the user driver's on_connection_open
    /// fires exactly once across two simulated connections, but the second
    /// one still ends up with the same channel/queue/consumer live via
    /// transparent replay, and the listener hears about it.
    #[test]
    fn reconnect_skips_user_on_connection_open_but_replays_topology() {
        let rt = Arc::new(Runtime::start(hopf_core::RuntimeConfig::default()).unwrap());
        let open_count = Arc::new(AtomicU32::new(0));
        let recovered = Arc::new(AtomicBool::new(false));

        let factory = RecoveringHandlerFactory {
            user_factory: Arc::new(FakeUserFactory { open_count: Arc::clone(&open_count) }),
            user_driver: Arc::new(Mutex::new(None)),
            topology: Arc::new(Mutex::new(Topology::default())),
            ever_connected: Arc::new(AtomicBool::new(false)),
            attempt: Arc::new(AtomicU32::new(0)),
            last_error: Arc::new(Mutex::new(None)),
            closing: Arc::new(AtomicBool::new(false)),
            backoff_cancel: Arc::new(Mutex::new(None)),
            reconnect_trigger: Arc::new(Mutex::new(None)),
            rt,
            policy: RecoveryPolicy::exponential_backoff(),
            listener: Some(Arc::new(FakeListener { recovered: Arc::clone(&recovered) }) as Arc<dyn RecoveryListener>),
        };

        // First "connection": user driver's on_connection_open opens a
        // channel; simulate the broker's channel.open-ok by also firing
        // on_channel_open, where the fake driver declares the topology.
        let mut first = factory.create();
        let mut control1 = FakeControl::default();
        first.on_connection_open(&mut control1);
        first.on_channel_open(&mut control1, 1);
        assert_eq!(open_count.load(Ordering::SeqCst), 1);
        assert_eq!(
            *control1.log.lock().unwrap(),
            vec!["channel_open(1)", "queue_declare(q)", "basic_consume(q,ctag)"]
        );
        assert!(!recovered.load(Ordering::SeqCst));

        // Second "connection" (as if reconnected): a fresh driver from the
        // same factory. on_connection_open must NOT reach the user driver
        // again, but the recorded topology replays against the new control.
        let mut second = factory.create();
        let mut control2 = FakeControl::default();
        second.on_connection_open(&mut control2);
        assert_eq!(open_count.load(Ordering::SeqCst), 1, "user driver's on_connection_open must not fire again");
        assert_eq!(
            *control2.log.lock().unwrap(),
            vec!["channel_open(1)", "queue_declare(q)", "basic_consume(q,ctag)"]
        );
        assert!(recovered.load(Ordering::SeqCst), "RecoveryListener::on_recovered must fire on reconnect");
    }

    #[test]
    fn channel_close_drops_all_of_that_channels_topology() {
        let mut t = Topology::default();
        t.open_channel(1);
        t.declare_queue(1, "q", false, false, false, false, &ft());
        t.open_channel(2);
        t.declare_queue(2, "q2", false, false, false, false, &ft());

        t.close_channel(1);

        assert!(t.channels.get(&1).is_none());
        assert!(t.channels.get(&2).is_some());
    }
}
