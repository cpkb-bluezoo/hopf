// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! `MqttMessageStore` SPI — deferred.
//!
//! Retained messages already have a concrete, sufficient home:
//! [`crate::server::broker::RetainedStore`] (one message per topic, in memory).
//! That covers everything this plan's broker core needs, so a separate
//! abstract store SPI would be an unused abstraction for now. This module
//! stays reserved for the thing that would actually need it — durable,
//! larger-than-memory storage (offline message queues, QoS state surviving
//! a restart) — which is explicit future work, not part of this plan (see
//! the MQTT implementation plan's "Future project work").
