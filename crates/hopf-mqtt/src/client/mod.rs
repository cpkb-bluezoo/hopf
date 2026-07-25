// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Async MQTT client — `hopf-core` `Runtime` / `ProtocolHandler` based.
//!
//! The primary entry points are:
//! - [`MqttClient`] — high-level facade (DNS + `Runtime::connect`)
//! - [`MqttClientDriver`] — consolidated callback trait for the connection lifecycle
//! - [`MqttClientControl`] — publish / subscribe / unsubscribe / disconnect, passed to the driver
//!
//! Reuses [`crate::codec`]'s push parser and encoders directly — MQTT's
//! wire format doesn't differ by direction the way POP3/IMAP's does, so
//! there's no separate client-side codec.
//!
//! # Quick start
//!
//! ```no_run
//! use std::sync::Arc;
//! use hopf_core::{Runtime, RuntimeConfig};
//! use hopf_mqtt::client::{MqttClient, MqttClientControl, MqttClientDriver, MqttClientHandlerFactory};
//! use hopf_mqtt::codec::{Properties, QoS, SubscribeFilter};
//!
//! struct Driver;
//! impl MqttClientDriver for Driver {
//!     fn on_connack(&mut self, client: &mut dyn MqttClientControl, _session_present: bool, reason_code: u8, _properties: &Properties) {
//!         if reason_code == 0 {
//!             client.subscribe(&[SubscribeFilter {
//!                 topic_filter: "demo/topic".into(),
//!                 max_qos: QoS::AtMostOnce,
//!                 no_local: false,
//!                 retain_as_published: false,
//!                 retain_handling: 0,
//!             }]);
//!         }
//!     }
//!     fn on_message_start(&mut self, topic: &str, _qos: QoS, _retain: bool, _packet_id: u16, _properties: &Properties, _payload_len: u32) {
//!         println!("message on {topic}");
//!     }
//!     fn on_message_data(&mut self, data: &[u8]) { let _ = data; }
//!     fn on_message_complete(&mut self, _client: &mut dyn MqttClientControl) {}
//!     fn on_suback(&mut self, _client: &mut dyn MqttClientControl, _packet_id: u16, _reason_codes: &[u8]) {}
//!     fn on_unsuback(&mut self, _client: &mut dyn MqttClientControl, _packet_id: u16, _reason_codes: &[u8]) {}
//!     fn on_publish_acked(&mut self, _client: &mut dyn MqttClientControl, _packet_id: u16) {}
//!     fn on_ping_resp(&mut self, _client: &mut dyn MqttClientControl) {}
//!     fn on_server_disconnect(&mut self, _reason_code: u8, _properties: &Properties) {}
//!     fn on_error(&mut self, err: &std::io::Error) { eprintln!("mqtt error: {err}"); }
//!     fn on_disconnected(&mut self) {}
//! }
//! struct Factory;
//! impl MqttClientHandlerFactory for Factory {
//!     fn create(&self) -> Box<dyn MqttClientDriver> { Box::new(Driver) }
//! }
//!
//! let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
//! MqttClient::new("broker.example.com", 1883, "my-client-id")
//!     .connect(&rt, Arc::new(Factory))
//!     .unwrap();
//! ```

mod endpoint;
mod error;
mod facade;
mod handlers;
mod timeout;

pub use endpoint::{MqttClientEndpoint, MqttClientParams};
pub use error::{MqttClientError, MqttClientResult};
pub use facade::MqttClient;
pub use handlers::{MqttClientControl, MqttClientDriver, MqttClientHandlerFactory};
pub use timeout::MqttClientTimeouts;
