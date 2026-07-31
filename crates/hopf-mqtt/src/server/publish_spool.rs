// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Shared PUBLISH-spooling helpers used by both the TCP control handler
//! ([`super::control::MqttControlHandler`]) and the WebSocket bridge
//! (`super::ws::MqttWsHandler`, feature `websocket`).
//!
//! A client's PUBLISH payload is never buffered whole in memory. QoS-0
//! recipients are streamed their payload live, chunk by chunk, as it
//! arrives ([`PublishFanout::feed`], already sent its header up front via
//! [`BrokerState::begin_publish`]). If any recipient is QoS 1/2, or the
//! publish is retained, the same chunks are *also* written to a temp
//! file — read back once per deferred recipient (and handed to the
//! retained store) in [`PendingPublish::finish`], rather than ever being
//! held whole in memory here.

use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::codec::packet::{PublishHeader, QoS};
use crate::codec::Properties;
use crate::server::broker::{BrokerState, PublishFanout, SubscriberId};

/// A file open for writing an in-progress PUBLISH's payload.
pub(crate) struct SpoolFile {
    pub(crate) path: PathBuf,
    file: File,
}

pub(crate) fn unique_spool_path() -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "hopf-mqtt-spool-{}-{}-{}.tmp",
        std::process::id(),
        nanos,
        n
    ))
}

/// One in-progress PUBLISH from the client.
pub(crate) struct PendingPublish {
    pub(crate) header: PublishHeader,
    fanout: PublishFanout,
    needs_spool: bool,
    spool: Option<SpoolFile>,
    bytes_written: u64,
}

impl PendingPublish {
    /// Begin fan-out for `header` (live QoS-0 headers already sent by the
    /// time this returns — see [`BrokerState::begin_publish`]).
    pub(crate) fn begin(broker: &BrokerState, publisher: SubscriberId, header: PublishHeader) -> Self {
        let fanout = broker.begin_publish(
            Some(publisher),
            &header.topic,
            header.payload_len as u64,
            header.qos,
            header.retain,
            &header.properties,
        );
        let needs_spool = header.payload_len > 0 && (header.retain || fanout.has_deferred());
        Self {
            header,
            fanout,
            needs_spool,
            spool: None,
            bytes_written: 0,
        }
    }

    /// Forward one chunk to live QoS-0 recipients and, if needed, the spool.
    pub(crate) fn feed(&mut self, data: &[u8]) {
        self.fanout.feed(data);
        if !self.needs_spool {
            return;
        }
        if self.spool.is_none() {
            let path = unique_spool_path();
            match File::create(&path) {
                Ok(file) => self.spool = Some(SpoolFile { path, file }),
                Err(_) => {
                    // Can't spool — QoS-0 recipients already got their live
                    // chunks; QoS-1/2/retain delivery for this publish is
                    // simply skipped in `finish` (spool stays None).
                    self.needs_spool = false;
                    return;
                }
            }
        }
        if let Some(spool) = &mut self.spool {
            if spool.file.write_all(data).is_err() {
                let path = std::mem::take(&mut spool.path);
                let _ = std::fs::remove_file(&path);
                self.spool = None;
                self.needs_spool = false;
            } else {
                self.bytes_written += data.len() as u64;
            }
        }
    }

    /// Resolve any deferred QoS-1/2 recipients and/or retain the payload,
    /// from the spool if one was opened (deleting it afterward unless
    /// ownership transferred to the retained store).
    pub(crate) fn finish(self, broker: &BrokerState) {
        let PendingPublish { header, fanout, spool, bytes_written, .. } = self;
        if header.retain || fanout.has_deferred() {
            let spooled = spool.filter(|_| bytes_written > 0);
            broker.deliver_deferred(
                &fanout,
                &header.topic,
                &header.properties,
                spooled.as_ref().map(|sf| (sf.path.as_path(), bytes_written)),
            );
            if header.retain {
                broker.retain(
                    &header.topic,
                    header.qos,
                    spooled.map(|sf| (sf.path, bytes_written)),
                    header.properties.clone(),
                );
            } else if let Some(sf) = spooled {
                let _ = std::fs::remove_file(&sf.path);
            }
        }
    }
}

/// Publish a payload that's already fully known in memory — used for the
/// CONNECT Will message, which (unlike a client PUBLISH) is decoded whole
/// as part of CONNECT and never arrives in wire chunks. Still never hands a
/// whole in-memory buffer to the retained store or a QoS-1/2 recipient: if
/// either needs it, `payload` is spooled to a temp file first and delivered
/// from there via the same [`BrokerState::deliver_deferred`] /
/// [`BrokerState::retain`] path [`PendingPublish::finish`] uses.
pub(crate) fn publish_whole(
    broker: &BrokerState,
    publisher: Option<SubscriberId>,
    topic: &str,
    payload: &[u8],
    qos: QoS,
    retain: bool,
    properties: &Properties,
) {
    let fanout = broker.begin_publish(publisher, topic, payload.len() as u64, qos, retain, properties);
    fanout.feed(payload);
    if !retain && !fanout.has_deferred() {
        return;
    }
    let spooled = if payload.is_empty() {
        None
    } else {
        let path = unique_spool_path();
        match File::create(&path).and_then(|mut f| f.write_all(payload).map(|_| f)) {
            Ok(_) => Some(path),
            Err(_) => None,
        }
    };
    broker.deliver_deferred(
        &fanout,
        topic,
        properties,
        spooled.as_deref().map(|p| (p, payload.len() as u64)),
    );
    if retain {
        broker.retain(topic, qos, spooled.map(|p| (p, payload.len() as u64)), properties.clone());
    } else if let Some(path) = spooled {
        let _ = std::fs::remove_file(&path);
    }
}
