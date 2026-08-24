// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! RFC 9114 §4.1.2 Content-Length / DATA payload consistency.

use crate::utils::parse_content_length_from_pairs;

/// Tracks DATA received for one HTTP/3 message (request or response body).
#[derive(Default)]
pub(crate) struct MessageBodyTracker {
    content_length: Option<u64>,
    data_received: u64,
    active: bool,
    forbid_body: bool,
    skip: bool,
}

impl MessageBodyTracker {
    /// When true, payload length is not validated (capsule / upgrade tunnels).
    pub fn set_skip(&mut self, skip: bool) {
        self.skip = skip;
        if skip {
            self.active = false;
            self.content_length = None;
            self.data_received = 0;
        }
    }

    /// Open a payload-bearing message after its HEADERS frame.
    pub fn begin_message(
        &mut self,
        pairs: &[(String, String)],
        forbid_body: bool,
    ) -> Result<(), ()> {
        if self.skip {
            return Ok(());
        }
        self.finish_message()?;
        let cl = parse_content_length_from_pairs(pairs)?;
        if forbid_body {
            if cl.is_some_and(|n| n > 0) {
                return Err(());
            }
            self.content_length = Some(0);
        } else {
            self.content_length = cl;
        }
        self.data_received = 0;
        self.forbid_body = forbid_body;
        self.active = true;
        Ok(())
    }

    /// Account for one DATA frame payload.
    pub fn add_data(&mut self, len: u64) -> Result<(), ()> {
        if self.skip {
            return Ok(());
        }
        if !self.active {
            return Err(());
        }
        if self.forbid_body && len > 0 {
            return Err(());
        }
        self.data_received = self.data_received.saturating_add(len);
        if let Some(expected) = self.content_length {
            if self.data_received > expected {
                return Err(());
            }
        }
        Ok(())
    }

    /// Close the current message (trailers, next HEADERS, or stream FIN).
    pub fn finish_message(&mut self) -> Result<(), ()> {
        if self.skip || !self.active {
            return Ok(());
        }
        self.active = false;
        if self.forbid_body && self.data_received > 0 {
            return Err(());
        }
        if let Some(expected) = self.content_length {
            if self.data_received != expected {
                return Err(());
            }
        }
        self.content_length = None;
        self.data_received = 0;
        Ok(())
    }

    /// Interim 1xx responses must not declare or carry content (RFC 9110 §15.2).
    pub fn check_interim_no_content(pairs: &[(String, String)]) -> Result<(), ()> {
        if parse_content_length_from_pairs(pairs)?.is_some_and(|n| n > 0) {
            return Err(());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(items: &[(&str, &str)]) -> Vec<(String, String)> {
        items
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn content_length_must_match_data_sum() {
        let mut t = MessageBodyTracker::default();
        t.begin_message(&pairs(&[("content-length", "5")]), false)
            .unwrap();
        t.add_data(3).unwrap();
        t.add_data(2).unwrap();
        t.finish_message().unwrap();
    }

    #[test]
    fn short_body_is_malformed_at_finish() {
        let mut t = MessageBodyTracker::default();
        t.begin_message(&pairs(&[("content-length", "5")]), false)
            .unwrap();
        t.add_data(3).unwrap();
        assert!(t.finish_message().is_err());
    }

    #[test]
    fn excess_data_is_malformed_immediately() {
        let mut t = MessageBodyTracker::default();
        t.begin_message(&pairs(&[("content-length", "2")]), false)
            .unwrap();
        t.add_data(2).unwrap();
        assert!(t.add_data(1).is_err());
    }

    #[test]
    fn forbid_body_rejects_content_length_and_data() {
        let mut t = MessageBodyTracker::default();
        assert!(
            t.begin_message(&pairs(&[("content-length", "1")]), true)
                .is_err()
        );
        t.begin_message(&pairs(&[]), true).unwrap();
        assert!(t.add_data(1).is_err());
    }
}
