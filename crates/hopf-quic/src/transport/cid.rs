// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Connection ID demux helpers.

use std::collections::HashMap;

use crate::transport::types::{ConnectionHandle, ConnectionId};

/// Map of local CIDs → connection handles.
#[derive(Debug, Default)]
pub struct CidMap {
    by_cid: HashMap<ConnectionId, ConnectionHandle>,
}

impl CidMap {
    /// Insert a mapping.
    pub fn insert(&mut self, cid: ConnectionId, handle: ConnectionHandle) {
        self.by_cid.insert(cid, handle);
    }

    /// Lookup by DCID.
    pub fn get(&self, cid: &ConnectionId) -> Option<ConnectionHandle> {
        self.by_cid.get(cid).copied()
    }

    /// Remove a CID.
    pub fn remove(&mut self, cid: &ConnectionId) {
        self.by_cid.remove(cid);
    }

    /// Remove all CIDs for a handle.
    pub fn remove_handle(&mut self, handle: ConnectionHandle) {
        self.by_cid.retain(|_, h| *h != handle);
    }
}
