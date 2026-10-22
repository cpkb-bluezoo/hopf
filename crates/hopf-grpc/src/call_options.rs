// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Per-call client options (metadata and deadline).

use std::time::{Duration, SystemTime};

use crate::metadata::GrpcMetadata;

/// Metadata and deadline for one outbound gRPC call.
#[derive(Debug, Clone, Default)]
pub struct GrpcCallOptions {
    metadata: GrpcMetadata,
    deadline: Option<SystemTime>,
}

impl GrpcCallOptions {
    /// Empty options.
    pub fn new() -> Self {
        Self::default()
    }

    /// Custom metadata sent with the request (excluding protocol headers).
    pub fn metadata(&self) -> &GrpcMetadata {
        &self.metadata
    }

    /// Mutable custom request metadata.
    pub fn metadata_mut(&mut self) -> &mut GrpcMetadata {
        &mut self.metadata
    }

    /// Relative timeout from now (also sent as `grpc-timeout`).
    pub fn timeout(mut self, duration: Duration) -> Self {
        self.deadline = SystemTime::now().checked_add(duration);
        self
    }

    /// Absolute deadline (also sent as `grpc-timeout` when the call starts).
    pub fn deadline(mut self, deadline: SystemTime) -> Self {
        self.deadline = Some(deadline);
        self
    }

    /// Remaining time until the deadline, in nanoseconds, or `None` if unset
    /// or already passed.
    pub fn remaining_nanos(&self) -> Option<u64> {
        let deadline = self.deadline?;
        let remaining = deadline.duration_since(SystemTime::now()).ok()?;
        Some(remaining.as_nanos().min(u64::MAX as u128) as u64)
    }
}
