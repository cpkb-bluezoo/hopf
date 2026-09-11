// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Cryptographically secure random bytes via AWS-LC.

use aws_lc_rs::error::Unspecified;
use aws_lc_rs::rand::SecureRandom;

/// OS-backed CSPRNG.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemRandom;

impl SystemRandom {
    /// Construct a new random source.
    pub fn new() -> Self {
        Self
    }

    /// Fill `dest` with random bytes.
    pub fn fill(&self, dest: &mut [u8]) -> Result<(), Unspecified> {
        aws_lc_rs::rand::SystemRandom::new().fill(dest)
    }
}
