// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Power-of-two buffer pool for socket `net_in` / `net_out` buffers.

use std::sync::Mutex;

const MIN_BUCKET: usize = 4096;
const MAX_BUCKET: usize = 1024 * 1024;
const DEFAULT_PER_BUCKET: usize = 64;

/// Global pool of reusable `Vec<u8>` buffers (Gumdrop `DirectByteBufferPool` role).
pub struct BufferPool {
    buckets: Mutex<Vec<Vec<Vec<u8>>>>,
    max_per_bucket: usize,
}

impl BufferPool {
    /// Create a pool with the given maximum free buffers per size class.
    pub fn new(max_per_bucket: usize) -> Self {
        let n = bucket_index(MAX_BUCKET) + 1;
        Self {
            buckets: Mutex::new((0..n).map(|_| Vec::new()).collect()),
            max_per_bucket,
        }
    }

    /// Acquire a cleared buffer with capacity at least `min_capacity` (rounded up).
    pub fn acquire(&self, min_capacity: usize) -> Vec<u8> {
        let cap = round_up_pow2(min_capacity.max(MIN_BUCKET).min(MAX_BUCKET));
        let idx = bucket_index(cap);
        if let Ok(mut buckets) = self.buckets.lock() {
            if let Some(buf) = buckets.get_mut(idx).and_then(|b| b.pop()) {
                return buf;
            }
        }
        Vec::with_capacity(cap)
    }

    /// Return a buffer to the pool. Non-PoT or oversized buffers are dropped.
    pub fn release(&self, mut buf: Vec<u8>) {
        buf.clear();
        let cap = buf.capacity();
        if cap < MIN_BUCKET || cap > MAX_BUCKET || !cap.is_power_of_two() {
            return;
        }
        let idx = bucket_index(cap);
        if let Ok(mut buckets) = self.buckets.lock() {
            if let Some(bucket) = buckets.get_mut(idx) {
                if bucket.len() < self.max_per_bucket {
                    bucket.push(buf);
                }
            }
        }
    }
}

impl Default for BufferPool {
    fn default() -> Self {
        Self::new(DEFAULT_PER_BUCKET)
    }
}

fn round_up_pow2(n: usize) -> usize {
    n.next_power_of_two().max(MIN_BUCKET)
}

fn bucket_index(pow2_cap: usize) -> usize {
    debug_assert!(pow2_cap.is_power_of_two());
    pow2_cap.trailing_zeros() as usize - MIN_BUCKET.trailing_zeros() as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_release_roundtrip() {
        let pool = BufferPool::new(8);
        let mut a = pool.acquire(100);
        assert!(a.capacity() >= 4096);
        a.extend_from_slice(b"hi");
        pool.release(a);
        let b = pool.acquire(100);
        assert!(b.is_empty());
        assert!(b.capacity() >= 4096);
    }
}
