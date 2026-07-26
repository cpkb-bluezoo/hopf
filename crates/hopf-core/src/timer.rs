// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Per-reactor timer wheel (deadline heap + poll timeout).

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering as AtomicOrdering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Cancel flag shared with [`crate::endpoint::TimerHandle`].
pub(crate) type CancelFlag = Arc<AtomicBool>;

struct TimerEntry {
    deadline: Instant,
    id: u64,
    cancelled: CancelFlag,
    callback: Box<dyn FnOnce() + Send>,
}

impl PartialEq for TimerEntry {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for TimerEntry {}

impl PartialOrd for TimerEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TimerEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Max-heap by reversing deadline so earliest pops first via peek/pop.
        other
            .deadline
            .cmp(&self.deadline)
            .then_with(|| other.id.cmp(&self.id))
    }
}

/// Below this size, a full compaction isn't worth its O(n) cost even if the
/// heap has doubled since the last one.
const COMPACT_MIN: usize = 256;

/// Min-deadline timer queue owned by a single reactor.
pub(crate) struct TimerQueue {
    heap: BinaryHeap<TimerEntry>,
    next_id: AtomicU64,
    /// Heap length as of the last compaction (or queue creation) — the
    /// baseline `schedule_with_cancel` compares against to decide whether
    /// cancelled entries buried in the heap are worth sweeping out again.
    compacted_len: usize,
}

impl TimerQueue {
    pub fn new() -> Self {
        Self {
            heap: BinaryHeap::new(),
            next_id: AtomicU64::new(1),
            compacted_len: 0,
        }
    }

    #[allow(dead_code)]
    pub fn schedule(
        &mut self,
        delay: Duration,
        callback: Box<dyn FnOnce() + Send>,
    ) -> CancelFlag {
        let cancelled = Arc::new(AtomicBool::new(false));
        self.schedule_with_cancel(delay, callback, Arc::clone(&cancelled));
        cancelled
    }

    pub fn schedule_with_cancel(
        &mut self,
        delay: Duration,
        callback: Box<dyn FnOnce() + Send>,
        cancelled: CancelFlag,
    ) {
        let id = self.next_id.fetch_add(1, AtomicOrdering::Relaxed);
        self.heap.push(TimerEntry {
            deadline: Instant::now() + delay,
            id,
            cancelled,
            callback,
        });
        // Cancellation only flips a shared flag — it never touches this
        // heap, since the flag can be set from any thread while only the
        // reactor thread ever owns the heap itself. A cancelled entry buried
        // below the top (not caught by `purge_cancelled`) otherwise stays
        // allocated, closure captures and all, until it naturally bubbles up
        // — which, for the cancel-and-reschedule-on-every-read idiom common
        // to keepalive timers, can be indefinitely long. Compacting once the
        // heap has doubled since the last sweep bounds worst-case size to
        // ~2x live timers, amortized O(log n) per schedule either way.
        if self.heap.len() >= self.compacted_len.saturating_mul(2).max(COMPACT_MIN) {
            self.compact();
        }
    }

    /// Rebuild the heap with every currently-cancelled entry dropped.
    fn compact(&mut self) {
        let old = std::mem::replace(&mut self.heap, BinaryHeap::new());
        let live: Vec<TimerEntry> = old
            .into_vec()
            .into_iter()
            .filter(|e| !e.cancelled.load(AtomicOrdering::Acquire))
            .collect();
        self.compacted_len = live.len();
        self.heap = BinaryHeap::from(live);
    }

    /// Duration until the next non-cancelled timer, if any.
    pub fn poll_timeout(&mut self) -> Option<Duration> {
        self.purge_cancelled();
        self.heap.peek().map(|e| {
            let now = Instant::now();
            if e.deadline <= now {
                Duration::ZERO
            } else {
                e.deadline - now
            }
        })
    }

    /// Run all due, non-cancelled callbacks.
    pub fn fire_due(&mut self) {
        let now = Instant::now();
        while let Some(top) = self.heap.peek() {
            if top.deadline > now {
                break;
            }
            let entry = self.heap.pop().expect("peek succeeded");
            if entry.cancelled.load(AtomicOrdering::Acquire) {
                continue;
            }
            (entry.callback)();
        }
    }

    fn purge_cancelled(&mut self) {
        while self
            .heap
            .peek()
            .is_some_and(|e| e.cancelled.load(AtomicOrdering::Acquire))
        {
            self.heap.pop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cancelling a timer buried under an earlier-deadline one that never
    /// fires (the cancel-and-reschedule-on-every-read keepalive idiom) must
    /// not let the heap grow forever — once it's doubled since the last
    /// compaction, the next schedule call sweeps cancelled entries out.
    #[test]
    fn cancelling_buried_entries_does_not_grow_the_heap_forever() {
        let mut q = TimerQueue::new();

        // One long-lived entry that outlives everything below it and would
        // otherwise block `purge_cancelled` (top-of-heap only) from ever
        // reaching the cancelled entries buried beneath it.
        q.schedule_with_cancel(
            Duration::from_secs(3600),
            Box::new(|| {}),
            Arc::new(AtomicBool::new(false)),
        );

        // Simulate hundreds of keepalive rearms: schedule, then immediately
        // cancel (as a real rearm does to the *previous* timer), well past
        // COMPACT_MIN so a compaction is guaranteed to trigger.
        for _ in 0..COMPACT_MIN * 2 {
            let cancelled = Arc::new(AtomicBool::new(false));
            q.schedule_with_cancel(Duration::from_secs(3600), Box::new(|| {}), cancelled.clone());
            cancelled.store(true, AtomicOrdering::Release);
        }

        // Every rearm's timer is now cancelled and none has a due deadline,
        // so only compaction — not `purge_cancelled` or `fire_due`, which
        // only ever look at the top of the heap — could have kept the heap
        // from growing to COMPACT_MIN * 2 + 1 entries.
        assert!(
            q.heap.len() < COMPACT_MIN * 2,
            "heap len {} was never compacted",
            q.heap.len()
        );
        // The one long-lived, never-cancelled entry must have survived a
        // compaction (it's still due in an hour, so `fire_due` is a no-op).
        assert!(!q.heap.is_empty());
        q.fire_due();
        assert!(!q.heap.is_empty());
    }
}
