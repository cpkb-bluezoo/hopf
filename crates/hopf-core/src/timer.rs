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

/// Min-deadline timer queue owned by a single reactor.
pub(crate) struct TimerQueue {
    heap: BinaryHeap<TimerEntry>,
    next_id: AtomicU64,
}

impl TimerQueue {
    pub fn new() -> Self {
        Self {
            heap: BinaryHeap::new(),
            next_id: AtomicU64::new(1),
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
