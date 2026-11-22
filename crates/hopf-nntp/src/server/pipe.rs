// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! A bounded pipe from a storage thread to a connection.
//!
//! A command's answer is produced on the storage pool, where the store may be
//! read, and consumed on the connection's reactor, which sends it on. The
//! pipe between them holds a bounded amount: when the connection is behind
//! (the client reads slowly, so what was sent has not drained) the pipe
//! fills, and the producer waits at its next write, so a slow client slows the
//! reading of the store instead of the answer piling up in memory.
//!
//! A producer that waits, waits for the consumer to take something, and for
//! no longer than the stall limit given to it: after that it gives up (its
//! writes return false), so that a client that has stopped reading cannot
//! hold a storage thread for ever. A consumer that has gone (the connection
//! closed) wakes it at once.

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// The size of the pieces an answer travels in.
pub(crate) const CHUNK: usize = 16 * 1024;

/// How much the pipe holds before its producer waits.
pub(crate) const HIGH_WATER: usize = 128 * 1024;

#[derive(Default)]
struct State {
    chunks: VecDeque<Vec<u8>>,
    queued: usize,
    /// How many chunks the consumer has taken, so that a producer can tell
    /// whether it is being read from while it waits.
    taken: u64,
    consumer_gone: bool,
    /// The consumer found the pipe empty and wants waking.
    consumer_waiting: bool,
    producer_done: bool,
    /// A producer gave up waiting for the consumer.
    stalled: bool,
}

struct Inner {
    state: Mutex<State>,
    space: Condvar,
}

/// Both ends of the pipe share this.
#[derive(Clone)]
pub(crate) struct Pipe {
    inner: Arc<Inner>,
}

/// What the consumer finds in the pipe.
pub(crate) enum Poll {
    /// Chunks to send.
    Data(Vec<Vec<u8>>),
    /// Nothing now. The producer has finished if `done`; otherwise the
    /// consumer will be woken when there is more.
    Empty { done: bool },
}

impl Pipe {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State::default()),
                space: Condvar::new(),
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.inner.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Takes what is queued, up to `max` bytes (always at least one chunk).
    pub(crate) fn poll(&self, max: usize) -> Poll {
        let mut s = self.lock();
        if s.chunks.is_empty() {
            if !s.producer_done {
                s.consumer_waiting = true;
            }
            return Poll::Empty { done: s.producer_done };
        }
        let mut out = Vec::new();
        let mut bytes = 0;
        while let Some(c) = s.chunks.front() {
            if !out.is_empty() && bytes + c.len() > max {
                break;
            }
            bytes += c.len();
            out.push(s.chunks.pop_front().unwrap());
        }
        s.queued -= bytes;
        s.taken += out.len() as u64;
        drop(s);
        self.inner.space.notify_all();
        Poll::Data(out)
    }

    /// The consumer is gone: the producer's writes fail from now on.
    pub(crate) fn close_consumer(&self) {
        let mut s = self.lock();
        s.consumer_gone = true;
        s.chunks.clear();
        s.queued = 0;
        drop(s);
        self.inner.space.notify_all();
    }

    /// The producer is finished, whether or not it said so itself (a job that
    /// was refused, or that panicked, never will).
    pub(crate) fn mark_done(&self) {
        self.lock().producer_done = true;
    }

    /// Did a producer give up waiting for the consumer?
    pub(crate) fn stalled(&self) -> bool {
        self.lock().stalled
    }

    /// The producer's end.
    pub(crate) fn output(&self, stall: Duration, wake: Arc<dyn Fn() + Send + Sync>) -> Output {
        Output {
            pipe: self.clone(),
            stall,
            wake,
            buf: Vec::with_capacity(CHUNK),
            alive: true,
        }
    }
}

/// The producer's end of a [`Pipe`]: bytes written are gathered into chunks
/// and passed on, waiting when the pipe is full.
pub(crate) struct Output {
    pipe: Pipe,
    stall: Duration,
    wake: Arc<dyn Fn() + Send + Sync>,
    buf: Vec<u8>,
    alive: bool,
}

impl Output {
    /// Can writes still get anywhere? False once the consumer has gone or a
    /// wait for it ran out.
    pub(crate) fn alive(&self) -> bool {
        self.alive
    }

    /// Writes `bytes`. Returns false if the answer has nowhere to go, and
    /// the producer should stop.
    pub(crate) fn write(&mut self, mut bytes: &[u8]) -> bool {
        while self.alive && !bytes.is_empty() {
            let room = CHUNK - self.buf.len();
            let (now, later) = bytes.split_at(room.min(bytes.len()));
            self.buf.extend_from_slice(now);
            bytes = later;
            if self.buf.len() >= CHUNK {
                self.flush();
            }
        }
        self.alive
    }

    /// Passes on what has been written, however little.
    pub(crate) fn flush(&mut self) -> bool {
        if !self.alive || self.buf.is_empty() {
            return self.alive;
        }
        let chunk = std::mem::replace(&mut self.buf, Vec::with_capacity(CHUNK));
        let len = chunk.len();
        let mut s = self.pipe.lock();
        let mut seen = s.taken;
        let mut deadline = Instant::now() + self.stall;
        while !s.consumer_gone && s.queued >= HIGH_WATER {
            let now = Instant::now();
            if now >= deadline {
                s.stalled = true;
                self.alive = false;
                drop(s);
                // The consumer may be waiting for the connection to drain,
                // which it never will: it has to hear of this to end it.
                (self.wake)();
                return false;
            }
            let (guard, _) = self
                .pipe
                .inner
                .space
                .wait_timeout(s, deadline - now)
                .unwrap_or_else(|e| e.into_inner());
            s = guard;
            if s.taken != seen {
                // Being read from: the stall starts again.
                seen = s.taken;
                deadline = Instant::now() + self.stall;
            }
        }
        if s.consumer_gone {
            self.alive = false;
            return false;
        }
        s.chunks.push_back(chunk);
        s.queued += len;
        let wake = std::mem::take(&mut s.consumer_waiting);
        drop(s);
        if wake {
            (self.wake)();
        }
        true
    }

    /// Ends the answer: what is written is passed on, and the consumer is told
    /// there will be no more.
    pub(crate) fn finish(mut self) {
        self.flush();
        let mut s = self.pipe.lock();
        s.producer_done = true;
        let wake = std::mem::take(&mut s.consumer_waiting);
        drop(s);
        if wake {
            (self.wake)();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn counter() -> (Arc<AtomicUsize>, Arc<dyn Fn() + Send + Sync>) {
        let n = Arc::new(AtomicUsize::new(0));
        let n2 = Arc::clone(&n);
        (n, Arc::new(move || {
            n2.fetch_add(1, Ordering::SeqCst);
        }))
    }

    fn drain(pipe: &Pipe) -> Vec<u8> {
        let mut out = Vec::new();
        while let Poll::Data(chunks) = pipe.poll(usize::MAX) {
            for c in chunks {
                out.extend_from_slice(&c);
            }
        }
        out
    }

    #[test]
    fn what_is_written_comes_out_in_order() {
        let pipe = Pipe::new();
        let (_, wake) = counter();
        let mut out = pipe.output(Duration::from_secs(5), wake);
        out.write(b"hello ");
        out.write(b"world");
        out.finish();
        assert_eq!(drain(&pipe), b"hello world");
        assert!(matches!(pipe.poll(10), Poll::Empty { done: true }));
    }

    #[test]
    fn a_large_write_travels_in_bounded_chunks() {
        let pipe = Pipe::new();
        let (_, wake) = counter();
        let mut out = pipe.output(Duration::from_secs(5), wake);
        let big = vec![7u8; CHUNK * 3 + 5];
        assert!(out.write(&big));
        out.finish();
        let Poll::Data(chunks) = pipe.poll(usize::MAX) else { panic!() };
        assert!(chunks.iter().all(|c| c.len() <= CHUNK));
        assert_eq!(chunks.iter().map(Vec::len).sum::<usize>(), big.len());
    }

    #[test]
    fn a_consumer_that_found_the_pipe_empty_is_woken_once() {
        let pipe = Pipe::new();
        let (woken, wake) = counter();
        assert!(matches!(pipe.poll(10), Poll::Empty { done: false }));
        let mut out = pipe.output(Duration::from_secs(5), wake);
        out.write(b"a");
        out.flush();
        out.write(b"b");
        out.flush();
        assert_eq!(woken.load(Ordering::SeqCst), 1, "no waiting consumer the second time");
        out.finish();
        assert_eq!(woken.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn the_end_wakes_a_waiting_consumer() {
        let pipe = Pipe::new();
        let (woken, wake) = counter();
        assert!(matches!(pipe.poll(10), Poll::Empty { done: false }));
        pipe.output(Duration::from_secs(5), wake).finish();
        assert_eq!(woken.load(Ordering::SeqCst), 1);
        assert!(matches!(pipe.poll(10), Poll::Empty { done: true }));
    }

    #[test]
    fn a_full_pipe_holds_the_producer_until_the_consumer_takes_something() {
        let pipe = Pipe::new();
        let (_, wake) = counter();
        let mut out = pipe.output(Duration::from_secs(30), wake);
        let producer = std::thread::spawn(move || {
            let chunk = vec![1u8; CHUNK];
            // Far more than the pipe holds.
            for _ in 0..(HIGH_WATER / CHUNK) * 4 {
                assert!(out.write(&chunk));
            }
            out.finish();
        });
        // Give the producer time to fill the pipe and stop.
        std::thread::sleep(Duration::from_millis(200));
        let held = pipe.lock().queued;
        assert!(held >= HIGH_WATER && held <= HIGH_WATER + CHUNK, "{held}");
        assert!(!producer.is_finished(), "the producer did not wait");
        let mut total = 0;
        loop {
            match pipe.poll(CHUNK) {
                Poll::Data(c) => total += c.iter().map(Vec::len).sum::<usize>(),
                Poll::Empty { done: true } => break,
                Poll::Empty { done: false } => std::thread::sleep(Duration::from_millis(1)),
            }
        }
        producer.join().unwrap();
        assert_eq!(total, HIGH_WATER * 4);
    }

    #[test]
    fn a_producer_that_waits_too_long_gives_up() {
        let pipe = Pipe::new();
        let (_, wake) = counter();
        let mut out = pipe.output(Duration::from_millis(100), wake);
        let chunk = vec![1u8; CHUNK];
        let mut wrote = 0;
        while out.write(&chunk) {
            wrote += 1;
            assert!(wrote < 100, "never waited");
        }
        assert!(pipe.stalled());
        assert!(!out.alive());
    }

    #[test]
    fn a_producer_being_read_from_does_not_stall() {
        let pipe = Pipe::new();
        let (_, wake) = counter();
        let mut out = pipe.output(Duration::from_millis(300), wake);
        let consumer = pipe.clone();
        let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let done = Arc::clone(&finished);
        let reader = std::thread::spawn(move || {
            // Slow, but never longer than the stall limit between reads.
            while !done.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(50));
                let _ = consumer.poll(CHUNK);
            }
        });
        let chunk = vec![1u8; CHUNK];
        for _ in 0..40 {
            assert!(out.write(&chunk), "stalled while being read");
        }
        assert!(!pipe.stalled());
        finished.store(true, Ordering::SeqCst);
        reader.join().unwrap();
    }

    #[test]
    fn a_consumer_that_has_gone_ends_the_producer_at_once() {
        let pipe = Pipe::new();
        let (_, wake) = counter();
        let mut out = pipe.output(Duration::from_secs(60), wake);
        let gone = pipe.clone();
        let started = Instant::now();
        let closer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            gone.close_consumer();
        });
        let chunk = vec![1u8; CHUNK];
        while out.write(&chunk) {}
        closer.join().unwrap();
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(!pipe.stalled(), "going away is not a stall");
    }
}
