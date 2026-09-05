// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! SMTP-aligned retry strategy (issue #344), built on `hopf-core`'s
//! generic [`RetryPolicy`].

use std::sync::{Arc, Mutex};
use std::time::Duration;

use hopf_core::{Retryable, Runtime};
use hopf_core::retry::{RetryPolicy, RetryState};

use super::facade::SmtpClient;
use super::pipeline::{SmtpSend, SmtpSendOutcome};

impl Retryable for SmtpSendOutcome {
    /// RFC 5321 §4.5.4: a 4xx (transient) reply is exactly the case a
    /// sender is expected to retry later. A failure with no explicit
    /// reply code at all — couldn't connect, connection dropped
    /// mid-transaction, a protocol-level desync before any reply arrived —
    /// is also worth retrying, since none of those indicate a definitional
    /// reason the message can never be delivered. A 5xx (permanent) reply
    /// must never be retried: the remote server has told us, explicitly,
    /// that retrying is pointless.
    fn is_retryable(&self) -> bool {
        match self {
            SmtpSendOutcome::Delivered => false,
            SmtpSendOutcome::Rejected { code, .. } => (400..500).contains(code),
            SmtpSendOutcome::Failed(_) => true,
        }
    }
}

/// RFC 5321 §4.5.4-aligned defaults for outbound SMTP delivery retry:
/// first retry no sooner than 30 minutes, growing (doubling) up to a
/// 4-hour cap between attempts, giving up after 5 days total elapsed
/// since the first attempt — at which point the message is undeliverable
/// and should be bounced. A 10% jitter avoids many queued messages to the
/// same, recently-recovered destination all retrying in lockstep.
///
/// These are sane defaults, not requirements — override via
/// [`RetryPolicy`]'s own builder methods (e.g. a shorter window for a
/// deployment that bounces sooner) and pass the result to
/// [`RetryingSend::new`].
pub fn smtp_retry_policy() -> RetryPolicy {
    RetryPolicy::exponential_backoff()
        .with_initial_delay(Duration::from_secs(30 * 60))
        .with_max_delay(Duration::from_secs(4 * 60 * 60))
        .with_jitter(0.1)
        .with_max_elapsed(Duration::from_secs(5 * 24 * 60 * 60))
}

/// Drives repeated [`SmtpSend`] attempts against the same destination,
/// retrying transient failures per a [`RetryPolicy`] and reporting exactly
/// one terminal [`SmtpSendOutcome`] via [`Self::on_final`] once delivery
/// either succeeds, is permanently rejected, or the retry window is
/// exhausted — that single callback firing at all is the "give up, this
/// is now undeliverable" signal a caller needs to generate a bounce/DSN,
/// distinct from "still retrying" (no callback yet).
pub struct RetryingSend(Arc<Inner>);

type FinalCallback = Box<dyn FnOnce(SmtpSendOutcome) + Send>;

struct Inner {
    client: SmtpClient,
    rt: Arc<Runtime>,
    build: Box<dyn Fn() -> SmtpSend + Send + Sync>,
    state: Mutex<RetryState>,
    on_final: Mutex<Option<FinalCallback>>,
}

impl RetryingSend {
    /// `client` identifies the destination to (re)dial on every attempt.
    /// `build` constructs a fresh [`SmtpSend`] (envelope + message) for
    /// each attempt: `SmtpSend`'s internal state (recipient index, SASL
    /// exchange, ...) is mutated over the course of one delivery attempt
    /// and can't be reused for a second dial, so this is called again —
    /// not the same instance replayed — every time a retry fires. Any
    /// `on_complete`/`on_result` callback set on the `SmtpSend` `build`
    /// returns is overridden — this struct owns getting the outcome.
    pub fn new(
        client: SmtpClient,
        rt: Arc<Runtime>,
        policy: RetryPolicy,
        build: impl Fn() -> SmtpSend + Send + Sync + 'static,
    ) -> Self {
        Self(Arc::new(Inner {
            client,
            rt,
            build: Box::new(build),
            state: Mutex::new(policy.start()),
            on_final: Mutex::new(None),
        }))
    }

    /// Register the terminal callback. Fires exactly once.
    pub fn on_final(self, cb: impl FnOnce(SmtpSendOutcome) + Send + 'static) -> Self {
        *self.0.on_final.lock().unwrap() = Some(Box::new(cb));
        self
    }

    /// Start the first attempt. Returns immediately — the outcome arrives
    /// via [`Self::on_final`], not this call.
    pub fn send(&self) {
        self.0.dial();
    }
}

impl Inner {
    fn dial(self: &Arc<Self>) {
        let this = Arc::clone(self);
        let send = (self.build)().on_result(Box::new(move |outcome| {
            this.handle_outcome(outcome);
        }));
        if let Err(e) = self.client.connect(&self.rt, Arc::new(send)) {
            self.handle_outcome(SmtpSendOutcome::Failed(e.to_string()));
        }
    }

    fn handle_outcome(self: &Arc<Self>, outcome: SmtpSendOutcome) {
        let delay = self.state.lock().unwrap().should_retry(&outcome);
        match delay {
            Some(delay) => {
                let this = Arc::clone(self);
                self.rt
                    .pick_worker()
                    .schedule_timer(delay, Box::new(move || this.dial()));
            }
            None => self.finish(outcome),
        }
    }

    fn finish(&self, outcome: SmtpSendOutcome) {
        if let Some(cb) = self.on_final.lock().unwrap().take() {
            cb(outcome);
        }
    }
}
