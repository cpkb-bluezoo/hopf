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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn only_temporary_failures_are_worth_trying_again() {
        assert!(!SmtpSendOutcome::Delivered.is_retryable());
        assert!(SmtpSendOutcome::Rejected { code: 450, message: String::new() }.is_retryable());
        assert!(SmtpSendOutcome::Rejected { code: 499, message: String::new() }.is_retryable());
        assert!(!SmtpSendOutcome::Rejected { code: 550, message: String::new() }.is_retryable());
        assert!(!SmtpSendOutcome::Rejected { code: 399, message: String::new() }.is_retryable());
        assert!(SmtpSendOutcome::Failed("connection reset".into()).is_retryable());
    }

    #[test]
    fn the_delivery_policy_starts_at_half_an_hour_and_gives_up_after_five_days() {
        let mut state = smtp_retry_policy().start();
        let first = state.should_retry(&SmtpSendOutcome::Failed(String::new())).unwrap();
        // 30 minutes, give or take the 10% jitter.
        assert!(first >= Duration::from_secs(27 * 60) && first <= Duration::from_secs(33 * 60), "{first:?}");
        assert!(state.should_retry(&SmtpSendOutcome::Delivered).is_none());
        assert!(state.should_retry(&SmtpSendOutcome::Rejected { code: 550, message: String::new() }).is_none());
    }

    /// A loopback SMTP server that answers each connection's MAIL FROM with
    /// `mail_reply(attempt)`; everything else is accepted.
    fn server(mail_reply: impl Fn(usize) -> &'static str + Send + Sync + 'static) -> (u16, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let attempts = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&attempts);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                let attempt = counted.fetch_add(1, Ordering::SeqCst);
                let reply = mail_reply(attempt);
                std::thread::spawn(move || {
                    let mut out = stream.try_clone().unwrap();
                    let mut input = BufReader::new(stream);
                    let _ = out.write_all(b"220 test ESMTP\r\n");
                    let mut in_data = false;
                    let mut line = String::new();
                    loop {
                        line.clear();
                        if input.read_line(&mut line).unwrap_or(0) == 0 {
                            return;
                        }
                        let cmd = line.trim_end().to_ascii_uppercase();
                        let answer = if in_data {
                            if cmd == "." {
                                in_data = false;
                                "250 2.0.0 queued\r\n"
                            } else {
                                continue;
                            }
                        } else if cmd.starts_with("EHLO") {
                            "250 test\r\n"
                        } else if cmd.starts_with("MAIL") {
                            reply
                        } else if cmd.starts_with("RCPT") {
                            "250 ok\r\n"
                        } else if cmd == "DATA" {
                            in_data = true;
                            "354 go\r\n"
                        } else if cmd == "QUIT" {
                            let _ = out.write_all(b"221 bye\r\n");
                            return;
                        } else {
                            "250 ok\r\n"
                        };
                        if out.write_all(answer.as_bytes()).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        (port, attempts)
    }

    fn quick_policy() -> RetryPolicy {
        RetryPolicy::exponential_backoff()
            .with_initial_delay(Duration::from_millis(20))
            .with_max_delay(Duration::from_millis(50))
            .with_jitter(0.0)
            .with_max_attempts(4)
    }

    fn run(port: u16, policy: RetryPolicy) -> SmtpSendOutcome {
        let rt = Arc::new(Runtime::start(hopf_core::RuntimeConfig::default()).unwrap());
        let client = SmtpClient::from_addr(format!("127.0.0.1:{port}").parse().unwrap());
        let (tx, rx) = mpsc::channel();
        RetryingSend::new(client, Arc::clone(&rt), policy, || {
            let mut once = Some(b"hi\r\n".to_vec());
            SmtpSend::new("client.example").mail_from("a@b").rcpt_to("c@d").message_with(move || once.take())
        })
        .on_final(move |o| {
            let _ = tx.send(o);
        })
        .send();
        rx.recv_timeout(Duration::from_secs(10)).expect("a final outcome")
    }

    #[test]
    fn a_delivery_that_works_first_time_is_reported_once() {
        let (port, attempts) = server(|_| "250 ok\r\n");
        assert!(matches!(run(port, quick_policy()), SmtpSendOutcome::Delivered));
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_temporary_refusal_is_tried_again_until_it_works() {
        let (port, attempts) = server(|n| if n < 2 { "451 4.3.0 try later\r\n" } else { "250 ok\r\n" });
        assert!(matches!(run(port, quick_policy()), SmtpSendOutcome::Delivered));
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn a_permanent_refusal_is_not_tried_again() {
        let (port, attempts) = server(|_| "550 5.1.1 no\r\n");
        assert!(matches!(run(port, quick_policy()), SmtpSendOutcome::Rejected { code: 550, .. }));
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_temporary_refusal_that_never_clears_is_given_up_on() {
        let (port, attempts) = server(|_| "451 4.3.0 try later\r\n");
        assert!(matches!(run(port, quick_policy()), SmtpSendOutcome::Rejected { code: 451, .. }));
        // The policy allows four retries after the first try.
        assert_eq!(attempts.load(Ordering::SeqCst), 5);
    }

    #[test]
    fn a_server_that_cannot_be_reached_is_a_failure_after_the_attempts_are_used() {
        let port = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        assert!(matches!(run(port, quick_policy()), SmtpSendOutcome::Failed(_)));
    }
}
