// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! What the server says for every accept or reject a handler can choose.
//! [`Policy`] is a handler whose answer at each stage is set by the test.

use super::*;
use hopf_core::testing::Peer;

#[derive(Clone, Copy, Debug, Default)]
enum Connect {
    #[default]
    Accept,
    Reject,
    RejectMsg,
    Shutdown,
}

#[derive(Clone, Copy, Debug, Default)]
enum Hello {
    #[default]
    Accept,
    Temporary,
    Permanent,
    Close,
    Shutdown,
}

#[derive(Clone, Copy, Debug, Default)]
enum Auth {
    #[default]
    Accept,
    Reject,
    RejectClose,
    Shutdown,
}

#[derive(Clone, Copy, Debug, Default)]
enum Sender {
    #[default]
    Accept,
    Greylist,
    RateLimit,
    StorageFull,
    BlockedDomain,
    InvalidDomain,
    Policy,
    Spam,
    Syntax,
    Custom,
    Shutdown,
}

#[derive(Clone, Copy, Debug, Default)]
enum Rcpt {
    #[default]
    Accept,
    Forward,
    Unavailable,
    NotFound,
    RelayDenied,
    Policy,
    Custom,
    Shutdown,
}

#[derive(Clone, Copy, Debug, Default)]
enum Start {
    #[default]
    Accept,
    StorageFull,
    Reject,
    Custom,
    Shutdown,
}

#[derive(Clone, Copy, Debug, Default)]
enum End {
    #[default]
    Accept,
    AcceptQueued,
    Temporary,
    Permanent,
    Policy,
    Custom,
    DeferAccept,
    DeferReject,
    Shutdown,
}

#[derive(Clone, Copy, Debug, Default)]
enum Reset {
    #[default]
    Accept,
    Shutdown,
}

#[derive(Clone, Copy, Debug, Default)]
struct Policy {
    connect: Connect,
    hello: Hello,
    auth: Auth,
    sender: Sender,
    rcpt: Rcpt,
    start: Start,
    end: End,
    reset: Reset,
}

impl SmtpClientConnected for Policy {
    fn connected(&mut self, state: &mut dyn ConnectedState, _meta: &SmtpConnectionMetadata) {
        match self.connect {
            Connect::Accept => state.accept_connection("mx.example ESMTP", Box::new(*self)),
            Connect::Reject => state.reject_connection(),
            Connect::RejectMsg => state.reject_connection_msg("go away"),
            Connect::Shutdown => state.server_shutting_down(),
        }
    }
    fn disconnected(&mut self) {}
}

impl HelloHandler for Policy {
    fn hello(&mut self, state: &mut dyn HelloState, _extended: bool, _hostname: &str) {
        match self.hello {
            Hello::Accept => state.accept_hello(Box::new(*self)),
            Hello::Temporary => state.reject_hello_temporary("try later", Box::new(*self)),
            Hello::Permanent => state.reject_hello("no hello for you", Box::new(*self)),
            Hello::Close => state.reject_hello_and_close("bye"),
            Hello::Shutdown => state.server_shutting_down(),
        }
    }
    fn tls_established(&mut self, _info: &hopf_core::SecurityInfo) {}
    fn authenticated(&mut self, state: &mut dyn AuthenticateState, _user: &str) {
        match self.auth {
            Auth::Accept => state.accept(Box::new(*self)),
            Auth::Reject => state.reject(Box::new(*self)),
            Auth::RejectClose => state.reject_and_close(),
            Auth::Shutdown => state.server_shutting_down(),
        }
    }
    fn quit(&mut self) {}
}

impl MailFromHandler for Policy {
    fn pipeline(&mut self) -> Option<Box<dyn SmtpPipeline>> {
        None
    }
    fn mail_from(
        &mut self,
        state: &mut dyn MailFromState,
        _sender: Option<&EmailAddress>,
        _smtputf8: bool,
        _delivery: &DeliveryRequirements,
    ) {
        let h = Box::new(*self);
        match self.sender {
            Sender::Accept => state.accept_sender(h),
            Sender::Greylist => state.reject_sender_greylist(h),
            Sender::RateLimit => state.reject_sender_rate_limit(h),
            Sender::StorageFull => state.reject_sender_storage_full(h),
            Sender::BlockedDomain => state.reject_sender_blocked_domain(h),
            Sender::InvalidDomain => state.reject_sender_invalid_domain(h),
            Sender::Policy => state.reject_sender_policy("5.7.1 not on our list", h),
            Sender::Spam => state.reject_sender_spam(h),
            Sender::Syntax => state.reject_sender_syntax(h),
            Sender::Custom => state.reject(471, "4.7.1 custom", h),
            Sender::Shutdown => state.server_shutting_down(),
        }
    }
    fn reset(&mut self, state: &mut dyn ResetState) {
        match self.reset {
            Reset::Accept => state.accept_reset(Box::new(*self)),
            Reset::Shutdown => state.server_shutting_down(),
        }
    }
    fn quit(&mut self) {}
}

impl RecipientHandler for Policy {
    fn rcpt_to(&mut self, state: &mut dyn RecipientState, _r: &EmailAddress, _d: &DsnRecipientParams) {
        let h = Box::new(*self);
        match self.rcpt {
            Rcpt::Accept => state.accept_recipient(h),
            Rcpt::Forward => state.accept_recipient_forward("other@elsewhere.example", h),
            Rcpt::Unavailable => state.reject_recipient_unavailable(h),
            Rcpt::NotFound => state.reject_recipient_not_found(h),
            Rcpt::RelayDenied => state.reject_recipient_relay_denied(h),
            Rcpt::Policy => state.reject_recipient_policy("5.7.1 not for you", h),
            Rcpt::Custom => state.reject(472, "4.7.2 custom", h),
            Rcpt::Shutdown => state.server_shutting_down(),
        }
    }
    fn start_message(&mut self, state: &mut dyn MessageStartState) {
        match self.start {
            Start::Accept => state.accept_message(Box::new(*self)),
            Start::StorageFull => state.reject_message_storage_full(Box::new(*self)),
            Start::Reject => state.reject_message("no messages today", Box::new(*self)),
            Start::Custom => state.reject(473, "4.7.3 custom", Box::new(*self)),
            Start::Shutdown => state.server_shutting_down(),
        }
    }
    fn reset(&mut self, state: &mut dyn ResetState) {
        match self.reset {
            Reset::Accept => state.accept_reset(Box::new(*self)),
            Reset::Shutdown => state.server_shutting_down(),
        }
    }
    fn quit(&mut self) {}
}

impl MessageDataHandler for Policy {
    fn message_content(&mut self, _chunk: &[u8]) {}
    fn message_complete(&mut self, state: &mut dyn MessageEndState) {
        let h = Box::new(*self);
        match self.end {
            End::Accept => state.accept_message_delivery(None, h),
            End::AcceptQueued => state.accept_message_delivery(Some("Q123"), h),
            End::Temporary => state.reject_message_temporary("busy", h),
            End::Permanent => state.reject_message_permanent("no", h),
            End::Policy => state.reject_message_policy("policy says no", h),
            End::Custom => state.reject(474, "4.7.4 custom", h),
            End::DeferAccept => state.defer(h).accept(Some("D1")),
            End::DeferReject => state.defer(h).reject(471, "4.7.1 deferred no"),
            End::Shutdown => state.server_shutting_down(),
        }
    }
    fn message_aborted(&mut self) {}
}

fn server(policy: Policy) -> Peer<SmtpControlHandler> {
    let local: SocketAddr = "127.0.0.1:25".parse().unwrap();
    let rt = Arc::new(Runtime::start(hopf_core::RuntimeConfig::default()).unwrap());
    let h = SmtpControlHandler::new(
        Box::new(policy),
        SmtpServerMetrics::shared(),
        SmtpConfig::new(local, "mx.example").auth_required(false),
        "192.0.2.5:4000".parse().unwrap(),
        local,
        rt,
    );
    Peer::connect(h, |h| h.busy.load(Ordering::SeqCst) || h.pending_finish)
}

/// Runs `commands` after a greeting and EHLO and returns the last reply.
fn last_reply(policy: Policy, commands: &[&str]) -> String {
    let mut s = server(policy);
    s.take();
    s.run("EHLO c\r\n");
    let mut r = String::new();
    for c in commands {
        r = s.run(c);
    }
    r
}

// Connecting ----------------------------------------------------------------

#[test]
fn a_handler_can_refuse_the_connection() {
    let mut s = server(Policy { connect: Connect::Reject, ..Policy::default() });
    assert_eq!(s.take(), "554 Transaction failed\r\n");
    let mut s = server(Policy { connect: Connect::RejectMsg, ..Policy::default() });
    assert_eq!(s.take(), "554 go away\r\n");
}

#[test]
fn a_handler_can_say_the_service_is_shutting_down() {
    let mut s = server(Policy { connect: Connect::Shutdown, ..Policy::default() });
    assert_eq!(s.take(), "421 4.3.2 Service not available\r\n");
}

// Hello ---------------------------------------------------------------------

#[test]
fn a_handler_can_refuse_a_hello_for_now_or_for_good_and_the_client_may_try_again() {
    let mut s = server(Policy { hello: Hello::Temporary, ..Policy::default() });
    s.take();
    assert_eq!(s.run("EHLO c\r\n"), "421 try later\r\n");
    let mut s = server(Policy { hello: Hello::Permanent, ..Policy::default() });
    s.take();
    assert_eq!(s.run("EHLO c\r\n"), "550 no hello for you\r\n");
    assert_eq!(s.run("NOOP\r\n"), "250 2.0.0 OK\r\n");
    assert!(!s.is_closed());
}

#[test]
fn a_handler_can_refuse_a_hello_and_hang_up() {
    let mut s = server(Policy { hello: Hello::Close, ..Policy::default() });
    s.take();
    assert_eq!(s.run("EHLO c\r\n"), "554 bye\r\n");
    assert!(s.is_closed());
}

#[test]
fn a_handler_can_shut_down_at_hello() {
    let mut s = server(Policy { hello: Hello::Shutdown, ..Policy::default() });
    s.take();
    assert_eq!(s.run("EHLO c\r\n"), "421 4.3.2 Service not available\r\n");
}

// MAIL FROM -----------------------------------------------------------------

#[test]
fn every_way_a_handler_can_refuse_a_sender() {
    for (sender, expect) in [
        (Sender::Greylist, "450 4.7.1 Greylisted\r\n"),
        (Sender::RateLimit, "450 4.7.1 Rate limit exceeded\r\n"),
        (Sender::StorageFull, "452 4.3.1 Insufficient system storage\r\n"),
        (Sender::BlockedDomain, "550 5.7.1 Sender domain blocked\r\n"),
        (Sender::InvalidDomain, "550 5.1.8 Sender domain invalid\r\n"),
        (Sender::Policy, "553 5.7.1 not on our list\r\n"),
        (Sender::Spam, "554 5.7.1 Message rejected as spam\r\n"),
        (Sender::Syntax, "501 5.1.7 Bad sender address syntax\r\n"),
        (Sender::Custom, "471 4.7.1 custom\r\n"),
        (Sender::Shutdown, "421 4.3.2 Service not available\r\n"),
    ] {
        let r = last_reply(Policy { sender, ..Policy::default() }, &["MAIL FROM:<a@b>\r\n"]);
        assert_eq!(r, expect, "{sender:?}");
    }
}

#[test]
fn after_a_refused_sender_the_client_may_try_another() {
    let mut s = server(Policy { sender: Sender::Greylist, ..Policy::default() });
    s.take();
    s.run("EHLO c\r\n");
    assert_eq!(s.run("MAIL FROM:<a@b>\r\n"), "450 4.7.1 Greylisted\r\n");
    assert_eq!(s.run("MAIL FROM:<c@d>\r\n"), "450 4.7.1 Greylisted\r\n", "still in the ready state");
}

// RCPT TO -------------------------------------------------------------------

#[test]
fn every_way_a_handler_can_refuse_a_recipient() {
    for (rcpt, expect) in [
        (Rcpt::Unavailable, "450 4.2.1 Mailbox unavailable\r\n"),
        (Rcpt::NotFound, "550 5.1.1 Mailbox unavailable\r\n"),
        (Rcpt::RelayDenied, "551 5.7.1 Relay denied\r\n"),
        (Rcpt::Policy, "553 5.7.1 not for you\r\n"),
        (Rcpt::Custom, "472 4.7.2 custom\r\n"),
        (Rcpt::Shutdown, "421 4.3.2 Service not available\r\n"),
    ] {
        let r = last_reply(
            Policy { rcpt, ..Policy::default() },
            &["MAIL FROM:<a@b>\r\n", "RCPT TO:<c@d>\r\n"],
        );
        assert_eq!(r, expect, "{rcpt:?}");
    }
}

#[test]
fn a_forwarded_recipient_is_accepted_like_any_other() {
    let r = last_reply(
        Policy { rcpt: Rcpt::Forward, ..Policy::default() },
        &["MAIL FROM:<a@b>\r\n", "RCPT TO:<c@d>\r\n"],
    );
    assert_eq!(r, "250 2.1.5 Recipient OK\r\n");
}

#[test]
fn a_refused_recipient_does_not_spoil_the_transaction() {
    let mut s = server(Policy { rcpt: Rcpt::NotFound, ..Policy::default() });
    s.take();
    s.run("EHLO c\r\nMAIL FROM:<a@b>\r\n");
    assert_eq!(s.run("RCPT TO:<c@d>\r\n"), "550 5.1.1 Mailbox unavailable\r\n");
    assert_eq!(s.run("RSET\r\n"), "250 2.0.0 Reset state\r\n");
    assert_eq!(s.run("MAIL FROM:<a@b>\r\n"), "250 2.1.0 Sender OK\r\n");
}

// DATA ----------------------------------------------------------------------

#[test]
fn a_handler_can_refuse_to_take_the_message_after_data() {
    for (start, expect) in [
        (Start::StorageFull, "452 4.3.1 Insufficient system storage\r\n"),
        (Start::Reject, "550 no messages today\r\n"),
        (Start::Custom, "473 4.7.3 custom\r\n"),
        (Start::Shutdown, "421 4.3.2 Service not available\r\n"),
    ] {
        let r = last_reply(
            Policy { start, ..Policy::default() },
            &["MAIL FROM:<a@b>\r\n", "RCPT TO:<c@d>\r\n", "DATA\r\n"],
        );
        assert_eq!(r, expect, "{start:?}");
    }
}

#[test]
fn a_session_goes_on_after_a_refused_data_command() {
    let mut s = server(Policy { start: Start::Reject, ..Policy::default() });
    s.take();
    s.run("EHLO c\r\nMAIL FROM:<a@b>\r\nRCPT TO:<c@d>\r\n");
    assert_eq!(s.run("DATA\r\n"), "550 no messages today\r\n");
    assert_eq!(s.run("NOOP\r\n"), "250 2.0.0 OK\r\n");
}

// The end of a message --------------------------------------------------------

const TO_END: [&str; 4] = ["MAIL FROM:<a@b>\r\n", "RCPT TO:<c@d>\r\n", "DATA\r\n", "text\r\n.\r\n"];

#[test]
fn every_way_a_handler_can_answer_the_end_of_a_message() {
    for (end, expect) in [
        (End::Accept, "250 2.0.0 Message accepted for delivery\r\n"),
        (End::AcceptQueued, "250 2.0.0 Queued as Q123\r\n"),
        (End::Temporary, "450 busy\r\n"),
        (End::Permanent, "550 no\r\n"),
        (End::Policy, "553 policy says no\r\n"),
        (End::Custom, "474 4.7.4 custom\r\n"),
        (End::Shutdown, "421 4.3.2 Service not available\r\n"),
    ] {
        let r = last_reply(Policy { end, ..Policy::default() }, &TO_END);
        assert_eq!(r, expect, "{end:?}");
    }
}

#[test]
fn a_handler_can_answer_later_either_way() {
    let r = last_reply(Policy { end: End::DeferAccept, ..Policy::default() }, &TO_END);
    assert!(r == "250 2.0.0 Queued as D1\r\n" || r.is_empty(), "{r}");
    let mut s = server(Policy { end: End::DeferReject, ..Policy::default() });
    s.take();
    s.run("EHLO c\r\n");
    for c in &TO_END[..3] {
        s.run(c);
    }
    let mut r = s.run(TO_END[3]);
    for _ in 0..50 {
        if !r.is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
        s.pump();
        r = s.take();
    }
    assert_eq!(r, "471 4.7.1 deferred no\r\n");
}

#[test]
fn another_message_can_follow_a_refused_one() {
    let mut s = server(Policy { end: End::Temporary, ..Policy::default() });
    s.take();
    s.run("EHLO c\r\n");
    for c in &TO_END {
        s.run(c);
    }
    assert_eq!(s.run("MAIL FROM:<a@b>\r\n"), "250 2.1.0 Sender OK\r\n");
}

// RSET and AUTH ---------------------------------------------------------------

#[test]
fn a_handler_can_shut_down_instead_of_resetting() {
    let r = last_reply(Policy { reset: Reset::Shutdown, ..Policy::default() }, &["MAIL FROM:<a@b>\r\n", "RSET\r\n"]);
    assert_eq!(r, "421 4.3.2 Service not available\r\n");
}

fn encrypted(policy: Policy) -> Peer<SmtpControlHandler> {
    let local: SocketAddr = "127.0.0.1:25".parse().unwrap();
    let rt = Arc::new(Runtime::start(hopf_core::RuntimeConfig::default()).unwrap());
    let store = hopf_auth::PasswordStore::new().with_user("alice", "secret").shared();
    let h = SmtpControlHandler::new(
        Box::new(policy),
        SmtpServerMetrics::shared(),
        SmtpConfig::new(local, "mx.example").auth_required(false).with_store(store),
        "192.0.2.5:4000".parse().unwrap(),
        local,
        rt,
    );
    let mut s = Peer::connect(h, |h| h.busy.load(Ordering::SeqCst) || h.pending_finish);
    s.handler.meta.tls = true;
    s.take();
    s.run("EHLO c\r\n");
    s
}

const PLAIN_ALICE: &str = "AUTH PLAIN AGFsaWNlAHNlY3JldA==\r\n";

#[test]
fn a_handler_can_veto_a_good_login() {
    let mut s = encrypted(Policy { auth: Auth::Reject, ..Policy::default() });
    assert_eq!(s.run(PLAIN_ALICE), "535 5.7.8 Authentication credentials invalid\r\n");
    assert!(!s.is_closed());
}

#[test]
fn a_handler_can_veto_a_good_login_and_hang_up() {
    let mut s = encrypted(Policy { auth: Auth::RejectClose, ..Policy::default() });
    assert_eq!(s.run(PLAIN_ALICE), "535 5.7.8 Authentication credentials invalid\r\n");
    assert!(s.is_closed());
}

#[test]
fn a_handler_can_shut_down_after_a_login() {
    let mut s = encrypted(Policy { auth: Auth::Shutdown, ..Policy::default() });
    let r = s.run(PLAIN_ALICE);
    assert!(r.ends_with("421 4.3.2 Service not available\r\n"), "{r}");
}
