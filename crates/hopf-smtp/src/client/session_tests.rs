// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! End-to-end tests of the SMTP client: the test plays the server over an
//! in-process [`Peer`], writing replies and checking the commands the client
//! sends. [`SmtpSend`] is the driver for most of them; a small scripted
//! driver covers the lower-level message-data calls.

use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hopf_core::testing::Peer;
use hopf_core::{Endpoint, Runtime, RuntimeConfig};

use super::endpoint::SmtpClientEndpoint;
use super::handlers::{SmtpClientDriver, SmtpClientHandlerFactory};
use super::pipeline::{SmtpSend, SmtpSendOutcome};
use super::state::{
    MailFromParams, SmtpCapabilities, SmtpClientAuthExchange, SmtpClientEnvelope, SmtpClientHello,
    SmtpClientMessageData, SmtpClientPostTls, SmtpClientSession,
};
use crate::{BodyType, DsnRecipientParams};

type Client = Peer<SmtpClientEndpoint>;

#[derive(Default, Clone)]
struct Results {
    outcomes: Arc<Mutex<Vec<SmtpSendOutcome>>>,
    completes: Arc<Mutex<Vec<bool>>>,
}

impl Results {
    fn only_outcome(&self) -> SmtpSendOutcome {
        let o = self.outcomes.lock().unwrap();
        assert_eq!(o.len(), 1, "expected one outcome, got {o:?}");
        o[0].clone()
    }

    fn none_yet(&self) -> bool {
        self.outcomes.lock().unwrap().is_empty() && self.completes.lock().unwrap().is_empty()
    }
}

fn runtime() -> Arc<Runtime> {
    Arc::new(Runtime::start(RuntimeConfig::default()).unwrap())
}

fn with_results(send: SmtpSend) -> (SmtpSend, Results) {
    let r = Results::default();
    let (o, c) = (Arc::clone(&r.outcomes), Arc::clone(&r.completes));
    let send = send
        .on_result(Box::new(move |out| o.lock().unwrap().push(out)))
        .on_complete(Box::new(move |ok| c.lock().unwrap().push(ok)));
    (send, r)
}

fn connect(send: &SmtpSend) -> Client {
    let ep = SmtpClientEndpoint::new(send, &runtime(), Duration::from_secs(60), Duration::from_secs(600), None, None);
    Peer::connect(ep, |_| false)
}

/// A delivery of `body` from a@b.example to c@d.example.
fn delivery(body: &'static [u8]) -> SmtpSend {
    let mut once = Some(body.to_vec());
    SmtpSend::new("client.example")
        .mail_from("a@b.example")
        .rcpt_to("c@d.example")
        .message_with(move || once.take())
}

const GREETING: &str = "220 server.example ESMTP ready\r\n";
const PLAIN_EHLO: &str = "250 server.example\r\n";
const PIPELINING_EHLO: &str = "250-server.example\r\n250 PIPELINING\r\n";
const CHUNKING_EHLO: &str = "250-server.example\r\n250 CHUNKING\r\n";

/// A session taken as far as a plain, non-pipelining 250 to EHLO.
fn after_ehlo(send: &SmtpSend, ehlo_reply: &str) -> (Client, String) {
    let mut c = connect(send);
    assert_eq!(c.run(GREETING), "EHLO client.example\r\n");
    let sent = c.run(ehlo_reply);
    (c, sent)
}

// The happy path ----------------------------------------------------------

#[test]
fn a_message_goes_through_the_whole_dialogue() {
    let (send, results) = with_results(delivery(b"Subject: hi\r\n\r\nbody\r\n"));
    let mut c = connect(&send);
    assert_eq!(c.take(), "", "the client waits for the greeting");
    assert_eq!(c.run(GREETING), "EHLO client.example\r\n");
    assert_eq!(c.run(PLAIN_EHLO), "MAIL FROM:<a@b.example>\r\n");
    assert_eq!(c.run("250 sender ok\r\n"), "RCPT TO:<c@d.example>\r\n");
    assert_eq!(c.run("250 recipient ok\r\n"), "DATA\r\n");
    assert_eq!(c.run("354 go ahead\r\n"), "Subject: hi\r\n\r\nbody\r\n.\r\n");
    assert!(results.none_yet());
    assert_eq!(c.run("250 2.0.0 queued as ABC123\r\n"), "QUIT\r\n");
    assert!(matches!(results.only_outcome(), SmtpSendOutcome::Delivered));
    assert_eq!(*results.completes.lock().unwrap(), [true]);
    c.run("221 bye\r\n");
    assert!(c.is_closed());
}

#[test]
fn the_hello_name_can_be_left_for_the_client_to_work_out() {
    let send = SmtpSend::new("").mail_from("a@b").rcpt_to("c@d").message_empty();
    let mut c = connect(&send);
    assert_eq!(c.run(GREETING), "EHLO [127.0.0.1]\r\n");
}

#[test]
fn a_whole_exchange_is_the_same_at_every_chunking() {
    let server = format!(
        "{GREETING}{PLAIN_EHLO}250 sender ok\r\n250 recipient ok\r\n354 go\r\n250 2.0.0 queued as XYZ\r\n221 bye\r\n"
    );
    let run = |chunk: usize| {
        let (send, results) = with_results(delivery(b"line\r\n.dot\r\n"));
        let mut c = connect(&send);
        let sent = c.run_chunked(&server, chunk);
        (sent, results.only_outcome().is_delivered(), c.is_closed())
    };
    let whole = run(server.len());
    assert_eq!(
        whole.0,
        "EHLO client.example\r\nMAIL FROM:<a@b.example>\r\nRCPT TO:<c@d.example>\r\nDATA\r\nline\r\n..dot\r\n.\r\nQUIT\r\n"
    );
    assert!(whole.1 && whole.2);
    for chunk in [1, 2, 3, 7, 16] {
        assert_eq!(run(chunk), whole, "chunk {chunk}");
    }
}

impl SmtpSendOutcome {
    fn is_delivered(&self) -> bool {
        matches!(self, SmtpSendOutcome::Delivered)
    }
}

#[test]
fn a_multiline_greeting_and_reply_are_each_one_reply() {
    let (send, _r) = with_results(delivery(b"x\r\n"));
    let mut c = connect(&send);
    assert_eq!(c.run("220-server.example\r\n220-more banner\r\n220 ESMTP\r\n"), "EHLO client.example\r\n");
}

// Pipelining and chunking -------------------------------------------------

#[test]
fn a_server_that_pipelines_gets_the_envelope_and_data_in_one_go() {
    let (send, results) = with_results(delivery(b"hello\r\n"));
    let (mut c, sent) = after_ehlo(&send, PIPELINING_EHLO);
    assert_eq!(sent, "MAIL FROM:<a@b.example>\r\nRCPT TO:<c@d.example>\r\nDATA\r\n");
    // The three replies come back together.
    assert_eq!(c.run("250 ok\r\n250 ok\r\n354 go\r\n"), "hello\r\n.\r\n");
    assert_eq!(c.run("250 queued\r\n"), "QUIT\r\n");
    assert!(results.only_outcome().is_delivered());
}

#[test]
fn replies_to_pipelined_commands_may_arrive_a_byte_at_a_time() {
    let (send, results) = with_results(delivery(b"hello\r\n"));
    let (mut c, _) = after_ehlo(&send, PIPELINING_EHLO);
    let sent = c.run_chunked("250 ok\r\n250 ok\r\n354 go\r\n250 queued\r\n", 1);
    assert_eq!(sent, "hello\r\n.\r\nQUIT\r\n");
    assert!(results.only_outcome().is_delivered());
}

#[test]
fn several_recipients_are_pipelined_together() {
    let send = SmtpSend::new("client.example")
        .mail_from("a@b")
        .recipients(vec!["1@d".into(), "2@d".into(), "3@d".into()])
        .message_empty();
    let (_c, sent) = after_ehlo(&send, PIPELINING_EHLO);
    assert_eq!(sent, "MAIL FROM:<a@b>\r\nRCPT TO:<1@d>\r\nRCPT TO:<2@d>\r\nRCPT TO:<3@d>\r\nDATA\r\n");
}

#[test]
fn without_pipelining_each_command_waits_for_its_reply() {
    let send = SmtpSend::new("client.example")
        .mail_from("a@b")
        .recipients(vec!["1@d".into(), "2@d".into()])
        .message_empty();
    let (mut c, sent) = after_ehlo(&send, PLAIN_EHLO);
    assert_eq!(sent, "MAIL FROM:<a@b>\r\n");
    assert_eq!(c.run("250 ok\r\n"), "RCPT TO:<1@d>\r\n");
    assert_eq!(c.run("250 ok\r\n"), "RCPT TO:<2@d>\r\n");
    assert_eq!(c.run("250 ok\r\n"), "DATA\r\n");
}

#[test]
fn chunking_sends_the_message_as_bdat_with_no_data_command() {
    let (send, results) = with_results(delivery(b"Subject: hi\r\n\r\nbody\r\n"));
    let (mut c, sent) = after_ehlo(&send, CHUNKING_EHLO);
    assert_eq!(sent, "MAIL FROM:<a@b.example>\r\n");
    assert_eq!(c.run("250 ok\r\n"), "RCPT TO:<c@d.example>\r\n");
    assert_eq!(c.run("250 ok\r\n"), "BDAT 21 LAST\r\nSubject: hi\r\n\r\nbody\r\n");
    assert_eq!(c.run("250 queued\r\n"), "QUIT\r\n");
    assert!(results.only_outcome().is_delivered());
}

#[test]
fn bdat_does_not_dot_stuff_its_payload() {
    let (send, _r) = with_results(delivery(b".starts with a dot\r\n"));
    let (mut c, _) = after_ehlo(&send, CHUNKING_EHLO);
    c.run("250 ok\r\n");
    assert_eq!(c.run("250 ok\r\n"), "BDAT 20 LAST\r\n.starts with a dot\r\n");
}

#[test]
fn a_message_in_several_chunks_is_several_bdat_commands() {
    let mut parts = vec![b"first ".to_vec(), b"second ".to_vec(), b"third\r\n".to_vec()].into_iter();
    let send = SmtpSend::new("client.example")
        .mail_from("a@b")
        .rcpt_to("c@d")
        .message_with(move || parts.next());
    let (mut c, _) = after_ehlo(&send, CHUNKING_EHLO);
    c.run("250 ok\r\n");
    assert_eq!(c.run("250 ok\r\n"), "BDAT 6\r\nfirst ");
    assert_eq!(c.run("250 ok\r\n"), "BDAT 7\r\nsecond ");
    assert_eq!(c.run("250 ok\r\n"), "BDAT 7 LAST\r\nthird\r\n");
}

// Dot-stuffing ------------------------------------------------------------

#[test]
fn a_message_is_dot_stuffed_and_ends_with_a_crlf_before_the_terminator() {
    let (send, _r) = with_results(delivery(b"a\r\n.b\r\n..c\r\nno newline at the end"));
    let (mut c, _) = after_ehlo(&send, PLAIN_EHLO);
    c.run("250 ok\r\n");
    c.run("250 ok\r\n");
    assert_eq!(
        c.run("354 go\r\n"),
        "a\r\n..b\r\n...c\r\nno newline at the end\r\n.\r\n"
    );
}

#[test]
fn an_empty_message_is_just_the_terminator() {
    let send = SmtpSend::new("client.example").mail_from("a@b").rcpt_to("c@d").message_empty();
    let (mut c, _) = after_ehlo(&send, PLAIN_EHLO);
    c.run("250 ok\r\n");
    c.run("250 ok\r\n");
    assert_eq!(c.run("354 go\r\n"), ".\r\n");
}

// Things the server can refuse ---------------------------------------------

#[test]
fn a_refusing_greeting_is_a_failure() {
    let (send, results) = with_results(delivery(b"x\r\n"));
    let mut c = connect(&send);
    assert_eq!(c.run("554 no service for you\r\n"), "");
    match results.only_outcome() {
        SmtpSendOutcome::Failed(why) => assert!(why.contains("service unavailable"), "{why}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(*results.completes.lock().unwrap(), [false]);
    assert!(c.is_closed());
}

#[test]
fn a_server_that_is_closing_down_with_421_is_a_failure() {
    let (send, results) = with_results(delivery(b"x\r\n"));
    let (mut c, _) = after_ehlo(&send, PLAIN_EHLO);
    c.run("421 4.3.2 shutting down\r\n");
    assert!(matches!(results.only_outcome(), SmtpSendOutcome::Failed(_)));
    assert!(c.is_closed());
}

#[test]
fn a_banner_that_does_not_say_esmtp_still_gets_ehlo_and_helo_only_if_refused() {
    let (send, _r) = with_results(delivery(b"x\r\n"));
    let mut c = connect(&send);
    assert_eq!(c.run("220 server.example SMTP ready\r\n"), "EHLO client.example\r\n");
    assert_eq!(c.run("502 5.5.1 EHLO not implemented\r\n"), "HELO client.example\r\n");
    assert_eq!(c.run("250 server.example\r\n"), "MAIL FROM:<a@b.example>\r\n");
}

#[test]
fn a_refused_ehlo_is_a_failure() {
    let (send, results) = with_results(delivery(b"x\r\n"));
    let mut c = connect(&send);
    c.run(GREETING);
    c.run("550 go away\r\n");
    assert!(matches!(results.only_outcome(), SmtpSendOutcome::Failed(why) if why.contains("EHLO rejected")));
}

#[test]
fn a_refused_sender_is_reported_with_its_code() {
    let (send, results) = with_results(delivery(b"x\r\n"));
    let (mut c, _) = after_ehlo(&send, PLAIN_EHLO);
    assert_eq!(c.run("550 5.7.1 sender not allowed\r\n"), "QUIT\r\n");
    match results.only_outcome() {
        SmtpSendOutcome::Rejected { code, message } => {
            assert_eq!(code, 550);
            assert!(message.contains("sender not allowed"), "{message}");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn when_every_recipient_is_refused_the_last_refusal_is_reported() {
    let send = SmtpSend::new("client.example")
        .mail_from("a@b")
        .recipients(vec!["1@d".into(), "2@d".into()])
        .message_empty();
    let (send, results) = with_results(send);
    let (mut c, _) = after_ehlo(&send, PLAIN_EHLO);
    c.run("250 ok\r\n");
    assert_eq!(c.run("550 no such user\r\n"), "RCPT TO:<2@d>\r\n");
    assert_eq!(c.run("551 user not local\r\n"), "RSET\r\n");
    assert_eq!(c.run("250 reset\r\n"), "QUIT\r\n");
    match results.only_outcome() {
        SmtpSendOutcome::Rejected { code, message } => {
            assert_eq!(code, 551);
            assert!(message.contains("2@d") && message.contains("not local"), "{message}");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_message_goes_to_the_recipients_that_were_accepted() {
    let send = SmtpSend::new("client.example")
        .mail_from("a@b")
        .recipients(vec!["1@d".into(), "2@d".into()])
        .message_with({
            let mut once = Some(b"hi\r\n".to_vec());
            move || once.take()
        });
    let (send, results) = with_results(send);
    let (mut c, _) = after_ehlo(&send, PLAIN_EHLO);
    c.run("250 ok\r\n");
    c.run("550 no such user\r\n");
    assert_eq!(c.run("250 ok\r\n"), "DATA\r\n");
    assert_eq!(c.run("354 go\r\n"), "hi\r\n.\r\n");
    c.run("250 queued\r\n");
    assert!(results.only_outcome().is_delivered());
}

#[test]
fn a_refused_data_command_is_reported() {
    let (send, results) = with_results(delivery(b"x\r\n"));
    let (mut c, _) = after_ehlo(&send, PLAIN_EHLO);
    c.run("250 ok\r\n");
    c.run("250 ok\r\n");
    assert_eq!(c.run("554 5.5.1 no valid recipients\r\n"), "QUIT\r\n");
    assert!(matches!(results.only_outcome(), SmtpSendOutcome::Rejected { code: 554, .. }));
}

#[test]
fn a_message_refused_after_the_text_is_reported_with_its_code() {
    let (send, results) = with_results(delivery(b"x\r\n"));
    let (mut c, _) = after_ehlo(&send, PLAIN_EHLO);
    c.run("250 ok\r\n");
    c.run("250 ok\r\n");
    c.run("354 go\r\n");
    assert_eq!(c.run("552 5.3.4 message too big\r\n"), "QUIT\r\n");
    assert!(matches!(results.only_outcome(), SmtpSendOutcome::Rejected { code: 552, .. }));
    assert_eq!(*results.completes.lock().unwrap(), [false]);
}

#[test]
fn a_temporary_refusal_keeps_its_four_hundred_code() {
    let (send, results) = with_results(delivery(b"x\r\n"));
    let (mut c, _) = after_ehlo(&send, PLAIN_EHLO);
    c.run("250 ok\r\n");
    c.run("250 ok\r\n");
    c.run("354 go\r\n");
    c.run("452 4.2.2 mailbox full\r\n");
    assert!(matches!(results.only_outcome(), SmtpSendOutcome::Rejected { code: 452, .. }));
}

#[test]
fn a_bdat_message_refused_part_way_is_reported() {
    let mut parts = vec![b"one".to_vec(), b"two".to_vec()].into_iter();
    let send = SmtpSend::new("client.example").mail_from("a@b").rcpt_to("c@d").message_with(move || parts.next());
    let (send, results) = with_results(send);
    let (mut c, _) = after_ehlo(&send, CHUNKING_EHLO);
    c.run("250 ok\r\n");
    c.run("250 ok\r\n");
    assert_eq!(c.run("552 too big\r\n"), "QUIT\r\n");
    assert!(matches!(results.only_outcome(), SmtpSendOutcome::Rejected { code: 552, .. }));
}

// Envelope parameters -----------------------------------------------------

#[test]
fn mail_parameters_are_sent_after_the_address() {
    let params = MailFromParams {
        size: Some(100),
        body: Some(BodyType::EightBitMime),
        smtputf8: true,
        ..Default::default()
    };
    let send = SmtpSend::new("client.example").mail_from_params(params).mail_from("a@b").rcpt_to("c@d").message_empty();
    let (_c, sent) = after_ehlo(&send, "250-server.example\r\n250-8BITMIME\r\n250 SIZE 1000\r\n");
    assert_eq!(sent, "MAIL FROM:<a@b> SIZE=100 BODY=8BITMIME SMTPUTF8\r\n");
}

#[test]
fn a_message_bigger_than_the_servers_limit_is_not_even_offered() {
    let params = MailFromParams { size: Some(5000), ..Default::default() };
    let send = SmtpSend::new("client.example").mail_from_params(params).mail_from("a@b").rcpt_to("c@d").message_empty();
    let (send, results) = with_results(send);
    let (_c, sent) = after_ehlo(&send, "250-server.example\r\n250 SIZE 1000\r\n");
    assert_eq!(sent, "QUIT\r\n");
    assert!(matches!(results.only_outcome(), SmtpSendOutcome::Failed(why) if why.contains("exceeds")));
}

#[test]
fn the_null_sender_is_written_as_empty_brackets() {
    let send = SmtpSend::new("client.example").mail_from("").rcpt_to("c@d").message_empty();
    let (_c, sent) = after_ehlo(&send, PLAIN_EHLO);
    assert_eq!(sent, "MAIL FROM:<>\r\n");
}

#[test]
fn dsn_recipient_parameters_are_sent_only_to_a_server_that_offers_dsn() {
    let dsn = DsnRecipientParams {
        notify: crate::DsnNotify { failure: true, ..Default::default() },
        orcpt_type: Some("rfc822".into()),
        orcpt_address: Some("orig@x".into()),
    };
    let mk = || SmtpSend::new("client.example").mail_from("a@b").rcpt_to_with("c@d", dsn.clone()).message_empty();
    let (mut c, _) = after_ehlo(&mk(), PLAIN_EHLO);
    assert_eq!(c.run("250 ok\r\n"), "RCPT TO:<c@d>\r\n", "no DSN offered");
    let (mut c, _) = after_ehlo(&mk(), "250-server.example\r\n250 DSN\r\n");
    let sent = c.run("250 ok\r\n");
    assert!(sent.starts_with("RCPT TO:<c@d> ") && sent.contains("NOTIFY=FAILURE") && sent.contains("ORCPT=rfc822;"), "{sent}");
}

#[test]
fn requiretls_and_binarymime_need_the_servers_support() {
    let params = MailFromParams { require_tls: true, ..Default::default() };
    let send = SmtpSend::new("client.example").mail_from_params(params).mail_from("a@b").rcpt_to("c@d").message_empty();
    let (send, results) = with_results(send);
    let (_c, sent) = after_ehlo(&send, PLAIN_EHLO);
    assert_eq!(sent, "QUIT\r\n");
    // REQUIRETLS needs the next hop's TLS first.
    assert!(matches!(results.only_outcome(), SmtpSendOutcome::Failed(why) if why.contains("STARTTLS")));

    let params = MailFromParams { body: Some(BodyType::BinaryMime), ..Default::default() };
    let send = SmtpSend::new("client.example").mail_from_params(params).mail_from("a@b").rcpt_to("c@d").message_empty();
    let (send, results) = with_results(send);
    let (_c, sent) = after_ehlo(&send, "250-server.example\r\n250 BINARYMIME\r\n");
    assert_eq!(sent, "QUIT\r\n");
    assert!(matches!(results.only_outcome(), SmtpSendOutcome::Failed(why) if why.contains("BINARYMIME")));
}

// STARTTLS and AUTH ---------------------------------------------------------

#[test]
fn required_starttls_that_the_server_does_not_offer_is_a_failure() {
    let send = delivery(b"x\r\n").require_starttls(true);
    let (send, results) = with_results(send);
    let (_c, sent) = after_ehlo(&send, PLAIN_EHLO);
    assert_eq!(sent, "QUIT\r\n");
    assert!(matches!(results.only_outcome(), SmtpSendOutcome::Failed(why) if why.contains("STARTTLS")));
}

#[test]
fn starttls_is_asked_for_when_required_and_offered() {
    let send = delivery(b"x\r\n").require_starttls(true);
    let (_c, sent) = after_ehlo(&send, "250-server.example\r\n250 STARTTLS\r\n");
    assert_eq!(sent, "STARTTLS\r\n");
}

#[test]
fn a_refused_starttls_that_was_required_is_a_failure() {
    let send = delivery(b"x\r\n").require_starttls(true);
    let (send, results) = with_results(send);
    let (mut c, _) = after_ehlo(&send, "250-server.example\r\n250 STARTTLS\r\n");
    assert_eq!(c.run("454 4.7.0 TLS not available\r\n"), "QUIT\r\n");
    assert!(matches!(results.only_outcome(), SmtpSendOutcome::Failed(why) if why.contains("STARTTLS")));
}

#[test]
fn plain_auth_sends_its_credentials_in_the_command() {
    let send = delivery(b"x\r\n").auth_plain("alice", "secret");
    let (mut c, sent) = after_ehlo(&send, "250-server.example\r\n250 AUTH PLAIN\r\n");
    assert_eq!(sent, "AUTH PLAIN AGFsaWNlAHNlY3JldA==\r\n");
    assert_eq!(c.run("235 2.7.0 welcome\r\n"), "MAIL FROM:<a@b.example>\r\n");
}

#[test]
fn login_auth_answers_each_prompt() {
    let send = delivery(b"x\r\n").auth_plain("alice", "secret");
    let (mut c, sent) = after_ehlo(&send, "250-server.example\r\n250 AUTH LOGIN\r\n");
    assert_eq!(sent, "AUTH LOGIN\r\n");
    assert_eq!(c.run("334 VXNlcm5hbWU6\r\n"), "YWxpY2U=\r\n");
    assert_eq!(c.run("334 UGFzc3dvcmQ6\r\n"), "c2VjcmV0\r\n");
    assert_eq!(c.run("235 2.7.0 welcome\r\n"), "MAIL FROM:<a@b.example>\r\n");
}

#[test]
fn refused_credentials_are_a_failure_with_the_code() {
    let send = delivery(b"x\r\n").auth_plain("alice", "wrong");
    let (send, results) = with_results(send);
    let (mut c, _) = after_ehlo(&send, "250-server.example\r\n250 AUTH PLAIN\r\n");
    assert_eq!(c.run("535 5.7.8 bad credentials\r\n"), "QUIT\r\n");
    assert!(matches!(results.only_outcome(), SmtpSendOutcome::Rejected { code: 535, .. }));
}

#[test]
fn credentials_with_no_common_mechanism_are_a_failure_not_an_unauthenticated_send() {
    let send = delivery(b"x\r\n").auth_plain("alice", "secret");
    let (send, results) = with_results(send);
    let (_c, sent) = after_ehlo(&send, PLAIN_EHLO);
    assert_eq!(sent, "QUIT\r\n");
    assert!(matches!(results.only_outcome(), SmtpSendOutcome::Failed(_)));
}

// Losing the connection -----------------------------------------------------

#[test]
fn a_server_that_hangs_up_mid_session_is_reported_as_a_failure() {
    let (send, results) = with_results(delivery(b"x\r\n"));
    let (mut c, _) = after_ehlo(&send, PLAIN_EHLO);
    c.run("250 ok\r\n");
    c.disconnect();
    assert!(matches!(results.only_outcome(), SmtpSendOutcome::Failed(_)), "the caller must hear about it");
    assert_eq!(*results.completes.lock().unwrap(), [false]);
}

#[test]
fn hanging_up_after_the_result_is_not_a_second_result() {
    let (send, results) = with_results(delivery(b"x\r\n"));
    let (mut c, _) = after_ehlo(&send, PLAIN_EHLO);
    for reply in ["250 ok\r\n", "250 ok\r\n", "354 go\r\n", "250 queued\r\n", "221 bye\r\n"] {
        c.run(reply);
    }
    c.disconnect();
    assert!(results.only_outcome().is_delivered());
    assert_eq!(*results.completes.lock().unwrap(), [true]);
}

#[test]
fn a_connection_error_is_a_failure() {
    let (send, results) = with_results(delivery(b"x\r\n"));
    let (mut c, _) = after_ehlo(&send, PLAIN_EHLO);
    c.fail(&io::Error::new(io::ErrorKind::ConnectionReset, "reset"));
    match results.only_outcome() {
        SmtpSendOutcome::Failed(why) => assert!(why.contains("reset"), "{why}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_stage_timeout_is_a_failure_and_closes_the_connection() {
    let (send, results) = with_results(delivery(b"x\r\n"));
    let (mut c, _) = after_ehlo(&send, PLAIN_EHLO);
    c.fail(&io::Error::new(io::ErrorKind::TimedOut, "slow"));
    assert!(matches!(results.only_outcome(), SmtpSendOutcome::Failed(why) if why.contains("timed out")));
    assert!(c.is_closed());
}

#[test]
fn a_reply_that_is_not_smtp_is_a_protocol_failure() {
    let (send, results) = with_results(delivery(b"x\r\n"));
    let mut c = connect(&send);
    c.run("this is not an smtp server\r\n");
    assert!(matches!(results.only_outcome(), SmtpSendOutcome::Failed(_)));
    assert!(c.is_closed());
}

// The message-data calls a custom driver uses --------------------------------

/// A driver that sends one message whose text it writes in the given pieces.
struct PiecesDriver {
    pieces: Vec<&'static [u8]>,
    done: Arc<Mutex<Vec<String>>>,
}

struct PiecesFactory {
    pieces: Vec<&'static [u8]>,
    done: Arc<Mutex<Vec<String>>>,
}

impl SmtpClientHandlerFactory for PiecesFactory {
    fn create(&self, _runtime: &Arc<Runtime>) -> Box<dyn SmtpClientDriver> {
        Box::new(PiecesDriver { pieces: self.pieces.clone(), done: Arc::clone(&self.done) })
    }
}

impl SmtpClientDriver for PiecesDriver {
    fn on_greeting(&mut self, hello: &mut dyn SmtpClientHello, _ep: &mut dyn Endpoint, _esmtp: bool) {
        hello.ehlo("client.example");
    }
    fn on_service_unavailable(&mut self, _ep: &mut dyn Endpoint, _m: &str) {}
    fn on_ehlo(&mut self, s: &mut dyn SmtpClientSession, _ep: &mut dyn Endpoint, _c: &SmtpCapabilities) {
        s.mail_from(Some("a@b"), &MailFromParams::default());
    }
    fn on_ehlo_not_supported(&mut self, _s: &mut dyn SmtpClientSession, _ep: &mut dyn Endpoint) {}
    fn on_ehlo_error(&mut self, _ep: &mut dyn Endpoint, _m: &str) {}
    fn on_helo(&mut self, _s: &mut dyn SmtpClientSession, _ep: &mut dyn Endpoint) {}
    fn on_helo_error(&mut self, _ep: &mut dyn Endpoint, _m: &str) {}
    fn on_tls_established(&mut self, _p: &mut dyn SmtpClientPostTls, _ep: &mut dyn Endpoint) {}
    fn on_tls_unavailable(&mut self, _s: &mut dyn SmtpClientSession, _ep: &mut dyn Endpoint) {}
    fn on_tls_error(&mut self, _ep: &mut dyn Endpoint, _m: &str) {}
    fn on_auth_ok(&mut self, _s: &mut dyn SmtpClientSession, _ep: &mut dyn Endpoint) {}
    fn on_auth_challenge(&mut self, _x: &mut dyn SmtpClientAuthExchange, _ep: &mut dyn Endpoint, _c: &[u8]) {}
    fn on_auth_failed(&mut self, _s: &mut dyn SmtpClientSession, _ep: &mut dyn Endpoint, _c: u16) {}
    fn on_auth_aborted(&mut self, _s: &mut dyn SmtpClientSession, _ep: &mut dyn Endpoint) {}
    fn on_mail_ok(&mut self, e: &mut dyn SmtpClientEnvelope, _ep: &mut dyn Endpoint) {
        e.rcpt_to("c@d", &DsnRecipientParams::default());
    }
    fn on_mail_rejected(&mut self, _s: &mut dyn SmtpClientSession, _ep: &mut dyn Endpoint, _c: u16, _m: &str) {}
    fn on_rcpt_ok(&mut self, e: &mut dyn SmtpClientEnvelope, _ep: &mut dyn Endpoint, _r: &str) {
        e.start_data();
    }
    fn on_rcpt_rejected(&mut self, _e: &mut dyn SmtpClientEnvelope, _ep: &mut dyn Endpoint, _r: &str, _c: u16, _m: &str) {}
    fn on_ready_for_data(&mut self, data: &mut dyn SmtpClientMessageData, _ep: &mut dyn Endpoint) {
        if data.is_bdat_mode() {
            let n = self.pieces.len();
            for (i, p) in self.pieces.iter().enumerate() {
                data.write_bdat_chunk(p, i + 1 == n);
            }
            return;
        }
        for p in &self.pieces {
            data.write_content(p);
        }
        data.end_message();
    }
    fn on_bdat_chunk_ok(&mut self, _d: &mut dyn SmtpClientMessageData, _ep: &mut dyn Endpoint) {}
    fn on_data_rejected(&mut self, _e: &mut dyn SmtpClientEnvelope, _ep: &mut dyn Endpoint, _c: u16, _m: &str) {}
    fn on_message_accepted(&mut self, s: &mut dyn SmtpClientSession, _ep: &mut dyn Endpoint, q: Option<&str>) {
        self.done.lock().unwrap().push(format!("accepted {}", q.unwrap_or("-")));
        s.quit();
    }
    fn on_message_rejected(&mut self, _s: &mut dyn SmtpClientSession, _ep: &mut dyn Endpoint, c: u16, _m: &str) {
        self.done.lock().unwrap().push(format!("rejected {c}"));
    }
    fn on_rset_ok(&mut self, _s: &mut dyn SmtpClientSession, _ep: &mut dyn Endpoint) {}
    fn on_vrfy_ok(&mut self, _s: &mut dyn SmtpClientSession, _ep: &mut dyn Endpoint, _c: u16, _t: &str) {}
    fn on_vrfy_failed(&mut self, _s: &mut dyn SmtpClientSession, _ep: &mut dyn Endpoint, _c: u16, _m: &str) {}
    fn on_expn_ok(&mut self, _s: &mut dyn SmtpClientSession, _ep: &mut dyn Endpoint, _m: &[String]) {}
    fn on_expn_failed(&mut self, _s: &mut dyn SmtpClientSession, _ep: &mut dyn Endpoint, _c: u16, _m: &str) {}
    fn on_error(&mut self, _ep: &mut dyn Endpoint, _e: &io::Error) {}
    fn on_timeout(&mut self, _ep: &mut dyn Endpoint) {}
    fn on_disconnected(&mut self, _ep: &mut dyn Endpoint) {}
}

/// What the client puts on the wire after `354`, for text written in `pieces`.
fn data_sent_for(pieces: Vec<&'static [u8]>) -> String {
    let done = Arc::new(Mutex::new(Vec::new()));
    let factory = PiecesFactory { pieces, done };
    let ep = SmtpClientEndpoint::new(&factory, &runtime(), Duration::from_secs(60), Duration::from_secs(600), None, None);
    let mut c = Peer::connect(ep, |_| false);
    c.run(GREETING);
    c.run(PLAIN_EHLO);
    c.run("250 ok\r\n");
    c.run("250 ok\r\n");
    c.run("354 go\r\n")
}

#[test]
fn text_written_in_pieces_arrives_as_the_same_text() {
    let whole = data_sent_for(vec![b"Subject: hi\r\n\r\nline one\r\nline two\r\n"]);
    assert_eq!(whole, "Subject: hi\r\n\r\nline one\r\nline two\r\n.\r\n");
    // Pieces that stop in the middle of a line, or between the CR and the LF.
    assert_eq!(data_sent_for(vec![b"Subject: hi\r\n\r\nli", b"ne one\r\nline two\r\n"]), whole);
    assert_eq!(data_sent_for(vec![b"Subject: hi\r", b"\n\r\nline one\r\nline two", b"\r\n"]), whole);
    assert_eq!(data_sent_for(vec![b"Subject: hi\r\n\r\nline one\r\n", b"line two\r\n"]), whole);
}

#[test]
fn a_dot_at_the_start_of_a_piece_is_stuffed_only_at_the_start_of_a_line() {
    // ".b" continues a line, so its dot is not stuffed; ".c" starts one.
    assert_eq!(data_sent_for(vec![b"a", b".b\r\n", b".c\r\n"]), "a.b\r\n..c\r\n.\r\n");
}
