// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! End-to-end tests of the SMTP server session: the test plays the client
//! over an in-process [`Peer`] and checks every reply. A child of `control`
//! so it can reach the handler's private state.

use super::*;
use crate::server::handler::AcceptAllSmtpHandler;
use hopf_core::testing::Peer;

type Session = Peer<SmtpControlHandler>;
type Capture = Arc<Mutex<Vec<u8>>>;

fn session(config: impl FnOnce(SmtpConfig) -> SmtpConfig) -> (Session, Capture) {
    let capture = Arc::new(Mutex::new(Vec::new()));
    let local: SocketAddr = "127.0.0.1:25".parse().unwrap();
    let remote: SocketAddr = "192.0.2.5:40000".parse().unwrap();
    let rt = Arc::new(Runtime::start(hopf_core::RuntimeConfig::default()).unwrap());
    let cfg = config(SmtpConfig::new(local, "mx.example").auth_required(false));
    let h = SmtpControlHandler::new(
        Box::new(AcceptAllSmtpHandler::new("mx.example").with_capture(Arc::clone(&capture))),
        SmtpServerMetrics::shared(),
        cfg,
        remote,
        local,
        rt,
    );
    let peer = Peer::connect(h, |h| h.busy.load(Ordering::SeqCst) || h.pending_finish);
    (peer, capture)
}

/// A session past the greeting and EHLO.
fn ready(config: impl FnOnce(SmtpConfig) -> SmtpConfig) -> (Session, Capture) {
    let (mut s, cap) = session(config);
    s.take();
    s.run("EHLO client.example\r\n");
    (s, cap)
}

/// A session with `MAIL` and `RCPT` accepted.
fn with_recipient() -> (Session, Capture) {
    let (mut s, cap) = ready(|c| c);
    s.run("MAIL FROM:<a@b.example>\r\nRCPT TO:<c@d.example>\r\n");
    (s, cap)
}

fn captured(cap: &Capture) -> String {
    String::from_utf8_lossy(&cap.lock().unwrap()).into_owned()
}

/// Runs each command and joins the replies.
fn transcript(s: &mut Session, commands: &[&str]) -> Vec<String> {
    commands.iter().map(|c| s.run(c)).collect()
}

const EHLO_REPLY_END: &str = "250 HELP\r\n";

// Greeting and hello -------------------------------------------------------

#[test]
fn the_server_speaks_first() {
    let (mut s, _) = session(|c| c);
    assert_eq!(s.take(), "220 mx.example ESMTP Hopf\r\n");
}

#[test]
fn ehlo_lists_the_extensions_this_server_has() {
    let (mut s, _) = session(|c| c);
    s.take();
    let r = s.run("EHLO client.example\r\n");
    assert!(r.starts_with("250-mx.example Hello client.example\r\n"), "{r}");
    for line in [
        "250-SIZE 36700160\r\n",
        "250-PIPELINING\r\n",
        "250-8BITMIME\r\n",
        "250-SMTPUTF8\r\n",
        "250-ENHANCEDSTATUSCODES\r\n",
        "250-CHUNKING\r\n",
        "250-BINARYMIME\r\n",
        "250-DSN\r\n",
        "250-LIMITS RCPTMAX=100 MAILMAX=100\r\n",
    ] {
        assert!(r.contains(line), "missing {line:?} in {r:?}");
    }
    assert!(r.ends_with(EHLO_REPLY_END), "{r}");
    assert!(!r.contains("STARTTLS") && !r.contains("AUTH"), "nothing to offer yet: {r}");
}

#[test]
fn ehlo_advertises_the_configured_limits() {
    let (mut s, _) = session(|mut c| {
        c.max_message_size = 1000;
        c.max_recipients = 7;
        c.with_max_mail_transactions(3)
    });
    s.take();
    let r = s.run("EHLO c\r\n");
    assert!(r.contains("250-SIZE 1000\r\n") && r.contains("250-LIMITS RCPTMAX=7 MAILMAX=3\r\n"), "{r}");
}

#[test]
fn helo_gets_a_plain_reply_and_hello_needs_a_name() {
    let (mut s, _) = session(|c| c);
    s.take();
    assert_eq!(s.run("HELO client.example\r\n"), "250 mx.example Hello client.example\r\n");
    assert_eq!(s.run("HELO\r\n"), "501 5.5.4 Syntax: HELO hostname\r\n");
    assert_eq!(s.run("EHLO\r\n"), "501 5.5.4 Syntax: EHLO hostname\r\n");
}

#[test]
fn hello_may_be_said_again() {
    let (mut s, _) = session(|c| c);
    s.take();
    s.run("EHLO a\r\n");
    s.run("MAIL FROM:<x@y>\r\n");
    assert!(s.run("EHLO b\r\n").starts_with("250-mx.example Hello b\r\n"));
}

#[test]
fn verbs_are_not_case_sensitive() {
    let (mut s, _) = session(|c| c);
    s.take();
    assert!(s.run("ehlo c\r\n").starts_with("250-"));
    assert_eq!(s.run("mail from:<a@b>\r\n"), "250 2.1.0 Sender OK\r\n");
    assert_eq!(s.run("rcpt to:<c@d>\r\n"), "250 2.1.5 Recipient OK\r\n");
    assert_eq!(s.run("quit\r\n"), "221 2.0.0 Bye\r\n");
}

#[test]
fn mail_data_and_bdat_need_a_hello_first() {
    let (mut s, _) = session(|c| c);
    s.take();
    assert_eq!(
        transcript(&mut s, &["MAIL FROM:<a@b>\r\n", "RCPT TO:<a@b>\r\n", "DATA\r\n", "BDAT 1\r\n"]),
        [
            "503 5.5.1 Bad sequence of commands\r\n",
            "503 5.5.1 Bad sequence of commands\r\n",
            "503 5.5.1 Bad sequence of commands\r\n",
            "503 5.5.1 BDAT requires EHLO\r\n",
        ]
    );
}

#[test]
fn the_housekeeping_commands_work_at_any_time() {
    let (mut s, _) = session(|c| c);
    s.take();
    assert_eq!(s.run("NOOP\r\n"), "250 2.0.0 OK\r\n");
    assert_eq!(s.run("RSET\r\n"), "250 2.0.0 Reset state\r\n");
    assert!(s.run("VRFY someone\r\n").starts_with("252 2.0.0 Cannot VRFY user"));
    assert_eq!(s.run("EXPN list\r\n"), "502 5.5.1 EXPN not implemented\r\n");
    let help = s.run("HELP\r\n");
    assert!(help.starts_with("214-") && help.ends_with("214 End of HELP\r\n"), "{help}");
}

#[test]
fn an_unknown_verb_is_refused_and_the_session_goes_on() {
    let (mut s, _) = ready(|c| c);
    assert_eq!(s.run("BOGUS\r\n"), "500 5.5.2 Command unrecognized\r\n");
    assert_eq!(s.run("NOOP\r\n"), "250 2.0.0 OK\r\n");
}

#[test]
fn a_command_line_that_is_far_too_long_is_refused_and_the_session_goes_on() {
    let (mut s, _) = ready(|c| c);
    assert_eq!(s.run(&format!("NOOP {}\r\n", "x".repeat(70_000))), "500 5.5.2 Line too long\r\n");
    assert_eq!(s.run("NOOP\r\n"), "250 2.0.0 OK\r\n");
}

#[test]
fn quit_says_goodbye_and_closes() {
    let (mut s, _) = ready(|c| c);
    assert_eq!(s.run("QUIT\r\n"), "221 2.0.0 Bye\r\n");
    assert!(s.is_closed());
}

#[test]
fn starttls_is_refused_when_there_is_nothing_to_start() {
    let (mut s, _) = ready(|c| c);
    assert_eq!(s.run("STARTTLS\r\n"), "454 4.7.0 TLS not available\r\n");
}

// MAIL FROM ---------------------------------------------------------------

fn mail_reply(args: &str) -> String {
    let (mut s, _) = ready(|c| c);
    s.run(&format!("MAIL FROM:{args}\r\n"))
}

#[test]
fn mail_from_accepts_a_sender_or_the_null_sender() {
    assert_eq!(mail_reply("<a@b.example>"), "250 2.1.0 Sender OK\r\n");
    assert_eq!(mail_reply("<>"), "250 2.1.0 Sender OK\r\n");
}

#[test]
fn mail_from_checks_its_syntax() {
    assert_eq!(mail_reply("<a@b"), "501 5.5.4 Unclosed angle-addr\r\n");
    assert_eq!(mail_reply("<a b@c>"), "501 5.1.7 Bad sender address syntax\r\n");
    let (mut s, _) = ready(|c| c);
    assert_eq!(s.run("MAIL\r\n"), "501 5.5.4 Syntax: MAIL FROM:<address>\r\n");
}

#[test]
fn mail_from_checks_its_parameters() {
    for (arg, reply) in [
        ("<a@b> SIZE=abc", "501 5.5.4 Invalid SIZE parameter\r\n"),
        ("<a@b> BODY=XYZ", "501 5.5.4 Invalid BODY parameter\r\n"),
        ("<a@b> RET=BAD", "501 5.5.4 Invalid RET parameter\r\n"),
        ("<a@b> BY=60;X", "501 5.5.4 Invalid BY parameter\r\n"),
        ("<a@b> BY=abc;R", "501 5.5.4 Invalid BY parameter\r\n"),
        ("<a@b> BY=-5;R", "501 5.5.4 DELIVERBY deadline has already passed\r\n"),
        ("<a@b> MT-PRIORITY=99", "501 5.5.4 MT-PRIORITY must be between -9 and 9\r\n"),
    ] {
        assert_eq!(mail_reply(arg), reply, "{arg}");
    }
}

#[test]
fn mail_from_accepts_the_parameters_it_advertises() {
    for arg in [
        "<a@b> SIZE=100",
        "<a@b> BODY=8BITMIME",
        "<a@b> SMTPUTF8",
        "<a@b> RET=HDRS ENVID=abc",
        "<a@b> MT-PRIORITY=3",
        "<a@b> BY=60;R",
        "<a@b> BY=60;NT",
        "<a@b> BY=60R",
    ] {
        assert_eq!(mail_reply(arg), "250 2.1.0 Sender OK\r\n", "{arg}");
    }
}

#[test]
fn a_declared_size_over_the_limit_is_refused_at_once() {
    for arg in ["<a@b> SIZE=36700161", "<a@b> SIZE=99999999999"] {
        assert_eq!(mail_reply(arg), "552 5.3.4 Message size exceeds fixed maximum\r\n", "{arg}");
    }
}

#[test]
fn requiretls_needs_a_secure_session() {
    assert_eq!(
        mail_reply("<a@b> REQUIRETLS"),
        "530 5.7.10 REQUIRETLS requires a TLS-protected session\r\n"
    );
}

#[test]
fn a_second_mail_in_one_transaction_is_out_of_sequence() {
    let (mut s, _) = ready(|c| c);
    assert_eq!(s.run("MAIL FROM:<a@b>\r\n"), "250 2.1.0 Sender OK\r\n");
    assert_eq!(s.run("MAIL FROM:<c@d>\r\n"), "503 5.5.1 Bad sequence of commands\r\n");
}

#[test]
fn rset_abandons_a_transaction_so_mail_can_start_again() {
    let (mut s, _) = with_recipient();
    assert_eq!(s.run("RSET\r\n"), "250 2.0.0 Reset state\r\n");
    assert_eq!(s.run("RCPT TO:<c@d>\r\n"), "503 5.5.1 Bad sequence of commands\r\n");
    assert_eq!(s.run("MAIL FROM:<a@b>\r\n"), "250 2.1.0 Sender OK\r\n");
}

#[test]
fn mail_is_refused_until_the_client_has_authenticated_when_that_is_required() {
    let (mut s, _) = ready(|c| c.auth_required(true));
    assert_eq!(s.run("MAIL FROM:<a@b>\r\n"), "530 5.7.0 Authentication required\r\n");
}

#[test]
fn the_number_of_mail_commands_is_limited() {
    let (mut s, _) = ready(|c| c.with_max_mail_transactions(2));
    for _ in 0..2 {
        assert_eq!(s.run("MAIL FROM:<a@b>\r\n"), "250 2.1.0 Sender OK\r\n");
        s.run("RSET\r\n");
    }
    assert_eq!(s.run("MAIL FROM:<a@b>\r\n"), "452 4.5.3 Too many MAIL transactions in this session\r\n");
    assert_eq!(s.run("NOOP\r\n"), "250 2.0.0 OK\r\n");
}

// RCPT TO -----------------------------------------------------------------

#[test]
fn rcpt_needs_a_mail_first() {
    let (mut s, _) = ready(|c| c);
    assert_eq!(s.run("RCPT TO:<c@d>\r\n"), "503 5.5.1 Bad sequence of commands\r\n");
}

#[test]
fn rcpt_accepts_any_number_up_to_the_limit_and_then_defers() {
    let (mut s, _) = ready(|mut c| {
        c.max_recipients = 2;
        c
    });
    s.run("MAIL FROM:<a@b>\r\n");
    assert_eq!(s.run("RCPT TO:<1@d>\r\n"), "250 2.1.5 Recipient OK\r\n");
    assert_eq!(s.run("RCPT TO:<2@d>\r\n"), "250 2.1.5 Recipient OK\r\n");
    assert_eq!(s.run("RCPT TO:<3@d>\r\n"), "452 4.5.3 Too many recipients\r\n");
}

#[test]
fn rcpt_checks_the_address_and_the_dsn_parameters() {
    let (mut s, _) = ready(|c| c);
    s.run("MAIL FROM:<a@b>\r\n");
    for (cmd, reply) in [
        ("RCPT TO:<>\r\n", "501 5.5.4 Empty recipient address\r\n"),
        ("RCPT TO:<postmaster>\r\n", "501 5.1.3 Bad recipient address syntax\r\n"),
        ("RCPT TO:<c@d> NOTIFY=BOGUS\r\n", "501 5.5.4 Invalid NOTIFY parameter\r\n"),
        (
            "RCPT TO:<c@d> NOTIFY=NEVER,SUCCESS\r\n",
            "501 5.5.4 NOTIFY=NEVER cannot be combined with other values\r\n",
        ),
        ("RCPT TO:<c@d> ORCPT=bad\r\n", "501 5.5.4 Invalid ORCPT syntax (expected type;address)\r\n"),
        ("RCPT TO:<c@d> NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;c@d\r\n", "250 2.1.5 Recipient OK\r\n"),
    ] {
        assert_eq!(s.run(cmd), reply, "{cmd}");
    }
}

#[test]
fn the_same_recipient_may_be_given_twice() {
    let (mut s, _) = ready(|c| c);
    s.run("MAIL FROM:<a@b>\r\n");
    assert_eq!(s.run("RCPT TO:<c@d>\r\n"), "250 2.1.5 Recipient OK\r\n");
    assert_eq!(s.run("RCPT TO:<c@d>\r\n"), "250 2.1.5 Recipient OK\r\n");
}

// DATA --------------------------------------------------------------------

#[test]
fn data_needs_a_recipient() {
    let (mut s, _) = ready(|c| c);
    assert_eq!(s.run("DATA\r\n"), "503 5.5.1 Bad sequence of commands\r\n");
    s.run("MAIL FROM:<a@b>\r\n");
    assert_eq!(s.run("DATA\r\n"), "503 5.5.1 Need RCPT (recipient)\r\n");
}

#[test]
fn a_message_is_delivered_with_its_dots_unstuffed() {
    let (mut s, cap) = with_recipient();
    assert_eq!(s.run("DATA\r\n"), "354 Start mail input; end with <CRLF>.<CRLF>\r\n");
    assert_eq!(
        s.run("Subject: hi\r\n\r\n.dot\r\n..x\r\nbody\r\n.\r\n"),
        "250 2.0.0 Message accepted for delivery\r\n"
    );
    assert_eq!(captured(&cap), "Subject: hi\r\n\r\ndot\r\n.x\r\nbody\r\n");
}

#[test]
fn a_message_may_arrive_in_pieces_and_the_terminator_may_be_split() {
    // RFC 2920: DATA ends a pipelined group, so the text follows the 354.
    let text = "line one\r\n.dot\r\n.\r\nNOOP\r\n";
    let run = |chunk: usize| {
        let (mut s, cap) = with_recipient();
        assert!(s.run("DATA\r\n").starts_with("354"));
        let out = s.run_chunked(text, chunk);
        (out, captured(&cap))
    };
    let whole = run(text.len());
    assert_eq!(whole.0, "250 2.0.0 Message accepted for delivery\r\n250 2.0.0 OK\r\n");
    assert_eq!(whole.1, "line one\r\ndot\r\n");
    for chunk in [1, 2, 3, 5, 11] {
        assert_eq!(run(chunk), whole, "chunk {chunk}");
    }
}

#[test]
fn commands_pipelined_up_to_data_get_every_reply_in_order() {
    let (mut s, cap) = session(|c| c);
    s.take();
    let out = s.run("EHLO c\r\nMAIL FROM:<a@b>\r\nRCPT TO:<c@d>\r\nDATA\r\n");
    let codes: Vec<&str> = out.lines().filter(|l| l.as_bytes().get(3) == Some(&b' ')).map(|l| &l[..3]).collect();
    assert_eq!(codes, ["250", "250", "250", "354"]);
    // After the message, more commands in the same write are answered too.
    let out = s.run("hello\r\n.\r\nMAIL FROM:<e@f>\r\nRSET\r\nQUIT\r\n");
    let codes: Vec<&str> = out.lines().map(|l| &l[..3]).collect();
    assert_eq!(codes, ["250", "250", "250", "221"]);
    assert_eq!(captured(&cap), "hello\r\n");
    assert!(s.is_closed());
}

#[test]
fn text_pipelined_behind_data_is_read_as_commands() {
    // The client broke RFC 2920 by not waiting for the 354.
    let (mut s, _) = with_recipient();
    let out = s.run("DATA\r\nhello\r\n.\r\n");
    assert!(out.starts_with("354 ") && out.contains("500 5.5.2 Command unrecognized\r\n"), "{out}");
}

#[test]
fn another_message_can_follow_the_first_on_the_same_connection() {
    let (mut s, cap) = with_recipient();
    s.run("DATA\r\n");
    s.run("first\r\n.\r\n");
    assert_eq!(s.run("MAIL FROM:<e@f>\r\n"), "250 2.1.0 Sender OK\r\n");
    s.run("RCPT TO:<g@h>\r\nDATA\r\n");
    assert_eq!(s.run("second\r\n.\r\n"), "250 2.0.0 Message accepted for delivery\r\n");
    assert_eq!(captured(&cap), "first\r\nsecond\r\n");
}

#[test]
fn losing_the_connection_in_the_middle_of_a_message_is_not_an_error() {
    let (mut s, _) = with_recipient();
    s.run("DATA\r\npartial");
    s.disconnect();
}

// BDAT --------------------------------------------------------------------

#[test]
fn bdat_chunks_make_a_message() {
    let (mut s, cap) = with_recipient();
    assert_eq!(s.run("BDAT 5\r\nhello"), "250 2.0.0 OK\r\n");
    assert_eq!(s.run("BDAT 6 LAST\r\n world"), "250 2.0.0 Message accepted for delivery\r\n");
    assert_eq!(captured(&cap), "hello world");
}

#[test]
fn bdat_payload_is_taken_whatever_it_looks_like() {
    let (mut s, cap) = with_recipient();
    let payload = "MAIL FROM:<x@y>\r\n.\r\nQUIT\r\n";
    assert_eq!(
        s.run(&format!("BDAT {} LAST\r\n{payload}", payload.len())),
        "250 2.0.0 Message accepted for delivery\r\n"
    );
    assert_eq!(captured(&cap), payload);
}

#[test]
fn bdat_arriving_a_byte_at_a_time_is_the_same() {
    let wire = "EHLO c\r\nMAIL FROM:<a@b>\r\nRCPT TO:<c@d>\r\nBDAT 3\r\nabcBDAT 2 LAST\r\nde";
    let run = |chunk: usize| {
        let (mut s, cap) = session(|c| c);
        s.take();
        let out = s.run_chunked(wire, chunk);
        (out, captured(&cap))
    };
    let whole = run(wire.len());
    assert!(whole.0.ends_with("250 2.0.0 OK\r\n250 2.0.0 Message accepted for delivery\r\n"), "{}", whole.0);
    assert_eq!(whole.1, "abcde");
    for chunk in [1, 2, 3, 7] {
        assert_eq!(run(chunk), whole, "chunk {chunk}");
    }
}

#[test]
fn bdat_checks_its_arguments_and_its_place() {
    let (mut s, _) = ready(|c| c);
    assert_eq!(s.run("BDAT 5\r\n"), "503 5.5.1 Bad sequence of commands\r\n");
    s.run("MAIL FROM:<a@b>\r\n");
    assert_eq!(s.run("BDAT 5\r\n"), "503 5.5.1 Need RCPT (recipient)\r\n");
    s.run("RCPT TO:<c@d>\r\n");
    assert_eq!(s.run("BDAT\r\n"), "501 5.5.4 Syntax: BDAT size [LAST]\r\n");
    assert_eq!(s.run("BDAT -1\r\n"), "501 5.5.4 Invalid BDAT size\r\n");
    assert_eq!(s.run("BDAT x\r\n"), "501 5.5.4 Invalid BDAT size\r\n");
}

#[test]
fn an_empty_final_chunk_ends_the_message() {
    let (mut s, cap) = with_recipient();
    assert_eq!(s.run("BDAT 3\r\nabc"), "250 2.0.0 OK\r\n");
    assert_eq!(s.run("BDAT 0 LAST\r\n"), "250 2.0.0 Message accepted for delivery\r\n");
    assert_eq!(captured(&cap), "abc");
}

#[test]
fn data_and_mail_are_out_of_sequence_in_the_middle_of_a_bdat_message() {
    let (mut s, _) = with_recipient();
    s.run("BDAT 3\r\nabc");
    assert_eq!(s.run("DATA\r\n"), "503 5.5.1 Bad sequence of commands\r\n");
    assert_eq!(s.run("MAIL FROM:<x@y>\r\n"), "503 5.5.1 Bad sequence of commands\r\n");
    assert_eq!(s.run("RSET\r\n"), "250 2.0.0 Reset state\r\n");
    assert_eq!(s.run("NOOP\r\n"), "250 2.0.0 OK\r\n");
}

// Size limits -------------------------------------------------------------

fn small_limit() -> (Session, Capture) {
    ready(|mut c| {
        c.max_message_size = 40;
        c
    })
}

const OVER: &str = "552 5.3.4 Message size exceeds maximum\r\n";

#[test]
fn a_message_over_the_limit_is_refused_once_when_it_ends_and_the_session_recovers() {
    let (mut s, _) = small_limit();
    s.run("MAIL FROM:<a@b>\r\nRCPT TO:<c@d>\r\nDATA\r\n");
    // The first lines overrun the limit; nothing is said until the client
    // has finished sending, and then only once.
    assert_eq!(s.run("0123456789012345678901234567890123456789\r\n"), "");
    assert_eq!(s.run("more more more more more more more more more\r\n"), "");
    assert_eq!(s.run("and more and more and more and more and more\r\n"), "");
    assert_eq!(s.run(".\r\n"), OVER);
    // The connection is usable again, though the handlers must be set up anew.
    assert_eq!(s.run("NOOP\r\n"), "250 2.0.0 OK\r\n");
    assert_eq!(s.run("MAIL FROM:<a@b>\r\n"), "503 5.5.1 Send HELO/EHLO first\r\n");
    assert!(s.run("EHLO client.example\r\n").starts_with("250-"));
    s.run("MAIL FROM:<a@b>\r\nRCPT TO:<c@d>\r\n");
    assert_eq!(s.run("DATA\r\n"), "354 Start mail input; end with <CRLF>.<CRLF>\r\n");
    assert_eq!(s.run("short\r\n.\r\n"), "250 2.0.0 Message accepted for delivery\r\n");
    assert_eq!(s.run("QUIT\r\n"), "221 2.0.0 Bye\r\n");
}

#[test]
fn an_oversize_message_sent_in_one_write_leaves_the_next_command_to_be_answered() {
    let (mut s, _) = small_limit();
    s.run("MAIL FROM:<a@b>\r\nRCPT TO:<c@d>\r\nDATA\r\n");
    let body = "x".repeat(100);
    assert_eq!(s.run(&format!("{body}\r\n.\r\nNOOP\r\n")), format!("{OVER}250 2.0.0 OK\r\n"));
}

#[test]
fn an_oversize_message_is_handled_the_same_at_every_chunking() {
    let body = "y".repeat(100);
    let text = format!("{body}\r\n{body}\r\n.\r\nNOOP\r\n");
    let run = |chunk: usize| {
        let (mut s, _) = small_limit();
        s.run("MAIL FROM:<a@b>\r\nRCPT TO:<c@d>\r\nDATA\r\n");
        s.run_chunked(&text, chunk)
    };
    let whole = run(text.len());
    assert_eq!(whole, format!("{OVER}250 2.0.0 OK\r\n"));
    for chunk in [1, 3, 7, 50] {
        assert_eq!(run(chunk), whole, "chunk {chunk}");
    }
}

#[test]
fn a_terminator_inside_the_discarded_part_still_ends_it() {
    // The dot line is found even when the data before it was thrown away
    // and the limit was passed in the middle of a line.
    let (mut s, _) = small_limit();
    s.run("MAIL FROM:<a@b>\r\nRCPT TO:<c@d>\r\nDATA\r\n");
    s.run("0123456789012345678901234567890123456789012345");
    assert_eq!(s.run("67890\r\n.\r\n"), OVER);
    assert_eq!(s.run("NOOP\r\n"), "250 2.0.0 OK\r\n");
}

#[test]
fn a_bdat_chunk_over_the_limit_is_taken_and_refused_once_when_it_ends() {
    let (mut s, _) = small_limit();
    s.run("MAIL FROM:<a@b>\r\nRCPT TO:<c@d>\r\n");
    assert_eq!(s.run("BDAT 100 LAST\r\n"), "");
    // The limit is passed with the second piece; the rest is still payload.
    assert_eq!(s.run(&"z".repeat(30)), "");
    assert_eq!(s.run(&"z\r\n".repeat(10)), "");
    assert_eq!(s.run(&"NOOP\r\n".repeat(5)), "");
    assert_eq!(s.run(&"z".repeat(10)), OVER);
    assert_eq!(s.run("NOOP\r\n"), "250 2.0.0 OK\r\n");
}

// Authentication ----------------------------------------------------------

fn store() -> Arc<dyn hopf_auth::CredentialStore> {
    hopf_auth::PasswordStore::new().with_user("alice", "secret").shared()
}

/// An authentication-required session that is already encrypted (PLAIN and
/// LOGIN are only offered over TLS).
fn encrypted() -> Session {
    let (mut s, _) = session(|c| c.with_store(store()).auth_required(true));
    s.handler.meta.tls = true;
    s.take();
    s.run("EHLO c\r\n");
    s
}

const PLAIN_ALICE: &str = "AGFsaWNlAHNlY3JldA=="; // \0alice\0secret
const PLAIN_WRONG: &str = "AGFsaWNlAG5vcGU="; // \0alice\0nope
const OK: &str = "235 2.7.0 Authentication successful\r\n";
const DENIED: &str = "535 5.7.8 Authentication credentials invalid\r\n";

#[test]
fn auth_is_not_offered_without_a_credential_store() {
    let (mut s, _) = ready(|c| c);
    assert_eq!(s.run("AUTH PLAIN AGEAYg==\r\n"), "502 5.5.1 AUTH not available\r\n");
}

#[test]
fn password_mechanisms_are_refused_on_a_connection_that_is_not_encrypted() {
    let (mut s, _) = ready(|c| c.with_store(store()));
    let r = s.run(&format!("AUTH PLAIN {PLAIN_ALICE}\r\n"));
    assert_eq!(r, "538 5.7.11 Encryption required for requested authentication mechanism\r\n");
}

#[test]
fn an_unknown_mechanism_is_refused() {
    let (mut s, _) = ready(|c| c.with_store(store()));
    assert_eq!(s.run("AUTH FOO\r\n"), "504 5.5.4 Unrecognized authentication type\r\n");
}

#[test]
fn ehlo_offers_the_password_mechanisms_once_encrypted() {
    let (mut s, _) = session(|c| c.with_store(store()));
    s.handler.meta.tls = true;
    s.take();
    let r = s.run("EHLO c\r\n");
    assert!(r.contains("250 AUTH PLAIN LOGIN"), "{r}");
}

#[test]
fn plain_with_an_initial_response_signs_the_client_in() {
    let mut s = encrypted();
    assert_eq!(s.run("MAIL FROM:<a@b>\r\n"), "530 5.7.0 Authentication required\r\n");
    assert_eq!(s.run(&format!("AUTH PLAIN {PLAIN_ALICE}\r\n")), OK);
    assert_eq!(s.run("MAIL FROM:<a@b>\r\n"), "250 2.1.0 Sender OK\r\n");
    assert_eq!(s.handler.meta.authenticated_user.as_deref(), Some("alice"));
}

#[test]
fn plain_may_ask_for_the_response_on_a_separate_line() {
    let mut s = encrypted();
    assert_eq!(s.run("AUTH PLAIN\r\n"), "334 \r\n");
    assert_eq!(s.run(&format!("{PLAIN_ALICE}\r\n")), OK);
}

#[test]
fn a_wrong_password_is_refused_and_the_client_stays_signed_out() {
    let mut s = encrypted();
    assert_eq!(s.run(&format!("AUTH PLAIN {PLAIN_WRONG}\r\n")), DENIED);
    assert_eq!(s.run("MAIL FROM:<a@b>\r\n"), "530 5.7.0 Authentication required\r\n");
    assert!(s.handler.meta.authenticated_user.is_none());
}

#[test]
fn malformed_base64_in_an_initial_response_is_refused() {
    let mut s = encrypted();
    assert_eq!(s.run("AUTH PLAIN !!!\r\n"), DENIED);
}

#[test]
fn login_asks_for_the_name_then_the_password() {
    let mut s = encrypted();
    assert_eq!(s.run("AUTH LOGIN\r\n"), "334 VXNlcm5hbWU6\r\n");
    assert_eq!(s.run("YWxpY2U=\r\n"), "334 UGFzc3dvcmQ6\r\n");
    assert_eq!(s.run("c2VjcmV0\r\n"), OK);
}

#[test]
fn login_with_a_wrong_password_is_refused() {
    let mut s = encrypted();
    s.run("AUTH LOGIN\r\n");
    s.run("YWxpY2U=\r\n");
    assert_eq!(s.run("d3Jvbmc=\r\n"), DENIED);
}

#[test]
fn a_client_can_cancel_an_exchange_with_a_star() {
    let mut s = encrypted();
    s.run("AUTH LOGIN\r\n");
    assert_eq!(s.run("*\r\n"), "501 5.0.0 Authentication cancelled\r\n");
    assert_eq!(s.run("NOOP\r\n"), "250 2.0.0 OK\r\n");
}

#[test]
fn a_continuation_that_is_not_base64_ends_the_exchange() {
    let mut s = encrypted();
    s.run("AUTH LOGIN\r\n");
    assert_eq!(s.run("***x\r\n"), DENIED);
    assert_eq!(s.run("NOOP\r\n"), "250 2.0.0 OK\r\n");
}

#[test]
fn a_command_pipelined_behind_auth_is_deferred_not_run_against_stale_state() {
    let mut s = encrypted();
    let r = s.run(&format!("AUTH PLAIN {PLAIN_ALICE}\r\nMAIL FROM:<a@b>\r\n"));
    assert!(r.contains("451 4.7.0 Authentication in progress, try again later\r\n"), "{r}");
    assert!(r.contains(OK), "{r}");
    assert_eq!(s.run("MAIL FROM:<a@b>\r\n"), "250 2.1.0 Sender OK\r\n");
}

// XCLIENT -----------------------------------------------------------------

#[test]
fn xclient_is_refused_to_an_address_that_is_not_trusted() {
    let (mut s, _) = ready(|c| c);
    assert_eq!(s.run("XCLIENT ADDR=1.2.3.4\r\n"), "550 5.7.0 XCLIENT not permitted\r\n");
}

fn trusted() -> (Session, Capture) {
    let (mut s, cap) = session(|c| c.with_xclient_allow(vec![hopf_core::IpNet::parse("127.0.0.0/8").unwrap()]));
    s.take();
    (s, cap)
}

#[test]
fn a_trusted_proxy_is_offered_xclient_and_can_override_the_client_details() {
    let (mut s, _) = trusted();
    let r = s.run("EHLO proxy\r\n");
    assert!(r.contains("250 XCLIENT NAME ADDR PORT PROTO HELO LOGIN DESTADDR DESTPORT\r\n"), "{r}");
    assert_eq!(
        s.run("XCLIENT ADDR=203.0.113.9 NAME=far.example PORT=1234 LOGIN=bob HELO=h.example\r\n"),
        "220 mx.example ESMTP Service ready\r\n"
    );
    let meta = &s.handler.meta;
    assert_eq!(meta.peer, "203.0.113.9:1234".parse().unwrap());
    assert_eq!(meta.reverse_name.as_deref(), Some("far.example"));
    assert_eq!(meta.xclient_login.as_deref(), Some("bob"));
    assert!(meta.authenticated_user.is_none(), "XCLIENT LOGIN is information, not a sign-in");
    assert_eq!(s.handler.tcp_peer, "127.0.0.1:9999".parse().unwrap(), "the real peer is not overridden");
}

#[test]
fn xclient_checks_its_attributes() {
    let (mut s, _) = trusted();
    s.run("EHLO proxy\r\n");
    assert_eq!(s.run("XCLIENT FOO=1\r\n"), "501 5.5.4 Unknown XCLIENT attribute: FOO\r\n");
    assert_eq!(s.run("XCLIENT\r\n"), "501 5.5.4 Syntax: XCLIENT attribute=value [...]\r\n");
}

#[test]
fn after_xclient_the_client_greets_again() {
    let (mut s, _) = trusted();
    s.run("EHLO proxy\r\n");
    s.run("XCLIENT ADDR=203.0.113.9\r\n");
    assert_eq!(s.run("MAIL FROM:<a@b>\r\n"), "503 5.5.1 Bad sequence of commands\r\n");
    assert!(s.run("EHLO far.example\r\n").starts_with("250-"));
    assert_eq!(s.run("MAIL FROM:<a@b>\r\n"), "250 2.1.0 Sender OK\r\n");
}
