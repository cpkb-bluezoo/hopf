// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! The relay end to end (issue #517): a client submits to a real
//! [`SimpleRelayService`], which queues the message and delivers it to a
//! scripted SMTP server standing in for the recipients' mail exchanger. The
//! script makes the next hop refuse, temporarily or for good, at each stage
//! of the dialogue.

use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, TcpListener, UdpSocket};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use hopf_core::retry::RetryPolicy;
use hopf_core::{Runtime, RuntimeConfig};
use hopf_dns::wire::{DnsMessage, DnsResourceRecord, DnsType, FLAG_QR, FLAG_RA};
use hopf_dns::DnsResolver;

use crate::client::{SmtpClient, SmtpClientTimeouts, SmtpSend};
use crate::server::delivery::DsnRecipientParams;

use super::{QueuedMessage, QueuedRecipient, RecipientStatus, RelayOptions, RelayQueue, SimpleRelayService};
use crate::server::service::SmtpConfig;

const SENDER: &str = "alice@sender.test";

/// A message the scripted server took.
#[derive(Debug, Clone)]
struct Taken {
    mail_from: String,
    rcpts: Vec<String>,
    body: String,
}

/// A scripted next hop. `script(connection, command, line)` may return a
/// reply to use instead of the usual acceptance; `command` is `CONNECT` for
/// the greeting, then `EHLO`, `MAIL`, `RCPT`, `DATA`, or `.` for the reply
/// to the end of the message text.
struct Sink {
    port: u16,
    taken: Arc<Mutex<Vec<Taken>>>,
    connections: Arc<AtomicUsize>,
}

impl Sink {
    fn start(script: impl Fn(usize, &str, &str) -> Option<&'static str> + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let taken = Arc::new(Mutex::new(Vec::new()));
        let connections = Arc::new(AtomicUsize::new(0));
        let script = Arc::new(script);
        let (taken2, connections2) = (Arc::clone(&taken), Arc::clone(&connections));
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                let conn = connections2.fetch_add(1, Ordering::SeqCst);
                let (script, taken) = (Arc::clone(&script), Arc::clone(&taken2));
                std::thread::spawn(move || serve(stream, conn, &*script, &taken));
            }
        });
        Self { port, taken, connections }
    }

    fn taken(&self) -> Vec<Taken> {
        self.taken.lock().unwrap().clone()
    }

    /// Messages taken that were not notices (a notice has the null sender).
    fn messages(&self) -> Vec<Taken> {
        self.taken().into_iter().filter(|t| !t.mail_from.is_empty()).collect()
    }

    fn notices(&self) -> Vec<Taken> {
        self.taken().into_iter().filter(|t| t.mail_from.is_empty()).collect()
    }
}

fn serve(
    stream: std::net::TcpStream,
    conn: usize,
    script: &(dyn Fn(usize, &str, &str) -> Option<&'static str> + Send + Sync),
    taken: &Mutex<Vec<Taken>>,
) {
    let mut out = stream.try_clone().unwrap();
    let mut input = BufReader::new(stream);
    let reply = |cmd: &str, line: &str, default: &'static str| script(conn, cmd, line).unwrap_or(default);
    let greeting = reply("CONNECT", "", "220 sink ESMTP\r\n");
    let _ = out.write_all(greeting.as_bytes());
    if !greeting.starts_with('2') {
        return;
    }
    let (mut mail_from, mut rcpts, mut body, mut in_data) = (String::new(), Vec::<String>::new(), String::new(), false);
    let mut line = String::new();
    loop {
        line.clear();
        if input.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        let text = line.trim_end().to_string();
        let answer = if in_data {
            if text == "." {
                in_data = false;
                let answer = reply(".", &text, "250 2.0.0 queued\r\n");
                if answer.starts_with('2') {
                    taken.lock().unwrap().push(Taken {
                        mail_from: mail_from.clone(),
                        rcpts: rcpts.clone(),
                        body: std::mem::take(&mut body),
                    });
                }
                answer
            } else {
                body.push_str(&line);
                continue;
            }
        } else {
            let upper = text.to_ascii_uppercase();
            if upper.starts_with("EHLO") || upper.starts_with("HELO") {
                reply("EHLO", &text, "250 sink\r\n")
            } else if upper.starts_with("MAIL") {
                let answer = reply("MAIL", &text, "250 ok\r\n");
                if answer.starts_with('2') {
                    mail_from = text[text.find('<').unwrap() + 1..text.find('>').unwrap()].to_string();
                    rcpts.clear();
                }
                answer
            } else if upper.starts_with("RCPT") {
                let answer = reply("RCPT", &text, "250 ok\r\n");
                if answer.starts_with('2') {
                    rcpts.push(text[text.find('<').unwrap() + 1..text.find('>').unwrap()].to_string());
                }
                answer
            } else if upper == "DATA" {
                let answer = reply("DATA", &text, "354 go\r\n");
                in_data = answer.starts_with('3');
                answer
            } else if upper == "QUIT" {
                let _ = out.write_all(b"221 bye\r\n");
                return;
            } else {
                "250 ok\r\n"
            }
        };
        if out.write_all(answer.as_bytes()).is_err() {
            return;
        }
    }
}

/// A resolver whose every name has a mail exchanger at 127.0.0.1.
fn loopback_dns(rt: &Arc<Runtime>) -> Arc<DnsResolver> {
    let stub = UdpSocket::bind("127.0.0.1:0").unwrap();
    stub.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    let stub_addr = stub.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut buf = [0u8; 512];
        while let Ok((n, peer)) = stub.recv_from(&mut buf) {
            let Ok(q) = DnsMessage::parse(&buf[..n]) else { continue };
            let mut resp = q.response_template(0);
            resp.flags |= FLAG_QR | FLAG_RA;
            if let Some(question) = q.questions.first() {
                match question.qtype {
                    Some(DnsType::Mx) => resp.answers.push(DnsResourceRecord::mx(&question.name, 60, 10, "127.0.0.1").unwrap()),
                    Some(DnsType::A) => resp.answers.push(DnsResourceRecord::a(&question.name, 60, Ipv4Addr::new(127, 0, 0, 1))),
                    _ => {}
                }
            }
            let _ = stub.send_to(&resp.serialize().unwrap(), peer);
        }
    });
    let dns = Arc::new(DnsResolver::new(rt.pick_worker().clone()));
    dns.add_server(stub_addr);
    dns.set_timeout(Duration::from_millis(500));
    dns.open().unwrap();
    dns
}

/// A relay delivering to `sink`, retrying every ~100 ms, with its queue in `queue`.
struct Relay {
    rt: Arc<Runtime>,
    addr: std::net::SocketAddr,
    _service: SimpleRelayService,
}

impl Relay {
    fn start(sink: &Sink, queue: &Path, lifetime: Duration) -> Self {
        let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
        let options = RelayOptions::default()
            .with_queue_dir(queue)
            .with_retry_policy(
                RetryPolicy::exponential_backoff()
                    .with_initial_delay(Duration::from_millis(100))
                    .with_max_delay(Duration::from_millis(200))
                    .with_jitter(0.0),
            )
            .with_max_queue_lifetime(lifetime);
        let config = SmtpConfig::new("127.0.0.1:0".parse().unwrap(), "relay.example.com").auth_required(false);
        let dns = loopback_dns(&rt);
        let service = SimpleRelayService::with_resolver_and_options(config, Arc::clone(&rt), dns, sink.port, options);
        let addr = service.start(Arc::clone(&rt)).unwrap();
        Self { rt, addr, _service: service }
    }

    /// Submit `body` from [`SENDER`] to `rcpts`; whether the relay accepted it.
    fn submit(&self, rcpts: &[&str], body: &str) -> bool {
        let mut once = Some(body.as_bytes().to_vec());
        let mut send = SmtpSend::new("client.example").mail_from(SENDER).message_with(move || once.take());
        for r in rcpts {
            send = send.rcpt_to(*r);
        }
        let (tx, rx) = mpsc::channel();
        send = send.on_complete(Box::new(move |ok| {
            let _ = tx.send(ok);
        }));
        let timeouts = SmtpClientTimeouts { stage: Duration::from_secs(5), ..Default::default() };
        SmtpClient::from_addr(self.addr).timeouts(timeouts).connect(&self.rt, Arc::new(send)).unwrap();
        rx.recv_timeout(Duration::from_secs(10)).expect("the relay answered")
    }
}

fn wait_for(pred: impl Fn() -> bool, max_ms: u64) -> bool {
    for _ in 0..(max_ms / 10).max(1) {
        if pred() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    pred()
}

fn queue_files(dir: &Path) -> usize {
    std::fs::read_dir(dir).map(|d| d.count()).unwrap_or(0)
}

/// Nothing is left in the queue: everything was delivered or bounced.
fn queue_is_empty(dir: &Path) -> bool {
    wait_for(|| queue_files(dir) == 0, 5000)
}

const LONG: Duration = Duration::from_secs(3600);
const BODY: &str = "Subject: hi\r\n\r\nrelayed-body\r\n";

/// Reply `refusal` to the first connection's `stage`; accept everything else.
fn refuse_first(stage: &'static str, refusal: &'static str) -> Sink {
    Sink::start(move |conn, cmd, _| (conn == 0 && cmd == stage).then_some(refusal))
}

fn delivered_once_after_a_temporary_refusal(sink: Sink) {
    let tmp = tempfile::tempdir().unwrap();
    let relay = Relay::start(&sink, tmp.path(), LONG);
    assert!(relay.submit(&["bob@example.com"], BODY), "the relay takes the message whatever the next hop says");
    assert!(wait_for(|| !sink.messages().is_empty(), 5000), "the message is delivered on a later attempt");
    assert!(queue_is_empty(tmp.path()));
    let messages = sink.messages();
    assert_eq!(messages.len(), 1, "delivered exactly once: {messages:?}");
    assert_eq!(messages[0].rcpts, ["bob@example.com"]);
    assert!(messages[0].body.contains("relayed-body"));
    assert!(sink.connections.load(Ordering::SeqCst) >= 2, "the first attempt was refused");
    assert!(sink.notices().is_empty(), "a message that gets through after a delay is not bounced");
}

#[test]
fn a_next_hop_that_is_busy_at_connect_is_tried_again() {
    delivered_once_after_a_temporary_refusal(refuse_first("CONNECT", "421 4.3.2 too busy, try later\r\n"));
}

#[test]
fn a_temporary_refusal_of_the_sender_is_tried_again() {
    delivered_once_after_a_temporary_refusal(refuse_first("MAIL", "451 4.7.1 greylisted\r\n"));
}

#[test]
fn a_temporary_refusal_of_the_recipient_is_tried_again() {
    delivered_once_after_a_temporary_refusal(refuse_first("RCPT", "451 4.2.1 mailbox busy\r\n"));
}

#[test]
fn a_temporary_refusal_after_the_text_is_tried_again() {
    delivered_once_after_a_temporary_refusal(refuse_first(".", "452 4.2.2 mailbox full\r\n"));
}

#[test]
fn a_permanent_refusal_is_bounced_at_once_with_what_the_next_hop_said() {
    let sink = Sink::start(|conn, cmd, line| {
        (conn == 0 && cmd == "RCPT" && line.contains("bob@")).then_some("550 5.1.1 no such user\r\n")
    });
    let tmp = tempfile::tempdir().unwrap();
    let relay = Relay::start(&sink, tmp.path(), LONG);
    assert!(relay.submit(&["bob@example.com"], BODY));
    assert!(wait_for(|| !sink.notices().is_empty(), 5000), "the sender is told");
    assert!(queue_is_empty(tmp.path()));
    assert!(sink.messages().is_empty(), "nothing was delivered");
    let notices = sink.notices();
    assert_eq!(notices.len(), 1, "{notices:?}");
    assert_eq!(notices[0].rcpts, [SENDER]);
    assert!(notices[0].body.contains("bob@example.com") && notices[0].body.contains("550"), "{}", notices[0].body);
    assert_eq!(sink.connections.load(Ordering::SeqCst), 2, "one attempt at bob, one delivering the notice: not retried");
}

#[test]
fn only_the_recipient_that_was_refused_is_retried_and_only_the_one_refused_for_good_is_bounced() {
    let sink = Sink::start(|conn, cmd, line| {
        if cmd != "RCPT" {
            return None;
        }
        if line.contains("bad@") {
            Some("550 5.1.1 no such user\r\n")
        } else if line.contains("slow@") && conn == 0 {
            Some("451 4.2.1 mailbox busy\r\n")
        } else {
            None
        }
    });
    let tmp = tempfile::tempdir().unwrap();
    let relay = Relay::start(&sink, tmp.path(), LONG);
    assert!(relay.submit(&["ok@example.com", "slow@example.com", "bad@example.com"], BODY));
    assert!(wait_for(|| sink.messages().len() >= 2 && !sink.notices().is_empty(), 5000));
    assert!(queue_is_empty(tmp.path()));
    let messages = sink.messages();
    assert_eq!(messages.len(), 2, "{messages:?}");
    assert_eq!(messages[0].rcpts, ["ok@example.com"], "the first attempt delivers to the recipient that was accepted");
    assert_eq!(messages[1].rcpts, ["slow@example.com"], "the retry is for the one that was deferred, not everyone");
    let notices = sink.notices();
    assert_eq!(notices.len(), 1, "{notices:?}");
    assert!(notices[0].body.contains("bad@example.com"));
    assert!(!notices[0].body.contains("slow@example.com") && !notices[0].body.contains("ok@example.com"));
}

#[test]
fn the_message_is_accepted_even_when_nothing_could_be_delivered_yet() {
    // The old behaviour answered the client with a temporary error here and
    // left the retrying to it.
    let sink = Sink::start(|_, cmd, _| (cmd == "RCPT").then_some("451 4.2.1 mailbox busy\r\n"));
    let tmp = tempfile::tempdir().unwrap();
    let relay = Relay::start(&sink, tmp.path(), LONG);
    assert!(relay.submit(&["bob@example.com"], BODY));
    assert!(wait_for(|| sink.connections.load(Ordering::SeqCst) >= 3, 5000), "it keeps trying");
    let scan = RelayQueue::open(tmp.path()).unwrap().scan().unwrap();
    assert_eq!(scan.messages.len(), 1, "the message is still held");
    let r = &scan.messages[0].recipients[0];
    assert_eq!(r.status, RecipientStatus::Pending);
    assert!(r.attempts >= 2 && r.diagnostic.as_deref().is_some_and(|d| d.starts_with("451")), "{r:?}");
    assert!(sink.notices().is_empty(), "a temporary failure is not a bounce");
}

#[test]
fn a_recipient_still_refused_when_the_queue_lifetime_ends_is_bounced() {
    let sink = Sink::start(|_, cmd, _| (cmd == "RCPT").then_some("451 4.2.1 mailbox busy\r\n"));
    let tmp = tempfile::tempdir().unwrap();
    let relay = Relay::start(&sink, tmp.path(), Duration::from_millis(600));
    assert!(relay.submit(&["bob@example.com"], BODY));
    assert!(queue_files(tmp.path()) > 0 || sink.connections.load(Ordering::SeqCst) > 0);
    // the notice is itself delivered by the sink, which refuses RCPT: it is
    // the queue that is checked, for the bounce that is now waiting to go
    assert!(
        wait_for(
            || {
                let scan = RelayQueue::open(tmp.path()).unwrap().scan().unwrap();
                scan.messages.iter().any(|m| m.sender.is_none() && m.recipients[0].address == SENDER)
                    && scan.messages.iter().all(|m| m.sender.is_none())
            },
            8000
        ),
        "the undeliverable message is replaced by a notice to its sender"
    );
    let scan = RelayQueue::open(tmp.path()).unwrap().scan().unwrap();
    assert_eq!(scan.messages.len(), 1, "{:?}", scan.messages);
    assert!(sink.messages().is_empty());
}

#[test]
fn a_message_queued_before_a_restart_is_delivered_when_the_relay_starts() {
    let sink = Sink::start(|_, _, _| None);
    let tmp = tempfile::tempdir().unwrap();
    let queue = RelayQueue::open(tmp.path().join("q")).unwrap();
    let content = tmp.path().join("spool.tmp");
    std::fs::write(&content, BODY).unwrap();
    let id = RelayQueue::new_id();
    let mut message = QueuedMessage {
        id: id.clone(),
        queued_at: SystemTime::now(),
        sender: Some(SENDER.into()),
        smtputf8: false,
        delivery: Default::default(),
        extra_header_lines: vec!["X-Queued-By: before-the-restart".into()],
        recipients: vec![
            QueuedRecipient::new("bob@example.com", DsnRecipientParams::default(), SystemTime::now()),
            QueuedRecipient::new("gone@example.com", DsnRecipientParams::default(), SystemTime::now()),
        ],
    };
    message.recipients[1].status = RecipientStatus::Delivered; // already done before the restart
    queue.enqueue(&message, &content).unwrap();
    std::fs::write(queue.dir().join("deadbeef-0000000000000001.msg"), "left by a crash").unwrap();

    let _relay = Relay::start(&sink, queue.dir(), LONG);
    assert!(wait_for(|| !sink.messages().is_empty(), 5000), "delivered without anyone submitting anything");
    assert!(queue_is_empty(queue.dir()), "the orphan is cleared too");
    let messages = sink.messages();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].rcpts, ["bob@example.com"], "not the recipient that was already delivered");
    assert_eq!(messages[0].mail_from, SENDER);
    assert!(messages[0].body.starts_with("X-Queued-By: before-the-restart\r\n"), "{}", messages[0].body);
    assert!(messages[0].body.contains("relayed-body"));
}

#[test]
fn the_client_is_answered_only_once_the_message_is_in_the_queue() {
    // Whatever happens to delivery, a 250 means the message is on disk.
    let sink = Sink::start(|_, cmd, _| (cmd == "CONNECT").then_some("421 down\r\n"));
    let tmp = tempfile::tempdir().unwrap();
    let relay = Relay::start(&sink, tmp.path(), LONG);
    assert!(relay.submit(&["bob@example.com"], BODY));
    let scan = RelayQueue::open(tmp.path()).unwrap().scan().unwrap();
    assert_eq!(scan.messages.len(), 1);
    assert_eq!(std::fs::read_to_string(RelayQueue::open(tmp.path()).unwrap().content_path(&scan.messages[0].id)).unwrap(), BODY);
}
