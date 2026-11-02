// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! [`RelayQueue`] - the relay's on-disk store of messages that have been
//! accepted but not yet delivered to every recipient.
//!
//! RFC 5321 section 4.5.4.1 has a relay that cannot deliver at once keep the
//! message and try again, so the message has to survive a restart. Each
//! queued message is two files in the queue directory:
//!
//! - `<id>.msg`: the message exactly as it was spooled while it was received;
//! - `<id>.env`: the envelope and the state of every recipient (see below).
//!
//! The `.env` file is what makes a message exist. It is written last, to a
//! temporary name, synced, and renamed into place, so a crash leaves either
//! no message or a complete one, never half of one. A `.msg` with no `.env`
//! is an orphan from a crash between the two steps; [`RelayQueue::scan`]
//! reports it and the caller decides to remove it.
//!
//! The `.env` file is UTF-8 text, one record per line, so an operator can
//! read it and a later version can add a line without breaking this one:
//!
//! ```text
//! HOPF-RELAY-QUEUE 1
//! id 0000656c1a2b-9f3c4d5e6a7b8c9d
//! queued 1767225600
//! sender alice@example.org
//! rcpt pending 2 1767229200 0 FD bob@example.net rfc822 bob@example.net 451%204.2.1%20busy
//! end
//! ```
//!
//! Free-form values are percent-escaped so they never contain a space or a
//! line break; see [`escape`]. The final `end` line lets a reader tell a
//! truncated file from a complete one.
//!
//! Everything here is blocking file I/O. Callers on a reactor thread must
//! run it on the storage pool (issue #184).

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::server::delivery::{DeliverBy, DeliveryRequirements, DsnNotify, DsnRecipientParams, DsnReturn};

const MAGIC: &str = "HOPF-RELAY-QUEUE 1";
const MESSAGE_SUFFIX: &str = ".msg";
const ENVELOPE_SUFFIX: &str = ".env";
const TEMP_SUFFIX: &str = ".tmp";

/// Where one recipient of a queued message stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecipientStatus {
    /// Still to be delivered; [`QueuedRecipient::next_attempt`] says when.
    Pending,
    /// The next hop accepted the message for this recipient.
    Delivered,
    /// Undeliverable: refused for good, or the queue lifetime ran out.
    Failed,
}

impl RecipientStatus {
    fn token(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Delivered => "delivered",
            Self::Failed => "failed",
        }
    }

    fn from_token(token: &str) -> Option<Self> {
        Some(match token {
            "pending" => Self::Pending,
            "delivered" => Self::Delivered,
            "failed" => Self::Failed,
            _ => return None,
        })
    }
}

/// One envelope recipient of a queued message and its delivery state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedRecipient {
    /// The recipient address.
    pub address: String,
    /// The DSN parameters the recipient arrived with (RFC 3461).
    pub params: DsnRecipientParams,
    /// Where delivery to this recipient stands.
    pub status: RecipientStatus,
    /// How many delivery attempts have been made.
    pub attempts: u32,
    /// When to try next; meaningful while the status is `Pending`.
    pub next_attempt: SystemTime,
    /// The last thing the next hop said, or why an attempt failed.
    pub diagnostic: Option<String>,
    /// A delay notice (DSN `Action: delayed`) has already gone out.
    pub delay_notified: bool,
}

impl QueuedRecipient {
    /// A recipient that has not been tried yet and is due at `due`.
    pub fn new(address: impl Into<String>, params: DsnRecipientParams, due: SystemTime) -> Self {
        Self {
            address: address.into(),
            params,
            status: RecipientStatus::Pending,
            attempts: 0,
            next_attempt: due,
            diagnostic: None,
            delay_notified: false,
        }
    }
}

/// A message held in the queue: its envelope and the state of each recipient.
/// The content is in the `.msg` file at [`RelayQueue::content_path`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedMessage {
    /// The queue identifier (see [`RelayQueue::new_id`]).
    pub id: String,
    /// When the message was accepted; the queue lifetime counts from here.
    pub queued_at: SystemTime,
    /// The envelope sender; `None` for the null sender.
    pub sender: Option<String>,
    /// The message arrived with SMTPUTF8 (RFC 6531).
    pub smtputf8: bool,
    /// What the message arrived with that the next hop must be told.
    pub delivery: DeliveryRequirements,
    /// Header field values (without a trailing CRLF) to send ahead of the
    /// content to every destination.
    pub extra_header_lines: Vec<String>,
    /// The recipients, in the order they were given.
    pub recipients: Vec<QueuedRecipient>,
}

impl QueuedMessage {
    /// Recipients still waiting to be delivered.
    pub fn pending(&self) -> impl Iterator<Item = &QueuedRecipient> {
        self.recipients.iter().filter(|r| r.status == RecipientStatus::Pending)
    }

    /// Nothing is waiting any more: every recipient is delivered or failed.
    pub fn is_finished(&self) -> bool {
        self.pending().next().is_none()
    }

    /// The earliest time a pending recipient is due, if any is pending.
    pub fn next_due(&self) -> Option<SystemTime> {
        self.pending().map(|r| r.next_attempt).min()
    }
}

/// What [`RelayQueue::scan`] found.
#[derive(Debug, Default)]
pub struct QueueScan {
    /// Every message whose envelope could be read.
    pub messages: Vec<QueuedMessage>,
    /// Envelope files that could not be read, with the reason. They are left
    /// in place for an operator to look at.
    pub unreadable: Vec<(PathBuf, String)>,
    /// Content files with no envelope: left by a crash between writing the
    /// two, and safe to delete once nothing is being enqueued.
    pub orphans: Vec<PathBuf>,
}

/// The relay's queue directory.
#[derive(Debug, Clone)]
pub struct RelayQueue {
    dir: PathBuf,
}

impl RelayQueue {
    /// Use `dir` as the queue, creating it if it does not exist.
    pub fn open(dir: impl Into<PathBuf>) -> io::Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    /// The queue directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// A fresh queue identifier: the time in hex, then random bits, so that
    /// listing the directory is roughly arrival order and no two collide.
    pub fn new_id() -> String {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let mut random = [0u8; 8];
        if getrandom::getrandom(&mut random).is_err() {
            // No entropy source: the nanosecond clock still keeps ids apart.
            let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
            random = (nanos as u64).to_be_bytes();
        }
        format!("{now:012x}-{:016x}", u64::from_be_bytes(random))
    }

    /// Where the content of message `id` is kept.
    pub fn content_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}{MESSAGE_SUFFIX}"))
    }

    fn envelope_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}{ENVELOPE_SUFFIX}"))
    }

    /// Put `message` in the queue, taking over the file at `content`, which
    /// is moved (or, across filesystems, copied and removed).
    ///
    /// The message exists once this returns `Ok`. On `Err` it does not, and
    /// `content` is left where it was if it could not be moved.
    pub fn enqueue(&self, message: &QueuedMessage, content: &Path) -> io::Result<()> {
        check_id(&message.id)?;
        let target = self.content_path(&message.id);
        if fs::rename(content, &target).is_err() {
            fs::copy(content, &target)?;
            sync_file(&target)?;
            fs::remove_file(content)?;
        }
        if let Err(e) = self.write_envelope(message) {
            let _ = fs::remove_file(&target);
            return Err(e);
        }
        Ok(())
    }

    /// Replace the stored envelope of a message already in the queue.
    pub fn update(&self, message: &QueuedMessage) -> io::Result<()> {
        check_id(&message.id)?;
        if !self.envelope_path(&message.id).exists() {
            return Err(io::Error::new(io::ErrorKind::NotFound, format!("no queued message {}", message.id)));
        }
        self.write_envelope(message)
    }

    /// Remove a message from the queue, content and envelope. The envelope
    /// goes first: if only the content is left it is an orphan, which is
    /// harmless, where an envelope with no content would be a message that
    /// can never be delivered.
    pub fn remove(&self, id: &str) -> io::Result<()> {
        check_id(id)?;
        remove_if_present(&self.envelope_path(id))?;
        remove_if_present(&self.content_path(id))
    }

    /// Read the whole queue.
    pub fn scan(&self) -> io::Result<QueueScan> {
        let mut scan = QueueScan::default();
        let mut contents = Vec::new();
        for entry in fs::read_dir(&self.dir)? {
            let path = entry?.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if let Some(id) = name.strip_suffix(ENVELOPE_SUFFIX) {
                if check_id(id).is_err() {
                    continue;
                }
                match fs::read_to_string(&path).map_err(|e| e.to_string()).and_then(|t| parse_envelope(&t, id)) {
                    Ok(message) => scan.messages.push(message),
                    Err(why) => scan.unreadable.push((path, why)),
                }
            } else if let Some(id) = name.strip_suffix(MESSAGE_SUFFIX) {
                if check_id(id).is_ok() {
                    contents.push((id.to_string(), path));
                }
            }
        }
        scan.orphans = contents
            .into_iter()
            .filter(|(id, _)| !self.envelope_path(id).exists())
            .map(|(_, path)| path)
            .collect();
        scan.messages.sort_by(|a, b| (a.queued_at, &a.id).cmp(&(b.queued_at, &b.id)));
        scan.orphans.sort();
        Ok(scan)
    }

    fn write_envelope(&self, message: &QueuedMessage) -> io::Result<()> {
        let target = self.envelope_path(&message.id);
        let temp = self.dir.join(format!("{}{ENVELOPE_SUFFIX}{TEMP_SUFFIX}", message.id));
        let mut file = File::create(&temp)?;
        let written = file.write_all(render_envelope(message).as_bytes()).and_then(|()| file.sync_all());
        drop(file);
        match written.and_then(|()| fs::rename(&temp, &target)) {
            Ok(()) => {
                sync_dir(&self.dir);
                Ok(())
            }
            Err(e) => {
                let _ = fs::remove_file(&temp);
                Err(e)
            }
        }
    }
}

/// Identifiers are used in file names, so only what [`RelayQueue::new_id`]
/// makes is accepted: nothing that could name another directory.
fn check_id(id: &str) -> io::Result<()> {
    if !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') {
        Ok(())
    } else {
        Err(io::Error::new(io::ErrorKind::InvalidInput, format!("bad queue id {id:?}")))
    }
}

fn remove_if_present(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

fn sync_file(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

/// Make a rename durable. Not every platform can open a directory, and the
/// rename has happened either way, so a failure here is not an error.
fn sync_dir(dir: &Path) {
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
}

// The envelope format -----------------------------------------------------

/// Percent-escape `s` so it is one space-free token: bytes that are
/// controls, space, or `%` become `%XX`. The empty string is `~`, and a value
/// that is itself `~` or `-` is escaped so neither can be mistaken for the
/// markers for "empty" and "absent".
fn escape(s: &str) -> String {
    if s.is_empty() {
        return "~".into();
    }
    if s == "-" || s == "~" {
        return format!("%{:02X}", s.as_bytes()[0]);
    }
    let mut out = Vec::with_capacity(s.len());
    for &b in s.as_bytes() {
        if b <= b' ' || b == 0x7f || b == b'%' {
            out.extend_from_slice(format!("%{b:02X}").as_bytes());
        } else {
            // The bytes of a multi-byte character are all >= 0x80 and pass through whole.
            out.push(b);
        }
    }
    String::from_utf8(out).expect("escaping only replaces ASCII bytes")
}

fn escape_opt(s: Option<&str>) -> String {
    s.map_or_else(|| "-".to_string(), escape)
}

fn unescape(token: &str) -> Result<String, String> {
    if token == "~" {
        return Ok(String::new());
    }
    let bytes = token.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = token.get(i + 1..i + 3).ok_or_else(|| format!("truncated escape in {token:?}"))?;
            out.push(u8::from_str_radix(hex, 16).map_err(|_| format!("bad escape in {token:?}"))?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| format!("{token:?} is not UTF-8"))
}

fn unescape_opt(token: &str) -> Result<Option<String>, String> {
    if token == "-" {
        Ok(None)
    } else {
        unescape(token).map(Some)
    }
}

fn secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn from_secs(s: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(s)
}

fn flag(b: bool) -> &'static str {
    if b {
        "1"
    } else {
        "0"
    }
}

fn render_notify(n: &DsnNotify) -> String {
    let mut s = String::new();
    for (on, c) in [(n.never, 'N'), (n.success, 'S'), (n.failure, 'F'), (n.delay, 'D')] {
        if on {
            s.push(c);
        }
    }
    if s.is_empty() {
        s.push('-');
    }
    s
}

fn parse_notify(token: &str) -> Result<DsnNotify, String> {
    let mut n = DsnNotify::default();
    if token != "-" {
        for c in token.chars() {
            match c {
                'N' => n.never = true,
                'S' => n.success = true,
                'F' => n.failure = true,
                'D' => n.delay = true,
                _ => return Err(format!("bad NOTIFY flags {token:?}")),
            }
        }
    }
    Ok(n)
}

fn render_envelope(m: &QueuedMessage) -> String {
    let mut out = String::new();
    let mut line = |s: String| {
        out.push_str(&s);
        out.push('\n');
    };
    line(MAGIC.into());
    line(format!("id {}", m.id));
    line(format!("queued {}", secs(m.queued_at)));
    line(format!("sender {}", escape_opt(m.sender.as_deref())));
    line(format!("smtputf8 {}", flag(m.smtputf8)));
    let d = &m.delivery;
    line(format!("require-tls {}", flag(d.require_tls)));
    if let Some(p) = d.priority {
        line(format!("priority {p}"));
    }
    if let Some(t) = d.hold_until {
        line(format!("hold-until {}", secs(t)));
    }
    if let Some(by) = &d.deliver_by {
        line(format!("deliver-by {} {}", secs(by.deadline), if by.return_on_fail { "R" } else { "N" }));
    }
    if let Some(ret) = d.dsn_ret {
        line(format!("dsn-ret {}", if ret == DsnReturn::Full { "FULL" } else { "HDRS" }));
    }
    if let Some(envid) = &d.dsn_envid {
        line(format!("dsn-envid {}", escape(envid)));
    }
    for h in &m.extra_header_lines {
        line(format!("header {}", escape(h)));
    }
    for r in &m.recipients {
        line(format!(
            "rcpt {} {} {} {} {} {} {} {} {}",
            r.status.token(),
            r.attempts,
            secs(r.next_attempt),
            flag(r.delay_notified),
            render_notify(&r.params.notify),
            escape(&r.address),
            escape_opt(r.params.orcpt_type.as_deref()),
            escape_opt(r.params.orcpt_address.as_deref()),
            escape_opt(r.diagnostic.as_deref()),
        ));
    }
    line("end".into());
    out
}

fn parse_envelope(text: &str, expected_id: &str) -> Result<QueuedMessage, String> {
    let mut lines = text.lines();
    if lines.next() != Some(MAGIC) {
        return Err("not a relay queue envelope, or from a newer version".into());
    }
    let mut id = None;
    let mut queued_at = None;
    let mut m = QueuedMessage {
        id: String::new(),
        queued_at: UNIX_EPOCH,
        sender: None,
        smtputf8: false,
        delivery: DeliveryRequirements::default(),
        extra_header_lines: Vec::new(),
        recipients: Vec::new(),
    };
    let mut ended = false;
    for line in lines {
        let (key, rest) = line.split_once(' ').unwrap_or((line, ""));
        let number = |s: &str| s.parse::<u64>().map_err(|_| format!("bad number {s:?} in {key:?}"));
        let boolean = |s: &str| match s {
            "0" => Ok(false),
            "1" => Ok(true),
            _ => Err(format!("bad flag {s:?} in {key:?}")),
        };
        match key {
            "id" => id = Some(rest.to_string()),
            "queued" => queued_at = Some(from_secs(number(rest)?)),
            "sender" => m.sender = unescape_opt(rest)?,
            "smtputf8" => m.smtputf8 = boolean(rest)?,
            "require-tls" => m.delivery.require_tls = boolean(rest)?,
            "priority" => m.delivery.priority = Some(rest.parse().map_err(|_| format!("bad priority {rest:?}"))?),
            "hold-until" => m.delivery.hold_until = Some(from_secs(number(rest)?)),
            "deliver-by" => {
                let (deadline, mode) = rest.split_once(' ').ok_or("bad deliver-by")?;
                let return_on_fail = match mode {
                    "R" => true,
                    "N" => false,
                    _ => return Err(format!("bad deliver-by mode {mode:?}")),
                };
                m.delivery.deliver_by = Some(DeliverBy { deadline: from_secs(number(deadline)?), return_on_fail });
            }
            "dsn-ret" => {
                m.delivery.dsn_ret = Some(match rest {
                    "FULL" => DsnReturn::Full,
                    "HDRS" => DsnReturn::Hdrs,
                    _ => return Err(format!("bad dsn-ret {rest:?}")),
                })
            }
            "dsn-envid" => m.delivery.dsn_envid = Some(unescape(rest)?),
            "header" => m.extra_header_lines.push(unescape(rest)?),
            "rcpt" => {
                let f: Vec<&str> = rest.split(' ').collect();
                let [status, attempts, next, notified, notify, address, orcpt_type, orcpt_address, diagnostic] = f[..]
                else {
                    return Err(format!("rcpt record has {} fields, expected 9", f.len()));
                };
                m.recipients.push(QueuedRecipient {
                    address: unescape(address)?,
                    params: DsnRecipientParams {
                        notify: parse_notify(notify)?,
                        orcpt_type: unescape_opt(orcpt_type)?,
                        orcpt_address: unescape_opt(orcpt_address)?,
                    },
                    status: RecipientStatus::from_token(status).ok_or_else(|| format!("bad status {status:?}"))?,
                    attempts: attempts.parse().map_err(|_| format!("bad attempts {attempts:?}"))?,
                    next_attempt: from_secs(number(next)?),
                    diagnostic: unescape_opt(diagnostic)?,
                    delay_notified: boolean(notified)?,
                });
            }
            "end" => {
                ended = true;
                break;
            }
            // A record from a later version of the format: not ours to read.
            _ => {}
        }
    }
    if !ended {
        return Err("truncated: no end line".into());
    }
    m.id = id.ok_or("no id line")?;
    if m.id != expected_id {
        return Err(format!("file for {expected_id} says it is {}", m.id));
    }
    m.queued_at = queued_at.ok_or("no queued line")?;
    Ok(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: u64) -> SystemTime {
        from_secs(s)
    }

    fn message(id: &str) -> QueuedMessage {
        QueuedMessage {
            id: id.into(),
            queued_at: at(1_767_225_600),
            sender: Some("alice@example.org".into()),
            smtputf8: false,
            delivery: DeliveryRequirements::default(),
            extra_header_lines: Vec::new(),
            recipients: vec![QueuedRecipient::new("bob@example.net", DsnRecipientParams::default(), at(1_767_225_600))],
        }
    }

    #[cfg(feature = "integration")]
    fn write_content(dir: &Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join(name);
        fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn values_with_awkward_characters_come_back_unchanged() {
        for s in ["plain", "with space", "100%", "a\r\nb", "tab\there", "naïve café", "日本語 text", "-", "~", "--", "%20", ""] {
            let e = escape(s);
            assert!(!e.contains([' ', '\n', '\r', '\t']), "{e:?} must be one token");
            assert_eq!(unescape(&e).unwrap(), s, "{s:?} via {e:?}");
        }
        // "absent" and "empty" are not the same as any value
        assert_eq!(unescape_opt(&escape_opt(None)).unwrap(), None);
        assert_eq!(unescape_opt(&escape_opt(Some(""))).unwrap(), Some(String::new()));
        assert_eq!(unescape_opt(&escape_opt(Some("-"))).unwrap(), Some("-".into()));
    }

    #[test]
    fn a_damaged_escape_is_an_error_not_a_panic() {
        assert!(unescape("%").is_err());
        assert!(unescape("%4").is_err());
        assert!(unescape("%zz").is_err());
        assert!(unescape("%FF").is_err(), "a lone 0xFF is not UTF-8");
    }

    #[test]
    fn an_envelope_with_everything_set_round_trips() {
        let mut m = message("0000656c1a2b-9f3c4d5e6a7b8c9d");
        m.sender = None;
        m.smtputf8 = true;
        m.delivery = DeliveryRequirements {
            require_tls: true,
            priority: Some(-3),
            hold_until: Some(at(1_767_300_000)),
            deliver_by: Some(DeliverBy { deadline: at(1_767_400_000), return_on_fail: true }),
            dsn_ret: Some(DsnReturn::Hdrs),
            dsn_envid: Some("env id/1".into()),
        };
        m.extra_header_lines = vec!["X-Spam: no, really".into(), "Received: from a\tb".into()];
        m.recipients = vec![
            QueuedRecipient {
                address: "bob@example.net".into(),
                params: DsnRecipientParams {
                    notify: DsnNotify { never: false, success: true, failure: true, delay: true },
                    orcpt_type: Some("rfc822".into()),
                    orcpt_address: Some("orig inal@example.net".into()),
                },
                status: RecipientStatus::Pending,
                attempts: 3,
                next_attempt: at(1_767_229_200),
                diagnostic: Some("451 4.2.1 mailbox busy, try later".into()),
                delay_notified: true,
            },
            QueuedRecipient {
                status: RecipientStatus::Delivered,
                ..QueuedRecipient::new("carol@example.com", DsnRecipientParams::default(), at(0))
            },
            QueuedRecipient {
                status: RecipientStatus::Failed,
                diagnostic: Some("550 5.1.1 no such user".into()),
                ..QueuedRecipient::new("dave@example.com", DsnRecipientParams::default(), at(0))
            },
        ];
        let text = render_envelope(&m);
        assert_eq!(parse_envelope(&text, &m.id).unwrap(), m, "{text}");
    }

    #[cfg(feature = "integration")]
    #[test]
    fn a_message_put_in_the_queue_is_found_by_a_scan_with_its_content_moved_in() {
        let tmp = tempfile::tempdir().unwrap();
        let q = RelayQueue::open(tmp.path().join("queue")).unwrap();
        let content = write_content(tmp.path(), "spool.tmp", "Subject: hi\r\n\r\nbody\r\n");
        let m = message(&RelayQueue::new_id());
        q.enqueue(&m, &content).unwrap();
        assert!(!content.exists(), "the spool file is taken over");
        assert_eq!(fs::read_to_string(q.content_path(&m.id)).unwrap(), "Subject: hi\r\n\r\nbody\r\n");
        let scan = q.scan().unwrap();
        assert_eq!(scan.messages, [m]);
        assert!(scan.unreadable.is_empty() && scan.orphans.is_empty());
    }

    #[cfg(feature = "integration")]
    #[test]
    fn a_message_whose_content_is_missing_is_not_queued() {
        let tmp = tempfile::tempdir().unwrap();
        let q = RelayQueue::open(tmp.path()).unwrap();
        let m = message(&RelayQueue::new_id());
        assert!(q.enqueue(&m, &tmp.path().join("nothing.tmp")).is_err());
        assert!(q.scan().unwrap().messages.is_empty());
    }

    #[cfg(feature = "integration")]
    #[test]
    fn an_update_replaces_the_state_and_a_removal_deletes_both_files() {
        let tmp = tempfile::tempdir().unwrap();
        let q = RelayQueue::open(tmp.path().join("q")).unwrap();
        let mut m = message(&RelayQueue::new_id());
        q.enqueue(&m, &write_content(tmp.path(), "s.tmp", "x")).unwrap();

        m.recipients[0].attempts = 4;
        m.recipients[0].status = RecipientStatus::Delivered;
        q.update(&m).unwrap();
        let scan = q.scan().unwrap();
        assert_eq!(scan.messages[0].recipients[0].attempts, 4);
        assert!(scan.messages[0].is_finished());

        q.remove(&m.id).unwrap();
        assert_eq!(fs::read_dir(q.dir()).unwrap().count(), 0, "nothing is left behind");
        q.remove(&m.id).unwrap(); // removing twice is not an error
    }

    #[cfg(feature = "integration")]
    #[test]
    fn updating_a_message_that_is_not_queued_is_an_error_not_a_resurrection() {
        let tmp = tempfile::tempdir().unwrap();
        let q = RelayQueue::open(tmp.path()).unwrap();
        let m = message(&RelayQueue::new_id());
        assert_eq!(q.update(&m).unwrap_err().kind(), io::ErrorKind::NotFound);
        assert!(q.scan().unwrap().messages.is_empty());
    }

    #[cfg(feature = "integration")]
    #[test]
    fn a_scan_lists_messages_in_the_order_they_arrived() {
        let tmp = tempfile::tempdir().unwrap();
        let q = RelayQueue::open(tmp.path().join("q")).unwrap();
        for (id, queued) in [("bbbb", 300), ("aaaa", 200), ("cccc", 100)] {
            let mut m = message(id);
            m.queued_at = at(queued);
            q.enqueue(&m, &write_content(tmp.path(), &format!("{id}.tmp"), "x")).unwrap();
        }
        let ids: Vec<String> = q.scan().unwrap().messages.into_iter().map(|m| m.id).collect();
        assert_eq!(ids, ["cccc", "aaaa", "bbbb"]);
    }

    #[cfg(feature = "integration")]
    #[test]
    fn a_torn_or_foreign_envelope_is_reported_and_does_not_stop_the_scan() {
        let tmp = tempfile::tempdir().unwrap();
        let q = RelayQueue::open(tmp.path().join("q")).unwrap();
        let good = message("aaaa");
        q.enqueue(&good, &write_content(tmp.path(), "g.tmp", "x")).unwrap();

        let full = render_envelope(&message("bbbb"));
        fs::write(q.dir().join("bbbb.env"), &full[..full.len() - 4]).unwrap(); // cut before `end`
        fs::write(q.dir().join("cccc.env"), "something else entirely\n").unwrap();
        fs::write(q.dir().join("dddd.env"), full.replace("id bbbb", "id eeee")).unwrap(); // renamed by hand

        let scan = q.scan().unwrap();
        assert_eq!(scan.messages, [good]);
        let mut bad: Vec<String> = scan
            .unreadable
            .iter()
            .map(|(p, _)| p.file_name().unwrap().to_str().unwrap().to_string())
            .collect();
        bad.sort();
        assert_eq!(bad, ["bbbb.env", "cccc.env", "dddd.env"]);
        assert!(q.dir().join("bbbb.env").exists(), "damaged files are left for an operator");
    }

    #[cfg(feature = "integration")]
    #[test]
    fn content_with_no_envelope_is_an_orphan_and_stray_files_are_ignored() {
        let tmp = tempfile::tempdir().unwrap();
        let q = RelayQueue::open(tmp.path()).unwrap();
        fs::write(q.dir().join("abcd.msg"), "left by a crash").unwrap();
        fs::write(q.dir().join("abcd.env.tmp"), "half written").unwrap();
        fs::write(q.dir().join("README"), "not ours").unwrap();
        fs::write(q.dir().join("not an id.msg"), "not ours").unwrap();
        let scan = q.scan().unwrap();
        assert!(scan.messages.is_empty() && scan.unreadable.is_empty());
        assert_eq!(scan.orphans, [q.dir().join("abcd.msg")]);
    }

    #[cfg(feature = "integration")]
    #[test]
    fn an_id_cannot_name_a_file_outside_the_queue() {
        let tmp = tempfile::tempdir().unwrap();
        let q = RelayQueue::open(tmp.path().join("q")).unwrap();
        for bad in ["", "../x", "a/b", "a b", "x.env", "..", "g"] {
            let m = message(bad);
            assert!(q.enqueue(&m, &tmp.path().join("c")).is_err(), "{bad:?}");
            assert!(q.update(&m).is_err(), "{bad:?}");
            assert!(q.remove(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn ids_are_unique_valid_and_sort_by_time() {
        let a = RelayQueue::new_id();
        let b = RelayQueue::new_id();
        assert_ne!(a, b);
        assert!(check_id(&a).is_ok() && check_id(&b).is_ok());
        assert!(a.as_str() <= b.as_str() || a[..12] == b[..12], "{a} {b}");
    }

    #[test]
    fn a_message_knows_when_it_is_finished_and_when_it_is_next_due() {
        let mut m = message("aaaa");
        m.recipients.push(QueuedRecipient::new("c@example.net", DsnRecipientParams::default(), at(50)));
        m.recipients[0].next_attempt = at(90);
        assert!(!m.is_finished());
        assert_eq!(m.next_due(), Some(at(50)));
        m.recipients[1].status = RecipientStatus::Failed;
        assert_eq!(m.next_due(), Some(at(90)), "a failed recipient is no longer due");
        m.recipients[0].status = RecipientStatus::Delivered;
        assert!(m.is_finished());
        assert_eq!(m.next_due(), None);
    }
}
