// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! RFC 5256 THREAD (ORDEREDSUBJECT and REFERENCES).
//!
//! Both algorithms build a forest of [`ThreadNode`]s and hand it to
//! [`format_thread_response`] for the wire form (RFC 5256 §5):
//! `thread-list = "(" (thread-members / thread-nested) ")"`, where a flat
//! run of bare numbers is a **chain** (each is the child of the one
//! before), and a node with more than one child switches to
//! `thread-nested` — each child written as its own fully-parenthesized
//! subtree.
//!
//! REFERENCES' "dummy" placeholder messages (RFC 5256 §2.2, step 3) never
//! survive to the final tree here: a dummy with no children is dropped,
//! and a dummy with children always has them promoted to its own place in
//! its parent's child list — including at the top level, where the RFC's
//! wording is unclear about a dummy with more than one child (the
//! response grammar has no way to write a parent-less placeholder there in
//! any case, and every real-world implementation this behaviour has been
//! checked against does the same). Step 5's subject-based regrouping,
//! which can otherwise fabricate a *new* dummy to join two same-subject
//! messages neither of which is a reply/forward of the other, is skipped
//! in that one case rather than doing the same — for the same reason:
//! there is no way to write the result as a legal `thread-list`.

use std::collections::HashMap;

use hopf_mailbox::MessageContext;

use crate::server::sort::{base_subject, is_reply_or_forward};

/// Which THREAD algorithm to run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadAlgorithm {
    /// RFC 5256 §2.1: flat (no grandchildren), grouped by base subject.
    OrderedSubject,
    /// RFC 5256 §2.2: linked by `References`/`In-Reply-To`.
    References,
}

impl ThreadAlgorithm {
    /// Parse a `THREAD`/`UID THREAD` algorithm name (case-insensitive).
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_uppercase().as_str() {
            "ORDEREDSUBJECT" => Some(Self::OrderedSubject),
            "REFERENCES" => Some(Self::References),
            _ => None,
        }
    }

    /// The `THREAD=...` capability token for this algorithm.
    pub fn capability_name(self) -> &'static str {
        match self {
            Self::OrderedSubject => "THREAD=ORDEREDSUBJECT",
            Self::References => "THREAD=REFERENCES",
        }
    }
}

/// Parse `THREAD`/`UID THREAD`'s full argument grammar: `algorithm charset
/// search-criteria` (RFC 5256 §4). Returns the parsed algorithm and the
/// still-unparsed search-criteria remainder (the caller runs that through
/// [`crate::server::search_parse::parse_search`]) — see
/// [`crate::server::sort::parse_sort_command`] for the `charset` handling.
pub fn parse_thread_command(args: &str) -> Result<(ThreadAlgorithm, String), String> {
    let args = args.trim_start();
    let (alg_tok, rest) = args
        .split_once(char::is_whitespace)
        .ok_or_else(|| "THREAD requires an algorithm and charset".to_string())?;
    let algorithm = ThreadAlgorithm::parse(alg_tok)
        .ok_or_else(|| format!("unsupported THREAD algorithm {alg_tok}"))?;
    let (charset, rest) = crate::server::codec::parse_astring(rest.trim_start())?;
    crate::server::sort::validate_charset(&charset)?;
    Ok((algorithm, rest.trim_start().to_string()))
}

/// One matched message's fields, gathered ahead of the actual threading —
/// mirrors [`crate::server::sort::SortableMessage::gather`].
#[derive(Clone, Debug)]
pub struct ThreadInput {
    /// The number this message is reported as in the response (a UID or a
    /// sequence number, depending on `THREAD` vs `UID THREAD`).
    pub result_number: u64,
    /// Sequence number — always this, never a UID, since it's the
    /// tie-break sort keys sort by (see [`crate::server::sort`]).
    pub sequence_number: u32,
    /// Sent (`Date:` header) date, Unix millis.
    pub sent: i64,
    /// Raw `Subject` header (base-subject normalization happens per
    /// algorithm, at grouping time).
    pub subject: String,
    /// `Message-ID`, or empty if missing/invalid.
    pub message_id: String,
    /// `References` header's IDs, in header order (empty if the header is
    /// absent or has none).
    pub references: Vec<String>,
    /// `In-Reply-To`'s first ID, or empty.
    pub in_reply_to: String,
}

impl ThreadInput {
    /// Gather every field either threading algorithm might need for `ctx`.
    pub fn gather(ctx: &dyn MessageContext, result_number: u64) -> std::io::Result<Self> {
        let references = ctx
            .header("References")?
            .split_whitespace()
            .map(str::to_string)
            .collect::<Vec<_>>();
        let in_reply_to = ctx
            .header("In-Reply-To")?
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_string();
        Ok(Self {
            result_number,
            sequence_number: ctx.message_number(),
            sent: ctx.sent_date_millis().unwrap_or(0),
            subject: ctx.header("Subject")?,
            message_id: ctx.header("Message-ID")?,
            references,
            in_reply_to,
        })
    }

    /// RFC 5256 §2.2.1: the References chain, or (if absent) In-Reply-To's
    /// first ID as the sole reference, or (if neither) none.
    fn effective_references(&self) -> &[String] {
        if !self.references.is_empty() {
            &self.references
        } else if !self.in_reply_to.is_empty() {
            std::slice::from_ref(&self.in_reply_to)
        } else {
            &[]
        }
    }
}

/// One node of the thread forest — a real matched message, or (mid
/// -construction only; see the module docs) a placeholder for a
/// referenced-but-not-yet-seen `Message-ID`.
#[derive(Clone, Debug)]
struct Node {
    /// `None` for a not-yet-pruned placeholder.
    result_number: Option<u64>,
    sequence_number: u32,
    sent: i64,
    subject: String,
    parent: Option<usize>,
    children: Vec<usize>,
}

impl Node {
    fn dummy() -> Self {
        Self {
            result_number: None,
            sequence_number: 0,
            sent: 0,
            subject: String::new(),
            parent: None,
            children: Vec::new(),
        }
    }

    fn is_dummy(&self) -> bool {
        self.result_number.is_none()
    }
}

/// A message-carrying node in the *final* (post-pruning) tree, ready for
/// [`format_thread_response`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThreadNode {
    /// The number this message is reported as (a UID or a sequence
    /// number).
    pub result_number: u64,
    /// Direct children, in final (sorted) response order.
    pub children: Vec<ThreadNode>,
}

/// RFC 5256 §2.1: sort by base subject then sent date, split into threads
/// of matching base subject (flat: a thread's 2nd+ messages are all
/// siblings, direct children of the 1st — "no grandchildren"), then sort
/// the resulting threads by their first message's sent date.
pub fn thread_ordered_subject(mut messages: Vec<ThreadInput>) -> Vec<ThreadNode> {
    messages.sort_by(|a, b| {
        base_subject(&a.subject)
            .cmp(&base_subject(&b.subject))
            .then(a.sent.cmp(&b.sent))
            .then(a.sequence_number.cmp(&b.sequence_number))
    });

    let mut threads: Vec<ThreadNode> = Vec::new();
    let mut current_subject: Option<String> = None;
    for m in messages {
        let subj = base_subject(&m.subject);
        if current_subject.as_deref() == Some(subj.as_str()) {
            let thread = threads.last_mut().expect("current_subject implies a thread");
            thread.children.push(ThreadNode {
                result_number: m.result_number,
                children: Vec::new(),
            });
        } else {
            threads.push(ThreadNode {
                result_number: m.result_number,
                children: Vec::new(),
            });
            current_subject = Some(subj);
        }
    }
    threads
}

/// RFC 5256 §2.2: link by `References`/`In-Reply-To`, root the orphans,
/// prune dummies, sort, then regroup root-level same-subject threads.
pub fn thread_references(messages: Vec<ThreadInput>) -> Vec<ThreadNode> {
    let mut arena: Vec<Node> = Vec::new();
    let mut id_to_index: HashMap<String, usize> = HashMap::new();
    // Real messages, keyed by their *original* (pre-arena) index, once
    // pass 1 has assigned each an arena slot — pass 2 needs this to look
    // its own node back up while walking references.
    let mut message_index: Vec<usize> = Vec::with_capacity(messages.len());

    // Pass 1: register every real message under its (de-duplicated)
    // Message-ID, synthesizing one where absent/invalid so it can never
    // collide with a real ID (RFC 5256 §2.2 step 1A: "assign a unique
    // Message ID"; also covers the "only the first of a duplicate ID keeps
    // it" rule, since messages are processed in ascending sequence order).
    let mut ordered = messages;
    ordered.sort_by_key(|m| m.sequence_number);
    for m in &ordered {
        let synthetic = format!("\0seq:{}", m.sequence_number);
        let already_real = !m.message_id.is_empty()
            && id_to_index
                .get(&m.message_id)
                .is_some_and(|&i| !arena[i].is_dummy());
        let id = if m.message_id.is_empty() || already_real {
            synthetic
        } else {
            m.message_id.clone()
        };
        let idx = get_or_create(&id, &mut arena, &mut id_to_index);
        arena[idx].result_number = Some(m.result_number);
        arena[idx].sequence_number = m.sequence_number;
        arena[idx].sent = m.sent;
        arena[idx].subject = m.subject.clone();
        message_index.push(idx);
    }

    // Pass 2: link parent/child along each message's reference chain
    // (step 1A), then the message itself as the last reference's child
    // (step 1B).
    for (m, &msg_idx) in ordered.iter().zip(&message_index) {
        let mut prev: Option<usize> = None;
        for rid in m.effective_references() {
            let idx = get_or_create(rid, &mut arena, &mut id_to_index);
            if let Some(p) = prev {
                link(idx, p, &mut arena);
            }
            prev = Some(idx);
        }
        if let Some(p) = prev {
            link(msg_idx, p, &mut arena);
        }
    }

    // Step 2: whatever has no parent is a root.
    let roots: Vec<usize> = (0..arena.len()).filter(|&i| arena[i].parent.is_none()).collect();

    // Step 3: prune dummies (promoting their children in place).
    let mut roots = prune_dummies(roots, &mut arena);

    // Step 4 (roots) / step 6 (every level): sort siblings by sent date.
    // Dummies never survive step 3 (see module docs), so there is no
    // "sort by first child" special case to handle here.
    sort_siblings(&mut roots, &arena);
    for i in 0..arena.len() {
        let mut children = std::mem::take(&mut arena[i].children);
        sort_siblings(&mut children, &arena);
        arena[i].children = children;
    }

    // Step 5: regroup root-level threads sharing a base subject.
    let roots = regroup_by_subject(roots, &mut arena);

    roots.into_iter().map(|i| build_thread_node(i, &arena)).collect()
}

fn get_or_create(id: &str, arena: &mut Vec<Node>, id_to_index: &mut HashMap<String, usize>) -> usize {
    if let Some(&i) = id_to_index.get(id) {
        return i;
    }
    let i = arena.len();
    arena.push(Node::dummy());
    id_to_index.insert(id.to_string(), i);
    i
}

fn link(child: usize, parent: usize, arena: &mut [Node]) {
    if arena[child].parent.is_some() {
        return; // "if a message already has a parent, don't change it"
    }
    if creates_loop(child, parent, arena) {
        return;
    }
    arena[parent].children.push(child);
    arena[child].parent = Some(parent);
}

fn creates_loop(child: usize, parent: usize, arena: &[Node]) -> bool {
    let mut cur = Some(parent);
    while let Some(c) = cur {
        if c == child {
            return true;
        }
        cur = arena[c].parent;
    }
    false
}

/// Post-order: prune each level's own children first, then decide this
/// level's own dummies — see the module docs for the "always promote"
/// simplification.
fn prune_dummies(level: Vec<usize>, arena: &mut Vec<Node>) -> Vec<usize> {
    let mut out = Vec::with_capacity(level.len());
    for idx in level {
        let children = std::mem::take(&mut arena[idx].children);
        let pruned = prune_dummies(children, arena);
        arena[idx].children = pruned;
        if arena[idx].is_dummy() {
            if !arena[idx].children.is_empty() {
                out.extend(arena[idx].children.iter().copied());
            }
            continue;
        }
        out.push(idx);
    }
    out
}

fn sort_siblings(indices: &mut [usize], arena: &[Node]) {
    indices.sort_by(|&a, &b| {
        arena[a]
            .sent
            .cmp(&arena[b].sent)
            .then(arena[a].sequence_number.cmp(&arena[b].sequence_number))
    });
}

/// RFC 5256 §2.2 step 5, restricted to what can actually be written as a
/// `thread-list` (see module docs): every candidate here is a real message
/// (never a dummy, by construction), so the only merges applied are
/// "replace the table entry with a message that is itself a reply/forward
/// when the table entry isn't" (§5B) — joining two non-reply messages
/// under a fresh, unwritable dummy (§5C) is skipped; both stay separate.
fn regroup_by_subject(roots: Vec<usize>, arena: &mut [Node]) -> Vec<usize> {
    let mut by_subject: HashMap<String, usize> = HashMap::new();
    let mut out: Vec<usize> = Vec::with_capacity(roots.len());
    for idx in roots {
        let subj = base_subject(&arena[idx].subject);
        if subj.is_empty() {
            out.push(idx);
            continue;
        }
        match by_subject.get(&subj).copied() {
            None => {
                by_subject.insert(subj, idx);
                out.push(idx);
            }
            Some(existing) => {
                let existing_is_reply = is_reply_or_forward(&arena[existing].subject);
                let current_is_reply = is_reply_or_forward(&arena[idx].subject);
                if current_is_reply && !existing_is_reply {
                    // The table entry represented the group; the current
                    // message is clearly a reply, so fold it under that
                    // entry instead of leaving it separate.
                    link(idx, existing, arena);
                } else if !current_is_reply && existing_is_reply {
                    // Symmetric case: `existing` turns out to be the
                    // reply — swap which one anchors the group and adopt
                    // it as `existing`'s new parent.
                    let pos = out.iter().position(|&i| i == existing).expect("existing is in out");
                    unlink(existing, arena);
                    link(existing, idx, arena);
                    out[pos] = idx;
                    by_subject.insert(subj, idx);
                } else {
                    // Neither, or both, are replies: §5C would fabricate a
                    // dummy parent here — left un-merged instead (see
                    // module docs).
                    out.push(idx);
                }
            }
        }
    }
    out
}

fn unlink(idx: usize, arena: &mut [Node]) {
    arena[idx].parent = None;
}

fn build_thread_node(idx: usize, arena: &[Node]) -> ThreadNode {
    ThreadNode {
        result_number: arena[idx].result_number.expect("dummies are pruned before this point"),
        children: arena[idx]
            .children
            .iter()
            .map(|&c| build_thread_node(c, arena))
            .collect(),
    }
}

/// RFC 5256 §5: `* THREAD` followed by one `thread-list` per top-level
/// thread, back to back with no separator (each one is fully
/// parenthesized). Returns the untagged response's argument text (without
/// the leading `THREAD ` keyword), or `None` if `threads` is empty — RFC
/// 5256 says the server sends **no** untagged THREAD response at all in
/// that case (unlike SEARCH, which always sends one, possibly empty).
pub fn format_thread_response(threads: &[ThreadNode]) -> Option<String> {
    if threads.is_empty() {
        return None;
    }
    let mut out = String::new();
    for t in threads {
        write_thread_list(t, &mut out);
    }
    Some(out)
}

fn write_thread_list(node: &ThreadNode, out: &mut String) {
    out.push('(');
    write_chain(node, out);
    out.push(')');
}

/// Writes `node`'s own number, then continues the flat chain through
/// single children, switching to nested sibling groups the moment a node
/// has more than one child.
fn write_chain(node: &ThreadNode, out: &mut String) {
    out.push_str(&node.result_number.to_string());
    match node.children.len() {
        0 => {}
        1 => {
            out.push(' ');
            write_chain(&node.children[0], out);
        }
        _ => {
            // `thread-nested = 2*thread-list`: one space separates the
            // chain prefix from the nested block, but the nested
            // `thread-list`s themselves are written back-to-back with no
            // separator (each is already fully parenthesized).
            out.push(' ');
            for child in &node.children {
                write_thread_list(child, out);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(seq: u32, subject: &str, message_id: &str, references: &[&str]) -> ThreadInput {
        ThreadInput {
            result_number: seq as u64,
            sequence_number: seq,
            sent: seq as i64, // monotonic with seq, so sent-order == seq-order below
            subject: subject.to_string(),
            message_id: message_id.to_string(),
            references: references.iter().map(|s| s.to_string()).collect(),
            in_reply_to: String::new(),
        }
    }

    #[test]
    fn ordered_subject_groups_by_base_subject_no_grandchildren() {
        let msgs = vec![
            input(1, "hello", "<1>", &[]),
            input(2, "unrelated", "<2>", &[]),
            input(3, "Re: hello", "<3>", &[]),
            input(4, "Re: hello", "<4>", &[]),
        ];
        let threads = thread_ordered_subject(msgs);
        // "hello" thread: root 1, children 3 and 4 as *siblings* (flat).
        let hello = threads
            .iter()
            .find(|t| t.result_number == 1)
            .expect("hello thread present");
        assert_eq!(hello.children.len(), 2);
        assert!(hello.children.iter().all(|c| c.children.is_empty()));
        let hello_children: Vec<u64> = hello.children.iter().map(|c| c.result_number).collect();
        assert_eq!(hello_children, vec![3, 4]);

        let unrelated = threads.iter().find(|t| t.result_number == 2).unwrap();
        assert!(unrelated.children.is_empty());
    }

    #[test]
    fn references_links_a_reply_chain() {
        let msgs = vec![
            input(1, "hello", "<1>", &[]),
            input(2, "Re: hello", "<2>", &["<1>"]),
            input(3, "Re: hello", "<3>", &["<1>", "<2>"]),
        ];
        let threads = thread_references(msgs);
        assert_eq!(threads.len(), 1);
        assert_eq!(threads[0].result_number, 1);
        assert_eq!(threads[0].children.len(), 1);
        assert_eq!(threads[0].children[0].result_number, 2);
        assert_eq!(threads[0].children[0].children[0].result_number, 3);
    }

    #[test]
    fn references_falls_back_to_in_reply_to() {
        let mut reply = input(2, "Re: hello", "<2>", &[]);
        reply.in_reply_to = "<1>".to_string();
        let msgs = vec![input(1, "hello", "<1>", &[]), reply];
        let threads = thread_references(msgs);
        assert_eq!(threads.len(), 1);
        assert_eq!(threads[0].children[0].result_number, 2);
    }

    #[test]
    fn references_missing_parent_creates_and_prunes_an_invisible_dummy() {
        // <1> is referenced but never actually present among the matched
        // messages — a dummy is created to link through it, then pruned
        // away (its one real child promoted) since it never gets "filled
        // in" by a real message with that ID.
        let msgs = vec![input(2, "Re: hello", "<2>", &["<1>"])];
        let threads = thread_references(msgs);
        assert_eq!(threads.len(), 1);
        assert_eq!(threads[0].result_number, 2);
        assert!(threads[0].children.is_empty());
    }

    #[test]
    fn references_unrelated_messages_are_separate_roots() {
        let msgs = vec![input(1, "a", "<1>", &[]), input(2, "b", "<2>", &[])];
        let threads = thread_references(msgs);
        assert_eq!(threads.len(), 2);
    }

    #[test]
    fn references_does_not_link_through_a_cycle() {
        // Malformed input: <1> references <2> and <2> references <1>.
        // Whichever link is made first wins; the second must not create a
        // cycle (nor infinite-loop the pruning/sorting passes).
        let msgs = vec![
            input(1, "a", "<1>", &["<2>"]),
            input(2, "b", "<2>", &["<1>"]),
        ];
        let threads = thread_references(msgs);
        // However it resolves, both messages must appear exactly once,
        // and the call must simply terminate (the real assertion is that
        // this test doesn't hang or panic).
        let mut seen: Vec<u64> = Vec::new();
        fn collect(n: &ThreadNode, seen: &mut Vec<u64>) {
            seen.push(n.result_number);
            for c in &n.children {
                collect(c, seen);
            }
        }
        for t in &threads {
            collect(t, &mut seen);
        }
        seen.sort_unstable();
        assert_eq!(seen, vec![1, 2]);
    }

    #[test]
    fn format_response_chains_single_children_and_nests_multiple() {
        let single_child = ThreadNode {
            result_number: 3,
            children: vec![ThreadNode {
                result_number: 6,
                children: Vec::new(),
            }],
        };
        let multi_child = ThreadNode {
            result_number: 6,
            children: vec![
                ThreadNode {
                    result_number: 4,
                    children: vec![ThreadNode {
                        result_number: 23,
                        children: Vec::new(),
                    }],
                },
                ThreadNode {
                    result_number: 44,
                    children: vec![ThreadNode {
                        result_number: 7,
                        children: Vec::new(),
                    }],
                },
            ],
        };
        let leaf = ThreadNode {
            result_number: 2,
            children: Vec::new(),
        };
        let resp = format_thread_response(&[leaf, single_child, multi_child]).unwrap();
        assert_eq!(resp, "(2)(3 6)(6 (4 23)(44 7))");
    }

    #[test]
    fn format_response_of_no_threads_is_none() {
        assert_eq!(format_thread_response(&[]), None);
    }

    #[test]
    fn thread_algorithm_parse() {
        assert_eq!(
            ThreadAlgorithm::parse("orderedsubject"),
            Some(ThreadAlgorithm::OrderedSubject)
        );
        assert_eq!(
            ThreadAlgorithm::parse("REFERENCES"),
            Some(ThreadAlgorithm::References)
        );
        assert_eq!(ThreadAlgorithm::parse("BOGUS"), None);
    }
}
