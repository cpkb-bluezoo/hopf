// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! IMAP response formatting (tagged / untagged / continuation).

/// Tagged `OK`.
pub fn tagged_ok(tag: &str, text: &str) -> Vec<u8> {
    format!("{tag} OK {text}\r\n").into_bytes()
}

/// Tagged `NO`.
pub fn tagged_no(tag: &str, text: &str) -> Vec<u8> {
    format!("{tag} NO {text}\r\n").into_bytes()
}

/// Tagged `BAD`.
pub fn tagged_bad(tag: &str, text: &str) -> Vec<u8> {
    format!("{tag} BAD {text}\r\n").into_bytes()
}

/// Untagged response (`* …`).
pub fn untagged(text: &str) -> Vec<u8> {
    format!("* {text}\r\n").into_bytes()
}

/// Continuation request (`+ …`).
pub fn continuation(text: &str) -> Vec<u8> {
    if text.is_empty() {
        b"+ \r\n".to_vec()
    } else {
        format!("+ {text}\r\n").into_bytes()
    }
}

/// Quote an IMAP mailbox / astring for LIST responses.
pub fn quote_astring(s: &str) -> String {
    if s.is_empty() {
        return "\"\"".into();
    }
    if s.bytes().all(|b| {
        b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'@' | b'/' | b'&' | b'=')
    }) {
        return s.to_string();
    }
    let mut out = String::from("\"");
    for c in s.chars() {
        if c == '\\' || c == '"' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

/// Format LIST attribute atoms.
pub fn format_list_attrs(
    attrs: &std::collections::BTreeSet<hopf_mailbox::MailboxAttribute>,
) -> String {
    use hopf_mailbox::MailboxAttribute;
    let parts: Vec<&str> = attrs
        .iter()
        .map(|a| match a {
            MailboxAttribute::NoInferiors => "\\Noinferiors",
            MailboxAttribute::NoSelect => "\\Noselect",
            MailboxAttribute::Marked => "\\Marked",
            MailboxAttribute::Unmarked => "\\Unmarked",
            MailboxAttribute::HasChildren => "\\HasChildren",
            MailboxAttribute::HasNoChildren => "\\HasNoChildren",
        })
        .collect();
    format!("({})", parts.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tagged_forms() {
        assert_eq!(tagged_ok("a1", "done"), b"a1 OK done\r\n");
        assert_eq!(tagged_no("a1", "fail"), b"a1 NO fail\r\n");
        assert_eq!(tagged_bad("*", "bad"), b"* BAD bad\r\n");
        assert_eq!(
            untagged("CAPABILITY IMAP4rev2"),
            b"* CAPABILITY IMAP4rev2\r\n"
        );
        assert_eq!(continuation("Ready"), b"+ Ready\r\n");
    }
}
