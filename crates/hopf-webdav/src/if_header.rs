// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! RFC 4918 §10.4 If header parser and evaluator.

use std::path::Path;

use crate::lock::WebDavLockManager;

/// A single condition within a parenthesized list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfCondition {
    pub negated: bool,
    pub state_token: Option<String>,
    pub entity_tag: Option<String>,
}

/// Parenthesized list of conditions (AND'd).
#[derive(Debug, Default, Clone)]
pub struct IfConditionList {
    pub conditions: Vec<IfCondition>,
}

/// Tagged or untagged group of condition lists (OR'd within group).
#[derive(Debug, Clone)]
pub struct IfGroup {
    pub resource_tag: Option<String>,
    pub lists: Vec<IfConditionList>,
}

/// Parse an If header value into groups.
pub fn parse_if_header(header: &str) -> Vec<IfGroup> {
    IfHeaderParser::new(header).parse()
}

struct IfHeaderParser<'a> {
    header: &'a str,
    pos: usize,
}

impl<'a> IfHeaderParser<'a> {
    fn new(header: &'a str) -> Self {
        Self { header, pos: 0 }
    }

    fn parse(mut self) -> Vec<IfGroup> {
        let mut groups = Vec::new();
        self.skip_whitespace();
        while self.pos < self.header.len() {
            let bytes = self.header.as_bytes();
            if bytes[self.pos] == b'<' {
                let saved = self.pos;
                let Some(uri) = self.read_angle_bracketed_uri() else {
                    break;
                };
                self.skip_whitespace();
                if self.pos < self.header.len() && bytes[self.pos] == b'(' {
                    let mut group = IfGroup {
                        resource_tag: Some(uri),
                        lists: Vec::new(),
                    };
                    while self.pos < self.header.len() && self.header.as_bytes()[self.pos] == b'(' {
                        if let Some(list) = self.read_condition_list() {
                            group.lists.push(list);
                        }
                        self.skip_whitespace();
                    }
                    groups.push(group);
                } else {
                    self.pos = saved;
                    let mut group = IfGroup {
                        resource_tag: None,
                        lists: Vec::new(),
                    };
                    while self.pos < self.header.len() && self.header.as_bytes()[self.pos] == b'('
                    {
                        if let Some(list) = self.read_condition_list() {
                            group.lists.push(list);
                        }
                        self.skip_whitespace();
                    }
                    if !group.lists.is_empty() {
                        groups.push(group);
                    }
                }
            } else if bytes[self.pos] == b'(' {
                let mut group = IfGroup {
                    resource_tag: None,
                    lists: Vec::new(),
                };
                while self.pos < self.header.len() && self.header.as_bytes()[self.pos] == b'(' {
                    if let Some(list) = self.read_condition_list() {
                        group.lists.push(list);
                    }
                    self.skip_whitespace();
                }
                if !group.lists.is_empty() {
                    groups.push(group);
                }
            } else {
                self.pos += 1;
            }
            self.skip_whitespace();
        }
        groups
    }

    fn read_condition_list(&mut self) -> Option<IfConditionList> {
        if self.pos >= self.header.len() || self.header.as_bytes()[self.pos] != b'(' {
            return None;
        }
        self.pos += 1;
        self.skip_whitespace();
        let mut list = IfConditionList::default();
        while self.pos < self.header.len() && self.header.as_bytes()[self.pos] != b')' {
            let mut negated = false;
            if self.pos + 3 <= self.header.len() {
                let slice = &self.header[self.pos..self.pos + 3];
                if slice.eq_ignore_ascii_case("not") {
                    let after = self.header.as_bytes().get(self.pos + 3).copied();
                    if matches!(after, Some(b' ') | Some(b'\t') | Some(b'<') | Some(b'[') | None) {
                        negated = true;
                        self.pos += 3;
                        self.skip_whitespace();
                    }
                }
            }
            if self.pos >= self.header.len() {
                break;
            }
            match self.header.as_bytes()[self.pos] {
                b'<' => {
                    if let Some(token) = self.read_angle_bracketed_uri() {
                        list.conditions.push(IfCondition {
                            negated,
                            state_token: Some(token),
                            entity_tag: None,
                        });
                    }
                }
                b'[' => {
                    if let Some(etag) = self.read_entity_tag() {
                        list.conditions.push(IfCondition {
                            negated,
                            state_token: None,
                            entity_tag: Some(etag),
                        });
                    }
                }
                _ => self.pos += 1,
            }
            self.skip_whitespace();
        }
        if self.pos < self.header.len() && self.header.as_bytes()[self.pos] == b')' {
            self.pos += 1;
        }
        if list.conditions.is_empty() {
            None
        } else {
            Some(list)
        }
    }

    fn read_angle_bracketed_uri(&mut self) -> Option<String> {
        if self.pos >= self.header.len() || self.header.as_bytes()[self.pos] != b'<' {
            return None;
        }
        let start = self.pos + 1;
        let end = self.header[start..].find('>')? + start;
        let uri = self.header[start..end].to_string();
        self.pos = end + 1;
        Some(uri)
    }

    fn read_entity_tag(&mut self) -> Option<String> {
        if self.pos >= self.header.len() || self.header.as_bytes()[self.pos] != b'[' {
            return None;
        }
        let start = self.pos + 1;
        let end = self.header[start..].find(']')? + start;
        let etag = self.header[start..end].trim().to_string();
        self.pos = end + 1;
        Some(etag)
    }

    fn skip_whitespace(&mut self) {
        while self.pos < self.header.len() {
            match self.header.as_bytes()[self.pos] {
                b' ' | b'\t' => self.pos += 1,
                _ => break,
            }
        }
    }
}

/// Evaluate parsed If groups against resource state.
pub fn evaluate_if_header(
    groups: &[IfGroup],
    resource_path: &Path,
    resource_href: &str,
    lock_manager: &WebDavLockManager,
    current_etag: Option<&str>,
) -> bool {
    if groups.is_empty() {
        return true;
    }
    for group in groups {
        if let Some(ref tag) = group.resource_tag {
            if !resource_tag_matches(tag, resource_href) {
                continue;
            }
        }
        for list in &group.lists {
            if evaluate_list(list, resource_path, lock_manager, current_etag) {
                return true;
            }
        }
    }
    let any_targets = groups.iter().any(|g| {
        g.resource_tag
            .as_ref()
            .map(|t| resource_tag_matches(t, resource_href))
            .unwrap_or(true)
    });
    !any_targets
}

fn evaluate_list(
    list: &IfConditionList,
    resource_path: &Path,
    lock_manager: &WebDavLockManager,
    current_etag: Option<&str>,
) -> bool {
    for cond in &list.conditions {
        let mut result = if let Some(ref token) = cond.state_token {
            lock_manager.validate_token(resource_path, token)
        } else if let Some(ref etag) = cond.entity_tag {
            etag_matches(etag, current_etag)
        } else {
            false
        };
        if cond.negated {
            result = !result;
        }
        if !result {
            return false;
        }
    }
    true
}

fn resource_tag_matches(tag: &str, href: &str) -> bool {
    if tag.contains("://") {
        if let Some(scheme_end) = tag.find("://") {
            let rest = &tag[scheme_end + 3..];
            if let Some(path_start) = rest.find('/') {
                return tag[scheme_end + 3 + path_start..] == *href;
            }
        }
    }
    tag == href
}

fn etag_matches(condition: &str, current: Option<&str>) -> bool {
    let Some(current) = current else {
        return false;
    };
    strip_weak(condition) == strip_weak(current)
}

fn strip_weak(etag: &str) -> &str {
    etag.strip_prefix("W/").unwrap_or(etag)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lock::{LockScope, LockType, WebDavLockManager};
    use std::path::PathBuf;

    #[test]
    fn parse_no_tag_list() {
        let groups = parse_if_header("(\"token\") (<opaquelocktoken:abc>)");
        assert!(!groups.is_empty());
        assert!(groups[0].resource_tag.is_none());
    }

    #[test]
    fn parse_and_eval_lock_token() {
        let header = "(<opaquelocktoken:test-token>)";
        let groups = parse_if_header(header);
        let _ = groups;
        let mgr = WebDavLockManager::new();
        let path = PathBuf::from("/f");
        let lock = mgr
            .lock(
                path.clone(),
                LockScope::Exclusive,
                LockType::Write,
                0,
                String::new(),
                3600,
            )
            .unwrap();
        let token = format!("<{}>", lock.token());
        let groups = parse_if_header(&format!("({token})"));
        assert!(evaluate_if_header(
            &groups,
            &path,
            "/f",
            &mgr,
            None
        ));
    }

    #[test]
    fn eval_etag_weak() {
        let groups = parse_if_header("([\"abc\"])");
        assert!(evaluate_if_header(
            &groups,
            Path::new("/x"),
            "/x",
            &WebDavLockManager::new(),
            Some("W/\"abc\"")
        ));
    }
}
