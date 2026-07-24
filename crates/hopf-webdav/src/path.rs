// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Request path resolution and containment (Gumdrop algorithms).

use std::path::{Component, Path, PathBuf};

/// Lexically resolve a request path against `root` without disk I/O.
pub fn resolve_path_lexical(root: &Path, request_path: &str) -> Option<PathBuf> {
    if request_path.is_empty() {
        return None;
    }
    if request_path.contains('\0') || request_path.len() > 2048 {
        return None;
    }
    if request_path == "*" {
        return None;
    }

    let mut resolved = root.to_path_buf();
    for component in request_path.split('/') {
        if component.is_empty() {
            continue;
        }
        let decoded = urlencoding_simple(component)?;
        let double = urlencoding_simple(&decoded).unwrap_or_else(|| decoded.clone());
        if double != decoded {
            return None;
        }
        if is_dangerous_path_component(&decoded) {
            return None;
        }
        resolved.push(&decoded);
    }
    let resolved = resolved.normalize_lexical();
    let root_norm = root.normalize_lexical();
    if !resolved.starts_with(&root_norm) {
        return None;
    }
    Some(resolved)
}

/// Disk containment / symlink resolve — call only from storage threads.
pub fn canonicalize_path(root: &Path, canonical_root: &Path, resolved: &Path) -> Option<PathBuf> {
    if !is_within_root(root, canonical_root, resolved) {
        return None;
    }
    if resolved.exists() {
        if let Ok(real) = resolved.canonicalize() {
            if !is_within_root(root, canonical_root, &real) {
                return None;
            }
            return Some(real);
        }
    }
    Some(resolved.to_path_buf())
}

pub fn is_within_root(root: &Path, canonical_root: &Path, path: &Path) -> bool {
    if path.exists() {
        if let Ok(real) = path.canonicalize() {
            return real.starts_with(canonical_root);
        }
        return false;
    }
    let normalized = path.normalize_lexical();
    let normalized_root = root.normalize_lexical();
    let mut parent = normalized.parent();
    while let Some(p) = parent {
        if p.exists() {
            if let Ok(real_parent) = p.canonicalize() {
                if !real_parent.starts_with(canonical_root) {
                    return false;
                }
            }
            break;
        }
        parent = p.parent();
    }
    normalized.starts_with(&normalized_root)
}

fn urlencoding_simple(component: &str) -> Option<String> {
    let mut out = String::new();
    let bytes = component.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return None;
            }
            let hi = hex(bytes[i + 1])?;
            let lo = hex(bytes[i + 2])?;
            out.push(char::from(hi << 4 | lo));
            i += 3;
        } else if bytes[i] == b'+' {
            out.push(' ');
            i += 1;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    Some(out)
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn is_dangerous_path_component(component: &str) -> bool {
    if component.is_empty() {
        return false;
    }
    if component == ".." || component == "." {
        return true;
    }
    if component.contains("..") || component.contains("./") || component.contains("/.") {
        return true;
    }
    if contains_dangerous_chars(component) {
        return true;
    }
    if component.chars().any(|c| c.is_control()) {
        return true;
    }
    is_reserved_windows_name(component)
}

fn contains_dangerous_chars(component: &str) -> bool {
    component.chars().any(|c| matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*'))
}

fn is_reserved_windows_name(component: &str) -> bool {
    let upper = component.to_ascii_uppercase();
    let base = upper.split('.').next().unwrap_or(&upper);
    matches!(base, "CON" | "PRN" | "AUX" | "NUL")
        || (base.len() == 4
            && base.as_bytes()[3].is_ascii_digit()
            && base.as_bytes()[3] >= b'1'
            && base.as_bytes()[3] <= b'9'
            && (base.starts_with("COM") || base.starts_with("LPT")))
}

trait NormalizeLexical {
    fn normalize_lexical(self) -> PathBuf;
}

impl NormalizeLexical for PathBuf {
    fn normalize_lexical(self) -> PathBuf {
        let mut out = PathBuf::new();
        for comp in self.components() {
            match comp {
                Component::CurDir => {}
                Component::ParentDir => {
                    out.pop();
                }
                other => out.push(other.as_os_str()),
            }
        }
        out
    }
}

impl NormalizeLexical for &Path {
    fn normalize_lexical(self) -> PathBuf {
        self.to_path_buf().normalize_lexical()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn lexical_containment_rejects_dotdot() {
        let root = PathBuf::from("/srv/root");
        assert!(resolve_path_lexical(&root, "../etc/passwd").is_none());
        assert!(resolve_path_lexical(&root, "foo/../../../etc").is_none());
    }

    #[test]
    fn lexical_ok_subpath() {
        let root = PathBuf::from("/srv/root");
        let p = resolve_path_lexical(&root, "a/b").unwrap();
        assert_eq!(p, PathBuf::from("/srv/root/a/b"));
    }
}
