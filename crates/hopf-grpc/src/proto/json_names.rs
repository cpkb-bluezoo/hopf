// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Proto3 JSON field-name helpers (default `json_name` = lowerCamelCase).

/// Convert a proto field name to its default JSON name (lowerCamelCase).
///
/// `foo_bar_baz` → `fooBarBaz`. Names without underscores are unchanged.
pub fn proto_json_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut capitalize = false;
    for c in name.chars() {
        if c == '_' {
            capitalize = true;
        } else if capitalize {
            for u in c.to_uppercase() {
                out.push(u);
            }
            capitalize = false;
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn camel_cases_snake() {
        assert_eq!(proto_json_name("text"), "text");
        assert_eq!(proto_json_name("foo_bar"), "fooBar");
        assert_eq!(proto_json_name("foo_bar_baz"), "fooBarBaz");
        assert_eq!(proto_json_name("URL_value"), "URLValue");
    }
}
