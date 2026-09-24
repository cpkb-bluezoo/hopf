// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

use std::time::{Duration, UNIX_EPOCH};

use super::*;
use crate::headers::Headers;

fn req(fields: &[(&str, &str)]) -> Headers {
    let mut h = Headers::new();
    for (n, v) in fields {
        h.add(*n, *v);
    }
    h
}

/// 1994-11-06T08:49:37Z, the RFC's example date.
const DATE: &str = "Sun, 06 Nov 1994 08:49:37 GMT";
const DATE_SECS: u64 = 784_111_777;

fn at(secs: u64) -> std::time::SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

fn cur(etag: &str, modified: u64) -> Validators {
    Validators::new()
        .etag(EntityTag::parse(etag).unwrap())
        .last_modified(at(modified))
}

#[test]
fn entity_tag_parse_format_and_compare() {
    let strong = EntityTag::parse("\"xyzzy\"").unwrap();
    let weak = EntityTag::parse("W/\"xyzzy\"").unwrap();
    assert!(!strong.is_weak() && weak.is_weak());
    assert_eq!(strong.opaque(), "xyzzy");
    assert_eq!(strong.to_string(), "\"xyzzy\"");
    assert_eq!(weak.to_string(), "W/\"xyzzy\"");

    // RFC 9110 §8.8.3.2 comparison table.
    let w1 = EntityTag::parse("W/\"1\"").unwrap();
    let w2 = EntityTag::parse("W/\"2\"").unwrap();
    let s1 = EntityTag::parse("\"1\"").unwrap();
    assert!(w1.weak_eq(&w1) && !w1.strong_eq(&w1));
    assert!(!w1.weak_eq(&w2) && !w1.strong_eq(&w2));
    assert!(w1.weak_eq(&s1) && !w1.strong_eq(&s1));
    assert!(s1.weak_eq(&s1) && s1.strong_eq(&s1));

    assert_eq!(EntityTag::parse("\"\"").unwrap().opaque(), "", "empty opaque is legal");
    for bad in ["", "xyzzy", "\"unterminated", "W/xyzzy", "\"a\"b\"", "\"a b\"", "w/\"x\"", "\"a\u{7f}\""] {
        assert!(EntityTag::parse(bad).is_none(), "{bad:?} must be rejected");
    }
    assert_eq!(EntityTag::strong("a\"b c").to_string(), "\"abc\"", "constructors strip illegal bytes");
}

#[test]
fn entity_tag_lists_are_scanned_quote_aware() {
    use EntityTagList::*;
    assert_eq!(parse_entity_tag_list("*"), Some(Any));
    assert_eq!(parse_entity_tag_list(" * "), Some(Any));
    let Some(Tags(t)) = parse_entity_tag_list("\"a\", W/\"b\" ,\"c,d\"") else { panic!() };
    assert_eq!(
        t.iter().map(|e| e.to_string()).collect::<Vec<_>>(),
        ["\"a\"", "W/\"b\"", "\"c,d\""],
        "a comma inside a tag is not a separator"
    );
    let Some(Tags(t)) = parse_entity_tag_list(",,\"a\",,") else { panic!() };
    assert_eq!(t.len(), 1, "empty list members are tolerated");
    for bad in ["", "a", "\"a\" \"b\"", "*, \"a\"", "\"a", "W/", "\"a\"x"] {
        assert_eq!(parse_entity_tag_list(bad), None, "{bad:?}");
    }
}

#[test]
fn if_none_match_uses_weak_comparison() {
    let v = cur("W/\"v2\"", 1000);
    // A strong tag in the request matches a weak current tag: weak comparison.
    assert_eq!(evaluate_preconditions("GET", &req(&[("If-None-Match", "\"v2\"")]), Some(&v)), Precondition::NotModified);
    assert_eq!(evaluate_preconditions("GET", &req(&[("If-None-Match", "\"v1\", W/\"v2\"")]), Some(&v)), Precondition::NotModified);
    assert_eq!(evaluate_preconditions("GET", &req(&[("If-None-Match", "\"v1\"")]), Some(&v)), Precondition::Proceed);
    assert_eq!(evaluate_preconditions("HEAD", &req(&[("If-None-Match", "*")]), Some(&v)), Precondition::NotModified);
    // The same match on an unsafe method is a failed precondition, not a 304.
    assert_eq!(evaluate_preconditions("PUT", &req(&[("If-None-Match", "\"v2\"")]), Some(&v)), Precondition::PreconditionFailed);
    assert_eq!(evaluate_preconditions("PUT", &req(&[("If-None-Match", "*")]), Some(&v)), Precondition::PreconditionFailed, "create-only PUT on an existing resource");
    assert_eq!(evaluate_preconditions("PUT", &req(&[("If-None-Match", "*")]), None), Precondition::Proceed, "create-only PUT on a missing resource");
}

#[test]
fn if_match_uses_strong_comparison() {
    let strong = cur("\"v1\"", 1000);
    let weak = cur("W/\"v1\"", 1000);
    assert_eq!(evaluate_preconditions("PUT", &req(&[("If-Match", "\"v1\"")]), Some(&strong)), Precondition::Proceed);
    assert_eq!(evaluate_preconditions("PUT", &req(&[("If-Match", "\"v2\", \"v1\"")]), Some(&strong)), Precondition::Proceed);
    assert_eq!(evaluate_preconditions("PUT", &req(&[("If-Match", "\"v2\"")]), Some(&strong)), Precondition::PreconditionFailed);
    // A weak tag never strongly matches, on either side.
    assert_eq!(evaluate_preconditions("PUT", &req(&[("If-Match", "\"v1\"")]), Some(&weak)), Precondition::PreconditionFailed);
    assert_eq!(evaluate_preconditions("PUT", &req(&[("If-Match", "W/\"v1\"")]), Some(&strong)), Precondition::PreconditionFailed);
    // `*` means "the resource exists".
    assert_eq!(evaluate_preconditions("PUT", &req(&[("If-Match", "*")]), Some(&weak)), Precondition::Proceed);
    assert_eq!(evaluate_preconditions("PUT", &req(&[("If-Match", "*")]), None), Precondition::PreconditionFailed);
    assert_eq!(evaluate_preconditions("PUT", &req(&[("If-Match", "\"v1\"")]), None), Precondition::PreconditionFailed);
    // No etag on the resource: nothing can strongly match.
    let none = Validators::new().last_modified(at(1000));
    assert_eq!(evaluate_preconditions("GET", &req(&[("If-Match", "\"v1\"")]), Some(&none)), Precondition::PreconditionFailed);
}

#[test]
fn date_conditions_compare_at_one_second_resolution() {
    let same = cur("\"x\"", DATE_SECS);
    let later = cur("\"x\"", DATE_SECS + 1);
    let earlier = cur("\"x\"", DATE_SECS - 1);
    let ims = req(&[("If-Modified-Since", DATE)]);
    assert_eq!(evaluate_preconditions("GET", &ims, Some(&same)), Precondition::NotModified);
    assert_eq!(evaluate_preconditions("GET", &ims, Some(&earlier)), Precondition::NotModified);
    assert_eq!(evaluate_preconditions("GET", &ims, Some(&later)), Precondition::Proceed);

    // A modification time with a fractional second is truncated: the date the
    // client echoes back is exactly what we sent, so it is current.
    let frac = Validators::new().last_modified(UNIX_EPOCH + Duration::from_millis(DATE_SECS * 1000 + 500));
    assert_eq!(evaluate_preconditions("GET", &ims, Some(&frac)), Precondition::NotModified);

    let ius = req(&[("If-Unmodified-Since", DATE)]);
    assert_eq!(evaluate_preconditions("PUT", &ius, Some(&same)), Precondition::Proceed);
    assert_eq!(evaluate_preconditions("PUT", &ius, Some(&earlier)), Precondition::Proceed);
    assert_eq!(evaluate_preconditions("PUT", &ius, Some(&later)), Precondition::PreconditionFailed);
    assert_eq!(evaluate_preconditions("PUT", &ius, Some(&frac)), Precondition::Proceed);
    // No known modification time: cannot fail.
    assert_eq!(evaluate_preconditions("PUT", &ius, Some(&Validators::new())), Precondition::Proceed);
    assert_eq!(evaluate_preconditions("GET", &ims, Some(&Validators::new())), Precondition::Proceed);
}

#[test]
fn if_modified_since_only_applies_to_get_and_head() {
    let v = cur("\"x\"", DATE_SECS);
    let ims = req(&[("If-Modified-Since", DATE)]);
    assert_eq!(evaluate_preconditions("GET", &ims, Some(&v)), Precondition::NotModified);
    assert_eq!(evaluate_preconditions("HEAD", &ims, Some(&v)), Precondition::NotModified);
    assert_eq!(evaluate_preconditions("POST", &ims, Some(&v)), Precondition::Proceed);
    assert_eq!(evaluate_preconditions("PUT", &ims, Some(&v)), Precondition::Proceed);
}

#[test]
fn obsolete_http_date_forms_are_understood() {
    let v = cur("\"x\"", DATE_SECS);
    for d in ["Sunday, 06-Nov-94 08:49:37 GMT", "Sun Nov  6 08:49:37 1994"] {
        assert_eq!(evaluate_preconditions("GET", &req(&[("If-Modified-Since", d)]), Some(&v)), Precondition::NotModified, "{d}");
    }
}

#[test]
fn evaluation_follows_the_rfc_precedence() {
    let v = cur("\"v1\"", DATE_SECS + 100);
    // If-Match present: If-Unmodified-Since is not evaluated at all.
    let r = req(&[("If-Match", "\"v1\""), ("If-Unmodified-Since", DATE)]);
    assert_eq!(evaluate_preconditions("PUT", &r, Some(&v)), Precondition::Proceed);
    // If-Match false wins before If-None-Match is looked at.
    let r = req(&[("If-Match", "\"other\""), ("If-None-Match", "\"other\"")]);
    assert_eq!(evaluate_preconditions("GET", &r, Some(&v)), Precondition::PreconditionFailed);
    // If-None-Match present: If-Modified-Since is not evaluated, even if it
    // would say "not modified".
    let r = req(&[("If-None-Match", "\"stale\""), ("If-Modified-Since", "Sun, 06 Nov 2100 08:49:37 GMT")]);
    assert_eq!(evaluate_preconditions("GET", &r, Some(&v)), Precondition::Proceed);
    // A matching If-None-Match with If-Modified-Since: still 304.
    let r = req(&[("If-None-Match", "\"v1\""), ("If-Modified-Since", DATE)]);
    assert_eq!(evaluate_preconditions("GET", &r, Some(&v)), Precondition::NotModified);
    // If-Unmodified-Since (fails) then If-None-Match would 304: 412 comes first.
    let r = req(&[("If-Unmodified-Since", DATE), ("If-None-Match", "\"v1\"")]);
    assert_eq!(evaluate_preconditions("GET", &r, Some(&v)), Precondition::PreconditionFailed);
}

#[test]
fn malformed_or_repeated_fields_are_ignored() {
    let v = cur("\"v1\"", DATE_SECS);
    // Bad dates and etag lists: ignored, request proceeds.
    assert_eq!(evaluate_preconditions("GET", &req(&[("If-Modified-Since", "yesterday")]), Some(&v)), Precondition::Proceed);
    assert_eq!(evaluate_preconditions("PUT", &req(&[("If-Unmodified-Since", "0")]), Some(&v)), Precondition::Proceed);
    assert_eq!(evaluate_preconditions("GET", &req(&[("If-None-Match", "not-a-tag")]), Some(&v)), Precondition::Proceed);
    assert_eq!(evaluate_preconditions("PUT", &req(&[("If-Match", "not-a-tag")]), Some(&v)), Precondition::Proceed);
    // A date field sent twice has "more than one member": ignored.
    let twice = req(&[("If-Modified-Since", DATE), ("If-Modified-Since", DATE)]);
    assert_eq!(evaluate_preconditions("GET", &twice, Some(&v)), Precondition::Proceed);
    // A malformed If-None-Match is still *present*, so If-Modified-Since stays out of it.
    let r = req(&[("If-None-Match", "garbage"), ("If-Modified-Since", DATE)]);
    assert_eq!(evaluate_preconditions("GET", &r, Some(&v)), Precondition::Proceed);
    // Etag lists split across several field lines are combined.
    let split = req(&[("If-None-Match", "\"a\""), ("If-None-Match", "\"v1\"")]);
    assert_eq!(evaluate_preconditions("GET", &split, Some(&v)), Precondition::NotModified);
    // No preconditions at all.
    assert_eq!(evaluate_preconditions("GET", &Headers::new(), Some(&v)), Precondition::Proceed);
    assert_eq!(evaluate_preconditions("GET", &Headers::new(), None), Precondition::Proceed);
}

#[test]
fn cache_control_builds_a_canonical_value() {
    let s = Duration::from_secs;
    assert_eq!(CacheControl::new().to_string(), "");
    assert!(CacheControl::new().is_empty());
    assert_eq!(CacheControl::new().no_store().to_string(), "no-store");
    assert_eq!(CacheControl::new().public().max_age(s(3600)).immutable().to_string(), "public, max-age=3600, immutable");
    assert_eq!(CacheControl::new().no_cache().must_revalidate().to_string(), "no-cache, must-revalidate");
    assert_eq!(
        CacheControl::new()
            .private()
            .max_age(s(60))
            .s_maxage(s(120))
            .stale_while_revalidate(s(30))
            .stale_if_error(s(600))
            .no_transform()
            .to_string(),
        "private, no-transform, max-age=60, s-maxage=120, stale-while-revalidate=30, stale-if-error=600"
    );
    assert_eq!(CacheControl::new().max_age(Duration::from_millis(1999)).to_string(), "max-age=1", "sub-second dropped");
    assert_eq!(CacheControl::new().max_age(s(0)).to_string(), "max-age=0", "zero is a real directive");

    let mut h = Headers::new();
    CacheControl::new().apply(&mut h);
    assert!(!h.contains("cache-control"), "an empty policy sets nothing");
    h.set("Cache-Control", "old");
    CacheControl::new().no_store().apply(&mut h);
    assert_eq!(h.get("cache-control"), Some("no-store"));
}
