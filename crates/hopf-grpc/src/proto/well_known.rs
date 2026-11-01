// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! The proto3 JSON mapping of the `google.protobuf` well-known types that are
//! a bare JSON value rather than an object: `Timestamp` as an RFC 3339
//! string, `Duration` as seconds with an `s`, `FieldMask` as comma-separated
//! camelCase paths, and the wrapper types as the value they wrap.
//!
//! This module is the text conversions; the serializer and the adapter use
//! them where such a message starts and ends.

use super::FieldType;

/// A well-known type whose JSON form is not an object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WellKnown {
    Timestamp,
    Duration,
    FieldMask,
    /// `DoubleValue`, `StringValue` and the like: the type of their `value`.
    Wrapper(FieldType),
}

/// The well-known type with this full name, if it has a bare JSON form.
pub(crate) fn classify(full_name: &str) -> Option<WellKnown> {
    let simple = full_name.trim_start_matches('.').strip_prefix("google.protobuf.")?;
    Some(match simple {
        "Timestamp" => WellKnown::Timestamp,
        "Duration" => WellKnown::Duration,
        "FieldMask" => WellKnown::FieldMask,
        "DoubleValue" => WellKnown::Wrapper(FieldType::Double),
        "FloatValue" => WellKnown::Wrapper(FieldType::Float),
        "Int64Value" => WellKnown::Wrapper(FieldType::Int64),
        "UInt64Value" => WellKnown::Wrapper(FieldType::Uint64),
        "Int32Value" => WellKnown::Wrapper(FieldType::Int32),
        "UInt32Value" => WellKnown::Wrapper(FieldType::Uint32),
        "BoolValue" => WellKnown::Wrapper(FieldType::Bool),
        "StringValue" => WellKnown::Wrapper(FieldType::String),
        "BytesValue" => WellKnown::Wrapper(FieldType::Bytes),
        _ => return None,
    })
}

const SECONDS_PER_DAY: i64 = 86_400;
/// 0001-01-01T00:00:00Z and 9999-12-31T23:59:59Z, the range of a Timestamp.
const MIN_TIMESTAMP: i64 = -62_135_596_800;
const MAX_TIMESTAMP: i64 = 253_402_300_799;
/// About 10,000 years either way, the range of a Duration.
const MAX_DURATION: i64 = 315_576_000_000;

/// Days since 1970-01-01 of a civil date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = i64::from((m + 9) % 12);
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The civil date of a day count since 1970-01-01.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if is_leap(y) => 29,
        _ => 28,
    }
}

/// The fraction of a second as `.mmm`, `.uuuuuu` or `.nnnnnnnnn`: the fewest
/// of 3, 6 or 9 digits that holds it. Empty for none.
fn fraction(nanos: u32) -> String {
    if nanos == 0 {
        String::new()
    } else if nanos % 1_000_000 == 0 {
        format!(".{:03}", nanos / 1_000_000)
    } else if nanos % 1000 == 0 {
        format!(".{:06}", nanos / 1000)
    } else {
        format!(".{nanos:09}")
    }
}

/// A Timestamp as RFC 3339 in UTC, `1972-01-01T10:00:20.021Z`.
pub(crate) fn format_timestamp(seconds: i64, nanos: i32) -> Result<String, String> {
    if !(MIN_TIMESTAMP..=MAX_TIMESTAMP).contains(&seconds) {
        return Err(format!("timestamp seconds {seconds} are outside 0001-01-01 to 9999-12-31"));
    }
    if !(0..=999_999_999).contains(&nanos) {
        return Err(format!("timestamp nanos {nanos} are outside 0 to 999999999"));
    }
    let (y, m, d) = civil_from_days(seconds.div_euclid(SECONDS_PER_DAY));
    let t = seconds.rem_euclid(SECONDS_PER_DAY);
    Ok(format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}{}Z",
        t / 3600,
        t % 3600 / 60,
        t % 60,
        fraction(nanos as u32)
    ))
}

fn digits(s: &str, n: usize) -> Option<u32> {
    (s.len() == n && s.bytes().all(|b| b.is_ascii_digit())).then(|| s.parse().ok()).flatten()
}

/// RFC 3339 text as seconds and nanos since the epoch. Any offset is accepted
/// and applied; a leap second (`:60`) is not.
pub(crate) fn parse_timestamp(text: &str) -> Result<(i64, i32), String> {
    let bad = || format!("{text:?} is not an RFC 3339 timestamp");
    let (date, rest) = text.split_once(['T', 't']).ok_or_else(bad)?;
    let mut d = date.split('-');
    let (y, mo, da) = (d.next().ok_or_else(bad)?, d.next().ok_or_else(bad)?, d.next().ok_or_else(bad)?);
    if d.next().is_some() {
        return Err(bad());
    }
    let (y, mo, da) = (
        digits(y, 4).ok_or_else(bad)? as i64,
        digits(mo, 2).ok_or_else(bad)?,
        digits(da, 2).ok_or_else(bad)?,
    );
    if !(1..=12).contains(&mo) || da < 1 || da > days_in_month(y, mo) || y < 1 {
        return Err(bad());
    }
    // The time ends at Z or at a numeric offset.
    let (time, offset) = if let Some(t) = rest.strip_suffix(['Z', 'z']) {
        (t, 0i64)
    } else {
        let at = rest.rfind(['+', '-']).ok_or_else(bad)?;
        let (t, off) = rest.split_at(at);
        let sign = if off.starts_with('-') { -1 } else { 1 };
        let (oh, om) = off[1..].split_once(':').ok_or_else(bad)?;
        let (oh, om) = (digits(oh, 2).ok_or_else(bad)?, digits(om, 2).ok_or_else(bad)?);
        if oh > 23 || om > 59 {
            return Err(bad());
        }
        (t, sign * (i64::from(oh) * 3600 + i64::from(om) * 60))
    };
    let (hms, frac) = match time.split_once('.') {
        Some((hms, frac)) => (hms, Some(frac)),
        None => (time, None),
    };
    let mut t = hms.split(':');
    let (h, mi, s) = (t.next().ok_or_else(bad)?, t.next().ok_or_else(bad)?, t.next().ok_or_else(bad)?);
    if t.next().is_some() {
        return Err(bad());
    }
    let (h, mi, s) = (digits(h, 2).ok_or_else(bad)?, digits(mi, 2).ok_or_else(bad)?, digits(s, 2).ok_or_else(bad)?);
    if h > 23 || mi > 59 || s > 59 {
        return Err(bad());
    }
    let nanos = match frac {
        None => 0,
        Some(f) if (1..=9).contains(&f.len()) && f.bytes().all(|b| b.is_ascii_digit()) => {
            f.parse::<u32>().map_err(|_| bad())? * 10u32.pow(9 - f.len() as u32)
        }
        Some(_) => return Err(bad()),
    };
    let seconds =
        days_from_civil(y, mo, da) * SECONDS_PER_DAY + i64::from(h) * 3600 + i64::from(mi) * 60 + i64::from(s) - offset;
    if !(MIN_TIMESTAMP..=MAX_TIMESTAMP).contains(&seconds) {
        return Err(format!("{text:?} is outside 0001-01-01 to 9999-12-31"));
    }
    Ok((seconds, nanos as i32))
}

/// A Duration as seconds with up to nine fractional digits and an `s`,
/// `1.5s`. The sign applies to the whole, so `-0.5s` is zero seconds and
/// minus half a second of nanos.
pub(crate) fn format_duration(seconds: i64, nanos: i32) -> Result<String, String> {
    if !(-MAX_DURATION..=MAX_DURATION).contains(&seconds) {
        return Err(format!("duration seconds {seconds} are outside plus or minus {MAX_DURATION}"));
    }
    if !(-999_999_999..=999_999_999).contains(&nanos) {
        return Err(format!("duration nanos {nanos} are outside plus or minus 999999999"));
    }
    if (seconds > 0 && nanos < 0) || (seconds < 0 && nanos > 0) {
        return Err("duration seconds and nanos have different signs".into());
    }
    let sign = if seconds < 0 || nanos < 0 { "-" } else { "" };
    Ok(format!("{sign}{}{}s", seconds.unsigned_abs(), fraction(nanos.unsigned_abs())))
}

/// Duration text as seconds and nanos (both negative for a negative one).
pub(crate) fn parse_duration(text: &str) -> Result<(i64, i32), String> {
    let bad = || format!("{text:?} is not a duration such as 1.5s");
    let body = text.strip_suffix('s').ok_or_else(bad)?;
    let (negative, body) = match body.strip_prefix('-') {
        Some(b) => (true, b),
        None => (false, body),
    };
    let (whole, frac) = match body.split_once('.') {
        Some((w, f)) => (w, Some(f)),
        None => (body, None),
    };
    if whole.is_empty() || !whole.bytes().all(|b| b.is_ascii_digit()) || whole.len() > 12 {
        return Err(bad());
    }
    let seconds: i64 = whole.parse().map_err(|_| bad())?;
    let nanos: i64 = match frac {
        None => 0,
        Some(f) if (1..=9).contains(&f.len()) && f.bytes().all(|b| b.is_ascii_digit()) => {
            i64::from(f.parse::<u32>().map_err(|_| bad())?) * 10i64.pow(9 - f.len() as u32)
        }
        Some(_) => return Err(bad()),
    };
    if seconds > MAX_DURATION || (seconds == MAX_DURATION && nanos > 0) {
        return Err(format!("{text:?} is outside plus or minus {MAX_DURATION} seconds"));
    }
    Ok(if negative { (-seconds, -(nanos as i32)) } else { (seconds, nanos as i32) })
}

/// FieldMask paths (`foo_bar.baz`) as the JSON string (`fooBar.baz`). A path
/// that does not survive the round trip (an uppercase letter, or an
/// underscore not followed by a lowercase letter) is an error.
pub(crate) fn field_mask_to_json(paths: &[String]) -> Result<String, String> {
    let mut out = Vec::with_capacity(paths.len());
    for path in paths {
        let mut camel = String::with_capacity(path.len());
        let mut upper_next = false;
        for c in path.chars() {
            if c.is_ascii_uppercase() {
                return Err(format!("field mask path {path:?} has an uppercase letter"));
            }
            if upper_next {
                if !c.is_ascii_lowercase() {
                    return Err(format!("field mask path {path:?} has an underscore not followed by a lowercase letter"));
                }
                camel.push(c.to_ascii_uppercase());
                upper_next = false;
            } else if c == '_' {
                upper_next = true;
            } else {
                camel.push(c);
            }
        }
        if upper_next {
            return Err(format!("field mask path {path:?} ends in an underscore"));
        }
        out.push(camel);
    }
    Ok(out.join(","))
}

/// The paths of a FieldMask JSON string. An underscore in one is an error,
/// since it could not be told from the camelCase of another path.
pub(crate) fn field_mask_from_json(text: &str) -> Result<Vec<String>, String> {
    if text.is_empty() {
        return Ok(Vec::new());
    }
    text.split(',')
        .map(|path| {
            if path.contains('_') {
                return Err(format!("field mask path {path:?} has an underscore: paths are camelCase in JSON"));
            }
            let mut snake = String::with_capacity(path.len() + 2);
            for c in path.chars() {
                if c.is_ascii_uppercase() {
                    snake.push('_');
                    snake.push(c.to_ascii_lowercase());
                } else {
                    snake.push(c);
                }
            }
            Ok(snake)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_types_with_a_bare_json_form_are_recognised_by_full_name() {
        assert_eq!(classify("google.protobuf.Timestamp"), Some(WellKnown::Timestamp));
        assert_eq!(classify(".google.protobuf.Duration"), Some(WellKnown::Duration));
        assert_eq!(classify("google.protobuf.FieldMask"), Some(WellKnown::FieldMask));
        assert_eq!(classify("google.protobuf.Int64Value"), Some(WellKnown::Wrapper(FieldType::Int64)));
        assert_eq!(classify("google.protobuf.BytesValue"), Some(WellKnown::Wrapper(FieldType::Bytes)));
        assert_eq!(classify("google.protobuf.Empty"), None, "an object like any other");
        assert_eq!(classify("google.protobuf.Any"), None);
        assert_eq!(classify("demo.Timestamp"), None, "only the well-known one");
    }

    #[test]
    fn timestamps_from_the_specification_and_the_edges_of_the_range() {
        for (text, seconds, nanos) in [
            ("1970-01-01T00:00:00Z", 0, 0),
            ("1972-01-01T10:00:20.021Z", 63_108_020, 21_000_000),
            ("0001-01-01T00:00:00Z", -62_135_596_800, 0),
            ("9999-12-31T23:59:59.999999999Z", 253_402_300_799, 999_999_999),
            ("2000-02-29T12:00:00Z", 951_825_600, 0),
            ("1969-12-31T23:59:59.500Z", -1, 500_000_000),
            ("2017-01-15T01:30:15.01Z", 1_484_443_815, 10_000_000),
        ] {
            assert_eq!(parse_timestamp(text), Ok((seconds, nanos)), "{text}");
        }
        assert_eq!(format_timestamp(63_108_020, 21_000_000).unwrap(), "1972-01-01T10:00:20.021Z");
        assert_eq!(format_timestamp(-62_135_596_800, 0).unwrap(), "0001-01-01T00:00:00Z");
        assert_eq!(format_timestamp(253_402_300_799, 999_999_999).unwrap(), "9999-12-31T23:59:59.999999999Z");
        assert_eq!(format_timestamp(-1, 500_000_000).unwrap(), "1969-12-31T23:59:59.500Z");
    }

    #[test]
    fn a_timestamp_prints_with_the_fewest_of_0_3_6_or_9_fractional_digits() {
        assert_eq!(format_timestamp(0, 0).unwrap(), "1970-01-01T00:00:00Z");
        assert_eq!(format_timestamp(0, 10_000_000).unwrap(), "1970-01-01T00:00:00.010Z");
        assert_eq!(format_timestamp(0, 1000).unwrap(), "1970-01-01T00:00:00.000001Z");
        assert_eq!(format_timestamp(0, 1).unwrap(), "1970-01-01T00:00:00.000000001Z");
        assert_eq!(format_timestamp(0, 123_450_000).unwrap(), "1970-01-01T00:00:00.123450Z");
    }

    #[test]
    fn an_offset_is_applied_and_every_form_of_fraction_is_read() {
        assert_eq!(parse_timestamp("1972-01-01T10:00:20-08:00"), Ok((63_108_020 + 8 * 3600, 0)));
        assert_eq!(parse_timestamp("1972-01-01T10:00:20+05:30"), Ok((63_108_020 - 5 * 3600 - 1800, 0)));
        assert_eq!(parse_timestamp("1972-01-01T10:00:20.5Z"), Ok((63_108_020, 500_000_000)));
        assert_eq!(parse_timestamp("1972-01-01T10:00:20.000000001Z"), Ok((63_108_020, 1)));
        assert_eq!(parse_timestamp("1972-01-01t10:00:20z"), Ok((63_108_020, 0)), "lowercase t and z are RFC 3339 too");
    }

    #[test]
    fn what_is_not_a_timestamp_is_an_error() {
        for bad in [
            "",
            "1972-01-01",
            "1972-01-01T10:00:20",
            "1972-01-01 10:00:20Z",
            "1972-1-1T10:00:20Z",
            "1972-13-01T10:00:20Z",
            "1972-00-10T10:00:20Z",
            "1972-02-30T10:00:20Z",
            "1900-02-29T00:00:00Z",
            "2001-02-29T00:00:00Z",
            "1972-01-01T24:00:00Z",
            "1972-01-01T10:60:00Z",
            "1972-01-01T10:00:60Z",
            "1972-01-01T10:00:20.Z",
            "1972-01-01T10:00:20.1234567890Z",
            "1972-01-01T10:00:20+0800",
            "1972-01-01T10:00:20+24:00",
            "0000-12-31T23:59:59Z",
            "10000-01-01T00:00:00Z",
            "0001-01-01T00:00:00+01:00",
            "9999-12-31T23:59:59-01:00",
        ] {
            assert!(parse_timestamp(bad).is_err(), "{bad:?} must not parse");
        }
    }

    #[test]
    fn a_timestamp_out_of_range_or_with_bad_nanos_cannot_be_written() {
        assert!(format_timestamp(MIN_TIMESTAMP - 1, 0).is_err());
        assert!(format_timestamp(MAX_TIMESTAMP + 1, 0).is_err());
        assert!(format_timestamp(0, -1).is_err());
        assert!(format_timestamp(0, 1_000_000_000).is_err());
    }

    #[test]
    fn every_second_of_a_leap_year_boundary_round_trips() {
        for s in [951_782_399, 951_782_400, 951_868_799, 951_868_800, 4_107_542_399, 4_107_542_400, -2_203_891_201, -2_203_891_200] {
            let text = format_timestamp(s, 0).unwrap();
            assert_eq!(parse_timestamp(&text), Ok((s, 0)), "{text}");
        }
    }

    #[test]
    fn durations_from_the_specification() {
        for (text, seconds, nanos) in [
            ("0s", 0, 0),
            ("3s", 3, 0),
            ("3.000001s", 3, 1000),
            ("1.000340012s", 1, 340_012),
            ("-3.000001s", -3, -1000),
            ("-0.5s", 0, -500_000_000),
            ("315576000000s", 315_576_000_000, 0),
            ("-315576000000s", -315_576_000_000, 0),
            ("1.5s", 1, 500_000_000),
        ] {
            assert_eq!(parse_duration(text), Ok((seconds, nanos)), "{text}");
        }
        assert_eq!(format_duration(3, 0).unwrap(), "3s");
        assert_eq!(format_duration(3, 1000).unwrap(), "3.000001s");
        assert_eq!(format_duration(1, 500_000_000).unwrap(), "1.500s");
        assert_eq!(format_duration(-3, -1000).unwrap(), "-3.000001s");
        assert_eq!(format_duration(0, -500_000_000).unwrap(), "-0.500s");
        assert_eq!(format_duration(0, 0).unwrap(), "0s");
    }

    #[test]
    fn what_is_not_a_duration_is_an_error() {
        for bad in ["", "s", "1", "1.5", "1.s", ".5s", "1.5 s", "+1s", "1.1234567890s", "315576000001s", "315576000000.1s", "-315576000000.1s", "1e3s", "--1s", "1S"] {
            assert!(parse_duration(bad).is_err(), "{bad:?} must not parse");
        }
        assert!(format_duration(1, -1).is_err(), "seconds and nanos of different signs");
        assert!(format_duration(-1, 1).is_err());
        assert!(format_duration(MAX_DURATION + 1, 0).is_err());
        assert!(format_duration(0, 1_000_000_000).is_err());
    }

    #[test]
    fn field_mask_paths_change_case_with_the_json_name_rules() {
        let paths = |p: &[&str]| p.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(field_mask_to_json(&paths(&["f.bar_baz", "qux"])).unwrap(), "f.barBaz,qux");
        assert_eq!(field_mask_from_json("f.barBaz,qux").unwrap(), paths(&["f.bar_baz", "qux"]));
        assert_eq!(field_mask_to_json(&[]).unwrap(), "");
        assert!(field_mask_from_json("").unwrap().is_empty());
        assert_eq!(field_mask_from_json("a").unwrap(), paths(&["a"]));
        assert!(field_mask_to_json(&paths(&["fooBar"])).is_err(), "would come back as foo_bar");
        assert!(field_mask_to_json(&paths(&["foo_"])).is_err());
        assert!(field_mask_to_json(&paths(&["foo__bar"])).is_err());
        assert!(field_mask_to_json(&paths(&["foo_1"])).is_err());
        assert!(field_mask_from_json("foo_bar").is_err(), "an underscore is not camelCase");
    }
}
