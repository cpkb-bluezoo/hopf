// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! RFC 9204 §4.5.1.1's Required Insert Count encoding — a compact wrapped
//! form (not the raw integer) chosen so a decoder can detect corruption:
//! since a real Required Insert Count can never exceed the peer's dynamic
//! table capacity in entries, the wire form wraps modulo twice that count.

/// Encode a Required Insert Count for the wire, given the encoder's
/// dynamic-table capacity in bytes.
pub(crate) fn encode(required_insert_count: u64, max_table_capacity: usize) -> u64 {
    if required_insert_count == 0 {
        return 0;
    }
    let max_entries = (max_table_capacity / 32) as u64;
    (required_insert_count % (2 * max_entries)) + 1
}

/// Decode a wire-form Required Insert Count. `total_inserts` is the
/// decoder's current Insert Count (how many entries it has processed off
/// the encoder stream so far) and `max_table_capacity` its dynamic table's
/// capacity in bytes. Returns `None` if `encoded` is out of range for a
/// table of this capacity, or decodes to a value the decoder can't yet
/// support (would require it to have received more insertions than it has
/// — i.e. would require blocking, which this decoder never permits).
pub(crate) fn decode(encoded: u64, total_inserts: u64, max_table_capacity: usize) -> Option<u64> {
    if encoded == 0 {
        return Some(0);
    }
    let max_entries = (max_table_capacity / 32) as u64;
    if max_entries == 0 {
        return None;
    }
    let full_range = 2 * max_entries;
    if encoded > full_range {
        return None;
    }
    let max_value = total_inserts + max_entries;
    let max_wrapped = (max_value / full_range) * full_range;
    let mut required_insert_count = max_wrapped + encoded - 1;
    if required_insert_count > max_value {
        if required_insert_count <= full_range {
            return None;
        }
        required_insert_count -= full_range;
    }
    if required_insert_count == 0 {
        return None;
    }
    Some(required_insert_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_round_trips() {
        assert_eq!(encode(0, 4096), 0);
        assert_eq!(decode(0, 0, 4096), Some(0));
    }

    #[test]
    fn small_values_round_trip_without_wraparound() {
        for ric in [1u64, 2, 10, 100] {
            let encoded = encode(ric, 4096);
            assert_eq!(decode(encoded, ric, 4096), Some(ric), "ric={ric}");
        }
    }

    #[test]
    fn round_trips_after_many_insertions_have_advanced_total_inserts() {
        // 4096 / 32 = 128 max entries; push total_inserts well past a
        // couple of wrap cycles and confirm recent RICs still decode.
        let max_table_capacity = 4096;
        for total_inserts in [500u64, 1000, 5000] {
            for back in [1u64, 5, 50] {
                if back > total_inserts {
                    continue;
                }
                let ric = total_inserts - back + 1;
                let encoded = encode(ric, max_table_capacity);
                assert_eq!(
                    decode(encoded, total_inserts, max_table_capacity),
                    Some(ric),
                    "ric={ric} total_inserts={total_inserts}"
                );
            }
        }
    }

    #[test]
    fn out_of_range_encoded_value_is_none() {
        // max_entries = 4096/32 = 128, full_range = 256.
        assert_eq!(decode(257, 0, 4096), None);
    }
}
