// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

use super::*;

const PLAIN_LINE: &str = "hello hello hello hello hello, hopf content coding!\n";

pub(super) fn plain() -> Vec<u8> {
    PLAIN_LINE.repeat(3).into_bytes()
}

// Produced by the reference gzip(1), brotli(1) and zlib tools - not by this
// crate - so the decoders are checked against independent encoders.
pub(super) const GOLDEN_GZIP: &[u8] = &[
    0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x57,
    0xc8, 0xc0, 0x4e, 0xea, 0x28, 0x64, 0xe4, 0x17, 0xa4, 0x29, 0x24, 0xe7, 0xe7, 0x95, 0xa4, 0xe6,
    0x95, 0x00, 0xe9, 0x94, 0xcc, 0xbc, 0x74, 0x45, 0xae, 0x0c, 0x3a, 0xe9, 0x01, 0x00, 0x60, 0x90,
    0x4a, 0x51, 0x9c, 0x00, 0x00, 0x00,
];
pub(super) const GOLDEN_BROTLI: &[u8] = &[
    0xa1, 0xd8, 0x04, 0x00, 0x20, 0xe0, 0x26, 0xeb, 0x94, 0x74, 0x3a, 0xb5, 0xb9, 0x39, 0x1b, 0xc2,
    0x06, 0x1c, 0x38, 0x24, 0x16, 0x72, 0x06, 0x0b, 0xe9, 0xb0, 0x01, 0x87, 0x01, 0x46, 0xed, 0xb3,
    0xe9, 0x02, 0x23, 0x5c, 0x7f, 0x6f, 0xc5, 0x64, 0xda, 0xea, 0xc2, 0xf2, 0x00,
];
pub(super) const GOLDEN_ZLIB: &[u8] = &[
    0x78, 0x9c, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0xc8, 0xc0, 0x4e, 0xea, 0x28, 0x64, 0xe4, 0x17,
    0xa4, 0x29, 0x24, 0xe7, 0xe7, 0x95, 0xa4, 0xe6, 0x95, 0x00, 0xe9, 0x94, 0xcc, 0xbc, 0x74, 0x45,
    0x2e, 0x1c, 0xaa, 0xa9, 0xae, 0x07, 0x00, 0x5e, 0x5a, 0x38, 0x26,
];
const GOLDEN_RAW_DEFLATE: &[u8] = &[
    0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0xc8, 0xc0, 0x4e, 0xea, 0x28, 0x64, 0xe4, 0x17, 0xa4, 0x29,
    0x24, 0xe7, 0xe7, 0x95, 0xa4, 0xe6, 0x95, 0x00, 0xe9, 0x94, 0xcc, 0xbc, 0x74, 0x45, 0xae, 0x0c,
    0x3a, 0xe9, 0x01, 0x00,
];

const BIG: u64 = 1 << 30;

/// Decode `data` in `chunk`-sized pushes, returning everything or the error.
pub(super) fn decode(coding: ContentCoding, data: &[u8], chunk: usize, max: u64) -> Result<Vec<u8>, CodingError> {
    let mut d = Decoder::new(coding, max)?;
    let mut out = Vec::new();
    for piece in data.chunks(chunk) {
        d.push(piece, &mut |b| out.extend_from_slice(b))?;
    }
    d.finish()?;
    Ok(out)
}

pub(super) fn encode(coding: ContentCoding, data: &[u8], chunk: usize) -> Vec<u8> {
    let mut e = Encoder::new(coding).unwrap();
    let mut out = Vec::new();
    for piece in data.chunks(chunk.max(1)) {
        e.push(piece, &mut |b| out.extend_from_slice(b)).unwrap();
    }
    e.finish(&mut |b| out.extend_from_slice(b)).unwrap();
    out
}

#[test]
fn golden_streams_decode_whole_and_one_byte_at_a_time() {
    for (coding, golden) in [
        (ContentCoding::Gzip, GOLDEN_GZIP),
        (ContentCoding::Brotli, GOLDEN_BROTLI),
        (ContentCoding::Deflate, GOLDEN_ZLIB),
        (ContentCoding::Deflate, GOLDEN_RAW_DEFLATE),
    ] {
        for chunk in [golden.len(), 7, 1] {
            let got = decode(coding, golden, chunk, BIG)
                .unwrap_or_else(|e| panic!("{coding} chunk {chunk}: {e}"));
            assert_eq!(got, plain(), "{coding} chunk {chunk}");
        }
    }
}

#[test]
fn round_trip_each_coding_at_every_chunking() {
    let mut data = Vec::new();
    for i in 0..50_000u32 {
        data.extend_from_slice(format!("line {i} of a moderately repetitive body\n").as_bytes());
    }
    for coding in [ContentCoding::Gzip, ContentCoding::Deflate, ContentCoding::Brotli] {
        for in_chunk in [data.len(), 4096, 1] {
            // 1-byte pushes over 2 MB are slow; a prefix keeps that case quick.
            let src = if in_chunk == 1 { &data[..20_000] } else { &data[..] };
            let enc = encode(coding, src, in_chunk);
            assert!(enc.len() < src.len(), "{coding} should compress");
            for out_chunk in [enc.len(), 1000, 1] {
                if out_chunk == 1 && enc.len() > 50_000 {
                    continue;
                }
                assert_eq!(
                    decode(coding, &enc, out_chunk, BIG).unwrap(),
                    src,
                    "{coding} in {in_chunk} out {out_chunk}"
                );
            }
        }
    }
}

#[test]
fn empty_body_round_trips() {
    for coding in [ContentCoding::Gzip, ContentCoding::Deflate, ContentCoding::Brotli] {
        let enc = encode(coding, b"", 1);
        assert_eq!(decode(coding, &enc, 1, BIG).unwrap(), b"", "{coding}");
    }
}

#[test]
fn decoder_that_saw_no_input_finishes_cleanly() {
    // A HEAD / 204 / zero-length response has Content-Encoding but no body.
    for coding in [ContentCoding::Gzip, ContentCoding::Deflate, ContentCoding::Brotli] {
        assert!(Decoder::new(coding, BIG).unwrap().finish().is_ok(), "{coding}");
    }
}

#[test]
fn flush_makes_prefix_decodable_before_finish() {
    for coding in [ContentCoding::Gzip, ContentCoding::Deflate, ContentCoding::Brotli] {
        let mut e = Encoder::new(coding).unwrap();
        let mut wire = Vec::new();
        e.push(b"first part ", &mut |b| wire.extend_from_slice(b)).unwrap();
        e.flush(&mut |b| wire.extend_from_slice(b)).unwrap();

        let mut d = Decoder::new(coding, BIG).unwrap();
        let mut got = Vec::new();
        d.push(&wire, &mut |b| got.extend_from_slice(b)).unwrap();
        assert_eq!(got, b"first part ", "{coding}: flushed prefix not decodable");

        e.push(b"second", &mut |b| wire.extend_from_slice(b)).unwrap();
        let mut tail = Vec::new();
        e.finish(&mut |b| tail.extend_from_slice(b)).unwrap();
        d.push(&tail, &mut |b| got.extend_from_slice(b)).unwrap();
        d.finish().unwrap();
        assert_eq!(got, b"first part second", "{coding}");
    }
}

#[test]
fn decompression_bomb_fails_closed() {
    let zeros = vec![0u8; 8 * 1024 * 1024];
    for coding in [ContentCoding::Gzip, ContentCoding::Deflate, ContentCoding::Brotli] {
        let enc = encode(coding, &zeros, 64 * 1024);
        assert!(enc.len() < 64 * 1024, "{coding} bomb should be tiny, was {}", enc.len());
        let err = decode(coding, &enc, enc.len(), 100_000).unwrap_err();
        assert_eq!(err, CodingError::LimitExceeded, "{coding}");
        // Exactly at the cap is fine; one byte over is not.
        let n = zeros.len() as u64;
        assert!(decode(coding, &enc, 512, n).is_ok(), "{coding} at cap");
        assert_eq!(
            decode(coding, &enc, 512, n - 1).unwrap_err(),
            CodingError::LimitExceeded,
            "{coding} one over"
        );
    }
}

#[test]
fn output_arrives_in_bounded_chunks() {
    let zeros = vec![0u8; 1024 * 1024];
    for coding in [ContentCoding::Gzip, ContentCoding::Brotli] {
        let enc = encode(coding, &zeros, 64 * 1024);
        let mut d = Decoder::new(coding, BIG).unwrap();
        let mut biggest = 0usize;
        d.push(&enc, &mut |b| biggest = biggest.max(b.len())).unwrap();
        d.finish().unwrap();
        assert!(biggest <= SCRATCH_LEN, "{coding}: sink saw a {biggest}-byte chunk");
    }
}

#[test]
fn truncated_streams_are_rejected() {
    for (coding, golden) in [
        (ContentCoding::Gzip, GOLDEN_GZIP),
        (ContentCoding::Brotli, GOLDEN_BROTLI),
        (ContentCoding::Deflate, GOLDEN_ZLIB),
    ] {
        let cut = &golden[..golden.len() - 3];
        assert_eq!(
            decode(coding, cut, 1, BIG).unwrap_err(),
            CodingError::Truncated,
            "{coding}"
        );
    }
}

#[test]
fn corrupt_streams_are_rejected() {
    // Flip a payload byte: gzip fails its CRC, brotli/deflate fail structurally
    // or checksum (zlib Adler-32).
    for (coding, golden, at) in [
        (ContentCoding::Gzip, GOLDEN_GZIP, 30),
        (ContentCoding::Deflate, GOLDEN_ZLIB, 20),
    ] {
        let mut bad = golden.to_vec();
        bad[at] ^= 0x55;
        assert!(decode(coding, &bad, 3, BIG).is_err(), "{coding}");
    }
    assert!(decode(ContentCoding::Gzip, b"not gzip at all!!", 5, BIG).is_err());
    assert!(decode(ContentCoding::Brotli, &[0xff; 32], 5, BIG).is_err());
}

#[test]
fn trailing_bytes_after_end_of_stream_are_rejected() {
    for (coding, golden) in [
        (ContentCoding::Brotli, GOLDEN_BROTLI),
        (ContentCoding::Deflate, GOLDEN_ZLIB),
    ] {
        let mut extra = golden.to_vec();
        extra.extend_from_slice(b"junk");
        assert_eq!(decode(coding, &extra, 1, BIG).unwrap_err(), CodingError::Corrupt, "{coding}");
    }
}

#[test]
fn concatenated_gzip_members_decode_in_sequence() {
    let mut two = GOLDEN_GZIP.to_vec();
    two.extend_from_slice(GOLDEN_GZIP);
    let mut want = plain();
    want.extend(plain());
    assert_eq!(decode(ContentCoding::Gzip, &two, 1, BIG).unwrap(), want);
}

#[test]
fn gzip_header_optional_fields_are_skipped() {
    // FEXTRA | FNAME | FCOMMENT | FHCRC around the golden deflate body.
    let mut gz = vec![0x1f, 0x8b, 8, 0x02 | 0x04 | 0x08 | 0x10, 0, 0, 0, 0, 0, 3];
    gz.extend_from_slice(&[3, 0, b'a', b'b', b'c']); // XLEN=3
    gz.extend_from_slice(b"name.txt\0");
    gz.extend_from_slice(b"a comment\0");
    gz.extend_from_slice(&[0xde, 0xad]); // FHCRC (not verified)
    gz.extend_from_slice(&GOLDEN_GZIP[10..]);
    for chunk in [gz.len(), 1] {
        assert_eq!(decode(ContentCoding::Gzip, &gz, chunk, BIG).unwrap(), plain());
    }
}

#[test]
fn stacked_codings_decode_in_reverse_order_of_application() {
    // Content-Encoding: gzip, br  =>  gzip applied first, then br.
    let inner = encode(ContentCoding::Gzip, &plain(), 100);
    let wire = encode(ContentCoding::Brotli, &inner, 100);
    for chunk in [wire.len(), 1] {
        let mut d = Decoder::for_header("gzip, br", BIG).unwrap();
        let mut out = Vec::new();
        for c in wire.chunks(chunk) {
            d.push(c, &mut |b| out.extend_from_slice(b)).unwrap();
        }
        d.finish().unwrap();
        assert_eq!(out, plain(), "chunk {chunk}");
    }
}

#[test]
fn content_encoding_header_parsing() {
    assert_eq!(parse_content_encoding("gzip").unwrap(), [ContentCoding::Gzip]);
    assert_eq!(parse_content_encoding("GZip , BR").unwrap(), [ContentCoding::Gzip, ContentCoding::Brotli]);
    assert_eq!(parse_content_encoding("x-gzip").unwrap(), [ContentCoding::Gzip]);
    assert!(parse_content_encoding("identity").unwrap().is_empty());
    assert!(parse_content_encoding("").unwrap().is_empty());
    assert_eq!(parse_content_encoding("compress").unwrap_err(), CodingError::Unsupported);
    assert_eq!(parse_content_encoding("gzip, zstd").unwrap_err(), CodingError::Unsupported);
    assert_eq!(
        parse_content_encoding("gzip, gzip, gzip, gzip, gzip").unwrap_err(),
        CodingError::Unsupported,
        "chain longer than MAX_CODING_CHAIN"
    );
}

#[test]
fn accept_encoding_negotiation() {
    use ContentCoding::*;
    let pref = [Brotli, Gzip, Deflate];
    assert_eq!(negotiate_accept_encoding("gzip, br", &pref), Some(Brotli));
    assert_eq!(negotiate_accept_encoding("gzip", &pref), Some(Gzip));
    assert_eq!(negotiate_accept_encoding("br;q=0, gzip", &pref), Some(Gzip));
    assert_eq!(negotiate_accept_encoding("*", &pref), Some(Brotli));
    assert_eq!(negotiate_accept_encoding("*;q=0, deflate", &pref), Some(Deflate));
    assert_eq!(negotiate_accept_encoding("identity", &pref), None);
    assert_eq!(negotiate_accept_encoding("", &pref), None);
    assert_eq!(negotiate_accept_encoding("zstd", &pref), None);
    assert_eq!(negotiate_accept_encoding("gzip;q=0.5, br;q=0", &pref), Some(Gzip));
}

#[test]
fn capability_cache_learns_expires_and_forgets() {
    use std::time::Duration;
    let cache = ContentCodingCache::new();
    assert_eq!(cache.get("Example.test", 80), None);
    cache.put("Example.test", 80, vec![ContentCoding::Gzip]);
    assert_eq!(cache.get("example.test", 80), Some(vec![ContentCoding::Gzip]), "host is case-insensitive");
    assert_eq!(cache.get("example.test", 8080), None, "port is part of the origin");
    // Known to accept nothing is distinct from unknown.
    cache.put("none.test", 80, vec![]);
    assert_eq!(cache.get("none.test", 80), Some(vec![]));
    cache.forget("example.test", 80);
    assert_eq!(cache.get("example.test", 80), None);

    let short = ContentCodingCache::with_ttl(Duration::from_millis(20));
    short.put("a.test", 1, vec![ContentCoding::Brotli]);
    assert!(short.get("a.test", 1).is_some());
    std::thread::sleep(Duration::from_millis(40));
    assert_eq!(short.get("a.test", 1), None, "expired entries are unknown again");
}

#[test]
fn acceptable_codings_lists_all_allowed_in_candidate_order() {
    use ContentCoding::*;
    let all = [Brotli, Gzip, Deflate];
    assert_eq!(acceptable_codings("gzip, br", &all), [Brotli, Gzip]);
    assert_eq!(acceptable_codings("*", &all), [Brotli, Gzip, Deflate]);
    assert_eq!(acceptable_codings("*, gzip;q=0", &all), [Brotli, Deflate]);
    assert!(acceptable_codings("identity", &all).is_empty());
    assert!(acceptable_codings("", &all).is_empty());
}
