//! Deterministic CBOR encoder and strict decoder.

use crate::entry_v2::cbor::Cbor;

fn encoded(item: &Cbor) -> String {
    hex::encode(item.encode())
}

#[test]
fn integers_use_the_shortest_head() {
    // RFC 8949 Appendix A.
    for (value, expected) in [
        (0, "00"),
        (1, "01"),
        (23, "17"),
        (24, "1818"),
        (255, "18ff"),
        (256, "190100"),
        (65_535, "19ffff"),
        (65_536, "1a00010000"),
        (1_000_000, "1a000f4240"),
        (4_294_967_296, "1b0000000100000000"),
        (u64::MAX, "1bffffffffffffffff"),
    ] {
        assert_eq!(encoded(&Cbor::Uint(value)), expected, "{value}");
    }
    assert_eq!(encoded(&Cbor::Nint(0)), "20"); // -1
    assert_eq!(encoded(&Cbor::Nint(99)), "3863"); // -100
}

#[test]
fn strings_arrays_and_simple_values_match_rfc_8949() {
    assert_eq!(encoded(&Cbor::bytes(vec![])), "40");
    assert_eq!(encoded(&Cbor::bytes(vec![1, 2, 3, 4])), "4401020304");
    assert_eq!(encoded(&Cbor::text("")), "60");
    assert_eq!(encoded(&Cbor::text("IETF")), "6449455446");
    assert_eq!(encoded(&Cbor::text("\u{00fc}")), "62c3bc");
    assert_eq!(
        encoded(&Cbor::Array(vec![
            Cbor::Uint(1),
            Cbor::Array(vec![Cbor::Uint(2), Cbor::Uint(3)]),
        ])),
        "8201820203"
    );
    assert_eq!(encoded(&Cbor::Bool(false)), "f4");
    assert_eq!(encoded(&Cbor::Bool(true)), "f5");
    assert_eq!(encoded(&Cbor::Null), "f6");
}

#[test]
fn map_keys_are_sorted_by_their_encoding() {
    // Bytewise order of encoded keys puts shorter text keys first ("b" is
    // 0x61 0x62, "aa" is 0x62 0x61 0x61) and integers before text.
    let map = Cbor::Map(vec![
        (Cbor::text("aa"), Cbor::Uint(1)),
        (Cbor::text("b"), Cbor::Uint(2)),
        (Cbor::Uint(10), Cbor::Uint(3)),
        (Cbor::Uint(1), Cbor::Uint(4)),
    ]);
    assert_eq!(encoded(&map), "a401040a0361620262616101");
}

#[test]
fn decoding_round_trips_canonical_items() {
    let item = Cbor::Array(vec![
        Cbor::text("tag"),
        Cbor::Uint(1_790_598_896_123_456_789),
        Cbor::Nint(5),
        Cbor::bytes(vec![0xff; 40]),
        Cbor::Map(vec![
            (Cbor::Uint(2), Cbor::Null),
            (Cbor::Uint(1), Cbor::Bool(true)),
        ]),
    ]);
    let bytes = item.encode();
    let decoded = Cbor::decode(&bytes).unwrap();
    assert_eq!(decoded.encode(), bytes);
}

#[test]
fn decoder_rejects_non_canonical_and_unsupported_input() {
    for (bytes, why) in [
        ("1817", "one-byte argument below 24"),
        ("190017", "two-byte argument that fits one byte"),
        ("1a000000ff", "four-byte argument that fits one byte"),
        (
            "1b00000000ffffffff",
            "eight-byte argument that fits four bytes",
        ),
        ("5f4101ff", "indefinite-length byte string"),
        ("9f01ff", "indefinite-length array"),
        ("a202010102", "unsorted map keys"),
        ("a201010102", "duplicate map keys"),
        ("f93c00", "half-precision float"),
        ("fb3ff8000000000000", "double-precision float"),
        ("c11a514b67b0", "tag"),
        ("f7", "undefined"),
        ("62c328", "invalid UTF-8"),
        ("0101", "trailing bytes"),
        ("5820", "truncated byte string"),
        ("9bffffffffffffffff", "array length beyond the input"),
        ("1c", "reserved additional information"),
    ] {
        let input = hex::decode(bytes).unwrap();
        assert!(Cbor::decode(&input).is_err(), "{why} must be rejected");
    }
}

#[test]
fn decoder_bounds_nesting() {
    let mut bytes = vec![0x81; 100];
    bytes.push(0x00);
    assert!(Cbor::decode(&bytes).is_err());
}
