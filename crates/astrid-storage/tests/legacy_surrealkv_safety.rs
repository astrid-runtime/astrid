//! Guard the legacy dependency boundary implicated by RUSTSEC-2026-0452.
#![cfg(feature = "legacy-surrealkv")]

#[test]
fn truncated_internal_keys_have_bounded_accessors() {
    // The old safe constructor only debug-asserted a sixteen-byte minimum;
    // release accessors could instead read before the allocation. Exercise
    // every truncated length through the real dependency, without unsafe code.
    // SurrealKV 1.2 uses an eight-byte trailer and no encoded timestamp.
    for length in 0..16 {
        let encoded = vec![0; length];
        let key = surrealkv::InternalKeyRef::from_encoded(&encoded);
        assert_eq!(key.user_key(), &encoded[..length.saturating_sub(8)]);
        assert_eq!(key.seq_num(), 0);
        assert_eq!(key.timestamp(), 0);
    }
}
