use super::*;
use crate::storage_model::physical::{Blake3PhysicalIdentity, PhysicalIdentity};

#[test]
fn fixed_context_keys_are_the_standard_domain_derivations() {
    assert_eq!(
        LEGACY_CONTEXT_KEY,
        blake3::hazmat::hash_derive_key_context(LEGACY_MAP_NODE_IDENTITY)
    );
    assert_eq!(
        RADIX_CONTEXT_KEY,
        blake3::hazmat::hash_derive_key_context(RADIX_MAP_NODE_IDENTITY)
    );
    assert_ne!(LEGACY_CONTEXT_KEY, RADIX_CONTEXT_KEY);
}

#[test]
fn physical_identity_matches_standard_derivation_across_input_boundaries() {
    for context in [
        LEGACY_MAP_NODE_IDENTITY,
        RADIX_MAP_NODE_IDENTITY,
        "astrid-representation-state-v1\0",
        "astrid-physical-map-node-v1",
        "astrid-physical-map-node-v2\0",
        "",
    ] {
        for length in [0, 1, 63, 64, 65, 1023, 1024, 1025, 4097] {
            let input = (0_u8..251)
                .cycle()
                .take(length)
                .collect::<alloc::vec::Vec<_>>();
            let expected = blake3::derive_key(context, &input);
            assert_eq!(Blake3PhysicalIdentity.identify(context, &input), expected);
            let middle = length / 2;
            assert_eq!(
                Blake3PhysicalIdentity
                    .identify_parts(context, &[&input[..middle], &[], &input[middle..]],),
                expected,
            );
        }
    }
}

#[test]
fn map_identity_does_not_rederive_context_per_body() {
    CONTEXT_DERIVATIONS.with(|count| count.set(0));
    for context in [LEGACY_MAP_NODE_IDENTITY, RADIX_MAP_NODE_IDENTITY] {
        let first = Blake3PhysicalIdentity.identify(context, b"first");
        let second = Blake3PhysicalIdentity.identify_parts(context, &[b"sec", b"ond"]);
        assert_ne!(first, second);
    }
    assert_eq!(CONTEXT_DERIVATIONS.with(core::cell::Cell::get), 0);
    Blake3PhysicalIdentity.identify("unknown domain", b"body");
    assert_eq!(CONTEXT_DERIVATIONS.with(core::cell::Cell::get), 1);
}
