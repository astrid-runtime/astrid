//! Search-key layout oracle against the independently written pre-fix Encoder grammar.

use alloc::vec::Vec;

use super::super::codec::Encoder;
use super::super::identity::encode_physical_digest;
use super::{
    PhysicalMapKey, SEARCH_KEY_BYTES, TAGGED_PHYSICAL_IDENTITY_BYTES, encode_physical_digest_bytes,
};
use super::{SEARCH_KEY_BITS, legacy};

/// Independently rewritten copy of the pre-fix Encoder search-key grammar.
///
/// This deliberately does not call the shared fixed-width helper, so a drift in
/// that helper fails this oracle instead of both sides moving together.
fn old_encoder_search_key(digest: [u8; 32]) -> [u8; SEARCH_KEY_BYTES] {
    let mut tagged = Encoder::new();
    // Mirror the historical encode_tagged field order and endianness exactly.
    tagged.u16(1); // BLAKE3_ALGORITHM
    tagged.u16(2); // PHYSICAL_CONSTRUCTION
    tagged.u32(32); // CURRENT_DIGEST_BYTES
    tagged.raw(&digest);
    let tagged = tagged.finish();
    assert_eq!(tagged.len(), TAGGED_PHYSICAL_IDENTITY_BYTES);
    let mut search = [0_u8; SEARCH_KEY_BYTES];
    search[..4].copy_from_slice(
        &u32::try_from(tagged.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    search[4..].copy_from_slice(&tagged);
    search
}

fn varied_digests() -> Vec<[u8; 32]> {
    let mut digests = Vec::new();
    digests.push([0; 32]);
    digests.push([0xff; 32]);
    digests.push({
        let mut bytes = [0; 32];
        bytes[0] = 0x80;
        bytes[31] = 0x01;
        bytes
    });
    for index in 0..32_u8 {
        let mut bytes = [0; 32];
        bytes[usize::from(index)] = index.wrapping_mul(7).wrapping_add(3);
        digests.push(bytes);
    }
    for seed in [1_u64, 7, 99, 0x4f1d_u64, u64::MAX] {
        let mut bytes = [0; 32];
        bytes[..8].copy_from_slice(&seed.to_le_bytes());
        bytes[8..16].copy_from_slice(&seed.wrapping_mul(0x9e37).to_be_bytes());
        digests.push(*blake3::hash(&bytes).as_bytes());
    }
    digests
}

#[test]
fn search_key_matches_independently_written_old_encoder_grammar() {
    for digest in varied_digests() {
        let key = PhysicalMapKey::new(digest);
        assert_eq!(key.search_key(), old_encoder_search_key(digest));
    }
}

#[test]
fn physical_digest_helper_matches_encoder_and_old_grammar_body() {
    for digest in varied_digests() {
        let mut encoder = Encoder::new();
        encode_physical_digest(&mut encoder, &digest);
        let wire_bytes = encoder.finish();
        let helper = encode_physical_digest_bytes(&digest);
        assert_eq!(wire_bytes.as_slice(), helper.as_slice());
        assert_eq!(&old_encoder_search_key(digest)[4..], helper.as_slice());
    }
}

#[test]
fn legacy_prefix_comparison_preserves_every_bit_length_and_zero_padding() {
    for digest in varied_digests() {
        let key = PhysicalMapKey::new(digest).search_key();
        for bits in 0..=SEARCH_KEY_BITS {
            // Frozen pre-fix canonical_prefix oracle, including unused-bit
            // clearing. Production lookup must agree without copying this Vec.
            let bytes = usize::try_from(bits.div_ceil(8)).unwrap();
            let mut expected = key[..bytes].to_vec();
            if !bits.is_multiple_of(8)
                && let Some(last) = expected.last_mut()
            {
                *last &= u8::MAX << 8_u32.strict_sub(bits % 8);
            }
            assert!(legacy::matches_prefix(&key, bits, &expected));
            if let Some(last) = expected.last_mut() {
                // This also rejects nonzero unused bits in partial bytes.
                *last ^= 1;
                assert!(!legacy::matches_prefix(&key, bits, &expected));
                *expected.last_mut().unwrap() ^= 1;
            }
            expected.push(0);
            assert!(!legacy::matches_prefix(&key, bits, &expected));
        }
        assert!(!legacy::matches_prefix(&key, SEARCH_KEY_BITS + 1, &key));
    }
}
