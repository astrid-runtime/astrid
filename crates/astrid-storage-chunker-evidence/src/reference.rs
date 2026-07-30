//! Deliberately scalar `MinCDC` oracle.
//!
//! This is not production format code. It is kept simple so the evidence
//! harness can catch divergence in the optimized third-party implementation
//! without sharing its SIMD or buffering machinery.

// These literals intentionally do not import the implementation constants:
// agreement must fail if either side drifts.
const REFERENCE_WINDOW_BYTES: u8 = 4;
const REFERENCE_MULTIPLIER: u32 = 0x915f_77f5;
const REFERENCE_ADDEND: u32 = 0x3463_6463;

pub fn chunk_lengths(bytes: &[u8], minimum: usize, maximum: usize) -> Vec<usize> {
    assert!(minimum <= maximum);
    assert!(maximum > 0);

    let mut offset = 0;
    let mut lengths = Vec::new();
    while offset < bytes.len() {
        let remaining = bytes
            .len()
            .checked_sub(offset)
            .expect("offset never exceeds the input length");
        if remaining <= minimum {
            lengths.push(remaining);
            break;
        }

        let search_start = offset
            .checked_add(minimum.saturating_sub(usize::from(REFERENCE_WINDOW_BYTES)))
            .expect("the input and configured bounds are addressable");
        let search_stop = offset
            .checked_add(maximum)
            .unwrap_or(bytes.len())
            .min(bytes.len());
        let split = search_start
            .checked_add(leftmost_minimum(&bytes[search_start..search_stop]))
            .expect("the split lies within the input");
        lengths.push(
            split
                .checked_sub(offset)
                .expect("the split never precedes the chunk"),
        );
        offset = split;
    }
    lengths
}

fn leftmost_minimum(bytes: &[u8]) -> usize {
    const WINDOW: usize = REFERENCE_WINDOW_BYTES as usize;
    if bytes.len() < WINDOW {
        return bytes.len();
    }

    let mut best_index = 0;
    let mut best_score = score(&bytes[..WINDOW]);
    let last_index = bytes
        .len()
        .checked_sub(WINDOW)
        .expect("the short-input case returned above");
    for index in 1..=last_index {
        let end = index
            .checked_add(WINDOW)
            .expect("the four-byte window lies within the input");
        let candidate = score(&bytes[index..end]);
        if candidate < best_score {
            best_index = index;
            best_score = candidate;
        }
    }
    WINDOW
        .checked_add(best_index)
        .expect("the selected window lies within the input")
}

fn score(window: &[u8]) -> u32 {
    let bytes: [u8; 4] = window
        .try_into()
        .expect("the scalar oracle only scores four-byte windows");
    u32::from_le_bytes(bytes)
        .wrapping_mul(REFERENCE_MULTIPLIER)
        .wrapping_add(REFERENCE_ADDEND)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use crate::algorithm::{Algorithm, candidates};
    use crate::fixture::pseudorandom_bytes;

    use super::*;

    #[test]
    fn scalar_oracle_matches_accelerated_reader_on_adversarial_inputs() {
        let mut fixtures = vec![
            Vec::new(),
            vec![7],
            vec![0; 4],
            vec![0; 64 * 1024],
            vec![0xff; 64 * 1024],
            (0_u8..=u8::MAX).cycle().take(256 * 1024).collect(),
            pseudorandom_bytes(2 * 1024 * 1024, 0xa11c_e5e5_d00d_f00d),
        ];
        fixtures.push(b"abcd".repeat(128 * 1024));

        for candidate in candidates(8)
            .unwrap()
            .into_iter()
            .filter(|candidate| candidate.algorithm == Algorithm::MinCdcHash4)
        {
            for fixture in &fixtures {
                let expected = chunk_lengths(
                    fixture,
                    usize::try_from(candidate.minimum_bytes).unwrap(),
                    usize::try_from(candidate.maximum_bytes).unwrap(),
                );
                let mut actual = Vec::new();
                candidate
                    .visit_boundary_chunks(Cursor::new(fixture), |chunk| {
                        actual.push(chunk.len());
                        Ok(())
                    })
                    .unwrap();
                assert_eq!(actual, expected, "candidate {}", candidate.name);
            }
        }
    }

    #[test]
    fn equal_scores_choose_the_leftmost_boundary() {
        let minimum = 32;
        let maximum = 128;
        let lengths = chunk_lengths(&vec![0; 512], minimum, maximum);
        assert_eq!(lengths, vec![minimum; 16]);
    }

    #[test]
    fn final_chunk_may_be_shorter_than_minimum() {
        assert_eq!(chunk_lengths(&[0; 35], 32, 128), vec![32, 3]);
    }

    #[test]
    fn maximum_is_inclusive_for_non_final_chunks() {
        let candidate = candidates(8)
            .unwrap()
            .into_iter()
            .find(|candidate| candidate.name == "mincdc-hash4-narrow-8k")
            .unwrap();
        let minimum = usize::try_from(candidate.minimum_bytes).unwrap();
        let maximum = usize::try_from(candidate.maximum_bytes).unwrap();
        let mut data = vec![0xff; maximum * 3];
        let zero_score_window = 0_u32
            .wrapping_sub(REFERENCE_ADDEND)
            .wrapping_mul(inverse_odd_u32(REFERENCE_MULTIPLIER))
            .to_le_bytes();
        data[maximum - zero_score_window.len()..maximum].copy_from_slice(&zero_score_window);

        let expected = chunk_lengths(&data, minimum, maximum);
        assert_eq!(expected[0], maximum);

        let mut actual = Vec::new();
        candidate
            .visit_boundary_chunks(Cursor::new(&data), |chunk| {
                actual.push(chunk.len());
                Ok(())
            })
            .unwrap();
        assert_eq!(actual, expected);
    }

    fn inverse_odd_u32(value: u32) -> u32 {
        debug_assert_eq!(value & 1, 1);
        let mut inverse = value;
        for _ in 0..5 {
            inverse = inverse.wrapping_mul(2_u32.wrapping_sub(value.wrapping_mul(inverse)));
        }
        debug_assert_eq!(value.wrapping_mul(inverse), 1);
        inverse
    }
}
