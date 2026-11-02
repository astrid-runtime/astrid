//! Golden checksums against a fresh derive-key context, plus clone isolation.

use super::*;

const CHUNK: usize = 65_536;

struct Case {
    magic: [u8; 8],
    payload_len: u64,
    payload: Vec<u8>,
}

fn payload(length: usize, seed: u8) -> Vec<u8> {
    (0..length)
        .map(|index| seed.wrapping_add(u8::try_from(index % 251).unwrap()))
        .collect()
}

fn cases() -> Vec<Case> {
    let magics = [ARENA_MAGIC, *b"ASTIDX1\0", *b"ASTROOT\0", [0; 8], [0xff; 8]];
    let bodies = [
        payload(0, 0),
        payload(1, 1),
        payload(63, 2),
        payload(64, 3),
        payload(65, 4),
        payload(1_024, 5),
        payload(CHUNK, 6),
        payload(CHUNK + 1, 7),
    ];
    let mut cases = Vec::new();
    for magic in magics {
        for payload in &bodies {
            let payload_len = u64::try_from(payload.len()).unwrap();
            cases.push(Case {
                magic,
                payload_len,
                payload: payload.clone(),
            });
        }
        cases.push(Case {
            magic,
            payload_len: 0,
            payload: payload(3, 8),
        });
        cases.push(Case {
            magic,
            payload_len: u64::from(u32::MAX),
            payload: payload(2, 9),
        });
    }
    cases
}

fn independent_fresh_checksum(magic: [u8; 8], payload_len: u64, payload: &[u8]) -> [u8; 32] {
    let mut hasher = new_frame_checksum_context();
    hasher.update(&magic);
    hasher.update(&FRAME_VERSION.to_le_bytes());
    hasher.update(&payload_len.to_le_bytes());
    hasher.update(payload);
    *hasher.finalize().as_bytes()
}

fn derive_key_checksum(magic: [u8; 8], payload_len: u64, payload: &[u8]) -> [u8; 32] {
    let mut material = Vec::new();
    material.extend_from_slice(&magic);
    material.extend_from_slice(&FRAME_VERSION.to_le_bytes());
    material.extend_from_slice(&payload_len.to_le_bytes());
    material.extend_from_slice(payload);
    blake3::derive_key(FRAME_CHECKSUM_DOMAIN, &material)
}

fn expected_checksum(magic: [u8; 8], payload_len: u64, payload: &[u8]) -> [u8; 32] {
    let fresh = independent_fresh_checksum(magic, payload_len, payload);
    let derived = derive_key_checksum(magic, payload_len, payload);
    assert_eq!(fresh, derived);
    derived
}

fn reset_context_initializations() {
    FRAME_CHECKSUM_CONTEXT_INITIALIZATIONS.with(|count| count.set(0));
}

fn context_initializations() -> usize {
    FRAME_CHECKSUM_CONTEXT_INITIALIZATIONS.with(std::cell::Cell::get)
}

#[test]
fn frame_checksum_matches_independent_fresh_context() {
    for case in cases() {
        let actual = frame_checksum(case.magic, case.payload_len, &case.payload);
        assert_eq!(
            actual,
            expected_checksum(case.magic, case.payload_len, &case.payload)
        );
    }
}

#[test]
fn chunked_payload_updates_match_contiguous_preimage() {
    for case in cases() {
        let mut hasher = frame_checksum_hasher(case.magic, case.payload_len);
        for chunk in case.payload.chunks(CHUNK) {
            hasher.update(chunk);
        }
        assert_eq!(
            *hasher.finalize().as_bytes(),
            expected_checksum(case.magic, case.payload_len, &case.payload)
        );
    }
}

#[test]
fn cloned_context_templates_do_not_share_later_updates() {
    let cases = cases();
    let mut hashers: Vec<_> = cases
        .iter()
        .map(|case| frame_checksum_hasher(case.magic, case.payload_len))
        .collect();
    for (hasher, case) in hashers.iter_mut().zip(&cases) {
        if let Some((first, rest)) = case.payload.split_first() {
            hasher.update(&[*first]);
            hasher.update(rest);
        }
    }
    for (hasher, case) in hashers.into_iter().zip(&cases) {
        assert_eq!(
            *hasher.finalize().as_bytes(),
            expected_checksum(case.magic, case.payload_len, &case.payload)
        );
    }
}

#[test]
fn frame_checksum_is_stable_across_threads() {
    let cases = cases();
    std::thread::scope(|scope| {
        for case in &cases {
            scope.spawn(move || {
                let actual = frame_checksum(case.magic, case.payload_len, &case.payload);
                assert_eq!(
                    actual,
                    derive_key_checksum(case.magic, case.payload_len, &case.payload)
                );
            });
        }
    });
}

#[test]
fn frame_checksum_hasher_reuses_actual_derive_key_initialization() {
    reset_context_initializations();
    for _ in 0..6 {
        let _ = new_frame_checksum_context();
    }
    assert_eq!(context_initializations(), 6);

    reset_context_initializations();
    for case in cases() {
        let _ = frame_checksum(case.magic, case.payload_len, &case.payload);
        let mut hasher = frame_checksum_hasher(case.magic, case.payload_len);
        hasher.update(&case.payload);
        let _ = hasher.finalize();
    }
    // Another test may already have initialized the process-wide template.
    assert!(context_initializations() <= 1);
}
