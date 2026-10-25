use super::*;

fn scheme() -> IdentityScheme {
    IdentityScheme::new(1, 1).unwrap()
}

fn empty() -> IndexState {
    let state = IndexState {
        arena_len: 0,
        arena_tail: None,
        objects: BTreeMap::new(),
    };
    decode_record(
        None,
        &encode_snapshot(&state, scheme()).unwrap(),
        scheme(),
        0,
    )
    .unwrap()
}

fn location(sequence: u64) -> ArenaLocation {
    ArenaLocation {
        offset: sequence
            .strict_sub(1)
            .strict_mul(FRAME_HEADER_LEN.strict_add(1)),
        payload_len: 1,
        checksum: [0; 32],
    }
}

fn identity(sequence: u64) -> ObjectId {
    let mut bytes = [0; 32];
    bytes[..8].copy_from_slice(&sequence.to_le_bytes());
    ObjectId::new(bytes)
}

fn delta(
    state: &IndexState,
    arena_len: u64,
    tail: ArenaLocation,
    additions: &[(ObjectId, ArenaLocation)],
) -> Vec<u8> {
    encode_delta(
        &IndexDelta {
            previous_arena_len: state.arena_len,
            arena_len,
            arena_tail: tail,
            objects: additions,
        },
        scheme(),
    )
    .unwrap()
}

#[test]
fn recovered_delta_bounds_validation_is_linear_in_added_objects() {
    let mut state = empty();
    validation::LOCATION_VISITS.with(|count| count.set(0));
    for sequence in 1..=2048 {
        let tail = location(sequence);
        let bytes = delta(
            &state,
            sequence * (FRAME_HEADER_LEN + 1),
            tail,
            &[(identity(sequence), tail)],
        );
        state = decode_record(Some(state), &bytes, scheme(), sequence).unwrap();
    }
    assert_eq!(state.objects.len(), 2048);
    validation::LOCATION_VISITS.with(|count| assert_eq!(count.get(), 2048));
    validate_state(&state, 2048).unwrap();
}

#[test]
fn rejects_location_outside_its_prefix_even_if_a_later_prefix_could_cover_it() {
    let state = empty();
    let bytes = delta(
        &state,
        FRAME_HEADER_LEN + 1,
        location(1),
        &[(identity(1), location(2))],
    );
    assert!(decode_record(Some(state), &bytes, scheme(), 0).is_err());
}

#[test]
fn delta_rejects_tail_mismatch_and_location_overflow() {
    for (tail, added) in [
        (location(2), location(1)),
        (
            location(1),
            ArenaLocation {
                offset: u64::MAX,
                ..location(1)
            },
        ),
    ] {
        let state = empty();
        let bytes = delta(&state, FRAME_HEADER_LEN + 1, tail, &[(identity(1), added)]);
        assert!(decode_record(Some(state), &bytes, scheme(), 0).is_err());
    }
}

#[test]
fn delta_cannot_remap_a_previously_validated_identity() {
    let state = empty();
    let bytes = delta(
        &state,
        FRAME_HEADER_LEN + 1,
        location(1),
        &[(identity(1), location(1))],
    );
    let state = decode_record(Some(state), &bytes, scheme(), 0).unwrap();
    let bytes = delta(
        &state,
        2 * (FRAME_HEADER_LEN + 1),
        location(2),
        &[(identity(1), location(2))],
    );
    assert!(decode_record(Some(state), &bytes, scheme(), 1).is_err());
}

#[test]
fn tail_only_delta_validates_its_prefix_without_rescanning_prior_locations() {
    let state = empty();
    let bytes = delta(&state, FRAME_HEADER_LEN.strict_add(1), location(1), &[]);
    let state = decode_record(Some(state), &bytes, scheme(), 0).unwrap();
    assert!(state.objects.is_empty());
    assert_eq!(state.arena_tail.unwrap().offset, 0);
    let bytes = delta(
        &state,
        FRAME_HEADER_LEN.strict_add(1).strict_mul(2),
        location(1),
        &[],
    );
    assert!(decode_record(Some(state), &bytes, scheme(), 1).is_err());
}

#[test]
fn borrowed_snapshot_preserves_canonical_wire_and_complete_locations() {
    let mut objects = BTreeMap::new();
    for sequence in (1..=4096).rev() {
        objects.insert(identity(sequence), location(sequence));
    }
    let tail = location(4096);
    let state = IndexState {
        arena_len: 4096 * (FRAME_HEADER_LEN + 1),
        arena_tail: Some(tail),
        objects: &objects,
    };
    let actual = encode_snapshot(&state, scheme()).unwrap();
    let mut expected = vec![SNAPSHOT_RECORD];
    encode_scheme(&mut expected, scheme());
    expected.extend_from_slice(&state.arena_len.to_le_bytes());
    encode_optional_location(&mut expected, state.arena_tail);
    // The existing unordered encoder is the canonical reference for old
    // snapshot/delta bytes. Include IDs whose byte order differs from number
    // order, rather than assuming insertion order is the wire ordering.
    encode_locations(
        &mut expected,
        scheme(),
        objects.iter().rev().map(|(id, location)| (*id, *location)),
    )
    .unwrap();
    assert_eq!(actual, expected);
    let recovered = decode_record(None, &actual, scheme(), 0).unwrap();
    assert_eq!(recovered.objects, objects);
    assert_eq!(recovered.arena_tail, Some(tail));
    assert_eq!(recovered.arena_len, state.arena_len);
    validate_state(&recovered, 0).unwrap();
}
