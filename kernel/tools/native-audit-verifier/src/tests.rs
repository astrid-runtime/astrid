//! Independent regressions for the frozen wire format and fold engine.

use super::*;
use blake3::Hasher;

const BOOT: [u8; 16] = [7; 16];

fn key() -> CheckpointKey {
    CheckpointKey::new([0x5a; 32]).unwrap()
}

#[derive(Clone, Copy)]
enum Object {
    None,
    Domain(u8, u64),
    Endpoint(u8, u64),
    Capability(u64, u8, u64, u8, u64),
}

fn body(
    boot: [u8; 16],
    seq: u64,
    class: u16,
    object: Object,
    rights: u16,
    payload: &[u8],
    prev: Option<[u8; 32]>,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&CODEC_VERSION.to_le_bytes());
    out.extend_from_slice(&boot);
    out.extend_from_slice(&seq.to_le_bytes());
    out.extend_from_slice(&class.to_le_bytes());
    out.push(0);
    out.extend_from_slice(&1u64.to_le_bytes());
    match object {
        Object::None => out.push(0),
        Object::Domain(slot, generation) => {
            out.push(1);
            out.push(slot);
            out.extend_from_slice(&generation.to_le_bytes());
        },
        Object::Endpoint(pool_index, generation) => {
            out.push(2);
            out.push(pool_index);
            out.extend_from_slice(&generation.to_le_bytes());
        },
        Object::Capability(token, slot, generation, kind, object_token) => {
            out.push(3);
            out.extend_from_slice(&token.to_le_bytes());
            out.push(slot);
            out.extend_from_slice(&generation.to_le_bytes());
            out.push(kind);
            out.extend_from_slice(&object_token.to_le_bytes());
        },
    }
    out.extend_from_slice(&rights.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    out.extend_from_slice(payload);
    match prev {
        None => out.push(0),
        Some(prev) => {
            out.push(1);
            out.extend_from_slice(&prev);
        },
    }
    let mut framed = Vec::new();
    framed.extend_from_slice(&(out.len() as u32).to_le_bytes());
    framed.extend_from_slice(&out);
    framed
}

fn expected_root(previous: [u8; 32], seq: u64, frame: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(ROOT_DOMAIN_TAG);
    hasher.update(ROOT_ALGORITHM_ID);
    hasher.update(&CODEC_VERSION.to_le_bytes());
    hasher.update(&BOOT);
    hasher.update(&seq.to_le_bytes());
    hasher.update(&previous);
    hasher.update(frame);
    hasher.finalize().into()
}

#[test]
fn genesis_fold_requires_boot_previous_root_and_source_root() {
    let mut verifier = AuditVerifier::genesis(BOOT, key()).unwrap();
    let genesis = verifier.root();

    let frame1 = body(BOOT, 1, 1, Object::None, 0, &[], Some(genesis));
    let root1 = expected_root(genesis, 1, &frame1);
    assert_eq!(verifier.fold(&frame1, root1).unwrap(), 1);

    let frame2 = body(
        BOOT,
        2,
        16,
        Object::Capability(9, 3, 4, 2, 11),
        0b0101,
        &[],
        Some(root1),
    );
    let root2 = expected_root(root1, 2, &frame2);
    assert_eq!(verifier.fold(&frame2, root2).unwrap(), 2);
    assert_eq!(verifier.root(), root2);
}

#[test]
fn tamper_without_a_valid_claimed_root_is_invalid() {
    let mut verifier = AuditVerifier::genesis(BOOT, key()).unwrap();
    let frame = body(BOOT, 1, 1, Object::None, 0, &[], Some(verifier.root()));
    assert_eq!(
        verifier.fold(&frame, [0; 32]),
        Err(FoldFailure::Invalid(InvalidReason::RootMismatch))
    );
}

#[test]
fn cross_boot_and_missing_previous_root_are_invalid() {
    let mut verifier = AuditVerifier::genesis(BOOT, key()).unwrap();
    let foreign = body([8; 16], 1, 1, Object::None, 0, &[], Some(verifier.root()));
    let foreign_root = expected_root(verifier.root(), 1, &foreign);
    assert_eq!(
        verifier.fold(&foreign, foreign_root),
        Err(FoldFailure::Invalid(InvalidReason::ForeignBoot))
    );

    let missing_previous = body(BOOT, 1, 1, Object::None, 0, &[], None);
    let missing_root = expected_root(verifier.root(), 1, &missing_previous);
    assert_eq!(
        verifier.fold(&missing_previous, missing_root),
        Err(FoldFailure::Invalid(InvalidReason::PreviousRootMismatch))
    );
}

#[test]
fn gap_is_incomplete_and_duplicate_is_invalid() {
    let mut verifier = AuditVerifier::genesis(BOOT, key()).unwrap();
    let genesis = verifier.root();
    let frame1 = body(BOOT, 1, 1, Object::None, 0, &[], Some(genesis));
    let root1 = expected_root(genesis, 1, &frame1);
    let frame3 = body(BOOT, 3, 3, Object::None, 0, &[], Some(root1));
    let root3 = expected_root(root1, 3, &frame3);
    verifier.fold(&frame1, root1).unwrap();
    assert_eq!(
        verifier.fold(&frame3, root3),
        Err(FoldFailure::Incomplete(IncompleteReason::SequenceGap))
    );
    assert_eq!(
        verifier.fold(&frame1, root1),
        Err(FoldFailure::Invalid(InvalidReason::DuplicateOrReorder))
    );
}

#[test]
fn denial_must_not_disclose_a_foreign_identity() {
    let mut verifier = AuditVerifier::genesis(BOOT, key()).unwrap();
    let mut payload = vec![4, 0];
    payload.extend_from_slice(&[9; 8]);
    let denial = body(
        BOOT,
        1,
        80,
        Object::None,
        0,
        &payload,
        Some(verifier.root()),
    );
    let denial_root = expected_root(verifier.root(), 1, &denial);
    assert!(verifier.fold(&denial, denial_root).is_ok());

    let mut verifier = AuditVerifier::genesis(BOOT, key()).unwrap();
    let disclosing = body(
        BOOT,
        1,
        80,
        Object::Domain(1, 3),
        0,
        &payload,
        Some(verifier.root()),
    );
    assert_eq!(
        verifier.fold(&disclosing, [0; 32]),
        Err(FoldFailure::Invalid(InvalidReason::DenialDisclosure))
    );
}

#[test]
fn non_canonical_inputs_fail_closed() {
    let valid = body(BOOT, 1, 1, Object::None, 0, &[], Some(genesis_root(BOOT)));
    let mut verifier = AuditVerifier::genesis(BOOT, key()).unwrap();

    assert!(matches!(
        verifier.fold(&valid[..valid.len() - 1], [0; 32]),
        Err(FoldFailure::Invalid(InvalidReason::Malformed))
    ));
    let mut slack = valid.clone();
    slack.push(0);
    assert!(matches!(
        verifier.fold(&slack, [0; 32]),
        Err(FoldFailure::Invalid(InvalidReason::Malformed))
    ));

    let cases = [
        body(
            [0; 16],
            1,
            1,
            Object::None,
            0,
            &[],
            Some(genesis_root(BOOT)),
        ),
        body(BOOT, 0, 1, Object::None, 0, &[], Some(genesis_root(BOOT))),
        body(BOOT, 1, 10, Object::None, 0, &[], Some(genesis_root(BOOT))),
        body(
            BOOT,
            1,
            1,
            Object::Domain(2, 1),
            0,
            &[],
            Some(genesis_root(BOOT)),
        ),
        body(
            BOOT,
            1,
            1,
            Object::Domain(1, 0),
            0,
            &[],
            Some(genesis_root(BOOT)),
        ),
        body(
            BOOT,
            1,
            1,
            Object::Endpoint(4, 1),
            0,
            &[],
            Some(genesis_root(BOOT)),
        ),
        body(
            BOOT,
            1,
            1,
            Object::Capability(1, 1, 1, 1, 1),
            0,
            &[],
            Some(genesis_root(BOOT)),
        ),
        body(
            BOOT,
            1,
            1,
            Object::Capability(0, 1, 1, 2, 1),
            0,
            &[],
            Some(genesis_root(BOOT)),
        ),
        body(
            BOOT,
            1,
            1,
            Object::Capability(1, 8, 1, 2, 1),
            0,
            &[],
            Some(genesis_root(BOOT)),
        ),
        body(
            BOOT,
            1,
            1,
            Object::Capability(1, 1, 0, 2, 1),
            0,
            &[],
            Some(genesis_root(BOOT)),
        ),
        body(
            BOOT,
            1,
            1,
            Object::Capability(1, 1, 1, 2, 0),
            0,
            &[],
            Some(genesis_root(BOOT)),
        ),
        body(
            BOOT,
            1,
            1,
            Object::None,
            0x10,
            &[],
            Some(genesis_root(BOOT)),
        ),
        body(
            BOOT,
            1,
            1,
            Object::None,
            0,
            &[0; 65],
            Some(genesis_root(BOOT)),
        ),
    ];
    for case in cases {
        let mut verifier = AuditVerifier::genesis(BOOT, key()).unwrap();
        assert!(matches!(
            verifier.fold(&case, [0; 32]),
            Err(FoldFailure::Invalid(InvalidReason::Malformed))
        ));
    }

    let mut bad_version = valid.clone();
    bad_version[4..6].copy_from_slice(&2u16.to_le_bytes());
    assert!(matches!(
        verifier.fold(&bad_version, [0; 32]),
        Err(FoldFailure::Invalid(InvalidReason::Malformed))
    ));
}

fn checkpoint_wire(
    boot: [u8; 16],
    seq: u64,
    root: [u8; 32],
    relay_generation: u64,
    tag: [u8; 32],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&CODEC_VERSION.to_le_bytes());
    body.extend_from_slice(&boot);
    body.extend_from_slice(&seq.to_le_bytes());
    body.extend_from_slice(&root);
    body.extend_from_slice(&relay_generation.to_le_bytes());
    body.extend_from_slice(&tag);
    let mut wire = Vec::new();
    wire.extend_from_slice(&(body.len() as u32).to_le_bytes());
    wire.extend_from_slice(&body);
    wire
}

fn sealed_tag(boot: [u8; 16], seq: u64, root: [u8; 32], relay_generation: u64) -> [u8; 32] {
    checkpoint_tag(boot, seq, root, relay_generation, key())
}

fn unkeyed_tag(boot: [u8; 16], seq: u64, root: [u8; 32], relay_generation: u64) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(CHECKPOINT_DOMAIN_TAG);
    hasher.update(&CODEC_VERSION.to_le_bytes());
    hasher.update(&boot);
    hasher.update(&seq.to_le_bytes());
    hasher.update(&root);
    hasher.update(&relay_generation.to_le_bytes());
    hasher.finalize().into()
}

#[test]
fn checkpoint_restart_and_mandatory_source_root_match() {
    let genesis = AuditVerifier::genesis(BOOT, key()).unwrap().root();
    let start = checkpoint_wire(BOOT, 0, genesis, 1, sealed_tag(BOOT, 0, genesis, 1));
    let mut verifier = AuditVerifier::from_checkpoint(&start, key()).unwrap();
    assert_eq!(verifier.root(), genesis);

    let frame = body(BOOT, 1, 1, Object::None, 0, &[], Some(genesis));
    let root1 = expected_root(genesis, 1, &frame);
    verifier.fold(&frame, root1).unwrap();

    let next = checkpoint_wire(BOOT, 1, root1, 1, sealed_tag(BOOT, 1, root1, 1));
    assert_eq!(verifier.accept_checkpoint(&next), Ok(()));

    let mut tampered = next.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(matches!(
        AuditVerifier::from_checkpoint(&tampered, key()),
        Err(VerifyFailure::CheckpointMismatch)
    ));

    let mut wrong_root = root1;
    wrong_root[0] ^= 1;
    let mismatched = checkpoint_wire(BOOT, 1, wrong_root, 1, sealed_tag(BOOT, 1, wrong_root, 1));
    assert_eq!(
        verifier.accept_checkpoint(&mismatched),
        Err(VerifyFailure::CheckpointMismatch)
    );
}

#[test]
fn host_minted_unkeyed_checkpoint_is_rejected() {
    let genesis = AuditVerifier::genesis(BOOT, key()).unwrap().root();
    let mut forged = checkpoint_wire(BOOT, 0, genesis, 1, unkeyed_tag(BOOT, 0, genesis, 1));
    assert_eq!(
        verify_checkpoint(&forged, key()),
        Err(VerifyFailure::CheckpointMismatch)
    );

    let trusted = checkpoint_wire(BOOT, 0, genesis, 1, sealed_tag(BOOT, 0, genesis, 1));
    let last = trusted.len() - 32;
    let (_, tail) = forged.split_at_mut(last);
    tail.copy_from_slice(&trusted[last..]);
    assert!(AuditVerifier::from_checkpoint(&forged, key()).is_ok());
}

#[test]
fn stale_and_future_relay_generations_fail_closed() {
    let genesis = AuditVerifier::genesis(BOOT, key()).unwrap().root();
    let start = checkpoint_wire(BOOT, 0, genesis, 1, sealed_tag(BOOT, 0, genesis, 1));
    let mut verifier = AuditVerifier::from_checkpoint(&start, key()).unwrap();
    let frame = body(BOOT, 1, 1, Object::None, 0, &[], Some(genesis));
    let root1 = expected_root(genesis, 1, &frame);
    verifier.fold(&frame, root1).unwrap();

    let resync = checkpoint_wire(BOOT, 1, root1, 2, sealed_tag(BOOT, 1, root1, 2));
    assert_eq!(verifier.accept_resync_checkpoint(&resync), Ok(()));
    let stale = checkpoint_wire(BOOT, 1, root1, 1, sealed_tag(BOOT, 1, root1, 1));
    assert_eq!(
        verifier.accept_checkpoint(&stale),
        Err(VerifyFailure::StaleRelayGeneration)
    );
    let future = checkpoint_wire(BOOT, 1, root1, 4, sealed_tag(BOOT, 1, root1, 4));
    assert_eq!(
        verifier.accept_resync_checkpoint(&future),
        Err(VerifyFailure::CheckpointMismatch)
    );
}

#[test]
fn max_checkpoint_sequence_is_typed_fail_closed() {
    let genesis = AuditVerifier::genesis(BOOT, key()).unwrap().root();
    let checkpoint = checkpoint_wire(
        BOOT,
        u64::MAX,
        genesis,
        1,
        sealed_tag(BOOT, u64::MAX, genesis, 1),
    );
    assert!(matches!(
        AuditVerifier::from_checkpoint(&checkpoint, key()),
        Err(VerifyFailure::SequenceOverflow)
    ));
}

#[test]
fn zero_boot_genesis_is_rejected() {
    assert!(matches!(
        AuditVerifier::genesis([0; 16], key()),
        Err(VerifyFailure::Malformed)
    ));
}
