//! Independent regressions for the frozen wire format and fold engine.

use super::*;
use blake3::Hasher;

const BOOT: [u8; 16] = [7; 16];

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
    framed.extend_from_slice(&((out.len()) as u32).to_le_bytes());
    framed.extend_from_slice(&out);
    framed
}

fn root_tag_bytes() -> Vec<u8> {
    let mut prefix = Vec::new();
    prefix.extend_from_slice(b"astrid.native-kernel.audit-root.v1");
    prefix.extend_from_slice(b"BLAKE3-256");
    prefix.extend_from_slice(&CODEC_VERSION.to_le_bytes());
    prefix
}

fn expected_root(previous: [u8; 32], seq: u64, frame: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(&root_tag_bytes());
    hasher.update(&BOOT);
    hasher.update(&seq.to_le_bytes());
    hasher.update(&previous);
    hasher.update(frame);
    hasher.finalize().into()
}

#[test]
fn genesis_then_fold_matches_source_roots() {
    let mut verifier = AuditVerifier::genesis(BOOT).unwrap();
    let genesis = verifier.root();

    let frame1 = body(BOOT, 1, 1, Object::None, 0, &[], None);
    let root1 = expected_root(genesis, 1, &frame1);
    assert_eq!(verifier.fold_with_root(&frame1, Some(root1)).unwrap(), 1);

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
    assert_eq!(verifier.fold_with_root(&frame2, Some(root2)).unwrap(), 2);
    assert_eq!(verifier.root(), root2);
}

#[test]
fn claimed_root_mismatch_is_invalid() {
    let mut verifier = AuditVerifier::genesis(BOOT).unwrap();
    let frame = body(BOOT, 1, 1, Object::None, 0, &[], None);
    let mut wrong = verifier.root();
    wrong[0] ^= 1;
    assert_eq!(
        verifier.fold_with_root(&frame, Some(wrong)),
        Err(FoldFailure::Invalid(InvalidReason::RootMismatch))
    );
}

#[test]
fn gap_is_incomplete_and_duplicate_is_invalid() {
    let mut verifier = AuditVerifier::genesis(BOOT).unwrap();
    let frame1 = body(BOOT, 1, 1, Object::None, 0, &[], None);
    let frame3 = body(BOOT, 3, 3, Object::None, 0, &[], None);
    verifier.fold(&frame1).unwrap();
    assert_eq!(
        verifier.fold(&frame3),
        Err(FoldFailure::Incomplete(IncompleteReason::SequenceGap))
    );
    assert_eq!(
        verifier.fold(&frame1),
        Err(FoldFailure::Invalid(InvalidReason::DuplicateOrReorder))
    );
}

#[test]
fn denial_must_not_disclose_a_foreign_identity() {
    let mut verifier = AuditVerifier::genesis(BOOT).unwrap();
    let mut payload = vec![4, 0];
    payload.extend_from_slice(&[9; 8]);
    let denial = body(BOOT, 1, 80, Object::None, 0, &payload, None);
    assert!(verifier.fold(&denial).is_ok());

    let mut verifier = AuditVerifier::genesis(BOOT).unwrap();
    let disclosing = body(BOOT, 1, 80, Object::Domain(1, 3), 0, &payload, None);
    assert_eq!(
        verifier.fold(&disclosing),
        Err(FoldFailure::Invalid(InvalidReason::DenialDisclosure))
    );
}

#[test]
fn non_canonical_inputs_fail_closed() {
    let valid = body(BOOT, 1, 1, Object::None, 0, &[], None);
    let mut verifier = AuditVerifier::genesis(BOOT).unwrap();

    assert!(matches!(
        verifier.fold(&valid[..valid.len() - 1]),
        Err(FoldFailure::Invalid(InvalidReason::Malformed))
    ));
    let mut slack = valid.clone();
    slack.push(0);
    assert!(matches!(
        verifier.fold(&slack),
        Err(FoldFailure::Invalid(InvalidReason::Malformed))
    ));

    let cases = [
        body([0; 16], 1, 1, Object::None, 0, &[], None),
        body(BOOT, 0, 1, Object::None, 0, &[], None),
        body(BOOT, 1, 10, Object::None, 0, &[], None),
        body(BOOT, 1, 1, Object::Domain(2, 1), 0, &[], None),
        body(BOOT, 1, 1, Object::Domain(1, 0), 0, &[], None),
        body(BOOT, 1, 1, Object::Endpoint(4, 1), 0, &[], None),
        body(BOOT, 1, 1, Object::Capability(0, 1, 1, 1, 1), 0, &[], None),
        body(BOOT, 1, 1, Object::Capability(1, 8, 1, 1, 1), 0, &[], None),
        body(BOOT, 1, 1, Object::Capability(1, 1, 1, 7, 1), 0, &[], None),
        body(BOOT, 1, 1, Object::None, 0x10, &[], None),
        body(BOOT, 1, 1, Object::None, 0, &[0; 65], None),
    ];
    for case in cases {
        let mut verifier = AuditVerifier::genesis(BOOT).unwrap();
        assert!(matches!(
            verifier.fold(&case),
            Err(FoldFailure::Invalid(InvalidReason::Malformed))
        ));
    }

    let mut bad_version = valid.clone();
    bad_version[4..6].copy_from_slice(&2u16.to_le_bytes());
    assert!(matches!(
        verifier.fold(&bad_version),
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

fn tag_for(boot: [u8; 16], seq: u64, root: [u8; 32], relay_generation: u64) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"astrid.native-kernel.audit-checkpoint.v1");
    hasher.update(&CODEC_VERSION.to_le_bytes());
    hasher.update(&boot);
    hasher.update(&seq.to_le_bytes());
    hasher.update(&root);
    hasher.update(&relay_generation.to_le_bytes());
    hasher.finalize().into()
}

#[test]
fn checkpoint_restart_and_source_root_match() {
    let genesis = AuditVerifier::genesis(BOOT).unwrap().root();
    let start = checkpoint_wire(BOOT, 0, genesis, 1, tag_for(BOOT, 0, genesis, 1));
    let mut verifier = AuditVerifier::from_checkpoint(&start).unwrap();
    assert_eq!(verifier.root(), genesis);

    let frame = body(BOOT, 1, 1, Object::None, 0, &[], Some(genesis));
    let root1 = expected_root(genesis, 1, &frame);
    verifier.fold_with_root(&frame, Some(root1)).unwrap();

    let next = checkpoint_wire(BOOT, 1, root1, 1, tag_for(BOOT, 1, root1, 1));
    assert_eq!(verifier.accept_checkpoint(&next), Ok(()));

    let mut tampered = next.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(matches!(
        AuditVerifier::from_checkpoint(&tampered),
        Err(VerifyFailure::CheckpointMismatch)
    ));
    assert_eq!(
        verifier.accept_checkpoint(&tampered),
        Err(VerifyFailure::CheckpointMismatch)
    );

    let mut wrong_root = root1;
    wrong_root[0] ^= 1;
    let mismatched = checkpoint_wire(BOOT, 1, wrong_root, 1, tag_for(BOOT, 1, wrong_root, 1));
    assert_eq!(
        verifier.accept_checkpoint(&mismatched),
        Err(VerifyFailure::CheckpointMismatch)
    );
}

#[test]
fn zero_boot_genesis_is_rejected() {
    assert!(matches!(
        AuditVerifier::genesis([0; 16]),
        Err(VerifyFailure::Malformed)
    ));
}
