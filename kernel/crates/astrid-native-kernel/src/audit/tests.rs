//! Kernel/harness-private regressions for the #1759 audit freeze.

use super::*;
use crate::ipc::DomainToken;
use blake3::Hasher;

fn boot() -> BootSessionId {
    BootSessionId::new([7; 16]).unwrap()
}

fn auth_key() -> CheckpointAuthKey {
    CheckpointAuthKey::new([0x5a; 32]).unwrap()
}

fn subject(slot: u64, generation: u64) -> AuditSubject {
    AuditSubject::from_domain(DomainToken::new(slot, generation).unwrap())
}

fn domain_event(class: AuditClass) -> AuditEvent {
    AuditEvent::new(class, subject(0, 1))
}

fn capability_object(
    projection_token: u64,
    slot: usize,
    generation: u64,
    object_token: u64,
) -> AuditObject {
    AuditObject::capability_instance(
        projection_token,
        slot,
        generation,
        AuditObjectKind::Endpoint,
        object_token,
    )
    .unwrap()
}

struct FrameBuf {
    bytes: [u8; MAX_FRAME_BYTES],
    len: usize,
}

impl FrameBuf {
    fn new(encoded: &[u8]) -> Self {
        let mut bytes = [0; MAX_FRAME_BYTES];
        bytes[..encoded.len()].copy_from_slice(encoded);
        Self {
            bytes,
            len: encoded.len(),
        }
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

fn encode_frame(
    chain_boot: BootSessionId,
    seq: u64,
    event: &AuditEvent,
    prev: Option<[u8; 32]>,
) -> FrameBuf {
    let frame = Frame::new(chain_boot, seq, event, prev).unwrap();
    let mut buf = [0; MAX_FRAME_BYTES];
    FrameBuf::new(frame.encode(&mut buf).unwrap())
}

fn host_key() -> native_audit_verifier::CheckpointKey {
    native_audit_verifier::CheckpointKey::new(auth_key().bytes()).unwrap()
}

fn verifier() -> native_audit_verifier::AuditVerifier {
    native_audit_verifier::AuditVerifier::genesis(boot().bytes(), host_key()).unwrap()
}

#[test]
fn roundtrip_and_injectivity() {
    let chain_boot = boot();
    let genesis = root::genesis(chain_boot);
    let cases = [
        domain_event(AuditClass::DomainCreate),
        domain_event(AuditClass::IpcSend)
            .with_object(AuditObject::endpoint(2, 5).unwrap())
            .unwrap(),
        domain_event(AuditClass::CapabilityDerive)
            .with_object(capability_object(9, 3, 4, 11))
            .unwrap()
            .with_rights(AuditRights::from_bits(0b0101).unwrap()),
        AuditEvent::denial(
            subject(1, 2),
            DenialContext::new(DenialReason::ForeignObject, [1; 8]),
        ),
        domain_event(AuditClass::RootCheckpoint)
            .with_payload(&[0xAA; 64])
            .unwrap(),
    ];
    let encoded = [
        encode_frame(chain_boot, 1, &cases[0], Some(genesis)),
        encode_frame(chain_boot, 1, &cases[1], Some(genesis)),
        encode_frame(chain_boot, 1, &cases[2], Some(genesis)),
        encode_frame(chain_boot, 1, &cases[3], Some(genesis)),
        encode_frame(chain_boot, 1, &cases[4], Some(genesis)),
    ];
    for bytes in &encoded {
        let decoded = decode(bytes.as_slice()).unwrap();
        let mut reencoded_buf = [0; MAX_FRAME_BYTES];
        let reencoded = decoded.encode(&mut reencoded_buf).unwrap();
        assert_eq!(reencoded, bytes.as_slice());
    }
    for left in 0..encoded.len() {
        for right in (left + 1)..encoded.len() {
            assert_ne!(encoded[left].as_slice(), encoded[right].as_slice());
        }
    }
}

#[test]
fn rejects_malformed_non_canonical_and_disclosing_inputs() {
    let chain_boot = boot();
    let event = domain_event(AuditClass::DomainAdmit)
        .with_object(capability_object(1, 0, 1, 1))
        .unwrap();
    let valid = encode_frame(chain_boot, 1, &event, Some(root::genesis(chain_boot)));

    let truncated = &valid.as_slice()[..valid.len - 1];
    assert!(matches!(decode(truncated), Err(AuditError::MalformedFrame)));

    let mut slack = [0u8; MAX_FRAME_BYTES + 1];
    slack[..valid.len].copy_from_slice(valid.as_slice());
    assert!(matches!(
        decode(&slack[..=valid.len]),
        Err(AuditError::MalformedFrame)
    ));

    let mut bad_class = FrameBuf::new(valid.as_slice());
    let class_index = 4 + 2 + 16 + 8;
    bad_class.bytes[class_index] = 0;
    bad_class.bytes[class_index + 1] = 99;
    assert!(matches!(
        decode(bad_class.as_slice()),
        Err(AuditError::MalformedFrame)
    ));

    let denial = encode_frame(
        chain_boot,
        1,
        &AuditEvent::denial(
            subject(0, 1),
            DenialContext::new(DenialReason::StaleIdentity, [0; 8]),
        ),
        Some(root::genesis(chain_boot)),
    );
    assert!(matches!(
        decode(denial.as_slice()),
        Ok(frame) if frame.class() == AuditClass::BoundedDenial && frame.object().is_none()
    ));

    let denial_event = AuditEvent::new(AuditClass::BoundedDenial, subject(0, 1));
    assert!(
        denial_event
            .with_object(capability_object(1, 0, 1, 1))
            .is_none()
    );
    assert!(AuditObject::capability_instance(1, 0, 1, AuditObjectKind::Domain, 1).is_none());
}

#[test]
fn append_folds_with_mandatory_source_root() {
    let chain_boot = boot();
    let mut chain = AuditChain::genesis(chain_boot, auth_key());
    let mut host_verifier = verifier();

    for expected_seq in 1u64..=5 {
        let class = match expected_seq {
            1 => AuditClass::DomainCreate,
            2 => AuditClass::CapabilityDerive,
            3 => AuditClass::IpcSend,
            4 => AuditClass::GenerationAdvance,
            _ => AuditClass::DomainReclaim,
        };
        let event = domain_event(class)
            .with_object(capability_object(expected_seq, 1, 2, 3))
            .unwrap();
        let seq = chain.append(event).unwrap();
        assert_eq!(seq, expected_seq);

        chain.relay_mut().grant_credits(1).unwrap();
        let record = chain.relay_mut().take().unwrap();
        let receipt = host_verifier.fold(record.frame(), record.root()).unwrap();
        assert_eq!(receipt.seq(), seq);
        assert_eq!(host_verifier.root(), *chain.root());
    }
}

#[test]
fn tamper_is_invalid_gap_is_incomplete_duplicate_is_invalid() {
    let chain_boot = boot();
    let mut chain = AuditChain::genesis(chain_boot, auth_key());
    for class in [
        AuditClass::DomainCreate,
        AuditClass::DomainAdmit,
        AuditClass::DomainStart,
    ] {
        chain.append(domain_event(class)).unwrap();
    }
    let mut records = [FrameBuf::new(&[]), FrameBuf::new(&[]), FrameBuf::new(&[])];
    let mut roots = [[0; 32]; 3];
    {
        chain.relay_mut().grant_credits(3).unwrap();
        let mut count = 0;
        while let Some(record) = chain.relay_mut().take() {
            records[count] = FrameBuf::new(record.frame());
            roots[count] = record.root();
            count += 1;
        }
        assert_eq!(count, 3);
    }

    let mut host_verifier = verifier();
    let mut tampered = FrameBuf::new(records[0].as_slice());
    let last = tampered.len - 1;
    tampered.bytes[last] ^= 0xFF;
    assert!(matches!(
        host_verifier.fold(tampered.as_slice(), roots[0]),
        Err(native_audit_verifier::FoldFailure::Invalid(_))
    ));

    let mut host_verifier = verifier();
    host_verifier.fold(records[0].as_slice(), roots[0]).unwrap();
    assert!(matches!(
        host_verifier.fold(records[2].as_slice(), roots[2]),
        Err(native_audit_verifier::FoldFailure::Incomplete(
            native_audit_verifier::IncompleteReason::SequenceGap
        ))
    ));

    let mut host_verifier = verifier();
    host_verifier.fold(records[0].as_slice(), roots[0]).unwrap();
    assert!(matches!(
        host_verifier.fold(records[0].as_slice(), roots[0]),
        Err(native_audit_verifier::FoldFailure::Invalid(
            native_audit_verifier::InvalidReason::DuplicateOrReorder
        ))
    ));
}

#[test]
fn foreign_boot_and_missing_previous_root_are_invalid() {
    let chain_boot = boot();
    let mut chain = AuditChain::genesis(chain_boot, auth_key());
    chain
        .append(domain_event(AuditClass::DomainCreate))
        .unwrap();
    let mut foreign = native_audit_verifier::AuditVerifier::genesis([8; 16], host_key()).unwrap();
    chain.relay_mut().grant_credits(1).unwrap();
    let record = chain.relay_mut().take().unwrap();
    assert!(matches!(
        foreign.fold(record.frame(), record.root()),
        Err(native_audit_verifier::FoldFailure::Invalid(
            native_audit_verifier::InvalidReason::ForeignBoot
        ))
    ));

    let mut host_verifier = verifier();
    let event = domain_event(AuditClass::DomainCreate);
    let frame = Frame::new(chain_boot, 1, &event, None).unwrap();
    let mut buf = [0; MAX_FRAME_BYTES];
    let encoded = frame.encode(&mut buf).unwrap();
    let expected = root::advance(root::genesis(chain_boot), chain_boot, 1, encoded);
    assert!(matches!(
        host_verifier.fold(encoded, expected),
        Err(native_audit_verifier::FoldFailure::Invalid(
            native_audit_verifier::InvalidReason::PreviousRootMismatch
        ))
    ));
}

#[test]
fn sequence_overflow_fails_closed_without_commit() {
    let chain_boot = boot();
    let checkpoint =
        AuditCheckpoint::seal(chain_boot, u64::MAX - 1, [9; 32], 1, auth_key()).unwrap();
    let mut chain = AuditChain::restore(checkpoint, auth_key()).unwrap();
    let before = (chain.seq(), *chain.root());
    assert_eq!(
        chain.append(domain_event(AuditClass::DomainCreate)),
        Err(AuditError::SequenceOverflow)
    );
    assert_eq!((chain.seq(), *chain.root()), before);
}

#[test]
fn ack_requires_take_in_flight_and_matching_folded_root() {
    let chain_boot = boot();
    let mut chain = AuditChain::genesis(chain_boot, auth_key());
    let mut host_verifier = verifier();
    chain
        .append(domain_event(AuditClass::DomainCreate))
        .unwrap();
    chain.append(domain_event(AuditClass::DomainAdmit)).unwrap();

    chain.relay_mut().grant_credits(1).unwrap();
    let first = chain.relay_mut().take().unwrap();
    assert_eq!(chain.relay().redeliver().count(), 2);
    let first_receipt = host_verifier.fold(first.frame(), first.root()).unwrap();
    assert_eq!(
        chain
            .relay_mut()
            .ack(first.seq(), first.root(), [0; 32], auth_key()),
        Err(AuditError::RootMismatch)
    );
    chain
        .relay_mut()
        .ack(
            first.seq(),
            first_receipt.folded_root(),
            first_receipt.ack_tag(),
            auth_key(),
        )
        .unwrap();

    assert_eq!(
        chain.relay_mut().ack(
            first.seq(),
            first_receipt.folded_root(),
            first_receipt.ack_tag(),
            auth_key()
        ),
        Err(AuditError::RelayStaleCursor)
    );
    chain.relay_mut().grant_credits(1).unwrap();
    let second = chain.relay_mut().take().unwrap();
    let second_receipt = host_verifier.fold(second.frame(), second.root()).unwrap();
    chain
        .relay_mut()
        .ack(
            second.seq(),
            second_receipt.folded_root(),
            second_receipt.ack_tag(),
            auth_key(),
        )
        .unwrap();
}

#[test]
fn ack_before_take_does_not_retire_a_buffered_slot() {
    let chain_boot = boot();
    let mut chain = AuditChain::genesis(chain_boot, auth_key());
    chain
        .append(domain_event(AuditClass::DomainCreate))
        .unwrap();
    let before = chain.relay().redeliver().count();
    assert_eq!(before, 1);
    assert_eq!(
        chain.relay_mut().ack(1, [0; 32], [0; 32], auth_key()),
        Err(AuditError::RelayNotInFlight)
    );
    assert_eq!(chain.relay().redeliver().count(), before);
    chain.relay_mut().grant_credits(1).unwrap();
    assert!(chain.relay_mut().take().is_some());
}

#[test]
fn restored_checkpoint_preserves_trusted_relay_generation() {
    let chain_boot = boot();
    let mut chain = AuditChain::genesis(chain_boot, auth_key());
    for _ in 0..AUDIT_RELAY_SLOTS {
        chain
            .append(domain_event(AuditClass::DomainReclaim))
            .unwrap();
    }
    let current_root = *chain.root();
    let current_seq = chain.seq();
    let checkpoint = chain
        .relay_mut()
        .resync(current_root, current_seq, auth_key())
        .unwrap();
    assert_eq!(checkpoint.relay_generation(), 2);

    let restored = AuditChain::restore(checkpoint, auth_key()).unwrap();
    assert_eq!(restored.boot(), checkpoint.boot());
    assert_eq!(restored.seq(), checkpoint.seq());
    assert_eq!(*restored.root(), checkpoint.root());
    assert_eq!(restored.relay().generation(), 2);
    assert!(restored.relay().redeliver().next().is_none());
}

#[test]
fn reserved_headroom_and_overflow_fail_before_atomic_commit() {
    let chain_boot = boot();
    let mut chain = AuditChain::genesis(chain_boot, auth_key());
    for _ in 0..(AUDIT_RELAY_SLOTS - MAX_TERMINAL_RECORDS_PER_BATCH) {
        chain.append(domain_event(AuditClass::DomainEnter)).unwrap();
    }
    assert_eq!(chain.seq(), 35);

    let before = (
        chain.seq(),
        *chain.root(),
        chain.relay().redeliver().count(),
    );
    assert_eq!(
        chain.append(domain_event(AuditClass::DomainEnter)),
        Err(AuditError::HandoffIncomplete)
    );
    assert_eq!(
        (
            chain.seq(),
            *chain.root(),
            chain.relay().redeliver().count()
        ),
        before
    );

    for expected_seq in 36u64..=(AUDIT_RELAY_SLOTS as u64) {
        let seq = chain
            .append(domain_event(AuditClass::DomainReclaim))
            .unwrap();
        assert_eq!(seq, expected_seq);
    }
    let full = (
        chain.seq(),
        *chain.root(),
        chain.relay().redeliver().count(),
    );
    assert_eq!(
        chain.append(domain_event(AuditClass::DomainReclaim)),
        Err(AuditError::HandoffIncomplete)
    );
    assert_eq!(
        (
            chain.seq(),
            *chain.root(),
            chain.relay().redeliver().count()
        ),
        full
    );
    assert_eq!(chain.relay().redeliver().count(), AUDIT_RELAY_SLOTS);
}

#[test]
fn verifier_sequence_overflow_is_atomic_and_repeatable() {
    let checkpoint = AuditCheckpoint::seal(boot(), u64::MAX - 1, [9; 32], 1, auth_key()).unwrap();
    let mut wire = [0; native_audit_verifier::CHECKPOINT_WIRE_BYTES];
    let bytes = encode_checkpoint(&checkpoint, auth_key(), &mut wire).unwrap();
    let mut verifier =
        native_audit_verifier::AuditVerifier::from_checkpoint(bytes, host_key()).unwrap();
    let before = (verifier.next_seq(), verifier.root());
    let event = domain_event(AuditClass::DomainCreate);
    let frame = Frame::new(boot(), u64::MAX, &event, Some([9; 32])).unwrap();
    let mut buf = [0; MAX_FRAME_BYTES];
    let encoded = frame.encode(&mut buf).unwrap();
    let claimed = root::advance([9; 32], boot(), u64::MAX, encoded);
    assert_eq!(
        verifier.fold(encoded, claimed),
        Err(native_audit_verifier::FoldFailure::SequenceOverflow)
    );
    assert_eq!(
        verifier.fold(encoded, claimed),
        Err(native_audit_verifier::FoldFailure::SequenceOverflow)
    );
    assert_eq!((verifier.next_seq(), verifier.root()), before);
}

#[test]
fn explicitly_mismatched_previous_root_is_invalid() {
    let chain_boot = boot();
    let wrong_previous = [0xAA; 32];
    let event = domain_event(AuditClass::DomainCreate);
    let frame = Frame::new(chain_boot, 1, &event, Some(wrong_previous)).unwrap();
    let mut buf = [0; MAX_FRAME_BYTES];
    let encoded = frame.encode(&mut buf).unwrap();
    let claimed = root::advance(wrong_previous, chain_boot, 1, encoded);
    let mut host_verifier = verifier();
    assert!(matches!(
        host_verifier.fold(encoded, claimed),
        Err(native_audit_verifier::FoldFailure::Invalid(
            native_audit_verifier::InvalidReason::PreviousRootMismatch
        ))
    ));
}

#[test]
fn kernel_and_verifier_reject_zero_relay_generation() {
    let chain_boot = boot();
    let chain = AuditChain::genesis(chain_boot, auth_key());
    let seq = chain.seq();
    let root = *chain.root();
    let mut wire = [0; native_audit_verifier::CHECKPOINT_WIRE_BYTES];
    encode_checkpoint(&chain.checkpoint(), auth_key(), &mut wire).unwrap();
    let generation_offset = 4 + 2 + 16 + 8 + 32;
    wire[generation_offset..generation_offset + 8].copy_from_slice(&0u64.to_le_bytes());
    let zero_tag = root::checkpoint_tag(chain_boot, seq, root, 0, auth_key());
    let tag_offset = native_audit_verifier::CHECKPOINT_WIRE_BYTES - 32;
    wire[tag_offset..].copy_from_slice(&zero_tag);

    assert_eq!(
        decode_checkpoint(&wire, auth_key()),
        Err(AuditError::MalformedFrame)
    );
    assert_eq!(
        native_audit_verifier::verify_checkpoint(&wire, host_key()),
        Err(native_audit_verifier::VerifyFailure::Malformed)
    );
    assert_eq!(
        AuditCheckpoint::seal(chain_boot, seq, root, 0, auth_key()),
        Err(AuditError::MalformedFrame)
    );
}

#[test]
fn resync_is_generation_bound_and_restores_flow() {
    let chain_boot = boot();
    let mut chain = AuditChain::genesis(chain_boot, auth_key());
    for _ in 0..AUDIT_RELAY_SLOTS {
        chain
            .append(domain_event(AuditClass::DomainReclaim))
            .unwrap();
    }
    let current_root = *chain.root();
    let current_seq = chain.seq();
    let checkpoint = chain
        .relay_mut()
        .resync(current_root, current_seq, auth_key())
        .unwrap();
    assert_eq!(checkpoint.relay_generation(), 2);

    let mut wire = [0; native_audit_verifier::CHECKPOINT_WIRE_BYTES];
    let bytes = encode_checkpoint(&checkpoint, auth_key(), &mut wire).unwrap();
    let mut host_verifier =
        native_audit_verifier::AuditVerifier::from_checkpoint(bytes, host_key()).unwrap();
    assert_eq!(host_verifier.root(), *chain.root());

    let seq = chain.append(domain_event(AuditClass::DomainEnter)).unwrap();
    chain.relay_mut().grant_credits(1).unwrap();
    let record = chain.relay_mut().take().unwrap();
    assert_eq!(record.seq(), seq);
    let receipt = host_verifier.fold(record.frame(), record.root()).unwrap();
    assert_eq!(receipt.seq(), seq);
}

#[test]
fn checkpoint_is_kernel_authenticated_and_state_bound() {
    let chain_boot = boot();
    let mut chain = AuditChain::genesis(chain_boot, auth_key());
    chain
        .append(domain_event(AuditClass::DomainCreate))
        .unwrap();
    let checkpoint = chain.checkpoint();
    assert!(checkpoint.verify_tag(auth_key()));

    let mut wire = [0; native_audit_verifier::CHECKPOINT_WIRE_BYTES];
    let bytes = encode_checkpoint(&checkpoint, auth_key(), &mut wire).unwrap();
    assert!(native_audit_verifier::AuditVerifier::from_checkpoint(bytes, host_key()).is_ok());

    // Replace the sealed tag with the rejected verifier-local unkeyed tag.
    let mut unkeyed = [0; native_audit_verifier::CHECKPOINT_WIRE_BYTES];
    unkeyed.copy_from_slice(bytes);
    let mut hasher = Hasher::new();
    hasher.update(root::CHECKPOINT_DOMAIN_TAG);
    hasher.update(&super::CODEC_VERSION.to_le_bytes());
    hasher.update(&checkpoint.boot().bytes());
    hasher.update(&checkpoint.seq().to_le_bytes());
    hasher.update(&checkpoint.root());
    hasher.update(&checkpoint.relay_generation().to_le_bytes());
    let unkeyed_tag: [u8; 32] = hasher.finalize().into();
    let tag_start = native_audit_verifier::CHECKPOINT_WIRE_BYTES - root::ROOT_LEN;
    unkeyed[tag_start..].copy_from_slice(&unkeyed_tag);
    assert_eq!(
        native_audit_verifier::verify_checkpoint(&unkeyed, host_key()),
        Err(native_audit_verifier::VerifyFailure::CheckpointMismatch)
    );
    assert_eq!(
        decode_checkpoint(&unkeyed, auth_key()),
        Err(AuditError::CheckpointMismatch)
    );
    assert_eq!(decode_checkpoint(bytes, auth_key()).unwrap(), checkpoint);
}

#[test]
fn batch_reserve_is_static_and_inside_the_window() {
    assert_eq!(MAX_TERMINAL_RECORDS_PER_BATCH, 29);
    assert!(AUDIT_RELAY_SLOTS >= MAX_TERMINAL_RECORDS_PER_BATCH);
}
