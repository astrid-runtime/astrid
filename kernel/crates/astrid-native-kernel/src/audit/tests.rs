//! Kernel/harness-private regressions for the #1759 audit freeze.

use super::*;
use crate::ipc::DomainToken;
use blake3::Hasher;

fn boot() -> BootSessionId {
    BootSessionId::new([7; 16]).unwrap()
}

fn secret() -> KernelSecretEntropy {
    KernelSecretEntropy::new([0x5A; 32]).unwrap()
}

fn authority() -> AuditAuthority {
    AuditAuthority::mint(boot(), secret()).unwrap()
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

/// Models the independently trusted kernel-origin anchor channel: the
/// kernel's live context is injected into the verifier directly, never
/// through the untrusted handoff.
fn anchor_of(live: &AuditAuthority) -> native_audit_verifier::AuthContext {
    native_audit_verifier::AuthContext::from_trusted_anchor(
        live.context().authority_id(),
        live.boot().bytes(),
        *live.context().verification_key().bytes(),
    )
    .unwrap()
}

fn foreign(boot_byte: u8) -> AuditAuthority {
    AuditAuthority::mint(BootSessionId::new([boot_byte; 16]).unwrap(), secret()).unwrap()
}

fn host_context() -> native_audit_verifier::AuthContext {
    anchor_of(&authority())
}

fn host_handoff() -> [u8; native_audit_verifier::AUTHORITY_HANDOFF_BYTES] {
    authority().verifier_handoff()
}

fn verifier() -> native_audit_verifier::AuditVerifier {
    native_audit_verifier::AuditVerifier::genesis(boot().bytes(), host_context(), &host_handoff())
        .unwrap()
}

fn genesis_chain(chain_boot: BootSessionId) -> AuditChain {
    AuditChain::genesis(chain_boot, secret()).unwrap()
}

fn test_root_hasher() -> root::RootHasher {
    root::RootHasher::new()
}

fn attacker_handoff_tag(boot: BootSessionId, authority_id: u64, key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Hasher::new_keyed(key);
    hasher.update(root::VERIFIER_HANDOFF_DOMAIN_TAG);
    hasher.update(&super::CODEC_VERSION.to_le_bytes());
    hasher.update(&boot.bytes());
    hasher.update(&authority_id.to_le_bytes());
    hasher.finalize().into()
}

#[test]
fn roundtrip_and_injectivity() {
    let chain_boot = boot();
    let root_hasher = test_root_hasher();
    let genesis = root_hasher.genesis(chain_boot);
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
    let root_hasher = test_root_hasher();
    let genesis = root_hasher.genesis(chain_boot);
    let valid = encode_frame(chain_boot, 1, &event, Some(genesis));

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
        Some(genesis),
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
    let mut chain = genesis_chain(chain_boot);
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
    let mut chain = genesis_chain(chain_boot);
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
    let mut chain = genesis_chain(chain_boot);
    chain
        .append(domain_event(AuditClass::DomainCreate))
        .unwrap();
    let foreign_authority = foreign(8);
    let mut foreign = native_audit_verifier::AuditVerifier::genesis(
        [8; 16],
        anchor_of(&foreign_authority),
        &foreign_authority.verifier_handoff(),
    )
    .unwrap();
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
    let root_hasher = test_root_hasher();
    let genesis = root_hasher.genesis(chain_boot);
    let expected = root_hasher.advance(genesis, chain_boot, 1, encoded);
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
        AuditCheckpoint::seal(chain_boot, u64::MAX - 1, [9; 32], 1, authority().context()).unwrap();
    let mut chain = AuditChain::restore(checkpoint, authority()).unwrap();
    let before = (chain.seq(), *chain.root());
    assert_eq!(
        chain.append(domain_event(AuditClass::DomainCreate)),
        Err(AuditError::SequenceOverflow)
    );
    assert_eq!((chain.seq(), *chain.root()), before);
}

#[test]
fn foreign_boot_checkpoint_cannot_use_live_context() {
    let foreign_boot = BootSessionId::new([0x2A; 16]).unwrap();
    assert_eq!(
        AuditCheckpoint::seal(foreign_boot, 1, [3; 32], 1, authority().context()),
        Err(AuditError::CheckpointMismatch)
    );
}

#[test]
fn immediate_retirement_rejects_retained_relay_evidence() {
    let chain_boot = boot();
    let mut chain = genesis_chain(chain_boot);
    let mut host_verifier = verifier();

    chain
        .append(domain_event(AuditClass::DomainCreate))
        .unwrap();
    let before = (chain.seq(), *chain.root());
    let verifier_before = (host_verifier.next_seq(), host_verifier.root());

    let folded = chain.append_verified(&domain_event(AuditClass::DomainAdmit), &mut host_verifier);
    assert_eq!(folded, Err(AuditError::RelayMixedMode));
    assert_eq!((chain.seq(), *chain.root()), before);
    assert_eq!(chain.relay().redeliver().count(), 1);
    assert_eq!(
        (host_verifier.next_seq(), host_verifier.root()),
        verifier_before
    );
}

#[test]
fn verified_staging_failure_leaves_chain_untouched() {
    let chain_boot = boot();
    let mut chain = genesis_chain(chain_boot);
    let mut host_verifier = verifier();

    chain
        .append(domain_event(AuditClass::DomainCreate))
        .unwrap();
    chain.relay_mut().grant_credits(1).unwrap();
    let first = chain.relay_mut().take().unwrap();
    let first_receipt = host_verifier.fold(first.frame(), first.root()).unwrap();
    chain
        .ack(first.seq(), first.root(), first_receipt.ack_tag())
        .unwrap();
    let before = (chain.seq(), *chain.root());
    let verifier_before = (host_verifier.next_seq(), host_verifier.root());

    chain
        .prepare_verified(&domain_event(AuditClass::DomainAdmit))
        .unwrap();
    let folded = host_verifier.open_fold(chain.seq() + 1, chain.staged_frame(), &[0x12; 32]);
    assert!(matches!(
        folded,
        Err(native_audit_verifier::FoldFailure::Invalid(
            native_audit_verifier::InvalidReason::RootMismatch,
        ))
    ));
    drop(folded);
    assert_eq!((chain.seq(), *chain.root()), before);
    assert_eq!(chain.relay().redeliver().count(), 0);
    assert_eq!(
        (host_verifier.next_seq(), host_verifier.root()),
        verifier_before
    );
}

#[test]
fn transaction_receipt_commits_after_successful_relay_auth() {
    let chain_boot = boot();
    let mut chain = genesis_chain(chain_boot);
    let mut host_verifier = verifier();

    chain
        .prepare_verified(&domain_event(AuditClass::DomainAdmit))
        .unwrap();
    let observation = chain
        .retire_verified(
            host_verifier
                .open_fold(chain.seq() + 1, chain.staged_frame(), chain.staged_root())
                .unwrap(),
        )
        .unwrap();
    assert_eq!(observation.seq(), 1);
    assert_eq!((chain.seq(), *chain.root()), (1, *observation.root()));
    assert_eq!(host_verifier.next_seq(), 2);
}

#[test]
fn transaction_receipt_cannot_retire_a_different_staged_frame() {
    let chain_boot = boot();
    let mut chain = genesis_chain(chain_boot);
    let mut host_verifier = verifier();

    let before = (chain.seq(), *chain.root());
    let verifier_before = (host_verifier.next_seq(), host_verifier.root());
    chain
        .prepare_verified(&domain_event(AuditClass::DomainCreate))
        .unwrap();
    let transaction = host_verifier
        .open_fold(chain.seq() + 1, chain.staged_frame(), chain.staged_root())
        .unwrap();

    // Re-stage a different frame at the same sequence/root. The old
    // transaction receipt is still the only retirement input, but its keyed
    // authentication no longer matches the staged bytes.
    chain
        .prepare_verified(&domain_event(AuditClass::DomainAdmit))
        .unwrap();
    assert_eq!(
        chain.retire_verified(transaction),
        Err(AuditError::RootMismatch)
    );
    assert_eq!((chain.seq(), *chain.root()), before);
    assert_eq!(chain.relay().redeliver().count(), 0);
    assert_eq!(
        (host_verifier.next_seq(), host_verifier.root()),
        verifier_before
    );

    let observation = chain
        .append_verified(&domain_event(AuditClass::DomainCreate), &mut host_verifier)
        .unwrap();
    assert_eq!(observation.seq(), 1);
}

#[test]
fn ack_requires_take_in_flight_and_matching_folded_root() {
    let chain_boot = boot();
    let mut chain = genesis_chain(chain_boot);
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
        chain.ack(first.seq(), first.root(), [0; 32]),
        Err(AuditError::RootMismatch)
    );
    chain
        .ack(
            first.seq(),
            first_receipt.folded_root(),
            first_receipt.ack_tag(),
        )
        .unwrap();

    assert_eq!(
        chain.ack(
            first.seq(),
            first_receipt.folded_root(),
            first_receipt.ack_tag()
        ),
        Err(AuditError::RelayStaleCursor)
    );
    chain.relay_mut().grant_credits(1).unwrap();
    let second = chain.relay_mut().take().unwrap();
    let second_receipt = host_verifier.fold(second.frame(), second.root()).unwrap();
    chain
        .ack(
            second.seq(),
            second_receipt.folded_root(),
            second_receipt.ack_tag(),
        )
        .unwrap();
}

#[test]
fn ack_before_take_does_not_retire_a_buffered_slot() {
    let chain_boot = boot();
    let mut chain = genesis_chain(chain_boot);
    chain
        .append(domain_event(AuditClass::DomainCreate))
        .unwrap();
    let before = chain.relay().redeliver().count();
    assert_eq!(before, 1);
    assert_eq!(
        chain.ack(1, [0; 32], [0; 32]),
        Err(AuditError::RelayNotInFlight)
    );
    assert_eq!(chain.relay().redeliver().count(), before);
    chain.relay_mut().grant_credits(1).unwrap();
    assert!(chain.relay_mut().take().is_some());
}

#[test]
fn restored_checkpoint_preserves_trusted_relay_generation() {
    let chain_boot = boot();
    let mut chain = genesis_chain(chain_boot);
    for _ in 0..AUDIT_RELAY_SLOTS {
        chain
            .append(domain_event(AuditClass::DomainReclaim))
            .unwrap();
    }
    let checkpoint = chain.resync().unwrap();
    assert_eq!(checkpoint.relay_generation(), 2);

    let restored = AuditChain::restore(checkpoint, authority()).unwrap();
    assert_eq!(restored.boot(), checkpoint.boot());
    assert_eq!(restored.seq(), checkpoint.seq());
    assert_eq!(*restored.root(), checkpoint.root());
    assert_eq!(restored.relay().generation(), 2);
    assert!(restored.relay().redeliver().next().is_none());
}

#[test]
fn reserved_headroom_and_overflow_fail_before_atomic_commit() {
    let chain_boot = boot();
    let mut chain = genesis_chain(chain_boot);
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
    let checkpoint =
        AuditCheckpoint::seal(boot(), u64::MAX - 1, [9; 32], 1, authority().context()).unwrap();
    let mut wire = [0; native_audit_verifier::CHECKPOINT_WIRE_BYTES];
    let bytes = encode_checkpoint(&checkpoint, authority().context(), &mut wire).unwrap();
    let mut verifier = native_audit_verifier::AuditVerifier::from_checkpoint(
        bytes,
        host_context(),
        &host_handoff(),
    )
    .unwrap();
    let before = (verifier.next_seq(), verifier.root());
    let event = domain_event(AuditClass::DomainCreate);
    let frame = Frame::new(boot(), u64::MAX, &event, Some([9; 32])).unwrap();
    let mut buf = [0; MAX_FRAME_BYTES];
    let encoded = frame.encode(&mut buf).unwrap();
    let claimed = test_root_hasher().advance([9; 32], boot(), u64::MAX, encoded);
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
    let claimed = test_root_hasher().advance(wrong_previous, chain_boot, 1, encoded);
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
    let chain = genesis_chain(chain_boot);
    let seq = chain.seq();
    let root = *chain.root();
    let mut wire = [0; native_audit_verifier::CHECKPOINT_WIRE_BYTES];
    encode_checkpoint(&chain.checkpoint(), authority().context(), &mut wire).unwrap();
    let generation_offset = 4 + 2 + 16 + 8 + 32;
    wire[generation_offset..generation_offset + 8].copy_from_slice(&0u64.to_le_bytes());
    let zero_tag = authority()
        .context()
        .checkpoint_tag(chain_boot, seq, root, 0);
    let tag_offset = native_audit_verifier::CHECKPOINT_WIRE_BYTES - 32;
    wire[tag_offset..].copy_from_slice(&zero_tag);

    assert_eq!(
        decode_checkpoint(&wire, authority().context()),
        Err(AuditError::MalformedFrame)
    );
    assert_eq!(
        native_audit_verifier::verify_checkpoint(&wire, &host_context()),
        Err(native_audit_verifier::VerifyFailure::Malformed)
    );
    assert_eq!(
        AuditCheckpoint::seal(chain_boot, seq, root, 0, authority().context()),
        Err(AuditError::MalformedFrame)
    );
}

#[test]
fn resync_is_generation_bound_and_restores_flow() {
    let chain_boot = boot();
    let mut chain = genesis_chain(chain_boot);
    for _ in 0..AUDIT_RELAY_SLOTS {
        chain
            .append(domain_event(AuditClass::DomainReclaim))
            .unwrap();
    }
    let checkpoint = chain.resync().unwrap();
    assert_eq!(checkpoint.relay_generation(), 2);

    let mut wire = [0; native_audit_verifier::CHECKPOINT_WIRE_BYTES];
    let bytes = encode_checkpoint(&checkpoint, authority().context(), &mut wire).unwrap();
    let mut host_verifier = native_audit_verifier::AuditVerifier::from_checkpoint(
        bytes,
        host_context(),
        &host_handoff(),
    )
    .unwrap();
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
    let mut chain = genesis_chain(chain_boot);
    chain
        .append(domain_event(AuditClass::DomainCreate))
        .unwrap();
    let checkpoint = chain.checkpoint();
    assert!(checkpoint.verify_tag(authority().context()));

    let mut wire = [0; native_audit_verifier::CHECKPOINT_WIRE_BYTES];
    let bytes = encode_checkpoint(&checkpoint, authority().context(), &mut wire).unwrap();
    assert!(
        native_audit_verifier::AuditVerifier::from_checkpoint(
            bytes,
            host_context(),
            &host_handoff()
        )
        .is_ok()
    );

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
    hasher.update(&checkpoint.authority_id().to_le_bytes());
    let unkeyed_tag: [u8; 32] = hasher.finalize().into();
    let tag_start = native_audit_verifier::CHECKPOINT_WIRE_BYTES - root::ROOT_LEN;
    unkeyed[tag_start..].copy_from_slice(&unkeyed_tag);
    assert_eq!(
        native_audit_verifier::verify_checkpoint(&unkeyed, &host_context()),
        Err(native_audit_verifier::VerifyFailure::CheckpointMismatch)
    );
    assert_eq!(
        decode_checkpoint(&unkeyed, authority().context()),
        Err(AuditError::CheckpointMismatch)
    );
    assert_eq!(
        decode_checkpoint(bytes, authority().context()).unwrap(),
        checkpoint
    );
}

#[test]
fn foreign_or_arbitrary_context_cannot_authenticate_or_retire() {
    let chain_boot = boot();
    let mut chain = genesis_chain(chain_boot);
    chain
        .append(domain_event(AuditClass::DomainCreate))
        .unwrap();

    let mut wire = [0; native_audit_verifier::CHECKPOINT_WIRE_BYTES];
    let checkpoint_wire =
        encode_checkpoint(&chain.checkpoint(), authority().context(), &mut wire).unwrap();
    let arbitrary_handoff = [7; native_audit_verifier::AUTHORITY_HANDOFF_BYTES];
    assert_eq!(
        host_context().bind_handoff(&arbitrary_handoff),
        Err(native_audit_verifier::VerifyFailure::Malformed)
    );

    let foreign_authority = foreign(8);
    let foreign_context = anchor_of(&foreign_authority);
    let genesis_context = anchor_of(&foreign_authority);
    assert!(matches!(
        native_audit_verifier::AuditVerifier::genesis(
            chain_boot.bytes(),
            genesis_context,
            &foreign_authority.verifier_handoff()
        ),
        Err(native_audit_verifier::VerifyFailure::Malformed)
    ));
    assert_eq!(
        native_audit_verifier::verify_checkpoint(checkpoint_wire, &foreign_context),
        Err(native_audit_verifier::VerifyFailure::Malformed)
    );
    assert_eq!(
        decode_checkpoint(checkpoint_wire, foreign_authority.context()),
        Err(AuditError::CheckpointMismatch)
    );

    chain.relay_mut().grant_credits(1).unwrap();
    let record = chain.relay_mut().take().unwrap();
    assert_eq!(
        chain.ack(record.seq(), record.root(), [0; 32]),
        Err(AuditError::RootMismatch)
    );
    assert_eq!(chain.relay().redeliver().count(), 1);
}

#[test]
fn handoff_is_untrusted_binding_without_verification_material() {
    let live = authority();
    let key = live.context().verification_key().bytes();
    let handoff = live.verifier_handoff();

    assert_eq!(
        handoff.len(),
        native_audit_verifier::AUTHORITY_HANDOFF_BYTES
    );
    assert_eq!(&handoff[..8], b"ASAUDCTX");
    assert_eq!(
        u64::from_le_bytes(handoff[8..16].try_into().unwrap()),
        live.context().authority_id()
    );
    assert_eq!(&handoff[16..32], &boot().bytes());
    // The kernel verification key must not ride in any window of the
    // untrusted handoff.
    assert!(handoff.windows(32).all(|window| window != key));

    assert_eq!(host_context().bind_handoff(&handoff), Ok(()));
    assert!(
        native_audit_verifier::AuditVerifier::genesis(boot().bytes(), host_context(), &handoff)
            .is_ok()
    );
}

#[test]
fn structurally_valid_self_authenticated_handoff_is_rejected() {
    let chain_boot = boot();
    let live = authority();
    let attacker_key = [0xB0; 32];

    // Structurally valid: correct magic, the live authority id and boot,
    // and a tag the attacker computed under a self-chosen key.
    let mut forged = [0; native_audit_verifier::AUTHORITY_HANDOFF_BYTES];
    forged[..8].copy_from_slice(b"ASAUDCTX");
    forged[8..16].copy_from_slice(&live.context().authority_id().to_le_bytes());
    forged[16..32].copy_from_slice(&chain_boot.bytes());
    let attacker_tag =
        attacker_handoff_tag(chain_boot, live.context().authority_id(), &attacker_key);
    forged[32..].copy_from_slice(&attacker_tag);

    assert_eq!(
        host_context().bind_handoff(&forged),
        Err(native_audit_verifier::VerifyFailure::HandoffUnbound)
    );
    assert!(matches!(
        native_audit_verifier::AuditVerifier::genesis(chain_boot.bytes(), host_context(), &forged),
        Err(native_audit_verifier::VerifyFailure::HandoffUnbound)
    ));

    // A self-consistent tag under a foreign boot fails the identity binding.
    let foreign_boot = foreign(9);
    let mut foreign = forged;
    foreign[16..32].copy_from_slice(&foreign_boot.boot().bytes());
    let foreign_tag = attacker_handoff_tag(
        foreign_boot.boot(),
        live.context().authority_id(),
        &attacker_key,
    );
    foreign[32..].copy_from_slice(&foreign_tag);
    assert_eq!(
        host_context().bind_handoff(&foreign),
        Err(native_audit_verifier::VerifyFailure::HandoffUnbound)
    );
}

#[test]
fn observed_public_derivation_cannot_forge_binding_or_material() {
    let chain_boot = boot();
    let live = authority();
    let handoff = live.verifier_handoff();
    let genuine_anchor = host_context();
    let genesis_anchor = host_context();

    // Reconstruct the rejected public-only derivation from exactly the
    // fields an observer can read out of the untrusted handoff.
    let observed_id = u64::from_le_bytes(handoff[8..16].try_into().expect("fixed handoff layout"));
    let mut old_key_hasher = Hasher::new();
    old_key_hasher.update(b"astrid.native-kernel.audit-authority-root.v1");
    old_key_hasher.update(&handoff[16..32]);
    old_key_hasher.update(b"astrid.native-kernel.audit-authority-key.v1");
    old_key_hasher.update(&observed_id.to_le_bytes());
    let old_key: [u8; 32] = old_key_hasher.finalize().into();

    let mut forged_handoff = handoff;
    forged_handoff[32..].copy_from_slice(&attacker_handoff_tag(chain_boot, observed_id, &old_key));
    assert_eq!(
        genuine_anchor.bind_handoff(&forged_handoff),
        Err(native_audit_verifier::VerifyFailure::HandoffUnbound)
    );
    assert!(matches!(
        native_audit_verifier::AuditVerifier::genesis(
            chain_boot.bytes(),
            genesis_anchor,
            &forged_handoff
        ),
        Err(native_audit_verifier::VerifyFailure::HandoffUnbound)
    ));

    let mut chain = genesis_chain(chain_boot);
    chain
        .append(domain_event(AuditClass::DomainCreate))
        .unwrap();
    let checkpoint = chain.checkpoint();
    let mut genuine_wire = [0; native_audit_verifier::CHECKPOINT_WIRE_BYTES];
    let genuine_wire = encode_checkpoint(&checkpoint, live.context(), &mut genuine_wire).unwrap();
    let mut forged_checkpoint = [0; native_audit_verifier::CHECKPOINT_WIRE_BYTES];
    forged_checkpoint.copy_from_slice(genuine_wire);

    let mut forged_tag_hasher = Hasher::new_keyed(&old_key);
    forged_tag_hasher.update(root::CHECKPOINT_DOMAIN_TAG);
    forged_tag_hasher.update(&super::CODEC_VERSION.to_le_bytes());
    forged_tag_hasher.update(&checkpoint.boot().bytes());
    forged_tag_hasher.update(&checkpoint.seq().to_le_bytes());
    forged_tag_hasher.update(&checkpoint.root());
    forged_tag_hasher.update(&checkpoint.relay_generation().to_le_bytes());
    forged_tag_hasher.update(&checkpoint.authority_id().to_le_bytes());
    let forged_tag: [u8; 32] = forged_tag_hasher.finalize().into();
    let tag_offset = native_audit_verifier::CHECKPOINT_WIRE_BYTES - root::ROOT_LEN;
    forged_checkpoint[tag_offset..].copy_from_slice(&forged_tag);

    assert_eq!(
        native_audit_verifier::verify_checkpoint(&forged_checkpoint, &genuine_anchor),
        Err(native_audit_verifier::VerifyFailure::CheckpointMismatch)
    );
    assert!(matches!(
        native_audit_verifier::AuditVerifier::from_checkpoint(
            &forged_checkpoint,
            genuine_anchor,
            &handoff
        ),
        Err(native_audit_verifier::VerifyFailure::CheckpointMismatch)
    ));

    chain.relay_mut().grant_credits(1).unwrap();
    let record = chain.relay_mut().take().unwrap();
    let mut forged_ack_hasher = Hasher::new_keyed(&old_key);
    forged_ack_hasher.update(root::ACK_DOMAIN_TAG);
    forged_ack_hasher.update(&super::CODEC_VERSION.to_le_bytes());
    forged_ack_hasher.update(&observed_id.to_le_bytes());
    forged_ack_hasher.update(&chain_boot.bytes());
    forged_ack_hasher.update(&chain.relay().generation().to_le_bytes());
    forged_ack_hasher.update(&record.seq().to_le_bytes());
    forged_ack_hasher.update(&record.root());
    forged_ack_hasher.update(record.frame());
    let forged_ack: [u8; 32] = forged_ack_hasher.finalize().into();

    assert_eq!(
        chain.ack(record.seq(), record.root(), forged_ack),
        Err(AuditError::RootMismatch)
    );
    assert_eq!(chain.relay().redeliver().count(), 1);
}

#[test]
fn checkpoint_under_forged_context_is_rejected() {
    let chain_boot = boot();
    // Arbitrary attacker-chosen root and sequence sealed under an
    // attacker-chosen key reusing only the public identity fields.
    let forged_key = [0xB0; 32];
    let mut hasher = Hasher::new_keyed(&forged_key);
    hasher.update(root::CHECKPOINT_DOMAIN_TAG);
    hasher.update(&super::CODEC_VERSION.to_le_bytes());
    hasher.update(&chain_boot.bytes());
    hasher.update(&999u64.to_le_bytes());
    hasher.update(&[0xAA; root::ROOT_LEN]);
    hasher.update(&1u64.to_le_bytes());
    hasher.update(&authority().context().authority_id().to_le_bytes());
    let forged_tag: [u8; 32] = hasher.finalize().into();

    let mut wire = [0; native_audit_verifier::CHECKPOINT_WIRE_BYTES];
    let body_len = (native_audit_verifier::CHECKPOINT_WIRE_BYTES - 4) as u32;
    wire[0..4].copy_from_slice(&body_len.to_le_bytes());
    let mut pos = 4;
    wire[pos..pos + 2].copy_from_slice(&super::CODEC_VERSION.to_le_bytes());
    pos += 2;
    wire[pos..pos + 16].copy_from_slice(&chain_boot.bytes());
    pos += 16;
    wire[pos..pos + 8].copy_from_slice(&999u64.to_le_bytes());
    pos += 8;
    wire[pos..pos + root::ROOT_LEN].copy_from_slice(&[0xAA; root::ROOT_LEN]);
    pos += root::ROOT_LEN;
    wire[pos..pos + 8].copy_from_slice(&1u64.to_le_bytes());
    pos += 8;
    wire[pos..pos + 8].copy_from_slice(&authority().context().authority_id().to_le_bytes());
    pos += 8;
    wire[pos..].copy_from_slice(&forged_tag);

    assert_eq!(
        native_audit_verifier::verify_checkpoint(&wire, &host_context()),
        Err(native_audit_verifier::VerifyFailure::CheckpointMismatch)
    );
    assert!(matches!(
        native_audit_verifier::AuditVerifier::from_checkpoint(
            &wire,
            host_context(),
            &host_handoff()
        ),
        Err(native_audit_verifier::VerifyFailure::CheckpointMismatch)
    ));
    assert_eq!(
        decode_checkpoint(&wire, authority().context()),
        Err(AuditError::CheckpointMismatch)
    );
}

#[test]
fn forged_retirement_receipt_is_rejected() {
    let chain_boot = boot();
    let mut chain = genesis_chain(chain_boot);
    chain
        .append(domain_event(AuditClass::DomainCreate))
        .unwrap();
    let mut host_verifier = verifier();

    chain.relay_mut().grant_credits(1).unwrap();
    let record = chain.relay_mut().take().unwrap();
    let genuine = host_verifier.fold(record.frame(), record.root()).unwrap();

    // A receipt minted under an attacker-chosen key fails even with the
    // correct folded root, sequence, frame, and source root.
    let forged_key = [0xB0; 32];
    let mut hasher = Hasher::new_keyed(&forged_key);
    hasher.update(root::ACK_DOMAIN_TAG);
    hasher.update(&super::CODEC_VERSION.to_le_bytes());
    hasher.update(&authority().context().authority_id().to_le_bytes());
    hasher.update(&chain_boot.bytes());
    hasher.update(&chain.relay().generation().to_le_bytes());
    hasher.update(&record.seq().to_le_bytes());
    hasher.update(&record.root());
    hasher.update(record.frame());
    let forged_tag: [u8; 32] = hasher.finalize().into();

    assert_eq!(
        chain.ack(record.seq(), record.root(), forged_tag),
        Err(AuditError::RootMismatch)
    );
    assert_eq!(chain.relay().redeliver().count(), 1);

    // The genuine verifier receipt still retires exactly the in-flight
    // record.
    chain
        .ack(record.seq(), genuine.folded_root(), genuine.ack_tag())
        .unwrap();
    assert_eq!(chain.relay().redeliver().count(), 0);
}

#[test]
fn batch_reserve_is_static_and_inside_the_window() {
    assert_eq!(MAX_TERMINAL_RECORDS_PER_BATCH, 29);
    // Statically re-proves the relay's own compile-time headroom invariant
    // from the test side, keeping the reserve story falsifiable here too.
    const { assert!(AUDIT_RELAY_SLOTS >= MAX_TERMINAL_RECORDS_PER_BATCH) }
}

#[test]
fn second_custody_install_cannot_replace_the_live_boot() {
    crate::audit::reset_for_test();
    let replacement = crate::audit::install_for_test(
        BootSessionId::new([8; 16]).unwrap(),
        KernelSecretEntropy::new([0x51; 32]).unwrap(),
    );
    assert_eq!(
        replacement,
        Err(crate::audit::AuditInstallError::AlreadyInstalled)
    );
}
