//! Kernel/harness-private regressions for the #1759 audit freeze.

use super::*;
use crate::ipc::DomainToken;

fn boot() -> BootSessionId {
    BootSessionId::new([7; 16]).unwrap()
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

/// Fixed-buffer frame storage: the kernel is `no_std`, so tests hold encoded
/// bytes in arrays instead of heap vectors.
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
    let frame = Frame::new(chain_boot, seq, event, prev);
    let mut buf = [0; MAX_FRAME_BYTES];
    FrameBuf::new(frame.encode(&mut buf).unwrap())
}

#[test]
fn roundtrip_and_injectivity() {
    let chain_boot = boot();
    let cases = [
        domain_event(AuditClass::DomainCreate),
        domain_event(AuditClass::IpcSend).with_object(AuditObject::endpoint(2, 5).unwrap()),
        domain_event(AuditClass::CapabilityDerive)
            .with_object(capability_object(9, 3, 4, 11))
            .with_rights(AuditRights::from_bits(0b0101).unwrap()),
        AuditEvent::denial(
            subject(1, 2),
            DenialContext::new(DenialReason::ForeignObject, [1; 8]),
        ),
        domain_event(AuditClass::RootCheckpoint)
            .with_payload(&[0xAA; 64])
            .unwrap(),
    ];
    let encoded: [FrameBuf; 5] = [
        encode_frame(chain_boot, 1, &cases[0], None),
        encode_frame(chain_boot, 1, &cases[1], None),
        encode_frame(chain_boot, 1, &cases[2], None),
        encode_frame(chain_boot, 1, &cases[3], None),
        encode_frame(chain_boot, 1, &cases[4], None),
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
fn rejects_malformed_and_non_canonical() {
    let chain_boot = boot();
    let event = domain_event(AuditClass::DomainAdmit).with_object(capability_object(1, 0, 1, 1));
    let valid = encode_frame(chain_boot, 1, &event, None);

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

    let mut bad_seq = FrameBuf::new(valid.as_slice());
    bad_seq.bytes[22..30].copy_from_slice(&0u64.to_le_bytes());
    assert!(matches!(
        decode(bad_seq.as_slice()),
        Err(AuditError::MalformedFrame)
    ));

    let mut zero_boot = FrameBuf::new(valid.as_slice());
    zero_boot.bytes[6..22].fill(0);
    assert!(matches!(
        decode(zero_boot.as_slice()),
        Err(AuditError::MalformedFrame)
    ));

    let denial = encode_frame(
        chain_boot,
        1,
        &AuditEvent::denial(
            subject(0, 1),
            DenialContext::new(DenialReason::StaleIdentity, [0; 8]),
        ),
        None,
    );
    assert!(matches!(
        decode(denial.as_slice()),
        Ok(frame) if frame.class() == AuditClass::BoundedDenial && frame.object().is_none()
    ));
}

#[test]
fn chain_append_is_atomic_and_verifier_fold_matches_root() {
    let chain_boot = boot();
    let mut chain = AuditChain::genesis(chain_boot);
    let mut verifier = native_audit_verifier::AuditVerifier::genesis(chain_boot.bytes()).unwrap();

    for expected_seq in 1u64..=5 {
        let class = match expected_seq {
            1 => AuditClass::DomainCreate,
            2 => AuditClass::CapabilityDerive,
            3 => AuditClass::IpcSend,
            4 => AuditClass::GenerationAdvance,
            _ => AuditClass::DomainReclaim,
        };
        let event = domain_event(class).with_object(capability_object(expected_seq, 1, 2, 3));
        let seq = chain.append(event).unwrap();
        assert_eq!(seq, expected_seq);

        chain.relay_mut().grant_credits(1).unwrap();
        let record = chain.relay_mut().take().unwrap();
        assert_eq!(
            verifier
                .fold_with_root(record.frame(), Some(record.root()))
                .unwrap(),
            expected_seq
        );
        assert_eq!(verifier.root(), *chain.root());
    }
}

#[test]
fn tamper_is_invalid_gap_is_incomplete_duplicate_is_invalid() {
    let chain_boot = boot();
    let mut chain = AuditChain::genesis(chain_boot);
    for class in [
        AuditClass::DomainCreate,
        AuditClass::DomainAdmit,
        AuditClass::DomainStart,
    ] {
        chain.append(domain_event(class)).unwrap();
    }
    let mut records = [FrameBuf::new(&[]), FrameBuf::new(&[]), FrameBuf::new(&[])];
    {
        chain.relay_mut().grant_credits(3).unwrap();
        let mut count = 0;
        while let Some(record) = chain.relay_mut().take() {
            records[count] = FrameBuf::new(record.frame());
            count += 1;
        }
        assert_eq!(count, 3);
    }

    let mut verifier = native_audit_verifier::AuditVerifier::genesis(chain_boot.bytes()).unwrap();
    let mut tampered = FrameBuf::new(records[0].as_slice());
    let last = tampered.len - 1;
    tampered.bytes[last] ^= 0xFF;
    assert!(matches!(
        verifier.fold(tampered.as_slice()),
        Err(native_audit_verifier::FoldFailure::Invalid(_))
    ));

    let mut verifier = native_audit_verifier::AuditVerifier::genesis(chain_boot.bytes()).unwrap();
    verifier.fold(records[0].as_slice()).unwrap();
    // records[2] without records[1] is a gap: Incomplete, never a skip.
    assert!(matches!(
        verifier.fold(records[2].as_slice()),
        Err(native_audit_verifier::FoldFailure::Incomplete(
            native_audit_verifier::IncompleteReason::SequenceGap
        ))
    ));

    let mut verifier = native_audit_verifier::AuditVerifier::genesis(chain_boot.bytes()).unwrap();
    verifier.fold(records[0].as_slice()).unwrap();
    assert!(matches!(
        verifier.fold(records[0].as_slice()),
        Err(native_audit_verifier::FoldFailure::Invalid(
            native_audit_verifier::InvalidReason::DuplicateOrReorder
        ))
    ));
}

#[test]
fn sequence_overflow_fails_closed_without_commit() {
    let chain_boot = boot();
    let mut chain = AuditChain::restore(chain_boot, u64::MAX, [9; 32]);
    let before = (chain.seq(), *chain.root());
    assert_eq!(
        chain.append(domain_event(AuditClass::DomainCreate)),
        Err(AuditError::SequenceOverflow)
    );
    assert_eq!((chain.seq(), *chain.root()), before);
}

#[test]
fn relay_flow_credits_acks_and_redelivery() {
    let chain_boot = boot();
    let mut chain = AuditChain::genesis(chain_boot);
    chain
        .append(domain_event(AuditClass::DomainCreate))
        .unwrap();
    chain.append(domain_event(AuditClass::DomainAdmit)).unwrap();

    chain.relay_mut().grant_credits(1).unwrap();
    let first = chain.relay_mut().take().unwrap();
    // Lost ack: both records stay outstanding and can be redelivered.
    let mut redelivered = chain.relay().redeliver();
    assert_eq!(redelivered.next().unwrap().frame(), first.frame());
    assert_eq!(redelivered.count(), 1);

    chain.relay_mut().ack(first.seq()).unwrap();
    chain.relay_mut().grant_credits(1).unwrap();
    let second = chain.relay_mut().take().unwrap();
    assert_eq!(second.seq(), 2);
    chain.relay_mut().ack(second.seq()).unwrap();

    assert!(chain.relay_mut().ack(first.seq()).is_err());
}

#[test]
fn window_overflow_keeps_authority_and_resync_rebinds() {
    let chain_boot = boot();
    let mut chain = AuditChain::genesis(chain_boot);
    let total = AUDIT_RELAY_SLOTS as u64 + 2;
    for index in 0..total {
        let class = if index % 2 == 0 {
            AuditClass::DomainEnter
        } else {
            AuditClass::DomainExit
        };
        let seq = chain.append(domain_event(class)).unwrap();
        assert_eq!(seq, index + 1);
    }
    // The window latched at capacity; the two newest rooted events wait for a
    // resync while every retained record stays intact and in order.
    assert_eq!(chain.seq(), total);
    assert_eq!(chain.relay().redeliver().count(), AUDIT_RELAY_SLOTS);

    let current_root = *chain.root();
    let current_seq = chain.seq();
    let checkpoint = chain.relay_mut().resync(current_root, current_seq).unwrap();
    assert_eq!(checkpoint.seq(), chain.seq());
    assert_eq!(checkpoint.relay_generation(), 2);
    let mut wire = [0; native_audit_verifier::CHECKPOINT_WIRE_BYTES];
    let bytes = encode_checkpoint(&checkpoint, &mut wire).unwrap();
    let mut verifier = native_audit_verifier::AuditVerifier::from_checkpoint(bytes).unwrap();
    assert_eq!(verifier.root(), *chain.root());

    // After resync the relay accepts further publishes and the verifier
    // continues from the trusted checkpoint.
    let seq = chain
        .append(domain_event(AuditClass::DomainCancel))
        .unwrap();
    chain.relay_mut().grant_credits(1).unwrap();
    let record = chain.relay_mut().take().unwrap();
    assert_eq!(record.seq(), seq);
    assert_eq!(
        verifier
            .fold_with_root(record.frame(), Some(record.root()))
            .unwrap(),
        seq
    );
    assert_eq!(verifier.root(), *chain.root());
}

#[test]
fn checkpoint_is_kernel_authenticated_and_binds_state() {
    let chain_boot = boot();
    let mut chain = AuditChain::genesis(chain_boot);
    chain
        .append(domain_event(AuditClass::DomainCreate))
        .unwrap();
    let checkpoint = chain.checkpoint();
    assert!(checkpoint.verify_tag());

    let mut wire = [0; native_audit_verifier::CHECKPOINT_WIRE_BYTES];
    let bytes = encode_checkpoint(&checkpoint, &mut wire).unwrap();
    assert!(
        native_audit_verifier::AuditVerifier::from_checkpoint(bytes).is_ok(),
        "verifier accepts a kernel-sealed checkpoint"
    );

    let mut tampered = [0; native_audit_verifier::CHECKPOINT_WIRE_BYTES];
    tampered.copy_from_slice(bytes);
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert_eq!(
        native_audit_verifier::verify_checkpoint(&tampered),
        Err(native_audit_verifier::VerifyFailure::CheckpointMismatch)
    );
    assert_eq!(
        decode_checkpoint(&tampered),
        Err(AuditError::CheckpointMismatch)
    );
    assert_eq!(decode_checkpoint(bytes).unwrap(), checkpoint);
}

#[test]
fn batch_reserve_is_static_and_inside_the_window() {
    assert_eq!(MAX_TERMINAL_RECORDS_PER_BATCH, 21);
    assert!(AUDIT_RELAY_SLOTS >= MAX_TERMINAL_RECORDS_PER_BATCH);
}
