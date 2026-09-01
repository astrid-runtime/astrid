//! Fail-closed regressions for kernel-private live audit custody.

use super::live::LiveVerifier;
use super::*;
use crate::ipc::DomainToken;

static LIVE_TEST_LOCK: spin::Mutex<()> = spin::Mutex::new(());

fn live_guard() -> spin::MutexGuard<'static, ()> {
    LIVE_TEST_LOCK.lock()
}

fn boot() -> BootSessionId {
    BootSessionId::new([7; 16]).unwrap()
}

fn secret() -> KernelSecretEntropy {
    KernelSecretEntropy::new([0x5A; 32]).unwrap()
}

fn foreign_secret() -> KernelSecretEntropy {
    KernelSecretEntropy::new([0x6B; 32]).unwrap()
}

fn authority() -> AuditAuthority {
    AuditAuthority::mint(boot(), secret()).unwrap()
}

fn foreign_authority() -> AuditAuthority {
    AuditAuthority::mint(boot(), foreign_secret()).unwrap()
}

fn event() -> AuditEvent {
    let token = DomainToken::new(0, 1).unwrap();
    AuditEvent::new(AuditClass::DomainCreate, AuditSubject::from_domain(token))
}

struct FrameBuf {
    bytes: [u8; MAX_FRAME_BYTES],
    len: usize,
}

impl FrameBuf {
    fn first(chain_boot: BootSessionId) -> (Self, [u8; 32]) {
        let genesis = root::RootHasher::new().genesis(chain_boot);
        let frame = Frame::new(chain_boot, 1, &event(), Some(genesis)).unwrap();
        let mut bytes = [0; MAX_FRAME_BYTES];
        let encoded = frame.encode(&mut bytes).unwrap();
        let claimed = root::RootHasher::new().advance(genesis, chain_boot, 1, &encoded);
        let encoded_len = encoded.len();
        let mut stored = [0; MAX_FRAME_BYTES];
        stored[..encoded_len].copy_from_slice(encoded);
        (
            Self {
                bytes: stored,
                len: encoded.len(),
            },
            claimed,
        )
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

fn first_frame(chain_boot: BootSessionId) -> (FrameBuf, [u8; 32]) {
    FrameBuf::first(chain_boot)
}

fn genesis_verifier() -> LiveVerifier {
    LiveVerifier::genesis(boot(), &authority()).unwrap()
}

fn prepared<'a>(
    verifier: &'a mut LiveVerifier,
    frame: &'a FrameBuf,
    root: [u8; 32],
) -> super::live::PreparedLive<'a> {
    try_prepare(verifier, frame, root, 1).unwrap()
}

fn try_prepare<'a>(
    verifier: &'a mut LiveVerifier,
    frame: &'a FrameBuf,
    root: [u8; 32],
    expected_seq: u64,
) -> Result<super::live::PreparedLive<'a>, AuditError> {
    let reservation = verifier.reserve(&authority(), expected_seq)?;
    let receipt_tag =
        authority()
            .context()
            .ack_tag(boot(), 1, expected_seq, root, frame.as_slice());
    verifier.finish(
        reservation,
        frame.as_slice(),
        root,
        AuditClass::DomainCreate,
        receipt_tag,
    )
}

fn occupied_relay(frame: &FrameBuf, root: [u8; 32]) -> AuditRelay {
    let mut relay = AuditRelay::new(boot());
    relay.publish(1, frame.as_slice(), root, false).unwrap();
    relay
}

#[test]
fn live_record_folds_and_commits_after_relay_authentication() {
    let _guard = live_guard();
    let mut chain = AuditChain::genesis(boot(), secret()).unwrap();
    let observation = chain.append_verified(&event()).unwrap();
    assert_eq!(observation.seq(), 1);
    assert_eq!(chain.seq(), 1);
    assert_eq!(chain.relay().redeliver().count(), 0);

    let mut wire = [0; native_audit_verifier::CHECKPOINT_WIRE_BYTES];
    let checkpoint_wire =
        encode_checkpoint(&chain.checkpoint(), chain.authority().context(), &mut wire).unwrap();
    let host = native_audit_verifier::AuditVerifier::from_checkpoint(
        checkpoint_wire,
        native_audit_verifier::AuthContext::from_trusted_anchor(
            chain.authority().context().authority_id(),
            boot().bytes(),
            *chain.authority().context().verification_key().bytes(),
        )
        .unwrap(),
        &chain.authority().verifier_handoff(),
    )
    .unwrap()
    .into_retained_evidence();
    assert_eq!(host.root(), *chain.root());
}

#[test]
fn early_late_cross_instance_and_root_rejections_are_fail_closed() {
    let _guard = live_guard();
    let (frame_buf, root) = first_frame(boot());
    let mut verifier = genesis_verifier();
    let initial = verifier.cursor();

    let early = try_prepare(&mut verifier, &frame_buf, root, 0);
    assert!(matches!(early, Err(AuditError::CheckpointMismatch)));
    assert_eq!(verifier.cursor(), initial);

    let late = try_prepare(&mut verifier, &frame_buf, root, 2);
    assert!(matches!(late, Err(AuditError::CheckpointMismatch)));
    assert_eq!(verifier.cursor(), initial);

    let cross = verifier.reserve(&foreign_authority(), 1);
    assert!(matches!(cross, Err(AuditError::CheckpointMismatch)));
    assert_eq!(verifier.cursor(), initial);
}

#[test]
fn raw_tag_substitution_fails_without_moving_any_cursor() {
    let _guard = live_guard();
    let (frame_buf, root) = first_frame(boot());
    let mut verifier = genesis_verifier();
    let initial = verifier.cursor();
    let mut transaction = prepared(&mut verifier, &frame_buf, root);
    transaction.set_raw_receipt_tag_for_test([0; 32]);

    let mut relay = AuditRelay::new(boot());
    assert_eq!(
        transaction.commit(&mut relay, &authority().context()),
        Err(AuditError::RootMismatch)
    );
    assert_eq!(verifier.cursor(), initial);
    assert_eq!(relay.generation(), 1);
    assert_eq!(relay.redeliver().count(), 0);

    let transaction = prepared(&mut verifier, &frame_buf, root);
    assert_eq!(transaction.transaction_id().get(), 3);
    let observation = transaction
        .commit(&mut relay, &authority().context())
        .unwrap();
    assert_eq!(observation.seq(), 1);
    assert_eq!(verifier.cursor(), (2, root));
}

#[test]
fn relay_cursor_rejection_leaves_verifier_and_relay_unchanged() {
    let _guard = live_guard();
    let (frame_buf, root) = first_frame(boot());
    let mut verifier = genesis_verifier();
    let initial = verifier.cursor();
    let transaction = prepared(&mut verifier, &frame_buf, root);
    let mut relay = occupied_relay(&frame_buf, root);
    let relay_count = relay.redeliver().count();

    assert_eq!(
        transaction.commit(&mut relay, &authority().context()),
        Err(AuditError::RelayInvalidCursor)
    );
    assert_eq!(verifier.cursor(), initial);
    assert_eq!(relay.generation(), 1);
    assert_eq!(relay.redeliver().count(), relay_count);
}

#[test]
fn transaction_overflow_is_typed_and_does_not_wrap() {
    let _guard = live_guard();
    let _ = first_frame(boot());
    let mut verifier = genesis_verifier();
    verifier.force_transaction_overflow_for_test();
    let initial = verifier.cursor();
    let overflow = verifier.reserve(&authority(), 1);
    assert!(matches!(overflow, Err(AuditError::LiveTransactionOverflow)));
    assert_eq!(verifier.transaction_id(), u64::MAX);
    assert_eq!(verifier.cursor(), initial);
}

#[test]
fn instance_overflow_is_typed_and_without_wrapping() {
    let _guard = live_guard();
    let overflow = super::live::AuthorityInstance::checked_id_for_test(u64::MAX);
    assert!(matches!(overflow, Err(AuditError::LiveInstanceOverflow)));
}

#[test]
fn runtime_refuses_a_second_live_custody_for_the_same_checkpoint() {
    let _guard = live_guard();
    let _ipc_runtime_guard = crate::ipc::test_support::test_lock();
    let _runtime_guard = super::tests::runtime_test_guard();
    crate::audit::reset_for_test();
    let replacement = crate::audit::install_for_test(
        BootSessionId::new([8; 16]).unwrap(),
        KernelSecretEntropy::new([0x51; 32]).unwrap(),
    );
    assert_eq!(
        replacement,
        Err(crate::audit::AuditInstallError::AlreadyInstalled)
    );
    assert_eq!(crate::audit::state_for_test().map(|(seq, _)| seq), Some(0));
}
