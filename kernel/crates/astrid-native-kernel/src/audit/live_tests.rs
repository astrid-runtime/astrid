//! Fail-closed regressions for kernel-private live audit custody.

use super::live::{LiveVerifier, PreparedLive};
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
    decoded: Frame,
    bytes: [u8; MAX_FRAME_BYTES],
    len: usize,
}

impl FrameBuf {
    fn first(chain_boot: BootSessionId, previous_root: [u8; 32]) -> Self {
        let frame = Frame::new(chain_boot, 1, &event(), Some(previous_root)).unwrap();
        let mut bytes = [0; MAX_FRAME_BYTES];
        let encoded = frame.encode(&mut bytes).unwrap();
        let len = encoded.len();
        let mut stored = [0; MAX_FRAME_BYTES];
        stored[..len].copy_from_slice(encoded);
        Self {
            decoded: frame,
            bytes: stored,
            len,
        }
    }

    fn decoded(&self) -> &Frame {
        &self.decoded
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

fn genesis_root(chain_boot: BootSessionId) -> [u8; 32] {
    root::RootHasher::new().genesis(chain_boot)
}

fn first_frame(chain_boot: BootSessionId) -> FrameBuf {
    FrameBuf::first(chain_boot, genesis_root(chain_boot))
}

fn stale_first_frame(chain_boot: BootSessionId) -> FrameBuf {
    FrameBuf::first(chain_boot, [0xAA; 32])
}

fn canonical_root(chain_boot: BootSessionId, frame: &FrameBuf) -> [u8; 32] {
    root::RootHasher::new().advance(genesis_root(chain_boot), chain_boot, 1, frame.as_slice())
}

fn genesis_verifier() -> LiveVerifier {
    LiveVerifier::genesis(boot(), &authority()).unwrap()
}

fn try_prepare<'a>(
    verifier: &'a mut LiveVerifier,
    frame: &'a FrameBuf,
    authority: &AuditAuthority,
    expected_seq: u64,
) -> Result<PreparedLive<'a>, AuditError> {
    let reservation = verifier.reserve(authority, expected_seq)?;
    verifier.finish(
        reservation,
        frame.decoded(),
        frame.as_slice(),
        1,
        authority.context(),
    )
}

fn prepare<'a>(verifier: &'a mut LiveVerifier, frame: &'a FrameBuf) -> PreparedLive<'a> {
    try_prepare(verifier, frame, &authority(), 1).unwrap()
}

fn occupied_relay(frame: &FrameBuf, chain_root: [u8; 32]) -> AuditRelay {
    let mut relay = AuditRelay::new(boot());
    relay
        .publish(1, frame.as_slice(), chain_root, false)
        .unwrap();
    relay
}

#[test]
fn live_record_folds_and_commits_after_relay_authentication() {
    let _guard = live_guard();
    let mut chain = AuditChain::genesis(boot(), secret()).unwrap();
    assert_eq!(*chain.root(), genesis_root(boot()));

    let observation = chain.append_verified(&event()).unwrap();
    let expected_root = canonical_root(boot(), &first_frame(boot()));
    assert_eq!(observation.seq(), 1);
    assert_eq!(*observation.root(), expected_root);
    assert_eq!((chain.seq(), *chain.root()), (1, expected_root));
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
fn early_late_stale_and_cross_instance_rejections_are_fail_closed() {
    let _guard = live_guard();
    let frame = first_frame(boot());
    let stale_frame = stale_first_frame(boot());
    let mut verifier = genesis_verifier();
    let initial = verifier.cursor();

    let early = try_prepare(&mut verifier, &frame, &authority(), 0);
    assert!(matches!(early, Err(AuditError::CheckpointMismatch)));

    let late = try_prepare(&mut verifier, &frame, &authority(), 2);
    assert!(matches!(late, Err(AuditError::CheckpointMismatch)));

    let stale = try_prepare(&mut verifier, &stale_frame, &authority(), 1);
    assert!(matches!(stale, Err(AuditError::CheckpointMismatch)));

    let cross = verifier.reserve(&foreign_authority(), 1);
    assert!(matches!(cross, Err(AuditError::CheckpointMismatch)));

    assert_eq!(verifier.cursor(), initial);
    // Failed preparation may burn only the monotonic reservation identity.
    assert_eq!(verifier.transaction_id(), 2);
}

#[test]
fn committed_frame_cannot_be_replayed_by_private_custody() {
    let _guard = live_guard();
    let frame = first_frame(boot());
    let mut verifier = genesis_verifier();
    let transaction = prepare(&mut verifier, &frame);
    let mut relay = AuditRelay::new(boot());
    let observation = transaction
        .commit(&mut relay, &authority().context())
        .unwrap();
    assert_eq!(observation.seq(), 1);

    let replay = try_prepare(&mut verifier, &frame, &authority(), 1);
    assert!(matches!(replay, Err(AuditError::CheckpointMismatch)));
    assert_eq!(verifier.cursor(), (2, canonical_root(boot(), &frame)));
}

#[test]
fn relay_independently_rejects_a_raw_substituted_tag() {
    let _guard = live_guard();
    let frame = first_frame(boot());
    let chain_root = canonical_root(boot(), &frame);
    let mut relay = AuditRelay::new(boot());
    let authority = authority();
    let context = authority.context();

    assert_eq!(
        relay.publish_retired(1, frame.as_slice(), chain_root, false, [0; 32], context),
        Err(AuditError::RootMismatch)
    );
    assert_eq!(relay.generation(), 1);
    assert_eq!(relay.redeliver().count(), 0);

    let receipt = context.ack_tag(boot(), 1, 1, chain_root, frame.as_slice());
    relay
        .publish_retired(1, frame.as_slice(), chain_root, false, receipt, context)
        .unwrap();
    assert_eq!(relay.redeliver().count(), 0);
}

#[test]
fn relay_cursor_rejection_leaves_verifier_and_relay_unchanged() {
    let _guard = live_guard();
    let frame = first_frame(boot());
    let chain_root = canonical_root(boot(), &frame);
    let mut verifier = genesis_verifier();
    let initial = verifier.cursor();
    let transaction = prepare(&mut verifier, &frame);
    let mut relay = occupied_relay(&frame, chain_root);
    let relay_count = relay.redeliver().count();

    assert_eq!(
        transaction.commit(&mut relay, &authority().context()),
        Err(AuditError::RelayInvalidCursor)
    );
    assert_eq!(verifier.cursor(), initial);
    assert_eq!(relay.generation(), 1);
    assert_eq!(relay.redeliver().count(), relay_count);

    let transaction = prepare(&mut verifier, &frame);
    assert_eq!(transaction.transaction_id().get(), 3);
    let observation = transaction
        .commit(&mut AuditRelay::new(boot()), &authority().context())
        .unwrap();
    assert_eq!(observation.seq(), 1);
    assert_eq!(verifier.cursor(), (2, chain_root));
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
