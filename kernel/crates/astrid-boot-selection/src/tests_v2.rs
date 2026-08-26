use astrid_native_closure::{
    AuthenticatedPolicyHandoff, BootContextBinding, ClosureKind, DualClosureKeys, GenerationFloor,
    HandoffContext, LoaderIdentity, LoaderMeasurement, MeasuredIdentity, PolicyGeneration,
    PolicyHandoff, RootVerifier, TrustedPolicy, encode_table, fixture_signing_key as closure_key,
    sign_artifact, sign_empty_sysgen, sign_policy_handoff, verify_policy_handoff, verify_table,
};
use astrid_system_generation::{
    ComponentSet, ContentId, Expiration, Generation, ManifestSizes, Revocation, RollbackFloor,
    TrustedInput, TrustedInputData, verify_manifest,
};
use ed25519_dalek::{Signer, SigningKey};

use crate::codec::{
    CHECKSUM_END, CHECKSUM_START, FRAME_LEN, MAGIC, POLICY_GENERATION_START, RESERVED_END,
    RESERVED_START, SYSGEN_START, VERSION,
};
use crate::error::{JournalError, SelectionError};
use crate::journal::{FRAME_COUNT, JOURNAL_LEN, Journal};
use crate::policy::{MAX_ATTEMPTS, SelectionPolicy};
use crate::selector::{BootDecision, Selector, VerifiedCandidates};
use crate::types::{CandidateFacts, CandidateInput, Slot};
use crate::verified_adapter::{AdapterError, authenticated_policy, bind_verified_candidate};

fn digest(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn facts(byte: u8, policy_generation: u64) -> CandidateFacts {
    CandidateFacts::from_verified(CandidateInput {
        descriptor_identity: digest(byte),
        kernel_identity: digest(byte.wrapping_add(1)),
        system_generation_identity: digest(byte.wrapping_add(5)),
        plan_digest: digest(byte.wrapping_add(2)),
        object_root: digest(byte.wrapping_add(3)),
        closure_root: digest(byte.wrapping_add(4)),
        generation: 10 + u64::from(byte),
        rollback_floor: 10 + u64::from(byte),
        kernel_floor: 10 + u64::from(byte),
        sysgen_floor: 10 + u64::from(byte),
        policy_generation,
    })
}

fn selector() -> Selector {
    Selector::new(SelectionPolicy::new(10, 10, 10, 10))
}

fn recompute_checksum(bytes: &mut [u8; JOURNAL_LEN], frame_index: usize) {
    let start = frame_index * FRAME_LEN;
    let frame = &mut bytes[start..start + FRAME_LEN];
    let mut hasher = blake3::Hasher::new_derive_key("astrid.boot-selection.journal.v2");
    hasher.update(&frame[..CHECKSUM_START]);
    frame[CHECKSUM_START..CHECKSUM_END].copy_from_slice(hasher.finalize().as_bytes());
}

#[test]
fn v2_frame_and_journal_sizes_are_exact() {
    assert_eq!(FRAME_LEN, 296);
    assert_eq!(FRAME_COUNT, 16);
    assert_eq!(JOURNAL_LEN, 4736);
    assert_eq!(CHECKSUM_END, FRAME_LEN);
    assert_eq!(CHECKSUM_START, 264);
    assert_eq!(POLICY_GENERATION_START, 256);
    assert_eq!(MAGIC, b"ASTRABJ2");
    assert_eq!(VERSION, 2);
}

#[test]
fn v1_length_and_padded_v1_are_rejected_without_reinterpretation() {
    assert_eq!(
        Journal::from_bytes(&[0; 4096]),
        Err(JournalError::WrongLength)
    );
    assert_eq!(
        Journal::from_bytes(&[0; 4096 + (FRAME_LEN - 256)]),
        Err(JournalError::WrongLength)
    );
    assert_eq!(
        Journal::from_bytes(&[0; JOURNAL_LEN - 1]),
        Err(JournalError::WrongLength)
    );
    assert_eq!(
        Journal::from_bytes(&[0; JOURNAL_LEN + 1]),
        Err(JournalError::WrongLength)
    );
}

#[test]
fn v2_roundtrip_persists_sysgen_identity_and_policy_epoch() {
    let candidate = facts(7, 19);
    let selector = Selector::new(SelectionPolicy::from_authenticated(17, 17, 17, 17, 19));
    let pending = selector
        .start_pending(Journal::empty(), Slot::A, candidate, 1)
        .expect("pending");
    let recovered = selector.recover(
        Journal::from_bytes(&pending.journal().as_bytes()).expect("v2 journal"),
        VerifiedCandidates::from_verified(Some(candidate), None),
    );
    assert!(matches!(
        recovered,
        BootDecision::Pending(trial)
            if trial.candidate().system_generation_identity() == digest(12)
                && trial.candidate().policy_generation() == 19
    ));
}

#[test]
fn recomputed_checksum_does_not_authorize_sysgen_or_epoch_mutation() {
    let candidate = facts(3, 9);
    let pending = selector()
        .start_pending(Journal::empty(), Slot::A, candidate, 1)
        .expect("pending");
    let mut bytes = pending.journal().as_bytes();
    bytes[SYSGEN_START] ^= 1;
    recompute_checksum(&mut bytes, 0);
    let changed = Journal::from_bytes(&bytes).expect("fixed journal");
    assert_eq!(
        selector().recover(
            changed,
            VerifiedCandidates::from_verified(Some(candidate), None)
        ),
        BootDecision::Recovery
    );

    let mut bytes = pending.journal().as_bytes();
    bytes[POLICY_GENERATION_START] = bytes[POLICY_GENERATION_START].wrapping_add(1);
    recompute_checksum(&mut bytes, 0);
    let changed = Journal::from_bytes(&bytes).expect("fixed journal");
    assert_eq!(
        selector().recover(
            changed,
            VerifiedCandidates::from_verified(Some(candidate), None)
        ),
        BootDecision::Recovery
    );
}

#[test]
fn reserved_bytes_and_checksum_remain_fail_closed() {
    let candidate = facts(4, 4);
    let pending = selector()
        .start_pending(Journal::empty(), Slot::A, candidate, 1)
        .expect("pending");
    let mut reserved = pending.journal().as_bytes();
    reserved[RESERVED_START] = 1;
    assert_eq!(
        selector().recover(
            Journal::from_bytes(&reserved).expect("fixed"),
            VerifiedCandidates::from_verified(Some(candidate), None)
        ),
        BootDecision::Recovery
    );
    assert_eq!(RESERVED_END - RESERVED_START, 4);

    let mut checksum = pending.journal().as_bytes();
    checksum[CHECKSUM_START] ^= 1;
    assert_eq!(
        selector().recover(
            Journal::from_bytes(&checksum).expect("fixed"),
            VerifiedCandidates::from_verified(Some(candidate), None)
        ),
        BootDecision::Recovery
    );
}

#[test]
fn authenticated_policy_generation_is_a_separate_floor() {
    let candidate = facts(5, 8);
    let policy = SelectionPolicy::from_authenticated(15, 15, 15, 15, 9);
    assert!(!policy.accepts_authenticated_generation(8));
    assert!(policy.accepts_authenticated_generation(9));
    assert_eq!(
        Selector::new(policy).start_pending(Journal::empty(), Slot::A, candidate, 1),
        Err(SelectionError::Journal(JournalError::Ineligible))
    );
    assert_eq!(MAX_ATTEMPTS, 3);
}

fn handoff_context(seed: u8) -> HandoffContext {
    HandoffContext::new(
        MeasuredIdentity::from_payload(&[seed, 0x11]),
        MeasuredIdentity::from_payload(&[seed, 0x22]),
        LoaderMeasurement::from_bytes([seed.wrapping_add(1); 32]),
        LoaderIdentity::from_bytes([seed.wrapping_add(2); 32]),
        BootContextBinding::from_bytes([seed.wrapping_add(3); 32]),
    )
}

fn verified_handoff(kernel_floor: u64, sysgen_floor: u64) -> AuthenticatedPolicyHandoff {
    let root = SigningKey::from_bytes(&[3; 32]);
    let kernel = SigningKey::from_bytes(&[1; 32]);
    let sysgen = SigningKey::from_bytes(&[2; 32]);
    let expected = handoff_context(9);
    let policy = PolicyHandoff::for_signing(
        kernel.verifying_key().to_bytes(),
        sysgen.verifying_key().to_bytes(),
        GenerationFloor::new(kernel_floor),
        GenerationFloor::new(sysgen_floor),
        PolicyGeneration::new(19),
        expected,
    );
    let bytes = sign_policy_handoff(&root, &policy);
    let verifier = RootVerifier::try_new(
        root.verifying_key().to_bytes(),
        GenerationFloor::new(kernel_floor),
        GenerationFloor::new(sysgen_floor),
        PolicyGeneration::new(19),
    )
    .expect("root");
    verify_policy_handoff(&bytes, &verifier, &expected).expect("handoff")
}

fn verified_bound(
    kernel_identity: [u8; 32],
    kernel_floor: u64,
    sysgen_floor: u64,
) -> astrid_native_closure::BoundIdentities {
    let kernel = closure_key(astrid_native_closure::FixtureRole::KernelBootstrap);
    let sysgen = closure_key(astrid_native_closure::FixtureRole::SystemGeneration);
    let kernel_artifact = sign_artifact(
        &kernel,
        ClosureKind::KernelBootstrap,
        GenerationFloor::new(kernel_floor),
        MeasuredIdentity::from_bytes(kernel_identity),
    );
    let table = astrid_native_closure::DualClosureTable {
        min_floor: GenerationFloor::new(core::cmp::min(kernel_floor, sysgen_floor)),
        keys: DualClosureKeys {
            kernel_bootstrap: kernel.verifying_key().to_bytes(),
            system_generation: sysgen.verifying_key().to_bytes(),
        },
        kernel: kernel_artifact,
        sysgen: sign_empty_sysgen(&sysgen, GenerationFloor::new(sysgen_floor)),
    };
    let policy = TrustedPolicy::try_new(
        kernel.verifying_key().to_bytes(),
        sysgen.verifying_key().to_bytes(),
        GenerationFloor::new(kernel_floor),
        GenerationFloor::new(sysgen_floor),
    )
    .expect("closure policy");
    verify_table(&encode_table(&table), &policy).expect("closure")
}

fn verified_generation(
    kernel_identity: [u8; 32],
    generation: u64,
    rollback: u64,
) -> astrid_system_generation::VerifiedGeneration {
    const UNSIGNED_LEN: usize = 452;
    const SIGNER_OFFSET: usize = 452;
    const SIGNATURE_OFFSET: usize = 484;
    let signer = astrid_system_generation::fixture_signing_key();
    let kernel = ContentId::try_from_bytes(kernel_identity).expect("kernel id");
    let plan = ContentId::try_from_bytes(digest(2)).expect("plan");
    let object = ContentId::try_from_bytes(digest(6)).expect("object");
    let closure = ContentId::try_from_bytes(digest(7)).expect("closure");
    let manifest = astrid_system_generation::SystemGenerationManifest::try_new(
        astrid_system_generation::ManifestInput {
            kernel_identity: kernel,
            plan_digest: plan,
            components: ComponentSet::empty(),
            object_root: object,
            closure_root: closure,
            generation: Generation::new(generation),
            rollback_floor: RollbackFloor::new(rollback),
            expires_at: Expiration::never(),
            revocation: Revocation::Active,
            sizes: ManifestSizes::new(1, 2, 3, 4),
        },
    )
    .expect("manifest");
    let mut unsigned = [0u8; UNSIGNED_LEN];
    unsigned[..8].copy_from_slice(b"ASTRIDSG");
    unsigned[8] = 1;
    unsigned[9] = 0;
    unsigned[10] = 0;
    unsigned[11] = 0;
    unsigned[12..44].copy_from_slice(&kernel.as_bytes());
    unsigned[44..76].copy_from_slice(&plan.as_bytes());
    unsigned[76..332].fill(0);
    unsigned[332..364].copy_from_slice(&object.as_bytes());
    unsigned[364..396].copy_from_slice(&closure.as_bytes());
    unsigned[396..404].copy_from_slice(&generation.to_le_bytes());
    unsigned[404..412].copy_from_slice(&rollback.to_le_bytes());
    unsigned[412..420].copy_from_slice(&0u64.to_le_bytes());
    unsigned[420..428].copy_from_slice(&1u64.to_le_bytes());
    unsigned[428..436].copy_from_slice(&2u64.to_le_bytes());
    unsigned[436..444].copy_from_slice(&3u64.to_le_bytes());
    unsigned[444..452].copy_from_slice(&4u64.to_le_bytes());
    let mut message = [0u8; 36 + UNSIGNED_LEN];
    message[..36].copy_from_slice(b"astrid.system-generation.manifest.v1");
    message[36..].copy_from_slice(&unsigned);
    let signature = signer.sign(&message);
    let mut bytes = [0u8; astrid_system_generation::MANIFEST_LEN];
    bytes[..UNSIGNED_LEN].copy_from_slice(&unsigned);
    bytes[SIGNER_OFFSET..SIGNATURE_OFFSET].copy_from_slice(&signer.verifying_key().to_bytes());
    bytes[SIGNATURE_OFFSET..].copy_from_slice(&signature.to_bytes());
    let trusted = TrustedInput::try_new(TrustedInputData {
        signer: signer.verifying_key().to_bytes(),
        kernel_identity: kernel,
        plan_digest: plan,
        components: ComponentSet::empty(),
        object_root: object,
        closure_root: closure,
        generation_floor: Generation::new(0),
        now_unix_seconds: 0,
        sizes: ManifestSizes::new(1, 2, 3, 4),
    })
    .expect("trusted");
    let verified = verify_manifest(&bytes, &trusted).expect("verified generation");
    assert_eq!(verified.manifest(), manifest);
    verified
}

fn candidate_tuple() -> (
    astrid_system_generation::VerifiedGeneration,
    astrid_native_closure::BoundIdentities,
    AuthenticatedPolicyHandoff,
) {
    let kernel = digest(11);
    (
        verified_generation(kernel, 17, 16),
        verified_bound(kernel, 13, 14),
        verified_handoff(13, 14),
    )
}

#[test]
fn adapter_maps_descriptor_closures_and_policy_without_crossing_domains() {
    let (generation, bound, handoff) = candidate_tuple();
    let facts = bind_verified_candidate(generation, bound, handoff).expect("adapter");
    assert_eq!(facts.generation(), 17);
    assert_eq!(facts.rollback_floor(), 16);
    assert_eq!(facts.kernel_floor(), 13);
    assert_eq!(facts.sysgen_floor(), 14);
    assert_eq!(facts.policy_generation(), 19);
    assert_eq!(
        facts.system_generation_identity(),
        bound.sysgen_identity().as_bytes()
    );
    let policy = authenticated_policy(generation, bound, handoff).expect("policy");
    assert!(policy.accepts_authenticated_generation(19));
    assert!(!policy.accepts_authenticated_generation(18));
}

#[test]
fn adapter_rejects_kernel_identity_mismatch_and_cross_bound_floors() {
    let (generation, bound, handoff) = candidate_tuple();
    let wrong_generation = verified_generation(digest(12), 17, 16);
    assert_eq!(
        bind_verified_candidate(wrong_generation, bound, handoff),
        Err(AdapterError::KernelIdentityMismatch)
    );

    let wrong_kernel_floor = verified_handoff(12, 14);
    assert_eq!(
        bind_verified_candidate(generation, bound, wrong_kernel_floor),
        Err(AdapterError::KernelFloorMismatch)
    );
    let wrong_sysgen_floor = verified_handoff(13, 12);
    assert_eq!(
        bind_verified_candidate(generation, bound, wrong_sysgen_floor),
        Err(AdapterError::SysgenFloorMismatch)
    );
}

#[test]
fn adapter_preserves_independent_generation_rollback_and_policy_epoch() {
    let kernel = digest(11);
    let generation = verified_generation(kernel, 21, 8);
    let bound = verified_bound(kernel, 34, 55);
    let handoff = verified_handoff(34, 55);
    let facts = bind_verified_candidate(generation, bound, handoff).expect("adapter");
    assert_eq!(facts.generation(), 21);
    assert_eq!(facts.rollback_floor(), 8);
    assert_eq!(facts.kernel_floor(), 34);
    assert_eq!(facts.sysgen_floor(), 55);
    assert_eq!(facts.policy_generation(), 19);
}
