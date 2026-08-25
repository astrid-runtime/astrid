use ed25519_dalek::SigningKey;

use crate::codec::{decode_manifest, encode_manifest};
use crate::error::GenerationError;
use crate::fixture::fixture_signing_key;
use crate::policy::{TrustedInput, TrustedInputData};
use crate::sign::sign_manifest;
use crate::types::{
    ComponentSet, ContentId, Expiration, Generation, MANIFEST_LEN, MAX_COMPONENTS,
    ManifestIdentity, ManifestInput, ManifestSizes, Revocation, RollbackFloor,
    SystemGenerationManifest,
};
use crate::verify::verify_manifest;

fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}

fn id(byte: u8) -> ContentId {
    ContentId::try_from_bytes([byte; 32]).expect("non-zero test digest")
}

fn sizes() -> ManifestSizes {
    ManifestSizes::new(4096, 8192, 16384, 32768)
}

fn components() -> ComponentSet {
    ComponentSet::try_from_slice(&[id(3), id(4), id(5)]).expect("sorted components")
}

fn make_manifest(input: ManifestInput) -> Result<SystemGenerationManifest, GenerationError> {
    SystemGenerationManifest::try_new(input)
}

fn manifest() -> SystemGenerationManifest {
    make_manifest(ManifestInput {
        kernel_identity: id(1),
        plan_digest: id(2),
        components: components(),
        object_root: id(6),
        closure_root: id(7),
        generation: Generation::new(8),
        rollback_floor: RollbackFloor::new(8),
        expires_at: Expiration::never(),
        revocation: Revocation::Active,
        sizes: sizes(),
    })
    .expect("valid manifest")
}

fn trusted(key: &SigningKey) -> TrustedInput {
    TrustedInput::try_new(TrustedInputData {
        signer: key.verifying_key().to_bytes(),
        kernel_identity: id(1),
        plan_digest: id(2),
        components: components(),
        object_root: id(6),
        closure_root: id(7),
        generation_floor: Generation::new(8),
        now_unix_seconds: 100,
        sizes: sizes(),
    })
    .expect("valid trusted input")
}

fn signed_bytes(key: &SigningKey) -> [u8; MANIFEST_LEN] {
    encode_manifest(&sign_manifest(key, manifest()))
}

#[test]
fn exact_canonical_bytes_roundtrip() {
    let signed = sign_manifest(&key(1), manifest());
    let bytes = encode_manifest(&signed);
    assert_eq!(bytes.len(), MANIFEST_LEN);
    assert_eq!(
        encode_manifest(&decode_manifest(&bytes).expect("decode")),
        bytes
    );
    let verified = verify_manifest(&bytes, &trusted(&key(1))).expect("verify");
    assert_eq!(verified.manifest(), manifest());
}

#[test]
fn manifest_identity_is_bound_to_verified_canonical_bytes() {
    let key = key(1);
    let bytes = signed_bytes(&key);
    let verified = verify_manifest(&bytes, &trusted(&key)).expect("verify");
    assert_eq!(
        verified.manifest_identity(),
        ManifestIdentity::from_canonical(&bytes)
    );

    let changed = make_manifest(ManifestInput {
        kernel_identity: id(1),
        plan_digest: id(2),
        components: components(),
        object_root: id(6),
        closure_root: id(7),
        generation: Generation::new(9),
        rollback_floor: RollbackFloor::new(9),
        expires_at: Expiration::never(),
        revocation: Revocation::Active,
        sizes: sizes(),
    })
    .expect("changed manifest");
    let changed_bytes = encode_manifest(&sign_manifest(&key, changed));
    let changed_verified = verify_manifest(&changed_bytes, &trusted(&key)).expect("changed verify");
    assert_ne!(
        verified.manifest_identity(),
        changed_verified.manifest_identity()
    );
}

#[test]
fn canonical_mutation_without_resigning_fails_verification() {
    let key = key(1);
    let mut bytes = signed_bytes(&key);
    bytes[396] ^= 1;
    assert_eq!(
        verify_manifest(&bytes, &trusted(&key)),
        Err(GenerationError::SignatureInvalid)
    );
}

#[test]
fn unknown_trailing_and_malformed_bytes_fail_closed() {
    assert_eq!(decode_manifest(&[]), Err(GenerationError::Missing));
    assert_eq!(
        decode_manifest(&[0; MANIFEST_LEN - 1]),
        Err(GenerationError::WrongLength)
    );
    assert_eq!(
        decode_manifest(&[0; MANIFEST_LEN + 1]),
        Err(GenerationError::WrongLength)
    );
    let mut bytes = signed_bytes(&key(1));
    bytes[0] ^= 1;
    assert_eq!(decode_manifest(&bytes), Err(GenerationError::Malformed));
    let mut bytes = signed_bytes(&key(1));
    bytes[8] = 2;
    assert_eq!(decode_manifest(&bytes), Err(GenerationError::Malformed));
    let mut bytes = signed_bytes(&key(1));
    bytes[9] = 0x80;
    assert_eq!(decode_manifest(&bytes), Err(GenerationError::UnknownFlags));
    let mut bytes = signed_bytes(&key(1));
    bytes[11] = 1;
    assert_eq!(decode_manifest(&bytes), Err(GenerationError::Malformed));
}

#[test]
fn oversized_component_set_and_noncanonical_padding_fail() {
    let too_many = [
        id(1),
        id(2),
        id(3),
        id(4),
        id(5),
        id(6),
        id(7),
        id(8),
        id(9),
    ];
    assert_eq!(
        ComponentSet::try_from_slice(&too_many),
        Err(GenerationError::InvalidComponentSet)
    );
    assert_eq!(MAX_COMPONENTS, 8);
    let mut bytes = signed_bytes(&key(1));
    bytes[10] = 2;
    bytes[76 + (2 * 32)] = 1;
    assert_eq!(
        decode_manifest(&bytes),
        Err(GenerationError::InvalidComponentSet)
    );
    let mut bytes = signed_bytes(&key(1));
    bytes[10] = 9;
    assert_eq!(
        decode_manifest(&bytes),
        Err(GenerationError::InvalidComponentSet)
    );
}

#[test]
fn duplicate_or_unsorted_components_are_rejected() {
    assert_eq!(
        ComponentSet::try_from_slice(&[id(3), id(3)]),
        Err(GenerationError::InvalidComponentSet)
    );
    assert_eq!(
        ComponentSet::try_from_slice(&[id(4), id(3)]),
        Err(GenerationError::InvalidComponentSet)
    );
}

#[test]
fn foreign_and_arbitrary_signers_fail() {
    let foreign = signed_bytes(&key(9));
    assert_eq!(
        verify_manifest(&foreign, &trusted(&key(1))),
        Err(GenerationError::UntrustedSigner)
    );
    let mut bytes = signed_bytes(&key(1));
    bytes[MANIFEST_LEN - 1] ^= 1;
    assert_eq!(
        verify_manifest(&bytes, &trusted(&key(1))),
        Err(GenerationError::SignatureInvalid)
    );
    let zero = TrustedInput::try_new(TrustedInputData {
        signer: [0; 32],
        kernel_identity: id(1),
        plan_digest: id(2),
        components: components(),
        object_root: id(6),
        closure_root: id(7),
        generation_floor: Generation::new(8),
        now_unix_seconds: 100,
        sizes: sizes(),
    });
    assert_eq!(zero, Err(GenerationError::InvalidSigner));
}

#[test]
fn stale_generation_and_rollback_floor_fail() {
    let key = key(1);
    let mut stale = manifest();
    stale = make_manifest(ManifestInput {
        kernel_identity: stale.kernel_identity(),
        plan_digest: stale.plan_digest(),
        components: stale.components(),
        object_root: stale.object_root(),
        closure_root: stale.closure_root(),
        generation: Generation::new(7),
        rollback_floor: RollbackFloor::new(7),
        expires_at: stale.expires_at(),
        revocation: stale.revocation(),
        sizes: stale.sizes(),
    })
    .expect("valid stale manifest");
    let bytes = encode_manifest(&sign_manifest(&key, stale));
    assert_eq!(
        verify_manifest(&bytes, &trusted(&key)),
        Err(GenerationError::Stale)
    );
    let mut low_floor = manifest();
    low_floor = make_manifest(ManifestInput {
        kernel_identity: low_floor.kernel_identity(),
        plan_digest: low_floor.plan_digest(),
        components: low_floor.components(),
        object_root: low_floor.object_root(),
        closure_root: low_floor.closure_root(),
        generation: Generation::new(9),
        rollback_floor: RollbackFloor::new(7),
        expires_at: low_floor.expires_at(),
        revocation: low_floor.revocation(),
        sizes: low_floor.sizes(),
    })
    .expect("valid low floor");
    let bytes = encode_manifest(&sign_manifest(&key, low_floor));
    assert_eq!(
        verify_manifest(&bytes, &trusted(&key)),
        Err(GenerationError::Stale)
    );
}

#[test]
fn expiry_and_revocation_fail() {
    let key = key(1);
    let expired = make_manifest(ManifestInput {
        kernel_identity: id(1),
        plan_digest: id(2),
        components: components(),
        object_root: id(6),
        closure_root: id(7),
        generation: Generation::new(8),
        rollback_floor: RollbackFloor::new(8),
        expires_at: Expiration::at(100),
        revocation: Revocation::Active,
        sizes: sizes(),
    })
    .expect("expired manifest shape");
    let bytes = encode_manifest(&sign_manifest(&key, expired));
    assert_eq!(
        verify_manifest(&bytes, &trusted(&key)),
        Err(GenerationError::Expired)
    );
    let revoked = make_manifest(ManifestInput {
        kernel_identity: id(1),
        plan_digest: id(2),
        components: components(),
        object_root: id(6),
        closure_root: id(7),
        generation: Generation::new(8),
        rollback_floor: RollbackFloor::new(8),
        expires_at: Expiration::never(),
        revocation: Revocation::Revoked,
        sizes: sizes(),
    })
    .expect("revoked manifest shape");
    let bytes = encode_manifest(&sign_manifest(&key, revoked));
    assert_eq!(
        verify_manifest(&bytes, &trusted(&key)),
        Err(GenerationError::Revoked)
    );
}

#[test]
fn kernel_plan_root_and_size_mismatch_fail() {
    let key = key(1);
    let cases = [
        (
            GenerationError::KernelMismatch,
            id(9),
            id(2),
            id(6),
            id(7),
            sizes(),
        ),
        (
            GenerationError::PlanMismatch,
            id(1),
            id(9),
            id(6),
            id(7),
            sizes(),
        ),
        (
            GenerationError::ObjectRootMismatch,
            id(1),
            id(2),
            id(9),
            id(7),
            sizes(),
        ),
        (
            GenerationError::ClosureRootMismatch,
            id(1),
            id(2),
            id(6),
            id(9),
            sizes(),
        ),
        (
            GenerationError::SizeMismatch,
            id(1),
            id(2),
            id(6),
            id(7),
            ManifestSizes::new(1, 2, 3, 4),
        ),
    ];
    for (expected, kernel, plan, object, closure, sizes) in cases {
        let candidate = make_manifest(ManifestInput {
            kernel_identity: kernel,
            plan_digest: plan,
            components: components(),
            object_root: object,
            closure_root: closure,
            generation: Generation::new(8),
            rollback_floor: RollbackFloor::new(8),
            expires_at: Expiration::never(),
            revocation: Revocation::Active,
            sizes,
        })
        .expect("candidate shape");
        let bytes = encode_manifest(&sign_manifest(&key, candidate));
        assert_eq!(verify_manifest(&bytes, &trusted(&key)), Err(expected));
    }
    let foreign_components = ComponentSet::try_from_slice(&[id(3), id(4), id(8)]).expect("set");
    let candidate = make_manifest(ManifestInput {
        kernel_identity: id(1),
        plan_digest: id(2),
        components: foreign_components,
        object_root: id(6),
        closure_root: id(7),
        generation: Generation::new(8),
        rollback_floor: RollbackFloor::new(8),
        expires_at: Expiration::never(),
        revocation: Revocation::Active,
        sizes: sizes(),
    })
    .expect("candidate shape");
    let bytes = encode_manifest(&sign_manifest(&key, candidate));
    assert_eq!(
        verify_manifest(&bytes, &trusted(&key)),
        Err(GenerationError::ComponentsMismatch)
    );
}

#[test]
fn invalid_floor_is_rejected_before_signing() {
    assert_eq!(
        make_manifest(ManifestInput {
            kernel_identity: id(1),
            plan_digest: id(2),
            components: components(),
            object_root: id(6),
            closure_root: id(7),
            generation: Generation::new(1),
            rollback_floor: RollbackFloor::new(2),
            expires_at: Expiration::never(),
            revocation: Revocation::Active,
            sizes: sizes(),
        }),
        Err(GenerationError::InvalidFloor)
    );
}

#[test]
fn no_slot_path_or_label_can_authorize_a_manifest() {
    let mut bytes = signed_bytes(&key(1));
    bytes[0..8].copy_from_slice(b"slotname");
    assert_eq!(decode_manifest(&bytes), Err(GenerationError::Malformed));
    let mut extended = [0u8; MANIFEST_LEN + 8];
    extended[..MANIFEST_LEN].copy_from_slice(&signed_bytes(&key(1)));
    extended[MANIFEST_LEN..].copy_from_slice(b"/slot___");
    assert_eq!(
        decode_manifest(&extended),
        Err(GenerationError::WrongLength)
    );
}

#[test]
fn distinct_content_ids_are_not_collapsed() {
    assert_ne!(
        ContentId::from_payload(b"kernel-a"),
        ContentId::from_payload(b"kernel-b")
    );
}

#[test]
fn fixture_signer_is_not_arbitrary_policy() {
    let fixture = fixture_signing_key();
    let policy = trusted(&key(1));
    let bytes = signed_bytes(&fixture);
    assert_eq!(
        verify_manifest(&bytes, &policy),
        Err(GenerationError::UntrustedSigner)
    );
}
