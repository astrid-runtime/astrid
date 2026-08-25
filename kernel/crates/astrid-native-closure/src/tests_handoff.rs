use ed25519_dalek::SigningKey;

use crate::error::ClosureError;
use crate::handoff::{
    HANDOFF_DOMAIN, HANDOFF_LEN, HandoffContext, PolicyHandoff, sign_policy_handoff,
};
use crate::root::RootVerifier;
use crate::types::{
    BootContextBinding, GenerationFloor, LoaderIdentity, LoaderMeasurement, MeasuredIdentity,
    PolicyGeneration,
};
use crate::verify::verify_policy_handoff;

fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}

fn context(seed: u8) -> HandoffContext {
    HandoffContext::new(
        MeasuredIdentity::from_payload(&[seed, 0x11]),
        MeasuredIdentity::from_payload(&[seed, 0x22]),
        LoaderMeasurement::from_bytes([seed.wrapping_add(1); 32]),
        LoaderIdentity::from_bytes([seed.wrapping_add(2); 32]),
        BootContextBinding::from_bytes([seed.wrapping_add(3); 32]),
    )
}

fn policy(root: &SigningKey) -> RootVerifier {
    RootVerifier::try_new(
        root.verifying_key().to_bytes(),
        GenerationFloor::new(3),
        GenerationFloor::new(5),
        PolicyGeneration::new(7),
    )
    .expect("test keys are distinct")
}

fn statement(kernel: &SigningKey, sysgen: &SigningKey, context: HandoffContext) -> PolicyHandoff {
    PolicyHandoff::new(
        kernel.verifying_key().to_bytes(),
        sysgen.verifying_key().to_bytes(),
        GenerationFloor::new(4),
        GenerationFloor::new(6),
        PolicyGeneration::new(8),
        context,
    )
}

fn signed() -> (RootVerifier, HandoffContext, [u8; HANDOFF_LEN]) {
    let root = key(3);
    let kernel = key(1);
    let sysgen = key(2);
    let expected = context(9);
    let bytes = sign_policy_handoff(&root, &statement(&kernel, &sysgen, expected));
    (policy(&root), expected, bytes)
}

#[test]
fn valid_handoff_binds_keys_floors_generation_and_context() {
    let (root, expected, bytes) = signed();
    let accepted = verify_policy_handoff(&bytes, &root, &expected).expect("valid handoff");
    assert_eq!(accepted.root_verify, root.root_verify());
    assert_ne!(accepted.policy.kernel_verify, accepted.policy.sysgen_verify);
    assert_eq!(accepted.policy.kernel_floor, GenerationFloor::new(4));
    assert_eq!(accepted.policy.sysgen_floor, GenerationFloor::new(6));
    assert_eq!(accepted.policy.policy_generation, PolicyGeneration::new(8));
    assert_eq!(accepted.policy.context, expected);
}

#[test]
fn fixed_envelope_has_versioned_domain_and_exact_length() {
    let (root, expected, bytes) = signed();
    assert_eq!(bytes.len(), HANDOFF_LEN);
    assert_eq!(&bytes[0..8], b"ASTRIDPH");
    assert_eq!(&bytes[9..33], HANDOFF_DOMAIN);
    verify_policy_handoff(&bytes, &root, &expected).expect("fixed envelope");

    let short = &bytes[..HANDOFF_LEN - 1];
    assert_eq!(
        verify_policy_handoff(short, &root, &expected),
        Err(ClosureError::Truncated)
    );
    let long = [bytes.as_slice(), &[0u8]].concat();
    assert_eq!(
        verify_policy_handoff(&long, &root, &expected),
        Err(ClosureError::Truncated)
    );

    let mut forged_length = bytes;
    forged_length[33] ^= 1;
    assert_eq!(
        verify_policy_handoff(&forged_length, &root, &expected),
        Err(ClosureError::Truncated)
    );
}

#[test]
fn altered_domain_and_version_fail_closed() {
    let (root, expected, bytes) = signed();
    let mut domain = bytes;
    domain[9] ^= 1;
    assert_eq!(
        verify_policy_handoff(&domain, &root, &expected),
        Err(ClosureError::Malformed)
    );

    let mut version = bytes;
    version[8] = version[8].wrapping_add(1);
    assert_eq!(
        verify_policy_handoff(&version, &root, &expected),
        Err(ClosureError::Malformed)
    );
}

#[test]
fn altered_field_or_signature_fails_root_authentication() {
    let (root, expected, bytes) = signed();
    let mut field = bytes;
    field[HANDOFF_PREFIX_LEN_FOR_TEST] ^= 1;
    assert_eq!(
        verify_policy_handoff(&field, &root, &expected),
        Err(ClosureError::RootSignatureInvalid)
    );

    let mut signature = bytes;
    let last = signature.len() - 1;
    signature[last] ^= 1;
    assert_eq!(
        verify_policy_handoff(&signature, &root, &expected),
        Err(ClosureError::RootSignatureInvalid)
    );
}

#[test]
fn arbitrary_self_signed_root_is_rejected() {
    let root = key(3);
    let attacker = key(9);
    let kernel = key(1);
    let sysgen = key(2);
    let expected = context(4);
    let bytes = sign_policy_handoff(&attacker, &statement(&kernel, &sysgen, expected));
    assert_eq!(
        verify_policy_handoff(&bytes, &policy(&root), &expected),
        Err(ClosureError::RootKeyMismatch)
    );
}

#[test]
fn root_signed_handoff_can_rotate_subordinate_keys() {
    let root = key(3);
    let rotated_kernel = key(8);
    let rotated_sysgen = key(7);
    let expected = context(10);
    let bytes = sign_policy_handoff(
        &root,
        &statement(&rotated_kernel, &rotated_sysgen, expected),
    );
    let accepted = verify_policy_handoff(&bytes, &policy(&root), &expected)
        .expect("root authorizes rotated subordinate keys");
    assert_eq!(
        accepted.policy.kernel_verify,
        rotated_kernel.verifying_key().to_bytes()
    );
    assert_eq!(
        accepted.policy.sysgen_verify,
        rotated_sysgen.verifying_key().to_bytes()
    );
}

#[test]
fn swapped_subordinate_keys_without_root_resign_fail_authentication() {
    let root = key(3);
    let kernel = key(1);
    let sysgen = key(2);
    let expected = context(5);
    let mut bytes = sign_policy_handoff(&root, &statement(&kernel, &sysgen, expected));
    let kernel_offset = HANDOFF_PREFIX_LEN_FOR_TEST;
    let sysgen_offset = kernel_offset + 32;
    for i in 0..32 {
        bytes.swap(kernel_offset + i, sysgen_offset + i);
    }
    assert_eq!(
        verify_policy_handoff(&bytes, &policy(&root), &expected),
        Err(ClosureError::RootSignatureInvalid)
    );
}

#[test]
fn collapsed_or_stale_independent_floors_are_rejected() {
    let root = key(3);
    let kernel = key(1);
    let sysgen = key(2);
    let expected = context(6);
    let mut collapsed = statement(&kernel, &sysgen, expected);
    collapsed.kernel_floor = GenerationFloor::new(4);
    collapsed.sysgen_floor = GenerationFloor::new(4);
    let bytes = sign_policy_handoff(&root, &collapsed);
    assert_eq!(
        verify_policy_handoff(&bytes, &policy(&root), &expected),
        Err(ClosureError::Stale)
    );

    let mut swapped = statement(&kernel, &sysgen, expected);
    swapped.kernel_floor = GenerationFloor::new(6);
    swapped.sysgen_floor = GenerationFloor::new(4);
    let bytes = sign_policy_handoff(&root, &swapped);
    assert_eq!(
        verify_policy_handoff(&bytes, &policy(&root), &expected),
        Err(ClosureError::Stale)
    );

    let mut stale = statement(&kernel, &sysgen, expected);
    stale.policy_generation = PolicyGeneration::new(6);
    let bytes = sign_policy_handoff(&root, &stale);
    assert_eq!(
        verify_policy_handoff(&bytes, &policy(&root), &expected),
        Err(ClosureError::PolicyGenerationStale)
    );
}

#[test]
fn image_and_closure_digest_replay_is_rejected() {
    let (root, expected, bytes) = signed();
    let mut replay = expected;
    replay.kernel_image = MeasuredIdentity::from_payload(b"different-kernel");
    assert_eq!(
        verify_policy_handoff(&bytes, &root, &replay),
        Err(ClosureError::BindingMismatch)
    );

    let mut replay = expected;
    replay.closure_table = MeasuredIdentity::from_payload(b"different-table");
    assert_eq!(
        verify_policy_handoff(&bytes, &root, &replay),
        Err(ClosureError::BindingMismatch)
    );
}

#[test]
fn loader_and_boot_context_replay_is_rejected() {
    let (root, expected, bytes) = signed();
    let mut replay = expected;
    replay.loader_measurement = LoaderMeasurement::from_bytes([0xa1; 32]);
    assert_eq!(
        verify_policy_handoff(&bytes, &root, &replay),
        Err(ClosureError::BindingMismatch)
    );

    let mut replay = expected;
    replay.loader_identity = LoaderIdentity::from_bytes([0xb2; 32]);
    replay.boot_context = BootContextBinding::from_bytes([0xc3; 32]);
    assert_eq!(
        verify_policy_handoff(&bytes, &root, &replay),
        Err(ClosureError::BindingMismatch)
    );
}

#[test]
fn untrusted_header_cannot_override_authenticated_policy() {
    let (root, expected, bytes) = signed();
    let mut forged = bytes;
    forged[HANDOFF_PREFIX_LEN_FOR_TEST] ^= 0xff;
    forged[HANDOFF_PREFIX_LEN_FOR_TEST + 32] ^= 0xff;
    assert_eq!(
        verify_policy_handoff(&forged, &root, &expected),
        Err(ClosureError::RootSignatureInvalid)
    );
}

const HANDOFF_PREFIX_LEN_FOR_TEST: usize = 67;
