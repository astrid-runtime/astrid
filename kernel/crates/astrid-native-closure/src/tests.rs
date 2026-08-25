use ed25519_dalek::SigningKey;

use crate::codec::{decode_table, encode_table};
use crate::error::ClosureError;
use crate::fixture::{FixtureRole, fixture_signing_key};
use crate::policy::{EMULATOR_KERNEL_VERIFY_KEY, EMULATOR_SYSGEN_VERIFY_KEY, TrustedPolicy};
use crate::sign::{sign_artifact, signed_table};
use crate::types::{
    CURRENT_FLOOR, ClosureKind, DualClosureKeys, DualClosureTable, GenerationFloor,
    MeasuredIdentity, TABLE_LEN,
};
use crate::verify::verify_table;

fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}

fn elf() -> &'static [u8] {
    b"fake-kernel-elf-bytes"
}

fn policy_for(
    kernel: &SigningKey,
    sysgen: &SigningKey,
    kernel_min: GenerationFloor,
    sysgen_min: GenerationFloor,
) -> TrustedPolicy {
    TrustedPolicy::try_new(
        kernel.verifying_key().to_bytes(),
        sysgen.verifying_key().to_bytes(),
        kernel_min,
        sysgen_min,
    )
    .expect("test keys are distinct")
}

fn good_keys() -> (SigningKey, SigningKey) {
    (key(1), key(2))
}

fn good_policy() -> TrustedPolicy {
    let (k, s) = good_keys();
    policy_for(&k, &s, CURRENT_FLOOR, CURRENT_FLOOR)
}

fn good_table() -> DualClosureTable {
    let (k, s) = good_keys();
    signed_table(&k, &s, CURRENT_FLOOR, CURRENT_FLOOR, elf())
}

fn verify(bytes: &[u8]) -> Result<crate::BoundIdentities, ClosureError> {
    verify_table(bytes, &good_policy())
}

#[test]
fn valid_distinct_empty_sysgen_binds() {
    let bound = verify(&encode_table(&good_table())).expect("valid table");
    assert_eq!(
        bound.kernel_bootstrap,
        MeasuredIdentity::from_payload(elf())
    );
    assert_eq!(bound.system_generation, MeasuredIdentity::empty_sysgen());
    assert_eq!(bound.kernel_floor, CURRENT_FLOOR);
    assert_eq!(bound.sysgen_floor, CURRENT_FLOOR);
    assert!(bound.distinct());
}

#[test]
fn mixed_valid_floors_bind() {
    let (k, s) = good_keys();
    let sysgen_floor = GenerationFloor::new(2);
    let table = signed_table(&k, &s, CURRENT_FLOOR, sysgen_floor, elf());
    let bound = verify(&encode_table(&table)).expect("mixed floors");
    assert_eq!(bound.kernel_floor, CURRENT_FLOOR);
    assert_eq!(bound.sysgen_floor, sysgen_floor);
}

#[test]
fn exact_floor_equals_policy_min_binds() {
    let (k, s) = good_keys();
    let kernel_min = GenerationFloor::new(4);
    let sysgen_min = GenerationFloor::new(7);
    let policy = policy_for(&k, &s, kernel_min, sysgen_min);
    let table = signed_table(&k, &s, kernel_min, sysgen_min, elf());
    let bound = verify_table(&encode_table(&table), &policy).expect("exact floors");
    assert_eq!(bound.kernel_floor, kernel_min);
    assert_eq!(bound.sysgen_floor, sysgen_min);
}

#[test]
fn missing_or_truncated_fails() {
    assert_eq!(verify(&[]), Err(ClosureError::Missing));
    assert_eq!(verify(&[0, 1, 2]), Err(ClosureError::Truncated));
    let mut bytes = encode_table(&good_table());
    bytes[0] ^= 0xff;
    assert_eq!(verify(&bytes), Err(ClosureError::Malformed));
    let short = [0u8; TABLE_LEN - 1];
    assert_eq!(verify(&short), Err(ClosureError::Truncated));
    let long = [0u8; TABLE_LEN + 1];
    assert_eq!(verify(&long), Err(ClosureError::Truncated));
}

#[test]
fn swapped_kinds_fail() {
    let mut table = good_table();
    core::mem::swap(&mut table.kernel, &mut table.sysgen);
    assert_eq!(verify(&encode_table(&table)), Err(ClosureError::Swapped));
}

#[test]
fn independently_stale_sysgen_fails() {
    let (k, s) = good_keys();
    let table = signed_table(&k, &s, CURRENT_FLOOR, GenerationFloor::new(0), elf());
    assert_eq!(verify(&encode_table(&table)), Err(ClosureError::Stale));
}

#[test]
fn independently_stale_kernel_fails() {
    let (k, s) = good_keys();
    let table = signed_table(&k, &s, GenerationFloor::new(0), CURRENT_FLOOR, elf());
    assert_eq!(verify(&encode_table(&table)), Err(ClosureError::Stale));
}

#[test]
fn lowered_header_min_floor_does_not_admit_stale() {
    let (k, s) = good_keys();
    let mut table = signed_table(
        &k,
        &s,
        GenerationFloor::new(0),
        GenerationFloor::new(0),
        elf(),
    );
    table.min_floor = GenerationFloor::new(0);
    assert_eq!(verify(&encode_table(&table)), Err(ClosureError::Stale));
}

#[test]
fn raised_header_min_floor_is_ignored() {
    let mut table = good_table();
    table.min_floor = GenerationFloor::new(99);
    verify(&encode_table(&table)).expect("header floor is untrusted");
}

#[test]
fn advertised_attacker_keys_ignored_when_signatures_match_policy() {
    let mut table = good_table();
    table.keys = DualClosureKeys {
        kernel_bootstrap: key(9).verifying_key().to_bytes(),
        system_generation: key(10).verifying_key().to_bytes(),
    };
    verify(&encode_table(&table)).expect("table keys are not policy");
}

#[test]
fn arbitrary_self_signed_keys_fail_against_policy() {
    let table = signed_table(&key(9), &key(10), CURRENT_FLOOR, CURRENT_FLOOR, elf());
    assert_eq!(verify(&encode_table(&table)), Err(ClosureError::CrossBound));
}

#[test]
fn cross_bound_kernel_signed_by_sysgen_fails() {
    let (kernel_key, sysgen_key) = good_keys();
    let mut table = signed_table(
        &kernel_key,
        &sysgen_key,
        CURRENT_FLOOR,
        CURRENT_FLOOR,
        elf(),
    );
    table.kernel = sign_artifact(
        &sysgen_key,
        ClosureKind::KernelBootstrap,
        CURRENT_FLOOR,
        MeasuredIdentity::from_payload(elf()),
    );
    assert_eq!(verify(&encode_table(&table)), Err(ClosureError::CrossBound));
}

#[test]
fn swapped_artifact_keys_fail() {
    let (kernel_key, sysgen_key) = good_keys();
    let mut table = signed_table(
        &kernel_key,
        &sysgen_key,
        CURRENT_FLOOR,
        CURRENT_FLOOR,
        elf(),
    );
    table.kernel = sign_artifact(
        &sysgen_key,
        ClosureKind::KernelBootstrap,
        CURRENT_FLOOR,
        MeasuredIdentity::from_payload(elf()),
    );
    table.sysgen = sign_artifact(
        &kernel_key,
        ClosureKind::SystemGeneration,
        CURRENT_FLOOR,
        MeasuredIdentity::empty_sysgen(),
    );
    assert_eq!(verify(&encode_table(&table)), Err(ClosureError::CrossBound));
}

#[test]
fn policy_same_key_rejected() {
    let k = key(7);
    let pk = k.verifying_key().to_bytes();
    assert_eq!(
        TrustedPolicy::try_new(pk, pk, CURRENT_FLOOR, CURRENT_FLOOR),
        Err(ClosureError::SameKey)
    );
}

#[test]
fn identity_collision_fails() {
    let mut table = good_table();
    table.kernel.identity = table.sysgen.identity;
    assert_eq!(verify(&encode_table(&table)), Err(ClosureError::Collision));
}

#[test]
fn non_empty_sysgen_fails() {
    let mut table = good_table();
    table.sysgen.identity = MeasuredIdentity::from_payload(b"not-empty");
    assert_eq!(verify(&encode_table(&table)), Err(ClosureError::NotEmpty));
}

#[test]
fn tampered_signature_fails() {
    let mut bytes = encode_table(&good_table());
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    assert_eq!(verify(&bytes), Err(ClosureError::SignatureInvalid));
}

#[test]
fn decode_roundtrip_preserves_table() {
    let table = good_table();
    assert_eq!(
        decode_table(&encode_table(&table)).expect("roundtrip"),
        table
    );
}

#[test]
fn emulator_fixture_uses_current_floor_and_fixture_public_keys() {
    let policy = TrustedPolicy::emulator_fixture();
    assert_eq!(policy.kernel_min(), CURRENT_FLOOR);
    assert_eq!(policy.sysgen_min(), CURRENT_FLOOR);
    assert_eq!(policy.kernel_verify(), EMULATOR_KERNEL_VERIFY_KEY);
    assert_eq!(policy.sysgen_verify(), EMULATOR_SYSGEN_VERIFY_KEY);
    assert_eq!(
        policy.kernel_verify(),
        fixture_signing_key(FixtureRole::KernelBootstrap)
            .verifying_key()
            .to_bytes()
    );
    assert_eq!(
        policy.sysgen_verify(),
        fixture_signing_key(FixtureRole::SystemGeneration)
            .verifying_key()
            .to_bytes()
    );
    let table = signed_table(
        &fixture_signing_key(FixtureRole::KernelBootstrap),
        &fixture_signing_key(FixtureRole::SystemGeneration),
        CURRENT_FLOOR,
        CURRENT_FLOOR,
        elf(),
    );
    let bound = verify_table(&encode_table(&table), &policy).expect("fixture table");
    assert_eq!(bound.kernel_floor, CURRENT_FLOOR);
    assert_eq!(bound.sysgen_floor, CURRENT_FLOOR);
}

#[test]
fn independently_stale_against_split_policy_mins() {
    let (k, s) = good_keys();
    let policy = policy_for(&k, &s, GenerationFloor::new(1), GenerationFloor::new(2));
    let stale_sysgen = signed_table(
        &k,
        &s,
        GenerationFloor::new(1),
        GenerationFloor::new(1),
        elf(),
    );
    assert_eq!(
        verify_table(&encode_table(&stale_sysgen), &policy),
        Err(ClosureError::Stale)
    );
    let stale_kernel = signed_table(
        &k,
        &s,
        GenerationFloor::new(0),
        GenerationFloor::new(2),
        elf(),
    );
    assert_eq!(
        verify_table(&encode_table(&stale_kernel), &policy),
        Err(ClosureError::Stale)
    );
    let mixed = signed_table(
        &k,
        &s,
        GenerationFloor::new(1),
        GenerationFloor::new(2),
        elf(),
    );
    verify_table(&encode_table(&mixed), &policy).expect("split mins");
}
