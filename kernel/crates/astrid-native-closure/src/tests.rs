use ed25519_dalek::SigningKey;

use crate::codec::{decode_table, encode_table};
use crate::error::ClosureError;
use crate::sign::{sign_artifact, signed_table};
use crate::types::{
    CURRENT_FLOOR, ClosureKind, DualClosureTable, GenerationFloor, MeasuredIdentity, TABLE_LEN,
};
use crate::verify::verify_table;

fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}

fn elf() -> &'static [u8] {
    b"fake-kernel-elf-bytes"
}

fn good_table() -> DualClosureTable {
    signed_table(&key(1), &key(2), CURRENT_FLOOR, CURRENT_FLOOR, elf())
}

#[test]
fn valid_distinct_empty_sysgen_binds() {
    let table = good_table();
    let bytes = encode_table(&table);
    let bound = verify_table(&bytes).expect("valid table");
    assert_eq!(
        bound.kernel_bootstrap,
        MeasuredIdentity::from_payload(elf())
    );
    assert_eq!(bound.system_generation, MeasuredIdentity::empty_sysgen());
    assert!(bound.distinct());
}

#[test]
fn missing_or_truncated_fails() {
    assert_eq!(verify_table(&[]), Err(ClosureError::Missing));
    assert_eq!(verify_table(&[0, 1, 2]), Err(ClosureError::Truncated));
    let mut bytes = encode_table(&good_table());
    bytes[0] ^= 0xff;
    assert_eq!(verify_table(&bytes), Err(ClosureError::Malformed));
    let short = [0u8; TABLE_LEN - 1];
    assert_eq!(verify_table(&short), Err(ClosureError::Truncated));
    let long = [0u8; TABLE_LEN + 1];
    assert_eq!(verify_table(&long), Err(ClosureError::Truncated));
}

#[test]
fn swapped_kinds_fail() {
    let mut table = good_table();
    core::mem::swap(&mut table.kernel, &mut table.sysgen);
    let bytes = encode_table(&table);
    assert_eq!(verify_table(&bytes), Err(ClosureError::Swapped));
}

#[test]
fn stale_below_floor_fails() {
    let stale = GenerationFloor::new(0);
    let table = signed_table(&key(1), &key(2), CURRENT_FLOOR, stale, elf());
    let bytes = encode_table(&table);
    assert_eq!(verify_table(&bytes), Err(ClosureError::Stale));
}

#[test]
fn cross_bound_kernel_signed_by_sysgen_fails() {
    let kernel_key = key(1);
    let sysgen_key = key(2);
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
    let bytes = encode_table(&table);
    assert_eq!(verify_table(&bytes), Err(ClosureError::CrossBound));
}

#[test]
fn same_key_fails() {
    let table = signed_table(&key(7), &key(7), CURRENT_FLOOR, CURRENT_FLOOR, elf());
    let bytes = encode_table(&table);
    assert_eq!(verify_table(&bytes), Err(ClosureError::SameKey));
}

#[test]
fn identity_collision_fails() {
    let mut table = good_table();
    table.kernel.identity = table.sysgen.identity;
    let bytes = encode_table(&table);
    assert_eq!(verify_table(&bytes), Err(ClosureError::Collision));
}

#[test]
fn non_empty_sysgen_fails() {
    let mut table = good_table();
    table.sysgen.identity = MeasuredIdentity::from_payload(b"not-empty");
    let bytes = encode_table(&table);
    assert_eq!(verify_table(&bytes), Err(ClosureError::NotEmpty));
}

#[test]
fn tampered_signature_fails() {
    let mut bytes = encode_table(&good_table());
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    assert_eq!(verify_table(&bytes), Err(ClosureError::SignatureInvalid));
}

#[test]
fn decode_roundtrip_preserves_table() {
    let table = good_table();
    let bytes = encode_table(&table);
    assert_eq!(decode_table(&bytes).expect("roundtrip"), table);
}
