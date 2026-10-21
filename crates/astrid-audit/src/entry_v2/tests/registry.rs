//! Key-registry construction, rotation and rejection rules.

use super::*;
use crate::entry_v2::{KeyBinding, KeyRegistryRecord, RegistryOp};
use crate::error::AuditError;

fn genesis(keys: &[(KeyRole, &KeyPair)]) -> Result<KeyRegistryRecord, AuditError> {
    KeyRegistry::genesis_record(at(KAT_GENESIS_SECONDS, 0), keys)
}

#[test]
fn genesis_binds_roles_and_is_signed_by_every_key() {
    let registry = kat_registry();
    let audit = key(1).export_public_key();
    let runtime = key(2).export_public_key();
    assert_eq!(registry.head_seq(), 0);
    assert_eq!(registry.active_key(KeyRole::Audit, 0), Some(audit));
    assert_eq!(registry.active_key(KeyRole::Capability, 0), Some(runtime));
    assert_eq!(registry.active_key(KeyRole::Build, 0), Some(runtime));
    assert_eq!(registry.active_key(KeyRole::AuditV1, 0), Some(runtime));
    assert!(registry.is_active(KeyRole::Audit, &audit, 0));
    assert!(!registry.is_active(KeyRole::Audit, &runtime, 0));
    // States beyond the latest record are unknown.
    assert!(!registry.is_active(KeyRole::Audit, &audit, 1));
    assert_eq!(registry.records()[0].signatures.len(), 2);
}

#[test]
fn genesis_rejects_invalid_key_sets() {
    let audit = key(1);
    let runtime = key(2);
    let other = key(3);
    assert!(
        genesis(&[(KeyRole::Capability, &runtime)]).is_err(),
        "no audit key"
    );
    assert!(
        genesis(&[(KeyRole::Audit, &audit), (KeyRole::Audit, &other)]).is_err(),
        "two audit keys"
    );
    assert!(
        genesis(&[(KeyRole::Audit, &audit), (KeyRole::Build, &audit)]).is_err(),
        "the audit key must not hold another role"
    );
    assert!(
        genesis(&[
            (KeyRole::Audit, &audit),
            (KeyRole::Build, &runtime),
            (KeyRole::Build, &other),
        ])
        .is_err(),
        "a role bound twice"
    );
}

#[test]
fn rotation_is_cross_signed_and_bounds_key_validity() {
    let mut registry = kat_registry();
    let old = key(1);
    let new = key(0x11);
    let record = registry
        .rotation_record(KeyRole::Audit, &old, &new, at(KAT_GENESIS_SECONDS, 1))
        .unwrap();
    assert_eq!(record.op, RegistryOp::Rotate);
    assert_eq!(record.prev, registry.head_hash());
    let mut signers: Vec<_> = record
        .signatures
        .iter()
        .map(|signature| signature.key)
        .collect();
    signers.sort_by_key(|key| *key.as_bytes());
    let mut expected = vec![old.export_public_key(), new.export_public_key()];
    expected.sort_by_key(|key| *key.as_bytes());
    assert_eq!(signers, expected, "both the old and the new key sign");

    registry.push(record).unwrap();
    assert_eq!(registry.head_seq(), 1);
    assert!(registry.is_active(KeyRole::Audit, &old.export_public_key(), 0));
    assert!(!registry.is_active(KeyRole::Audit, &old.export_public_key(), 1));
    assert!(registry.is_active(KeyRole::Audit, &new.export_public_key(), 1));
    assert!(!registry.is_active(KeyRole::Audit, &new.export_public_key(), 0));
    assert!(registry.was_registered(KeyRole::Audit, &old.export_public_key()));
    assert_eq!(
        registry.registry_id(),
        kat_registry().registry_id(),
        "rotation keeps the registry id"
    );
}

#[test]
fn rotation_rejects_wrong_or_reused_keys() {
    let registry = kat_registry();
    let when = at(KAT_GENESIS_SECONDS, 1);
    // The old key must be the role's active key.
    assert!(
        registry
            .rotation_record(KeyRole::Audit, &key(2), &key(0x11), when)
            .is_err()
    );
    // The new key must never have been registered, for any role.
    assert!(
        registry
            .rotation_record(KeyRole::Audit, &key(1), &key(2), when)
            .is_err()
    );
    let mut rotated = registry.clone();
    let record = rotated
        .rotation_record(KeyRole::Audit, &key(1), &key(0x11), when)
        .unwrap();
    rotated.push(record).unwrap();
    // A retired key cannot come back.
    assert!(
        rotated
            .rotation_record(KeyRole::Audit, &key(0x11), &key(1), when)
            .is_err()
    );
}

#[test]
fn records_that_are_not_cross_signed_are_rejected() {
    let registry = kat_registry();
    let old = key(1);
    let new = key(0x11);
    let honest = registry
        .rotation_record(KeyRole::Audit, &old, &new, at(KAT_GENESIS_SECONDS, 1))
        .unwrap();

    // Only the new key signs: someone holding a fresh key cannot enrol it.
    let mut unsigned_by_old = honest.clone();
    unsigned_by_old
        .signatures
        .retain(|signature| signature.key == new.export_public_key());
    assert!(registry.clone().push(unsigned_by_old).is_err());

    // A signature over a different record does not count.
    let mut swapped = honest.clone();
    swapped.timestamp = at(KAT_GENESIS_SECONDS, 2);
    assert!(registry.clone().push(swapped).is_err());

    // A rotation that skips a sequence number or does not link is rejected.
    let mut skipped = honest.clone();
    skipped.seq = 2;
    assert!(registry.clone().push(skipped).is_err());
    let mut unlinked = honest;
    unlinked.prev = [0xee; 32];
    assert!(registry.clone().push(unlinked).is_err());
}

#[test]
fn a_tampered_stored_registry_fails_to_load() {
    let registry = kat_registry();
    let mut records = registry.records().to_vec();
    records[0].add[0] = KeyBinding {
        role: KeyRole::Audit,
        key: key(0x55).export_public_key(),
    };
    assert!(KeyRegistry::from_records(records).is_err());
    assert!(KeyRegistry::from_records(Vec::new()).is_err());
}

#[test]
fn registry_records_survive_a_json_round_trip() {
    let mut registry = kat_registry();
    let record = registry
        .rotation_record(
            KeyRole::Audit,
            &key(1),
            &key(0x11),
            at(KAT_GENESIS_SECONDS, 1),
        )
        .unwrap();
    registry.push(record).unwrap();
    let stored: Vec<Vec<u8>> = registry
        .records()
        .iter()
        .map(|record| serde_json::to_vec(record).unwrap())
        .collect();
    let reloaded: Vec<KeyRegistryRecord> = stored
        .iter()
        .map(|bytes| serde_json::from_slice(bytes).unwrap())
        .collect();
    let reloaded = KeyRegistry::from_records(reloaded).unwrap();
    assert_eq!(reloaded.head_hash(), registry.head_hash());
    assert_eq!(reloaded.registry_id(), registry.registry_id());
}
