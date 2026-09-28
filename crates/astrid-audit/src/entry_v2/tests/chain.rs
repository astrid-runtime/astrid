//! Chain verification: sequence, linkage, registered keys, rotation and the
//! v1 to v2 boundary.

use super::*;
use crate::entry_v2::{ChainStart, ChainVerifier};
use crate::log::ChainIssue;

fn issues(registry: &KeyRegistry, entries: &[AuditEntry]) -> Vec<ChainIssue> {
    ChainVerifier::new(Some(registry))
        .verify(entries, ChainStart::Genesis)
        .issues
}

/// Re-sign `entry` with `signer` after an edit, keeping it otherwise intact.
fn resign(mut entry: AuditEntry, signer: &KeyPair) -> AuditEntry {
    entry.runtime_key = signer.export_public_key();
    entry.signature = signer.sign(&entry.signing_data());
    entry
}

/// The next v2 entry after `previous` on the same chain.
fn next_entry(registry: &KeyRegistry, previous: &AuditEntry, signer: &KeyPair) -> AuditEntry {
    let seal = previous.v2.as_ref().unwrap();
    let mut next = draft(
        registry,
        &previous.session_id,
        previous.principal.clone(),
        seal.principal_uid,
        AuditAction::FileRead {
            path: "/next".into(),
        },
    );
    next.seq = seal.seq.checked_add(1).unwrap();
    next.previous_hash = previous.content_hash();
    next.key_epoch = registry.head_seq();
    AuditEntry::create_v2(next, signer).unwrap()
}

fn v1_entries(signer: &KeyPair, count: usize) -> Vec<AuditEntry> {
    let mut entries: Vec<AuditEntry> = Vec::new();
    for index in 0..count {
        let previous = entries
            .last()
            .map_or_else(ContentHash::zero, AuditEntry::content_hash);
        entries.push(AuditEntry::create_with_principal(
            kat_session(),
            alice(),
            AuditAction::FileRead {
                path: format!("/v1/{index}"),
            },
            AuthorizationProof::System {
                reason: "test".into(),
            },
            AuditOutcome::success(),
            previous,
            signer,
        ));
    }
    entries
}

#[test]
fn a_well_formed_chain_verifies() {
    let registry = kat_registry();
    let chain = signed_chain(&registry, &key(1), 5);
    assert!(issues(&registry, &chain).is_empty());
    let seqs: Vec<u64> = chain
        .iter()
        .map(|entry| entry.v2.as_ref().unwrap().seq)
        .collect();
    assert_eq!(seqs, [1, 2, 3, 4, 5]);
}

#[test]
fn a_removed_entry_shows_as_a_sequence_gap() {
    let registry = kat_registry();
    let mut chain = signed_chain(&registry, &key(1), 5);
    let removed = chain.remove(2);
    let found = issues(&registry, &chain);
    assert!(found.iter().any(|issue| matches!(
        issue,
        ChainIssue::SequenceGap { entry_id, expected: 3, actual: 4 } if *entry_id == chain[2].id
    )));
    assert!(
        found
            .iter()
            .any(|issue| matches!(issue, ChainIssue::BrokenLink { .. }))
    );
    assert_ne!(removed.id, chain[2].id);
}

#[test]
fn a_wrong_sequence_number_is_caught_even_with_an_intact_link() {
    // Even the registered key cannot sign a skipped or repeated position.
    let registry = kat_registry();
    let mut chain = signed_chain(&registry, &key(1), 3);
    let mut skipped = chain[2].clone();
    skipped.v2.as_mut().unwrap().seq = 7;
    chain[2] = resign(skipped, &key(1));
    let found = issues(&registry, &chain);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(matches!(
        found[0],
        ChainIssue::SequenceGap {
            expected: 3,
            actual: 7,
            ..
        }
    ));

    // A first entry cannot claim a later position without a prune anchor.
    let mut late_start = signed_chain(&registry, &key(1), 1);
    late_start[0].v2.as_mut().unwrap().seq = 4;
    late_start[0] = resign(late_start[0].clone(), &key(1));
    assert!(issues(&registry, &late_start).iter().any(|issue| matches!(
        issue,
        ChainIssue::SequenceGap {
            expected: 1,
            actual: 4,
            ..
        }
    )));
}

#[test]
fn a_chain_rewritten_under_an_unregistered_key_is_rejected() {
    let registry = kat_registry();
    let rogue = key(0x55);
    // A consistent chain whose embedded key verifies every signature: v1
    // verification would accept it.
    let forged = signed_chain(&registry, &rogue, 3);
    assert!(forged.iter().all(|entry| entry.verify_signature().is_ok()));
    let found = issues(&registry, &forged);
    assert_eq!(
        found
            .iter()
            .filter(|issue| matches!(issue, ChainIssue::UnregisteredKey { .. }))
            .count(),
        3
    );
    // The runtime key is registered, but not for the audit role.
    assert!(!issues(&registry, &signed_chain(&registry, &key(2), 1)).is_empty());
    // Without a registry no v2 entry verifies.
    let honest = signed_chain(&registry, &key(1), 1);
    assert!(
        !ChainVerifier::new(None)
            .verify(&honest, ChainStart::Genesis)
            .valid
    );
}

#[test]
fn a_chain_from_another_registry_is_rejected() {
    let registry = kat_registry();
    let other = KeyRegistry::from_records(vec![
        KeyRegistry::genesis_record(at(KAT_GENESIS_SECONDS, 5), &[(KeyRole::Audit, &key(1))])
            .unwrap(),
    ])
    .unwrap();
    // Same audit key, different registry: the chain id no longer derives.
    let transplanted = signed_chain(&other, &key(1), 2);
    let found = issues(&registry, &transplanted);
    assert!(
        found
            .iter()
            .any(|issue| matches!(issue, ChainIssue::ChainIdMismatch { .. }))
    );
}

#[test]
fn rotation_keeps_old_entries_valid_and_bounds_the_retired_key() {
    let mut registry = kat_registry();
    let old = key(1);
    let new = key(0x11);
    let before = signed_chain(&registry, &old, 2);
    let record = registry
        .rotation_record(KeyRole::Audit, &old, &new, at(KAT_GENESIS_SECONDS, 1))
        .unwrap();
    registry.push(record).unwrap();

    let mut chain = before;
    let after = next_entry(&registry, chain.last().unwrap(), &new);
    assert_eq!(after.v2.as_ref().unwrap().key_epoch, 1);
    chain.push(after);
    assert!(
        issues(&registry, &chain).is_empty(),
        "{:?}",
        issues(&registry, &chain)
    );

    // The retired key cannot sign at the new epoch...
    let stale = next_entry(&registry, chain.last().unwrap(), &old);
    let mut with_stale = chain.clone();
    with_stale.push(stale);
    assert!(
        issues(&registry, &with_stale)
            .iter()
            .any(|issue| matches!(issue, ChainIssue::UnregisteredKey { .. }))
    );

    // ...and cannot continue the chain by naming the old epoch either.
    let mut backdated = next_entry(&registry, chain.last().unwrap(), &old);
    backdated.v2.as_mut().unwrap().key_epoch = 0;
    let backdated = resign(backdated, &old);
    let mut with_backdated = chain.clone();
    with_backdated.push(backdated);
    assert!(
        issues(&registry, &with_backdated)
            .iter()
            .any(|issue| matches!(issue, ChainIssue::KeyEpochRegression { .. }))
    );
}

#[test]
fn v1_history_links_into_a_v2_chain_and_v1_cannot_follow() {
    let registry = kat_registry();
    let runtime = key(2);
    let mut chain = v1_entries(&runtime, 3);
    let mut opening = draft(
        &registry,
        &kat_session(),
        Some(alice()),
        None,
        AuditAction::FileRead { path: "/v2".into() },
    );
    opening.previous_hash = chain.last().unwrap().content_hash();
    chain.push(AuditEntry::create_v2(opening, &key(1)).unwrap());
    let next = next_entry(&registry, chain.last().unwrap(), &key(1));
    chain.push(next);
    assert!(
        issues(&registry, &chain).is_empty(),
        "{:?}",
        issues(&registry, &chain)
    );

    // With a registry, v1 entries must be signed by the registered v1 key:
    // a v1 chain rewritten under another key no longer verifies. Without a
    // registry, or with the check turned off, v1 keeps its embedded-key rule.
    let foreign_v1 = v1_entries(&key(0x55), 1);
    let found = issues(&registry, &foreign_v1);
    assert!(
        found
            .iter()
            .any(|issue| matches!(issue, ChainIssue::UnregisteredKey { .. })),
        "{found:?}"
    );
    assert!(
        ChainVerifier::new(Some(&registry))
            .require_registered_v1_keys(false)
            .verify(&foreign_v1, ChainStart::Genesis)
            .valid
    );
    assert!(
        ChainVerifier::new(None)
            .verify(&foreign_v1, ChainStart::Genesis)
            .valid
    );

    // A v2 chain opening after v1 must start at 1.
    let mut late = chain.clone();
    late[3].v2.as_mut().unwrap().seq = 2;
    late[3] = resign(late[3].clone(), &key(1));
    assert!(issues(&registry, &late[..4]).iter().any(|issue| matches!(
        issue,
        ChainIssue::SequenceGap {
            expected: 1,
            actual: 2,
            ..
        }
    )));

    // A v1 entry after the v2 entries is a downgrade.
    let mut downgraded = chain.clone();
    let last_hash = downgraded.last().unwrap().content_hash();
    downgraded.push(AuditEntry::create_with_principal(
        kat_session(),
        alice(),
        AuditAction::FileRead {
            path: "/v1-again".into(),
        },
        AuthorizationProof::System {
            reason: "test".into(),
        },
        AuditOutcome::success(),
        last_hash,
        &runtime,
    ));
    assert!(
        issues(&registry, &downgraded)
            .iter()
            .any(|issue| matches!(issue, ChainIssue::FormatDowngrade { .. }))
    );
}

#[test]
fn a_detached_segment_checks_everything_but_its_first_link() {
    let registry = kat_registry();
    let chain = signed_chain(&registry, &key(1), 4);
    let verifier = ChainVerifier::new(Some(&registry));
    assert!(verifier.verify(&chain[2..], ChainStart::Detached).valid);
    assert!(
        verifier
            .verify(&chain[2..], ChainStart::After(&chain[1]))
            .valid
    );
    assert!(
        !verifier
            .verify(&chain[2..], ChainStart::After(&chain[0]))
            .valid
    );
    assert!(!verifier.verify(&chain[2..], ChainStart::Genesis).valid);
}
