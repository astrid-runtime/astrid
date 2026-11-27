//! Startup fences for retained, renamed, and legacy retirement reservations.

use std::sync::Arc;

use astrid_approval::{Allowance, AllowanceId, AllowancePattern, AllowanceStore};
use astrid_capabilities::CapabilityStore;
use astrid_core::{PrincipalId, PrincipalUid, types::Timestamp};
use astrid_crypto::KeyPair;
use astrid_storage::{MemoryKvStore, OwnershipStore, PrincipalDirectory};

fn grant(alias: &PrincipalId) -> Allowance {
    Allowance {
        id: AllowanceId::new(),
        principal: alias.clone(),
        action_pattern: AllowancePattern::ServerTools {
            server: "test".to_owned(),
        },
        created_at: Timestamp::now(),
        expires_at: None,
        max_uses: None,
        uses_remaining: None,
        session_only: true,
        workspace_root: None,
        signature: KeyPair::generate().sign(b"recovery"),
    }
}

#[tokio::test]
async fn restored_fences_cover_legacy_and_renamed_reservations_in_both_stores() {
    let retained = PrincipalId::new("retained").unwrap();
    let renamed = PrincipalId::new("renamed").unwrap();
    let legacy = PrincipalId::new("legacy").unwrap();
    let unrelated = PrincipalId::new("unrelated").unwrap();
    let renamed_uid = PrincipalUid::from_bytes([1; 32]);
    let legacy_uid = PrincipalUid::from_bytes([2; 32]);

    let reserved = PrincipalDirectory::default();
    reserved.register(retained.clone(), renamed_uid).unwrap();
    reserved.register(legacy.clone(), legacy_uid).unwrap();
    let ownership = OwnershipStore::new(Arc::new(MemoryKvStore::new()), reserved).unwrap();
    drop(
        ownership
            .guard_principal_deletion_for_alias(renamed_uid, retained.clone())
            .await
            .unwrap(),
    );
    drop(
        ownership
            .guard_principal_deletion(legacy_uid)
            .await
            .unwrap(),
    );
    let snapshot = ownership.load().await.unwrap();

    let recovered = PrincipalDirectory::default();
    recovered.register(renamed.clone(), renamed_uid).unwrap();
    recovered.register(legacy.clone(), legacy_uid).unwrap();
    recovered
        .register(unrelated.clone(), PrincipalUid::from_bytes([3; 32]))
        .unwrap();

    let allowances = AllowanceStore::new();
    let cases = [
        (retained, true),
        (renamed, true),
        (legacy, true),
        (unrelated, false),
    ];
    for (alias, _) in &cases {
        allowances.add_allowance(grant(alias)).unwrap();
    }
    let (capabilities, allowances) = super::authority_recovery::restore_retirement_fences(
        &snapshot,
        &recovered,
        CapabilityStore::in_memory(),
        allowances,
    )
    .unwrap();

    for (alias, expected) in cases {
        assert_eq!(capabilities.is_principal_retiring(&alias).await, expected);
        assert_eq!(allowances.count_for(&alias), usize::from(!expected));
        let result = allowances.add_allowance(grant(&alias));
        if expected {
            assert!(matches!(
                result,
                Err(astrid_approval::ApprovalError::Storage(message))
                    if message == format!("principal {alias} is retiring")
            ));
        } else {
            result.unwrap();
        }
    }
}
