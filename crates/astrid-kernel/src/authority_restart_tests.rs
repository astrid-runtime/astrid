//! Capability authority across abrupt exit and reopen of hosted storage.

use astrid_approval::{Allowance, AllowanceId, AllowancePattern, AllowanceStore};
use astrid_capabilities::{
    AuditEntryId, CapabilityError, CapabilityStore, CapabilityToken, ResourcePattern, TokenScope,
};
use astrid_core::{Permission, PrincipalId, TokenId, dirs::AstridHome, types::Timestamp};
use astrid_crypto::KeyPair;
use std::io::Write as _;

use std::sync::Arc;

const CHILD_HOME: &str = "ASTRID_AUTHORITY_RESTART_TEST_HOME";
const CRASH_AFTER_COMMIT_EXIT: i32 = 74;

#[tokio::test]
#[ignore = "internal subprocess for the hosted authority restart test"]
async fn commit_authority_changes_and_exit_without_shutdown() {
    let home = AstridHome::from_path(
        std::env::var_os(CHILD_HOME).expect("subprocess needs its isolated storage root"),
    );
    home.ensure().unwrap();
    let (kv, directory, _runtime) = super::open_test_runtime_kv(&home).await;
    let store = CapabilityStore::with_kv_store(Arc::clone(&kv))
        .await
        .unwrap();
    let issuer = KeyPair::generate();
    let mint = |principal, single_use| {
        CapabilityToken::create_with_options(
            ResourcePattern::exact("mcp://test:tool").unwrap(),
            vec![Permission::Invoke],
            TokenScope::Persistent,
            issuer.key_id(),
            AuditEntryId::new(),
            &issuer,
            None,
            single_use,
            principal,
        )
    };
    let revoked = mint(PrincipalId::default(), false);
    let consumed = mint(PrincipalId::default(), true);
    let live = mint(PrincipalId::default(), false);
    let retiring_alias = PrincipalId::new("deletion-in-progress").unwrap();
    let retiring = mint(retiring_alias.clone(), false);
    let retiring_id = retiring.id.clone();
    let (revoked_id, consumed_id, live_id) =
        (revoked.id.clone(), consumed.id.clone(), live.id.clone());
    for token in [revoked, consumed, live, retiring] {
        store.add(token).await.unwrap();
    }
    store.revoke(&revoked_id).await.unwrap();
    store.use_token(&consumed_id).await.unwrap();
    let ownership = astrid_storage::OwnershipStore::new(kv, directory).unwrap();
    let _reservation = ownership
        .guard_legacy_alias_deletion(retiring_alias)
        .await
        .unwrap();

    let mut stdout = std::io::stdout().lock();
    writeln!(
        stdout,
        "committed {} {} {} {}",
        revoked_id.0, consumed_id.0, live_id.0, retiring_id.0
    )
    .unwrap();
    stdout.flush().unwrap();
    // std::process::exit skips the Rust destructors and daemon shutdown.
    std::process::exit(CRASH_AFTER_COMMIT_EXIT);
}

#[tokio::test]
async fn hosted_token_revocation_and_consumption_survive_storage_reopen() {
    let root = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(root.path());
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "authority_restart_tests::commit_authority_changes_and_exit_without_shutdown",
            "--ignored",
            "--nocapture",
        ])
        .env(CHILD_HOME, root.path())
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(
        output.status.code(),
        Some(CRASH_AFTER_COMMIT_EXIT),
        "{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let ids = stdout
        .lines()
        .find_map(|line| line.strip_prefix("committed "))
        .unwrap();
    let mut ids = ids
        .split_whitespace()
        .map(|id| TokenId::from_uuid(id.parse().unwrap()));
    let revoked_id = ids.next().unwrap();
    let consumed_id = ids.next().unwrap();
    let live_id = ids.next().unwrap();
    let retiring_id = ids.next().unwrap();
    assert!(ids.next().is_none());

    let (kv, directory, _runtime) = super::open_test_runtime_kv(&home).await;
    let reopened = CapabilityStore::with_kv_store(Arc::clone(&kv))
        .await
        .unwrap();
    let ownership =
        astrid_storage::OwnershipStore::new(Arc::clone(&kv), directory.clone()).unwrap();
    let snapshot = ownership.load().await.unwrap();
    let retiring_alias = PrincipalId::new("deletion-in-progress").unwrap();
    // The token payload survived, so denial must come from recovered authority.
    assert!(reopened.get(&retiring_id).await.unwrap().is_some());
    let allowances = AllowanceStore::new();
    let allowance = Allowance {
        id: AllowanceId::new(),
        principal: retiring_alias.clone(),
        action_pattern: AllowancePattern::ServerTools {
            server: "test".to_owned(),
        },
        created_at: Timestamp::now(),
        expires_at: None,
        max_uses: None,
        uses_remaining: None,
        session_only: true,
        workspace_root: None,
        signature: KeyPair::generate().sign(b"retirement test allowance"),
    };
    allowances.add_allowance(allowance.clone()).unwrap();
    super::authority_recovery::restore_retirement_fences(
        &snapshot,
        &directory,
        &reopened,
        &allowances,
    )
    .await
    .unwrap();
    assert_eq!(allowances.count_for(&retiring_alias), 0);
    assert!(allowances.add_allowance(allowance).is_err());
    assert!(reopened.is_principal_retiring(&retiring_alias).await);
    assert!(matches!(
        reopened.use_token(&retiring_id).await,
        Err(CapabilityError::TokenNotFound { .. })
    ));
    assert!(matches!(
        reopened.use_token(&revoked_id).await,
        Err(CapabilityError::TokenRevoked { .. })
    ));
    assert!(matches!(
        reopened.use_token(&consumed_id).await,
        Err(CapabilityError::TokenAlreadyUsed { .. })
    ));
    assert!(reopened.use_token(&live_id).await.is_ok());
    drop(reopened);
    kv.close().await.unwrap();
}
