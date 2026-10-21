use super::*;
use astrid_storage::{KvIdentityStore, ScopedKvStore};

#[tokio::test]
async fn log_preflight_above_generic_byte_budget_preserves_all_bytes() {
    let root = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(root.path().join("runtime"));
    home.ensure().unwrap();
    let directory = PrincipalDirectory::default();
    let store = astrid_storage::open_runtime_principal_store_with_directory(
        &home,
        Arc::new(|_: &astrid_storage::StateOwner| Ok(None)),
        directory.clone(),
    )
    .await
    .unwrap();
    let identities = KvIdentityStore::with_principal_directory(
        ScopedKvStore::new(store.kv(), "system:identity").unwrap(),
        directory.clone(),
    );
    let alias = PrincipalId::new("alice").unwrap();
    let principal = identities
        .create_principal(alias.clone(), [0x49; 32])
        .await
        .unwrap();
    let uid = identities
        .get_principal_identity(principal.id)
        .await
        .unwrap()
        .unwrap()
        .uid;
    let source = home.principal_home(&alias).log_dir();
    astrid_core::platform_fs::ensure_private_directory(&source).unwrap();
    let file = source.join("removed-capsule.log");
    astrid_core::platform_fs::atomic_write_private_file(&file, b"").unwrap();
    let length = MAX_BYTES + 1;
    let handle = fs::OpenOptions::new().write(true).open(&file).unwrap();
    handle.set_len(length).unwrap();
    handle.sync_all().unwrap();
    drop(handle);

    let sources = preflight_sources(&home, &store, &directory.bindings()).unwrap();
    let captured = &sources[&format!("principal:{uid}:logs")];
    assert!(captured.present);
    assert_eq!(captured.bytes.get(), length);
    assert_eq!(captured.entries.get(), 1);
    assert!(
        snapshot_path(&source).is_err(),
        "other component budgets remain enforced"
    );

    crate::principal_log_migration::migrate_legacy_principal_logs(&home, &directory).unwrap();
    assert!(!source.exists());
    let destination = home
        .log_dir()
        .join("principals")
        .join(uid.to_string())
        .join("removed-capsule.log");
    assert_eq!(fs::metadata(&destination).unwrap().len(), length);
    assert_eq!(
        snapshot_log_path(destination.parent().unwrap()).unwrap(),
        *captured
    );
    let proof = crate::principal_log_migration::legacy_log_destination_proof(&home, uid).unwrap();
    assert_ne!(proof, "absent");
    crate::principal_log_migration::migrate_legacy_principal_logs(&home, &directory).unwrap();
    assert_eq!(
        crate::principal_log_migration::legacy_log_destination_proof(&home, uid).unwrap(),
        proof
    );
}
