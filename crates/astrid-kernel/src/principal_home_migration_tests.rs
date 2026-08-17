use super::*;
use std::convert::TryFrom;
use std::sync::Arc;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;

use astrid_core::PrincipalUid;
use astrid_storage::{KvQuotaResolver, open_runtime_principal_store_with_directory};

async fn fixture() -> (
    tempfile::TempDir,
    AstridHome,
    RuntimePrincipalStore,
    PrincipalDirectory,
    PrincipalId,
    PrincipalUid,
) {
    let directory = tempfile::tempdir().expect("migration root");
    let home = AstridHome::from_path(directory.path());
    home.ensure().expect("home layout");
    let principal = PrincipalId::new("default").expect("principal");
    let uid = PrincipalUid::from_bytes([0x71; 32]);
    // This test fixture intentionally recreates only the released legacy
    // source root. Normal v2 boot must not scaffold `home/` at all.
    astrid_core::platform_fs::ensure_private_directory(home.principal_home(&principal).root())
        .expect("legacy principal home");
    let principals = PrincipalDirectory::default();
    let quota_principals = principals.clone();
    let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(move |owner: &StateOwner| {
        Ok(match owner {
            StateOwner::System => None,
            StateOwner::Principal(uid) => {
                if quota_principals.contains_uid(*uid) {
                    Some(u64::MAX)
                } else {
                    None
                }
            },
            StateOwner::Fleet(_) => Some(u64::MAX),
        })
    });
    let store = open_runtime_principal_store_with_directory(&home, quota, principals.clone())
        .await
        .expect("store");
    principals
        .register(principal.clone(), uid)
        .expect("register");
    (directory, home, store, principals, principal, uid)
}

#[tokio::test]
async fn v0104_fixture_ordinary_files_publish_and_restart_idempotently() {
    let (_directory, home, store, principals, principal, uid) = fixture().await;
    let source = home.principal_home(&principal).root().to_path_buf();
    astrid_core::platform_fs::ensure_private_directory(&source.join("documents"))
        .expect("documents");
    fs::write(source.join("documents/note.txt"), b"released-home-file").expect("file");
    fs::create_dir_all(source.join(".local/log")).expect("excluded log");
    fs::write(source.join(".local/log/operator.log"), b"operator").expect("log");
    migrate_legacy_principal_homes(&home, &store, &principals).expect("migration");

    let filesystem = AstridFilesystem::new(store.content(), StateOwner::Principal(uid));
    let destination = FilesystemPath::new("home/documents/note.txt").unwrap();
    assert_eq!(
        filesystem
            .read(
                &destination,
                0,
                u64::try_from(b"released-home-file".len()).expect("fixture length fits u64"),
            )
            .unwrap(),
        b"released-home-file"
    );
    assert!(matches!(
        filesystem.stat(&FilesystemPath::new("home/.local/log/operator.log").unwrap()),
        Err(FilesystemError::NotFound(_))
    ));
    let receipt = receipt_path(&home, uid);
    assert!(receipt.is_file());
    migrate_legacy_principal_homes(&home, &store, &principals).expect("restart migration");
    assert_eq!(
        fs::read(source.join("documents/note.txt")).unwrap(),
        b"released-home-file"
    );
}

#[tokio::test]
async fn renamed_alias_keeps_legacy_receipt_discoverable_on_restart() {
    let (_directory, home, store, principals, principal, uid) = fixture().await;
    let source = home.principal_home(&principal).root().to_path_buf();
    astrid_core::platform_fs::ensure_private_directory(&source.join("documents"))
        .expect("documents");
    fs::write(source.join("documents/note.txt"), b"alias-stable").expect("file");
    migrate_legacy_principal_homes(&home, &store, &principals).expect("migration");

    let renamed = PrincipalId::new("renamed").expect("renamed alias");
    principals
        .rename(uid, &principal, renamed)
        .expect("rename alias");
    // The old native source remains until the final coordinated retirement;
    // boot must use the UID receipt rather than rejecting the stale alias.
    migrate_legacy_principal_homes(&home, &store, &principals).expect("restart after alias rename");
    let filesystem = AstridFilesystem::new(store.content(), StateOwner::Principal(uid));
    assert_eq!(
        filesystem
            .read(
                &FilesystemPath::new("home/documents/note.txt").unwrap(),
                0,
                12,
            )
            .unwrap(),
        b"alias-stable"
    );
}

#[tokio::test]
async fn alias_reuse_never_remaps_a_receipted_source() {
    let (_directory, home, store, principals, principal, uid) = fixture().await;
    let source = home.principal_home(&principal).root().to_path_buf();
    astrid_core::platform_fs::ensure_private_directory(&source.join("documents"))
        .expect("documents");
    fs::write(source.join("documents/note.txt"), b"old-owner").expect("file");
    migrate_legacy_principal_homes(&home, &store, &principals).expect("migration");

    let renamed = PrincipalId::new("renamed").expect("renamed alias");
    principals
        .rename(uid, &principal, renamed)
        .expect("rename alias");
    let replacement_uid = PrincipalUid::from_bytes([0x72; 32]);
    principals
        .register(principal.clone(), replacement_uid)
        .expect("reuse old alias");

    let error = migrate_legacy_principal_homes(&home, &store, &principals)
        .expect_err("receipt must not migrate into replacement owner");
    assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(
        fs::read(source.join("documents/note.txt")).unwrap(),
        b"old-owner"
    );
}

#[tokio::test]
async fn migration_rejects_redirected_special_and_non_private_sources() {
    let (_directory, home, store, principals, principal, _uid) = fixture().await;
    let source = home.principal_home(&principal).root().to_path_buf();
    astrid_core::platform_fs::ensure_private_directory(&source.join("documents"))
        .expect("documents");
    fs::write(source.join("documents/note.txt"), b"private").expect("file");
    #[cfg(unix)]
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o644)).expect("permissions");
    #[cfg(unix)]
    assert!(migrate_legacy_principal_homes(&home, &store, &principals).is_err());
}

#[tokio::test]
async fn dedicated_paths_are_not_imported_and_conflicts_preflight_before_writes() {
    let (_directory, home, store, principals, principal, uid) = fixture().await;
    let source = home.principal_home(&principal).root().to_path_buf();
    for path in [
        ".config/env",
        ".local/capsules",
        ".local/audit",
        ".local/tmp",
        ".local/kv",
        ".local/tokens",
        ".local/log",
    ] {
        let path = source.join(path).join("entry");
        if let Some(parent) = path.parent() {
            astrid_core::platform_fs::ensure_private_directory(parent).expect("dedicated dir");
        }
        fs::write(path, b"dedicated").expect("dedicated file");
    }
    astrid_core::platform_fs::ensure_private_directory(&source.join("documents"))
        .expect("documents");
    fs::write(source.join("documents/ok"), b"ok").expect("ordinary");

    let filesystem = AstridFilesystem::new(store.content(), StateOwner::Principal(uid));
    filesystem
        .create_dir(&FilesystemPath::new("home").unwrap())
        .unwrap();
    filesystem
        .create_dir(&FilesystemPath::new("home/documents").unwrap())
        .unwrap();
    filesystem
        .write(
            &FilesystemPath::new("home/documents/ok").unwrap(),
            b"different",
        )
        .unwrap();
    assert!(migrate_legacy_principal_homes(&home, &store, &principals).is_err());
    assert!(matches!(
        filesystem.stat(&FilesystemPath::new("home/other").unwrap()),
        Err(FilesystemError::NotFound(_))
    ));
    for path in [
        "home/.config/env/entry",
        "home/.local/capsules/entry",
        "home/.local/audit/entry",
        "home/.local/tmp/entry",
        "home/.local/kv/entry",
        "home/.local/tokens/entry",
        "home/.local/log/entry",
    ] {
        assert!(matches!(
            filesystem.stat(&FilesystemPath::new(path).unwrap()),
            Err(FilesystemError::NotFound(_))
        ));
    }
}

#[tokio::test]
async fn large_file_readback_is_chunked() {
    let (_directory, home, store, principals, principal, uid) = fixture().await;
    let source = home.principal_home(&principal).root().to_path_buf();
    astrid_core::platform_fs::ensure_private_directory(&source.join("documents"))
        .expect("documents");
    let readback_chunk = usize::try_from(READBACK_CHUNK_BYTES).expect("chunk fits usize");
    let bytes = vec![0x5a; (readback_chunk * 2) + 17];
    fs::write(source.join("documents/large.bin"), &bytes).expect("large file");
    migrate_legacy_principal_homes(&home, &store, &principals).expect("large migration");
    let filesystem = AstridFilesystem::new(store.content(), StateOwner::Principal(uid));
    let path = FilesystemPath::new("home/documents/large.bin").unwrap();
    assert_eq!(
        filesystem.stat(&path).unwrap().logical_bytes(),
        u64::try_from(bytes.len()).expect("fixture length fits u64")
    );
}

#[tokio::test]
async fn large_entry_count_uses_bounded_receipt_pages() {
    let (_directory, home, store, principals, principal, uid) = fixture().await;
    let source = home.principal_home(&principal).root().to_path_buf();
    let documents = source.join("documents");
    astrid_core::platform_fs::ensure_private_directory(&documents).expect("documents");
    for index in 0..=PAGE_ENTRY_LIMIT {
        fs::write(
            documents.join(format!("entry-{index:04}")),
            index.to_string(),
        )
        .expect("file");
    }
    migrate_legacy_principal_homes(&home, &store, &principals).expect("large migration");

    let receipt: MigrationReceipt =
        serde_json::from_slice(&fs::read(receipt_path(&home, uid)).expect("receipt"))
            .expect("receipt JSON");
    assert_eq!(
        receipt.entry_count,
        u64::try_from(PAGE_ENTRY_LIMIT + 2).expect("fixture count fits u64")
    );
    assert_eq!(receipt.page_count, 2);
    assert!(page_path(&home, uid, 0).is_file());
    assert!(page_path(&home, uid, 1).is_file());
}

#[tokio::test]
async fn interrupted_page_publication_restarts_and_receipt_tampering_fails_closed() {
    let (_directory, home, store, principals, principal, uid) = fixture().await;
    let source = home.principal_home(&principal).root().to_path_buf();
    astrid_core::platform_fs::ensure_private_directory(&source.join("documents"))
        .expect("documents");
    fs::write(source.join("documents/note.txt"), b"receipt-check").expect("file");
    migrate_legacy_principal_homes(&home, &store, &principals).expect("migration");

    // A crash after durable pages but before the index receipt is recoverable.
    fs::remove_file(receipt_path(&home, uid)).expect("remove index");
    assert!(page_path(&home, uid, 0).is_file());
    migrate_legacy_principal_homes(&home, &store, &principals).expect("restart migration");
    assert!(receipt_path(&home, uid).is_file());

    // A malformed page is never silently accepted on restart.
    let page = page_path(&home, uid, 0);
    let mut bytes = fs::read(&page).expect("page");
    bytes[0] = b'!';
    fs::write(&page, bytes).expect("tamper page");
    assert!(migrate_legacy_principal_homes(&home, &store, &principals).is_err());
}
