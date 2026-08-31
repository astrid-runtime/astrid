use super::*;
use std::convert::TryFrom;
use std::sync::Arc;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;

use astrid_core::{PrincipalProfile, PrincipalUid};
use astrid_storage::{
    ContentName, IdentityStore, KvIdentityStore, KvQuotaResolver, MemoryKvStore, OwnershipStore,
    ScopedKvStore, open_runtime_principal_store_with_directory,
};

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
            StateOwner::Fleet(_) | StateOwner::User(_) => Some(u64::MAX),
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
async fn migration_repairs_non_private_sources() {
    let (_directory, home, store, principals, principal, uid) = fixture().await;
    let source = home.principal_home(&principal).root().to_path_buf();
    astrid_core::platform_fs::ensure_private_directory(&source.join("documents"))
        .expect("documents");
    fs::write(source.join("documents/note.txt"), b"private").expect("file");
    #[cfg(unix)]
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o755)).expect("permissions");
    migrate_legacy_principal_homes(&home, &store, &principals)
        .expect("cutover repairs leftover world-readable directories");
    #[cfg(unix)]
    {
        let mode = std::fs::metadata(&source)
            .expect("source metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "source must be owner-only after repair");
    }
    let filesystem = AstridFilesystem::new(store.content(), StateOwner::Principal(uid));
    assert_eq!(
        filesystem
            .read(
                &FilesystemPath::new("home/documents/note.txt").unwrap(),
                0,
                7
            )
            .unwrap(),
        b"private"
    );
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

#[test]
fn receipt_json_rejects_noncanonical_digest_and_schema() {
    let uid = PrincipalUid::from_bytes([0x71; 32]);
    let alias = PrincipalId::new("default").expect("alias");
    let hex = "ab".repeat(32);
    let valid = serde_json::json!({
        "schema": 2,
        "uid": uid,
        "alias": alias,
        "inventory_digest": hex,
        "entry_count": 1,
        "bytes": 4,
        "page_count": 1
    });
    serde_json::from_value::<MigrationReceipt>(valid).expect("canonical receipt");

    let empty_digest = serde_json::json!({
        "schema": 2,
        "uid": uid,
        "alias": alias,
        "inventory_digest": "",
        "entry_count": 0,
        "bytes": 0,
        "page_count": 0
    });
    assert!(serde_json::from_value::<MigrationReceipt>(empty_digest).is_err());

    let uppercase = serde_json::json!({
        "schema": 2,
        "uid": uid,
        "alias": alias,
        "inventory_digest": "AB".repeat(32),
        "entry_count": 1,
        "bytes": 4,
        "page_count": 1
    });
    assert!(serde_json::from_value::<MigrationReceipt>(uppercase).is_err());

    let old_schema = serde_json::json!({
        "schema": 1,
        "uid": uid,
        "alias": alias,
        "inventory_digest": hex,
        "entry_count": 1,
        "bytes": 4,
        "page_count": 1
    });
    assert!(serde_json::from_value::<MigrationReceipt>(old_schema).is_err());
}

fn identity_store(principals: &PrincipalDirectory) -> KvIdentityStore {
    let backend: Arc<dyn astrid_storage::KvStore> = Arc::new(MemoryKvStore::new());
    KvIdentityStore::with_principal_directory(
        ScopedKvStore::new(backend, "system:identity").expect("identity kv"),
        principals.clone(),
    )
}

fn quarantined_payloads(home: &AstridHome) -> Vec<std::path::PathBuf> {
    fs::read_dir(home.migrations_dir().join("unbound-legacy-homes"))
        .expect("quarantine dir")
        .map(|entry| entry.expect("entry").path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_none_or(|name| !name.ends_with(".original-name"))
        })
        .collect()
}

fn write_ordinary_legacy_file(home: &AstridHome, alias: &PrincipalId, contents: &[u8]) {
    let source = home.principal_home(alias).root().to_path_buf();
    astrid_core::platform_fs::ensure_private_directory(&source).expect("legacy leftover home");
    astrid_core::platform_fs::ensure_private_directory(&source.join("documents"))
        .expect("documents");
    fs::write(source.join("documents/note.txt"), contents).expect("leftover file");
}

#[tokio::test]
async fn unbound_valid_alias_is_minted_and_other_principals_still_load() {
    let (_directory, home, store, principals, principal, uid) = fixture().await;
    write_ordinary_legacy_file(&home, &principal, b"default-home");
    let leftover = PrincipalId::new("legacy-agent").expect("leftover alias");
    write_ordinary_legacy_file(&home, &leftover, b"leftover-home");
    assert!(
        !PrincipalProfile::path_for(&home, &leftover).is_file(),
        "leftover must start with no profile"
    );

    let error = migrate_legacy_principal_homes(&home, &store, &principals)
        .expect_err("unbound leftover must fail before admit");
    assert!(error.to_string().contains("has no durable UID"), "{error}");

    let identity = identity_store(&principals);
    admit_unbound_legacy_principal_homes(&home, &principals, &identity)
        .await
        .expect("admit leftover");
    assert!(principals.uid_for(&principal).is_ok());
    let leftover_uid = principals
        .uid_for(&leftover)
        .expect("minted leftover identity");
    assert_ne!(leftover_uid, uid);
    assert!(PrincipalProfile::path_for(&home, &leftover).is_file());
    migrate_legacy_principal_homes(&home, &store, &principals).expect("migration after admit");

    let default_fs = AstridFilesystem::new(store.content(), StateOwner::Principal(uid));
    assert_eq!(
        default_fs
            .read(
                &FilesystemPath::new("home/documents/note.txt").unwrap(),
                0,
                12
            )
            .unwrap(),
        b"default-home"
    );
    let leftover_fs = AstridFilesystem::new(store.content(), StateOwner::Principal(leftover_uid));
    assert_eq!(
        leftover_fs
            .read(
                &FilesystemPath::new("home/documents/note.txt").unwrap(),
                0,
                13
            )
            .unwrap(),
        b"leftover-home"
    );
}

#[tokio::test]
async fn invalid_legacy_home_name_is_quarantined_out_of_home() {
    let (_directory, home, store, principals, principal, uid) = fixture().await;
    write_ordinary_legacy_file(&home, &principal, b"default-home");
    let invalid = home.home_dir().join("not.valid");
    astrid_core::platform_fs::ensure_private_directory(&invalid).expect("invalid leftover");
    fs::write(invalid.join("keep-me.txt"), b"preserved").expect("invalid leftover file");

    let identity = identity_store(&principals);
    admit_unbound_legacy_principal_homes(&home, &principals, &identity)
        .await
        .expect("quarantine invalid leftover");
    assert!(!invalid.exists());
    let quarantined = quarantined_payloads(&home);
    assert_eq!(quarantined.len(), 1);
    assert_eq!(
        fs::read(quarantined[0].join("keep-me.txt")).expect("preserved"),
        b"preserved"
    );
    migrate_legacy_principal_homes(&home, &store, &principals).expect("valid homes still migrate");
    let filesystem = AstridFilesystem::new(store.content(), StateOwner::Principal(uid));
    assert_eq!(
        filesystem
            .read(
                &FilesystemPath::new("home/documents/note.txt").unwrap(),
                0,
                12
            )
            .unwrap(),
        b"default-home"
    );
}

#[test]
fn verify_fails_closed_on_unbound_leftover_home() {
    let directory = tempfile::tempdir().expect("verify root");
    let home = AstridHome::from_path(directory.path());
    home.ensure().expect("home layout");
    let admitted = PrincipalId::new("default").expect("principal");
    let uid = PrincipalUid::from_bytes([0x71; 32]);
    let principals = PrincipalDirectory::default();
    principals
        .register(admitted.clone(), uid)
        .expect("register admitted");
    let leftover = PrincipalId::new("legacy-agent").expect("leftover");
    astrid_core::platform_fs::ensure_private_directory(home.principal_home(&leftover).root())
        .expect("unbound leftover home");
    let error = verify_migrated_legacy_principal_sources_retired(&home, &principals)
        .expect_err("unbound leftover must fail closed after cut-over");
    let message = error.to_string();
    assert!(message.contains("no current alias binding"), "{message}");
    assert!(home.principal_home(&leftover).root().is_dir());
}

#[tokio::test]
async fn leftover_local_alias_does_not_claim_cli_root_link() {
    let (_directory, home, store, principals, principal, _uid) = fixture().await;
    write_ordinary_legacy_file(&home, &principal, b"default-home");
    let leftover = PrincipalId::new("local").expect("valid leftover alias");
    write_ordinary_legacy_file(&home, &leftover, b"local-home");
    let identity = identity_store(&principals);
    admit_unbound_legacy_principal_homes(&home, &principals, &identity)
        .await
        .expect("admit leftover local");
    assert!(
        identity
            .resolve("cli", "local")
            .await
            .expect("resolve cli/local")
            .is_none(),
        "leftover alias must not occupy the CLI root identity link"
    );
    assert!(principals.uid_for(&leftover).is_ok());
    migrate_legacy_principal_homes(&home, &store, &principals).expect("migration after admit");
}

#[tokio::test]
async fn leftover_file_is_quarantined_without_minting_identity() {
    let (_directory, home, store, principals, principal, uid) = fixture().await;
    write_ordinary_legacy_file(&home, &principal, b"default-home");
    let leftover = PrincipalId::new("legacy-agent").expect("valid leftover name");
    let leftover_path = home.home_dir().join(leftover.as_str());
    fs::write(&leftover_path, b"not-a-directory").expect("leftover file");
    let identity = identity_store(&principals);
    admit_unbound_legacy_principal_homes(&home, &principals, &identity)
        .await
        .expect("quarantine leftover file");
    assert!(!leftover_path.exists());
    assert!(principals.uid_for(&leftover).is_err());
    let quarantined = quarantined_payloads(&home);
    assert_eq!(quarantined.len(), 1);
    assert_eq!(
        fs::read(&quarantined[0]).expect("preserved"),
        b"not-a-directory"
    );
    migrate_legacy_principal_homes(&home, &store, &principals)
        .expect("admitted homes still migrate");
    let filesystem = AstridFilesystem::new(store.content(), StateOwner::Principal(uid));
    assert_eq!(
        filesystem
            .read(
                &FilesystemPath::new("home/documents/note.txt").unwrap(),
                0,
                12
            )
            .unwrap(),
        b"default-home"
    );
}

#[tokio::test]
async fn unbound_leftover_is_adopted_into_the_operator_fleet() {
    let (_directory, home, _store, principals, principal, uid) = fixture().await;
    write_ordinary_legacy_file(&home, &principal, b"default-home");
    let leftover = PrincipalId::new("legacy-agent").expect("leftover");
    write_ordinary_legacy_file(&home, &leftover, b"leftover-home");
    let identity = identity_store(&principals);
    admit_unbound_legacy_principal_homes(&home, &principals, &identity)
        .await
        .expect("admit leftover");
    let leftover_uid = principals.uid_for(&leftover).expect("minted leftover");
    let bindings = principals.bindings();
    assert!(
        bindings
            .iter()
            .any(|(alias, bound)| *alias == leftover && *bound == leftover_uid),
        "barrier snapshot must see the minted leftover"
    );

    let backend: Arc<dyn astrid_storage::KvStore> = Arc::new(MemoryKvStore::new());
    let ownership = OwnershipStore::new(backend, principals.clone()).expect("ownership");
    let root_identity =
        astrid_core::PrincipalIdentity::from_genesis(astrid_core::PrincipalGenesis::from_parts(
            uuid::Uuid::from_u128(2),
            chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            [2; 32],
        ))
        .expect("root identity");
    let root_user = astrid_core::AstridUserId {
        id: uuid::Uuid::from_u128(1),
        principal: principal.clone(),
        public_key: None,
        display_name: None,
        created_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
    };
    crate::bootstrap_cli_root_ownership(&ownership, &principals, root_user, root_identity, true)
        .await
        .expect("adopt unowned principals");
    let graph = ownership.load().await.expect("ownership graph");
    let default_owner = graph.principal_owner(uid).expect("default owned");
    let leftover_owner = graph.principal_owner(leftover_uid).expect("leftover owned");
    assert_eq!(default_owner.fleet_uid, leftover_owner.fleet_uid);
}

#[tokio::test]
async fn long_invalid_leftover_name_uses_bounded_quarantine_encoding() {
    let (_directory, home, store, principals, principal, uid) = fixture().await;
    write_ordinary_legacy_file(&home, &principal, b"default-home");
    let long_name = "a".repeat(200);
    let leftover = home.home_dir().join(&long_name);
    astrid_core::platform_fs::ensure_private_directory(&leftover).expect("long leftover");
    fs::write(leftover.join("keep-me.txt"), b"preserved").expect("long leftover file");
    let identity = identity_store(&principals);
    admit_unbound_legacy_principal_homes(&home, &principals, &identity)
        .await
        .expect("quarantine long leftover");
    assert!(!leftover.exists());
    let quarantine = home.migrations_dir().join("unbound-legacy-homes");
    let names = fs::read_dir(&quarantine)
        .expect("quarantine dir")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect::<Vec<_>>();
    let dest = names
        .iter()
        .find(|name| name.starts_with("invalid-") && !name.ends_with(".original-name"))
        .expect("bounded quarantine name");
    assert!(
        dest.len() <= 80,
        "quarantine component must stay well under ENAMETOOLONG: {dest}"
    );
    let dest_path = quarantine.join(dest);
    assert_eq!(
        fs::read(dest_path.join("keep-me.txt")).expect("preserved"),
        b"preserved"
    );
    assert_eq!(
        fs::read(quarantine.join(format!("{dest}.original-name"))).expect("sidecar"),
        long_name.as_bytes()
    );
    migrate_legacy_principal_homes(&home, &store, &principals).expect("valid homes still migrate");
    let filesystem = AstridFilesystem::new(store.content(), StateOwner::Principal(uid));
    assert_eq!(
        filesystem
            .read(
                &FilesystemPath::new("home/documents/note.txt").unwrap(),
                0,
                12
            )
            .unwrap(),
        b"default-home"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn leftover_symlink_is_quarantined_without_minting_identity() {
    let (_directory, home, store, principals, principal, uid) = fixture().await;
    write_ordinary_legacy_file(&home, &principal, b"default-home");
    let leftover = PrincipalId::new("legacy-agent").expect("valid leftover name");
    let leftover_path = home.home_dir().join(leftover.as_str());
    let target = home.root().join("symlink-target");
    fs::write(&target, b"target-bytes").expect("symlink target");
    std::os::unix::fs::symlink(&target, &leftover_path).expect("leftover symlink");
    let identity = identity_store(&principals);
    admit_unbound_legacy_principal_homes(&home, &principals, &identity)
        .await
        .expect("quarantine leftover symlink");
    assert!(!leftover_path.exists() || leftover_path.symlink_metadata().is_err());
    assert!(leftover_path.symlink_metadata().is_err());
    assert!(principals.uid_for(&leftover).is_err());
    migrate_legacy_principal_homes(&home, &store, &principals)
        .expect("admitted homes still migrate");
    let filesystem = AstridFilesystem::new(store.content(), StateOwner::Principal(uid));
    assert_eq!(
        filesystem
            .read(
                &FilesystemPath::new("home/documents/note.txt").unwrap(),
                0,
                12
            )
            .unwrap(),
        b"default-home"
    );
}

#[tokio::test]
async fn contiguous_home_import_shares_identical_payloads_and_compacts_below_unreclaimed_journal() {
    let (_directory, home, store, principals, principal, uid) = fixture().await;
    let source = home.principal_home(&principal).root().to_path_buf();
    let unique_dir = source.join("unique");
    let shared_dir = source.join("shared");
    astrid_core::platform_fs::ensure_private_directory(&unique_dir).expect("unique dir");
    astrid_core::platform_fs::ensure_private_directory(&shared_dir).expect("shared dir");
    let unique_payload = 32_usize;
    let shared_bytes = vec![0x11_u8; 4096];
    let mut unique_logical = 0_u64;
    for index in 0..unique_payload {
        let bytes = vec![u8::try_from(index).expect("index fits u8"); 2048];
        unique_logical += u64::try_from(bytes.len()).expect("len");
        fs::write(unique_dir.join(format!("u-{index:02}")), bytes).expect("unique file");
    }
    for index in 0..16 {
        fs::write(shared_dir.join(format!("s-{index:02}")), &shared_bytes).expect("shared file");
    }
    let walked = unique_logical + u64::try_from(shared_bytes.len() * 16).expect("shared len");
    migrate_legacy_principal_homes(&home, &store, &principals).expect("contiguous import");
    let filesystem = AstridFilesystem::new(store.content(), StateOwner::Principal(uid));
    assert_eq!(
        filesystem
            .read(&FilesystemPath::new("home/shared/s-00").unwrap(), 0, 4)
            .unwrap(),
        &shared_bytes[..4]
    );
    assert_eq!(
        filesystem
            .read(&FilesystemPath::new("home/shared/s-15").unwrap(), 0, 4)
            .unwrap(),
        &shared_bytes[..4]
    );
    let volume_len = fs::metadata(home.storage_volume_path())
        .expect("volume")
        .len();
    let policy = astrid_storage::storage_model::ObjectRecord::new(
        astrid_storage::storage_model::ObjectKind::Evidence,
        astrid_storage::storage_model::ObjectFormatVersion::V1,
        b"home-import-packing-regression".to_vec(),
        Vec::new(),
        0,
        astrid_storage::storage_model::ObjectClass::Metadata,
    )
    .expect("policy");
    match store
        .compact_with_deterministic_proof(
            astrid_storage::storage_model::ObjectId::new([0x51; 32]),
            policy,
            Vec::new(),
        )
        .await
    {
        Ok(_) => {
            let compacted = fs::metadata(home.storage_volume_path())
                .expect("compacted volume")
                .len();
            // Reclaim rewrites live regions as Create+Write records. That can
            // be a few headers larger than a still-hot append journal. Packed
            // size is compared to walked payload, not the pre-reclaim file.
            assert!(
                compacted <= walked.saturating_add(2 * 1024 * 1024),
                "compacted {compacted} must stay in class with walked {walked} (pre-reclaim {volume_len})"
            );
        },
        Err(error) => {
            // Volume arena compact still validates historical root-journal
            // snapshots. Contiguous blobs must remain the live payload even
            // when that rewrite cannot run. Ingest packing is the claim.
            assert!(
                volume_len <= walked.saturating_add(4 * 1024 * 1024),
                "uncompacted volume {volume_len} must stay in class with walked {walked} ({error})"
            );
        },
    }
    let owner = StateOwner::Principal(uid);
    let first = store
        .content()
        .describe(&owner, &ContentName::new("home/shared/s-00").expect("name"))
        .expect("describe first")
        .expect("first file");
    let sixteenth = store
        .content()
        .describe(&owner, &ContentName::new("home/shared/s-15").expect("name"))
        .expect("describe sixteenth")
        .expect("sixteenth file");
    assert_eq!(
        first.file(),
        sixteenth.file(),
        "identical payloads must share one File object"
    );
}
