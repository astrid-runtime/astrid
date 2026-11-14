use std::sync::Arc;

use super::*;
use crate::{KvQuotaResolver, open_runtime_principal_store};

fn quota() -> Arc<dyn KvQuotaResolver<StateOwner>> {
    Arc::new(|_: &StateOwner| Ok(None))
}

async fn fixture() -> (tempfile::TempDir, AstridHome, RuntimePrincipalStore) {
    let (directory, home) = super::super::lifecycle_tests::fixture();
    let store = open_runtime_principal_store(&home, quota()).await.unwrap();
    // A completed public open creates staging after ACTIVE publication. Admit
    // that real journal through the normal lifecycle before modelling a stop.
    store.publish_runtime_projection(&home).unwrap();
    (directory, home, store)
}

async fn stop(store: RuntimePrincipalStore) {
    store.kv().close().await.unwrap();
    drop(store);
}

async fn recover(home: &AstridHome, names: &[String]) -> RuntimePrincipalStore {
    crate::principal_state::open_runtime_principal_store_recovering_projection(
        home,
        quota(),
        crate::PrincipalDirectory::default(),
        |recovery| {
            // This public read-only callback is reached only after authenticating
            // the complete same-root RETIRING inventory, before staging opens.
            for name in names {
                assert_eq!(
                    recovery
                        .read(&ContentName::new(name.clone()).unwrap(), 0)
                        .map_err(std::io::Error::other)?,
                    Some(Vec::new())
                );
            }
            Ok(())
        },
    )
    .await
    .unwrap()
}

fn log(uid: char, day: &str) -> String {
    format!("{PREFIX}{}/capsule/{day}.log", uid.to_string().repeat(64))
}

fn put(store: &RuntimePrincipalStore, name: &str, bytes: &[u8]) {
    store
        .content()
        .put(&StateOwner::System, &ContentName::new(name).unwrap(), bytes)
        .unwrap();
}

fn project(home: &AstridHome, name: &str, bytes: &[u8]) {
    super::super::write_projection_file(home.root(), name, bytes).unwrap();
}

fn read(store: &RuntimePrincipalStore, name: &str) -> Vec<u8> {
    store
        .content()
        .read(&StateOwner::System, &ContentName::new(name).unwrap())
        .unwrap()
        .unwrap()
}

fn catalog(
    store: &RuntimePrincipalStore,
) -> Vec<(ContentName, crate::storage_model::ObjectId, u64)> {
    store
        .content()
        .list(&StateOwner::System)
        .unwrap()
        .into_iter()
        .filter(|entry| !super::super::is_excluded(entry.name().as_str()))
        .map(|entry| (entry.name().clone(), entry.file(), entry.logical_bytes()))
        .collect()
}

fn restore(home: &AstridHome, store: &RuntimePrincipalStore) -> StorageResult<()> {
    restoration::restore_projection(home, store, &store.content())
}

fn selection(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
) -> (RootState, Vec<ContentEntry>, EmptyLogs) {
    let root = current_root(home, store).unwrap();
    let entries = restoration::projection_entries(home, &store.content()).unwrap();
    let empty = EmptyLogs::authenticate(home, &store.content(), &entries).unwrap();
    (root, entries, empty)
}

#[test]
fn canonical_group_names_require_exact_uid_and_unambiguous_real_dates() {
    assert!(canonical_log("capsule/2024-02-29.log"));
    for invalid in [
        "capsule/2023-02-29.log",
        "capsule/2026-2-01.log",
        "capsule/2026-02-1.log",
        "capsule/2026-11-14.LOG",
        "capsule/+2026-11-14.log",
        "capsule/2026-13-01.log",
        "capsule/2026-11-14.log/",
        "capsule/sub/2026-11-14.log",
        "./2026-11-14.log",
        "/2026-11-14.log",
    ] {
        assert!(!canonical_log(invalid), "{invalid}");
    }
    assert!(group_name(&log('a', "2026-11-14")).is_some());
    assert!(group_name(&log('A', "2026-11-14")).is_none());
    assert!(group_name("log/principals/abcd/capsule/2026-11-14.log").is_none());
    assert!(group_name(&format!("{PREFIX}{}/", "a".repeat(64))).is_some());
    assert!(
        !canonical_log(""),
        "a UID directory marker must reject the group"
    );
}

#[tokio::test]
async fn public_restore_omits_only_empty_groups_and_preserves_catalog_on_pack_reopen() {
    let (_directory, home, store) = fixture().await;
    let names = [log('a', "2026-11-13"), log('a', "2026-11-14")];
    for name in &names {
        put(&store, name, b"");
    }
    put(&store, "empty-generic.conf", b"");
    let before = catalog(&store);
    stop(store).await;
    let store = open_runtime_principal_store(&home, quota()).await.unwrap();
    assert_eq!(catalog(&store), before);
    for name in &names {
        assert!(!home.root().join(name).exists());
        assert!(read(&store, name).is_empty());
    }
    assert!(home.root().join("empty-generic.conf").is_file());
    super::super::establish_active_receipt(&home, &store).unwrap();
    let receipt = super::super::active::read(&home, &store).unwrap().unwrap();
    for name in &names {
        assert!(!receipt.contains_inventory_name(name));
    }
    store.pack_and_retire_runtime_projection(&home).unwrap();
    let packed = catalog(&store);
    assert_eq!(packed, before);
    drop(store);

    for _ in 0..2 {
        let reopened = open_runtime_principal_store(&home, quota()).await.unwrap();
        assert_eq!(catalog(&reopened), packed);
        for name in &names {
            assert!(!home.root().join(name).exists());
            assert!(read(&reopened, name).is_empty());
        }
        assert!(home.root().join("empty-generic.conf").is_file());
        reopened.pack_and_retire_runtime_projection(&home).unwrap();
        drop(reopened);
    }
}

#[tokio::test]
async fn surviving_active_boot_removes_old_empty_groups_after_latest_publication() {
    let (_directory, home, store) = fixture().await;
    let name = log('a', "2026-11-14");
    project(&home, &name, b"");
    project(&home, "config.toml", b"old");
    store.publish_runtime_projection(&home).unwrap();
    std::fs::write(home.root().join("config.toml"), b"newest").unwrap();
    stop(store).await;
    let store = open_runtime_principal_store(&home, quota()).await.unwrap();
    assert!(!home.root().join(&name).exists());
    assert!(read(&store, &name).is_empty());
    assert_eq!(read(&store, "config.toml"), b"newest");
    assert_eq!(
        std::fs::read(home.root().join("config.toml")).unwrap(),
        b"newest"
    );
    let receipt = super::super::active::read(&home, &store).unwrap().unwrap();
    assert_eq!(receipt.phase(), super::super::ReceiptPhase::Active);
    assert!(!receipt.contains_inventory_name(&name));
}

#[tokio::test]
async fn mixed_history_explicit_markers_and_noncanonical_empty_logs_stay_eager() {
    let (_directory, home, store) = fixture().await;
    let historical = log('a', "2026-11-13");
    let newest = log('a', "2026-11-14");
    put(&store, &historical, b"retained history\n");
    put(&store, &newest, b"");
    let uid_marker = format!("{PREFIX}{}/", "b".repeat(64));
    let marked = log('b', "2026-11-14");
    put(&store, &uid_marker, b"");
    put(&store, &marked, b"");
    let child_marker = format!("{PREFIX}{}/capsule/", "c".repeat(64));
    let log_under_marker = log('c', "2026-11-14");
    put(&store, &child_marker, b"");
    put(&store, &log_under_marker, b"");
    let noncanonical = log('d', "2026-2-01");
    let companion = log('d', "2026-11-14");
    put(&store, &noncanonical, b"");
    put(&store, &companion, b"");
    let uppercase_uid = log('E', "2026-11-14");
    put(&store, &uppercase_uid, b"");
    let before = catalog(&store);

    stop(store).await;
    let store = open_runtime_principal_store(&home, quota()).await.unwrap();
    assert_eq!(catalog(&store), before);
    for name in [
        &historical,
        &newest,
        &marked,
        &log_under_marker,
        &noncanonical,
        &companion,
        &uppercase_uid,
    ] {
        assert!(
            home.root().join(name).is_file(),
            "{name} must remain eagerly projected"
        );
    }
    assert_eq!(
        std::fs::read(home.root().join(historical)).unwrap(),
        b"retained history\n"
    );
    assert!(std::fs::read(home.root().join(newest)).unwrap().is_empty());
    assert!(home.root().join(uid_marker).is_dir());
    assert!(home.root().join(child_marker).is_dir());
}

#[tokio::test]
async fn unknown_empty_directory_rejects_all_groups_before_delete_and_retries() {
    let (_directory, home, store) = fixture().await;
    let names = [log('a', "2026-11-14"), log('b', "2026-11-14")];
    for name in &names {
        put(&store, name, b"");
        project(&home, name, b"");
    }
    let unknown = home
        .root()
        .join(format!("{PREFIX}{}/unknown-empty", "b".repeat(64)));
    std::fs::create_dir(&unknown).unwrap();
    let before = catalog(&store);
    stop(store).await;
    let error = open_runtime_principal_store(&home, quota())
        .await
        .err()
        .expect("unknown directory must reject bootstrap cleanup");
    assert!(error.to_string().contains("unauthenticated"), "{error}");
    for name in &names {
        assert!(home.root().join(name).is_file());
    }
    assert!(unknown.is_dir());

    std::fs::remove_dir(unknown).unwrap();
    let reopened = recover(&home, &names).await;
    for name in &names {
        assert!(!home.root().join(name).exists());
    }
    assert_eq!(catalog(&reopened), before);
}

#[tokio::test]
async fn late_nonempty_source_after_capture_is_not_deleted() {
    let (_directory, home, store) = fixture().await;
    let names = [log('a', "2026-11-14"), log('b', "2026-11-14")];
    for name in &names {
        put(&store, name, b"");
        project(&home, name, b"");
    }
    let (root, entries, empty) = selection(&home, &store);
    let _intent = restoration::record_inventory_intent(&home, &store, &entries, root).unwrap();
    let captured = retirement::prepare_empty_projection(&home, &store, &empty.selected).unwrap();
    std::fs::write(home.root().join(&names[1]), b"late data").unwrap();
    assert!(
        captured
            .retire_empty_subtrees(&empty.selected, |relative, kind| empty
                .authorize(relative, kind))
            .is_err()
    );
    assert!(home.root().join(&names[0]).is_file());
    assert_eq!(
        std::fs::read(home.root().join(&names[1])).unwrap(),
        b"late data"
    );
    assert_eq!(
        super::super::active::read(&home, &store)
            .unwrap()
            .unwrap()
            .phase(),
        super::super::ReceiptPhase::Retiring
    );
}

#[tokio::test]
async fn changed_catalog_and_invalid_names_cannot_trigger_empty_cleanup() {
    let (_directory, home, store) = fixture().await;
    let name = log('a', "2026-11-14");
    put(&store, &name, b"");
    project(&home, &name, b"");
    let (root, entries, _) = selection(&home, &store);
    put(&store, "new-volume-only.conf", b"latest");
    let after = current_root(&home, &store).unwrap();
    assert!(restoration::record_inventory_intent(&home, &store, &entries, root).is_err());
    assert_eq!(current_root(&home, &store).unwrap(), after);
    assert!(home.root().join(&name).is_file());
    assert!(read(&store, &name).is_empty());

    put(&store, "opaque\\noncanonical", b"");
    stop(store).await;
    assert!(open_runtime_principal_store(&home, quota()).await.is_err());
    assert!(home.root().join(&name).is_file());
}

#[tokio::test]
async fn cleanup_keeps_volume_authoritative_restore_of_stale_retained_siblings() {
    let (_directory, home, store) = fixture().await;
    let name = log('a', "2026-11-14");
    put(&store, &name, b"");
    put(&store, "config.toml", b"authoritative");
    project(&home, &name, b"");
    project(&home, "config.toml", b"stale retained sibling");
    // RETIRING, unlike surviving ACTIVE, is volume-authoritative.
    let intent = restoration::record_intent(&home, &store).unwrap();
    drop(intent);
    stop(store).await;
    let store = open_runtime_principal_store(&home, quota()).await.unwrap();
    assert!(!home.root().join(name).exists());
    assert_eq!(
        std::fs::read(home.root().join("config.toml")).unwrap(),
        b"authoritative"
    );
    assert_eq!(read(&store, "config.toml"), b"authoritative");
}

#[cfg(unix)]
#[tokio::test]
async fn partial_empty_cleanup_keeps_retiring_authority_and_public_reopen_retries() {
    let (_directory, home, store) = fixture().await;
    let name = log('a', "2026-11-14");
    let scope = format!("{PREFIX}{}", "a".repeat(64));
    put(&store, &name, b"");
    project(&home, &name, b"");
    let before = catalog(&store);
    stop(store).await;
    // The actual bootstrap cleanup must retain its durable inventory after
    // descendants disappear but before the UID directory can be unlinked.
    astrid_core::dirs::interrupt_retirement_before_unlink_once(home.root(), Path::new(&scope))
        .unwrap();
    let error = open_runtime_principal_store(&home, quota())
        .await
        .err()
        .expect("bootstrap cut must fire");
    assert!(
        error
            .to_string()
            .contains("injected projection retirement interruption"),
        "{error}"
    );
    assert!(!home.root().join(&name).exists());
    assert!(home.root().join(&scope).is_dir());

    let reopened = recover(&home, std::slice::from_ref(&name)).await;
    assert_eq!(catalog(&reopened), before);
    assert!(!home.root().join(scope).exists());
    assert!(!home.root().join(&name).exists());
    assert!(read(&reopened, &name).is_empty());
    let receipt = super::super::active::read(&home, &reopened)
        .unwrap()
        .unwrap();
    assert_eq!(receipt.phase(), super::super::ReceiptPhase::Active);
    assert!(!receipt.contains_inventory_name(&name));
}

#[tokio::test]
async fn initialized_staging_keeps_original_restore_without_empty_cleanup_or_omission() {
    let (_directory, home) = super::super::lifecycle_tests::fixture();
    let store = open_runtime_principal_store(&home, quota()).await.unwrap();
    let name = log('a', "2026-11-14");
    put(&store, &name, b"");
    project(&home, &name, b"");
    let journal = ContentName::new(super::super::STAGING_JOURNAL_PROJECTION).unwrap();
    assert!(
        store
            .content()
            .describe(&StateOwner::System, &journal)
            .unwrap()
            .is_none()
    );
    let before = current_root(&home, &store).unwrap();
    cleanup_current(&home, &store).unwrap();
    restore(&home, &store).unwrap();
    assert!(home.root().join(name).is_file());
    assert_eq!(current_root(&home, &store).unwrap(), before);
    assert!(
        store
            .content()
            .describe(&StateOwner::System, &journal)
            .unwrap()
            .is_none()
    );
    assert!(store.staging().ready().unwrap().is_empty());
    let receipt = super::super::active::read(&home, &store).unwrap().unwrap();
    assert_eq!(receipt.phase(), super::super::ReceiptPhase::Active);
}
