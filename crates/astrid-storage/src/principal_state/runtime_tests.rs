pub(super) use std::collections::BTreeMap;
pub(super) use std::num::NonZeroU64;
pub(super) use std::path::Path;
pub(super) use std::time::{Duration, Instant};

pub(super) use crate::engine::{ObjectCacheCapacity, ObjectCacheController, RootTransaction};
pub(super) use crate::resources::ResidentMemoryAuthority;
pub(super) use crate::storage_model::{
    ObjectFormatVersion, ObjectKind, ObjectReference, ReferenceLabel, RootGeneration, RootState,
};
pub(super) use crate::{AstridFilesystem, FilesystemPath};
#[cfg(feature = "legacy-surrealkv")]
pub(super) use astrid_core::profile::{DeviceKey, DeviceScope, PrincipalProfile};

use super::*;
pub(super) use crate::content::{
    CONTENT_COMPONENT_LABEL, CatalogValue, LegacyCatalog, encode_legacy_catalog,
};
pub(super) use crate::{ChunkingProfile, ContentIngest, ContentName};

mod staging_batch_tests;

pub(super) fn unlimited_quota() -> Arc<dyn KvQuotaResolver<StateOwner>> {
    Arc::new(|owner: &StateOwner| {
        Ok(match owner {
            StateOwner::System => None,
            StateOwner::Principal(_) | StateOwner::Fleet(_) => Some(u64::MAX),
        })
    })
}
fn test_uid(alias: &str) -> PrincipalUid {
    let mut hasher = blake3::Hasher::new_derive_key("astrid principal uid test fixture v1");
    hasher.update(alias.as_bytes());
    PrincipalUid::from_bytes(*hasher.finalize().as_bytes())
}

pub(super) fn test_owner(alias: &str) -> StateOwner {
    StateOwner::Principal(test_uid(alias))
}

pub(super) fn test_directory(aliases: &[&str]) -> PrincipalDirectory {
    let directory = PrincipalDirectory::default();
    for alias in aliases {
        directory
            .register(PrincipalId::new(*alias).unwrap(), test_uid(alias))
            .unwrap();
    }
    directory
}

pub(super) async fn create_test_principal(
    store: &RuntimePrincipalStore,
    alias: &str,
) -> PrincipalUid {
    let identities = KvIdentityStore::with_principal_directory(
        ScopedKvStore::new(store.kv(), "system:identity").unwrap(),
        store.principal_directory(),
    );
    let user = identities
        .create_principal(
            PrincipalId::new(alias).unwrap(),
            *blake3::hash(alias.as_bytes()).as_bytes(),
        )
        .await
        .unwrap();
    identities
        .get_principal_identity(user.id)
        .await
        .unwrap()
        .unwrap()
        .uid
}

pub(super) fn chunker_golden_source(length: usize) -> Vec<u8> {
    let mut state = 0x4d59_5df4_d0f3_3173_u64;
    (0..length)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            ((state >> 37) & 0xff) as u8
        })
        .collect()
}

pub(super) fn seed_legacy_layout(home: &AstridHome) {
    std::fs::create_dir_all(home.etc_dir()).unwrap();
    std::fs::write(
        home.layout_version_path(),
        astrid_core::dirs::LEGACY_LAYOUT_VERSION,
    )
    .unwrap();
}

pub(super) fn seed_legacy_surrealkv(home: &AstridHome, bytes: &[u8]) -> std::path::PathBuf {
    let manifest = home.state_db_path().join("manifest");
    std::fs::create_dir_all(&manifest).unwrap();
    std::fs::write(home.state_db_path().join("LOCK"), b"lock").unwrap();
    let file = manifest.join("00000000000000000001.manifest");
    std::fs::write(&file, bytes).unwrap();
    file
}

#[tokio::test]
async fn runtime_reports_principal_attributed_cache_residency() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let capacity = ObjectCacheCapacity::Bounded(NonZeroU64::new(1024 * 1024).unwrap());
    let store = open_runtime_principal_store_with_object_cache(
        &home,
        unlimited_quota(),
        ObjectCacheConfig::new(
            ObjectCacheController::new(capacity),
            Arc::new(move |_: &StateOwner| capacity),
        ),
    )
    .await
    .unwrap();
    let uid = create_test_principal(&store, "alice").await;
    let owner = StateOwner::Principal(uid);

    store
        .kv()
        .set("alice:capsule:shell", "cwd", b"/workspace".to_vec())
        .await
        .unwrap();
    assert_eq!(
        store.kv().get("alice:capsule:shell", "cwd").await.unwrap(),
        Some(b"/workspace".to_vec())
    );
    let content_name = ContentName::new("models/cache-accounting.bin").unwrap();
    let content = vec![0x5a; 512 * 1024];
    store
        .content()
        .put(&owner, &content_name, &content)
        .unwrap();
    assert_eq!(
        store
            .content()
            .read_range(&owner, &content_name, 1024, 4096)
            .unwrap(),
        Some(content[1024..5120].to_vec())
    );

    let stats = store.object_cache_stats();
    assert!(stats.resident_objects > 0);
    assert!(stats.resident_record_bytes > 0);
    assert!(stats.resident_association_bytes > 0);
    assert!(stats.resident_projection_entries > 0);
    assert!(stats.resident_projection_bytes > 0);
    assert!(store.object_cache_principal_charge(&owner) > 0);
}

#[tokio::test]
async fn governed_cache_reclaims_under_pressure_without_failing_reads() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let owner = test_owner("alice");
    let authority = ResidentMemoryAuthority::new(2 * 1024 * 1024);
    authority
        .register_principal(StateOwner::System, None, u64::MAX)
        .unwrap();
    authority.register_principal(owner, None, u64::MAX).unwrap();
    let cache = crate::GovernedObjectCache::new(authority.clone());
    let store =
        open_runtime_principal_store_with_object_cache(&home, unlimited_quota(), cache.config())
            .await
            .unwrap();
    let name = ContentName::new("models/governed-cache.bin").unwrap();
    let content = vec![0x5a; 512 * 1024];
    store.content().put(&owner, &name, &content).unwrap();
    assert_eq!(
        store
            .content()
            .read_range(&owner, &name, 4096, 64 * 1024)
            .unwrap(),
        Some(content[4096..4096 + 64 * 1024].to_vec())
    );

    let warm = authority.snapshot();
    assert!(warm.physical_reserved_bytes > 0);
    assert!(
        warm.principals
            .iter()
            .find(|account| account.principal == owner)
            .unwrap()
            .direct_logical_bytes
            > 0
    );

    let pressure = authority.set_physical_limit(0);
    assert!(pressure.reclaim_requested_bytes > 0);
    store.reclaim_object_cache();
    assert_eq!(store.object_cache_stats().resident_bytes, 0);
    let reclaimed = authority.snapshot();
    assert_eq!(reclaimed.physical_reserved_bytes, 0);
    assert_eq!(
        reclaimed
            .principals
            .iter()
            .find(|account| account.principal == owner)
            .unwrap()
            .direct_logical_bytes,
        0
    );

    assert_eq!(
        store
            .content()
            .read_range(&owner, &name, 4096, 64 * 1024)
            .unwrap(),
        Some(content[4096..4096 + 64 * 1024].to_vec())
    );
    assert_eq!(store.object_cache_stats().resident_bytes, 0);
    let after_uncached_read = authority.snapshot();
    assert_eq!(after_uncached_read.physical_reserved_bytes, 0);
    assert_eq!(
        after_uncached_read
            .principals
            .iter()
            .find(|account| account.principal == owner)
            .unwrap()
            .direct_logical_bytes,
        0
    );
    authority.remove_principal(&owner).unwrap();
}

#[tokio::test]
async fn closing_a_governed_cache_releases_physical_and_logical_leases() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let owner = test_owner("alice");
    let authority = ResidentMemoryAuthority::new(2 * 1024 * 1024);
    authority
        .register_principal(StateOwner::System, None, u64::MAX)
        .unwrap();
    authority.register_principal(owner, None, u64::MAX).unwrap();
    let cache = crate::GovernedObjectCache::new(authority.clone());
    let store =
        open_runtime_principal_store_with_object_cache(&home, unlimited_quota(), cache.config())
            .await
            .unwrap();
    let name = ContentName::new("models/close-releases-cache.bin").unwrap();
    let content = vec![0x5a; 128 * 1024];
    store.content().put(&owner, &name, &content).unwrap();
    assert_eq!(
        store.content().read_range(&owner, &name, 0, 4096).unwrap(),
        Some(content[..4096].to_vec())
    );
    assert!(authority.snapshot().physical_reserved_bytes > 0);

    store.kv().close().await.unwrap();

    let closed = authority.snapshot();
    assert_eq!(closed.physical_reserved_bytes, 0);
    assert!(closed.logical_leases.is_empty());
    authority.remove_principal(&owner).unwrap();
}

#[tokio::test]
async fn completed_store_does_not_self_heal_a_missing_runatal_object() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    seed_legacy_layout(&home);
    let path = home.principal_store_path();
    std::fs::create_dir_all(&path).unwrap();
    let record = bootstrap::format_specification().unwrap();
    let id = Blake3ObjectIdentityV1.identify(&record);
    let catalog_id = Blake3ObjectIdentityV1
        .identify(&bootstrap::content_catalog_format_specification().unwrap());
    std::fs::write(
        path.join(STORE_METADATA_FILE),
        store_metadata(id, catalog_id),
    )
    .unwrap();
    drop(
        RuntimeEngine::open(
            &path,
            Blake3ObjectIdentityV1,
            StateOwnerCodecV2,
            RecoveryLimits::process_addressable(),
        )
        .unwrap(),
    );
    std::fs::write(
        path.join(migrations::MIGRATION_MARKER_FILE),
        b"migration=surrealkv-to-principal-store\nfrom=legacy\nto=1\n",
    )
    .unwrap();

    let Err(error) = open_runtime_kv(&home, unlimited_quota()).await else {
        panic!("completed store without its RÚNATAL object was accepted");
    };
    assert!(
        error
            .to_string()
            .contains("missing its in-band format specification")
    );
}

#[tokio::test]
async fn current_metadata_does_not_self_heal_a_missing_catalog_specification() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    seed_legacy_layout(&home);
    let path = home.principal_store_path();
    std::fs::create_dir_all(&path).unwrap();
    let format_spec = bootstrap::format_specification().unwrap();
    let format_id = Blake3ObjectIdentityV1.identify(&format_spec);
    let catalog_id = Blake3ObjectIdentityV1
        .identify(&bootstrap::content_catalog_format_specification().unwrap());
    std::fs::write(
        path.join(STORE_METADATA_FILE),
        store_metadata(format_id, catalog_id),
    )
    .unwrap();
    let engine = RuntimeEngine::open(
        &path,
        Blake3ObjectIdentityV1,
        StateOwnerCodecV2,
        RecoveryLimits::process_addressable(),
    )
    .unwrap();
    engine.persist_standalone_object(&format_spec).unwrap();
    engine.close().unwrap();
    std::fs::write(
        path.join(migrations::MIGRATION_MARKER_FILE),
        migrations::CATALOG_TREE_MARKER,
    )
    .unwrap();

    let Err(error) = open_runtime_kv(&home, unlimited_quota()).await else {
        panic!("completed store without its catalog specification was accepted");
    };
    assert!(
        error
            .to_string()
            .contains("missing its content catalog specification")
    );
}

#[test]
fn namespace_owner_fails_closed_at_the_host_stamped_boundary() {
    let resolver = StateOwnerResolver::new(test_directory(&["alice"]));
    assert_eq!(
        resolver.resolve("system:identity").unwrap(),
        StateOwner::System
    );
    assert_eq!(
        resolver.resolve("alice:capsule:shell").unwrap(),
        test_owner("alice")
    );
    assert!(matches!(
        resolver.resolve("alice:capsule:"),
        Err(StorageError::InvalidKey(message))
            if message.contains("empty capsule identifier")
    ));
}

#[test]
fn control_namespaces_require_admitted_immutable_uids() {
    let directory = test_directory(&["alice"]);
    let resolver = StateOwnerResolver::new(directory.clone());
    let uid = test_uid("alice");
    let namespace = format!("principal-uid:{uid}:control:env:runner");
    assert_eq!(
        resolver.resolve(&namespace).unwrap(),
        StateOwner::Principal(uid)
    );
    assert_eq!(
        resolver
            .resolve(&format!("principal-uid:{uid}:control:secret:runner"))
            .unwrap(),
        StateOwner::Principal(uid)
    );
    for component in ["distro", "capsule-install-resume"] {
        assert_eq!(
            resolver
                .resolve(&format!("principal-uid:{uid}:control:{component}"))
                .unwrap(),
            StateOwner::Principal(uid)
        );
    }
    for component in [
        "capsule-install-resumes",
        "capsule-install",
        "capsule-install-resume-x",
        "x-capsule-install-resume",
        "distro-x",
    ] {
        assert!(
            resolver
                .resolve(&format!("principal-uid:{uid}:control:{component}"))
                .is_err(),
            "unexpectedly admitted control component {component}"
        );
    }
    assert!(matches!(
        resolver.resolve("alice:control:env:runner"),
        Err(StorageError::InvalidKey(message))
            if message.contains("immutable principal-uid")
    ));
    assert!(
        resolver
            .resolve("alice:control:capsule-install-resume")
            .is_err()
    );
    let unknown = PrincipalUid::from_bytes([0xa5; 32]);
    assert!(matches!(
        resolver.resolve(&format!("principal-uid:{unknown}:control:env:runner")),
        Err(StorageError::InvalidKey(message))
            if message.contains("not an admitted durable identity")
    ));
    assert!(matches!(
        resolver.resolve(&format!("principal-uid:{unknown}:control:capsule-install-resume")),
        Err(StorageError::InvalidKey(message))
            if message.contains("not an admitted durable identity")
    ));
    assert_eq!(
        resolver.resolve("system:control:audit").unwrap(),
        StateOwner::System
    );
    assert_eq!(
        resolver.resolve("system:control:invites").unwrap(),
        StateOwner::System
    );
    assert_eq!(
        resolver.resolve("system:control:pair-tokens").unwrap(),
        StateOwner::System
    );
    assert!(matches!(
        resolver.resolve("system:control:unknown"),
        Err(StorageError::InvalidKey(message))
            if message.contains("env or secret")
    ));
}

#[cfg(feature = "legacy-surrealkv")]
#[tokio::test]
async fn first_boot_migrates_verifies_and_preserves_legacy_state() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    seed_legacy_layout(&home);
    let legacy = Arc::new(SurrealKvStore::open(home.state_db_path()).unwrap());
    let legacy_kv: Arc<dyn KvStore> = legacy.clone();
    let identities = KvIdentityStore::new(
        ScopedKvStore::new(Arc::clone(&legacy_kv), "system:identity").unwrap(),
    );
    for (alias, key) in [("alice", [0x11; 32]), ("bob", [0x22; 32])] {
        let principal = PrincipalId::new(alias).unwrap();
        let user = identities.create_user(Some(alias)).await.unwrap();
        identities
            .link("astrid-agent", alias, user.id, "system")
            .await
            .unwrap();
        let mut profile = PrincipalProfile::default();
        profile.auth.public_keys.push(DeviceKey::new(
            hex::encode(key),
            DeviceScope::Full,
            None,
            1_700_000_000,
        ));
        profile
            .save_to_path(&home.profile_path(&principal))
            .unwrap();
    }
    legacy
        .set("system:identity", "root", b"default".to_vec())
        .await
        .unwrap();
    legacy
        .set("alice:capsule:shell", "cwd", b"/workspace".to_vec())
        .await
        .unwrap();
    legacy
        .set("bob:capsule:build", "toolchain", b"rust".to_vec())
        .await
        .unwrap();
    drop(identities);
    drop(legacy_kv);
    legacy.close().await.unwrap();

    let store = open_runtime_kv(&home, unlimited_quota()).await.unwrap();
    assert_eq!(
        store.get("system:identity", "root").await.unwrap(),
        Some(b"default".to_vec())
    );
    assert_eq!(
        store.get("alice:capsule:shell", "cwd").await.unwrap(),
        Some(b"/workspace".to_vec())
    );
    assert_eq!(
        store.get("bob:capsule:build", "toolchain").await.unwrap(),
        Some(b"rust".to_vec())
    );
    assert!(home.storage_volume_path().is_file());
    assert!(home.principal_store_path().is_dir());
    store.close().await.unwrap();
    drop(store);

    let legacy = SurrealKvStore::open(home.state_db_path()).unwrap();
    assert_eq!(
        legacy.get("alice:capsule:shell", "cwd").await.unwrap(),
        Some(b"/workspace".to_vec())
    );
    legacy
        .set("alice:capsule:shell", "legacy-only", b"stale".to_vec())
        .await
        .unwrap();
    legacy.close().await.unwrap();

    let reopened = open_runtime_kv(&home, unlimited_quota()).await.unwrap();
    assert_eq!(
        reopened
            .get("alice:capsule:shell", "legacy-only")
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        reopened.get("alice:capsule:shell", "cwd").await.unwrap(),
        Some(b"/workspace".to_vec())
    );
}

#[tokio::test]
async fn live_quota_blocks_growth_but_allows_recovery_and_system_state() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|owner: &StateOwner| {
        Ok(match owner {
            StateOwner::System => None,
            StateOwner::Principal(_) | StateOwner::Fleet(_) => Some(27),
        })
    });
    let store = open_runtime_principal_store(&home, quota).await.unwrap();
    create_test_principal(&store, "alice").await;
    let store = store.kv();

    store
        .set("alice:capsule:shell", "one", b"1234".to_vec())
        .await
        .unwrap();
    assert!(matches!(
        store.set("alice:capsule:shell", "two", b"5".to_vec()).await,
        Err(StorageError::Internal(message))
            if message
                == "storage quota exceeded: mutation would use 51 bytes (limit 27)"
    ));
    store
        .set("alice:capsule:shell", "one", b"123".to_vec())
        .await
        .unwrap();
    assert!(store.delete("alice:capsule:shell", "one").await.unwrap());
    store
        .set("alice:capsule:shell", "two", b"1234".to_vec())
        .await
        .unwrap();
    assert!(matches!(
        store.set("alice:capsule:shell", "empty", Vec::new()).await,
        Err(StorageError::Internal(message))
            if message
                == "storage quota exceeded: mutation would use 52 bytes (limit 27)"
    ));
    store
        .set("system:identity", "unmetered", vec![0; 64])
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejected_streaming_writes_do_not_grow_the_physical_volume() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|owner: &StateOwner| {
        Ok(match owner {
            StateOwner::System => None,
            StateOwner::Principal(_) | StateOwner::Fleet(_) => Some(27),
        })
    });
    let store = open_runtime_principal_store(&home, quota).await.unwrap();
    let uid = create_test_principal(&store, "alice").await;
    let owner = StateOwner::Principal(uid);
    let filesystem = AstridFilesystem::new(store.content(), owner);
    let accepted = FilesystemPath::new("accepted").unwrap();
    filesystem
        .write_streaming(&accepted, std::io::Cursor::new(b"first".to_vec()))
        .unwrap();
    filesystem.sync().unwrap();

    filesystem
        .write_streaming(&accepted, std::io::Cursor::new(b"first".to_vec()))
        .unwrap();
    filesystem.sync().unwrap();
    let warmup = FilesystemPath::new("rejected-warmup").unwrap();
    let error = filesystem
        .write_streaming(&warmup, std::io::Cursor::new(vec![7_u8; 64]))
        .unwrap_err();
    assert!(error.to_string().contains("quota exceeded"));
    filesystem.sync().unwrap();
    let bounded_len = std::fs::metadata(home.storage_volume_path()).unwrap().len();

    for index in 0..8 {
        let name = FilesystemPath::new(format!("rejected-{index}")).unwrap();
        let error = filesystem
            .write_streaming(&name, std::io::Cursor::new(vec![7_u8; 64]))
            .unwrap_err();
        assert!(
            error.to_string().contains("quota exceeded"),
            "unexpected error: {error}"
        );
        filesystem.sync().unwrap();
        assert_eq!(
            std::fs::metadata(home.storage_volume_path()).unwrap().len(),
            bounded_len
        );
    }

    let mut workers = Vec::new();
    for index in 0..8 {
        let content = store.content();
        let name = ContentName::new(format!("concurrent-{index}")).unwrap();
        workers.push(tokio::task::spawn_blocking(move || {
            content.put_streaming(&owner, &name, std::io::Cursor::new(vec![9_u8; 64]))
        }));
    }
    for worker in workers {
        let error = worker.await.unwrap().unwrap_err();
        assert!(
            error.to_string().contains("quota exceeded"),
            "unexpected concurrent error: {error}"
        );
    }
    filesystem.sync().unwrap();
    assert_eq!(
        std::fs::metadata(home.storage_volume_path()).unwrap().len(),
        bounded_len
    );

    for index in 0..4 {
        let first = ContentIngest::new(
            ContentName::new(format!("batch-{index}-first")).unwrap(),
            std::io::Cursor::new(vec![3_u8; 64]),
        );
        let second = ContentIngest::new(
            ContentName::new(format!("batch-{index}-second")).unwrap(),
            std::io::Cursor::new(vec![4_u8; 64]),
        );
        let error = store
            .content()
            .put_streaming_batch(&owner, [first, second])
            .unwrap_err();
        assert!(
            error.to_string().contains("quota exceeded"),
            "unexpected batch error: {error}"
        );
        filesystem.sync().unwrap();
        assert_eq!(
            std::fs::metadata(home.storage_volume_path()).unwrap().len(),
            bounded_len
        );
    }
}

#[tokio::test]
async fn incomplete_destination_is_quarantined_before_reimport() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    seed_legacy_layout(&home);
    std::fs::create_dir_all(home.principal_store_path()).unwrap();
    std::fs::write(home.principal_store_path().join("partial"), b"incomplete").unwrap();

    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    assert!(!home.principal_store_path().exists());
    assert!(!home.var_dir().join("principal-store.incomplete.0").exists());
    assert!(home.storage_volume_path().is_file());
    let quarantine_name =
        ContentName::new("quarantine/principal-store/0/partial").expect("valid quarantine name");
    assert_eq!(
        store
            .content()
            .read(&StateOwner::System, &quarantine_name)
            .unwrap(),
        Some(b"incomplete".to_vec())
    );
    store.engine.close().unwrap();
    drop(store);

    let packer = open_runtime_principal_store_for_pack(&home, unlimited_quota())
        .await
        .unwrap();
    packer
        .pack_and_retire_runtime_projection(&home)
        .expect("pack quarantine");
    assert_eq!(std::fs::read_dir(home.root()).unwrap().count(), 1);
    packer.engine.close().unwrap();
    drop(packer);

    let reopened = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    assert_eq!(
        std::fs::read(home.root().join("quarantine/principal-store/0/partial")).unwrap(),
        b"incomplete"
    );
    reopened
        .pack_and_retire_runtime_projection(&home)
        .expect("retire quarantine projection");
    assert_eq!(std::fs::read_dir(home.root()).unwrap().count(), 1);
}

#[test]
fn layout_retirement_resumes_exact_source_and_fails_closed_on_mismatch() {
    let directory = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    seed_legacy_layout(&home);
    home.ensure().unwrap();
    seed_legacy_surrealkv(&home, b"exact-source");
    let target = astrid_core::dirs::LayoutMigrationTarget::new(
        "test-store/3;state-owner-codec/2",
        "test-binary/1",
    )
    .unwrap();
    home.begin_layout_v2_migration(&target).unwrap();
    std::fs::write(home.storage_volume_path(), b"cutover-volume").unwrap();
    home.complete_layout_v2(&target).unwrap();

    std::fs::write(home.storage_volume_path(), b"post-cutover-write").unwrap();
    let drifted = seed_legacy_surrealkv(&home, b"pack-restored-drift");
    home.complete_layout_v2(&target).unwrap();
    assert!(!drifted.exists());

    let foreign_volume = outside.path().join("foreign.volume");
    std::fs::write(&foreign_volume, b"foreign-volume").unwrap();
    std::fs::remove_file(home.storage_volume_path()).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&foreign_volume, home.storage_volume_path()).unwrap();
    let mismatched = seed_legacy_surrealkv(&home, b"changed-source");
    let error = home.complete_layout_v2(&target).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert!(error.to_string().contains("redirected"), "{error}");
    assert!(mismatched.exists());
}

#[cfg(unix)]
#[test]
fn layout_retirement_rejects_redirected_residue_before_retirement() {
    let directory = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    seed_legacy_layout(&home);
    home.ensure().unwrap();
    seed_legacy_surrealkv(&home, b"exact-source");
    let target = astrid_core::dirs::LayoutMigrationTarget::new(
        "test-store/3;state-owner-codec/2",
        "test-binary/1",
    )
    .unwrap();
    home.begin_layout_v2_migration(&target).unwrap();
    std::fs::write(home.storage_volume_path(), b"cutover-volume").unwrap();
    home.complete_layout_v2(&target).unwrap();

    let external_source = outside.path().join("foreign-state");
    std::fs::write(&external_source, b"outside").unwrap();
    std::os::unix::fs::symlink(&external_source, home.state_db_path()).unwrap();
    let error = home.complete_layout_v2(&target).unwrap_err();

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert!(error.to_string().contains("redirected"), "{error}");
    assert!(home.state_db_path().symlink_metadata().is_ok());
    assert!(external_source.is_file());
}

#[cfg(not(feature = "legacy-surrealkv"))]
#[tokio::test]
async fn legacy_source_requires_the_transition_feature() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    seed_legacy_layout(&home);
    home.ensure().unwrap();
    std::fs::create_dir_all(home.state_db_path()).unwrap();

    let Err(error) = open_runtime_kv(&home, unlimited_quota()).await else {
        panic!("legacy source opened without transition support");
    };
    assert!(
        error
            .to_string()
            .contains("rebuild with the legacy-surrealkv feature")
    );
}

#[tokio::test]
async fn durable_point_update_has_height_bounded_write_amplification() {
    let directory = tempfile::tempdir().unwrap();
    let limits = RecoveryLimits::new(1024 * 1024).unwrap();
    let engine = Arc::new(
        RuntimeEngine::open(
            directory.path(),
            Blake3ObjectIdentityV1,
            StateOwnerCodecV2,
            limits,
        )
        .unwrap(),
    );
    let principals = test_directory(&["alice"]);
    let store = RuntimeStore::from_engine(
        Arc::clone(&engine),
        StateOwnerResolver::new(principals.clone()),
    );
    for value in 0..256_u32 {
        store
            .set(
                "alice:capsule:build",
                &format!("{value:04}"),
                value.to_le_bytes().to_vec(),
            )
            .await
            .unwrap();
    }
    let before = engine.object_count().unwrap();
    store
        .set("alice:capsule:build", "0128", b"replacement".to_vec())
        .await
        .unwrap();
    let inserted = engine.object_count().unwrap().saturating_sub(before);
    assert!(
        inserted <= 16,
        "one point update inserted {inserted} objects for a 256-key tree"
    );
    store.close().await.unwrap();
    drop(store);
    drop(engine);

    let reopened = Arc::new(
        RuntimeEngine::open(
            directory.path(),
            Blake3ObjectIdentityV1,
            StateOwnerCodecV2,
            limits,
        )
        .unwrap(),
    );
    let store = RuntimeStore::from_engine(reopened, StateOwnerResolver::new(principals));
    assert_eq!(
        store.get("alice:capsule:build", "0128").await.unwrap(),
        Some(b"replacement".to_vec())
    );
}
