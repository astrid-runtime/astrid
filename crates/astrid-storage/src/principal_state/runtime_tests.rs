use std::collections::BTreeMap;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::num::NonZeroU64;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::engine::{ObjectCacheCapacity, ObjectCacheController, RootTransaction};
use crate::resources::ResidentMemoryAuthority;
use crate::storage_model::{
    ObjectClass, ObjectFormatVersion, ObjectKind, ObjectReference, PhysicalIdentity, ProfileKind,
    ReconstructionBounds, ReferenceLabel, RepresentationProfile, RootGeneration, RootState,
};
use crate::volume::AstridVolume as _;
use crate::{AstridFilesystem, FilesystemPath};
#[cfg(feature = "legacy-surrealkv")]
use astrid_core::profile::{DeviceKey, DeviceScope, PrincipalProfile};

use super::*;
use crate::content::{CONTENT_COMPONENT_LABEL, CatalogValue, LegacyCatalog, encode_legacy_catalog};
use crate::{ChunkingProfile, ContentIngest, ContentName};

mod staging_batch_tests;

fn unlimited_quota() -> Arc<dyn KvQuotaResolver<StateOwner>> {
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

fn test_owner(alias: &str) -> StateOwner {
    StateOwner::Principal(test_uid(alias))
}

fn test_directory(aliases: &[&str]) -> PrincipalDirectory {
    let directory = PrincipalDirectory::default();
    for alias in aliases {
        directory
            .register(PrincipalId::new(*alias).unwrap(), test_uid(alias))
            .unwrap();
    }
    directory
}

async fn create_test_principal(store: &RuntimePrincipalStore, alias: &str) -> PrincipalUid {
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

fn chunker_golden_source(length: usize) -> Vec<u8> {
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

#[test]
fn owner_codec_round_trips_only_canonical_values() {
    let codec = StateOwnerCodecV2;
    let owners = [
        StateOwner::System,
        test_owner("alice"),
        StateOwner::Fleet(astrid_core::FleetUid::from_bytes([7; 32])),
    ];
    for owner in owners {
        let encoded = codec.encode(&owner);
        assert_eq!(codec.decode(&encoded), Some(owner));
    }
    assert_eq!(codec.decode(&[]), None);
    assert_eq!(codec.decode(&[0, 0]), None);
    assert_eq!(codec.decode(&[1]), None);
    assert_eq!(codec.decode(&[1, b':']), None);
}

#[test]
fn object_identity_v1_has_a_stable_golden_vector() {
    let record = ObjectRecord::new(
        ObjectKind::KvLeaf,
        ObjectFormatVersion::V1,
        b"hello".to_vec(),
        Vec::new(),
        0,
        ObjectClass::Data,
    )
    .unwrap();
    assert_eq!(
        Blake3ObjectIdentityV1.identify(&record).as_bytes(),
        &[
            14, 77, 237, 193, 155, 81, 194, 119, 35, 35, 59, 81, 40, 49, 0, 31, 232, 131, 137, 111,
            27, 237, 250, 91, 151, 7, 135, 21, 99, 27, 128, 55,
        ]
    );
}

#[test]
fn physical_identity_v1_matches_the_runatal_golden_vector() {
    let profile = RepresentationProfile::new_builtin(
        ProfileKind::DirectCanonical,
        ReconstructionBounds::new(
            8,
            32,
            8 * 1024 * 1024,
            16 * 1024 * 1024,
            1_000_000,
            32 * 1024 * 1024,
            5_000_000,
        )
        .unwrap(),
        ObjectId::new([1; 32]),
    )
    .unwrap()
    .encode()
    .unwrap();
    assert_eq!(
        Blake3PhysicalIdentityV1.identify("astrid-representation-profile-v1\0", &profile),
        [
            0x59, 0xc0, 0x99, 0x24, 0xb3, 0xb0, 0x72, 0x12, 0xc4, 0xbc, 0x10, 0x35, 0x35, 0xcf,
            0xbb, 0xe1, 0x0d, 0xee, 0xe3, 0x1d, 0x1b, 0x15, 0x7d, 0x21, 0x53, 0x8b, 0x17, 0x75,
            0x95, 0x23, 0x58, 0x04,
        ]
    );
}

#[test]
fn format_specification_has_a_tagged_metadata_identity() {
    let record = bootstrap::format_specification().unwrap();
    let id = Blake3ObjectIdentityV1.identify(&record);
    let catalog_id = Blake3ObjectIdentityV1
        .identify(&bootstrap::content_catalog_format_specification().unwrap());
    let metadata = String::from_utf8(store_metadata(id, catalog_id)).unwrap();

    assert_eq!(record.kind(), ObjectKind::Evidence);
    assert_eq!(record.canonical_bytes(), STORE_FORMAT_SPEC);
    assert!(record.references().is_empty());
    assert_eq!(
        object_id_hex(id),
        "ac3e1ab1e82be24dae7cdef949698dd54d2407bc7f39fb30709dc36677eea61d"
    );
    assert_eq!(
        object_id_hex(catalog_id),
        "8f3999b066b666396259c4a92f9de7c5b8e67df9d38a69fb4fb824968b56ecdb"
    );
    assert_eq!(
        metadata,
        "format=astrid-principal-store-v1\n\
         identity=blake3-object-identity-v1\n\
         identity-wire=tagged-identity-v1\n\
         format-spec-object=1:1:32:ac3e1ab1e82be24dae7cdef949698dd54d2407bc7f39fb30709dc36677eea61d\n\
         content-catalog-spec-object=1:1:32:8f3999b066b666396259c4a92f9de7c5b8e67df9d38a69fb4fb824968b56ecdb\n\
         representations=authoritative-direct-v1\n\
         principal-codec=state-owner-v2\n\
         projection=kv-transition-bplus-v4\n"
    );
}

#[test]
fn pre_derivation_v1_runatal_upgrade_is_idempotent_and_preserves_history() {
    let directory = tempfile::tempdir().unwrap();
    let store_path = directory.path().join("principal-store");
    std::fs::create_dir_all(&store_path).unwrap();
    let engine = RuntimeEngine::open(
        &store_path,
        Blake3ObjectIdentityV1,
        StateOwnerCodecV2,
        RecoveryLimits::process_addressable(),
    )
    .unwrap();
    let legacy_spec = ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        b"pre-derivation format 1 specification".to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let (legacy_spec_id, _) = engine.persist_standalone_object(&legacy_spec).unwrap();
    let current_spec = bootstrap::format_specification().unwrap();
    let current_spec_id = Blake3ObjectIdentityV1.identify(&current_spec);
    let catalog_spec = bootstrap::content_catalog_format_specification().unwrap();
    let catalog_spec_id = Blake3ObjectIdentityV1.identify(&catalog_spec);
    let current_metadata = store_metadata(current_spec_id, catalog_spec_id);
    atomic_write(
        &store_path.join(STORE_METADATA_FILE),
        &legacy_store_metadata(legacy_spec_id),
    )
    .unwrap();

    // Simulate a crash after the successor RÚNATAL object became durable
    // but before store.meta changed.
    persist_format_specification(&engine, &current_spec).unwrap();
    prepare_format_specification(
        &engine,
        DestinationFormat::PriorV1 {
            format_spec: legacy_spec_id,
            catalog_spec_was_declared: false,
        },
        &current_spec,
        current_spec_id,
    )
    .unwrap();
    prepare_catalog_specification(
        &engine,
        DestinationFormat::PriorV1 {
            format_spec: legacy_spec_id,
            catalog_spec_was_declared: false,
        },
        &catalog_spec,
        catalog_spec_id,
    )
    .unwrap();
    atomic_write(&store_path.join(STORE_METADATA_FILE), &current_metadata).unwrap();

    assert_eq!(
        std::fs::read(store_path.join(STORE_METADATA_FILE)).unwrap(),
        current_metadata
    );
    assert_eq!(engine.object(legacy_spec_id).unwrap(), Some(legacy_spec));
    assert_eq!(
        engine.object(current_spec_id).unwrap(),
        Some(current_spec.clone())
    );
    prepare_format_specification(
        &engine,
        DestinationFormat::Current,
        &current_spec,
        current_spec_id,
    )
    .unwrap();
    prepare_catalog_specification(
        &engine,
        DestinationFormat::Current,
        &catalog_spec,
        catalog_spec_id,
    )
    .unwrap();
    engine.close().unwrap();
}

#[test]
fn prior_metadata_that_declared_a_catalog_specification_requires_it() {
    let directory = tempfile::tempdir().unwrap();
    let engine = RuntimeEngine::open(
        directory.path(),
        Blake3ObjectIdentityV1,
        StateOwnerCodecV2,
        RecoveryLimits::process_addressable(),
    )
    .unwrap();
    let catalog_spec = bootstrap::content_catalog_format_specification().unwrap();
    let catalog_spec_id = Blake3ObjectIdentityV1.identify(&catalog_spec);
    let destination = DestinationFormat::PriorV1 {
        format_spec: PRE_DERIVATION_FORMAT_SPEC_ID,
        catalog_spec_was_declared: true,
    };

    let error = prepare_catalog_specification(&engine, destination, &catalog_spec, catalog_spec_id)
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("completed principal store is missing its content catalog specification"),
        "{error}"
    );
}

#[tokio::test]
async fn completed_pre_derivation_v1_store_is_selected_for_runatal_amendment() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    super::format_migration_tests::seed_current_directory_store(&home);

    let store_path = home.principal_store_path();
    std::fs::write(
        store_path.join(STORE_METADATA_FILE),
        legacy_store_metadata(PRE_DERIVATION_FORMAT_SPEC_ID),
    )
    .unwrap();
    let current_spec = bootstrap::format_specification().unwrap();
    let current_spec_id = Blake3ObjectIdentityV1.identify(&current_spec);
    let catalog_spec = bootstrap::content_catalog_format_specification().unwrap();
    let current_metadata = store_metadata(
        current_spec_id,
        Blake3ObjectIdentityV1.identify(&catalog_spec),
    );
    assert_eq!(
        prepare_destination(
            &store_path,
            &current_metadata,
            Blake3ObjectIdentityV1.identify(&catalog_spec),
        )
        .unwrap(),
        DestinationFormat::PriorV1 {
            format_spec: PRE_DERIVATION_FORMAT_SPEC_ID,
            catalog_spec_was_declared: false,
        }
    );
}

#[tokio::test]
async fn new_store_persists_and_verifies_the_in_band_specification() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();

    let record = bootstrap::format_specification().unwrap();
    let id = Blake3ObjectIdentityV1.identify(&record);
    assert_eq!(store.engine.object(id).unwrap(), Some(record.clone()));
    assert!(home.storage_volume_path().is_file());
    assert!(home.principal_store_path().is_dir());
    store.engine.close().unwrap();
    drop(store);

    let reopened = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    assert_eq!(reopened.engine.object(id).unwrap(), Some(record));
    assert!(home.principal_store_path().is_dir());
    reopened
        .retire_verified_legacy_directory_store(&home)
        .unwrap();
    assert!(!home.principal_store_path().exists());
}

#[tokio::test]
async fn explicit_close_releases_the_hosted_volume_while_store_references_remain() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let retained_engine = Arc::clone(&store.engine);
    retained_engine.close().unwrap();

    let reopened = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    reopened.engine.close().unwrap();
    drop(reopened);
    drop(store);
    drop(retained_engine);
}

#[tokio::test]
async fn volume_without_its_cutover_receipt_fails_closed() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_kv(&home, unlimited_quota()).await.unwrap();
    store.close().await.unwrap();
    drop(store);

    let volume = crate::volume::HostedFileVolume::open(home.storage_volume_path()).unwrap();
    let receipt =
        crate::volume::VolumeRegion::new("system/migrations/directory-store-to-volume-v1").unwrap();
    volume.remove_region(&receipt).unwrap();
    volume.sync().unwrap();
    drop(volume);

    let Err(error) = open_runtime_kv(&home, unlimited_quota()).await else {
        panic!("volume without a cutover receipt unexpectedly reopened");
    };
    assert!(error.to_string().contains("cutover receipt"), "{error}");
}

#[tokio::test]
async fn changed_surviving_directory_store_is_rejected_by_post_barrier_retirement() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    super::format_migration_tests::seed_current_directory_store(&home);
    let migrated = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    migrated.engine.close().unwrap();
    drop(migrated);
    assert!(home.principal_store_path().is_dir());
    let source = Arc::new(
        RuntimeEngine::open(
            home.principal_store_path(),
            Blake3ObjectIdentityV1,
            StateOwnerCodecV2,
            RecoveryLimits::process_addressable(),
        )
        .unwrap(),
    );
    let changed = RuntimeStore::from_engine(
        Arc::clone(&source),
        StateOwnerResolver::new(test_directory(&["alice"])),
    );
    changed
        .set("alice:capsule:shell", "drift", b"changed".to_vec())
        .await
        .unwrap();
    source.close().unwrap();
    drop(changed);
    drop(source);

    let reopened = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let error = reopened
        .retire_verified_legacy_directory_store(&home)
        .expect_err("changed surviving source must not be retired");
    assert!(error.to_string().contains("cutover receipt"), "{error}");
    assert!(home.principal_store_path().exists());
}

fn replace_catalog_with_legacy(
    engine: &RuntimeEngine,
    owner: &StateOwner,
    name: &ContentName,
    file: ObjectId,
    logical_bytes: u64,
) -> RootState {
    let previous = engine.root(owner).unwrap().unwrap();
    let quota_bytes = logical_bytes
        .checked_add(u64::try_from(name.as_str().len()).unwrap())
        .unwrap();
    let legacy = LegacyCatalog {
        entries: BTreeMap::from([(
            name.clone(),
            CatalogValue {
                file,
                logical_bytes,
            },
        )]),
        logical_bytes,
        quota_bytes,
    };
    let catalog = encode_legacy_catalog(&legacy).unwrap();
    let catalog_id = Blake3ObjectIdentityV1.identify(&catalog);
    let graph_version = ObjectFormatVersion::new(3).unwrap();
    let state = ObjectRecord::new(
        ObjectKind::PrincipalState,
        graph_version,
        Vec::new(),
        vec![ObjectReference::owns(
            ReferenceLabel::new(CONTENT_COMPONENT_LABEL.to_vec()),
            catalog_id,
        )],
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let state_id = Blake3ObjectIdentityV1.identify(&state);
    let commit = ObjectRecord::new(
        ObjectKind::Commit,
        graph_version,
        Vec::new(),
        vec![
            ObjectReference::new(
                ReferenceLabel::new(b"parent".to_vec()),
                previous.commit,
                ReferenceKind::Lineage,
            ),
            ObjectReference::owns(ReferenceLabel::new(b"state".to_vec()), state_id),
        ],
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let commit_id = Blake3ObjectIdentityV1.identify(&commit);
    engine
        .commit(RootTransaction::new(
            *owner,
            Some(previous),
            commit_id,
            vec![
                (catalog_id, catalog),
                (state_id, state),
                (commit_id, commit),
            ],
        ))
        .unwrap()
        .root()
}

fn mark_store_as_legacy(home: &AstridHome) {
    std::fs::write(
        home.principal_store_path()
            .join(migrations::MIGRATION_MARKER_FILE),
        migrations::LEGACY_TO_V1_MARKER,
    )
    .unwrap();
}

fn install_legacy_catalog_fixtures(
    home: &AstridHome,
    fixtures: &[(&StateOwner, &ContentName, &[u8])],
) -> BTreeMap<StateOwner, RootState> {
    super::format_migration_tests::seed_current_directory_store(home);
    let engine = Arc::new(
        RuntimeEngine::open(
            home.principal_store_path(),
            Blake3ObjectIdentityV1,
            StateOwnerCodecV2,
            RecoveryLimits::process_addressable(),
        )
        .unwrap(),
    );
    let store = NativePrincipalContentStore::from_engine(Arc::clone(&engine));
    let published: Vec<_> = fixtures
        .iter()
        .map(|(owner, name, bytes)| {
            (
                **owner,
                (*name).clone(),
                store.put(owner, name, bytes).unwrap(),
            )
        })
        .collect();
    let legacy_roots = published
        .into_iter()
        .map(|(owner, name, outcome)| {
            let descriptor = outcome.descriptor();
            let root = replace_catalog_with_legacy(
                engine.as_ref(),
                &owner,
                &name,
                descriptor.file(),
                descriptor.logical_bytes(),
            );
            (owner, root)
        })
        .collect();
    drop(store);
    engine.close().unwrap();
    drop(engine);
    mark_store_as_legacy(home);
    legacy_roots
}

#[derive(Debug)]
struct CatalogWorkloadMetrics {
    arena_bytes: u64,
    root_journal_bytes: u64,
    representation_metadata_bytes: u64,
    publication_time: Duration,
    reopen_time: Duration,
}

fn durable_file_len(store: &RuntimePrincipalStore, name: &str) -> u64 {
    store.engine.durable_region_len(name).unwrap()
}

fn volume_file_len(home: &AstridHome) -> u64 {
    std::fs::metadata(home.storage_volume_path()).unwrap().len()
}

async fn measure_catalog_publications(unique_content: bool) -> CatalogWorkloadMetrics {
    const PUBLICATIONS: u64 = 1_000;
    const CONTENT_BYTES: usize = 4 * 1024;

    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let owner = test_owner("catalog-probe");
    let store = open_runtime_principal_store_with_directory(
        &home,
        unlimited_quota(),
        test_directory(&["catalog-probe"]),
    )
    .await
    .unwrap();
    let arena_before = durable_file_len(&store, "objects.arena");
    let roots_before = durable_file_len(&store, "roots.journal");
    let volume_before = volume_file_len(&home);
    let started = Instant::now();
    for index in 0..PUBLICATIONS {
        let name = ContentName::new(format!("workspace/fixture/{index:04}")).unwrap();
        let mut bytes = vec![7_u8; CONTENT_BYTES];
        if unique_content {
            bytes[..8].copy_from_slice(&index.to_le_bytes());
        }
        store.content().put(&owner, &name, &bytes).unwrap();
    }
    let publication_time = started.elapsed();
    let arena_bytes = durable_file_len(&store, "objects.arena")
        .checked_sub(arena_before)
        .unwrap();
    let root_journal_bytes = durable_file_len(&store, "roots.journal")
        .checked_sub(roots_before)
        .unwrap();
    let representation_metadata_bytes = volume_file_len(&home).checked_sub(volume_before).unwrap();
    drop(store);

    let reopen_started = Instant::now();
    let reopened = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let reopen_time = reopen_started.elapsed();
    assert_eq!(
        reopened.content().list(&owner).unwrap().len(),
        usize::try_from(PUBLICATIONS).unwrap()
    );
    drop(reopened);

    CatalogWorkloadMetrics {
        arena_bytes,
        root_journal_bytes,
        representation_metadata_bytes,
        publication_time,
        reopen_time,
    }
}

#[tokio::test]
async fn thousand_deduplicated_four_kib_publications_bound_durable_arena_growth() {
    const PUBLICATIONS: u64 = 1_000;
    const MAX_ARENA_BYTES_PER_PUBLICATION: u64 = 16 * 1024;

    let metrics = measure_catalog_publications(false).await;
    assert!(
        metrics.arena_bytes
            < PUBLICATIONS
                .checked_mul(MAX_ARENA_BYTES_PER_PUBLICATION)
                .unwrap(),
        "deduplicated publications appended unexpected arena bytes: {metrics:?}"
    );
}

#[tokio::test]
#[ignore = "explicit durable catalog amplification and reopen probe"]
async fn catalog_durable_performance_probe() {
    let duplicate = measure_catalog_publications(false).await;
    let unique = measure_catalog_publications(true).await;
    for (name, metrics) in [("duplicate", duplicate), ("unique", unique)] {
        eprintln!(
            "{name}: arena={} roots={} representations={} publication={:?} reopen={:?}",
            metrics.arena_bytes,
            metrics.root_journal_bytes,
            metrics.representation_metadata_bytes,
            metrics.publication_time,
            metrics.reopen_time
        );
    }
}

#[tokio::test]
async fn flat_content_catalog_migration_resumes_and_is_idempotent() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let alice = test_owner("alice");
    let bob = test_owner("bob");
    let alice_name = ContentName::new("workspace/alice-legacy.bin").unwrap();
    let bob_name = ContentName::new("workspace/bob-legacy.bin").unwrap();
    let alice_bytes = b"alice content survives the catalog migration";
    let bob_bytes = b"bob content survives the catalog migration";
    let legacy_roots = install_legacy_catalog_fixtures(
        &home,
        &[
            (&alice, &alice_name, alice_bytes),
            (&bob, &bob_name, bob_bytes),
        ],
    );

    let engine = Arc::new(
        RuntimeEngine::open(
            home.principal_store_path(),
            Blake3ObjectIdentityV1,
            StateOwnerCodecV2,
            RecoveryLimits::process_addressable(),
        )
        .unwrap(),
    );
    let content = NativePrincipalContentStore::from_engine(Arc::clone(&engine));
    assert!(content.migrate_legacy_catalog(&alice).unwrap());
    let partially_migrated_alice_root = engine.root(&alice).unwrap().unwrap();
    assert_eq!(engine.root(&bob).unwrap(), legacy_roots.get(&bob).copied());
    drop(content);
    engine.close().unwrap();
    drop(engine);

    let migrated = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    assert_eq!(
        migrated.content().read(&alice, &alice_name).unwrap(),
        Some(alice_bytes.to_vec())
    );
    assert_eq!(
        migrated.content().read(&bob, &bob_name).unwrap(),
        Some(bob_bytes.to_vec())
    );
    let migrated_alice_root = migrated.engine.root(&alice).unwrap().unwrap();
    let migrated_bob_root = migrated.engine.root(&bob).unwrap().unwrap();
    assert_eq!(migrated_alice_root, partially_migrated_alice_root);
    assert_eq!(
        migrated_bob_root.generation,
        legacy_roots
            .get(&bob)
            .unwrap()
            .generation
            .checked_next()
            .unwrap()
    );
    migrated.engine.close().unwrap();
    drop(migrated);
    assert!(home.storage_volume_path().is_file());
    assert!(home.principal_store_path().is_dir());

    let reopened = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    assert_eq!(
        reopened.content().read(&alice, &alice_name).unwrap(),
        Some(alice_bytes.to_vec())
    );
    assert_eq!(
        reopened.content().read(&bob, &bob_name).unwrap(),
        Some(bob_bytes.to_vec())
    );
    assert_eq!(
        reopened.engine.root(&alice).unwrap(),
        Some(migrated_alice_root)
    );
    assert_eq!(reopened.engine.root(&bob).unwrap(), Some(migrated_bob_root));
}

#[tokio::test]
async fn native_stage_acknowledges_before_ingest_and_publishes_on_a_blocking_worker() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let owner = test_owner("alice");
    let name = ContentName::new("workspace/target/release/game").unwrap();
    let mut writer = store
        .staging()
        .begin(owner, name.clone(), ChunkingProfile::ASTRID_V1)
        .unwrap();
    writer.write_all(b"linux build.......").unwrap();
    writer.seek(SeekFrom::Start(12)).unwrap();
    writer.write_all(b"artifact").unwrap();
    writer.set_len(20).unwrap();
    let staged = writer.seal().unwrap();

    assert_eq!(staged.logical_bytes(), 20);
    assert_eq!(store.content().describe(&owner, &name).unwrap(), None);
    assert_eq!(store.staging().ready().unwrap(), vec![staged.clone()]);

    let outcome = store.publish_staged(staged).await.unwrap();
    assert_eq!(outcome.descriptor().logical_bytes(), 20);
    assert_eq!(
        store.content().read(&owner, &name).unwrap(),
        Some(b"linux build.artifact".to_vec())
    );
    let snapshot = store.content().engine().snapshot(&owner).unwrap().unwrap();
    assert!(
        snapshot
            .records()
            .iter()
            .any(|(_, record)| record.kind() == ObjectKind::Chunk),
        "archival snapshots must materialize canonical chunk records"
    );
    assert!(store.staging().ready().unwrap().is_empty());
    drop(store);

    let reopened = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    assert_eq!(
        reopened.content().read(&owner, &name).unwrap(),
        Some(b"linux build.artifact".to_vec())
    );
}

#[tokio::test]
async fn native_staging_batch_publishes_one_atomic_root_and_reaps_together() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let owner = test_owner("alice");
    let values = [
        ("workspace/a.txt", b"alpha".as_slice()),
        ("workspace/b.txt", b"bravo".as_slice()),
        ("workspace/c.txt", b"charlie".as_slice()),
    ];
    let mut staged = Vec::new();
    for (name, value) in values {
        let mut writer = store
            .staging()
            .begin(
                owner,
                ContentName::new(name).unwrap(),
                ChunkingProfile::ASTRID_V1,
            )
            .unwrap();
        writer.write_all(value).unwrap();
        staged.push(writer.seal().unwrap());
    }

    let outcome = store.publish_staged_batch(staged).await.unwrap();

    assert_eq!(outcome.principal_root().generation, RootGeneration::INITIAL);
    assert_eq!(outcome.entries().len(), values.len());
    assert!(store.staging().ready().unwrap().is_empty());
    for (name, value) in values {
        assert_eq!(
            store
                .content()
                .read(&owner, &ContentName::new(name).unwrap())
                .unwrap(),
            Some(value.to_vec())
        );
    }
    drop(store);

    let reopened = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    for (name, value) in values {
        assert_eq!(
            reopened
                .content()
                .read(&owner, &ContentName::new(name).unwrap())
                .unwrap(),
            Some(value.to_vec())
        );
    }
}

#[tokio::test]
async fn native_staging_batch_rejects_mixed_owners_without_consuming_generations() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let mut staged = Vec::new();
    for owner in [test_owner("alice"), test_owner("bob")] {
        let mut writer = store
            .staging()
            .begin(
                owner,
                ContentName::new("workspace/shared.txt").unwrap(),
                ChunkingProfile::ASTRID_V1,
            )
            .unwrap();
        writer.write_all(b"owner-specific bytes").unwrap();
        staged.push(writer.seal().unwrap());
    }

    let error = store
        .publish_staged_batch(staged.clone())
        .await
        .unwrap_err();

    assert!(error.to_string().contains("multiple owners"));
    assert_eq!(store.staging().ready().unwrap(), staged);
}

#[tokio::test]
async fn staged_publication_rejects_a_generation_truncated_after_seal() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let owner = test_owner("alice");
    let name = ContentName::new("workspace/truncated.bin").unwrap();
    let mut writer = store
        .staging()
        .begin(owner, name.clone(), ChunkingProfile::ASTRID_V1)
        .unwrap();
    writer.write_all(b"durable staged bytes").unwrap();
    let staged = writer.seal().unwrap();
    let path = staged.content_path();

    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(staged.logical_bytes().saturating_sub(1))
        .unwrap();

    let error = store.publish_staged(staged).await.unwrap_err();
    assert!(error.to_string().contains("footer"));
    assert_eq!(store.content().describe(&owner, &name).unwrap(), None);
    assert!(
        path.exists(),
        "failed publication must retain staged evidence"
    );
}

#[tokio::test]
async fn staged_publication_retries_after_root_commit_before_cleanup() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let owner = test_owner("alice");
    let name = ContentName::new("workspace/retry.bin").unwrap();
    let mut writer = store
        .staging()
        .begin(owner, name.clone(), ChunkingProfile::ASTRID_V1)
        .unwrap();
    writer.write_all(b"one identity").unwrap();
    let staged = writer.seal().unwrap();

    let source = native_io::open_private_file(&staged.content_path())
        .unwrap()
        .take(staged.logical_bytes());
    let first = store
        .content()
        .put_streaming(&owner, &name, source)
        .unwrap();
    assert_eq!(store.staging().ready().unwrap(), vec![staged.clone()]);

    let retried = store.publish_staged(staged).await.unwrap();
    assert_eq!(retried.descriptor(), first.descriptor());
    assert_eq!(retried.principal_root(), first.principal_root());
    assert_eq!(
        retried.objects_inserted(),
        0,
        "retry must not count immutable objects admitted by the first publication"
    );
    assert!(store.staging().ready().unwrap().is_empty());
}

#[tokio::test]
async fn staged_publication_enforces_close_order_for_the_same_name() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let owner = test_owner("alice");
    let name = ContentName::new("workspace/order.txt").unwrap();
    let mut first = store
        .staging()
        .begin(owner, name.clone(), ChunkingProfile::ASTRID_V1)
        .unwrap();
    first.write_all(b"first close").unwrap();
    let first = first.seal().unwrap();
    let mut second = store
        .staging()
        .begin(owner, name.clone(), ChunkingProfile::ASTRID_V1)
        .unwrap();
    second.write_all(b"second close").unwrap();
    let second = second.seal().unwrap();

    let error = store.publish_staged(second.clone()).await.unwrap_err();
    assert!(error.to_string().contains("earlier close"));
    store.publish_staged(first).await.unwrap();
    store.publish_staged(second).await.unwrap();
    assert_eq!(
        store.content().read(&owner, &name).unwrap(),
        Some(b"second close".to_vec())
    );
}

#[cfg(not(target_os = "windows"))]
#[tokio::test]
async fn hosted_volume_retires_a_torn_tail_and_reopens_committed_roots() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let alice_uid = create_test_principal(&store, "alice").await;
    store
        .kv()
        .set("alice:capsule:shell", "cwd", b"/workspace".to_vec())
        .await
        .unwrap();
    store
        .kv()
        .set("alice:capsule:shell", "theme", b"raven".to_vec())
        .await
        .unwrap();
    store.engine.close().unwrap();
    drop(store);

    let path = home.storage_volume_path();
    let committed_len = std::fs::metadata(&path).unwrap().len();
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap();
    file.write_all(&[0xA5; 17]).unwrap();
    file.sync_all().unwrap();
    drop(file);

    let reopened = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().len(), committed_len);
    assert_eq!(
        reopened
            .engine
            .root(&StateOwner::Principal(alice_uid))
            .unwrap()
            .unwrap()
            .generation,
        RootGeneration::new(1)
    );
    assert_eq!(
        reopened
            .kv()
            .get("alice:capsule:shell", "theme")
            .await
            .unwrap(),
        Some(b"raven".to_vec())
    );
}

#[cfg(not(target_os = "windows"))]
#[tokio::test]
async fn hosted_volume_rejects_interior_container_corruption() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    store.engine.close().unwrap();
    drop(store);

    let path = home.storage_volume_path();
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[8] ^= 0x80;
    std::fs::write(&path, bytes).unwrap();
    let Err(error) = open_runtime_principal_store(&home, unlimited_quota()).await else {
        panic!("corrupt Astrid volume unexpectedly reopened");
    };
    assert!(error.to_string().contains("record magic"), "{error}");
}

#[tokio::test]
async fn independent_reader_accepts_a_rust_produced_volume() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let alice_uid = create_test_principal(&store, "alice").await;
    let alice = alice_uid.to_string();
    store
        .kv()
        .set("alice:capsule:shell", "cwd", b"/workspace".to_vec())
        .await
        .unwrap();
    let owner = StateOwner::Principal(alice_uid);
    let name = ContentName::new("workspace/fastcdc-golden.bin").unwrap();
    store
        .content()
        .put(&owner, &name, &chunker_golden_source(1024 * 1024))
        .unwrap();
    drop(store);

    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/runatal_v1_reader.py");
    let output = std::process::Command::new("python3")
        .arg(&script)
        .arg(home.storage_volume_path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "independent reader failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let decoded: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(decoded["roots"][alice.as_str()]["generation"], 1);
    assert_eq!(decoded["roots"][alice.as_str()]["kv"]["entries"], 1);
    assert_eq!(
        decoded["roots"][alice.as_str()]["kv"]["logical_bytes"],
        b"/workspace".len()
    );
    assert!(
        decoded["roots"][alice.as_str()]["commit"]
            .as_str()
            .unwrap()
            .starts_with("1:1:32:")
    );
    assert!(
        decoded["objects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|object| object["kind"] == "Evidence")
    );
    assert!(
        decoded["objects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|object| object["kind"] == "Commit")
    );
    assert!(
        decoded["objects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|object| object["kind"] == "File")
    );
    assert_eq!(
        decoded["content_catalog_spec_object"],
        format!(
            "1:1:32:{}",
            object_id_hex(
                Blake3ObjectIdentityV1
                    .identify(&bootstrap::content_catalog_format_specification().unwrap(),)
            )
        )
    );

    let volume_path = home.storage_volume_path();
    let mut volume = std::fs::read(&volume_path).unwrap();
    volume[43] ^= 0x80;
    std::fs::write(&volume_path, volume).unwrap();
    let rejected = std::process::Command::new("python3")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/runatal_v1_reader.py"))
        .arg(volume_path)
        .output()
        .unwrap();
    assert!(
        !rejected.status.success(),
        "independent reader accepted a corrupt Rust-produced volume"
    );
}

#[test]
fn independent_volume_validator_rejects_the_full_unicode_control_set() {
    let script_directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts");
    let output = std::process::Command::new("python3")
        .current_dir(script_directory)
        .arg("-c")
        .arg(
            r#"from runatal_v1_volume import VolumeFormatError, volume_region_name
for codepoint in range(0x80, 0xa0):
    try:
        volume_region_name(chr(codepoint).encode())
    except VolumeFormatError:
        continue
    raise AssertionError(f"U+{codepoint:04X} was accepted")
assert volume_region_name(" Astrid ".encode()) == " Astrid ""#,
        )
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "independent validator failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn completed_store_does_not_self_heal_a_missing_runatal_object() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
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
    assert!(matches!(
        resolver.resolve("alice:control:env:runner"),
        Err(StorageError::InvalidKey(message))
            if message.contains("immutable principal-uid")
    ));
    let unknown = PrincipalUid::from_bytes([0xa5; 32]);
    assert!(matches!(
        resolver.resolve(&format!("principal-uid:{unknown}:control:env:runner")),
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
    std::fs::create_dir_all(home.principal_store_path()).unwrap();
    std::fs::write(home.principal_store_path().join("partial"), b"incomplete").unwrap();

    let store = open_runtime_kv(&home, unlimited_quota()).await.unwrap();
    assert!(
        home.var_dir()
            .join("principal-store.incomplete.0")
            .join("partial")
            .exists()
    );
    assert!(home.storage_volume_path().is_file());
    assert!(home.principal_store_path().is_dir());
    drop(store);
}

#[cfg(not(feature = "legacy-surrealkv"))]
#[tokio::test]
async fn legacy_source_requires_the_transition_feature() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
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

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "explicit native KV group-commit throughput probe"]
async fn native_kv_group_commit_scale_probe() {
    const COMMITS_PER_WRITER: u8 = 64;

    for writers in [1_u8, 2, 4, 8] {
        let directory = tempfile::tempdir().unwrap();
        let aliases = (0..writers)
            .map(|writer| format!("principal-{writer}"))
            .collect::<Vec<_>>();
        let alias_refs = aliases.iter().map(String::as_str).collect::<Vec<_>>();
        let engine = Arc::new(
            RuntimeEngine::open(
                directory.path(),
                Blake3ObjectIdentityV1,
                StateOwnerCodecV2,
                RecoveryLimits::process_addressable(),
            )
            .unwrap(),
        );
        let specification = bootstrap::format_specification().unwrap();
        let specification_id = engine.identify(&specification);
        engine.persist_standalone_object(&specification).unwrap();
        engine
            .ensure_direct_representation_catalogue(specification_id, &[specification_id])
            .unwrap();
        let store = Arc::new(RuntimeStore::from_engine(
            Arc::clone(&engine),
            StateOwnerResolver::new(test_directory(&alias_refs)),
        ));
        let barrier = Arc::new(tokio::sync::Barrier::new(usize::from(writers) + 1));
        let mut tasks = Vec::new();
        for writer in 0..writers {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            tasks.push(tokio::spawn(async move {
                let namespace = format!("principal-{writer}:capsule:probe");
                let mut latencies = Vec::new();
                barrier.wait().await;
                for sequence in 0..COMMITS_PER_WRITER {
                    let mut value = vec![0_u8; 128];
                    value[..2].copy_from_slice(&[writer, sequence]);
                    let started = Instant::now();
                    store.set(&namespace, "state", value).await.unwrap();
                    latencies.push(started.elapsed());
                }
                latencies
            }));
        }
        barrier.wait().await;
        let started = Instant::now();
        let mut writer_latencies = Vec::new();
        for task in tasks {
            writer_latencies.push(task.await.unwrap());
        }
        let elapsed = started.elapsed();
        let mut latencies: Vec<_> = writer_latencies.iter().flatten().copied().collect();
        latencies.sort_unstable();
        let operations = u32::from(writers) * u32::from(COMMITS_PER_WRITER);
        let p50 = latencies[latencies.len() / 2];
        let p95 = latencies[(latencies.len() * 95 / 100).min(latencies.len() - 1)];
        let per_writer_p95: Vec<_> = writer_latencies
            .iter_mut()
            .map(|latencies| {
                latencies.sort_unstable();
                latencies[(latencies.len() * 95 / 100).min(latencies.len() - 1)].as_micros()
            })
            .collect();
        let per_writer_max: Vec<_> = writer_latencies
            .iter()
            .map(|latencies| latencies.last().unwrap().as_micros())
            .collect();
        println!(
            "native_kv_group_commit writers={writers} operations={operations} ops_per_second={:.1} p50_us={} p95_us={} per_writer_p95_us={per_writer_p95:?} per_writer_max_us={per_writer_max:?} wall_ms={}",
            f64::from(operations) / elapsed.as_secs_f64(),
            p50.as_micros(),
            p95.as_micros(),
            elapsed.as_millis(),
        );
        store.close().await.unwrap();
    }
}
