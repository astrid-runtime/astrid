//! Opening and assembling the native runtime principal store.

use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::sync::{Arc, OnceLock};

use parking_lot::Mutex;

use crate::content::CatalogValidation;
use crate::engine::{
    DurableEnginePolicy, GroupCommitPolicy, ObjectCacheConfig, RecoveryLimits, RecoveryRetryPolicy,
};
use crate::error::StorageError;
use crate::identity::{IdentityStore, KvIdentityStore};
use crate::kv::{KvQuotaResolver, KvReadCacheConfig, KvStore, ScopedKvStore};
use crate::principal_state::StorageResult as PrincipalStorageResult;
use crate::principal_state::bootstrap;
use crate::principal_state::format_amendment::{
    PRE_DENSE_RADIX_FORMAT_SPEC_ID, STORE_METADATA_FILE, prepare_catalog_specification,
    prepare_destination, prepare_format_specification, representation_bootstrap_objects,
    store_metadata,
};
use crate::principal_state::migrations;
use crate::principal_state::native_io::atomic_write;
use crate::principal_state::owner_migration;
use crate::principal_state::volume_migration;
use crate::principal_state::{
    Blake3ObjectIdentityV1, NativeContentStagingArea, NativePrincipalContentStore,
    PrincipalDirectory, RuntimeEngine, RuntimePrincipalStore, RuntimeStore, StateOwner,
    StateOwnerCodecV2, StateOwnerResolver,
};
use crate::storage_model::ObjectIdentity;
use astrid_core::dirs::AstridHome;

/// Open every native projection over the authoritative principal store.
///
/// KV and named content share one object arena, principal-root CAS, and live
/// quota resolver. The caller must already hold the kernel singleton lock.
///
/// # Errors
///
/// Returns a storage error if policy, metadata, migration, verification, or
/// durable recovery fails.
pub async fn open_runtime_principal_store(
    home: &AstridHome,
    quota: Arc<dyn KvQuotaResolver<StateOwner>>,
) -> crate::principal_state::StorageResult<RuntimePrincipalStore> {
    open_runtime_principal_store_with_options(
        home,
        quota,
        PrincipalDirectory::default(),
        DurableEnginePolicy::default(),
    )
    .await
}

/// Open durable authority for a stop-time projection pack without restoring.
///
/// Normal store assembly materializes volume-backed projections. During clean
/// shutdown, the durable tree is still the source of the final generation, so
/// restoring first would discard newly written authority before it is packed.
///
/// # Errors
///
/// Returns the same errors as [`open_runtime_principal_store`].
pub async fn open_runtime_principal_store_for_pack(
    home: &AstridHome,
    quota: Arc<dyn KvQuotaResolver<StateOwner>>,
) -> crate::principal_state::StorageResult<RuntimePrincipalStore> {
    let policy = DurableEnginePolicy::default();
    if volume_migration::existing_volume_available(home)? {
        let (engine, receipt) =
            volume_migration::open_existing(home, policy)?.ok_or_else(|| {
                StorageError::Connection("Astrid volume disappeared while opening".to_owned())
            })?;
        let store = assemble_volume_store(
            home,
            quota,
            PrincipalDirectory::default(),
            Arc::new(engine),
            receipt,
            false,
            false,
        )
        .await?;
        quarantine_unrecognized_principal_store(home, &store)?;
        return Ok(store);
    }
    let (engine, receipt) = volume_migration::initialize_volume(home, policy)?;
    let store = assemble_volume_store(
        home,
        quota,
        PrincipalDirectory::default(),
        Arc::new(engine),
        receipt,
        false,
        false,
    )
    .await?;
    quarantine_unrecognized_principal_store(home, &store)?;
    Ok(store)
}

/// Open every native projection with an externally shared principal
/// directory.
///
/// Native kernel composition uses this form so namespace resolution,
/// identity lifecycle, and UID-to-alias quota policy share one mapping.
///
/// # Errors
///
/// Returns a storage error if policy, metadata, migration, verification, or
/// durable recovery fails.
pub async fn open_runtime_principal_store_with_directory(
    home: &AstridHome,
    quota: Arc<dyn KvQuotaResolver<StateOwner>>,
    principals: PrincipalDirectory,
) -> crate::principal_state::StorageResult<RuntimePrincipalStore> {
    open_runtime_principal_store_with_options(
        home,
        quota,
        principals,
        DurableEnginePolicy::default(),
    )
    .await
}

/// Open every native projection with an explicitly governed decoded-object
/// cache.
///
/// The injected policy owns total and per-principal resident budgets. Cache
/// misses, disabled policy, and eviction always fall back to verified arena
/// reads.
///
/// # Errors
///
/// Returns the same errors as [`open_runtime_principal_store`].
pub async fn open_runtime_principal_store_with_object_cache(
    home: &AstridHome,
    quota: Arc<dyn KvQuotaResolver<StateOwner>>,
    object_cache: ObjectCacheConfig<StateOwner>,
) -> crate::principal_state::StorageResult<RuntimePrincipalStore> {
    open_runtime_principal_store_with_options(
        home,
        quota,
        PrincipalDirectory::default(),
        DurableEnginePolicy::new(
            GroupCommitPolicy::default(),
            RecoveryRetryPolicy::default(),
            object_cache,
        ),
    )
    .await
}

/// Open every native projection with one complete operator-owned engine policy.
///
/// The policy controls durability batching, bounded in-process recovery, and
/// disposable decoded-object memory. It does not alter the persistent format
/// or principal quota semantics.
///
/// # Errors
///
/// Returns the same errors as [`open_runtime_principal_store`].
pub async fn open_runtime_principal_store_with_policy(
    home: &AstridHome,
    quota: Arc<dyn KvQuotaResolver<StateOwner>>,
    principals: PrincipalDirectory,
    policy: DurableEnginePolicy<StateOwner>,
) -> crate::principal_state::StorageResult<RuntimePrincipalStore> {
    open_runtime_principal_store_with_options(home, quota, principals, policy).await
}

async fn open_runtime_principal_store_with_options(
    home: &AstridHome,
    quota: Arc<dyn KvQuotaResolver<StateOwner>>,
    principals: PrincipalDirectory,
    policy: DurableEnginePolicy<StateOwner>,
) -> crate::principal_state::StorageResult<RuntimePrincipalStore> {
    if volume_migration::existing_volume_available(home)? {
        let (engine, receipt) =
            volume_migration::open_existing(home, policy)?.ok_or_else(|| {
                StorageError::Connection("Astrid volume disappeared while opening".to_owned())
            })?;
        let store = assemble_volume_store(
            home,
            quota,
            principals,
            Arc::new(engine),
            receipt,
            true,
            false,
        )
        .await;
        let store = store?;
        quarantine_unrecognized_principal_store(home, &store)?;
        return Ok(store);
    }
    let layout_version = home
        .layout_version()
        .map_err(|error| StorageError::Connection(error.to_string()))?;
    if layout_version.as_deref() != Some(astrid_core::dirs::LEGACY_LAYOUT_VERSION) {
        let (engine, receipt) = volume_migration::initialize_volume(home, policy)?;
        let store = assemble_volume_store(
            home,
            quota,
            principals,
            Arc::new(engine),
            receipt,
            true,
            true,
        )
        .await;
        let store = store?;
        quarantine_unrecognized_principal_store(home, &store)?;
        return Ok(store);
    }
    if unrecognized_principal_store_present(home)? {
        let (engine, receipt) = volume_migration::initialize_volume(home, policy)?;
        let store = assemble_volume_store(
            home,
            quota,
            principals,
            Arc::new(engine),
            receipt,
            true,
            true,
        )
        .await;
        let store = store?;
        super::runtime_tree::quarantine_principal_store(home, &store)?;
        return Ok(store);
    }
    open_migrated_directory_store(home, quota, principals, policy).await
}

async fn open_migrated_directory_store(
    home: &AstridHome,
    quota: Arc<dyn KvQuotaResolver<StateOwner>>,
    principals: PrincipalDirectory,
    policy: DurableEnginePolicy<StateOwner>,
) -> crate::principal_state::StorageResult<RuntimePrincipalStore> {
    let store_path = home.principal_store_path();
    let open_path = store_path.clone();
    let format_spec = bootstrap::format_specification()?;
    let format_spec_id = Blake3ObjectIdentityV1.identify(&format_spec);
    let catalog_spec = bootstrap::content_catalog_format_specification()?;
    let catalog_spec_id = Blake3ObjectIdentityV1.identify(&catalog_spec);
    let metadata = store_metadata(format_spec_id, catalog_spec_id);
    owner_migration::apply_if_required(home, &principals, &format_spec, &catalog_spec, &metadata)
        .await?;
    let metadata_for_open = metadata.clone();
    let opened = tokio::task::spawn_blocking(move || {
        let destination_format =
            prepare_destination(&open_path, &metadata_for_open, catalog_spec_id)?;
        let metadata_current = destination_format.metadata_is_current();
        let engine = RuntimeEngine::open_with_policy(
            &open_path,
            Blake3ObjectIdentityV1,
            StateOwnerCodecV2,
            RecoveryLimits::process_addressable(),
            DurableEnginePolicy::default(),
        )
        .map_err(|error| {
            StorageError::Connection(format!("open durable principal store: {error}"))
        })?;
        prepare_format_specification(&engine, destination_format, &format_spec, format_spec_id)?;
        prepare_catalog_specification(&engine, destination_format, &catalog_spec, catalog_spec_id)?;
        let bootstrap_objects = representation_bootstrap_objects(format_spec_id, catalog_spec_id);
        engine
            .ensure_direct_representation_catalogue_compatible_with(
                format_spec_id,
                &[PRE_DENSE_RADIX_FORMAT_SPEC_ID],
                &bootstrap_objects,
            )
            .map_err(|error| {
                StorageError::Connection(format!(
                    "activate direct representation catalogue: {error}"
                ))
            })?;
        Ok((engine, metadata_current))
    })
    .await
    .map_err(|error| {
        StorageError::Connection(format!(
            "durable principal-store open worker failed: {error}"
        ))
    })??;
    let (engine, metadata_current) = opened;
    let engine = Arc::new(engine);
    let validated_catalogs = Arc::new(Mutex::new(BTreeMap::<StateOwner, CatalogValidation>::new()));

    migrations::apply_required(home, &store_path, &engine, &validated_catalogs, &principals)
        .await?;
    if !metadata_current {
        let metadata_path = store_path.join(STORE_METADATA_FILE);
        tokio::task::spawn_blocking(move || atomic_write(&metadata_path, &metadata))
            .await
            .map_err(|error| {
                StorageError::Connection(format!(
                    "principal-store metadata migration worker failed: {error}"
                ))
            })??;
    }

    let (engine, receipt) = volume_migration::migrate_directory_store(home, engine, policy)?;
    assemble_volume_store(
        home,
        quota,
        principals,
        Arc::new(engine),
        receipt,
        true,
        true,
    )
    .await
}

async fn assemble_volume_store(
    home: &AstridHome,
    quota: Arc<dyn KvQuotaResolver<StateOwner>>,
    principals: PrincipalDirectory,
    engine: Arc<RuntimeEngine>,
    directory_cutover_receipt: String,
    restore_projection: bool,
    allow_receiptless_bootstrap: bool,
) -> crate::principal_state::StorageResult<RuntimePrincipalStore> {
    assemble_runtime_store(
        home,
        quota,
        principals,
        engine,
        directory_cutover_receipt,
        restore_projection,
        allow_receiptless_bootstrap,
    )
    .await
}

fn quarantine_unrecognized_principal_store(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
) -> PrincipalStorageResult<()> {
    if !unrecognized_principal_store_present(home)? {
        return Ok(());
    }
    super::runtime_tree::quarantine_principal_store(home, store)
}

fn unrecognized_principal_store_present(home: &AstridHome) -> PrincipalStorageResult<bool> {
    let source = home.principal_store_path();
    let metadata = match std::fs::symlink_metadata(&source) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(StorageError::Connection(format!(
                "inspect incomplete principal store {}: {error}",
                source.display()
            )));
        },
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(StorageError::Connection(format!(
            "principal store is redirected or not a directory: {}",
            source.display()
        )));
    }
    if source.join(STORE_METADATA_FILE).exists()
        || source.join(migrations::MIGRATION_MARKER_FILE).exists()
    {
        return Ok(false);
    }
    Ok(true)
}

async fn assemble_runtime_store(
    home: &AstridHome,
    quota: Arc<dyn KvQuotaResolver<StateOwner>>,
    principals: PrincipalDirectory,
    engine: Arc<RuntimeEngine>,
    directory_cutover_receipt: String,
    restore_projection: bool,
    allow_receiptless_bootstrap: bool,
) -> crate::principal_state::StorageResult<RuntimePrincipalStore> {
    let format_spec = bootstrap::format_specification()?;
    let format_spec_id = engine.identify(&format_spec);
    let catalog_spec = bootstrap::content_catalog_format_specification()?;
    let catalog_spec_id = engine.identify(&catalog_spec);
    let bootstrap_objects = representation_bootstrap_objects(format_spec_id, catalog_spec_id);
    let catalogue_engine = Arc::clone(&engine);
    tokio::task::spawn_blocking(move || {
        catalogue_engine.ensure_direct_representation_catalogue_compatible_with(
            format_spec_id,
            &[PRE_DENSE_RADIX_FORMAT_SPEC_ID],
            &bootstrap_objects,
        )
    })
    .await
    .map_err(|error| {
        StorageError::Connection(format!(
            "volume representation-catalogue worker failed: {error}"
        ))
    })?
    .map_err(|error| {
        StorageError::Connection(format!("activate volume representation catalogue: {error}"))
    })?;
    let validated_catalogs = Arc::new(Mutex::new(BTreeMap::<StateOwner, CatalogValidation>::new()));
    let validated_kv = Arc::new(crate::kv::KvValidationCache::default());

    let runtime_kv = Arc::new(
        RuntimeStore::from_engine_with_quota_and_content_validation(
            Arc::clone(&engine),
            StateOwnerResolver::new(principals.clone()),
            Arc::clone(&quota),
            Arc::clone(&validated_kv),
            Arc::clone(&validated_catalogs),
        )
        .with_read_cache(KvReadCacheConfig::bounded(
            NonZeroUsize::new(256 * 1024 * 1024).expect("256 MiB"),
            NonZeroUsize::new(64 * 1024 * 1024).expect("64 MiB"),
            NonZeroUsize::new(4_096).expect("owner limit"),
            NonZeroUsize::new(65_536).expect("entries per owner"),
        )),
    );
    let kv: Arc<dyn KvStore> = runtime_kv.clone();
    KvIdentityStore::with_principal_directory(
        ScopedKvStore::new(Arc::clone(&kv), "system:identity")?,
        principals.clone(),
    )
    .load_principal_directory()
    .await
    .map_err(|error| {
        StorageError::Connection(format!(
            "load principal identities before serving durable namespaces: {error}"
        ))
    })?;
    let content = Arc::new(
        NativePrincipalContentStore::from_engine_with_quota_and_validation(
            Arc::clone(&engine),
            quota,
            validated_catalogs,
            validated_kv,
        ),
    );
    let staging = Arc::new(OnceLock::new());
    let store = RuntimePrincipalStore {
        engine,
        directory_cutover_receipt: Arc::from(directory_cutover_receipt),
        runtime_kv,
        kv,
        content,
        staging: Arc::clone(&staging),
        principals,
    };
    if restore_projection {
        crate::principal_state::runtime_tree::reconcile_running_projection(
            home,
            &store,
            allow_receiptless_bootstrap,
        )?;
    }
    let staging_area = NativeContentStagingArea::open(home.content_staging_path())?;
    staging.set(Arc::new(staging_area)).map_err(|_| {
        StorageError::Internal("runtime store staging area initialized twice".to_owned())
    })?;
    Ok(store)
}

/// Open the native kernel's authoritative KV store.
///
/// The caller must already hold the kernel singleton lock. On first cutover,
/// legacy state is imported and independently verified before the completion
/// marker is made durable. A partial prior destination is quarantined rather
/// than trusted or deleted.
///
/// # Errors
///
/// Returns a storage error if policy, metadata, migration, verification, or
/// durable recovery fails.
pub async fn open_runtime_kv(
    home: &AstridHome,
    quota: Arc<dyn KvQuotaResolver<StateOwner>>,
) -> crate::principal_state::StorageResult<Arc<dyn KvStore>> {
    open_runtime_principal_store(home, quota)
        .await
        .map(|store| store.kv())
}

/// Open the native kernel KV projection with an externally shared principal
/// directory.
///
/// # Errors
///
/// Returns a storage error if policy, metadata, migration, verification, or
/// durable recovery fails.
pub async fn open_runtime_kv_with_directory(
    home: &AstridHome,
    quota: Arc<dyn KvQuotaResolver<StateOwner>>,
    principals: PrincipalDirectory,
) -> crate::principal_state::StorageResult<Arc<dyn KvStore>> {
    open_runtime_principal_store_with_directory(home, quota, principals)
        .await
        .map(|store| store.kv())
}
