//! Native runtime integration for durable principal-owned state.
//!
//! The legacy raw KV database is migrated under the kernel's singleton boot
//! lock. A durable store is not served until every legacy entry has been
//! imported, independently verified by owner, flushed, and covered by a
//! completion marker. The legacy database remains untouched as a recovery
//! source.

use std::collections::BTreeMap;
use std::sync::Arc;

use astrid_core::dirs::AstridHome;
use astrid_core::identity::PrincipalUid;
use astrid_core::kernel_api::{ProjectionNameDiagnostic, ProjectionNamePolicyPreset};
use astrid_core::principal::PrincipalId;
use astrid_storage_engine::{
    DurableEngine, IdentityScheme, ObjectCacheConfig, PersistentObjectIdentity, PrincipalCodec,
    RecoveryLimits,
};
use astrid_storage_model::{ObjectClass, ObjectId, ObjectIdentity, ObjectRecord, ReferenceKind};
use parking_lot::Mutex;

pub use crate::PrincipalDirectory;
use crate::content::{
    CatalogValidation, ContentWriteOutcome, PrincipalContentStore, ProjectionNamePolicy,
    plan_projection_names,
};
use crate::error::{StorageError, StorageResult};
use crate::identity::{IdentityStore, KvIdentityStore};
#[cfg(all(test, feature = "legacy-surrealkv"))]
use crate::kv::SurrealKvStore;
use crate::kv::{KvPrincipalResolver, KvQuotaResolver, KvStore, ScopedKvStore, TreeKvStore};

mod bootstrap;
#[cfg(test)]
mod compaction_tests;
mod format_amendment;
#[cfg(test)]
mod format_amendment_tests;
#[cfg(test)]
mod format_migration_tests;
mod migrations;
mod native_io;
mod owner_migration;
#[cfg(test)]
mod projection_name_tests;
mod staging;

#[cfg(test)]
use format_amendment::{
    DestinationFormat, PRE_DERIVATION_FORMAT_SPEC_ID, STORE_FORMAT_SPEC, legacy_store_metadata,
    object_id_hex, persist_format_specification,
};
use format_amendment::{
    STORE_METADATA_FILE, prepare_catalog_specification, prepare_destination,
    prepare_format_specification, store_metadata,
};
use native_io::atomic_write;
pub use staging::{
    NativeContentStagingArea, ReadyStagedContent, StagedContentId, StagedContentWriter,
};

/// Explicit owner of one durable state root.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum StateOwner {
    /// Kernel-owned state that must not consume a user's storage quota.
    System,
    /// State owned by one validated Astrid principal.
    Principal(PrincipalUid),
}

/// Version-one canonical BLAKE3 identity for typed storage objects.
#[derive(Clone, Copy, Debug, Default)]
pub struct Blake3ObjectIdentityV1;

const BLAKE3_OBJECT_IDENTITY_V1_SCHEME: IdentityScheme = match IdentityScheme::new(1, 1) {
    Some(scheme) => scheme,
    None => panic!("the production identity scheme uses non-zero wire codes"),
};

impl ObjectIdentity for Blake3ObjectIdentityV1 {
    fn identify(&self, record: &ObjectRecord) -> ObjectId {
        let mut hasher =
            blake3::Hasher::new_derive_key("astrid principal store object identity v1");
        hasher.update(&record.kind().code().to_le_bytes());
        hasher.update(&record.format_version().get().to_le_bytes());
        hash_length(&mut hasher, record.canonical_bytes().len());
        hasher.update(record.canonical_bytes());
        hasher.update(&record.logical_bytes().to_le_bytes());
        hasher.update(&[match record.class() {
            ObjectClass::Data => 0,
            ObjectClass::Metadata => 1,
        }]);
        hash_length(&mut hasher, record.references().len());
        for reference in record.references() {
            hash_length(&mut hasher, reference.label().as_bytes().len());
            hasher.update(reference.label().as_bytes());
            hasher.update(reference.target().as_bytes());
            hasher.update(&[match reference.kind() {
                ReferenceKind::Owns => 0,
                ReferenceKind::Evidence => 1,
                ReferenceKind::Lineage => 2,
                ReferenceKind::Derived => 3,
            }]);
        }
        ObjectId::new(*hasher.finalize().as_bytes())
    }
}

impl PersistentObjectIdentity for Blake3ObjectIdentityV1 {
    fn scheme(&self) -> IdentityScheme {
        BLAKE3_OBJECT_IDENTITY_V1_SCHEME
    }
}

fn hash_length(hasher: &mut blake3::Hasher, length: usize) {
    hasher.update(&(length as u128).to_le_bytes());
}

/// Canonical codec for [`StateOwner`].
#[derive(Clone, Copy, Debug, Default)]
pub struct StateOwnerCodecV1;

impl PrincipalCodec<StateOwner> for StateOwnerCodecV1 {
    fn encode(&self, owner: &StateOwner) -> Vec<u8> {
        match owner {
            StateOwner::System => vec![0],
            StateOwner::Principal(principal) => {
                let mut bytes = Vec::with_capacity(33);
                bytes.push(1);
                bytes.extend_from_slice(principal.as_bytes());
                bytes
            },
        }
    }

    fn decode(&self, bytes: &[u8]) -> Option<StateOwner> {
        match bytes.split_first()? {
            (0, []) => Some(StateOwner::System),
            (1, principal) if principal.len() == 32 => {
                let uid = PrincipalUid::from_bytes(<[u8; 32]>::try_from(principal).ok()?);
                Some(StateOwner::Principal(uid))
            },
            _ => None,
        }
    }
}

/// Authority-aware mapping from live KV namespaces to durable owners.
#[derive(Clone, Debug)]
pub struct StateOwnerResolver {
    principals: PrincipalDirectory,
}

impl StateOwnerResolver {
    /// Bind namespace resolution to the validated live principal directory.
    #[must_use]
    pub fn new(principals: PrincipalDirectory) -> Self {
        Self { principals }
    }
}

impl KvPrincipalResolver<StateOwner> for StateOwnerResolver {
    fn resolve(&self, namespace: &str) -> StorageResult<StateOwner> {
        let Some((principal, capsule)) = namespace.split_once(":capsule:") else {
            return Ok(StateOwner::System);
        };
        if capsule.is_empty() {
            return Err(StorageError::InvalidKey(
                "host-stamped capsule namespace has an empty capsule identifier".to_owned(),
            ));
        }
        let principal = PrincipalId::new(principal.to_owned()).map_err(|error| {
            StorageError::InvalidKey(format!(
                "capsule namespace has invalid host-stamped principal: {error}"
            ))
        })?;
        self.principals
            .uid_for(&principal)
            .map(StateOwner::Principal)
    }
}

type RuntimeEngine = DurableEngine<StateOwner, Blake3ObjectIdentityV1, StateOwnerCodecV1>;
type RuntimeStore =
    TreeKvStore<StateOwner, Blake3ObjectIdentityV1, StateOwnerResolver, RuntimeEngine>;

/// Native named-content projection sharing the authoritative principal arena.
pub type NativePrincipalContentStore = PrincipalContentStore<
    StateOwner,
    DurableEngine<StateOwner, Blake3ObjectIdentityV1, StateOwnerCodecV1>,
>;

/// Native principal-store projections opened over one durable engine.
#[derive(Clone)]
pub struct RuntimePrincipalStore {
    engine: Arc<RuntimeEngine>,
    kv: Arc<dyn KvStore>,
    content: Arc<NativePrincipalContentStore>,
    staging: Arc<NativeContentStagingArea>,
    principals: PrincipalDirectory,
}

impl RuntimePrincipalStore {
    /// Clone the runtime KV projection.
    #[must_use]
    pub fn kv(&self) -> Arc<dyn KvStore> {
        Arc::clone(&self.kv)
    }

    /// Clone the named content projection.
    #[must_use]
    pub fn content(&self) -> Arc<NativePrincipalContentStore> {
        Arc::clone(&self.content)
    }

    /// Clone the private native content-staging area.
    #[must_use]
    pub fn staging(&self) -> Arc<NativeContentStagingArea> {
        Arc::clone(&self.staging)
    }

    /// Clone the live alias-to-UID directory used by every projection.
    #[must_use]
    pub fn principal_directory(&self) -> PrincipalDirectory {
        self.principals.clone()
    }

    /// Inspect one owner's exact catalog names under a target-volume policy.
    ///
    /// This is a read-only diagnostic. It never mutates the principal root or
    /// disposable projection metadata and it never reports another owner
    /// unless the caller already supplied that typed owner.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the authoritative catalog cannot be read
    /// or the selected policy cannot produce a collision-free plan.
    pub async fn projection_name_diagnostic(
        &self,
        owner: StateOwner,
        preset: ProjectionNamePolicyPreset,
    ) -> StorageResult<ProjectionNameDiagnostic> {
        let content = Arc::clone(&self.content);
        tokio::task::spawn_blocking(move || {
            let entries = content.list(&owner).map_err(|error| {
                StorageError::Internal(format!(
                    "read principal content names for projection diagnosis: {error}"
                ))
            })?;
            let names = entries
                .into_iter()
                .map(|entry| entry.name().clone())
                .collect::<Vec<_>>();
            plan_projection_names(ProjectionNamePolicy::from(preset), &names)
                .map(ProjectionNameDiagnostic::from)
                .map_err(|error| {
                    StorageError::Internal(format!("plan target-volume projection names: {error}"))
                })
        })
        .await
        .map_err(|error| {
            StorageError::Internal(format!("projection-name diagnostic worker failed: {error}"))
        })?
    }

    /// Publish one sealed native write through the authoritative content store.
    ///
    /// # Errors
    ///
    /// Returns a storage or content-publication error while retaining the
    /// staged bytes for an idempotent retry.
    pub async fn publish_staged(
        &self,
        staged: ReadyStagedContent,
    ) -> StorageResult<ContentWriteOutcome> {
        self.staging
            .publish(staged, Arc::clone(&self.content))
            .await
    }

    #[cfg(test)]
    fn validated_catalog_count(&self) -> usize {
        self.content.validated_catalog_count()
    }
}

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
) -> StorageResult<RuntimePrincipalStore> {
    open_runtime_principal_store_with_options(
        home,
        quota,
        PrincipalDirectory::default(),
        ObjectCacheConfig::disabled(),
    )
    .await
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
) -> StorageResult<RuntimePrincipalStore> {
    open_runtime_principal_store_with_options(
        home,
        quota,
        principals,
        ObjectCacheConfig::disabled(),
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
) -> StorageResult<RuntimePrincipalStore> {
    open_runtime_principal_store_with_options(
        home,
        quota,
        PrincipalDirectory::default(),
        object_cache,
    )
    .await
}

async fn open_runtime_principal_store_with_options(
    home: &AstridHome,
    quota: Arc<dyn KvQuotaResolver<StateOwner>>,
    principals: PrincipalDirectory,
    object_cache: ObjectCacheConfig<StateOwner>,
) -> StorageResult<RuntimePrincipalStore> {
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
        let engine = RuntimeEngine::open_with_object_cache(
            &open_path,
            Blake3ObjectIdentityV1,
            StateOwnerCodecV1,
            RecoveryLimits::process_addressable(),
            object_cache,
        )
        .map_err(|error| {
            StorageError::Connection(format!("open durable principal store: {error}"))
        })?;
        prepare_format_specification(&engine, destination_format, &format_spec, format_spec_id)?;
        prepare_catalog_specification(&engine, destination_format, &catalog_spec, catalog_spec_id)?;
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
    let validated_kv = Arc::new(crate::kv::KvValidationCache::default());

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

    let kv: Arc<dyn KvStore> =
        Arc::new(RuntimeStore::from_engine_with_quota_and_content_validation(
            Arc::clone(&engine),
            StateOwnerResolver::new(principals.clone()),
            Arc::clone(&quota),
            Arc::clone(&validated_kv),
            Arc::clone(&validated_catalogs),
        ));
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
    let staging = Arc::new(NativeContentStagingArea::open(home.content_staging_path())?);
    Ok(RuntimePrincipalStore {
        engine,
        kv,
        content,
        staging,
        principals,
    })
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
) -> StorageResult<Arc<dyn KvStore>> {
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
) -> StorageResult<Arc<dyn KvStore>> {
    open_runtime_principal_store_with_directory(home, quota, principals)
        .await
        .map(|store| store.kv())
}

#[cfg(test)]
mod runtime_tests;
