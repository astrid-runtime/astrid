//! Native runtime integration for durable principal-owned state.
//!
//! The legacy raw KV database is migrated under the kernel's singleton boot
//! lock. A durable store is not served until every legacy entry has been
//! imported, independently verified by owner, flushed, and covered by a
//! completion marker. The legacy database remains untouched as a recovery
//! source.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::sync::Arc;

use astrid_core::dirs::AstridHome;
use astrid_core::principal::PrincipalId;
use astrid_storage_engine::{
    DurableEngine, IdentityScheme, PersistentObjectIdentity, PrincipalCodec, RecoveryLimits,
};
use astrid_storage_model::{ObjectClass, ObjectId, ObjectIdentity, ObjectRecord, ReferenceKind};
use parking_lot::Mutex;

use crate::content::{CatalogValidation, ContentWriteOutcome, PrincipalContentStore};
use crate::error::{StorageError, StorageResult};
#[cfg(all(test, feature = "legacy-surrealkv"))]
use crate::kv::SurrealKvStore;
use crate::kv::{KvPrincipalResolver, KvQuotaResolver, KvStore, TreeKvStore};

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
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StateOwner {
    /// Kernel-owned state that must not consume a user's storage quota.
    System,
    /// State owned by one validated Astrid principal.
    Principal(PrincipalId),
}

impl Ord for StateOwner {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::System, Self::System) => Ordering::Equal,
            (Self::System, Self::Principal(_)) => Ordering::Less,
            (Self::Principal(_), Self::System) => Ordering::Greater,
            (Self::Principal(left), Self::Principal(right)) => left.as_str().cmp(right.as_str()),
        }
    }
}

impl PartialOrd for StateOwner {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
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
                let mut bytes = Vec::with_capacity(principal.as_str().len().saturating_add(1));
                bytes.push(1);
                bytes.extend_from_slice(principal.as_str().as_bytes());
                bytes
            },
        }
    }

    fn decode(&self, bytes: &[u8]) -> Option<StateOwner> {
        match bytes.split_first()? {
            (0, []) => Some(StateOwner::System),
            (1, principal) => std::str::from_utf8(principal)
                .ok()
                .and_then(|value| PrincipalId::new(value.to_owned()).ok())
                .map(StateOwner::Principal),
            _ => None,
        }
    }
}

/// Authority-aware mapping from live KV namespaces to durable owners.
#[derive(Clone, Copy, Debug, Default)]
pub struct StateOwnerResolver;

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
        PrincipalId::new(principal.to_owned())
            .map(StateOwner::Principal)
            .map_err(|error| {
                StorageError::InvalidKey(format!(
                    "capsule namespace has invalid host-stamped principal: {error}"
                ))
            })
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
    let store_path = home.principal_store_path();
    let open_path = store_path.clone();
    let format_spec = bootstrap::format_specification()?;
    let format_spec_id = Blake3ObjectIdentityV1.identify(&format_spec);
    let catalog_spec = bootstrap::content_catalog_format_specification()?;
    let catalog_spec_id = Blake3ObjectIdentityV1.identify(&catalog_spec);
    let metadata = store_metadata(format_spec_id, catalog_spec_id);
    let metadata_for_open = metadata.clone();
    let opened = tokio::task::spawn_blocking(move || {
        let destination_format = prepare_destination(
            &open_path,
            &metadata_for_open,
            format_spec_id,
            catalog_spec_id,
        )?;
        let metadata_current = destination_format.metadata_is_current();
        let engine = RuntimeEngine::open(
            &open_path,
            Blake3ObjectIdentityV1,
            StateOwnerCodecV1,
            RecoveryLimits::process_addressable(),
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

    migrations::apply_required(home, &store_path, &engine, &validated_catalogs).await?;
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
            StateOwnerResolver,
            Arc::clone(&quota),
            Arc::clone(&validated_catalogs),
        ));
    let content = Arc::new(
        NativePrincipalContentStore::from_engine_with_quota_and_validation(
            Arc::clone(&engine),
            quota,
            validated_catalogs,
        ),
    );
    let staging = Arc::new(NativeContentStagingArea::open(home.content_staging_path())?);
    Ok(RuntimePrincipalStore {
        engine,
        kv,
        content,
        staging,
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

#[cfg(test)]
mod runtime_tests;
