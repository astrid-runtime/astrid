//! Native runtime integration for durable principal-owned state.
//!
//! The legacy raw KV database is migrated under the kernel's singleton boot
//! lock. A durable store is not served until every legacy entry has been
//! imported, independently verified by owner, flushed, and covered by a
//! completion marker. The layout cutover retains the legacy database until
//! that verification succeeds, records a content-bound receipt, and then
//! removes the retired source.

use std::sync::Arc;

pub use crate::PrincipalDirectory;
use crate::capsule_registry::CapsuleRegistry;
use crate::content::{
    ContentBatchWriteOutcome, ContentWriteOutcome, PrincipalContentStore, ProjectionNamePolicy,
    plan_projection_names,
};
use crate::engine::{
    DurableEngine, IdentityScheme, ObjectCacheStats, PersistentObjectIdentity, PrincipalCodec,
};
#[cfg(test)]
use crate::engine::{ObjectCacheConfig, RecoveryLimits};
use crate::error::{StorageError, StorageResult};
#[cfg(test)]
use crate::identity::{IdentityStore, KvIdentityStore};
#[cfg(test)]
use crate::kv::KvQuotaResolver;
#[cfg(all(test, feature = "legacy-surrealkv"))]
use crate::kv::SurrealKvStore;
use crate::kv::{KvPrincipalResolver, KvStore, ScopedKvStore, TreeKvStore};
use crate::storage_model::{
    ObjectClass, ObjectId, ObjectIdentity, ObjectRecord, PhysicalIdentity, ReferenceKind,
};
use astrid_core::FleetUid;
use astrid_core::dirs::AstridHome;
use astrid_core::identity::PrincipalUid;
use astrid_core::kernel_api::{ProjectionNameDiagnostic, ProjectionNamePolicyPreset};
use astrid_core::principal::PrincipalId;

mod bootstrap;
#[cfg(test)]
mod compaction_tests;
#[cfg(test)]
mod content_staging_tests;
mod contiguous_ingest;
mod format_amendment;
#[cfg(test)]
mod format_amendment_tests;
#[cfg(test)]
mod format_identity_tests;
#[cfg(test)]
mod format_migration_tests;
#[cfg(test)]
mod hosted_volume_tests;
mod migrations;
mod native_io;
#[cfg(test)]
mod native_kv_scale_probe_tests;
mod owner_migration;
#[cfg(test)]
mod projection_name_tests;
#[cfg(all(test, feature = "legacy-surrealkv"))]
mod release_fixture_tests;
#[cfg(test)]
mod runtime_tests;
mod runtime_tree;
mod staging;
mod store_open;
#[cfg(test)]
mod store_open_volume_tests;
mod volume_migration;

/// Durable runtime format admitted before layout version two can commit.
pub const RUNTIME_STORE_FORMAT_ID: &str =
    "astrid-principal-store-v1;state-owner-v2;workspace-branch-v1";

pub use contiguous_ingest::ContiguousFileIngest;
#[cfg(test)]
use format_amendment::{
    DestinationFormat, PRE_DERIVATION_FORMAT_SPEC_ID, STORE_FORMAT_SPEC, legacy_store_metadata,
    object_id_hex, persist_format_specification,
};
#[cfg(test)]
use format_amendment::{
    STORE_METADATA_FILE, prepare_catalog_specification, prepare_destination,
    prepare_format_specification, store_metadata,
};
use native_io::atomic_write;
pub use runtime_tree::RuntimeTreeEntry;
pub use staging::{
    NativeContentStagingArea, ReadyStagedContent, StagedContentId, StagedContentWriter,
};
pub use store_open::open_runtime_principal_store_for_pack;
pub use store_open::{
    open_runtime_kv, open_runtime_kv_with_directory, open_runtime_principal_store,
    open_runtime_principal_store_with_directory, open_runtime_principal_store_with_object_cache,
    open_runtime_principal_store_with_policy,
};

/// Explicit owner of one durable state root.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum StateOwner {
    /// Kernel-owned state that must not consume a user's storage quota.
    System,
    /// State owned by one validated Astrid principal.
    Principal(PrincipalUid),
    /// State shared by the admitted members of one user-owned fleet.
    Fleet(FleetUid),
}

/// Version-one canonical BLAKE3 identity for typed storage objects.
#[derive(Clone, Copy, Debug, Default)]
pub struct Blake3ObjectIdentityV1;

/// Canonical BLAKE3 construction two identity for physical store records.
#[derive(Clone, Copy, Debug, Default)]
pub struct Blake3PhysicalIdentityV1;

impl PhysicalIdentity for Blake3PhysicalIdentityV1 {
    fn identify(&self, context: &'static str, material: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(context);
        hasher.update(material);
        *hasher.finalize().as_bytes()
    }

    fn identify_parts(&self, context: &'static str, parts: &[&[u8]]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(context);
        for part in parts {
            hasher.update(part);
        }
        *hasher.finalize().as_bytes()
    }
}

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

/// Frozen owner domain admitted by [`StateOwnerCodecV1`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum StateOwnerV1 {
    /// Kernel-owned state.
    System,
    /// State owned by one validated principal.
    Principal(PrincipalUid),
}

impl From<StateOwnerV1> for StateOwner {
    fn from(owner: StateOwnerV1) -> Self {
        match owner {
            StateOwnerV1::System => Self::System,
            StateOwnerV1::Principal(principal) => Self::Principal(principal),
        }
    }
}

/// Canonical codec for [`StateOwnerV1`].
#[derive(Clone, Copy, Debug, Default)]
pub struct StateOwnerCodecV1;

impl PrincipalCodec<StateOwnerV1> for StateOwnerCodecV1 {
    fn encode(&self, owner: &StateOwnerV1) -> Vec<u8> {
        match owner {
            StateOwnerV1::System => vec![0],
            StateOwnerV1::Principal(principal) => {
                let mut bytes = Vec::with_capacity(33);
                bytes.push(1);
                bytes.extend_from_slice(principal.as_bytes());
                bytes
            },
        }
    }

    fn decode(&self, bytes: &[u8]) -> Option<StateOwnerV1> {
        match bytes.split_first()? {
            (0, []) => Some(StateOwnerV1::System),
            (1, principal) if principal.len() == 32 => {
                let uid = PrincipalUid::from_bytes(<[u8; 32]>::try_from(principal).ok()?);
                Some(StateOwnerV1::Principal(uid))
            },
            _ => None,
        }
    }
}

/// Version-two canonical owner grammar with an explicit fleet tag.
///
/// The version-one `System` and `Principal` encodings remain byte-for-byte
/// stable. Fleet ownership is appended under tag `2`; it is never represented
/// as a synthetic principal or hidden beneath system authority.
#[derive(Clone, Copy, Debug, Default)]
pub struct StateOwnerCodecV2;

impl PrincipalCodec<StateOwner> for StateOwnerCodecV2 {
    fn encode(&self, owner: &StateOwner) -> Vec<u8> {
        match owner {
            StateOwner::System => vec![0],
            StateOwner::Principal(principal) => {
                let mut bytes = Vec::with_capacity(33);
                bytes.push(1);
                bytes.extend_from_slice(principal.as_bytes());
                bytes
            },
            StateOwner::Fleet(fleet) => {
                let mut bytes = Vec::with_capacity(33);
                bytes.push(2);
                bytes.extend_from_slice(fleet.as_bytes());
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
            (2, fleet) if fleet.len() == 32 => {
                let uid = FleetUid::from_bytes(<[u8; 32]>::try_from(fleet).ok()?);
                Some(StateOwner::Fleet(uid))
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
        if let Some((principal, control)) = namespace.split_once(":control:") {
            if principal == "system" && matches!(control, "audit" | "invites" | "pair-tokens") {
                return Ok(StateOwner::System);
            }
            // The fixed distro control projection is principal-owned but has
            // no capsule suffix. It is kept distinct from env/secret views
            // so ordinary capsule code cannot address distro provenance.
            if control == "distro" {
                let uid_text = principal.strip_prefix("principal-uid:").ok_or_else(|| {
                    StorageError::InvalidKey(
                        "principal distro namespace must use immutable principal-uid".to_owned(),
                    )
                })?;
                let uid = uid_text.parse::<PrincipalUid>().map_err(|error| {
                    StorageError::InvalidKey(format!("invalid principal distro UID: {error}"))
                })?;
                if !self.principals.contains_uid(uid) {
                    return Err(StorageError::InvalidKey(
                        "principal distro UID is not an admitted durable identity".to_owned(),
                    ));
                }
                return Ok(StateOwner::Principal(uid));
            }
            // Host-only control namespaces share the same durable owner and
            // quota as a principal's capsule namespace, while remaining
            // unreachable through the guest KV view. They are keyed only by
            // immutable UIDs; mutable aliases are rejected so rename/reuse
            // cannot redirect durable env or secret state.
            let Some((kind, capsule)) = control.split_once(':') else {
                return Err(StorageError::InvalidKey(
                    "control namespace must name env or secret and a capsule".to_owned(),
                ));
            };
            if !matches!(kind, "env" | "secret") || capsule.is_empty() || capsule.contains(':') {
                return Err(StorageError::InvalidKey(
                    "control namespace has an invalid projection or capsule".to_owned(),
                ));
            }
            if principal == "system" {
                return Ok(StateOwner::System);
            }
            let uid_text = principal.strip_prefix("principal-uid:").ok_or_else(|| {
                StorageError::InvalidKey(
                    "principal control namespace must use immutable principal-uid".to_owned(),
                )
            })?;
            let uid = uid_text.parse::<PrincipalUid>().map_err(|error| {
                StorageError::InvalidKey(format!("invalid principal control UID: {error}"))
            })?;
            if !self.principals.contains_uid(uid) {
                return Err(StorageError::InvalidKey(
                    "principal control UID is not an admitted durable identity".to_owned(),
                ));
            }
            return Ok(StateOwner::Principal(uid));
        }

        let Some((principal, capsule)) = namespace.split_once(":capsule:") else {
            return Ok(StateOwner::System);
        };
        if capsule.is_empty() || capsule.contains(':') {
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

type RuntimeEngine = DurableEngine<StateOwner, Blake3ObjectIdentityV1, StateOwnerCodecV2>;
type RuntimeStore =
    TreeKvStore<StateOwner, Blake3ObjectIdentityV1, StateOwnerResolver, RuntimeEngine>;

/// Native named-content projection sharing the authoritative principal arena.
pub type NativePrincipalContentStore = PrincipalContentStore<
    StateOwner,
    DurableEngine<StateOwner, Blake3ObjectIdentityV1, StateOwnerCodecV2>,
>;

/// Native principal-store projections opened over one durable engine.
#[derive(Clone)]
pub struct RuntimePrincipalStore {
    engine: Arc<RuntimeEngine>,
    directory_cutover_receipt: Arc<str>,
    runtime_kv: Arc<RuntimeStore>,
    kv: Arc<dyn KvStore>,
    content: Arc<NativePrincipalContentStore>,
    staging: Arc<NativeContentStagingArea>,
    principals: PrincipalDirectory,
}

impl RuntimePrincipalStore {
    /// Retire the verified directory-store cutover source after the caller's
    /// global migration barrier is durable.
    ///
    /// Opening a runtime store deliberately retains `var/principal-store`:
    /// storage-local cutover verification cannot authorize deletion before
    /// the kernel has receipted every other released-layout component. The
    /// post-barrier caller invokes this method only after its component ledger
    /// is committed. A surviving source is independently reopened, matched to
    /// the immutable volume cutover receipt and current destination roots, and
    /// then removed with no-follow tree retirement.
    ///
    /// # Errors
    ///
    /// Returns a storage error if the source changed, the cutover receipt or
    /// destination does not match it, or safe no-follow retirement fails.
    pub fn retire_verified_legacy_directory_store(&self, home: &AstridHome) -> StorageResult<()> {
        volume_migration::retire_verified_directory_if_present(
            home,
            &self.directory_cutover_receipt,
        )
    }

    /// Return privileged decoded-object cache diagnostics.
    ///
    /// These values are for kernel and operator accounting. Guest surfaces
    /// must not expose cache residency because it can reveal cross-principal
    /// reuse.
    #[must_use]
    pub fn object_cache_stats(&self) -> ObjectCacheStats {
        self.engine.object_cache_stats()
    }

    /// Return one owner's current logical decoded-object cache charge.
    ///
    /// The charge is independent of whether physical records are shared.
    #[must_use]
    pub fn object_cache_principal_charge(&self, owner: &StateOwner) -> u64 {
        self.engine.object_cache_principal_charge(owner)
    }

    /// Honor current resident-memory pressure by evicting cache entries.
    pub fn reclaim_object_cache(&self) {
        self.engine.reclaim_object_cache();
    }

    /// Return backend-reported free capacity and active arena bytes.
    ///
    /// This read-only media capability is suitable for audit or migration
    /// preflight. It never derives capacity from an `AstridHome` path and
    /// returns `None` when the selected bare-metal adapter cannot report it.
    ///
    /// # Errors
    ///
    /// Returns a storage error if the backend capacity query fails.
    pub fn compaction_capacity(&self) -> StorageResult<Option<(u64, u64)>> {
        self.engine
            .compaction_capacity()
            .map_err(|error| StorageError::Connection(format!("read storage capacity: {error}")))
    }

    /// Clone the runtime KV projection.
    #[must_use]
    pub fn kv(&self) -> Arc<dyn KvStore> {
        Arc::clone(&self.kv)
    }

    /// Return a host-only system-control projection over the authoritative
    /// principal store.
    ///
    /// Control projections are deliberately separate from principal capsule
    /// namespaces and are never handed to a guest or filesystem mount. The
    /// component grammar is intentionally narrow so callers cannot turn this
    /// convenience into an unrestricted namespace selector.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::InvalidKey`] when `component` is empty, too
    /// long, or contains characters outside the narrow control grammar.
    pub fn system_control_kv(&self, component: &str) -> StorageResult<ScopedKvStore> {
        if component.is_empty()
            || component.len() > 64
            || !component
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(StorageError::InvalidKey(
                "system control component must be lowercase alphanumeric or '-'".to_owned(),
            ));
        }
        ScopedKvStore::new(Arc::clone(&self.kv), format!("system:control:{component}"))
    }

    /// Return a host-only control projection owned by one immutable principal
    /// UID. This is the only constructor for durable principal control state;
    /// callers cannot select an alias-derived namespace.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::InvalidKey`] when the component is invalid or
    /// when `principal` is not an admitted durable identity.
    pub fn principal_control_kv(
        &self,
        principal: PrincipalUid,
        component: &str,
    ) -> StorageResult<ScopedKvStore> {
        if !self.principals.contains_uid(principal) {
            return Err(StorageError::InvalidKey(
                "principal control UID is not an admitted durable identity".to_owned(),
            ));
        }
        if component.is_empty()
            || component.len() > 64
            || !component
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(StorageError::InvalidKey(
                "principal control component must be lowercase alphanumeric or '-'".to_owned(),
            ));
        }
        ScopedKvStore::new(
            Arc::clone(&self.kv),
            format!("principal-uid:{principal}:control:{component}"),
        )
    }

    /// Clone the named content projection.
    #[must_use]
    pub fn content(&self) -> Arc<NativePrincipalContentStore> {
        Arc::clone(&self.content)
    }

    /// Admit the durable native runtime tree into the system-owned catalog.
    ///
    /// The source is walked without following redirects. The live runtime
    /// socket and hosted volume remain POSIX-owned; every other regular file,
    /// including sentinels and bootstrap binaries, is published under its
    /// slash-separated relative path through the packed content arena. Other
    /// special entries are skipped. This is an explicit admission operation,
    /// never an open-time conversion of existing volume regions.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the source tree contains a redirect,
    /// cannot be read, or packed publication fails.
    pub fn admit_runtime_tree(
        &self,
        runtime_root: impl AsRef<std::path::Path>,
    ) -> StorageResult<()> {
        runtime_tree::admit(self, runtime_root.as_ref())
    }

    /// Publish the live running projection while retaining host files.
    ///
    /// Graceful kernel shutdown calls this before its durable projections are
    /// closed. Host retirement remains an explicit post-exit CLI stop duty so
    /// the process can still read its projected files.
    ///
    /// # Errors
    ///
    /// Returns a storage error if the running projection cannot be admitted or
    /// flushed without following a redirect.
    pub fn publish_runtime_projection(&self, home: &AstridHome) -> StorageResult<()> {
        runtime_tree::publish_running_projection(home, self)
    }

    /// Pack running projection changes and retire every durable host sidecar.
    ///
    /// # Errors
    ///
    /// Returns a storage error if the running projection cannot be admitted,
    /// flushed, or retired without following a redirect.
    pub fn pack_and_retire_runtime_projection(&self, home: &AstridHome) -> StorageResult<()> {
        runtime_tree::pack_and_retire_projection(home, self)
    }

    /// Scan the native runtime tree without reading file payloads.
    ///
    /// The scan uses the exact exclusions and path validation applied by
    /// [`Self::admit_runtime_tree`]. Kernel migration receipts therefore do
    /// not maintain a second, drifting definition of the packed tree.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the source tree contains a redirect,
    /// cannot be read, or has an unrepresentable timestamp.
    pub fn scan_runtime_tree(
        &self,
        runtime_root: impl AsRef<std::path::Path>,
    ) -> StorageResult<Vec<RuntimeTreeEntry>> {
        runtime_tree::scan(runtime_root.as_ref())
    }

    /// Return the durable per-principal installed-capsule registry.
    ///
    /// The registry is backed by the same owner-root content projection as KV;
    /// callers must supply an explicit [`StateOwner::Principal`] when reading
    /// or mutating packages. No host directory is consulted for authority.
    #[must_use]
    pub fn capsules(&self) -> CapsuleRegistry<StateOwner, RuntimeEngine> {
        CapsuleRegistry::new(Arc::clone(&self.content))
    }

    /// Clone the private native content-staging area.
    #[must_use]
    pub fn staging(&self) -> Arc<NativeContentStagingArea> {
        Arc::clone(&self.staging)
    }

    /// Return file roots held by currently open immutable content handles.
    ///
    /// Compaction retention includes these closures so a handle never reads a
    /// reclaimed generation after an unrelated catalog update.
    #[must_use]
    pub(crate) fn compaction_read_handle_roots(&self) -> Vec<(StateOwner, ObjectId)> {
        self.content.compaction_read_handle_roots()
    }

    /// Clone the live alias-to-UID directory used by every projection.
    #[must_use]
    pub fn principal_directory(&self) -> PrincipalDirectory {
        self.principals.clone()
    }

    /// Remove every KV namespace owned by one immutable principal UID.
    ///
    /// This is the authoritative identity-deletion primitive: it reclaims
    /// every capsule KV namespace without guessing capsule IDs from the live
    /// registry or installation directory. Other typed state components remain
    /// bound to the retired immutable UID and cannot be inherited by a later
    /// identity that reuses the alias.
    ///
    /// # Errors
    ///
    /// Returns a storage error if the principal's authoritative KV state cannot
    /// be read or the clearing mutation cannot be committed.
    pub fn purge_principal_kv(&self, principal: PrincipalUid) -> StorageResult<bool> {
        let owner = StateOwner::Principal(principal);
        self.runtime_kv
            .clear_owner(&owner)
            .map(|removed| removed != 0)
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

    /// Publish sealed native writes atomically under one principal root.
    ///
    /// # Errors
    ///
    /// Returns a staging or content-publication error while retaining the
    /// unacknowledged generations for retry.
    pub async fn publish_staged_batch(
        &self,
        staged: Vec<ReadyStagedContent>,
    ) -> StorageResult<ContentBatchWriteOutcome> {
        self.staging
            .publish_batch(staged, Arc::clone(&self.content))
            .await
    }
}

#[cfg(test)]
mod purge_tests;
#[cfg(test)]
mod volume_migration_tests;
