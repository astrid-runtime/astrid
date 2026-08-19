//! Capsule registry.
//!
//! Manages loaded capsule instances and principal-scoped capsule views.
//!
//! Immutable capsule artifacts are content-addressed, but executable runtimes
//! are authority-scoped. A mutable Wasmtime `Store`/`Instance`, run task, native
//! child, subscription, readiness channel, or cancellation token is never shared
//! by two durable principal identities. Sharing stops at verified bytes and
//! compiled code.

use std::collections::HashMap;
use std::sync::Arc;

use tracing::{debug, info};
use uuid::Uuid;

use astrid_core::{PrincipalId, PrincipalUid};
use astrid_core::{UplinkCapabilities, UplinkDescriptor, UplinkId};

use crate::capsule::{Capsule, CapsuleId};
use crate::error::{CapsuleError, CapsuleResult};

mod compatibility;
mod replacement;
mod runtime_id;
mod uplinks;
pub use runtime_id::{RuntimeId, RuntimeKey, RuntimeScope, WasmHash};

fn capsule_source_uuid(id: &CapsuleId, artifact: &WasmHash) -> Uuid {
    const CAPSULE_ID_NAMESPACE: Uuid = Uuid::from_u128(0x310714d5_9c6d_4c94_8187_75258f393bb6);
    let seed = format!("{}\0{}", id.as_str(), artifact.as_str());
    Uuid::new_v5(&CAPSULE_ID_NAMESPACE, seed.as_bytes())
}

fn system_uplink_descriptors(capsule: &dyn Capsule) -> CapsuleResult<Vec<UplinkDescriptor>> {
    let id = capsule.id();
    capsule
        .manifest()
        .uplinks
        .iter()
        .map(|uplink| {
            let source = astrid_core::uplink::UplinkSource::new_wasm(id.as_str()).map_err(|e| {
                CapsuleError::UnsupportedEntryPoint(format!("Failed to create source: {e}"))
            })?;
            Ok(
                UplinkDescriptor::builder(uplink.name.clone(), uplink.platform.clone())
                    .source(source)
                    .capabilities(UplinkCapabilities::receive_only())
                    .profile(uplink.profile)
                    .build(),
            )
        })
        .collect()
}

/// A single authority-scoped executable runtime.
struct InstanceEntry {
    capsule: Arc<dyn Capsule>,
    /// Current alias for diagnostics and view lookup. Authority is keyed by the
    /// immutable UID in [`RuntimeId`], never by this reusable name.
    owner_alias: Option<PrincipalId>,
}

/// Outcome of removing one principal's runtime view.
#[non_exhaustive]
pub struct Unregistered {
    /// A handle to the removed runtime.
    pub capsule: Arc<dyn Capsule>,
    /// `true` when the runtime itself was removed. A dependent system view can
    /// detach while its explicit owner and singleton remain live.
    pub torn_down: bool,
}

/// Result of atomically replacing one runtime generation.
#[non_exhaustive]
pub struct ReplacedRuntime {
    /// Identity assigned to the newly published generation.
    pub runtime_id: RuntimeId,
    /// The generation removed from every affected view.
    pub previous: Arc<dyn Capsule>,
}

/// Publication failure that preserves ownership of the activated candidate so
/// the kernel can cancel and unload it synchronously.
pub struct RuntimePublicationError {
    pub capsule: Box<dyn Capsule>,
    pub error: CapsuleError,
}

impl std::fmt::Debug for RuntimePublicationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimePublicationError")
            .field("capsule_id", &self.capsule.id())
            .field("error", &self.error)
            .finish()
    }
}

impl std::fmt::Debug for Unregistered {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Unregistered")
            .field("capsule_id", &self.capsule.id())
            .field("torn_down", &self.torn_down)
            .finish()
    }
}

/// Registry of loaded capsules.
///
/// Stores authority-scoped runtime incarnations and per-principal views.
#[non_exhaustive]
pub struct CapsuleRegistry {
    instances: HashMap<RuntimeId, InstanceEntry>,
    views: HashMap<PrincipalId, HashMap<CapsuleId, RuntimeId>>,
    next_generation: u64,
    uplinks: HashMap<UplinkId, (CapsuleId, UplinkDescriptor)>,
    /// Legacy reverse map from WASM session UUIDs to capsule IDs.
    uuid_id_map: HashMap<Uuid, CapsuleId>,
    /// Principal-scoped map from public, content-derived source UUIDs to the
    /// current runtime generation. Identical artifacts intentionally retain the
    /// same wire UUID; the authentic principal view disambiguates them.
    uuid_map: HashMap<(Uuid, PrincipalId), RuntimeId>,
    /// Forward map from runtime incarnations to their live source IDs.
    source_uuid_by_runtime: HashMap<RuntimeId, Uuid>,
    /// Legacy caller-supplied UUID mappings retained at the artifact boundary.
    /// Resolution is scoped to a principal view, or fails closed when an
    /// unscoped lookup spans more than one authority-scoped runtime.
    legacy_uuid_map: HashMap<Uuid, WasmHash>,
}

impl CapsuleRegistry {
    /// Create an empty capsule registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            instances: HashMap::new(),
            views: HashMap::new(),
            next_generation: 1,
            uplinks: HashMap::new(),
            uuid_id_map: HashMap::new(),
            uuid_map: HashMap::new(),
            source_uuid_by_runtime: HashMap::new(),
            legacy_uuid_map: HashMap::new(),
        }
    }

    /// Register a principal-scoped capsule in the default principal's view.
    ///
    /// This compatibility wrapper is for older unit tests and single-principal
    /// callers. Kernel loading should prefer [`Self::register_for`] with an
    /// actual content hash.
    pub fn register(&mut self, capsule: Box<dyn Capsule>) -> CapsuleResult<()> {
        let id = capsule.id().clone();
        let version = capsule.manifest().package.version.clone();
        let hash = WasmHash::synthetic(id.as_str(), &version);
        self.register_for(capsule, hash, &PrincipalId::default())
    }

    /// Register a capsule under `hash` in `principal`'s view, owned by
    /// `principal`.
    ///
    /// This compatibility entry point creates a fresh principal runtime. An
    /// identical hash already loaded for another principal does not share any
    /// executable state.
    ///
    /// # Errors
    ///
    /// Returns an error when the principal already has a capsule with that ID,
    /// or when the capsule requires explicit System scope.
    pub fn register_for(
        &mut self,
        capsule: Box<dyn Capsule>,
        hash: WasmHash,
        principal: &PrincipalId,
    ) -> CapsuleResult<()> {
        // Compatibility edge for callers that do not yet have the durable
        // directory. Production kernel loads call `register_principal_runtime`
        // with the admitted UID. The derived value is local to this legacy API
        // and never used for durable storage or authorization.
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"astrid legacy registry principal uid\0");
        hasher.update(principal.as_str().as_bytes());
        let uid = PrincipalUid::from_bytes(*hasher.finalize().as_bytes());
        self.register_principal_runtime(capsule, hash, principal, uid)
            .map(|_| ())
    }

    /// Register a fresh executable runtime owned by one durable principal.
    ///
    /// A second principal loading identical bytes receives a distinct runtime
    /// generation. The compiled artifact cache may still reuse immutable code.
    pub fn register_principal_runtime(
        &mut self,
        capsule: Box<dyn Capsule>,
        artifact: WasmHash,
        principal: &PrincipalId,
        uid: PrincipalUid,
    ) -> CapsuleResult<RuntimeId> {
        if !capsule.manifest().uplinks.is_empty() {
            return Err(CapsuleError::UnsupportedEntryPoint(format!(
                "uplink capsule '{}' requires explicit system runtime scope",
                capsule.id()
            )));
        }
        let runtime_id =
            self.reserve_runtime_id(capsule.id().clone(), artifact, RuntimeScope::Principal(uid))?;
        self.commit_reserved_runtime(capsule, runtime_id, principal, Some(principal.clone()))
    }

    /// Register a fresh explicit system runtime.
    pub fn register_system_runtime(
        &mut self,
        capsule: Box<dyn Capsule>,
        artifact: WasmHash,
        view_principal: &PrincipalId,
    ) -> CapsuleResult<RuntimeId> {
        if let Some(runtime_id) = self.system_runtime_for_hash(capsule.id(), &artifact) {
            self.add_system_view(capsule.id(), &runtime_id, view_principal)?;
            return Ok(runtime_id);
        }
        let runtime_id =
            self.reserve_runtime_id(capsule.id().clone(), artifact, RuntimeScope::SystemResident)?;
        self.commit_reserved_runtime(
            capsule,
            runtime_id,
            view_principal,
            Some(view_principal.clone()),
        )
    }

    /// Reserve the exact generation identity before constructing its mutable
    /// runtime. A reservation carries no authority and is safe to abandon.
    pub fn reserve_runtime_id(
        &mut self,
        id: CapsuleId,
        artifact: WasmHash,
        scope: RuntimeScope,
    ) -> CapsuleResult<RuntimeId> {
        self.next_runtime_id(id, artifact, scope)
    }

    /// Commit a previously validated runtime generation.
    fn commit_reserved_runtime(
        &mut self,
        capsule: Box<dyn Capsule>,
        runtime_id: RuntimeId,
        view_principal: &PrincipalId,
        owner_alias: Option<PrincipalId>,
    ) -> CapsuleResult<RuntimeId> {
        let id = capsule.id().clone();
        if runtime_id.key.capsule_id() != &id {
            return Err(CapsuleError::ExecutionFailed(format!(
                "reserved runtime belongs to '{}', not '{id}'",
                runtime_id.key.capsule_id()
            )));
        }
        let artifact = runtime_id.key.artifact().clone();
        let scope = runtime_id.key.scope();
        if matches!(scope, RuntimeScope::Principal(_)) && !capsule.manifest().uplinks.is_empty() {
            return Err(CapsuleError::UnsupportedEntryPoint(format!(
                "uplink capsule '{id}' requires explicit system runtime scope"
            )));
        }
        if self
            .views
            .get(view_principal)
            .is_some_and(|view| view.contains_key(&id))
        {
            return Err(CapsuleError::UnsupportedEntryPoint(format!(
                "Already registered: {id}"
            )));
        }

        let generation = runtime_id.generation;
        let descriptors = if scope == RuntimeScope::SystemResident {
            system_uplink_descriptors(capsule.as_ref())?
        } else {
            Vec::new()
        };
        let mut pending_ids = std::collections::HashSet::new();
        for descriptor in &descriptors {
            if self.uplinks.contains_key(&descriptor.id) || !pending_ids.insert(descriptor.id) {
                return Err(CapsuleError::UnsupportedEntryPoint(format!(
                    "Uplink already registered: {}",
                    descriptor.id
                )));
            }
        }
        let capsule: Arc<dyn Capsule> = Arc::from(capsule);
        for descriptor in descriptors {
            self.uplinks.insert(descriptor.id, (id.clone(), descriptor));
        }

        info!(capsule_id = %id, ?scope, view = %view_principal, hash = %artifact, generation, "Registered authority-scoped capsule runtime");
        let source_uuid = capsule_source_uuid(&id, &artifact);
        self.instances.insert(
            runtime_id.clone(),
            InstanceEntry {
                capsule,
                owner_alias,
            },
        );
        self.views
            .entry(view_principal.clone())
            .or_default()
            .insert(id.clone(), runtime_id.clone());
        self.uuid_map
            .insert((source_uuid, view_principal.clone()), runtime_id.clone());
        self.source_uuid_by_runtime
            .insert(runtime_id.clone(), source_uuid);
        self.uuid_id_map.insert(source_uuid, id);
        Ok(runtime_id)
    }

    /// Publish a reserved runtime while preserving the candidate on error.
    pub fn try_register_reserved_runtime(
        &mut self,
        capsule: Box<dyn Capsule>,
        runtime_id: RuntimeId,
        view_principal: &PrincipalId,
        owner_alias: Option<PrincipalId>,
    ) -> Result<RuntimeId, RuntimePublicationError> {
        if let Err(error) =
            self.validate_reserved_runtime(capsule.as_ref(), &runtime_id, view_principal)
        {
            return Err(RuntimePublicationError { capsule, error });
        }
        Ok(self
            .commit_reserved_runtime(capsule, runtime_id, view_principal, owner_alias)
            .expect("validated runtime publication must commit"))
    }

    fn validate_reserved_runtime(
        &self,
        capsule: &dyn Capsule,
        runtime_id: &RuntimeId,
        view_principal: &PrincipalId,
    ) -> CapsuleResult<()> {
        let id = capsule.id();
        if runtime_id.key.capsule_id() != id {
            return Err(CapsuleError::ExecutionFailed(format!(
                "reserved runtime belongs to '{}', not '{id}'",
                runtime_id.key.capsule_id()
            )));
        }
        if matches!(runtime_id.key.scope(), RuntimeScope::Principal(_))
            && !capsule.manifest().uplinks.is_empty()
        {
            return Err(CapsuleError::UnsupportedEntryPoint(format!(
                "uplink capsule '{id}' requires explicit system runtime scope"
            )));
        }
        if self
            .views
            .get(view_principal)
            .is_some_and(|view| view.contains_key(id))
        {
            return Err(CapsuleError::UnsupportedEntryPoint(format!(
                "Already registered: {id}"
            )));
        }
        let mut pending = std::collections::HashSet::new();
        for descriptor in system_uplink_descriptors(capsule)? {
            if self.uplinks.contains_key(&descriptor.id) || !pending.insert(descriptor.id) {
                return Err(CapsuleError::UnsupportedEntryPoint(format!(
                    "Uplink already registered: {}",
                    descriptor.id
                )));
            }
        }
        Ok(())
    }

    /// Add an already-loaded explicit system runtime to `principal`'s view.
    ///
    /// # Errors
    ///
    /// Returns [`CapsuleError::NotFound`] if no instance exists for `hash`, or
    /// an unsupported-entry error if the principal already has `id`.
    pub fn register_existing(
        &mut self,
        id: &CapsuleId,
        hash: &WasmHash,
        principal: &PrincipalId,
    ) -> CapsuleResult<()> {
        if self
            .views
            .get(principal)
            .is_some_and(|view| view.contains_key(id))
        {
            return Err(CapsuleError::UnsupportedEntryPoint(format!(
                "Already registered: {id}"
            )));
        }
        let runtime_id = self.system_runtime_for_hash(id, hash).ok_or_else(|| {
            CapsuleError::NotFound(format!(
                "system runtime {id} ({hash}); principal runtimes cannot be shared"
            ))
        })?;
        self.add_system_view(id, &runtime_id, principal)
    }

    fn system_runtime_for_hash(&self, id: &CapsuleId, hash: &WasmHash) -> Option<RuntimeId> {
        self.instances.keys().find_map(|runtime_id| {
            (runtime_id.key.scope() == RuntimeScope::SystemResident
                && runtime_id.key.capsule_id() == id
                && runtime_id.key.artifact() == hash)
                .then(|| runtime_id.clone())
        })
    }

    /// Whether this exact capsule artifact has an explicit System runtime.
    #[must_use]
    pub fn contains_system_runtime(&self, id: &CapsuleId, hash: &WasmHash) -> bool {
        self.system_runtime_for_hash(id, hash).is_some()
    }

    fn add_system_view(
        &mut self,
        id: &CapsuleId,
        runtime_id: &RuntimeId,
        principal: &PrincipalId,
    ) -> CapsuleResult<()> {
        let entry = self
            .instances
            .get(runtime_id)
            .ok_or_else(|| CapsuleError::NotFound(format!("runtime {runtime_id:?}")))?;
        if runtime_id.key.scope() != RuntimeScope::SystemResident {
            return Err(CapsuleError::UnsupportedEntryPoint(
                "only explicit system runtimes may have multiple principal views".into(),
            ));
        }
        if entry.capsule.id() != id {
            return Err(CapsuleError::UnsupportedEntryPoint(format!(
                "Runtime is registered for capsule {}",
                entry.capsule.id()
            )));
        }
        self.views
            .entry(principal.clone())
            .or_default()
            .insert(id.clone(), runtime_id.clone());
        if let Some(source_uuid) = self.source_uuid_by_runtime.get(runtime_id).copied() {
            self.uuid_map
                .insert((source_uuid, principal.clone()), runtime_id.clone());
        }
        info!(capsule_id = %id, principal = %principal, generation = runtime_id.generation, "Registered explicit system capsule view");
        Ok(())
    }

    /// Unregister a capsule from the default principal's view.
    ///
    /// # Errors
    ///
    /// Returns [`CapsuleError::NotFound`] if the capsule is absent from the
    /// default principal's view.
    pub fn unregister(&mut self, id: &CapsuleId) -> CapsuleResult<Unregistered> {
        self.unregister_for(&PrincipalId::default(), id)
    }

    /// Unregister a capsule from `principal`'s view.
    ///
    /// A principal runtime is always removed. An explicit system runtime is
    /// removed when its owner departs or after its last dependent view leaves.
    ///
    /// # Errors
    ///
    /// Returns [`CapsuleError::NotFound`] if the capsule is absent from that
    /// principal's view.
    pub fn unregister_for(
        &mut self,
        principal: &PrincipalId,
        id: &CapsuleId,
    ) -> CapsuleResult<Unregistered> {
        let runtime_id = self
            .views
            .get_mut(principal)
            .and_then(|view| view.remove(id))
            .ok_or_else(|| CapsuleError::NotFound(format!("capsule {id}")))?;

        if self.views.get(principal).is_some_and(HashMap::is_empty) {
            self.views.remove(principal);
        }

        let capsule = self
            .instances
            .get(&runtime_id)
            .map(|entry| Arc::clone(&entry.capsule))
            .expect("principal view referenced missing capsule runtime");

        let owner_departed = self
            .instances
            .get(&runtime_id)
            .and_then(|entry| entry.owner_alias.as_ref())
            == Some(principal);
        // Principal runtimes have exactly one view. Explicit System runtimes
        // are removed with their operator owner or their final dependent view.
        let torn_down = runtime_id.key.scope() != RuntimeScope::SystemResident
            || owner_departed
            || !self
                .views
                .values()
                .any(|view| view.values().any(|candidate| candidate == &runtime_id));
        if torn_down {
            if owner_departed {
                for view in self.views.values_mut() {
                    view.retain(|_, candidate| candidate != &runtime_id);
                }
                self.views.retain(|_, view| !view.is_empty());
            }
            self.instances.remove(&runtime_id);
            if self.any_principal_with(id).is_none() {
                self.unregister_capsule_uplinks(id);
            }
            self.uuid_map
                .retain(|_, mapped_runtime| mapped_runtime != &runtime_id);
            if let Some(source_uuid) = self.source_uuid_by_runtime.remove(&runtime_id)
                && !self
                    .source_uuid_by_runtime
                    .values()
                    .any(|candidate| candidate == &source_uuid)
            {
                self.uuid_id_map.remove(&source_uuid);
            }
            self.remove_legacy_uuid_mappings_if_unused(runtime_id.key.artifact());
            info!(capsule_id = %id, principal = %principal, generation = runtime_id.generation, "Unregistered capsule runtime");
        } else {
            if let Some(source_uuid) = self.source_uuid_by_runtime.get(&runtime_id) {
                self.uuid_map.remove(&(*source_uuid, principal.clone()));
            }
            info!(capsule_id = %id, principal = %principal, generation = runtime_id.generation, "Unregistered system capsule view (runtime retained)");
        }

        Ok(Unregistered { capsule, torn_down })
    }

    // -----------------------------------------------------------------
    // UUID mapping
    // -----------------------------------------------------------------

    /// Register a session UUID for a capsule ID.
    ///
    /// Called during WASM capsule load so that host functions can resolve
    /// IPC `source_id` UUIDs back to capsule identities.
    ///
    /// Silently overwrites on duplicate UUID. Installed WASM runtimes use a
    /// deterministic v5 UUID derived from capsule ID and artifact hash.
    pub fn register_uuid(&mut self, uuid: Uuid, capsule_id: CapsuleId) {
        debug!(
            %uuid,
            capsule_id = %capsule_id,
            "Registered capsule UUID ID mapping"
        );
        self.uuid_id_map.insert(uuid, capsule_id);
    }

    /// Register a legacy caller-supplied UUID for an artifact hash.
    ///
    /// The mapping intentionally stops at immutable artifact identity. Scoped
    /// lookup resolves it through the caller's current view; unscoped lookup
    /// succeeds only when exactly one live runtime uses the artifact.
    pub fn register_instance_uuid(&mut self, uuid: Uuid, hash: WasmHash) {
        debug!(%uuid, hash = %hash, "Registered legacy artifact UUID mapping");
        self.legacy_uuid_map.insert(uuid, hash);
    }

    /// Look up a capsule instance by source UUID within one principal view.
    #[must_use]
    pub fn find_instance_by_uuid_for(
        &self,
        principal: &PrincipalId,
        uuid: &Uuid,
    ) -> Option<Arc<dyn Capsule>> {
        let runtime_id = if let Some(runtime_id) = self.uuid_map.get(&(*uuid, principal.clone())) {
            runtime_id
        } else {
            let artifact = self.legacy_uuid_map.get(uuid)?;
            let mut matches = self.views.get(principal)?.values().filter(|runtime_id| {
                runtime_id.key.artifact() == artifact && self.instances.contains_key(*runtime_id)
            });
            let first = matches.next()?;
            if matches.next().is_some() {
                return None;
            }
            first
        };
        self.instances
            .get(runtime_id)
            .map(|entry| Arc::clone(&entry.capsule))
    }

    /// Compatibility lookup. Returns a runtime only when the UUID is
    /// unambiguous across all principal views; security-sensitive callers must
    /// use [`Self::find_instance_by_uuid_for`].
    #[must_use]
    pub fn find_instance_by_uuid(&self, uuid: &Uuid) -> Option<Arc<dyn Capsule>> {
        let mut matches: Box<dyn Iterator<Item = &RuntimeId> + '_> =
            if let Some(artifact) = self.legacy_uuid_map.get(uuid) {
                Box::new(
                    self.instances
                        .keys()
                        .filter(move |runtime_id| runtime_id.key.artifact() == artifact),
                )
            } else {
                Box::new(
                    self.uuid_map
                        .iter()
                        .filter(|((candidate, _), _)| candidate == uuid)
                        .map(|(_, runtime_id)| runtime_id),
                )
            };
        let first = matches.next()?;
        if matches.any(|candidate| candidate != first) {
            return None;
        }
        self.instances
            .get(first)
            .map(|entry| Arc::clone(&entry.capsule))
    }

    /// Look up a capsule ID by its session UUID.
    #[must_use]
    pub fn find_by_uuid(&self, uuid: &Uuid) -> Option<&CapsuleId> {
        self.uuid_id_map.get(uuid)
    }

    /// Whether any runtime currently uses this immutable artifact hash.
    #[must_use]
    pub fn contains_hash(&self, hash: &WasmHash) -> bool {
        self.instances
            .keys()
            .any(|runtime_id| runtime_id.key.artifact() == hash)
    }

    fn remove_legacy_uuid_mappings_if_unused(&mut self, artifact: &WasmHash) {
        if !self.contains_hash(artifact) {
            self.legacy_uuid_map
                .retain(|_, mapped_artifact| mapped_artifact != artifact);
        }
    }

    /// Get a shared reference to a capsule by ID.
    ///
    /// This compatibility wrapper resolves across any principal view. Security
    /// sensitive callers should use [`Self::get_for`].
    #[must_use]
    pub fn get(&self, id: &CapsuleId) -> Option<Arc<dyn Capsule>> {
        self.get_any(id)
    }

    /// Get a capsule visible to `principal`.
    ///
    /// Returns a cloned `Arc` so callers can use the capsule after releasing
    /// the registry lock.
    #[must_use]
    pub fn get_for(&self, principal: &PrincipalId, id: &CapsuleId) -> Option<Arc<dyn Capsule>> {
        let runtime_id = self.views.get(principal)?.get(id)?;
        self.instances
            .get(runtime_id)
            .map(|entry| Arc::clone(&entry.capsule))
    }

    /// Runtime incarnation currently visible as `id` to `principal`.
    #[must_use]
    pub fn runtime_id_for(&self, principal: &PrincipalId, id: &CapsuleId) -> Option<RuntimeId> {
        self.views.get(principal)?.get(id).cloned()
    }

    /// Runtime identities and handles visible to one principal.
    #[must_use]
    pub fn cloned_runtimes_for(
        &self,
        principal: &PrincipalId,
    ) -> Vec<(RuntimeId, Arc<dyn Capsule>)> {
        self.views.get(principal).map_or_else(Vec::new, |view| {
            view.values()
                .filter_map(|runtime_id| {
                    self.instances
                        .get(runtime_id)
                        .map(|entry| (runtime_id.clone(), Arc::clone(&entry.capsule)))
                })
                .collect()
        })
    }

    /// Every distinct runtime incarnation and handle.
    #[must_use]
    pub fn cloned_runtimes(&self) -> Vec<(RuntimeId, Arc<dyn Capsule>)> {
        self.instances
            .iter()
            .map(|(runtime_id, entry)| (runtime_id.clone(), Arc::clone(&entry.capsule)))
            .collect()
    }

    /// One health/lifecycle representative per distinct runtime generation.
    #[must_use]
    pub fn cloned_runtimes_with_principal(
        &self,
    ) -> Vec<(PrincipalId, RuntimeId, Arc<dyn Capsule>)> {
        self.instances
            .iter()
            .filter_map(|(runtime_id, entry)| {
                let principal = entry.owner_alias.clone().or_else(|| {
                    self.views.iter().find_map(|(principal, view)| {
                        view.values()
                            .any(|candidate| candidate == runtime_id)
                            .then(|| principal.clone())
                    })
                })?;
                Some((principal, runtime_id.clone(), Arc::clone(&entry.capsule)))
            })
            .collect()
    }

    /// Explicit system runtimes only. Principal-less lifecycle events must not
    /// select an arbitrary human principal runtime.
    #[must_use]
    pub fn cloned_system_runtimes(&self) -> Vec<(RuntimeId, Arc<dyn Capsule>)> {
        self.instances
            .iter()
            .filter(|(runtime_id, _)| runtime_id.key.scope() == RuntimeScope::SystemResident)
            .map(|(runtime_id, entry)| (runtime_id.clone(), Arc::clone(&entry.capsule)))
            .collect()
    }

    /// Get a capsule from any principal view.
    #[must_use]
    pub fn get_any(&self, id: &CapsuleId) -> Option<Arc<dyn Capsule>> {
        self.views.values().find_map(|view| {
            let runtime_id = view.get(id)?;
            self.instances
                .get(runtime_id)
                .map(|entry| Arc::clone(&entry.capsule))
        })
    }

    /// List capsule IDs visible to the default principal.
    #[must_use]
    pub fn list(&self) -> Vec<&CapsuleId> {
        self.list_for(&PrincipalId::default())
    }

    /// List capsule IDs visible to `principal`.
    #[must_use]
    pub fn list_for(&self, principal: &PrincipalId) -> Vec<&CapsuleId> {
        self.views
            .get(principal)
            .map_or_else(Vec::new, |view| view.keys().collect())
    }

    /// List capsule IDs from every principal view, deduplicated by ID.
    #[must_use]
    pub fn list_any(&self) -> Vec<&CapsuleId> {
        let mut ids = Vec::new();
        for view in self.views.values() {
            for id in view.keys() {
                if !ids.contains(&id) {
                    ids.push(id);
                }
            }
        }
        ids
    }

    /// The content [`WasmHash`] that `principal`'s view resolves `id` to, if any.
    ///
    /// Two principals can resolve the same id to DIFFERENT hashes (per-principal
    /// installs of different versions), so a restart must pin the specific hash
    /// the requesting principal views rather than assume one hash per id.
    #[must_use]
    pub fn hash_for(&self, principal: &PrincipalId, id: &CapsuleId) -> Option<WasmHash> {
        self.views
            .get(principal)?
            .get(id)
            .map(|runtime_id| runtime_id.key.artifact().clone())
    }

    /// Kernel-stamped IPC source ID for the runtime visible as `id` to
    /// `principal`.
    #[must_use]
    pub fn source_id_for(&self, principal: &PrincipalId, id: &CapsuleId) -> Option<Uuid> {
        let runtime_id = self.views.get(principal)?.get(id)?;
        self.source_uuid_by_runtime.get(runtime_id).copied()
    }

    /// Return an arbitrary principal whose view contains `id`.
    #[must_use]
    pub fn any_principal_with(&self, id: &CapsuleId) -> Option<PrincipalId> {
        self.views
            .iter()
            .find(|(_, view)| view.contains_key(id))
            .map(|(principal, _)| principal.clone())
    }

    /// Every principal whose view contains `id`.
    ///
    /// Principal runtimes have one viewer. Explicit System runtimes may have
    /// several views, all of which are returned. Order is unspecified.
    #[must_use]
    pub fn principals_viewing(&self, id: &CapsuleId) -> Vec<PrincipalId> {
        self.views
            .iter()
            .filter(|(_, view)| view.contains_key(id))
            .map(|(principal, _)| principal.clone())
            .collect()
    }

    /// Iterator over all distinct loaded capsule instances.
    pub fn values(&self) -> impl Iterator<Item = &(dyn Capsule + '_)> {
        self.instances.values().map(|entry| entry.capsule.as_ref())
    }

    /// Snapshot of cloned `Arc` handles to every distinct loaded instance.
    ///
    /// One pass over the map (the public [`Self::values`] yields `&dyn Capsule`,
    /// so it can't be `cloned()` into owned handles). Lets a caller release the
    /// registry lock before doing async work on the capsules (e.g. invoking an
    /// interceptor that may `block_in_place`).
    #[must_use]
    pub fn cloned_values(&self) -> Vec<Arc<dyn Capsule>> {
        self.instances
            .values()
            .map(|entry| Arc::clone(&entry.capsule))
            .collect()
    }

    /// Snapshot of `(viewing principal, capsule)` for every principal view.
    ///
    /// A principal runtime appears once for its owner. An explicit System
    /// runtime appears once per principal view, sharing its `Arc` deliberately.
    #[must_use]
    pub fn cloned_values_with_principal(&self) -> Vec<(PrincipalId, Arc<dyn Capsule>)> {
        let mut out = Vec::new();
        for (principal, view) in &self.views {
            for runtime_id in view.values() {
                if let Some(entry) = self.instances.get(runtime_id) {
                    out.push((principal.clone(), Arc::clone(&entry.capsule)));
                }
            }
        }
        out
    }

    /// Snapshot of `(viewing principal, content hash, capsule)` for every view.
    ///
    /// Like [`cloned_values_with_principal`](Self::cloned_values_with_principal)
    /// but also carries the [`WasmHash`] each view resolves to. A capsule id can
    /// legitimately map to TWO distinct hashes at once — e.g. `default` on
    /// `foo@1.0` and `alice` on `foo@2.0`, since installs are owned by each
    /// principal's immutable UID and each derives its own content hash. The
    /// health monitor keys dedup and restart by
    /// `(id, hash)` off this snapshot so two distinct runtimes for one id are each
    /// probed and restarted independently rather than collapsed to one.
    #[must_use]
    pub fn cloned_values_with_principal_and_hash(
        &self,
    ) -> Vec<(PrincipalId, WasmHash, Arc<dyn Capsule>)> {
        let mut out = Vec::new();
        for (principal, view) in &self.views {
            for runtime_id in view.values() {
                if let Some(entry) = self.instances.get(runtime_id) {
                    out.push((
                        principal.clone(),
                        runtime_id.key.artifact().clone(),
                        Arc::clone(&entry.capsule),
                    ));
                }
            }
        }
        out
    }

    /// Every principal whose view resolves `id` to the specific `hash`.
    ///
    /// Distinct from [`principals_viewing`](Self::principals_viewing), which
    /// returns every viewer of the id regardless of which hash they point at.
    /// A per-`(id, hash)` restart must rebuild ONLY the views pointing at the
    /// failed runtime's exact hash — rebuilding a viewer that points at a
    /// *different* hash of the same id would wrongly re-home it onto the
    /// restarted version. Order is unspecified (`HashMap` iteration).
    #[must_use]
    pub fn principals_viewing_hash(&self, id: &CapsuleId, hash: &WasmHash) -> Vec<PrincipalId> {
        self.views
            .iter()
            .filter(|(_, view)| {
                view.get(id)
                    .is_some_and(|runtime_id| runtime_id.key.artifact() == hash)
            })
            .map(|(principal, _)| principal.clone())
            .collect()
    }

    /// Every alias whose view targets this exact runtime generation.
    #[must_use]
    pub fn principals_viewing_runtime(&self, runtime_id: &RuntimeId) -> Vec<PrincipalId> {
        self.views
            .iter()
            .filter(|(_, view)| view.values().any(|candidate| candidate == runtime_id))
            .map(|(principal, _)| principal.clone())
            .collect()
    }

    /// Snapshot of cloned `Arc` handles visible to `principal`.
    #[must_use]
    pub fn cloned_values_for(&self, principal: &PrincipalId) -> Vec<Arc<dyn Capsule>> {
        self.views.get(principal).map_or_else(Vec::new, |view| {
            view.values()
                .filter_map(|runtime_id| {
                    self.instances
                        .get(runtime_id)
                        .map(|entry| Arc::clone(&entry.capsule))
                })
                .collect()
        })
    }

    /// Number of distinct loaded runtime generations.
    #[must_use]
    pub fn len(&self) -> usize {
        self.instances.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.instances.is_empty()
    }

    /// Number of principal views that reference `hash`, or `None` if absent.
    /// This preserves the pre-runtime-scope public hash-query semantics.
    #[must_use]
    pub fn refcount_for_hash(&self, hash: &WasmHash) -> Option<usize> {
        let count = self
            .views
            .values()
            .flat_map(HashMap::values)
            .filter(|runtime_id| runtime_id.key.artifact() == hash)
            .count();
        (count > 0).then_some(count)
    }
}

impl Default for CapsuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for CapsuleRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapsuleRegistry")
            .field("instance_count", &self.instances.len())
            .field("view_count", &self.views.len())
            .field("uplink_count", &self.uplinks.len())
            .finish()
    }
}

#[cfg(test)]
#[path = "registry_tests.rs"]
mod tests;
