//! Capsule registry.
//!
//! Manages loaded capsule instances and principal-scoped capsule views.
//!
//! Runtime instances are **content-addressed by WASM hash and shared across
//! principals**: a hash referenced by N principals loads exactly ONCE (one
//! [`Capsule`] runtime, one WASM build), with a per-principal `name -> hash`
//! view layered on top for dispatch/visibility isolation. Identical hashes
//! SHARE the runtime; different hashes are distinct instances (issue #1069;
//! this restores the shared-by-hash model regressed by #1083, which keyed
//! instances by `(principal, hash)` and built one runtime per principal).
//!
//! Cross-principal host-state isolation does **not** come from duplicating the
//! runtime. A shared instance is loaded under [`PrincipalId::default()`], but its
//! load-time host state (`kv` / `secret_store` / `home`) is a NEUTRAL,
//! fail-closed placeholder that holds no real principal's data — not `default`'s.
//! EVERY invocation that carries a principal — the owner/`default` included —
//! installs per-invocation `invocation_*` overlays (KV / secret store / home /
//! tmp / log) scoped to the *invoking* principal, resolved through the
//! `effective_*` accessors. A principal-less system/lifecycle event reaches only
//! the neutral placeholder, which denies rather than exposing any principal's
//! private state.

use std::collections::HashMap;
use std::sync::Arc;

use tracing::{debug, info};
use uuid::Uuid;

use astrid_core::PrincipalId;
use astrid_core::{UplinkCapabilities, UplinkDescriptor, UplinkId};

use crate::capsule::{Capsule, CapsuleId};
use crate::error::{CapsuleError, CapsuleResult};

/// Content hash addressing a distinct loaded capsule instance.
///
/// For WASM capsules this is the BLAKE3 hash recorded as `wasm_hash` in
/// `meta.json`. Capsules with no WASM hash, such as MCP-only capsules, use a
/// synthetic domain-separated hash from package name and version.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WasmHash(String);

impl WasmHash {
    /// Wrap a pre-computed content hash.
    #[must_use]
    pub fn from_raw(hash: impl Into<String>) -> Self {
        Self(hash.into())
    }

    /// Build a stable synthetic key for capsules with no WASM binary hash.
    #[must_use]
    pub fn synthetic(name: &str, version: &str) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"synthetic-capsule-instance:");
        hasher.update(name.as_bytes());
        hasher.update(&[0]);
        hasher.update(version.as_bytes());
        Self(hasher.finalize().to_hex().to_string())
    }

    /// Return the hash string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for WasmHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A single shared, content-addressed runtime instance.
///
/// Keyed by [`WasmHash`] in [`CapsuleRegistry::instances`]. `refcount` is the
/// number of principal views that reference this hash; the runtime is torn down
/// only when the last view releases it.
///
/// The runtime's load-time owner (its `HostState.principal`) is a property of
/// the built [`Capsule`] itself, not tracked here. Kernel-loaded shared instances
/// are always built under [`PrincipalId::default()`] (see
/// [`CapsuleRegistry::register_owned_by_default`]), but the load-time host-state
/// fields the `effective_*` accessors fall back to for principal-less invocations
/// are NEUTRAL, fail-closed placeholders (not `default`'s real KV/secrets/home),
/// so that fallback exposes no principal's private state.
struct InstanceEntry {
    capsule: Arc<dyn Capsule>,
    refcount: usize,
    /// The principal the runtime was built under (its `HostState.principal`, the
    /// `effective_*` load-time fallback owner). Tracked so [`register_for`] can
    /// REJECT sharing an instance across a different owner — forcing callers onto
    /// [`register_existing`] and guaranteeing no code path ever creates a shared
    /// instance owned by a real non-default principal whose load-time fields
    /// would become a cross-principal fallback. Kernel loads use
    /// [`register_owned_by_default`], so a shared instance's owner is always
    /// [`PrincipalId::default()`].
    owner: PrincipalId,
}

/// Outcome of removing one principal's view of a shared instance.
///
/// A shared runtime is referenced by N principal views. Releasing a single view
/// must NOT cancel or unload the runtime while other principals still reference
/// it — only the caller that observes `torn_down == true` (the last release) may
/// drive `request_cancel()` / `unload()`. Callers that unconditionally unload
/// the returned handle would break every other principal sharing the instance.
#[non_exhaustive]
pub struct Unregistered {
    /// A handle to the (possibly still-shared) runtime.
    pub capsule: Arc<dyn Capsule>,
    /// `true` when this was the last view and the runtime was removed from the
    /// registry; `false` when other principal views still reference it.
    pub torn_down: bool,
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
/// Stores one shared runtime instance per content [`WasmHash`] and exposes
/// per-principal `name -> hash` views over them. A principal can only resolve
/// capsules present in its view; daemon-health operations can still inspect the
/// global instance set. Two principals whose views point at the same hash share
/// one runtime.
#[non_exhaustive]
pub struct CapsuleRegistry {
    instances: HashMap<WasmHash, InstanceEntry>,
    views: HashMap<PrincipalId, HashMap<CapsuleId, WasmHash>>,
    uplinks: HashMap<UplinkId, (CapsuleId, UplinkDescriptor)>,
    /// Legacy reverse map from WASM session UUIDs to capsule IDs.
    uuid_id_map: HashMap<Uuid, CapsuleId>,
    /// Reverse map from WASM session UUIDs to content hashes.
    ///
    /// Populated during capsule load so that host functions can resolve an IPC
    /// `source_id` back to the originating shared instance. One runtime per hash
    /// means one source UUID per hash, so this keys by [`WasmHash`].
    uuid_map: HashMap<Uuid, WasmHash>,
}

impl CapsuleRegistry {
    /// Create an empty capsule registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            instances: HashMap::new(),
            views: HashMap::new(),
            uplinks: HashMap::new(),
            uuid_id_map: HashMap::new(),
            uuid_map: HashMap::new(),
        }
    }

    /// Register a capsule in the default principal's view.
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
    /// The instance is owned by (loaded under) `principal`. When a runtime for
    /// `hash` already exists this shares it — bumping the refcount and adding
    /// `principal`'s view — but ONLY when the existing runtime's owner is also
    /// `principal`; sharing a hash already owned by a DIFFERENT principal is
    /// REJECTED (use [`Self::register_existing`] to add a view without asserting
    /// ownership). This guarantees no code path can create a shared instance
    /// owned by a real non-default principal whose load-time host-state fields
    /// would become a cross-principal fallback. This is the single-owner /
    /// same-principal path used by tests and by the default principal's own boot
    /// loads. The kernel builds shared instances under the default principal via
    /// [`Self::register_owned_by_default`].
    ///
    /// # Errors
    ///
    /// Returns an error when the principal already has a capsule with that ID,
    /// when `hash` is already loaded under a DIFFERENT owner, or when uplink
    /// registration fails for a new instance.
    pub fn register_for(
        &mut self,
        capsule: Box<dyn Capsule>,
        hash: WasmHash,
        principal: &PrincipalId,
    ) -> CapsuleResult<()> {
        self.register_instance(capsule, hash, principal, principal)
    }

    /// Register a shared capsule owned by [`PrincipalId::default()`], visible to
    /// `view_principal`.
    ///
    /// This is the kernel's primary load path. The runtime is loaded under the
    /// default (system) principal so that principal-less invocations fall back
    /// to the system scope, never a specific principal's private state; the
    /// installing `view_principal` gets the dispatch view. If a runtime for
    /// `hash` already exists this shares it (no second build).
    ///
    /// # Errors
    ///
    /// Returns an error when `view_principal` already has a capsule with that
    /// ID, or when uplink registration fails for a new instance.
    pub fn register_owned_by_default(
        &mut self,
        capsule: Box<dyn Capsule>,
        hash: WasmHash,
        view_principal: &PrincipalId,
    ) -> CapsuleResult<()> {
        self.register_instance(capsule, hash, &PrincipalId::default(), view_principal)
    }

    /// Core registration: ensure a shared runtime for `hash` exists (owned by
    /// `owner` if newly built) and add `view_principal`'s view over it.
    fn register_instance(
        &mut self,
        capsule: Box<dyn Capsule>,
        hash: WasmHash,
        owner: &PrincipalId,
        view_principal: &PrincipalId,
    ) -> CapsuleResult<()> {
        let id = capsule.id().clone();
        if self
            .views
            .get(view_principal)
            .is_some_and(|view| view.contains_key(&id))
        {
            return Err(CapsuleError::UnsupportedEntryPoint(format!(
                "Already registered: {id}"
            )));
        }

        // A runtime for this hash is already loaded. Sharing it is allowed ONLY
        // when the existing owner matches the owner this call would use — which
        // for `register_for` is `owner == view_principal`, and for
        // `register_owned_by_default` is `owner == default`. Sharing across a
        // DIFFERENT real owner would leave the instance's load-time
        // `kv`/`secret_store`/`home` fields (the owner's) reachable as a
        // cross-principal fallback for the other viewer. Reject and force the
        // caller onto `register_existing`, which adds a view without implying a
        // new owner. (In practice the kernel always loads via
        // `register_owned_by_default`, so a shared instance's owner is always
        // `default`; this guard makes that structurally unbreakable.)
        if let Some(existing) = self.instances.get(&hash) {
            if existing.owner != *owner {
                return Err(CapsuleError::UnsupportedEntryPoint(format!(
                    "content hash {hash} is already loaded under owner '{}'; refusing to \
                     re-register under '{owner}'. Use register_existing to add a view over \
                     the shared instance.",
                    existing.owner
                )));
            }
            return self.add_view(&id, &hash, view_principal);
        }

        let capsule: Arc<dyn Capsule> = Arc::from(capsule);
        let mut registered_ids: Vec<UplinkId> = Vec::new();
        for uplink in &capsule.manifest().uplinks {
            let source = astrid_core::uplink::UplinkSource::new_wasm(id.as_str()).map_err(|e| {
                CapsuleError::UnsupportedEntryPoint(format!("Failed to create source: {}", e))
            })?;

            let descriptor =
                UplinkDescriptor::builder(uplink.name.clone(), uplink.platform.clone())
                    .source(source)
                    .capabilities(UplinkCapabilities::receive_only())
                    .profile(uplink.profile)
                    .build();

            match self.register_uplink(&id, descriptor.clone()) {
                Ok(()) => registered_ids.push(descriptor.id),
                Err(e) => {
                    for rollback_id in &registered_ids {
                        self.uplinks.remove(rollback_id);
                    }
                    return Err(e);
                },
            }
        }

        info!(capsule_id = %id, owner = %owner, view = %view_principal, hash = %hash, "Registered shared capsule instance");
        self.instances.insert(
            hash.clone(),
            InstanceEntry {
                capsule,
                refcount: 1,
                owner: owner.clone(),
            },
        );
        self.views
            .entry(view_principal.clone())
            .or_default()
            .insert(id, hash);
        Ok(())
    }

    /// Add an already-loaded shared instance to `principal`'s view.
    ///
    /// The primary path for granting a principal a view over a runtime that
    /// another principal already loaded (same content hash → shared runtime).
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
        self.add_view(id, hash, principal)
    }

    /// Add `principal`'s view over the existing shared instance for `hash`,
    /// bumping its refcount. Caller must have already rejected a duplicate
    /// view for `principal`.
    fn add_view(
        &mut self,
        id: &CapsuleId,
        hash: &WasmHash,
        principal: &PrincipalId,
    ) -> CapsuleResult<()> {
        let entry = self
            .instances
            .get_mut(hash)
            .ok_or_else(|| CapsuleError::NotFound(format!("instance {hash}")))?;
        if entry.capsule.id() != id {
            return Err(CapsuleError::UnsupportedEntryPoint(format!(
                "Content hash {hash} is registered for capsule {}",
                entry.capsule.id()
            )));
        }
        entry.refcount += 1;
        self.views
            .entry(principal.clone())
            .or_default()
            .insert(id.clone(), hash.clone());
        info!(capsule_id = %id, principal = %principal, hash = %hash, refcount = entry.refcount, "Registered capsule view (shared instance)");
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
    /// Decrements the shared runtime's refcount and tears it down only when the
    /// last view releases it. The returned [`Unregistered::torn_down`] tells the
    /// caller whether it is safe to `request_cancel()` / `unload()` the runtime:
    /// doing so while other principal views still reference the shared instance
    /// would break them.
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
        let hash = self
            .views
            .get_mut(principal)
            .and_then(|view| view.remove(id))
            .ok_or_else(|| CapsuleError::NotFound(format!("capsule {id}")))?;

        if self.views.get(principal).is_some_and(HashMap::is_empty) {
            self.views.remove(principal);
        }

        let entry = self
            .instances
            .get_mut(&hash)
            .expect("principal view referenced missing capsule instance");
        entry.refcount = entry.refcount.saturating_sub(1);
        let capsule = Arc::clone(&entry.capsule);

        // Tear the shared runtime down only when the LAST view releases it.
        let torn_down = entry.refcount == 0;
        if torn_down {
            self.instances.remove(&hash);
            if self.any_principal_with(id).is_none() {
                self.unregister_capsule_uplinks(id);
            }
            self.uuid_map.retain(|_, mapped_hash| mapped_hash != &hash);
            self.uuid_id_map
                .retain(|_, mapped_capsule_id| mapped_capsule_id != id);
            info!(capsule_id = %id, principal = %principal, hash = %hash, "Unregistered shared capsule instance (last view released)");
        } else {
            info!(capsule_id = %id, principal = %principal, hash = %hash, refcount = entry.refcount, "Unregistered capsule view (shared instance retained)");
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
    /// Silently overwrites on duplicate UUID. Each capsule load generates a
    /// fresh v4 UUID, so collisions are not practically possible.
    pub fn register_uuid(&mut self, uuid: Uuid, capsule_id: CapsuleId) {
        debug!(
            %uuid,
            capsule_id = %capsule_id,
            "Registered capsule UUID ID mapping"
        );
        self.uuid_id_map.insert(uuid, capsule_id);
    }

    /// Register a session UUID for a shared capsule runtime instance.
    ///
    /// One runtime per content hash → one source UUID per hash. The UUID is
    /// derived deterministically from `{capsule_name}\0{hash}` (no principal
    /// segment), so a shared instance presents one stable identity to every
    /// principal that views it.
    pub fn register_instance_uuid(&mut self, uuid: Uuid, hash: WasmHash) {
        debug!(
            %uuid,
            hash = %hash,
            "Registered capsule UUID mapping"
        );
        self.uuid_map.insert(uuid, hash);
    }

    /// Look up a capsule instance by its session UUID.
    #[must_use]
    pub fn find_instance_by_uuid(&self, uuid: &Uuid) -> Option<Arc<dyn Capsule>> {
        let hash = self.uuid_map.get(uuid)?;
        self.instances
            .get(hash)
            .map(|entry| Arc::clone(&entry.capsule))
    }

    /// Look up a capsule ID by its session UUID.
    #[must_use]
    pub fn find_by_uuid(&self, uuid: &Uuid) -> Option<&CapsuleId> {
        self.uuid_id_map.get(uuid)
    }

    /// Whether a shared runtime for this content hash is already loaded.
    #[must_use]
    pub fn contains_hash(&self, hash: &WasmHash) -> bool {
        self.instances.contains_key(hash)
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
        let hash = self.views.get(principal)?.get(id)?;
        self.instances
            .get(hash)
            .map(|entry| Arc::clone(&entry.capsule))
    }

    /// Get a capsule from any principal view.
    #[must_use]
    pub fn get_any(&self, id: &CapsuleId) -> Option<Arc<dyn Capsule>> {
        self.views.values().find_map(|view| {
            let hash = view.get(id)?;
            self.instances
                .get(hash)
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
        self.views.get(principal)?.get(id).cloned()
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
    /// A shared runtime (issue #1069) is referenced by N principal views; this
    /// returns all of them so a restart of a shared FAILED runtime can rebuild it
    /// for every view rather than leaving non-requesting principals with a dead
    /// view. Order is unspecified (`HashMap` iteration).
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
    /// One shared runtime keyed by hash appears once per principal that views
    /// it (so a hash referenced by N principals yields N pairs sharing one
    /// `Arc`). Health-monitor / inventory / failed-cleanup consumers need the
    /// *viewing* principals — the set of principals whose dispatch would reach
    /// the instance — not the single load-owner.
    #[must_use]
    pub fn cloned_values_with_principal(&self) -> Vec<(PrincipalId, Arc<dyn Capsule>)> {
        let mut out = Vec::new();
        for (principal, view) in &self.views {
            for hash in view.values() {
                if let Some(entry) = self.instances.get(hash) {
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
    /// `foo@1.0` and `alice` on `foo@2.0`, since installs are per-principal
    /// (`~/.astrid/home/{principal}/.local/capsules/{id}`) and each derives its
    /// own content hash. The health monitor keys dedup and restart by
    /// `(id, hash)` off this snapshot so two distinct runtimes for one id are each
    /// probed and restarted independently rather than collapsed to one.
    #[must_use]
    pub fn cloned_values_with_principal_and_hash(
        &self,
    ) -> Vec<(PrincipalId, WasmHash, Arc<dyn Capsule>)> {
        let mut out = Vec::new();
        for (principal, view) in &self.views {
            for hash in view.values() {
                if let Some(entry) = self.instances.get(hash) {
                    out.push((principal.clone(), hash.clone(), Arc::clone(&entry.capsule)));
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
            .filter(|(_, view)| view.get(id) == Some(hash))
            .map(|(principal, _)| principal.clone())
            .collect()
    }

    /// Snapshot of cloned `Arc` handles visible to `principal`.
    #[must_use]
    pub fn cloned_values_for(&self, principal: &PrincipalId) -> Vec<Arc<dyn Capsule>> {
        self.views.get(principal).map_or_else(Vec::new, |view| {
            view.values()
                .filter_map(|hash| {
                    self.instances
                        .get(hash)
                        .map(|entry| Arc::clone(&entry.capsule))
                })
                .collect()
        })
    }

    /// Number of distinct loaded runtime instances (one per content hash).
    #[must_use]
    pub fn len(&self) -> usize {
        self.instances.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.instances.is_empty()
    }

    /// Number of principal views that reference `hash` (the shared instance's
    /// refcount), or `None` if no runtime for `hash` is loaded.
    #[must_use]
    pub fn refcount_for_hash(&self, hash: &WasmHash) -> Option<usize> {
        self.instances.get(hash).map(|entry| entry.refcount)
    }

    // -----------------------------------------------------------------
    // Uplink management
    // -----------------------------------------------------------------

    /// Look up a uplink by its ID.
    #[must_use]
    pub fn get_uplink(&self, id: &UplinkId) -> Option<&UplinkDescriptor> {
        self.uplinks.get(id).map(|(_, desc)| desc)
    }

    /// Register a uplink for a capsule.
    ///
    /// # Errors
    ///
    /// Returns [`CapsuleError::UplinkAlreadyRegistered`] if a uplink
    /// with the same ID is already in the registry.
    pub fn register_uplink(
        &mut self,
        capsule_id: &CapsuleId,
        descriptor: UplinkDescriptor,
    ) -> CapsuleResult<()> {
        let uplink_id = descriptor.id;
        if self.uplinks.contains_key(&uplink_id) {
            return Err(CapsuleError::UnsupportedEntryPoint(format!(
                "Uplink already registered: {uplink_id}"
            )));
        }
        debug!(
            capsule_id = %capsule_id,
            uplink_id = %uplink_id,
            uplink_name = %descriptor.name,
            "Registered uplink"
        );
        self.uplinks
            .insert(uplink_id, (capsule_id.clone(), descriptor));
        Ok(())
    }

    /// Remove all uplinks belonging to a capsule.
    pub fn unregister_capsule_uplinks(&mut self, capsule_id: &CapsuleId) {
        self.uplinks.retain(|_, (owner, _)| owner != capsule_id);
    }

    /// Find a uplink that serves the given platform type.
    #[must_use]
    pub fn find_uplink_by_platform(&self, platform: &str) -> Option<&UplinkDescriptor> {
        self.uplinks
            .values()
            .find(|(_, desc)| desc.platform == platform)
            .map(|(_, desc)| desc)
    }

    /// Find all uplinks whose capabilities satisfy the given predicate.
    #[must_use]
    pub fn find_uplinks_with_capability(
        &self,
        check: impl Fn(&UplinkCapabilities) -> bool,
    ) -> Vec<&UplinkDescriptor> {
        self.uplinks
            .values()
            .filter(|(_, desc)| check(&desc.capabilities))
            .map(|(_, desc)| desc)
            .collect()
    }

    /// List all registered uplink descriptors.
    #[must_use]
    pub fn all_uplink_descriptors(&self) -> Vec<&UplinkDescriptor> {
        self.uplinks.values().map(|(_, desc)| desc).collect()
    }

    /// Remove and return all capsules, clearing uplinks too.
    ///
    /// Used during kernel shutdown to unload everything in one pass.
    pub fn drain(&mut self) -> Vec<Arc<dyn Capsule>> {
        self.uplinks.clear();
        self.uuid_id_map.clear();
        self.uuid_map.clear();
        self.views.clear();
        self.instances
            .drain()
            .map(|(_, entry)| entry.capsule)
            .collect()
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
