//! Capsule registry.
//!
//! Manages the set of loaded capsules and provides tool lookup across
//! all registered capsules.
//!
//! # Content-addressed instance store + per-principal view (issue #1069)
//!
//! The registry separates two orthogonal concerns:
//!
//! 1. **Instance store** — distinct capsule binaries are stored once, keyed
//!    by their content hash ([`WasmHash`]). Two principals running the same
//!    capsule binary share a single [`Arc<dyn Capsule>`]; a refcount tracks
//!    how many views reference each instance.
//! 2. **Per-principal view** — each [`PrincipalId`] has a `name → hash` map
//!    determining which capsules it can see/resolve. The view is the
//!    visibility floor: a capsule absent from a principal's view is invisible
//!    to that principal, full stop.
//!
//! **Phase 1 (this commit) is shape-only with ZERO behaviour change.** Every
//! caller is wired with [`PrincipalId::default()`] (or an `*_all`/`*_any`
//! variant), so the only populated view is `default`'s — which holds every
//! loaded capsule, exactly as the flat map did before. No per-principal
//! isolation or view-scoping LOGIC lives here yet; that is Phase 2.

use std::collections::HashMap;
use std::sync::Arc;

use tracing::{debug, info};
use uuid::Uuid;

use astrid_core::PrincipalId;
use astrid_core::{UplinkCapabilities, UplinkDescriptor, UplinkId};

use crate::capsule::{Capsule, CapsuleId};
use crate::error::{CapsuleError, CapsuleResult};

/// Content hash that addresses a distinct capsule binary in the instance store.
///
/// For a WASM capsule this is the BLAKE3 hex of the component, identical to
/// the `wasm_hash` recorded in the capsule's `meta.json` (see
/// `astrid-capsule-install`'s `CapsuleMeta::wasm_hash`). Two principals running
/// byte-identical binaries therefore resolve to the same [`WasmHash`] and share
/// one loaded instance.
///
/// Non-WASM capsules (MCP) have no component to hash — their `meta.json`
/// `wasm_hash` is `None`. They get a **synthetic** key derived from
/// `name + version` via [`WasmHash::synthetic`]. A synthetic key never dedups
/// against a real binary hash (the input space is disjoint), so distinct
/// non-WASM capsules — and distinct versions of one — still occupy distinct
/// instance slots.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WasmHash(String);

impl WasmHash {
    /// Wrap a pre-computed content hash (e.g. the `wasm_hash` from `meta.json`).
    #[must_use]
    pub fn from_raw(hash: impl Into<String>) -> Self {
        Self(hash.into())
    }

    /// Synthesize a stable instance key for a capsule with no binary hash
    /// (non-WASM/MCP capsules whose `meta.json` `wasm_hash` is `None`).
    ///
    /// Derived as BLAKE3 over `"synthetic:{name}\0{version}"`. The `synthetic:`
    /// domain prefix keeps the input space disjoint from a raw WASM binary hash
    /// (which is BLAKE3 of the component bytes), so a synthetic key can never
    /// collide with — and dedup against — a real binary.
    #[must_use]
    pub fn synthetic(name: &str, version: &str) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"synthetic:");
        hasher.update(name.as_bytes());
        hasher.update(&[0]);
        hasher.update(version.as_bytes());
        Self(hasher.finalize().to_hex().to_string())
    }

    /// The underlying hex string.
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

/// A single loaded capsule instance plus a reference count.
///
/// `refcount` is the number of per-principal views that reference this hash.
/// The instance (and its uplinks/uuid entries) is dropped only when the last
/// view releases it, i.e. when `refcount` reaches zero.
struct InstanceEntry {
    capsule: Arc<dyn Capsule>,
    refcount: usize,
}

/// Registry of loaded capsules.
///
/// Stores distinct capsule binaries once (content-addressed by [`WasmHash`])
/// and exposes them per-principal through [`views`](Self). See the module docs
/// for the instance-store / view split.
pub struct CapsuleRegistry {
    /// Distinct loaded instances, deduped by content hash.
    instances: HashMap<WasmHash, InstanceEntry>,
    /// Per-principal visibility: `principal → (capsule name → hash)`.
    views: HashMap<PrincipalId, HashMap<CapsuleId, WasmHash>>,
    /// Uplinks stay global (kernel-routed, principal-agnostic).
    uplinks: HashMap<UplinkId, (CapsuleId, UplinkDescriptor)>,
    /// Reverse map from WASM session UUIDs to instance hashes.
    ///
    /// Populated during capsule load so that host functions can resolve
    /// an IPC `source_id` (a UUID stamped by the kernel) back to the
    /// originating capsule instance for capability checks.
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
            uuid_map: HashMap::new(),
        }
    }

    /// Register a capsule binary under `hash` and add it to `principal`'s view.
    ///
    /// Dedup semantics: if the `hash` is already loaded, the existing instance
    /// is reused and its refcount is bumped (no second compile/load, no second
    /// uplink registration). Otherwise the supplied `capsule` becomes the
    /// instance, its uplinks are registered once, and the refcount starts at
    /// the count of views that reference it.
    ///
    /// The capsule is then made visible to `principal` via
    /// `views[principal][name] = hash`.
    ///
    /// # Errors
    ///
    /// Returns an error if the same capsule name is already present in
    /// `principal`'s view (a duplicate add for one principal), or if uplink
    /// registration fails for a freshly loaded instance.
    pub fn register(
        &mut self,
        capsule: Box<dyn Capsule>,
        hash: WasmHash,
        principal: &PrincipalId,
    ) -> CapsuleResult<()> {
        let id = capsule.id().clone();

        // Reject a duplicate add for this principal — the view already maps
        // this capsule name. (Mirrors the old "Already registered" guard,
        // which was global; in Phase 1 the only view is `default`, so the
        // behaviour is identical.)
        if let Some(view) = self.views.get(principal)
            && view.contains_key(&id)
        {
            return Err(CapsuleError::UnsupportedEntryPoint(format!(
                "Already registered: {id}"
            )));
        }

        if self.instances.contains_key(&hash) {
            // Dedup: instance already loaded — reuse it, bump the refcount,
            // and just extend this principal's view. Uplinks were registered
            // when the instance was first loaded; do NOT register them again.
            self.instances
                .get_mut(&hash)
                .expect("hash present, just checked")
                .refcount += 1;
            self.views
                .entry(principal.clone())
                .or_default()
                .insert(id.clone(), hash);
            info!(capsule_id = %id, principal = %principal, "Registered capsule (deduped, existing instance)");
            return Ok(());
        }

        // Fresh instance: store it and register its uplinks once.
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

        info!(capsule_id = %id, principal = %principal, "Registered capsule");
        self.instances.insert(
            hash.clone(),
            InstanceEntry {
                capsule,
                refcount: 1,
            },
        );
        self.views
            .entry(principal.clone())
            .or_default()
            .insert(id, hash);
        Ok(())
    }

    /// Unregister a capsule from `principal`'s view, returning the instance.
    ///
    /// Removes the `name → hash` entry from the principal's view and decrements
    /// the instance's refcount. The instance (and its uplinks + uuid entries)
    /// is dropped only when the last view releases it (refcount reaches zero).
    /// The `Arc` is returned in every case so the caller can run async unload.
    ///
    /// # Errors
    ///
    /// Returns [`CapsuleError::NotFound`] if no capsule with the given ID is in
    /// `principal`'s view.
    pub fn unregister(
        &mut self,
        principal: &PrincipalId,
        id: &CapsuleId,
    ) -> CapsuleResult<Arc<dyn Capsule>> {
        let hash = self
            .views
            .get_mut(principal)
            .and_then(|view| view.remove(id))
            .ok_or_else(|| CapsuleError::NotFound(format!("capsule {id}")))?;

        // Drop the principal's view entirely if it is now empty.
        if self.views.get(principal).is_some_and(HashMap::is_empty) {
            self.views.remove(principal);
        }

        let entry = self
            .instances
            .get_mut(&hash)
            .expect("view referenced a hash with no instance (registry invariant violated)");
        entry.refcount -= 1;
        let capsule = Arc::clone(&entry.capsule);

        if entry.refcount == 0 {
            // Last view released this instance — drop it and its global state.
            self.instances.remove(&hash);
            self.unregister_capsule_uplinks(id);
            self.uuid_map.retain(|_, h| h != &hash);
            info!(capsule_id = %id, principal = %principal, "Unregistered capsule (instance dropped)");
        } else {
            info!(capsule_id = %id, principal = %principal, refcount = entry.refcount, "Unregistered capsule (instance retained)");
        }

        Ok(capsule)
    }

    // -----------------------------------------------------------------
    // UUID mapping
    // -----------------------------------------------------------------

    /// Register a session UUID for a capsule instance (keyed by its hash).
    ///
    /// Called during WASM capsule load so that host functions can resolve
    /// IPC `source_id` UUIDs back to capsule identities.
    ///
    /// Silently overwrites on duplicate UUID. Each capsule load generates a
    /// fresh UUID, so collisions are not practically possible.
    pub fn register_uuid(&mut self, uuid: Uuid, hash: WasmHash) {
        debug!(%uuid, hash = %hash, "Registered capsule UUID mapping");
        self.uuid_map.insert(uuid, hash);
    }

    /// Resolve a capsule instance by its session UUID (uuid → hash → instance).
    #[must_use]
    pub fn find_instance_by_uuid(&self, uuid: &Uuid) -> Option<Arc<dyn Capsule>> {
        let hash = self.uuid_map.get(uuid)?;
        self.instances.get(hash).map(|e| Arc::clone(&e.capsule))
    }

    /// Whether an instance with this content hash is already loaded.
    ///
    /// Lets the kernel's per-principal load path DEDUP (#1069): if the hash is
    /// already loaded, the capsule binary need not be compiled again — the
    /// kernel can add it to a principal's view via [`Self::register_existing`]
    /// (or call [`Self::register`] with a freshly-built instance, which also
    /// dedups). Lookup is O(1).
    #[must_use]
    pub fn contains_hash(&self, hash: &WasmHash) -> bool {
        self.instances.contains_key(hash)
    }

    /// Add an ALREADY-LOADED instance (by hash) to `principal`'s view, bumping
    /// its refcount — without supplying a second `Box<dyn Capsule>`.
    ///
    /// The dedup fast path for the per-principal load (#1069): when
    /// [`Self::contains_hash`] is true, the kernel skips compiling the capsule
    /// entirely and calls this to extend the principal's view onto the existing
    /// instance. Uplinks were registered when the instance was first loaded, so
    /// they are NOT re-registered.
    ///
    /// # Errors
    ///
    /// Returns [`CapsuleError::NotFound`] if no instance with `hash` is loaded
    /// (caller must check [`Self::contains_hash`] first), or
    /// [`CapsuleError::UnsupportedEntryPoint`] if `principal`'s view already maps
    /// `id` (a duplicate add).
    pub fn register_existing(
        &mut self,
        id: &CapsuleId,
        hash: &WasmHash,
        principal: &PrincipalId,
    ) -> CapsuleResult<()> {
        if let Some(view) = self.views.get(principal)
            && view.contains_key(id)
        {
            return Err(CapsuleError::UnsupportedEntryPoint(format!(
                "Already registered: {id}"
            )));
        }
        let entry = self
            .instances
            .get_mut(hash)
            .ok_or_else(|| CapsuleError::NotFound(format!("no loaded instance for hash {hash}")))?;
        entry.refcount += 1;
        self.views
            .entry(principal.clone())
            .or_default()
            .insert(id.clone(), hash.clone());
        info!(capsule_id = %id, principal = %principal, "Registered capsule (deduped onto existing instance)");
        Ok(())
    }

    /// Get a capsule instance visible to `principal`, by capsule ID.
    ///
    /// Resolves through `principal`'s view (name → hash → instance). Returns a
    /// cloned `Arc` so callers can use the capsule after releasing the registry
    /// lock. A capsule absent from `principal`'s view is invisible: returns
    /// `None` (the fail-closed floor — there is no fallback to another view).
    #[must_use]
    pub fn get(&self, principal: &PrincipalId, id: &CapsuleId) -> Option<Arc<dyn Capsule>> {
        let hash = self.views.get(principal)?.get(id)?;
        self.instances.get(hash).map(|e| Arc::clone(&e.capsule))
    }

    /// Resolve a capsule instance by name across ANY view/instance.
    ///
    /// Principal-agnostic lookup for daemon-health / lifecycle readers that
    /// operate on the global loaded set rather than one principal's view.
    /// Returns the first instance whose ID matches in any view.
    #[must_use]
    pub fn get_any(&self, id: &CapsuleId) -> Option<Arc<dyn Capsule>> {
        for view in self.views.values() {
            if let Some(hash) = view.get(id)
                && let Some(entry) = self.instances.get(hash)
            {
                return Some(Arc::clone(&entry.capsule));
            }
        }
        None
    }

    /// Return the first principal whose view maps `id`, if any.
    ///
    /// For daemon-wide, principal-agnostic operations (e.g. the health-monitor
    /// auto-restart) that hold a capsule ID resolved from `all_instances` and
    /// need SOME principal whose view to operate the per-principal
    /// load/unload/restart machinery against. Map iteration order is arbitrary,
    /// so the choice among multiple referencing principals is unspecified — fine
    /// for these global operations, where the underlying instance is shared and
    /// restarting it re-reads the same content-addressed bytes regardless.
    #[must_use]
    pub fn any_principal_with(&self, id: &CapsuleId) -> Option<PrincipalId> {
        self.views
            .iter()
            .find(|(_, view)| view.contains_key(id))
            .map(|(principal, _)| principal.clone())
    }

    /// List the capsule IDs visible to `principal` (its view keys).
    #[must_use]
    pub fn list(&self, principal: &PrincipalId) -> Vec<&CapsuleId> {
        match self.views.get(principal) {
            Some(view) => view.keys().collect(),
            None => Vec::new(),
        }
    }

    /// Snapshot of cloned `Arc` handles to every DISTINCT loaded instance.
    ///
    /// Global, principal-agnostic — one handle per instance regardless of how
    /// many views reference it. For drain/health/mesh readers that operate on
    /// the loaded set rather than a single principal's view.
    #[must_use]
    pub fn all_instances(&self) -> Vec<Arc<dyn Capsule>> {
        self.instances
            .values()
            .map(|e| Arc::clone(&e.capsule))
            .collect()
    }

    /// Iterator over every distinct loaded instance (global).
    pub fn values(&self) -> impl Iterator<Item = &(dyn Capsule + '_)> {
        self.instances.values().map(|e| e.capsule.as_ref())
    }

    /// Snapshot of cloned `Arc` handles to the capsules visible to `principal`.
    ///
    /// One pass over `principal`'s view. Lets a caller release the registry
    /// lock before doing async work on the capsules (e.g. invoking an
    /// interceptor that may `block_in_place`).
    #[must_use]
    pub fn cloned_values(&self, principal: &PrincipalId) -> Vec<Arc<dyn Capsule>> {
        match self.views.get(principal) {
            Some(view) => view
                .values()
                .filter_map(|hash| self.instances.get(hash).map(|e| Arc::clone(&e.capsule)))
                .collect(),
            None => Vec::new(),
        }
    }

    /// Number of distinct loaded instances.
    #[must_use]
    pub fn len(&self) -> usize {
        self.instances.len()
    }

    /// Whether any instance is loaded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.instances.is_empty()
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

    /// Remove and return all instances, clearing views/uplinks/uuid map too.
    ///
    /// Used during kernel shutdown to unload everything in one pass.
    pub fn drain(&mut self) -> Vec<Arc<dyn Capsule>> {
        self.uplinks.clear();
        self.uuid_map.clear();
        self.views.clear();
        self.instances.drain().map(|(_, e)| e.capsule).collect()
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
mod tests {
    use super::*;

    use std::path::Path;
    use std::time::Duration;

    use async_trait::async_trait;

    use crate::capsule::{CapsuleState, ReadyStatus};
    use crate::context::CapsuleContext;
    use crate::error::CapsuleResult;
    use crate::manifest::{CapabilitiesDef, CapsuleManifest, PackageDef};

    /// Synthetic per-name hash used by tests that don't care about content
    /// addressing — keeps each registered capsule in its own instance slot.
    fn test_hash(name: &str) -> WasmHash {
        WasmHash::synthetic(name, "0.0.1")
    }

    struct MockCapsule {
        id: CapsuleId,
        manifest: CapsuleManifest,
    }

    impl MockCapsule {
        fn new(name: &str) -> Self {
            Self {
                id: CapsuleId::from_static(name),
                manifest: CapsuleManifest {
                    package: PackageDef {
                        name: name.to_string(),
                        version: "0.0.1".to_string(),
                        description: None,
                        authors: Vec::new(),
                        repository: None,
                        homepage: None,
                        documentation: None,
                        license: None,
                        license_file: None,
                        readme: None,
                        keywords: Vec::new(),
                        categories: Vec::new(),
                        astrid_version: None,
                        publish: None,
                        include: None,
                        exclude: None,
                        metadata: None,
                    },
                    components: Vec::new(),
                    imports: std::collections::HashMap::new(),
                    exports: std::collections::HashMap::new(),
                    capabilities: CapabilitiesDef::default(),
                    env: std::collections::HashMap::new(),
                    context_files: Vec::new(),
                    commands: Vec::new(),
                    mcp_servers: Vec::new(),
                    skills: Vec::new(),
                    uplinks: Vec::new(),
                    publishes: ::std::collections::HashMap::new(),
                    subscribes: ::std::collections::HashMap::new(),
                    tools: ::std::vec::Vec::new(),
                },
            }
        }
    }

    #[async_trait]
    impl crate::capsule::Capsule for MockCapsule {
        fn id(&self) -> &CapsuleId {
            &self.id
        }
        fn manifest(&self) -> &CapsuleManifest {
            &self.manifest
        }
        fn state(&self) -> CapsuleState {
            CapsuleState::Ready
        }
        async fn load(&mut self, _ctx: &CapsuleContext) -> CapsuleResult<()> {
            Ok(())
        }
        async fn unload(&mut self) -> CapsuleResult<()> {
            Ok(())
        }
        fn take_inbound_rx(
            &mut self,
        ) -> Option<tokio::sync::mpsc::Receiver<astrid_core::InboundMessage>> {
            None
        }
        async fn wait_ready(&self, _timeout: Duration) -> ReadyStatus {
            ReadyStatus::Ready
        }
        async fn invoke_interceptor(
            &self,
            _action: &str,
            _payload: &[u8],
            _caller: Option<&astrid_events::ipc::IpcMessage>,
        ) -> CapsuleResult<crate::capsule::InterceptResult> {
            Ok(crate::capsule::InterceptResult::Continue(Vec::new()))
        }
        fn check_health(&self) -> CapsuleState {
            CapsuleState::Ready
        }
        fn source_dir(&self) -> Option<&Path> {
            None
        }
    }

    #[test]
    fn synthetic_hash_is_disjoint_from_raw() {
        // A synthetic key (domain-prefixed) can never equal a raw binary hash.
        let synthetic = WasmHash::synthetic("foo", "1.0.0");
        let raw = WasmHash::from_raw(blake3::hash(b"foo").to_hex().to_string());
        assert_ne!(synthetic, raw);
        // Same name+version is stable; different version diverges.
        assert_eq!(synthetic, WasmHash::synthetic("foo", "1.0.0"));
        assert_ne!(synthetic, WasmHash::synthetic("foo", "2.0.0"));
    }

    #[test]
    fn unregister_not_found_returns_not_found_error() {
        let mut registry = CapsuleRegistry::new();
        let principal = PrincipalId::default();
        let id = CapsuleId::from_static("nonexistent");
        match registry.unregister(&principal, &id) {
            Err(CapsuleError::NotFound(msg)) => {
                assert!(
                    msg.contains("nonexistent"),
                    "message should contain the id: {msg}"
                );
            },
            Err(other) => panic!("expected NotFound, got: {other:?}"),
            Ok(_) => panic!("expected error for nonexistent capsule"),
        }
    }

    #[test]
    fn uuid_mapping_register_and_find() {
        let mut registry = CapsuleRegistry::new();
        let principal = PrincipalId::default();
        let uuid = Uuid::new_v4();
        let hash = test_hash("test-capsule");

        // No instance yet — uuid resolves to nothing.
        registry.register_uuid(uuid, hash.clone());
        assert!(registry.find_instance_by_uuid(&uuid).is_none());

        // Register the instance under the same hash; now uuid resolves.
        registry
            .register(Box::new(MockCapsule::new("test-capsule")), hash, &principal)
            .expect("register");
        assert!(registry.find_instance_by_uuid(&uuid).is_some());
        assert!(registry.find_instance_by_uuid(&Uuid::new_v4()).is_none());
    }

    #[test]
    fn uuid_mapping_overwrite_on_duplicate() {
        let mut registry = CapsuleRegistry::new();
        let uuid = Uuid::new_v4();
        let first = test_hash("first");
        let second = test_hash("second");

        registry.register_uuid(uuid, first);
        registry.register_uuid(uuid, second.clone());
        // Latest write wins.
        let principal = PrincipalId::default();
        registry
            .register(Box::new(MockCapsule::new("second")), second, &principal)
            .expect("register");
        assert!(registry.find_instance_by_uuid(&uuid).is_some());
    }

    #[test]
    fn uuid_mapping_cleanup_on_unregister() {
        let mut registry = CapsuleRegistry::new();
        let principal = PrincipalId::default();
        let uuid = Uuid::new_v4();
        let capsule_id = CapsuleId::from_static("removable");
        let hash = test_hash("removable");

        registry
            .register(
                Box::new(MockCapsule::new("removable")),
                hash.clone(),
                &principal,
            )
            .expect("register");
        registry.register_uuid(uuid, hash);
        assert!(registry.find_instance_by_uuid(&uuid).is_some());

        registry
            .unregister(&principal, &capsule_id)
            .expect("unregister");
        assert!(registry.find_instance_by_uuid(&uuid).is_none());
    }

    #[test]
    fn uuid_mapping_cleanup_on_drain() {
        let mut registry = CapsuleRegistry::new();
        let principal = PrincipalId::default();
        let uuid = Uuid::new_v4();
        let hash = test_hash("test");
        registry
            .register(Box::new(MockCapsule::new("test")), hash.clone(), &principal)
            .expect("register");
        registry.register_uuid(uuid, hash);
        assert!(registry.find_instance_by_uuid(&uuid).is_some());

        let _ = registry.drain();
        assert!(registry.find_instance_by_uuid(&uuid).is_none());
    }

    #[test]
    fn dedup_shares_instance_and_refcounts() {
        // Same binary (same hash) seen by two principals: one instance,
        // refcount 2. Unregistering one keeps it alive; unregistering both
        // drops it.
        let mut registry = CapsuleRegistry::new();
        let a = PrincipalId::new("alice").unwrap();
        let b = PrincipalId::new("bob").unwrap();
        let hash = test_hash("shared");
        let id = CapsuleId::from_static("shared");

        registry
            .register(Box::new(MockCapsule::new("shared")), hash.clone(), &a)
            .expect("register a");
        registry
            .register(Box::new(MockCapsule::new("shared")), hash, &b)
            .expect("register b");

        // One distinct instance despite two views.
        assert_eq!(registry.len(), 1);
        assert!(registry.get(&a, &id).is_some());
        assert!(registry.get(&b, &id).is_some());

        // Drop alice's view — instance survives for bob.
        registry.unregister(&a, &id).expect("unregister a");
        assert_eq!(registry.len(), 1);
        assert!(registry.get(&a, &id).is_none());
        assert!(registry.get(&b, &id).is_some());

        // Drop bob's view — last reference, instance gone.
        registry.unregister(&b, &id).expect("unregister b");
        assert_eq!(registry.len(), 0);
        assert!(registry.get(&b, &id).is_none());
    }

    #[test]
    fn register_existing_dedups_onto_loaded_instance() {
        // The kernel's per-principal load fast path: A loads `shared` (compiles
        // it once), then B reuses the SAME hash via `register_existing` without
        // a second compile. One instance, refcount 2; both views resolve it.
        let mut registry = CapsuleRegistry::new();
        let a = PrincipalId::new("alice").unwrap();
        let b = PrincipalId::new("bob").unwrap();
        let hash = test_hash("shared");
        let id = CapsuleId::from_static("shared");

        assert!(!registry.contains_hash(&hash), "not loaded yet");
        registry
            .register(Box::new(MockCapsule::new("shared")), hash.clone(), &a)
            .expect("register a");
        assert!(registry.contains_hash(&hash), "loaded after first register");

        // B dedups onto the existing instance — no second Box<dyn Capsule>.
        registry
            .register_existing(&id, &hash, &b)
            .expect("register_existing b");
        assert_eq!(registry.len(), 1, "still one instance");
        assert!(registry.get(&a, &id).is_some());
        assert!(registry.get(&b, &id).is_some());

        // Unregistering one keeps it alive; both gone drops it.
        registry.unregister(&a, &id).expect("unregister a");
        assert_eq!(registry.len(), 1);
        registry.unregister(&b, &id).expect("unregister b");
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn register_existing_missing_hash_is_not_found() {
        let mut registry = CapsuleRegistry::new();
        let p = PrincipalId::new("alice").unwrap();
        let id = CapsuleId::from_static("ghost");
        let hash = test_hash("ghost");
        match registry.register_existing(&id, &hash, &p) {
            Err(CapsuleError::NotFound(_)) => {},
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn view_is_fail_closed_no_cross_principal_fallback() {
        // A capsule in alice's view is invisible to bob via `get`, but
        // resolvable globally via `get_any`.
        let mut registry = CapsuleRegistry::new();
        let a = PrincipalId::new("alice").unwrap();
        let b = PrincipalId::new("bob").unwrap();
        let id = CapsuleId::from_static("only-alice");

        registry
            .register(
                Box::new(MockCapsule::new("only-alice")),
                test_hash("only-alice"),
                &a,
            )
            .expect("register");

        assert!(registry.get(&a, &id).is_some());
        assert!(
            registry.get(&b, &id).is_none(),
            "no cross-principal fallback"
        );
        assert!(registry.get_any(&id).is_some(), "global resolver sees it");
        assert_eq!(registry.list(&b).len(), 0, "bob's view is empty");
        assert_eq!(registry.list(&a).len(), 1);
    }
}
