//! Capsule registry.
//!
//! Manages loaded capsule instances and principal-scoped capsule views.
//!
//! Runtime instances are principal-scoped. The installed artifact remains
//! content-addressed by WASM hash on disk, but a loaded [`Capsule`] owns
//! principal-bound host state such as KV and resolved env, so it cannot be
//! shared across principal views.

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

struct InstanceEntry {
    capsule: Arc<dyn Capsule>,
    refcount: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct InstanceKey {
    principal: PrincipalId,
    hash: WasmHash,
}

impl InstanceKey {
    fn new(principal: &PrincipalId, hash: &WasmHash) -> Self {
        Self {
            principal: principal.clone(),
            hash: hash.clone(),
        }
    }
}

/// Registry of loaded capsules.
///
/// Stores principal-bound runtime instances by `(principal, content hash)` and
/// exposes per-principal views of those instances. A principal can only resolve
/// capsules present in its view; daemon-health operations can still inspect the
/// global instance set.
pub struct CapsuleRegistry {
    instances: HashMap<InstanceKey, InstanceEntry>,
    views: HashMap<PrincipalId, HashMap<CapsuleId, WasmHash>>,
    uplinks: HashMap<UplinkId, (CapsuleId, UplinkDescriptor)>,
    /// Legacy reverse map from WASM session UUIDs to capsule IDs.
    uuid_id_map: HashMap<Uuid, CapsuleId>,
    /// Reverse map from WASM session UUIDs to runtime instance keys.
    ///
    /// Populated during capsule load so that host functions can resolve
    /// an IPC `source_id` back to the originating loaded instance.
    uuid_map: HashMap<Uuid, InstanceKey>,
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

    /// Register a capsule under `hash` in `principal`'s view.
    ///
    /// # Errors
    ///
    /// Returns an error when the principal already has a capsule with that ID,
    /// or when uplink registration fails for a new instance.
    pub fn register_for(
        &mut self,
        capsule: Box<dyn Capsule>,
        hash: WasmHash,
        principal: &PrincipalId,
    ) -> CapsuleResult<()> {
        let id = capsule.id().clone();
        if self
            .views
            .get(principal)
            .is_some_and(|view| view.contains_key(&id))
        {
            return Err(CapsuleError::UnsupportedEntryPoint(format!(
                "Already registered: {id}"
            )));
        }

        let key = InstanceKey::new(principal, &hash);
        if let Some(entry) = self.instances.get_mut(&key) {
            if entry.capsule.id() != &id {
                return Err(CapsuleError::UnsupportedEntryPoint(format!(
                    "Content hash {hash} is already registered for capsule {}",
                    entry.capsule.id()
                )));
            }
            entry.refcount += 1;
            self.views
                .entry(principal.clone())
                .or_default()
                .insert(id.clone(), hash);
            info!(capsule_id = %id, principal = %principal, "Registered capsule view (existing principal instance)");
            return Ok(());
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

        info!(capsule_id = %id, principal = %principal, hash = %hash, "Registered capsule instance");
        self.instances.insert(
            key,
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

    /// Add an already-loaded instance to `principal`'s view.
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
        let key = InstanceKey::new(principal, hash);
        let entry = self
            .instances
            .get_mut(&key)
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
        info!(capsule_id = %id, principal = %principal, hash = %hash, "Registered capsule view (existing instance)");
        Ok(())
    }

    /// Unregister a capsule from the default principal's view.
    pub fn unregister(&mut self, id: &CapsuleId) -> CapsuleResult<Arc<dyn Capsule>> {
        self.unregister_for(&PrincipalId::default(), id)
    }

    /// Unregister a capsule from `principal`'s view, returning the instance.
    ///
    /// # Errors
    ///
    /// Returns [`CapsuleError::NotFound`] if the capsule is absent from that
    /// principal's view.
    pub fn unregister_for(
        &mut self,
        principal: &PrincipalId,
        id: &CapsuleId,
    ) -> CapsuleResult<Arc<dyn Capsule>> {
        let hash = self
            .views
            .get_mut(principal)
            .and_then(|view| view.remove(id))
            .ok_or_else(|| CapsuleError::NotFound(format!("capsule {id}")))?;

        if self.views.get(principal).is_some_and(HashMap::is_empty) {
            self.views.remove(principal);
        }

        let key = InstanceKey::new(principal, &hash);
        let entry = self
            .instances
            .get_mut(&key)
            .expect("principal view referenced missing capsule instance");
        entry.refcount = entry.refcount.saturating_sub(1);
        let capsule = Arc::clone(&entry.capsule);

        if entry.refcount == 0 {
            self.instances.remove(&key);
            if self.any_principal_with(id).is_none() {
                self.unregister_capsule_uplinks(id);
            }
            self.uuid_map.retain(|_, instance_key| instance_key != &key);
            self.uuid_id_map
                .retain(|_, mapped_capsule_id| mapped_capsule_id != id);
            info!(capsule_id = %id, principal = %principal, hash = %hash, "Unregistered capsule instance");
        } else {
            info!(capsule_id = %id, principal = %principal, hash = %hash, refcount = entry.refcount, "Unregistered capsule view");
        }

        Ok(capsule)
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

    /// Register a session UUID for a principal-scoped capsule runtime instance.
    pub fn register_instance_uuid(&mut self, uuid: Uuid, hash: WasmHash, principal: &PrincipalId) {
        debug!(
            %uuid,
            hash = %hash,
            principal = %principal,
            "Registered capsule UUID mapping"
        );
        self.uuid_map
            .insert(uuid, InstanceKey::new(principal, &hash));
    }

    /// Look up a capsule instance by its session UUID.
    #[must_use]
    pub fn find_instance_by_uuid(&self, uuid: &Uuid) -> Option<Arc<dyn Capsule>> {
        let key = self.uuid_map.get(uuid)?;
        self.instances
            .get(key)
            .map(|entry| Arc::clone(&entry.capsule))
    }

    /// Look up a capsule ID by its session UUID.
    #[must_use]
    pub fn find_by_uuid(&self, uuid: &Uuid) -> Option<&CapsuleId> {
        self.uuid_id_map.get(uuid)
    }

    /// Whether this content-addressed instance is already loaded.
    #[must_use]
    pub fn contains_hash(&self, hash: &WasmHash) -> bool {
        self.instances.keys().any(|key| &key.hash == hash)
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
        let key = InstanceKey::new(principal, hash);
        self.instances
            .get(&key)
            .map(|entry| Arc::clone(&entry.capsule))
    }

    /// Get a capsule from any principal view.
    #[must_use]
    pub fn get_any(&self, id: &CapsuleId) -> Option<Arc<dyn Capsule>> {
        self.views.iter().find_map(|(principal, view)| {
            let hash = view.get(id)?;
            let key = InstanceKey::new(principal, hash);
            self.instances
                .get(&key)
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

    /// Return an arbitrary principal whose view contains `id`.
    #[must_use]
    pub fn any_principal_with(&self, id: &CapsuleId) -> Option<PrincipalId> {
        self.views
            .iter()
            .find(|(_, view)| view.contains_key(id))
            .map(|(principal, _)| principal.clone())
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

    /// Snapshot of cloned `Arc` handles to every loaded principal instance.
    #[must_use]
    pub fn cloned_values_with_principal(&self) -> Vec<(PrincipalId, Arc<dyn Capsule>)> {
        self.instances
            .iter()
            .map(|(key, entry)| (key.principal.clone(), Arc::clone(&entry.capsule)))
            .collect()
    }

    /// Snapshot of cloned `Arc` handles visible to `principal`.
    #[must_use]
    pub fn cloned_values_for(&self, principal: &PrincipalId) -> Vec<Arc<dyn Capsule>> {
        self.views.get(principal).map_or_else(Vec::new, |view| {
            view.values()
                .filter_map(|hash| {
                    let key = InstanceKey::new(principal, hash);
                    self.instances
                        .get(&key)
                        .map(|entry| Arc::clone(&entry.capsule))
                })
                .collect()
        })
    }

    /// Number of distinct loaded instances.
    #[must_use]
    pub fn len(&self) -> usize {
        self.instances.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.instances.is_empty()
    }

    /// Number of principal views that reference `hash`.
    #[must_use]
    pub fn refcount_for_hash(&self, hash: &WasmHash) -> Option<usize> {
        let count = self
            .instances
            .iter()
            .filter(|(key, _)| &key.hash == hash)
            .map(|(_, entry)| entry.refcount)
            .sum();
        (count > 0).then_some(count)
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
mod tests {
    use super::*;

    use std::path::Path;
    use std::time::Duration;

    use async_trait::async_trait;

    use crate::capsule::{CapsuleState, ReadyStatus};
    use crate::context::CapsuleContext;
    use crate::error::CapsuleResult;
    use crate::manifest::{CapabilitiesDef, CapsuleManifest, PackageDef};

    fn pid(name: &str) -> PrincipalId {
        PrincipalId::new(name).expect("valid principal")
    }

    fn test_hash(value: &str) -> WasmHash {
        WasmHash::from_raw(value)
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
    fn unregister_not_found_returns_not_found_error() {
        let mut registry = CapsuleRegistry::new();
        let id = CapsuleId::from_static("nonexistent");
        match registry.unregister(&id) {
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
        let uuid = Uuid::new_v4();
        let hash = test_hash("hash-a");

        registry
            .register_for(
                Box::new(MockCapsule::new("test-capsule")),
                hash.clone(),
                &pid("alice"),
            )
            .expect("register");
        registry.register_uuid(uuid, CapsuleId::from_static("test-capsule"));
        registry.register_instance_uuid(uuid, hash, &pid("alice"));

        assert!(
            registry.find_instance_by_uuid(&uuid).is_some(),
            "uuid should resolve to the loaded capsule instance"
        );
        assert_eq!(
            registry
                .find_by_uuid(&uuid)
                .expect("legacy uuid mapped")
                .as_str(),
            "test-capsule"
        );
        assert!(registry.find_instance_by_uuid(&Uuid::new_v4()).is_none());
    }

    #[test]
    fn uuid_mapping_overwrite_on_duplicate() {
        let mut registry = CapsuleRegistry::new();
        let uuid = Uuid::new_v4();
        let first = test_hash("first-hash");
        let second = test_hash("second-hash");

        registry
            .register_for(
                Box::new(MockCapsule::new("first")),
                first.clone(),
                &pid("alice"),
            )
            .expect("register first");
        registry
            .register_for(
                Box::new(MockCapsule::new("second")),
                second.clone(),
                &pid("alice"),
            )
            .expect("register second");
        registry.register_instance_uuid(uuid, first, &pid("alice"));
        registry.register_instance_uuid(uuid, second, &pid("alice"));
        assert_eq!(
            registry
                .find_instance_by_uuid(&uuid)
                .expect("uuid mapped")
                .id()
                .as_str(),
            "second"
        );
    }

    #[test]
    fn uuid_mapping_cleanup_on_unregister() {
        let mut registry = CapsuleRegistry::new();
        let uuid = Uuid::new_v4();
        let capsule_id = CapsuleId::from_static("removable");
        let hash = test_hash("removable-hash");

        registry
            .register_for(
                Box::new(MockCapsule::new("removable")),
                hash.clone(),
                &pid("alice"),
            )
            .expect("register");
        registry.register_instance_uuid(uuid, hash, &pid("alice"));
        assert!(registry.find_instance_by_uuid(&uuid).is_some());

        registry
            .unregister_for(&pid("alice"), &capsule_id)
            .expect("unregister");
        assert!(registry.find_instance_by_uuid(&uuid).is_none());
    }

    #[test]
    fn uuid_mapping_cleanup_on_drain() {
        let mut registry = CapsuleRegistry::new();
        let uuid = Uuid::new_v4();
        let hash = test_hash("test-hash");
        registry
            .register_for(
                Box::new(MockCapsule::new("test")),
                hash.clone(),
                &pid("alice"),
            )
            .expect("register");
        registry.register_instance_uuid(uuid, hash, &pid("alice"));
        assert!(registry.find_instance_by_uuid(&uuid).is_some());

        let _ = registry.drain();
        assert!(registry.find_instance_by_uuid(&uuid).is_none());
    }

    #[test]
    fn same_hash_reuses_artifact_but_isolates_runtime_instances() {
        let mut registry = CapsuleRegistry::new();
        let hash = test_hash("same-wasm-hash");
        let id = CapsuleId::from_static("shared-capsule");
        let alice = pid("alice");
        let bob = pid("bob");

        registry
            .register_for(
                Box::new(MockCapsule::new("shared-capsule")),
                hash.clone(),
                &alice,
            )
            .expect("register alice");
        registry
            .register_for(
                Box::new(MockCapsule::new("shared-capsule")),
                hash.clone(),
                &bob,
            )
            .expect("register bob");

        let alice_capsule = registry.get_for(&alice, &id).expect("alice sees capsule");
        let bob_capsule = registry.get_for(&bob, &id).expect("bob sees capsule");
        assert!(
            !Arc::ptr_eq(&alice_capsule, &bob_capsule),
            "same content hash must not share principal-bound runtime state"
        );
        let mut owners: Vec<_> = registry
            .cloned_values_with_principal()
            .into_iter()
            .map(|(principal, capsule)| (principal.to_string(), capsule.id().to_string()))
            .collect();
        owners.sort();
        assert_eq!(
            owners,
            vec![
                ("alice".to_string(), "shared-capsule".to_string()),
                ("bob".to_string(), "shared-capsule".to_string()),
            ]
        );
        assert_eq!(registry.refcount_for_hash(&hash), Some(2));
        assert_eq!(registry.len(), 2, "one runtime instance per principal");
    }

    #[test]
    fn unregister_one_principal_retains_shared_instance() {
        let mut registry = CapsuleRegistry::new();
        let hash = test_hash("same-wasm-hash");
        let id = CapsuleId::from_static("shared-capsule");
        let alice = pid("alice");
        let bob = pid("bob");

        registry
            .register_for(
                Box::new(MockCapsule::new("shared-capsule")),
                hash.clone(),
                &alice,
            )
            .expect("register alice");
        registry
            .register_for(
                Box::new(MockCapsule::new("shared-capsule")),
                hash.clone(),
                &bob,
            )
            .expect("register bob");

        let removed = registry
            .unregister_for(&alice, &id)
            .expect("alice unregister");
        assert_eq!(removed.id().as_str(), "shared-capsule");
        assert!(
            registry.get_for(&alice, &id).is_none(),
            "alice's view no longer contains the capsule"
        );
        assert!(
            registry.get_for(&bob, &id).is_some(),
            "bob's view still references its own runtime instance"
        );
        assert_eq!(registry.refcount_for_hash(&hash), Some(1));
    }
}
