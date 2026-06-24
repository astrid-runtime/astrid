//! Capsule registry.
//!
//! Manages the set of loaded capsules and provides tool lookup across
//! all registered capsules.

use std::collections::HashMap;
use std::sync::Arc;

use tracing::{debug, info};
use uuid::Uuid;

use astrid_core::{UplinkCapabilities, UplinkDescriptor, UplinkId};

use crate::capsule::{Capsule, CapsuleId};
use crate::error::{CapsuleError, CapsuleResult};

/// Registry of loaded capsules.
///
/// Parallel to `ToolRegistry` in `astrid-tools`. Stores capsules keyed by
/// their `CapsuleId` and provides cross-capsule tool lookup.
pub struct CapsuleRegistry {
    capsules: HashMap<CapsuleId, Arc<dyn Capsule>>,
    uplinks: HashMap<UplinkId, (CapsuleId, UplinkDescriptor)>,
    /// Reverse map from WASM session UUIDs to capsule IDs.
    ///
    /// Populated during capsule load so that host functions can resolve
    /// an IPC `source_id` (a UUID stamped by the kernel) back to the
    /// originating capsule for capability checks.
    uuid_map: HashMap<Uuid, CapsuleId>,
}

impl CapsuleRegistry {
    /// Create an empty capsule registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            capsules: HashMap::new(),
            uplinks: HashMap::new(),
            uuid_map: HashMap::new(),
        }
    }

    /// Register a capsule.
    ///
    /// # Errors
    ///
    /// Returns [`CapsuleError::AlreadyRegistered`] if a capsule with the same
    /// ID is already in the registry.
    pub fn register(&mut self, capsule: Box<dyn Capsule>) -> CapsuleResult<()> {
        let capsule: Arc<dyn Capsule> = Arc::from(capsule);
        let id = capsule.id().clone();
        if self.capsules.contains_key(&id) {
            return Err(CapsuleError::UnsupportedEntryPoint(format!(
                "Already registered: {id}"
            )));
        }

        // Register the capsule's uplinks (uplinks)
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

        info!(capsule_id = %id, "Registered capsule");
        self.capsules.insert(id, capsule);
        Ok(())
    }

    /// Unregister a capsule, returning it if it was present.
    ///
    /// # Errors
    ///
    /// Returns [`CapsuleError::NotFound`] if no capsule with the given ID exists.
    pub fn unregister(&mut self, id: &CapsuleId) -> CapsuleResult<Arc<dyn Capsule>> {
        let capsule = self
            .capsules
            .remove(id)
            .ok_or_else(|| CapsuleError::NotFound(format!("capsule {id}")))?;

        // Clean up the capsule's uplinks.
        self.unregister_capsule_uplinks(id);

        // Clean up UUID mapping for this capsule.
        self.uuid_map.retain(|_, cid| cid != id);

        info!(capsule_id = %id, "Unregistered capsule");
        Ok(capsule)
    }

    // -----------------------------------------------------------------
    // UUID mapping
    // -----------------------------------------------------------------

    /// Register a session UUID for a capsule.
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
            "Registered capsule UUID mapping"
        );
        self.uuid_map.insert(uuid, capsule_id);
    }

    /// Look up a capsule ID by its session UUID.
    #[must_use]
    pub fn find_by_uuid(&self, uuid: &Uuid) -> Option<&CapsuleId> {
        self.uuid_map.get(uuid)
    }

    /// Get a shared reference to a capsule by ID.
    ///
    /// Returns a cloned `Arc` so callers can use the capsule after releasing
    /// the registry lock.
    #[must_use]
    pub fn get(&self, id: &CapsuleId) -> Option<Arc<dyn Capsule>> {
        self.capsules.get(id).cloned()
    }

    /// List all registered capsule IDs.
    #[must_use]
    pub fn list(&self) -> Vec<&CapsuleId> {
        self.capsules.keys().collect()
    }

    /// Iterator over all registered capsules.
    pub fn values(&self) -> impl Iterator<Item = &(dyn Capsule + '_)> {
        self.capsules.values().map(|c| c.as_ref())
    }

    /// Snapshot of cloned `Arc` handles to every registered capsule.
    ///
    /// One pass over the map (the public [`Self::values`] yields `&dyn Capsule`,
    /// so it can't be `cloned()` into owned handles). Lets a caller release the
    /// registry lock before doing async work on the capsules (e.g. invoking an
    /// interceptor that may `block_in_place`).
    #[must_use]
    pub fn cloned_values(&self) -> Vec<Arc<dyn Capsule>> {
        self.capsules.values().cloned().collect()
    }

    /// Number of registered capsules.
    #[must_use]
    pub fn len(&self) -> usize {
        self.capsules.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.capsules.is_empty()
    }

    /// A stable hash over the loaded capsule set — the sorted list of
    /// `(capsule_id, package_version)` pairs.
    ///
    /// Moves iff a capsule is added, removed, or version-bumped (a live
    /// upgrade), and is independent of insertion order (the pairs are sorted
    /// first). Unlike a monotonic counter it carries no process state, so an
    /// unchanged set hashes identically across daemon restarts. That lets a
    /// consumer persist this epoch beside a cache and re-validate cheaply on
    /// its own next turn — the mechanism the per-principal tool-schema cache
    /// uses to self-heal after a runtime capsule install without the kernel
    /// fanning an invalidation out to every principal.
    ///
    /// Not a cryptographic digest: `DefaultHasher` is a fixed-key SipHash,
    /// deterministic for a given build. A `std` upgrade could change the
    /// algorithm, costing at most one spurious cache refresh after a daemon
    /// binary upgrade — harmless and self-correcting.
    #[must_use]
    pub fn set_epoch(&self) -> CapsuleSetEpoch {
        let mut pairs: Vec<(&str, &str)> = self
            .capsules
            .iter()
            .map(|(id, capsule)| (id.as_str(), capsule.manifest().package.version.as_str()))
            .collect();
        pairs.sort_unstable();
        CapsuleSetEpoch(hash_capsule_set(&pairs))
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
        self.uuid_map.clear();
        self.capsules.drain().map(|(_, c)| c).collect()
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
            .field("capsule_count", &self.capsules.len())
            .field("capsule_ids", &self.list())
            .field("uplink_count", &self.uplinks.len())
            .finish()
    }
}

/// A stable fingerprint of the loaded capsule set — the value returned by
/// [`CapsuleRegistry::set_epoch`].
///
/// A newtype over the hash rather than a bare `u64`: it has exactly one meaning
/// — "which capsules are loaded, at which versions" — and must not be conflated
/// with other counters or hashes. Serde-transparent so it persists / crosses the
/// `astrid:sys@1.1.0` `capsule-set-epoch` ABI boundary as a plain integer;
/// `Copy` because it is a single word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct CapsuleSetEpoch(u64);

impl CapsuleSetEpoch {
    /// The raw fingerprint, for crossing an ABI boundary that speaks `u64` (the
    /// host call returns a bare integer; the newtype lives on the Rust side).
    #[must_use]
    pub fn get(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for CapsuleSetEpoch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

/// Order-sensitive hash of pre-sorted `(id, version)` pairs, split out from
/// [`CapsuleRegistry::set_epoch`] so the hashing is unit-testable without a
/// registry. Callers MUST pass a sorted slice; the count is folded in to frame
/// the set, and `str`'s `Hash` is prefix-safe, so distinct sets do not alias.
fn hash_capsule_set(sorted_pairs: &[(&str, &str)]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    sorted_pairs.len().hash(&mut hasher);
    for (id, version) in sorted_pairs {
        id.hash(&mut hasher);
        version.hash(&mut hasher);
    }
    hasher.finish()
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

    struct MockCapsule {
        id: CapsuleId,
        manifest: CapsuleManifest,
    }

    impl MockCapsule {
        fn new(name: &str) -> Self {
            Self::with_version(name, "0.0.1")
        }

        fn with_version(name: &str, version: &str) -> Self {
            Self {
                id: CapsuleId::from_static(name),
                manifest: CapsuleManifest {
                    package: PackageDef {
                        name: name.to_string(),
                        version: version.to_string(),
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
        let capsule_id = CapsuleId::from_static("test-capsule");
        registry.register_uuid(uuid, capsule_id.clone());

        assert_eq!(registry.find_by_uuid(&uuid), Some(&capsule_id));
        assert_eq!(registry.find_by_uuid(&Uuid::new_v4()), None);
    }

    #[test]
    fn uuid_mapping_overwrite_on_duplicate() {
        let mut registry = CapsuleRegistry::new();
        let uuid = Uuid::new_v4();
        let first = CapsuleId::from_static("first");
        let second = CapsuleId::from_static("second");

        registry.register_uuid(uuid, first);
        registry.register_uuid(uuid, second.clone());
        assert_eq!(registry.find_by_uuid(&uuid), Some(&second));
    }

    #[test]
    fn uuid_mapping_cleanup_on_unregister() {
        let mut registry = CapsuleRegistry::new();
        let uuid = Uuid::new_v4();
        let capsule_id = CapsuleId::from_static("removable");

        registry
            .register(Box::new(MockCapsule::new("removable")))
            .expect("register");
        registry.register_uuid(uuid, capsule_id.clone());
        assert!(registry.find_by_uuid(&uuid).is_some());

        registry.unregister(&capsule_id).expect("unregister");
        assert!(registry.find_by_uuid(&uuid).is_none());
    }

    #[test]
    fn uuid_mapping_cleanup_on_drain() {
        let mut registry = CapsuleRegistry::new();
        let uuid = Uuid::new_v4();
        registry.register_uuid(uuid, CapsuleId::from_static("test"));
        assert!(registry.find_by_uuid(&uuid).is_some());

        let _ = registry.drain();
        assert!(registry.find_by_uuid(&uuid).is_none());
    }

    // -----------------------------------------------------------------
    // Capsule-set epoch (backs the prompt-builder tool-cache self-heal)
    // -----------------------------------------------------------------

    #[test]
    fn set_epoch_moves_when_a_capsule_is_installed() {
        // The bug behind #982: a runtime install must produce an observable
        // change so a cached consumer knows to re-describe.
        let mut registry = CapsuleRegistry::new();
        registry
            .register(Box::new(MockCapsule::new("alpha")))
            .expect("register alpha");
        let before = registry.set_epoch();

        registry
            .register(Box::new(MockCapsule::new("beta")))
            .expect("register beta");
        let after = registry.set_epoch();

        assert_ne!(before, after, "installing a capsule must move the epoch");
    }

    #[test]
    fn set_epoch_is_restart_stable_for_an_unchanged_set() {
        // Same set => same epoch, with no process state. This is what lets the
        // persistent per-principal cache survive a daemon restart without a
        // spurious re-fan-out. Adding then removing returns to the prior value.
        let mut registry = CapsuleRegistry::new();
        registry
            .register(Box::new(MockCapsule::new("alpha")))
            .expect("register alpha");
        let one = registry.set_epoch();

        registry
            .register(Box::new(MockCapsule::new("beta")))
            .expect("register beta");
        registry
            .unregister(&CapsuleId::from_static("beta"))
            .expect("unregister beta");
        let back = registry.set_epoch();

        assert_eq!(
            one, back,
            "removing the added capsule must restore the epoch"
        );
    }

    #[test]
    fn set_epoch_ignores_insertion_order() {
        let mut a = CapsuleRegistry::new();
        a.register(Box::new(MockCapsule::new("alpha")))
            .expect("register alpha");
        a.register(Box::new(MockCapsule::new("beta")))
            .expect("register beta");

        let mut b = CapsuleRegistry::new();
        b.register(Box::new(MockCapsule::new("beta")))
            .expect("register beta");
        b.register(Box::new(MockCapsule::new("alpha")))
            .expect("register alpha");

        assert_eq!(
            a.set_epoch(),
            b.set_epoch(),
            "epoch must not depend on load order"
        );
    }

    #[test]
    fn set_epoch_moves_on_version_bump() {
        // A live upgrade keeps the id but changes the version; the tool surface
        // may change with it, so the epoch must move.
        let mut before = CapsuleRegistry::new();
        before
            .register(Box::new(MockCapsule::with_version("alpha", "1.0.0")))
            .expect("register alpha 1.0.0");

        let mut after = CapsuleRegistry::new();
        after
            .register(Box::new(MockCapsule::with_version("alpha", "1.0.1")))
            .expect("register alpha 1.0.1");

        assert_ne!(
            before.set_epoch(),
            after.set_epoch(),
            "a version bump must move the epoch"
        );
    }

    #[test]
    fn set_epoch_empty_registry_is_deterministic() {
        assert_eq!(
            CapsuleRegistry::new().set_epoch(),
            CapsuleRegistry::new().set_epoch(),
            "the empty set must hash deterministically and not panic"
        );
    }
}
