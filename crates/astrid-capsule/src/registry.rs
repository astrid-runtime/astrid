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
                    topics: Vec::new(),
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
}
