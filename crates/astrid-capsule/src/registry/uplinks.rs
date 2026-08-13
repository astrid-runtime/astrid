//! Uplink indexes and whole-registry draining.

use std::sync::Arc;

use astrid_core::{UplinkCapabilities, UplinkDescriptor, UplinkId};
use tracing::debug;

use super::CapsuleRegistry;
use crate::capsule::{Capsule, CapsuleId};
use crate::error::{CapsuleError, CapsuleResult};

impl CapsuleRegistry {
    /// Look up an uplink by its ID.
    #[must_use]
    pub fn get_uplink(&self, id: &UplinkId) -> Option<&UplinkDescriptor> {
        self.uplinks.get(id).map(|(_, descriptor)| descriptor)
    }

    /// Register an uplink for a capsule.
    ///
    /// # Errors
    ///
    /// Returns an error if an uplink with the same ID is already registered.
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

    /// Find an uplink that serves the given platform type.
    #[must_use]
    pub fn find_uplink_by_platform(&self, platform: &str) -> Option<&UplinkDescriptor> {
        self.uplinks
            .values()
            .find(|(_, descriptor)| descriptor.platform == platform)
            .map(|(_, descriptor)| descriptor)
    }

    /// Find all uplinks whose capabilities satisfy the given predicate.
    #[must_use]
    pub fn find_uplinks_with_capability(
        &self,
        check: impl Fn(&UplinkCapabilities) -> bool,
    ) -> Vec<&UplinkDescriptor> {
        self.uplinks
            .values()
            .filter(|(_, descriptor)| check(&descriptor.capabilities))
            .map(|(_, descriptor)| descriptor)
            .collect()
    }

    /// List all registered uplink descriptors.
    #[must_use]
    pub fn all_uplink_descriptors(&self) -> Vec<&UplinkDescriptor> {
        self.uplinks
            .values()
            .map(|(_, descriptor)| descriptor)
            .collect()
    }

    /// Remove and return all capsules, clearing every index.
    ///
    /// Used during kernel shutdown to unload everything in one pass.
    pub fn drain(&mut self) -> Vec<Arc<dyn Capsule>> {
        self.uplinks.clear();
        self.uuid_id_map.clear();
        self.uuid_map.clear();
        self.source_uuid_by_runtime.clear();
        self.legacy_uuid_map.clear();
        self.views.clear();
        self.instances
            .drain()
            .map(|(_, entry)| entry.capsule)
            .collect()
    }
}
