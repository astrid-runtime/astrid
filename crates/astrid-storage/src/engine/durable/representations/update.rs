//! One bounded authenticated-page workspace for a direct map update.
use super::{
    BTreeSet, Blake3PhysicalIdentity, DirectMapEntry, DurableError, MetadataFrame,
    RepresentationStore, append_new_reachable_map_nodes,
};
use crate::storage_model::PhysicalMapNodeId;

impl RepresentationStore {
    pub(super) fn stage_direct_maps(
        &mut self,
        entries: &[DirectMapEntry],
        metadata: &mut Vec<MetadataFrame>,
        appended: &mut BTreeSet<PhysicalMapNodeId>,
    ) -> Result<(), DurableError> {
        let mut provider = self.persisted_map_nodes.memoized_nodes();
        {
            let mut map = self.representations.with_node_provider(&mut provider);
            map.insert_entries(
                &Blake3PhysicalIdentity,
                entries
                    .iter()
                    .map(|entry| entry.representation.clone())
                    .collect(),
            )?;
            self.representations = map.with_node_provider(self.persisted_map_nodes.clone());
        }
        {
            let mut map = self.placement_entries.with_node_provider(&mut provider);
            map.insert_entries(
                &Blake3PhysicalIdentity,
                entries
                    .iter()
                    .map(|entry| entry.placement.clone())
                    .collect(),
            )?;
            self.placement_entries = map.with_node_provider(self.persisted_map_nodes.clone());
        }
        // Node reads, collision/absence checks and closure proofs share only
        // authenticated locator pages. Bodies remain fresh positional reads;
        // locator run replacement rebinds the operation memo by epoch.
        let (presence, mut complete) = provider.closure_handles();
        append_new_reachable_map_nodes(
            metadata,
            &self.representations.with_node_provider(&provider),
            &presence,
            appended,
            &mut complete,
        )?;
        append_new_reachable_map_nodes(
            metadata,
            &self.placement_entries.with_node_provider(&provider),
            &presence,
            appended,
            &mut complete,
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
