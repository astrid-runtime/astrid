//! Historical recovery needs authenticated links, not every decoded value body.

use super::{
    BTreeMap, Blake3PhysicalIdentity, DurableError, DurableIo, METADATA_FILE, METADATA_MAGIC,
    MetadataFrame, MetadataKind, RecoveryLimits, map_node_id, read_frame_at,
};
use crate::storage_model::{
    CanonicalPhysicalMap, PhysicalMapDomain, PhysicalMapNode, PhysicalMapNodeId,
};

#[derive(Clone, Copy, Debug)]
pub(super) struct MetadataFrameOffset(u64);

mod graph;
pub(super) use graph::{HistoricalMapClosure, HistoricalMapGraph};

#[derive(Default)]
pub(in crate::engine::durable::representations) struct MetadataIndex {
    pub(super) values: BTreeMap<(MetadataKind, [u8; 32]), Vec<u8>>,
    pub(super) nodes: HistoricalMapGraph,
    /// `MapNode` frames observed in this generation, including identical duplicates.
    pub(in crate::engine::durable::representations) map_frame_count: u64,
}

impl MetadataIndex {
    pub(super) fn insert_at<V: AsRef<[u8]> + Into<Vec<u8>>>(
        &mut self,
        offset: u64,
        frame: MetadataFrame<V>,
        load_previous: impl FnOnce(u64) -> Result<Vec<u8>, DurableError>,
    ) -> Result<(), DurableError> {
        if frame.kind == MetadataKind::MapNode {
            return PhysicalMapNode::with_child_ids_and_identify(
                frame.value.as_ref(),
                &Blake3PhysicalIdentity,
                |id, children| {
                    if id != map_node_id(frame.identity) {
                        return Err(DurableError::InvalidRepresentationState(
                            "metadata identity does not match canonical value",
                        ));
                    }
                    if let Some(existing) = self.nodes.offset(&id) {
                        // Compare actual earlier bytes. Identity equality alone must
                        // not turn a collision into a successful duplicate append.
                        let payload = load_previous(existing.0)?;
                        let previous = MetadataFrame::decode(&payload)?;
                        if previous.kind != frame.kind
                            || previous.identity != frame.identity
                            || previous.value != frame.value.as_ref()
                        {
                            return Err(DurableError::InvalidRepresentationState(
                                "physical metadata identity collision",
                            ));
                        }
                    } else {
                        self.nodes
                            .insert(id, MetadataFrameOffset(offset), children)?;
                    }
                    // Count every durable MapNode frame, including identical re-appends.
                    self.map_frame_count = self
                        .map_frame_count
                        .checked_add(1)
                        .ok_or(DurableError::EncodingOverflow)?;
                    Ok(())
                },
            )?;
        }

        frame.verify(&Blake3PhysicalIdentity)?;
        let key = (frame.kind, frame.identity);
        if let Some(existing) = self.values.get(&key) {
            if existing.as_slice() != frame.value.as_ref() {
                return Err(DurableError::InvalidRepresentationState(
                    "physical metadata identity collision",
                ));
            }
        } else {
            self.values.insert(key, frame.value.into());
        }
        Ok(())
    }

    pub(in crate::engine::durable::representations) fn value(
        &self,
        kind: MetadataKind,
        identity: &[u8; 32],
    ) -> Result<&[u8], DurableError> {
        self.values
            .get(&(kind, *identity))
            .map(Vec::as_slice)
            .ok_or(DurableError::InvalidRepresentationState(
                "physical metadata closure is incomplete",
            ))
    }

    #[tracing::instrument(target = "astrid_storage::recovery", level = "debug", skip_all, fields(domain = ?domain, input_nodes = self.nodes.len(), active_nodes = tracing::field::Empty))]
    pub(in crate::engine::durable::representations) fn recover_active_map<F: DurableIo>(
        &mut self,
        domain: PhysicalMapDomain,
        root: Option<PhysicalMapNodeId>,
        source: &F,
        limits: RecoveryLimits,
    ) -> Result<CanonicalPhysicalMap, DurableError> {
        let mut nodes = BTreeMap::new();
        let mut pending: Vec<_> = root.into_iter().collect();
        while let Some(id) = pending.pop() {
            if nodes.contains_key(&id) {
                continue;
            }
            let entry = self
                .nodes
                .take(&id)
                .ok_or(DurableError::InvalidRepresentationState(
                    "active physical map closure is incomplete",
                ))?;
            let payload = read_frame_at(
                source,
                METADATA_FILE,
                METADATA_MAGIC,
                entry.offset.0,
                limits,
            )?;
            let frame = MetadataFrame::decode(&payload)?;
            let (node, computed) =
                PhysicalMapNode::decode_and_identify(frame.value, &Blake3PhysicalIdentity)?;
            if frame.kind != MetadataKind::MapNode
                || map_node_id(frame.identity) != id
                || computed != id
            {
                return Err(DurableError::InvalidRepresentationState(
                    "metadata identity does not match canonical value",
                ));
            }
            let branch_children;
            let children = match &node {
                PhysicalMapNode::Branch { zero, one, .. } => {
                    branch_children = [*zero, *one];
                    branch_children.as_slice()
                },
                PhysicalMapNode::Radix { children, .. } => children.as_slice(),
                PhysicalMapNode::Leaf { .. } | PhysicalMapNode::Page { .. } => &[],
            };
            if !self.nodes.matches_children(&entry, children) {
                return Err(DurableError::InvalidRepresentationState(
                    "active physical map links changed during recovery",
                ));
            }
            pending.extend(children.iter().copied());
            nodes.insert(id, node);
        }
        if tracing::enabled!(target: "astrid_storage::recovery", tracing::Level::DEBUG) {
            tracing::Span::current().record("active_nodes", nodes.len());
        }
        // The indexed traversal already extracted exactly this active closure.
        // Transfer its ownership directly; canonical recovery still validates
        // identities, domains and shape, including cycles and shared children.
        Ok(CanonicalPhysicalMap::recover(
            &Blake3PhysicalIdentity,
            domain,
            root,
            nodes,
        )?)
    }

    #[cfg(test)]
    pub(super) fn insert<V: AsRef<[u8]> + Into<Vec<u8>>>(
        &mut self,
        frame: MetadataFrame<V>,
    ) -> Result<(), DurableError> {
        // Synthetic journal fixtures contain unique identities and never read
        // bodies back. Real duplicate and reconstruction tests use framed IO.
        self.insert_at(0, frame, |_| {
            Err(DurableError::InvalidRepresentationState(
                "synthetic metadata fixture cannot reread duplicate frames",
            ))
        })
    }
}
