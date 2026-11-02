//! Historical recovery needs authenticated links, not every decoded value body.

use super::{
    BTreeMap, Blake3PhysicalIdentity, DurableError, DurableIo, METADATA_FILE, METADATA_MAGIC,
    MetadataFrame, MetadataKind, RecoveryLimits, map_node_id, read_frame_at,
};
use crate::storage_model::{
    CanonicalPhysicalMap, PhysicalMapDomain, PhysicalMapNode, PhysicalMapNodeId,
};

#[derive(Clone, Copy, Debug)]
struct MetadataFrameOffset(u64);

#[derive(Clone, Debug)]
pub(super) struct RecoveredMapNode {
    offset: MetadataFrameOffset,
    pub(super) children: Box<[PhysicalMapNodeId]>,
}

impl RecoveredMapNode {
    #[cfg(test)]
    pub(super) fn new(offset: u64, node: PhysicalMapNode) -> Self {
        let children: Box<[_]> = match node {
            PhysicalMapNode::Branch { zero, one, .. } => Box::new([zero, one]),
            PhysicalMapNode::Radix { children, .. } => children.into_boxed_slice(),
            PhysicalMapNode::Leaf { .. } | PhysicalMapNode::Page { .. } => Box::default(),
        };
        Self {
            offset: MetadataFrameOffset(offset),
            children,
        }
    }
}

#[derive(Default)]
pub(in crate::engine::durable::representations) struct MetadataIndex {
    pub(super) values: BTreeMap<(MetadataKind, [u8; 32]), Vec<u8>>,
    pub(super) nodes: BTreeMap<PhysicalMapNodeId, RecoveredMapNode>,
}

impl MetadataIndex {
    pub(super) fn insert_at<V: AsRef<[u8]> + Into<Vec<u8>>>(
        &mut self,
        offset: u64,
        frame: MetadataFrame<V>,
        load_previous: impl FnOnce(u64) -> Result<Vec<u8>, DurableError>,
    ) -> Result<(), DurableError> {
        if frame.kind == MetadataKind::MapNode {
            let (children, id) = PhysicalMapNode::decode_child_ids_and_identify(
                frame.value.as_ref(),
                &Blake3PhysicalIdentity,
            )?;
            if id != map_node_id(frame.identity) {
                return Err(DurableError::InvalidRepresentationState(
                    "metadata identity does not match canonical value",
                ));
            }
            if let Some(existing) = self.nodes.get(&id) {
                // Compare actual earlier bytes. Identity equality alone must
                // not turn a collision into a successful duplicate append.
                let payload = load_previous(existing.offset.0)?;
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
                self.nodes.insert(
                    id,
                    RecoveredMapNode {
                        offset: MetadataFrameOffset(offset),
                        children,
                    },
                );
            }
            return Ok(());
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
                .remove(&id)
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
            pending.extend(entry.children.into_vec());
            nodes.insert(id, node);
        }
        super::super::residency::recover_active_map(domain, root, &mut nodes)
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
