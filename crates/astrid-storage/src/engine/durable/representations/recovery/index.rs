//! Historical recovery needs authenticated links, not every decoded value body.

use super::{
    BTreeMap, Blake3PhysicalIdentity, DurableError, DurableIo, METADATA_FILE, METADATA_MAGIC,
    MetadataFrame, MetadataKind, RecoveryLimits, map_node_id, read_frame_at,
};
use crate::storage_model::physical::AuthenticatedMapRecovery;
use crate::storage_model::{
    CanonicalPhysicalMap, PhysicalMapDomain, PhysicalMapNode, PhysicalMapNodeId, PhysicalModelError,
};

#[derive(Clone, Copy, Debug)]
pub(super) struct MetadataFrameOffset(u64);

mod graph;
pub(super) use graph::{HistoricalMapClosure, HistoricalMapGraph};

#[derive(Default)]
pub(in crate::engine::durable::representations) struct MetadataIndex {
    pub(super) values: BTreeMap<(MetadataKind, [u8; 32]), Vec<u8>>,
    pub(super) nodes: HistoricalMapGraph,
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

    // This phase includes indexed frame loading and full canonical validation.
    // Its inventory count includes historical nodes, not only the active closure.
    #[tracing::instrument(name = "recover_indexed_active_map", target = "astrid_storage::recovery", level = "debug", skip_all, fields(domain = ?domain, indexed_nodes = self.nodes.len(), active_nodes = tracing::field::Empty))]
    pub(in crate::engine::durable::representations) fn recover_active_map<F: DurableIo>(
        &mut self,
        domain: PhysicalMapDomain,
        root: Option<PhysicalMapNodeId>,
        source: &F,
        limits: RecoveryLimits,
    ) -> Result<CanonicalPhysicalMap, DurableError> {
        let mut recovery = AuthenticatedMapRecovery::new(&Blake3PhysicalIdentity, domain, root);
        let mut pending: Vec<_> = root.into_iter().collect();
        while let Some(id) = pending.pop() {
            if recovery.contains(id) {
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
            if frame.kind != MetadataKind::MapNode || map_node_id(frame.identity) != id {
                return Err(DurableError::InvalidRepresentationState(
                    "metadata identity does not match canonical value",
                ));
            }
            // Copy links into the format's child-id stack so this loop does not
            // keep a borrow of the owned arena across `pending.extend`.
            let mut child_buf = [PhysicalMapNodeId::new([0; 32]); u16::BITS as usize];
            let node = match recovery.authenticate(id, frame.value) {
                Ok(node) => node,
                Err(PhysicalModelError::InvalidMap("map-node identity mismatch")) => {
                    return Err(DurableError::InvalidRepresentationState(
                        "metadata identity does not match canonical value",
                    ));
                },
                Err(error) => return Err(error.into()),
            };
            let child_count = match node {
                PhysicalMapNode::Branch { zero, one, .. } => {
                    child_buf[0] = *zero;
                    child_buf[1] = *one;
                    2
                },
                PhysicalMapNode::Radix { children, .. } => {
                    let count = children.len();
                    child_buf[..count].copy_from_slice(children);
                    count
                },
                PhysicalMapNode::Leaf { .. } | PhysicalMapNode::Page { .. } => 0,
            };
            let children = &child_buf[..child_count];
            if !self.nodes.matches_children(&entry, children) {
                return Err(DurableError::InvalidRepresentationState(
                    "active physical map links changed during recovery",
                ));
            }
            pending.extend(children.iter().copied());
        }
        if tracing::enabled!(target: "astrid_storage::recovery", tracing::Level::DEBUG) {
            tracing::Span::current().record("active_nodes", recovery.len());
        }
        // Fresh frames were authenticated into the owned arena. Finish still
        // rebuilds the canonical root and rejects domain, cycle, sharing, and
        // missing bodies without hashing those owned nodes again.
        Ok(recovery.finish()?)
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
