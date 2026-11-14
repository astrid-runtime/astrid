//! Historical recovery needs authenticated links, not every decoded value body.

use super::{
    BTreeMap, Blake3PhysicalIdentity, DurableError, DurableIo, METADATA_FILE, METADATA_MAGIC,
    MetadataFrame, MetadataKind, RecoveryLimits, map_node_id,
};
use crate::engine::durable::format::FrameLocation;
use crate::storage_model::{PhysicalMapDomain, PhysicalMapNode, PhysicalMapNodeId};

mod graph;
pub(super) use graph::{HistoricalMapClosure, HistoricalMapGraph};

#[derive(Default)]
pub(in crate::engine::durable::representations) struct MetadataIndex {
    pub(super) values: BTreeMap<(MetadataKind, [u8; 32]), Vec<u8>>,
    pub(super) nodes: HistoricalMapGraph,
    /// `MapNode` frames observed in this generation, including identical duplicates.
    pub(in crate::engine::durable::representations) map_frame_count: u64,
}

#[cfg(test)]
thread_local! {
    static RECOVER_ACTIVE_NODES_CALLS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(in crate::engine::durable::representations) fn reset_recover_active_nodes_calls() {
    RECOVER_ACTIVE_NODES_CALLS.with(|calls| calls.set(0));
}

#[cfg(test)]
pub(in crate::engine::durable::representations) fn recover_active_nodes_calls() -> u64 {
    RECOVER_ACTIVE_NODES_CALLS.with(std::cell::Cell::get)
}

impl MetadataIndex {
    pub(super) fn insert_at<V: AsRef<[u8]> + Into<Vec<u8>>>(
        &mut self,
        location: FrameLocation,
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
                    if let Some(existing) = self.nodes.location(&id) {
                        // Compare actual earlier bytes. Identity equality alone must
                        // not turn a collision into a successful duplicate append.
                        let payload = load_previous(existing.offset())?;
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
                        self.nodes.insert(id, location, children)?;
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

    /// Extract the exact active closure as untrusted node bytes.
    ///
    /// Domain authentication happens at the typed `recover_exact` boundary so
    /// this helper stays a lean traversal over already-indexed links.
    #[tracing::instrument(target = "astrid_storage::recovery", level = "debug", skip_all, fields(domain = ?domain, input_nodes = self.nodes.len(), active_nodes = tracing::field::Empty))]
    pub(in crate::engine::durable::representations) fn recover_active_nodes<F: DurableIo>(
        &mut self,
        domain: PhysicalMapDomain,
        root: Option<PhysicalMapNodeId>,
        source: &F,
        limits: RecoveryLimits,
    ) -> Result<BTreeMap<PhysicalMapNodeId, PhysicalMapNode>, DurableError> {
        #[cfg(test)]
        {
            RECOVER_ACTIVE_NODES_CALLS.with(|calls| calls.set(calls.get().saturating_add(1)));
        }
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
            let payload = entry
                .location
                .read(source, METADATA_FILE, METADATA_MAGIC, limits)?;
            let frame = MetadataFrame::decode(payload.payload())?;
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
        Ok(nodes)
    }

    #[cfg(test)]
    pub(super) fn insert<V: AsRef<[u8]> + Into<Vec<u8>>>(
        &mut self,
        frame: MetadataFrame<V>,
    ) -> Result<(), DurableError> {
        // Synthetic journal fixtures contain unique identities and never read
        // bodies back. Real duplicate and reconstruction tests use framed IO.
        let payload_bytes =
            u64::try_from(frame.encode()?.len()).map_err(|_| DurableError::EncodingOverflow)?;
        self.insert_at(FrameLocation::for_test(0, payload_bytes), frame, |_| {
            Err(DurableError::InvalidRepresentationState(
                "synthetic metadata fixture cannot reread duplicate frames",
            ))
        })
    }
}
