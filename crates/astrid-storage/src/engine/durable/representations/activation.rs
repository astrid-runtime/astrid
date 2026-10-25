//! Construction and publication of the first physical authority generation.

use crate::storage_model::{
    CanonicalPhysicalMap, Coverage, ObjectId, PhysicalMapDomain, PhysicalMapKey, PhysicalMapNode,
    PlacementEntry, PlacementSet, Recipe, ReconstructionBounds, Replica, ReplicaLocator,
    RepresentationCatalogueRoot, RepresentationProfile, RepresentationRecord, RepresentationState,
};
use std::collections::BTreeSet;

use super::format::{Blake3PhysicalIdentity, MetadataFrame};
use super::node_view::MapView;
use super::{DirectArenaObject, DurableError, LOCAL_STORAGE_NODE};

pub(super) trait NodePresence {
    fn has_node(&self, id: &crate::storage_model::PhysicalMapNodeId) -> Result<bool, DurableError>;
}
impl NodePresence for BTreeSet<crate::storage_model::PhysicalMapNodeId> {
    fn has_node(&self, id: &crate::storage_model::PhysicalMapNodeId) -> Result<bool, DurableError> {
        Ok(self.contains(id))
    }
}
impl NodePresence for super::cold::ColdNodes {
    fn has_node(&self, id: &crate::storage_model::PhysicalMapNodeId) -> Result<bool, DurableError> {
        self.contains(id)
    }
}

pub(super) struct InitialState {
    pub(super) metadata: Vec<MetadataFrame>,
    pub(super) active: crate::storage_model::RepresentationStateId,
}

pub(super) fn build_initial_state(
    frozen_specification: ObjectId,
    objects: impl IntoIterator<Item = Result<DirectArenaObject, DurableError>>,
) -> Result<InitialState, DurableError> {
    let identity = Blake3PhysicalIdentity;
    let (profile, direct_profile) = direct_profile(frozen_specification)?;
    let mut metadata = Vec::new();
    let profiles = CanonicalPhysicalMap::build_dense(
        &identity,
        PhysicalMapDomain::Profile,
        vec![(PhysicalMapKey::from(direct_profile), profile.encode()?)],
    )?;
    append_map_nodes(&mut metadata, profiles.nodes())?;
    let mut representation_entries = Vec::new();
    let mut placement_entries = Vec::new();
    for object in objects {
        let object = object?;
        let record = RepresentationRecord::new(
            direct_profile,
            Coverage::exact(object.object, object.canonical_length)?,
            Recipe::DirectCanonical { blob: object.blob },
            object.canonical_length,
            object.canonical_length,
            None,
        )?;
        let record_id = record.identify(&identity)?;
        representation_entries.push((PhysicalMapKey::from(record_id), record.encode()?));

        let replica = Replica::new(
            LOCAL_STORAGE_NODE,
            ReplicaLocator::ArenaFrame {
                arena_generation: 0,
                offset: object.location.offset,
                payload_length: object.location.payload_len,
                frame_checksum: object.location.checksum,
            },
        )?;
        let placement = PlacementEntry::new(
            object.blob,
            direct_profile,
            object.canonical_length,
            vec![replica],
        )?;
        placement_entries.push((PhysicalMapKey::from(object.blob), placement.encode()?));
    }
    let representations = CanonicalPhysicalMap::build_dense(
        &identity,
        PhysicalMapDomain::Representation,
        representation_entries,
    )?;
    append_map_nodes(&mut metadata, representations.nodes())?;
    let placements = CanonicalPhysicalMap::build_dense(
        &identity,
        PhysicalMapDomain::Placement,
        placement_entries,
    )?;
    append_map_nodes(&mut metadata, placements.nodes())?;
    let catalogue = RepresentationCatalogueRoot::new(
        1,
        profiles.root(),
        profiles.entry_count(),
        representations.root(),
        representations.entry_count(),
    )?;
    let placement_set = PlacementSet::new(
        1,
        placements.root(),
        placements.entry_count(),
        placements.entry_count(),
    )?;
    metadata.push(MetadataFrame::catalogue(&identity, catalogue));
    metadata.push(MetadataFrame::placement(&identity, placement_set));
    let state = RepresentationState::new(
        1,
        None,
        catalogue.identify(&identity),
        placement_set.identify(&identity),
    )?;
    let active = state.identify(&identity);
    metadata.push(MetadataFrame::state(&identity, state));
    Ok(InitialState { metadata, active })
}

pub(super) fn direct_profile(
    frozen_specification: ObjectId,
) -> Result<
    (
        RepresentationProfile,
        crate::storage_model::RepresentationProfileId,
    ),
    DurableError,
> {
    let bounds = ReconstructionBounds::new(1, 2, u64::MAX, u64::MAX, 1, u64::MAX, 1)?;
    let profile = RepresentationProfile::new_builtin(
        crate::storage_model::ProfileKind::DirectCanonical,
        bounds,
        frozen_specification,
    )?;
    let id = profile.identify(&Blake3PhysicalIdentity)?;
    Ok((profile, id))
}

pub(super) fn append_map_nodes(
    metadata: &mut Vec<MetadataFrame>,
    nodes: impl IntoIterator<Item = impl MapNodeRef>,
) -> Result<(), DurableError> {
    for node in nodes {
        metadata.push(MetadataFrame::map_node(
            &Blake3PhysicalIdentity,
            node.node(),
        )?);
    }
    Ok(())
}

pub(super) fn append_new_reachable_map_nodes(
    metadata: &mut Vec<MetadataFrame>,
    map: &(impl MapView + ?Sized),
    durable: &impl NodePresence,
    appended: &mut BTreeSet<crate::storage_model::PhysicalMapNodeId>,
    complete: &mut impl CompleteNodes,
) -> Result<usize, DurableError> {
    let Some(root) = map.view_root() else {
        return Ok(0);
    };
    let mut pending = vec![(root, false)];
    let mut visited = BTreeSet::new();
    while let Some((id, expanded)) = pending.pop() {
        if expanded {
            let node = map.view_node(id)?;
            // A persisted parent alone does not establish durable descendants.
            // Cache only closures checked against the append-only persisted set.
            let children_complete = match &node {
                PhysicalMapNode::Branch { zero, one, .. } => {
                    complete.complete(zero)? && complete.complete(one)?
                },
                PhysicalMapNode::Radix { children, .. } => children_complete(complete, children)?,
                PhysicalMapNode::Leaf { .. } | PhysicalMapNode::Page { .. } => true,
            };
            if durable.has_node(&id)? && children_complete {
                complete.remember(id)?;
            }
            if !durable.has_node(&id)? && !appended.contains(&id) {
                metadata.push(MetadataFrame::map_node(&Blake3PhysicalIdentity, &node)?);
                appended.insert(id);
            }
            continue;
        }
        if complete.complete(&id)? || !visited.insert(id) {
            continue;
        }
        let node = map.view_node(id)?;
        pending.push((id, true));
        match &node {
            PhysicalMapNode::Branch { zero, one, .. } => {
                pending.push((*one, false));
                pending.push((*zero, false));
            },
            PhysicalMapNode::Radix { children, .. } => {
                pending.extend(children.iter().rev().map(|child| (*child, false)));
            },
            PhysicalMapNode::Leaf { .. } | PhysicalMapNode::Page { .. } => {},
        }
    }
    Ok(visited.len())
}

/// Positive membership means every immutable descendant is canonical too.
pub(super) trait CompleteNodes {
    fn complete(&self, id: &crate::storage_model::PhysicalMapNodeId) -> Result<bool, DurableError>;
    fn remember(&mut self, id: crate::storage_model::PhysicalMapNodeId)
    -> Result<(), DurableError>;
}

fn children_complete(
    complete: &impl CompleteNodes,
    children: &[crate::storage_model::PhysicalMapNodeId],
) -> Result<bool, DurableError> {
    for child in children {
        if !complete.complete(child)? {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
impl CompleteNodes for BTreeSet<crate::storage_model::PhysicalMapNodeId> {
    fn complete(&self, id: &crate::storage_model::PhysicalMapNodeId) -> Result<bool, DurableError> {
        Ok(self.contains(id))
    }
    fn remember(
        &mut self,
        id: crate::storage_model::PhysicalMapNodeId,
    ) -> Result<(), DurableError> {
        self.insert(id);
        Ok(())
    }
}

pub(super) trait MapNodeRef {
    fn node(&self) -> &PhysicalMapNode;
}

impl MapNodeRef for (&crate::storage_model::PhysicalMapNodeId, &PhysicalMapNode) {
    fn node(&self) -> &PhysicalMapNode {
        self.1
    }
}

impl MapNodeRef for &(crate::storage_model::PhysicalMapNodeId, PhysicalMapNode) {
    fn node(&self) -> &PhysicalMapNode {
        &self.1
    }
}

pub(super) fn generation_name(generation: u64) -> String {
    format!("{generation:016x}")
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use crate::storage_model::{
        CanonicalPhysicalMap, PhysicalMapDomain, PhysicalMapKey, PhysicalMapNode,
    };

    use super::{Blake3PhysicalIdentity, append_new_reachable_map_nodes};

    fn dense_map() -> CanonicalPhysicalMap {
        CanonicalPhysicalMap::build_dense(
            &Blake3PhysicalIdentity,
            PhysicalMapDomain::Representation,
            (0_u32..32)
                .map(|ordinal| {
                    let key = blake3::hash(&ordinal.to_le_bytes());
                    (
                        PhysicalMapKey::new(*key.as_bytes()),
                        ordinal.to_le_bytes().to_vec(),
                    )
                })
                .collect(),
        )
        .unwrap()
    }

    #[test]
    fn verified_durable_subtrees_skip_unchanged_nodes() {
        let mut map = dense_map();
        let durable: BTreeSet<_> = map.nodes().keys().copied().collect();
        let mut complete = BTreeSet::new();
        let mut metadata = Vec::new();
        let mut appended = BTreeSet::new();
        let cold = append_new_reachable_map_nodes(
            &mut metadata,
            &map,
            &durable,
            &mut appended,
            &mut complete,
        )
        .unwrap();
        assert_eq!(cold, map.nodes().len());
        assert!(metadata.is_empty());
        let warm = append_new_reachable_map_nodes(
            &mut metadata,
            &map,
            &durable,
            &mut appended,
            &mut complete,
        )
        .unwrap();
        assert_eq!(warm, 0);

        map.insert(
            &Blake3PhysicalIdentity,
            PhysicalMapKey::new([42; 32]),
            vec![7],
        )
        .unwrap();
        let changed = append_new_reachable_map_nodes(
            &mut metadata,
            &map,
            &durable,
            &mut appended,
            &mut complete,
        )
        .unwrap();
        assert!(changed > 0 && changed < cold);
        let mut cold_metadata = Vec::new();
        let mut cold_appended = BTreeSet::new();
        append_new_reachable_map_nodes(
            &mut cold_metadata,
            &map,
            &durable,
            &mut cold_appended,
            &mut BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(appended, cold_appended);
        assert_eq!(
            metadata
                .iter()
                .map(|frame| frame.encode().unwrap())
                .collect::<Vec<_>>(),
            cold_metadata
                .iter()
                .map(|frame| frame.encode().unwrap())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn durable_parent_does_not_hide_missing_descendants() {
        let map = dense_map();
        let root = map.root().unwrap();
        let mut metadata = Vec::new();
        let mut appended = BTreeSet::new();

        let mut complete = BTreeSet::new();
        append_new_reachable_map_nodes(
            &mut metadata,
            &map,
            &BTreeSet::from([root]),
            &mut appended,
            &mut complete,
        )
        .unwrap();

        assert!(!complete.contains(&root));
        assert!(!appended.contains(&root));
        assert_eq!(appended.len(), map.nodes().len().checked_sub(1).unwrap());
        assert_eq!(metadata.len(), appended.len());
    }

    #[test]
    fn new_map_nodes_are_emitted_children_before_parents() {
        let map = dense_map();
        let root = map.root().unwrap();
        let mut metadata = Vec::new();
        let mut appended = BTreeSet::new();
        append_new_reachable_map_nodes(
            &mut metadata,
            &map,
            &BTreeSet::new(),
            &mut appended,
            &mut BTreeSet::new(),
        )
        .unwrap();

        let positions = metadata
            .iter()
            .enumerate()
            .map(|(position, frame)| (frame.identity, position))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(metadata.last().unwrap().identity, *root.as_bytes());
        for (parent, node) in map.nodes() {
            let Some(parent_position) = positions.get(parent.as_bytes()) else {
                continue;
            };
            let children = match &node {
                PhysicalMapNode::Branch { zero, one, .. } => vec![*zero, *one],
                PhysicalMapNode::Radix { children, .. } => children.clone(),
                PhysicalMapNode::Leaf { .. } | PhysicalMapNode::Page { .. } => Vec::new(),
            };
            assert!(children.iter().all(|child| {
                positions
                    .get(child.as_bytes())
                    .is_some_and(|child_position| child_position < parent_position)
            }));
        }
    }
}
