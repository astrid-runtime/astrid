//! Construction and publication of the first physical authority generation.

use crate::storage_model::physical::{
    AuthenticatedPhysicalMap, PlacementMap, ProfileMap, RepresentationMap,
};
use crate::storage_model::{
    CanonicalPhysicalMap, Coverage, ObjectId, PhysicalMapKey, PhysicalMapNode, PlacementEntry,
    PlacementSet, Recipe, ReconstructionBounds, Replica, ReplicaLocator,
    RepresentationCatalogueRoot, RepresentationProfile, RepresentationRecord, RepresentationState,
};
use std::collections::BTreeSet;

use super::format::{Blake3PhysicalIdentity, MetadataFrame, MetadataKind};
use super::{DirectArenaObject, DurableError, LOCAL_STORAGE_NODE};

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
    let profiles = ProfileMap::build_dense(vec![(
        PhysicalMapKey::from(direct_profile),
        profile.encode()?,
    )])?;
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
    let representations = RepresentationMap::build_dense(representation_entries)?;
    append_map_nodes(&mut metadata, representations.nodes())?;
    let placements = PlacementMap::build_dense(placement_entries)?;
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

/// Visit tip-reachable map nodes that still need durable publication.
///
/// `emit` runs once per newly appended node identity. Callers push into a Vec or
/// write through a framed append stream; the walk/validation stays authoritative.
pub(super) fn visit_new_reachable_map_nodes(
    map: &CanonicalPhysicalMap,
    durable: &mut BTreeSet<crate::storage_model::PhysicalMapNodeId>,
    appended: &mut BTreeSet<crate::storage_model::PhysicalMapNodeId>,
    complete: &mut BTreeSet<crate::storage_model::PhysicalMapNodeId>,
    mut emit: impl FnMut(
        crate::storage_model::PhysicalMapNodeId,
        &PhysicalMapNode,
    ) -> Result<(), DurableError>,
) -> Result<usize, DurableError> {
    let Some(root) = map.root() else {
        return Ok(0);
    };
    // The map is immutable throughout this walk. Retain the body for the
    // postorder visit rather than looking it up in the arena a second time.
    let mut pending = vec![(root, None::<&PhysicalMapNode>)];
    // Canonical reachable closures are trees. The arena also retains historical
    // nodes, so its size bounds every valid walk and terminates corrupted cycles
    // without allocating a second index of identities already held by the map.
    let mut remaining = map.nodes().len();
    while let Some((id, body)) = pending.pop() {
        if let Some(node) = body {
            // A persisted parent alone does not establish durable descendants.
            // Move checked IDs into the complete-closure partition so the two
            // disposable memos never retain duplicate IDs.
            let children_complete = match node {
                PhysicalMapNode::Branch { zero, one, .. } => {
                    complete.contains(zero) && complete.contains(one)
                },
                PhysicalMapNode::Radix { children, .. } => {
                    children.iter().all(|child| complete.contains(child))
                },
                PhysicalMapNode::Leaf { .. } | PhysicalMapNode::Page { .. } => true,
            };
            let persisted = if children_complete {
                let persisted = durable.remove(&id);
                if persisted {
                    complete.insert(id);
                }
                persisted
            } else {
                durable.contains(&id)
            };
            if !persisted && !appended.contains(&id) {
                emit(id, node)?;
                appended.insert(id);
            }
            continue;
        }
        if complete.contains(&id) {
            continue;
        }
        remaining = remaining
            .checked_sub(1)
            .ok_or(DurableError::InvalidRepresentationState(
                "active physical map traversal exceeds its arena",
            ))?;
        let node = map
            .nodes()
            .get(&id)
            .ok_or(DurableError::InvalidRepresentationState(
                "active physical map is missing a reachable node",
            ))?;
        pending.push((id, Some(node)));
        match node {
            PhysicalMapNode::Branch { zero, one, .. } => {
                pending.push((*one, None));
                pending.push((*zero, None));
            },
            PhysicalMapNode::Radix { children, .. } => {
                pending.extend(children.iter().rev().map(|child| (*child, None)));
            },
            PhysicalMapNode::Leaf { .. } | PhysicalMapNode::Page { .. } => {},
        }
    }
    Ok(map.nodes().len().strict_sub(remaining))
}

pub(super) fn append_authenticated_map_nodes(
    metadata: &mut Vec<MetadataFrame>,
    map: &(impl AuthenticatedPhysicalMap + ?Sized),
    durable: &mut BTreeSet<crate::storage_model::PhysicalMapNodeId>,
    appended: &mut BTreeSet<crate::storage_model::PhysicalMapNodeId>,
    complete: &mut BTreeSet<crate::storage_model::PhysicalMapNodeId>,
) -> Result<usize, DurableError> {
    visit_new_reachable_map_nodes(
        map.as_canonical(),
        durable,
        appended,
        complete,
        |id, node| {
            // The sealed input fixes the identity policy. This same walk supplied
            // the ID and immutable body together; neither needs another lookup.
            metadata.push(MetadataFrame {
                kind: MetadataKind::MapNode,
                identity: *id.as_bytes(),
                value: node.encode()?,
            });
            Ok(())
        },
    )
}

// Hash-agile fixtures retain the generic, independently hashing encoder.
#[cfg(test)]
pub(super) fn append_new_reachable_map_nodes(
    metadata: &mut Vec<MetadataFrame>,
    map: &CanonicalPhysicalMap,
    durable: &mut BTreeSet<crate::storage_model::PhysicalMapNodeId>,
    appended: &mut BTreeSet<crate::storage_model::PhysicalMapNodeId>,
    complete: &mut BTreeSet<crate::storage_model::PhysicalMapNodeId>,
) -> Result<usize, DurableError> {
    visit_new_reachable_map_nodes(map, durable, appended, complete, |_, node| {
        metadata.push(MetadataFrame::map_node(&Blake3PhysicalIdentity, node)?);
        Ok(())
    })
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

    use super::{
        Blake3PhysicalIdentity, append_new_reachable_map_nodes, visit_new_reachable_map_nodes,
    };

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
    fn publication_rejects_a_cached_cycle_before_emitting_nodes() {
        let mut map = crate::storage_model::physical::RepresentationMap::build_dense(vec![(
            PhysicalMapKey::new([1; 32]),
            vec![1],
        )])
        .unwrap();
        let root = map.root().unwrap();
        assert!(map.replace_arena_node_for_fault(
            root,
            PhysicalMapNode::Branch {
                domain: PhysicalMapDomain::Representation,
                prefix_bits: 0,
                prefix: vec![],
                zero: root,
                one: root,
                subtree_entries: 1,
            },
        ));
        let mut emitted = 0;
        let result = visit_new_reachable_map_nodes(
            map.as_canonical(),
            &mut BTreeSet::new(),
            &mut BTreeSet::new(),
            &mut BTreeSet::new(),
            |_, _| {
                emitted += 1;
                Ok(())
            },
        );
        assert!(result.is_err(), "a cached cycle cannot be published");
        assert_eq!(emitted, 0);
    }

    #[test]
    fn verified_durable_subtrees_skip_unchanged_nodes() {
        let mut map = dense_map();
        let mut durable: BTreeSet<_> = map.nodes().keys().copied().collect();
        let mut reference_durable = durable.clone();
        let mut complete = BTreeSet::new();
        let mut metadata = Vec::new();
        let mut appended = BTreeSet::new();
        let cold = append_new_reachable_map_nodes(
            &mut metadata,
            &map,
            &mut durable,
            &mut appended,
            &mut complete,
        )
        .unwrap();
        assert_eq!(cold, map.nodes().len());
        assert!(metadata.is_empty());
        let warm = append_new_reachable_map_nodes(
            &mut metadata,
            &map,
            &mut durable,
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
            &mut durable,
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
            &mut reference_durable,
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
            &mut BTreeSet::from([root]),
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
            &mut BTreeSet::new(),
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
            let children = match node {
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
