//! Construction and publication of the first physical authority generation.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::path::Path;

use astrid_storage_model::{
    CanonicalPhysicalMap, Coverage, ObjectId, PhysicalMapDomain, PhysicalMapKey, PhysicalMapNode,
    PlacementEntry, PlacementSet, Recipe, ReconstructionBounds, Replica, ReplicaLocator,
    RepresentationCatalogueRoot, RepresentationProfile, RepresentationRecord, RepresentationState,
};

use super::format::{Blake3PhysicalIdentity, CURRENT_MAGIC, CurrentPointer, MetadataFrame};
use super::{
    CURRENT_PATH, CURRENT_TEMP_PATH, DIRECTORY, DirectArenaObject, DurableError,
    LOCAL_STORAGE_NODE, RecoveryLimits, append_frame, io_error, read_current, sync_store_directory,
};

pub(super) struct InitialState {
    pub(super) metadata: Vec<MetadataFrame>,
    pub(super) active: astrid_storage_model::RepresentationStateId,
}

pub(super) fn build_initial_state(
    frozen_specification: ObjectId,
    objects: impl IntoIterator<Item = Result<DirectArenaObject, DurableError>>,
) -> Result<InitialState, DurableError> {
    let identity = Blake3PhysicalIdentity;
    let (profile, direct_profile) = direct_profile(frozen_specification)?;
    let mut metadata = Vec::new();
    let profiles = CanonicalPhysicalMap::build(
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
    let representations = CanonicalPhysicalMap::build(
        &identity,
        PhysicalMapDomain::Representation,
        representation_entries,
    )?;
    append_map_nodes(&mut metadata, representations.nodes())?;
    let placements =
        CanonicalPhysicalMap::build(&identity, PhysicalMapDomain::Placement, placement_entries)?;
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
        astrid_storage_model::RepresentationProfileId,
    ),
    DurableError,
> {
    let bounds = ReconstructionBounds::new(1, 2, u64::MAX, u64::MAX, 1, u64::MAX, 1)?;
    let profile = RepresentationProfile::new_builtin(
        astrid_storage_model::ProfileKind::DirectCanonical,
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
    map: &CanonicalPhysicalMap,
    durable: &BTreeSet<astrid_storage_model::PhysicalMapNodeId>,
) -> Result<(), DurableError> {
    let Some(root) = map.root() else {
        return Ok(());
    };
    let mut pending = vec![root];
    let mut visited = BTreeSet::new();
    while let Some(id) = pending.pop() {
        if !visited.insert(id) || durable.contains(&id) {
            continue;
        }
        let node = map
            .nodes()
            .get(&id)
            .ok_or(DurableError::InvalidRepresentationState(
                "active physical map is missing a reachable node",
            ))?;
        metadata.push(MetadataFrame::map_node(&Blake3PhysicalIdentity, node)?);
        if let PhysicalMapNode::Branch { zero, one, .. } = node {
            pending.push(*one);
            pending.push(*zero);
        }
    }
    Ok(())
}

pub(super) trait MapNodeRef {
    fn node(&self) -> &PhysicalMapNode;
}

impl MapNodeRef for (&astrid_storage_model::PhysicalMapNodeId, &PhysicalMapNode) {
    fn node(&self) -> &PhysicalMapNode {
        self.1
    }
}

impl MapNodeRef for &(astrid_storage_model::PhysicalMapNodeId, PhysicalMapNode) {
    fn node(&self) -> &PhysicalMapNode {
        &self.1
    }
}

pub(super) fn publish_current(root: &Path, current: CurrentPointer) -> Result<(), DurableError> {
    let temporary = root.join(CURRENT_TEMP_PATH);
    let mut file = create_new(&temporary)?;
    append_frame(&mut file, CURRENT_MAGIC, &current.encode())?;
    file.sync_data()
        .map_err(|source| io_error("flush representation current pointer", source))?;
    drop(file);
    let recovered = read_current(&temporary, RecoveryLimits::process_addressable())?;
    if recovered != current {
        return Err(DurableError::InvalidRepresentationState(
            "representation current pointer failed verification",
        ));
    }
    fs::rename(&temporary, root.join(CURRENT_PATH))
        .map_err(|source| io_error("publish representation current pointer", source))?;
    sync_store_directory(root)
}

pub(super) fn create_new(path: &Path) -> Result<File, DurableError> {
    let mut options = OpenOptions::new();
    options.create_new(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|source| io_error("create representation file", source))
}

pub(super) fn quarantine_incomplete_root(store: &Path, root: &Path) -> Result<(), DurableError> {
    if !root.exists() {
        return Ok(());
    }
    for ordinal in 0_u32..=u32::MAX {
        let quarantine = store.join(format!("{DIRECTORY}.incomplete.{ordinal:08x}"));
        if quarantine.exists() {
            continue;
        }
        fs::rename(root, quarantine).map_err(|source| {
            io_error("quarantine incomplete representation activation", source)
        })?;
        sync_store_directory(store)?;
        return Ok(());
    }
    Err(DurableError::InvalidRepresentationState(
        "representation quarantine namespace is exhausted",
    ))
}

pub(super) fn quarantine_temporary_current(root: &Path) -> Result<(), DurableError> {
    let temporary = root.join(CURRENT_TEMP_PATH);
    if !temporary.exists() {
        return Ok(());
    }
    for ordinal in 0_u32..=u32::MAX {
        let quarantine = root.join(format!("{CURRENT_TEMP_PATH}.incomplete.{ordinal:08x}"));
        if quarantine.exists() {
            continue;
        }
        fs::rename(&temporary, quarantine)
            .map_err(|source| io_error("quarantine stale representation pointer", source))?;
        sync_store_directory(root)?;
        return Ok(());
    }
    Err(DurableError::InvalidRepresentationState(
        "representation pointer quarantine namespace is exhausted",
    ))
}

pub(super) fn generation_name(generation: u64) -> String {
    format!("{generation:016x}")
}
