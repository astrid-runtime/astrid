//! Recovery and closed-world validation for physical representation authority.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use astrid_storage_model::{
    CanonicalPhysicalMap, Coverage, ObjectId, PhysicalMapKey, PhysicalMapNode, PlacementEntry,
    PlacementSet, Recipe, RepresentationCatalogueRoot, RepresentationProfile,
    RepresentationProfileId, RepresentationRecord, RepresentationRecordId, RepresentationState,
    RepresentationStateId,
};

use super::super::{FRAME_HEADER_LEN, scan_frames};
use super::format::{
    Blake3PhysicalIdentity, CURRENT_FILE, CURRENT_MAGIC, CurrentPointer, JOURNAL_FILE,
    JOURNAL_MAGIC, JournalEntry, METADATA_FILE, METADATA_MAGIC, MetadataFrame, MetadataKind,
    journal_digest, map_node_id,
};
use super::{
    DurableError, FIRST_JOURNAL_GENERATION, RecoveryLimits, increment, io_error, read_all,
};

#[derive(Default)]
pub(super) struct MetadataIndex {
    values: BTreeMap<(MetadataKind, [u8; 32]), Vec<u8>>,
    pub(super) nodes: BTreeMap<astrid_storage_model::PhysicalMapNodeId, PhysicalMapNode>,
}

impl MetadataIndex {
    fn insert(&mut self, frame: MetadataFrame) -> Result<(), DurableError> {
        frame.verify(&Blake3PhysicalIdentity)?;
        let key = (frame.kind, frame.identity);
        if let Some(existing) = self.values.get(&key) {
            if existing != &frame.value {
                return Err(DurableError::InvalidRepresentationState(
                    "physical metadata identity collision",
                ));
            }
            return Ok(());
        }
        if frame.kind == MetadataKind::MapNode {
            self.nodes.insert(
                map_node_id(frame.identity),
                PhysicalMapNode::decode(&frame.value)?,
            );
        }
        self.values.insert(key, frame.value);
        Ok(())
    }

    pub(super) fn value(
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
}

pub(super) fn recover_metadata(
    file: &mut File,
    limits: RecoveryLimits,
) -> Result<MetadataIndex, DurableError> {
    let mut index = MetadataIndex::default();
    scan_frames(
        file,
        METADATA_FILE,
        METADATA_MAGIC,
        limits,
        |_offset, payload| index.insert(MetadataFrame::decode(payload)?),
    )?;
    Ok(index)
}

pub(super) fn recover_journal(
    file: &mut File,
    current: CurrentPointer,
    metadata: &MetadataIndex,
    limits: RecoveryLimits,
) -> Result<(RepresentationStateId, RepresentationState), DurableError> {
    let mut entries = Vec::new();
    scan_frames(
        file,
        JOURNAL_FILE,
        JOURNAL_MAGIC,
        limits,
        |offset, payload| {
            entries.push((offset, JournalEntry::decode(payload)?));
            Ok(())
        },
    )?;
    let checkpoint_end = first_frame_end(file)?;
    let bytes = read_all(file, "read representation journal")?;
    let checkpoint_bytes =
        bytes
            .get(..checkpoint_end)
            .ok_or(DurableError::InvalidRepresentationState(
                "representation checkpoint frame is truncated",
            ))?;
    if journal_digest(checkpoint_bytes) != current.checkpoint_digest {
        return Err(DurableError::InvalidRepresentationState(
            "representation checkpoint digest mismatch",
        ));
    }
    let first = entries.first().map(|(_, entry)| *entry).ok_or(
        DurableError::InvalidRepresentationState("representation journal is empty"),
    )?;
    let (mut active, mut generation) = match first {
        JournalEntry::Checkpoint {
            journal_generation,
            active,
            state_generation,
            prior_journal_digest,
        } if journal_generation == current.journal_generation
            && journal_generation == FIRST_JOURNAL_GENERATION
            && active.is_none()
            && state_generation == 0
            && prior_journal_digest.is_none() =>
        {
            (active, state_generation)
        },
        _ => {
            return Err(DurableError::InvalidRepresentationState(
                "representation journal begins with an invalid checkpoint",
            ));
        },
    };
    validate_tail_budget(entries.len(), bytes.len(), checkpoint_end, current)?;
    let mut previous_state = None;
    let entry_count = entries.len();
    for (position, (offset, entry)) in entries.into_iter().enumerate().skip(1) {
        let JournalEntry::StateCas {
            journal_generation,
            expected,
            replacement,
        } = entry
        else {
            return Err(DurableError::InvalidRepresentationState(
                "representation checkpoint appears after journal start",
            ));
        };
        if journal_generation != current.journal_generation || expected != active {
            return Err(DurableError::InvalidRepresentationState(
                "representation journal CAS conflict",
            ));
        }
        if !state_metadata_closure_complete(replacement, metadata)? {
            if position.checked_add(1) != Some(entry_count) {
                return Err(DurableError::InvalidRepresentationState(
                    "interior representation journal state has an incomplete metadata closure",
                ));
            }
            truncate_repairable_journal_tail(file, offset)?;
            break;
        }
        let state = RepresentationState::decode(
            metadata.value(MetadataKind::State, replacement.as_bytes())?,
        )?;
        let next_generation = generation
            .checked_add(1)
            .ok_or(DurableError::EncodingOverflow)?;
        if state.previous() != active || state.generation() != next_generation {
            return Err(DurableError::InvalidRepresentationState(
                "representation state does not match journal transition",
            ));
        }
        validate_authority_transition(previous_state, state, metadata)?;
        active = Some(replacement);
        generation = next_generation;
        previous_state = Some(state);
    }
    let active = active.ok_or(DurableError::InvalidRepresentationState(
        "representation journal has no active state",
    ))?;
    let state =
        RepresentationState::decode(metadata.value(MetadataKind::State, active.as_bytes())?)?;
    Ok((active, state))
}

fn state_metadata_closure_complete(
    state_id: RepresentationStateId,
    metadata: &MetadataIndex,
) -> Result<bool, DurableError> {
    let Some(state_bytes) = metadata
        .values
        .get(&(MetadataKind::State, *state_id.as_bytes()))
    else {
        return Ok(false);
    };
    let state = RepresentationState::decode(state_bytes)?;
    let Some(catalogue_bytes) = metadata
        .values
        .get(&(MetadataKind::Catalogue, *state.catalogue().as_bytes()))
    else {
        return Ok(false);
    };
    let catalogue = RepresentationCatalogueRoot::decode(catalogue_bytes)?;
    let Some(placement_bytes) = metadata
        .values
        .get(&(MetadataKind::Placement, *state.placements().as_bytes()))
    else {
        return Ok(false);
    };
    let placements = PlacementSet::decode(placement_bytes)?;
    for root in [
        catalogue.profiles_root(),
        catalogue.representations_root(),
        placements.entries_root(),
    ] {
        if !map_closure_complete(root, &metadata.nodes) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn map_closure_complete(
    root: Option<astrid_storage_model::PhysicalMapNodeId>,
    nodes: &BTreeMap<astrid_storage_model::PhysicalMapNodeId, PhysicalMapNode>,
) -> bool {
    let Some(root) = root else {
        return true;
    };
    let mut pending = vec![root];
    let mut visited = BTreeSet::new();
    while let Some(id) = pending.pop() {
        if !visited.insert(id) {
            continue;
        }
        let Some(node) = nodes.get(&id) else {
            return false;
        };
        match node {
            PhysicalMapNode::Branch { zero, one, .. } => pending.extend([*zero, *one]),
            PhysicalMapNode::Radix { children, .. } => {
                pending.extend(children.iter().copied());
            },
            PhysicalMapNode::Leaf { .. } | PhysicalMapNode::Page { .. } => {},
        }
    }
    true
}

fn truncate_repairable_journal_tail(file: &mut File, offset: u64) -> Result<(), DurableError> {
    file.set_len(offset)
        .map_err(|source| io_error("truncate uncommitted representation state", source))?;
    file.sync_data()
        .map_err(|source| io_error("flush repaired representation journal", source))?;
    file.seek(SeekFrom::End(0))
        .map_err(|source| io_error("seek repaired representation journal", source))?;
    Ok(())
}

fn validate_tail_budget(
    entry_count: usize,
    journal_bytes: usize,
    checkpoint_end: usize,
    current: CurrentPointer,
) -> Result<(), DurableError> {
    let tail_frames = entry_count.saturating_sub(1);
    if tail_frames > usize::try_from(current.max_tail_frames).unwrap_or(usize::MAX) {
        return Err(DurableError::InvalidRepresentationState(
            "representation journal exceeds its tail-frame budget",
        ));
    }
    let checkpoint_bytes =
        u64::try_from(checkpoint_end).map_err(|_| DurableError::EncodingOverflow)?;
    let tail_bytes = u64::try_from(journal_bytes)
        .map_err(|_| DurableError::EncodingOverflow)?
        .checked_sub(checkpoint_bytes)
        .ok_or(DurableError::EncodingOverflow)?;
    if tail_bytes > current.max_tail_bytes {
        return Err(DurableError::InvalidRepresentationState(
            "representation journal exceeds its tail-byte budget",
        ));
    }
    Ok(())
}

fn validate_authority_transition(
    previous: Option<RepresentationState>,
    current: RepresentationState,
    metadata: &MetadataIndex,
) -> Result<(), DurableError> {
    let catalogue = RepresentationCatalogueRoot::decode(
        metadata.value(MetadataKind::Catalogue, current.catalogue().as_bytes())?,
    )?;
    let placements = PlacementSet::decode(
        metadata.value(MetadataKind::Placement, current.placements().as_bytes())?,
    )?;
    let Some(previous) = previous else {
        if catalogue.generation() != 1 || placements.epoch() != 1 {
            return Err(DurableError::InvalidRepresentationState(
                "initial physical roots do not start at generation one",
            ));
        }
        return Ok(());
    };
    let previous_catalogue = RepresentationCatalogueRoot::decode(
        metadata.value(MetadataKind::Catalogue, previous.catalogue().as_bytes())?,
    )?;
    let previous_placements = PlacementSet::decode(
        metadata.value(MetadataKind::Placement, previous.placements().as_bytes())?,
    )?;
    validate_root_generation(
        previous.catalogue() == current.catalogue(),
        previous_catalogue.generation(),
        catalogue.generation(),
    )?;
    validate_root_generation(
        previous.placements() == current.placements(),
        previous_placements.epoch(),
        placements.epoch(),
    )
}

fn validate_root_generation(reused: bool, previous: u64, current: u64) -> Result<(), DurableError> {
    let expected = if reused {
        previous
    } else {
        increment(previous)?
    };
    if current == expected {
        Ok(())
    } else {
        Err(DurableError::InvalidRepresentationState(
            "physical root generation does not match its identity change",
        ))
    }
}

pub(super) fn validate_profiles(
    map: &CanonicalPhysicalMap,
) -> Result<RepresentationProfileId, DurableError> {
    let mut direct = None;
    for (key, value) in active_entries(map)? {
        let profile = RepresentationProfile::decode(value)?;
        let id = profile.identify(&Blake3PhysicalIdentity)?;
        if PhysicalMapKey::from(id) != key {
            return Err(DurableError::InvalidRepresentationState(
                "profile leaf key does not match its value",
            ));
        }
        if profile.kind() == astrid_storage_model::ProfileKind::DirectCanonical
            && direct.replace(id).is_some()
        {
            return Err(DurableError::InvalidRepresentationState(
                "catalogue has more than one direct profile",
            ));
        }
    }
    direct.ok_or(DurableError::InvalidRepresentationState(
        "catalogue has no direct profile",
    ))
}

pub(super) fn validate_representations(
    profiles: &CanonicalPhysicalMap,
    representations: &CanonicalPhysicalMap,
    placements: &CanonicalPhysicalMap,
) -> Result<(BTreeMap<ObjectId, Vec<RepresentationRecordId>>, u64), DurableError> {
    let mut placement_by_blob = BTreeMap::new();
    let mut extent_count = 0_u64;
    for (key, bytes) in active_entries(placements)? {
        let entry = PlacementEntry::decode(bytes)?;
        if PhysicalMapKey::from(entry.blob()) != key {
            return Err(DurableError::InvalidRepresentationState(
                "placement leaf key does not match its value",
            ));
        }
        if profiles
            .get(PhysicalMapKey::from(entry.profile()))
            .is_none()
        {
            return Err(DurableError::InvalidRepresentationState(
                "placement profile is missing",
            ));
        }
        extent_count = extent_count
            .checked_add(
                u64::try_from(entry.replicas().len())
                    .map_err(|_| DurableError::EncodingOverflow)?,
            )
            .ok_or(DurableError::EncodingOverflow)?;
        placement_by_blob.insert(entry.blob(), entry);
    }
    let mut reverse = BTreeMap::<ObjectId, Vec<RepresentationRecordId>>::new();
    for (key, bytes) in active_entries(representations)? {
        let record = RepresentationRecord::decode(bytes)?;
        let id = record.identify(&Blake3PhysicalIdentity)?;
        if PhysicalMapKey::from(id) != key {
            return Err(DurableError::InvalidRepresentationState(
                "representation leaf key does not match its value",
            ));
        }
        let profile_bytes = profiles.get(PhysicalMapKey::from(record.profile())).ok_or(
            DurableError::InvalidRepresentationState("representation profile is missing"),
        )?;
        let profile = RepresentationProfile::decode(profile_bytes)?;
        record.validate_against_profile(&Blake3PhysicalIdentity, &profile)?;
        let (object, blob, canonical_length) = match (record.coverage(), record.recipe()) {
            (
                Coverage::Exact {
                    object,
                    canonical_record_bytes,
                },
                Recipe::DirectCanonical { blob },
            ) => (*object, *blob, *canonical_record_bytes),
            _ => continue,
        };
        let placement =
            placement_by_blob
                .get(&blob)
                .ok_or(DurableError::InvalidRepresentationState(
                    "direct representation placement is missing",
                ))?;
        if placement.profile() != record.profile() || placement.encoded_length() != canonical_length
        {
            return Err(DurableError::InvalidRepresentationState(
                "direct representation placement does not match its record",
            ));
        }
        reverse.entry(object).or_default().push(id);
    }
    Ok((reverse, extent_count))
}

fn active_entries(
    map: &CanonicalPhysicalMap,
) -> Result<Vec<(PhysicalMapKey, &[u8])>, DurableError> {
    let Some(root) = map.root() else {
        return Ok(Vec::new());
    };
    let mut entries = Vec::new();
    let mut stack = vec![root];
    let mut visited = BTreeSet::new();
    while let Some(id) = stack.pop() {
        if !visited.insert(id) {
            return Err(DurableError::InvalidRepresentationState(
                "physical map traversal revisited a node",
            ));
        }
        match map
            .nodes()
            .get(&id)
            .ok_or(DurableError::InvalidRepresentationState(
                "physical map traversal found a missing node",
            ))? {
            PhysicalMapNode::Leaf { key, value, .. } => entries.push((*key, value.as_slice())),
            PhysicalMapNode::Branch { zero, one, .. } => {
                stack.push(*one);
                stack.push(*zero);
            },
            PhysicalMapNode::Page {
                entries: page_entries,
                ..
            } => entries.extend(
                page_entries
                    .iter()
                    .map(|(key, value)| (*key, value.as_slice())),
            ),
            PhysicalMapNode::Radix { children, .. } => {
                stack.extend(children.iter().rev().copied());
            },
        }
    }
    Ok(entries)
}

pub(super) fn read_current(
    path: &Path,
    limits: RecoveryLimits,
) -> Result<CurrentPointer, DurableError> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|source| io_error("open representation current pointer", source))?;
    let mut current = None;
    scan_frames(
        &mut file,
        CURRENT_FILE,
        CURRENT_MAGIC,
        limits,
        |_offset, payload| {
            if current.is_some() {
                return Err(DurableError::InvalidRepresentationState(
                    "current pointer contains more than one frame",
                ));
            }
            current = Some(CurrentPointer::decode(payload)?);
            Ok(())
        },
    )?;
    current.ok_or(DurableError::InvalidRepresentationState(
        "current pointer is empty",
    ))
}

fn first_frame_end(file: &mut File) -> Result<usize, DurableError> {
    file.seek(SeekFrom::Start(12))
        .map_err(|source| io_error("seek representation checkpoint header", source))?;
    let mut length = [0_u8; 8];
    file.read_exact(&mut length)
        .map_err(|source| io_error("read representation checkpoint header", source))?;
    let payload =
        usize::try_from(u64::from_le_bytes(length)).map_err(|_| DurableError::EncodingOverflow)?;
    usize::try_from(FRAME_HEADER_LEN)
        .map_err(|_| DurableError::EncodingOverflow)?
        .checked_add(payload)
        .ok_or(DurableError::EncodingOverflow)
}
