//! Physical representation catalogue on Astrid volume media.
//!
//! Volume regions are placement, not identity. Catalogue files keep the same
//! frame grammar as the directory store.

use std::sync::Arc;

use crate::storage_model::ObjectId;
use crate::volume::AstridVolume;

use super::super::{File as DurableFile, RecoveryLimits};
use super::activation::{build_initial_state, generation_name};
use super::format::{
    CURRENT_MAGIC, CurrentPointer, JOURNAL_MAGIC, JournalEntry, METADATA_MAGIC, MetadataFrame,
    journal_digest,
};
use super::recovery::{read_current_file, recover_journal, recover_metadata};
use super::{
    DIRECTORY, DurableError, FIRST_JOURNAL_GENERATION, GENERATIONS_DIRECTORY, JOURNAL_PATH,
    METADATA_PATH, RepresentationStore, append_frame, append_frames, io_error,
};

const CURRENT_REGION: &str = "representations/CURRENT";
const CURRENT_TEMP_REGION: &str = "representations/CURRENT.tmp";

impl RepresentationStore {
    pub(in crate::engine::durable) fn open_volume(
        volume: &Arc<dyn AstridVolume>,
        limits: RecoveryLimits,
    ) -> Result<Option<Self>, DurableError> {
        if !region_exists(volume, CURRENT_REGION)? {
            return Ok(None);
        }
        let current_file = DurableFile::volume(Arc::clone(volume), CURRENT_REGION, false)?;
        let current = read_current_file(current_file, limits)?;
        let generation = generation_name(current.journal_generation);
        let mut metadata = DurableFile::volume(
            Arc::clone(volume),
            &generation_region(&generation, METADATA_PATH),
            false,
        )?;
        let mut journal = DurableFile::volume(
            Arc::clone(volume),
            &generation_region(&generation, JOURNAL_PATH),
            false,
        )?;
        let index = recover_metadata(&mut metadata, limits)?;
        let (active, state) = recover_journal(&mut journal, current, &index, limits)?;
        let recovered = Self::from_recovered(
            metadata,
            journal,
            current.journal_generation,
            active,
            state,
            &index,
        )?;
        Ok(Some(recovered))
    }

    pub(in crate::engine::durable) fn activate_volume(
        volume: &Arc<dyn AstridVolume>,
        limits: RecoveryLimits,
        frozen_specification: ObjectId,
        objects: impl IntoIterator<Item = Result<super::DirectArenaObject, DurableError>>,
    ) -> Result<Self, DurableError> {
        if let Some(existing) = Self::open_volume(volume, limits)? {
            return Ok(existing);
        }
        remove_region_if_present(volume, CURRENT_TEMP_REGION)?;
        let generation = generation_name(FIRST_JOURNAL_GENERATION);
        let mut metadata = DurableFile::volume(
            Arc::clone(volume),
            &generation_region(&generation, METADATA_PATH),
            true,
        )?;
        let mut journal = DurableFile::volume(
            Arc::clone(volume),
            &generation_region(&generation, JOURNAL_PATH),
            true,
        )?;
        let built = build_initial_state(frozen_specification, objects)?;
        let payloads = built
            .metadata
            .iter()
            .map(MetadataFrame::encode)
            .collect::<Result<Vec<_>, _>>()?;
        append_frames(&mut metadata, METADATA_MAGIC, &payloads)?;
        metadata
            .sync_data()
            .map_err(|source| io_error("flush volume representation metadata", source))?;
        let checkpoint = JournalEntry::Checkpoint {
            journal_generation: FIRST_JOURNAL_GENERATION,
            active: None,
            state_generation: 0,
            prior_journal_digest: None,
        }
        .encode();
        append_frame(&mut journal, JOURNAL_MAGIC, &checkpoint)?;
        journal
            .sync_data()
            .map_err(|source| io_error("flush volume representation checkpoint", source))?;
        let checkpoint_bytes =
            super::read_all(&mut journal, "read volume representation checkpoint")?;
        let checkpoint_digest = journal_digest(&checkpoint_bytes);
        let state_cas = JournalEntry::StateCas {
            journal_generation: FIRST_JOURNAL_GENERATION,
            expected: None,
            replacement: built.active,
        }
        .encode();
        append_frame(&mut journal, JOURNAL_MAGIC, &state_cas)?;
        journal
            .sync_data()
            .map_err(|source| io_error("flush initial volume representation state", source))?;
        let current = CurrentPointer {
            journal_generation: FIRST_JOURNAL_GENERATION,
            checkpoint_digest,
            max_tail_frames: u32::MAX,
            max_tail_bytes: u64::MAX,
        };
        {
            let mut current_file =
                DurableFile::volume(Arc::clone(volume), CURRENT_TEMP_REGION, true)?;
            append_frame(&mut current_file, CURRENT_MAGIC, &current.encode())?;
            current_file.sync_data().map_err(|source| {
                io_error("flush volume representation current pointer", source)
            })?;
        }
        let recovered = read_current_file(
            DurableFile::volume(Arc::clone(volume), CURRENT_TEMP_REGION, false)?,
            RecoveryLimits::process_addressable(),
        )?;
        if recovered != current {
            return Err(DurableError::InvalidRepresentationState(
                "volume representation current pointer failed verification",
            ));
        }
        let from = crate::volume::VolumeRegion::new(CURRENT_TEMP_REGION).map_err(|source| {
            io_error("validate volume representation current temporary", source)
        })?;
        let to = crate::volume::VolumeRegion::new(CURRENT_REGION)
            .map_err(|source| io_error("validate volume representation current", source))?;
        volume
            .rename_region(&from, &to)
            .map_err(|source| io_error("publish volume representation current pointer", source))?;
        volume
            .sync()
            .map_err(|source| io_error("flush volume representation namespace", source))?;
        drop(metadata);
        drop(journal);
        Self::open_volume(volume, limits)?.ok_or(DurableError::InvalidRepresentationState(
            "published volume representation state did not reopen",
        ))
    }
}

fn generation_region(generation: &str, file: &str) -> String {
    format!("{DIRECTORY}/{GENERATIONS_DIRECTORY}/{generation}/{file}")
}

fn region_exists(volume: &Arc<dyn AstridVolume>, name: &str) -> Result<bool, DurableError> {
    let region = crate::volume::VolumeRegion::new(name)
        .map_err(|source| io_error("validate volume representation region", source))?;
    volume
        .region_exists(&region)
        .map_err(|source| io_error("inspect volume representation region", source))
}

fn remove_region_if_present(
    volume: &Arc<dyn AstridVolume>,
    name: &str,
) -> Result<(), DurableError> {
    if !region_exists(volume, name)? {
        return Ok(());
    }
    let region = crate::volume::VolumeRegion::new(name)
        .map_err(|source| io_error("validate volume representation temporary", source))?;
    volume
        .remove_region(&region)
        .map_err(|source| io_error("remove volume representation temporary", source))
}
