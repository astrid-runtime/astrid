//! Physical representation catalogue and loose blobs on Astrid volume media.
//!
//! Volume regions are placement, not identity. Catalogue files keep the same
//! frame grammar as the directory store; file payloads use `ContiguousFile`
//! blobs instead of `DirectCanonical` chunk frames.

use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::Arc;

use crate::storage_model::{BlobId, ObjectId, RepresentationProfileId};
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
    METADATA_PATH, RepresentationMedia, RepresentationStore, append_frame, append_frames, io_error,
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
            RepresentationMedia::Volume(Arc::clone(volume)),
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

pub(in crate::engine::durable) fn install_volume_blob_copy<R: Read>(
    volume: &Arc<dyn AstridVolume>,
    blob: BlobId,
    profile: RepresentationProfileId,
    logical_bytes: u64,
    source: R,
) -> Result<(), DurableError> {
    let blob_region = blob_region(blob, super::contiguous::LOOSE_NAMESPACE_GENERATION);
    let meta_region = format!("{blob_region}.meta");
    let expected_meta = super::contiguous::encode_loose_metadata(profile, blob, logical_bytes)?;
    write_exact_region(volume, &meta_region, &expected_meta, true)?;
    if region_exists(volume, &blob_region)? {
        verify_volume_blob(volume, &blob_region, profile, blob, logical_bytes)?;
        return Ok(());
    }
    let mut output = DurableFile::volume(Arc::clone(volume), &blob_region, true)?;
    let copied = std::io::copy(&mut source.take(logical_bytes), &mut output)
        .map_err(|source| io_error("copy volume contiguous blob", source))?;
    if copied != logical_bytes {
        return Err(DurableError::InvalidRepresentationState(
            "volume contiguous blob source ended before its declared length",
        ));
    }
    output
        .sync_data()
        .map_err(|source| io_error("flush volume contiguous blob", source))?;
    verify_volume_blob(volume, &blob_region, profile, blob, logical_bytes)?;
    volume
        .sync()
        .map_err(|source| io_error("flush volume blob namespace", source))?;
    Ok(())
}

pub(in crate::engine::durable) fn open_volume_blob(
    volume: &Arc<dyn AstridVolume>,
    blob: BlobId,
    namespace_generation: u64,
) -> Result<DurableFile, DurableError> {
    DurableFile::volume(
        Arc::clone(volume),
        &blob_region(blob, namespace_generation),
        false,
    )
}

pub(in crate::engine::durable) fn verify_installed_volume_blob(
    volume: &Arc<dyn AstridVolume>,
    blob: BlobId,
    profile: RepresentationProfileId,
    logical_bytes: u64,
    namespace_generation: u64,
) -> Result<(), DurableError> {
    let name = blob_region(blob, namespace_generation);
    let meta_region = format!("{name}.meta");
    let expected = super::contiguous::encode_loose_metadata(profile, blob, logical_bytes)?;
    let mut meta = DurableFile::volume(Arc::clone(volume), &meta_region, false)?;
    let mut actual = Vec::new();
    meta.read_to_end(&mut actual)
        .map_err(|source| io_error("read volume contiguous blob metadata", source))?;
    if actual != expected {
        return Err(DurableError::InvalidRepresentationState(
            "volume contiguous blob metadata disagrees with its profile",
        ));
    }
    verify_volume_blob(volume, &name, profile, blob, logical_bytes)
}

fn verify_volume_blob(
    volume: &Arc<dyn AstridVolume>,
    region: &str,
    profile: RepresentationProfileId,
    blob: BlobId,
    logical_bytes: u64,
) -> Result<(), DurableError> {
    let mut file = DurableFile::volume(Arc::clone(volume), region, false)?;
    let mut hasher = super::contiguous::blob_hasher(profile, logical_bytes);
    let mut remaining = logical_bytes;
    let mut buffer = vec![0_u8; 64 * 1024];
    file.seek(SeekFrom::Start(0))
        .map_err(|source| io_error("rewind volume contiguous blob", source))?;
    while remaining > 0 {
        let want = usize::try_from(remaining.min(u64::try_from(buffer.len()).unwrap_or(u64::MAX)))
            .map_err(|_| DurableError::EncodingOverflow)?;
        let read = file
            .read(&mut buffer[..want])
            .map_err(|source| io_error("read volume contiguous blob", source))?;
        if read == 0 {
            return Err(DurableError::InvalidRepresentationState(
                "volume contiguous blob is truncated",
            ));
        }
        hasher.update(&buffer[..read]);
        remaining = remaining
            .checked_sub(u64::try_from(read).map_err(|_| DurableError::EncodingOverflow)?)
            .ok_or(DurableError::EncodingOverflow)?;
    }
    let computed = hasher.finalize();
    if computed.as_bytes() != blob.as_bytes() {
        return Err(DurableError::InvalidRepresentationState(
            "volume contiguous blob identity mismatch",
        ));
    }
    Ok(())
}

fn write_exact_region(
    volume: &Arc<dyn AstridVolume>,
    name: &str,
    bytes: &[u8],
    replace_equal: bool,
) -> Result<(), DurableError> {
    if region_exists(volume, name)? {
        let mut existing = DurableFile::volume(Arc::clone(volume), name, false)?;
        let mut actual = Vec::new();
        existing
            .read_to_end(&mut actual)
            .map_err(|source| io_error("read existing volume blob metadata", source))?;
        if actual.as_slice() == bytes {
            return Ok(());
        }
        if !replace_equal {
            return Err(DurableError::InvalidRepresentationState(
                "occupied volume blob metadata has a different preimage",
            ));
        }
        return Err(DurableError::InvalidRepresentationState(
            "occupied volume blob metadata has a different preimage",
        ));
    }
    let mut file = DurableFile::volume(Arc::clone(volume), name, true)?;
    file.write_all(bytes)
        .map_err(|source| io_error("write volume blob metadata", source))?;
    file.sync_data()
        .map_err(|source| io_error("flush volume blob metadata", source))
}

fn generation_region(generation: &str, file: &str) -> String {
    format!("{DIRECTORY}/{GENERATIONS_DIRECTORY}/{generation}/{file}")
}

fn blob_region(blob: BlobId, namespace_generation: u64) -> String {
    format!(
        "{DIRECTORY}/blobs/loose/{namespace_generation:016x}/{}",
        super::contiguous::loose_blob_name(blob).display()
    )
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
