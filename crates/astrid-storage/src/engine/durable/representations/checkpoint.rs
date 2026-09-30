//! Compact physical bookkeeping without changing logical retention or authority.
//!
//! A checkpoint keeps the exact active state identity and its reachable maps.
//! Historical placement states are recovery machinery, not logical history.
//! Publish CURRENT only after the replacement generation is durable and verified;
//! reclaim the previous generation only after CURRENT itself is durable.

use super::{
    BTreeSet, Blake3PhysicalIdentity, CurrentPointer, DurableError, DurableFile, JOURNAL_MAGIC,
    JOURNAL_PATH, JournalEntry, METADATA_MAGIC, METADATA_PATH, MetadataFrame, RecoveryLimits,
    RepresentationStore, append_frame, append_frames, append_new_reachable_map_nodes, format,
    generation_name, increment, io_error, journal_digest, read_all, read_current_file,
    recover_journal, recover_metadata,
};

mod native;
#[cfg(test)]
mod tests;

impl RepresentationStore {
    fn checkpoint_into(
        &mut self,
        mut metadata: DurableFile,
        mut journal: DurableFile,
        limits: RecoveryLimits,
    ) -> Result<(Self, CurrentPointer), DurableError> {
        self.flush()?;
        let generation = increment(self.journal_generation)?;
        let mut frames = Vec::new();
        let mut appended = BTreeSet::new();
        for map in [
            &self.profiles,
            &self.representations,
            &self.placement_entries,
        ] {
            append_new_reachable_map_nodes(
                &mut frames,
                map,
                &BTreeSet::new(),
                &mut appended,
                &mut BTreeSet::new(),
            )?;
        }
        frames.extend([
            MetadataFrame::catalogue(&Blake3PhysicalIdentity, self.catalogue),
            MetadataFrame::placement(&Blake3PhysicalIdentity, self.placements),
            MetadataFrame::state(&Blake3PhysicalIdentity, self.state),
        ]);
        let payloads = frames
            .iter()
            .map(MetadataFrame::encode)
            .collect::<Result<Vec<_>, _>>()?;
        append_frames(&mut metadata, METADATA_MAGIC, &payloads)?;
        metadata
            .sync_data()
            .map_err(|source| io_error("flush checkpoint metadata", source))?;
        let prior = journal_digest(&read_all(
            &mut self.journal,
            "read prior representation journal",
        )?);
        let checkpoint = JournalEntry::Checkpoint {
            journal_generation: generation,
            active: Some(self.active),
            state_generation: self.state.generation(),
            prior_journal_digest: Some(prior),
        };
        append_frame(&mut journal, JOURNAL_MAGIC, &checkpoint.encode())?;
        journal
            .sync_data()
            .map_err(|source| io_error("flush checkpoint journal", source))?;
        let current = CurrentPointer {
            journal_generation: generation,
            checkpoint_digest: journal_digest(&read_all(&mut journal, "read checkpoint journal")?),
            max_tail_frames: u32::MAX,
            max_tail_bytes: u64::MAX,
        };
        let index = recover_metadata(&mut metadata, limits)?;
        let (active, state) = recover_journal(&mut journal, current, &index, limits)?;
        let recovered = Self::from_recovered(metadata, journal, generation, active, state, &index)?;
        if recovered.active != self.active || recovered.reverse != self.reverse {
            return Err(DurableError::InvalidRepresentationState(
                "checkpoint changed physical authority",
            ));
        }
        Ok((recovered, current))
    }

    pub(in crate::engine::durable) fn checkpoint_volume(
        &mut self,
        volume: &std::sync::Arc<dyn crate::volume::AstridVolume>,
        limits: RecoveryLimits,
    ) -> Result<(), DurableError> {
        use super::volume::{generation_region, remove_region_if_present};
        use crate::volume::VolumeRegion;
        use std::sync::Arc;

        let next = generation_name(increment(self.journal_generation)?);
        let metadata_path = generation_region(&next, METADATA_PATH);
        let journal_path = generation_region(&next, JOURNAL_PATH);
        // A failed preparation is unreachable from CURRENT and safe to retry.
        for path in [&metadata_path, &journal_path, "representations/CURRENT.tmp"] {
            remove_region_if_present(volume, path)?;
        }
        let metadata = DurableFile::volume(Arc::clone(volume), &metadata_path, true)?;
        let journal = DurableFile::volume(Arc::clone(volume), &journal_path, true)?;
        let (replacement, current) = self.checkpoint_into(metadata, journal, limits)?;
        let mut pointer =
            DurableFile::volume(Arc::clone(volume), "representations/CURRENT.tmp", true)?;
        append_frame(&mut pointer, format::CURRENT_MAGIC, &current.encode())?;
        pointer
            .sync_data()
            .map_err(|source| io_error("flush checkpoint pointer", source))?;
        if read_current_file(pointer, limits)? != current {
            return Err(DurableError::InvalidRepresentationState(
                "checkpoint pointer verification failed",
            ));
        }
        let from = VolumeRegion::new("representations/CURRENT.tmp")
            .map_err(|source| io_error("validate checkpoint temporary", source))?;
        let to = VolumeRegion::new("representations/CURRENT")
            .map_err(|source| io_error("validate checkpoint current", source))?;
        volume
            .replace_region(&from, &to)
            .map_err(|source| io_error("publish checkpoint pointer", source))?;
        // Once the namespace changes, subsequent writes must use the new handles
        // even if the durability barrier reports an error. Keep old regions then.
        *self = replacement;
        volume
            .sync()
            .map_err(|source| io_error("flush checkpoint publication", source))?;
        for region in volume
            .list_regions("representations/generations/")
            .map_err(|source| io_error("list obsolete checkpoint regions", source))?
        {
            let Some(suffix) = region.as_str().strip_prefix("representations/generations/") else {
                continue;
            };
            let Some((generation, file)) = suffix.split_once('/') else {
                continue;
            };
            if obsolete_generation(generation, self.journal_generation)
                && matches!(file, METADATA_PATH | JOURNAL_PATH)
            {
                remove_region_if_present(volume, region.as_str())?;
            }
        }
        volume
            .sync()
            .map_err(|source| io_error("flush checkpoint reclamation", source))
    }
}

fn obsolete_generation(name: &str, current: u64) -> bool {
    name.len() == 16
        && name
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && u64::from_str_radix(name, 16)
            .is_ok_and(|generation| generation > 0 && generation < current)
}
