//! Compact physical bookkeeping without changing logical retention or authority.
//!
//! A checkpoint keeps the exact active state identity and its reachable maps.
//! Historical placement states are recovery machinery, not logical history.
//! Publish CURRENT only after the replacement generation is durable and verified;
//! reclaim the previous generation only after CURRENT itself is durable.

use super::activation::visit_new_reachable_map_nodes;
use super::{
    BTreeSet, Blake3PhysicalIdentity, CurrentPointer, DurableError, DurableFile,
    FramedAppendStream, JOURNAL_MAGIC, JOURNAL_PATH, JournalEntry, METADATA_MAGIC, METADATA_PATH,
    MetadataFrame, RecoveryLimits, RepresentationStore, append_frame, digest_journal_file, format,
    generation_name, increment, io_error, read_current_file, recover_journal, recover_metadata,
};

#[cfg(test)]
mod maintenance_tests;
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
        // Stream tip-reachable MapNode frames through one framed append stream:
        // seek once, reuse the shared transfer buffer, flush before sync/readback.
        let mut appended = BTreeSet::new();
        let mut complete = BTreeSet::new();
        let mut durable = BTreeSet::new();
        {
            let mut stream = FramedAppendStream::begin(&mut metadata, METADATA_MAGIC)?;
            for map in [
                &self.profiles,
                &self.representations,
                &self.placement_entries,
            ] {
                visit_new_reachable_map_nodes(
                    map,
                    &mut durable,
                    &mut appended,
                    &mut complete,
                    |node| {
                        let frame = MetadataFrame::map_node(&Blake3PhysicalIdentity, node)?;
                        stream.append_payload(&frame.encode()?)
                    },
                )?;
            }
            for frame in [
                MetadataFrame::catalogue(&Blake3PhysicalIdentity, self.catalogue),
                MetadataFrame::placement(&Blake3PhysicalIdentity, self.placements),
                MetadataFrame::state(&Blake3PhysicalIdentity, self.state),
            ] {
                stream.append_payload(&frame.encode()?)?;
            }
            stream.finish()?;
        }
        metadata
            .sync_data()
            .map_err(|source| io_error("flush checkpoint metadata", source))?;
        let prior = digest_journal_file(&mut self.journal, "digest prior representation journal")?;
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
            checkpoint_digest: digest_journal_file(&mut journal, "digest checkpoint journal")?,
            max_tail_frames: u32::MAX,
            max_tail_bytes: u64::MAX,
        };
        let index = recover_metadata(&mut metadata, limits)?;
        let (active, state) = recover_journal(&mut journal, current, &index, limits)?;
        let (recovered, _) = Self::from_recovered::<false>(
            metadata, journal, generation, active, state, index, limits,
        )?;
        if recovered.active != self.active || recovered.reverse != self.reverse {
            return Err(DurableError::InvalidRepresentationState(
                "checkpoint changed physical authority",
            ));
        }
        Ok((recovered, current))
    }

    /// Prepare a private generation without changing CURRENT. Callers may rebase
    /// this copy before publishing it with the arena in one metadata transaction.
    pub(in crate::engine::durable) fn prepare_checkpoint_volume(
        &mut self,
        volume: &std::sync::Arc<dyn crate::volume::AstridVolume>,
        limits: RecoveryLimits,
    ) -> Result<Self, DurableError> {
        use super::volume::{generation_region, remove_region_if_present};
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
        Ok(replacement)
    }

    pub(in crate::engine::durable) fn checkpoint_volume_publication()
    -> Result<crate::volume::VolumeMetadataMutation, DurableError> {
        use crate::volume::{VolumeMetadataMutation, VolumeRegion};

        let from = VolumeRegion::new("representations/CURRENT.tmp")
            .map_err(|source| io_error("validate checkpoint temporary", source))?;
        let to = VolumeRegion::new("representations/CURRENT")
            .map_err(|source| io_error("validate checkpoint current", source))?;
        Ok(VolumeMetadataMutation::Replace {
            source: from,
            destination: to,
        })
    }

    pub(in crate::engine::durable) fn checkpoint_volume(
        &mut self,
        volume: &std::sync::Arc<dyn crate::volume::AstridVolume>,
        limits: RecoveryLimits,
    ) -> Result<(), DurableError> {
        let replacement = self.prepare_checkpoint_volume(volume, limits)?;
        volume
            .commit_metadata(&[Self::checkpoint_volume_publication()?])
            .map_err(|source| io_error("publish checkpoint pointer", source))?;
        // Once the namespace changes, subsequent writes must use the new handles
        // even if the durability barrier reports an error. Keep old regions then.
        *self = replacement;
        volume
            .sync()
            .map_err(|source| io_error("flush checkpoint publication", source))?;
        self.reclaim_checkpoint_volume(volume)
    }

    /// Checkpoint once obsolete frames provably reach the resident map size.
    ///
    /// The resident count includes transient unreachable nodes and can defer
    /// maintenance beyond one reachable tip's worth of obsolete frames. Conservative free-space gate uses current durable
    /// metadata length as an upper bound for the tip rewrite. Unknown or
    /// insufficient space skips without failing the caller.
    pub(in crate::engine::durable) fn maybe_checkpoint_volume(
        &mut self,
        volume: &std::sync::Arc<dyn crate::volume::AstridVolume>,
        limits: RecoveryLimits,
    ) -> Result<bool, DurableError> {
        if !self.should_checkpoint_representations_metadata() {
            return Ok(false);
        }
        let durable_len = self
            .metadata
            .metadata()
            .map_err(|source| io_error("measure representation metadata length", source))?
            .len();
        match volume.available_space() {
            Ok(Some(space)) if space < durable_len => return Ok(false),
            Ok(None) | Err(_) => return Ok(false),
            Ok(Some(_)) => {},
        }
        self.checkpoint_volume(volume, limits)?;
        debug_assert!(self.map_frame_count() <= self.resident_map_node_count());
        Ok(true)
    }

    /// Apply the same resident-node scheduling bound to native capability media.
    pub(in crate::engine::durable) fn maybe_checkpoint_native(
        &mut self,
        store_root: &cap_std::fs::Dir,
        limits: RecoveryLimits,
    ) -> Result<bool, DurableError> {
        if !self.should_checkpoint_representations_metadata() {
            return Ok(false);
        }
        self.checkpoint_native(store_root, limits)?;
        debug_assert!(self.map_frame_count() <= self.resident_map_node_count());
        Ok(true)
    }

    /// Only call after this generation and its matching arena are durable.
    pub(in crate::engine::durable) fn reclaim_checkpoint_volume(
        &self,
        volume: &std::sync::Arc<dyn crate::volume::AstridVolume>,
    ) -> Result<(), DurableError> {
        use super::volume::remove_region_if_present;

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
