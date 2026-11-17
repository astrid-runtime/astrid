//! Compact physical bookkeeping without changing logical retention or authority.
//!
//! A checkpoint keeps the exact active state identity and its reachable maps.
//! Historical placement states are recovery machinery, not logical history.
//! Publish CURRENT only after the replacement generation is durable and verified;
//! reclaim the previous generation only after CURRENT itself is durable.

use super::{
    DurableError, DurableFile, JOURNAL_PATH, METADATA_PATH, RecoveryLimits, RepresentationStore,
    generation_name, increment, io_error,
};

mod adoption;
pub(in crate::engine::durable) use adoption::is_checkpoint_cancelled;
mod background;
mod control;
pub(in crate::engine::durable) use control::{CheckpointCancellation, CheckpointControl};
mod handover;
mod tail;
#[cfg(test)]
mod test_support;
pub(in crate::engine::durable) use background::{
    CapturedCheckpoint, CheckpointMedia, PreparedCheckpoint,
};
#[cfg(test)]
mod adoption_counter_tests;
#[cfg(test)]
mod adoption_tests;
#[cfg(test)]
mod maintenance_tests;
mod native;
#[cfg(test)]
mod streaming_tests;
#[cfg(test)]
mod tests;

impl RepresentationStore {
    fn checkpoint_into(
        &mut self,
        mut metadata: DurableFile,
        mut journal: DurableFile,
        limits: RecoveryLimits,
    ) -> Result<(Self, super::CurrentPointer), DurableError> {
        let emit = self.emit_sealed_generation(&mut metadata, &mut journal)?;
        self.materialize_sealed_generation(metadata, journal, emit, limits)
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
        let pointer = DurableFile::volume(Arc::clone(volume), "representations/CURRENT.tmp", true)?;
        adoption::write_verified_current_tmp(pointer, current, limits)?;
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

    /// Only call after this generation and its matching arena are durable.
    pub(in crate::engine::durable) fn reclaim_checkpoint_volume(
        &self,
        volume: &std::sync::Arc<dyn crate::volume::AstridVolume>,
    ) -> Result<(), DurableError> {
        background::CheckpointMedia::Volume(std::sync::Arc::clone(volume))
            .reclaim_before(self.journal_generation)
    }
}

pub(super) fn obsolete_generation(name: &str, current: u64) -> bool {
    name.len() == 16
        && name
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && u64::from_str_radix(name, 16)
            .is_ok_and(|generation| generation > 0 && generation < current)
}
