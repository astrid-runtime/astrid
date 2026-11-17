//! Synchronous test drivers for the same automatic checkpoint implementation.
//! Production automatic maintenance has one engine-owned worker path; these
//! adapters keep media fault injection and proof counters deterministic.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use super::background::{CapturedCheckpoint, CheckpointMedia};
use super::{DurableError, RecoveryLimits, RepresentationStore, io_error};

impl RepresentationStore {
    fn complete_captured_checkpoint(
        &mut self,
        media: CheckpointMedia,
        limits: RecoveryLimits,
    ) -> Result<(), DurableError> {
        let cancel = AtomicBool::new(false);
        let capture = CapturedCheckpoint::capture_from_media(self, media)?;
        capture
            .prepare(limits, &cancel)?
            .finish_publish(self, limits, &cancel)?
            .reclaim()
    }

    pub(in crate::engine::durable) fn checkpoint_volume(
        &mut self,
        volume: &Arc<dyn crate::volume::AstridVolume>,
        limits: RecoveryLimits,
    ) -> Result<(), DurableError> {
        self.complete_captured_checkpoint(CheckpointMedia::Volume(Arc::clone(volume)), limits)
    }

    pub(super) fn checkpoint_native_adopting(
        &mut self,
        store_root: &cap_std::fs::Dir,
        limits: RecoveryLimits,
    ) -> Result<(), DurableError> {
        let directory = store_root
            .try_clone()
            .map_err(|source| io_error("clone checkpoint directory capability", source))?;
        self.complete_captured_checkpoint(CheckpointMedia::Directory(Arc::new(directory)), limits)
    }

    pub(in crate::engine::durable) fn maybe_checkpoint_volume(
        &mut self,
        volume: &Arc<dyn crate::volume::AstridVolume>,
        limits: RecoveryLimits,
    ) -> Result<bool, DurableError> {
        let media = CheckpointMedia::Volume(Arc::clone(volume));
        if !media.should_prepare(self)? {
            return Ok(false);
        }
        self.complete_captured_checkpoint(media, limits)?;
        debug_assert!(self.map_frame_count() <= self.resident_map_node_count());
        Ok(true)
    }

    pub(in crate::engine::durable) fn maybe_checkpoint_native(
        &mut self,
        store_root: &cap_std::fs::Dir,
        limits: RecoveryLimits,
    ) -> Result<bool, DurableError> {
        if !self.should_checkpoint_representations_metadata() {
            return Ok(false);
        }
        self.checkpoint_native_adopting(store_root, limits)?;
        debug_assert!(self.map_frame_count() <= self.resident_map_node_count());
        Ok(true)
    }
}
