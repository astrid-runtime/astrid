//! One closed physical tip, prepared with the ordinary sealed adoption proof.
//!
//! The engine owns publication exclusion and cancellation/joining. This module
//! never owns an engine, principal, or detached task. Source readers are opened
//! independently; cloning a native file would share the writer's seek cursor.

use super::super::CheckpointCancellation;
use std::collections::BTreeSet;

use super::super::super::format::{DurableFrameRange, DurablePrefixEnd};
use super::super::{
    CurrentPointer, DurableError, DurableFile, RecoveryLimits, RepresentationStore, increment,
    io_error, journal_byte_len,
};
use super::adoption::ensure_not_cancelled;
use super::tail::CheckpointTail;

mod media;
#[cfg(test)]
mod tests;
pub(in crate::engine::durable) use media::CheckpointMedia;
use media::{GenerationFiles, NextGenerationGuard};

/// Captured only while the complete publisher frontier is excluded. Maps and
/// reverse associations come from the same closed authority, not cold recovery.
pub(in crate::engine::durable) struct CapturedCheckpoint {
    snapshot: RepresentationStore,
    metadata_end: DurablePrefixEnd,
    journal_end: DurablePrefixEnd,
    media: CheckpointMedia,
}

impl CapturedCheckpoint {
    pub(in crate::engine::durable) fn capture_from_media(
        store: &mut RepresentationStore,
        media: CheckpointMedia,
    ) -> Result<Self, DurableError> {
        store.flush()?;
        let (metadata, mut journal) = media.open_generation_files(store.journal_generation)?;
        let metadata_end = file_end(&metadata)?;
        let journal_end = DurablePrefixEnd::exclusive(journal_byte_len(
            &mut journal,
            "measure captured representation journal",
        )?);
        let profiles = store.profiles.clone();
        let representations = store.representations.clone();
        let placement_entries = store.placement_entries.clone();
        let residency = super::super::residency::MapResidency::new(
            profiles.as_canonical(),
            representations.as_canonical(),
            placement_entries.as_canonical(),
        );
        let snapshot = RepresentationStore {
            metadata,
            journal,
            journal_generation: store.journal_generation,
            active: store.active,
            state: store.state,
            catalogue: store.catalogue,
            placements: store.placements,
            residency,
            profiles,
            representations,
            placement_entries,
            // Source-generation append memos confer no authority in the sealed
            // destination. Its ordinary adoption proof installs fresh memos.
            persisted_map_nodes: BTreeSet::new(),
            complete_map_subtrees: BTreeSet::new(),
            map_frame_count: 0,
            direct_profile: store.direct_profile,
            reverse: store.reverse.clone(),
        };
        Ok(Self {
            snapshot,
            metadata_end,
            journal_end,
            media,
        })
    }

    pub(in crate::engine::durable) fn prepare(
        mut self,
        limits: RecoveryLimits,
        cancel: &impl CheckpointCancellation,
    ) -> Result<PreparedCheckpoint, DurableError> {
        ensure_not_cancelled(cancel)?;
        let source_generation = self.snapshot.journal_generation;
        // Only this captured prefix is the checkpoint's predecessor. Concurrent
        // appends cannot change the digest or the independent reader's cursor.
        let prior = super::super::digest::digest_journal_prefix_with_check(
            &mut self.snapshot.journal,
            self.journal_end.get(),
            "digest captured representation journal prefix",
            || ensure_not_cancelled(cancel),
        )?;
        ensure_not_cancelled(cancel)?;
        let mut files = self
            .media
            .create_next_generation_files(increment(source_generation)?)?;
        let (current, proof) = self.snapshot.prepare_sealed_adoption_with_prior(
            &mut files.metadata,
            &mut files.journal,
            limits,
            prior,
            cancel,
        )?;
        ensure_not_cancelled(cancel)?;
        let (source_metadata, source_journal) =
            self.media.open_generation_files(source_generation)?;
        let GenerationFiles {
            metadata,
            journal,
            guard,
        } = files;
        let mut prepared = PreparedCheckpoint {
            replacement: self.snapshot,
            current,
            source_generation,
            source_metadata,
            source_journal,
            metadata_end: self.metadata_end,
            journal_end: self.journal_end,
            media: self.media,
            guard: Some(guard),
        };
        // Prepared ownership closes replacement files before its guard even if
        // adoption returns an invariant error or unwinds during map reclamation.
        prepared
            .replacement
            .adopt_sealed_generation(metadata, journal, proof)?;
        Ok(prepared)
    }
}

pub(in crate::engine::durable) struct PreparedCheckpoint {
    replacement: RepresentationStore,
    current: CurrentPointer,
    source_generation: u64,
    source_metadata: DurableFile,
    source_journal: DurableFile,
    metadata_end: DurablePrefixEnd,
    journal_end: DurablePrefixEnd,
    media: CheckpointMedia,
    guard: Option<NextGenerationGuard>,
}

impl PreparedCheckpoint {
    /// Complete an explicitly joined clean-close job. The closer excludes all
    /// source publishers, so even a bulk residual is replayed once through the
    /// ordinary updater and fresh-media proofs. Ordinary writer handover keeps
    /// its separate one-non-bulk-CAS preflight bound.
    pub(in crate::engine::durable) fn finish_drained(
        mut self,
        live: &mut RepresentationStore,
        limits: RecoveryLimits,
        cancel: &impl CheckpointCancellation,
    ) -> Result<RetiredCheckpoint, DurableError> {
        if !self.tip_matches_live(live) {
            let tail = self.capture_tail(live)?;
            self.replay_tail(&tail, limits, cancel)?;
        }
        self.finish_publish(live, limits, cancel)
    }

    /// A quick scheduling predicate, not the final authority/body comparison.
    pub(in crate::engine::durable) fn tip_matches_live(&self, live: &RepresentationStore) -> bool {
        live.journal_generation == self.source_generation && live.active == self.replacement.active
    }

    pub(in crate::engine::durable) fn capture_tail(
        &self,
        live: &RepresentationStore,
    ) -> Result<CheckpointTail, DurableError> {
        if live.journal_generation != self.source_generation {
            return Err(DurableError::InvalidRepresentationState(
                "checkpoint source generation changed",
            ));
        }
        Ok(CheckpointTail {
            metadata: DurableFrameRange::try_new(self.metadata_end, file_end(&live.metadata)?)?,
            journal: DurableFrameRange::try_new(self.journal_end, file_end(&live.journal)?)?,
            source_generation: self.source_generation,
            expected_active: live.active,
        })
    }

    pub(in crate::engine::durable) fn replay_tail(
        &mut self,
        tail: &CheckpointTail,
        limits: RecoveryLimits,
        cancel: &impl CheckpointCancellation,
    ) -> Result<(), DurableError> {
        ensure_not_cancelled(cancel)?;
        self.replacement.replay_checkpoint_tail(
            &mut self.source_metadata,
            &mut self.source_journal,
            tail,
            limits,
            cancel,
        )?;
        if self.replacement.active != tail.expected_active {
            return Err(DurableError::InvalidRepresentationState(
                "checkpoint tail missed its captured authority",
            ));
        }
        self.metadata_end = tail.metadata.end();
        self.journal_end = tail.journal.end();
        Ok(())
    }

    pub(in crate::engine::durable) fn can_finish(
        &mut self,
        live: &RepresentationStore,
        limits: RecoveryLimits,
        cancel: &impl CheckpointCancellation,
    ) -> Result<bool, DurableError> {
        let tail = self.capture_tail(live)?;
        self.replacement.checkpoint_tail_is_nonbulk(
            &mut self.source_metadata,
            &mut self.source_journal,
            &tail,
            limits,
            cancel,
        )
    }

    /// Called by the worker holding fresh publication exclusion and the full
    /// physical fence. The only permitted residual is one non-bulk direct CAS.
    pub(in crate::engine::durable) fn finish_publish(
        mut self,
        live: &mut RepresentationStore,
        limits: RecoveryLimits,
        cancel: &impl CheckpointCancellation,
    ) -> Result<RetiredCheckpoint, DurableError> {
        if !self.can_finish(live, limits, cancel)? {
            return Err(DurableError::InvalidRepresentationState(
                "checkpoint residual requires off-writer catch-up",
            ));
        }
        let tail = self.capture_tail(live)?;
        self.replay_tail(&tail, limits, cancel)?;
        live.verify_checkpoint_tip(&self.replacement)?;
        ensure_not_cancelled(cancel)?;
        self.media.write_current(self.current, limits)?;
        ensure_not_cancelled(cancel)?;
        // A failed rename can have an uncertain namespace outcome. From this
        // point recovery, not private-generation cleanup, decides its authority.
        if let Some(guard) = self.guard.take() {
            guard.disarm();
        }
        self.media.publish_current()?;
        let old = std::mem::replace(live, self.replacement);
        // Install new custody before reporting a durability-barrier error. Old
        // media remains intact on failure, just as synchronous adoption does.
        self.media.sync_publication()?;
        Ok(RetiredCheckpoint {
            old,
            source_metadata: self.source_metadata,
            source_journal: self.source_journal,
            media: self.media,
            generation: self.current.journal_generation,
        })
    }
}

/// Kept on the worker stack, never on the next request's maintenance slot.
pub(in crate::engine::durable) struct RetiredCheckpoint {
    old: RepresentationStore,
    source_metadata: DurableFile,
    source_journal: DurableFile,
    media: CheckpointMedia,
    generation: u64,
}

impl RetiredCheckpoint {
    pub(in crate::engine::durable) fn reclaim(self) -> Result<(), DurableError> {
        let Self {
            old,
            source_metadata,
            source_journal,
            media,
            generation,
        } = self;
        // Windows also requires releasing generation readers before unlink.
        drop(old);
        drop(source_metadata);
        drop(source_journal);
        media.reclaim_before(generation)
    }
}

fn file_end(file: &DurableFile) -> Result<DurablePrefixEnd, DurableError> {
    file.metadata()
        .map(|metadata| DurablePrefixEnd::exclusive(metadata.len()))
        .map_err(|source| io_error("measure representation checkpoint boundary", source))
}
