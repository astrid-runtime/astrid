//! Astrid-volume arena replacement under the compaction mutation fence.

use std::io::{Seek, SeekFrom};
use std::sync::Arc;

use crate::volume::{AstridVolume, VolumeRegion};

use super::{
    ARENA_COMPACTING, ARENA_FILE, ARENA_MAGIC, BTreeMap, BTreeSet, CompactionReport, DurableEngine,
    DurableError, DurableFiles, DurableInner, File, IndexState, ObjectId, PersistentObjectIdentity,
    PrincipalCodec, ROOT_FILE, ReplacementState, VerifiedCompactionPlan, append_frame,
    encode_object_frame, ensure_payload_limit, evidence, io_error, live_files_mut, outbox,
    replace_volume_index, root_journal_digest, validate_replacement,
};

impl<P, I, C> DurableEngine<P, I, C>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    #[allow(clippy::too_many_lines)]
    pub(super) fn compact_volume_locked(
        &self,
        inner: &mut DurableInner<P>,
        authorization: &VerifiedCompactionPlan,
        live: &BTreeSet<ObjectId>,
        volume: &Arc<dyn AstridVolume>,
    ) -> Result<CompactionReport, DurableError> {
        // ContiguousFile blobs are volume regions, not host files. Arena
        // compaction must not materialize those payloads as DirectCanonical
        // frames. Count and copy only arena-resident objects.
        let objects_before =
            u64::try_from(inner.index.len()).map_err(|_| DurableError::EncodingOverflow)?;
        let (arena_bytes_before, root_bytes, root_digest) = {
            let files = live_files_mut(&mut inner.files)?;
            let arena_bytes = files
                .arena
                .metadata()
                .map_err(|source| io_error("read volume arena before compaction", source))?
                .len();
            let root_bytes = files
                .roots
                .metadata()
                .map_err(|source| io_error("read volume roots before compaction", source))?
                .len();
            let root_digest = root_journal_digest(&mut files.roots)?;
            (arena_bytes, root_bytes, root_digest)
        };

        let temporary = VolumeRegion::new(ARENA_COMPACTING)
            .map_err(|source| io_error("validate compacting volume region", source))?;
        if volume
            .region_exists(&temporary)
            .map_err(|source| io_error("inspect compacting volume region", source))?
        {
            volume
                .remove_region(&temporary)
                .map_err(|source| io_error("remove stale compacting volume region", source))?;
        }
        let mut arena = File::volume(Arc::clone(volume), ARENA_COMPACTING, true)?;
        let mut new_index = BTreeMap::new();
        for id in live {
            if !inner.index.contains_key(id) {
                continue;
            }
            let record = self.read_compaction_object(inner, *id)?;
            let payload = encode_object_frame(self.identity.scheme(), *id, &record)?;
            ensure_payload_limit(ARENA_FILE, 0, payload.len(), self.limits)?;
            let location = append_frame(&mut arena, ARENA_MAGIC, &payload)?;
            new_index.insert(*id, location);
        }
        arena
            .sync_data()
            .map_err(|source| io_error("flush compacted volume arena", source))?;
        let mut roots = live_files_mut(&mut inner.files)?
            .roots
            .try_clone()
            .map_err(|source| io_error("clone volume roots for compaction", source))?;
        let replacement = validate_replacement(
            &mut arena,
            &mut roots,
            &new_index,
            inner.representations.as_ref(),
            &self.principal_codec,
            &self.identity,
            self.limits,
        )?;
        let objects_after =
            u64::try_from(replacement.index.len()).map_err(|_| DurableError::EncodingOverflow)?;
        let objects_reclaimed = objects_before.checked_sub(objects_after).ok_or(
            DurableError::InvalidCompactionEvidence(
                "volume replacement contains more objects than its source",
            ),
        )?;
        if objects_reclaimed
            != u64::try_from(authorization.facts.condemned.len())
                .map_err(|_| DurableError::EncodingOverflow)?
        {
            return Err(DurableError::InvalidCompactionEvidence(
                "volume replacement does not execute the complete condemned set",
            ));
        }
        let bundle = evidence::build_bundle(
            authorization,
            &evidence::PlacementView {
                operation_contract: authorization.retention.operation_contract(),
                arena_bytes: arena_bytes_before,
                root_journal_bytes: root_bytes,
                root_journal_digest: root_digest,
                index: &inner.index,
                roots: &inner.roots_by_principal,
            },
            &evidence::PlacementView {
                operation_contract: authorization.retention.operation_contract(),
                arena_bytes: replacement.arena_len,
                root_journal_bytes: replacement.root_len,
                root_journal_digest: replacement.root_digest,
                index: &replacement.index,
                roots: &replacement.roots,
            },
            evidence::TransitionMeasurements {
                objects_before,
                objects_after,
                objects_reclaimed,
                arena_bytes_before,
                arena_bytes_after: replacement.arena_len,
                root_bytes_before: root_bytes,
                root_bytes_after: replacement.root_len,
            },
            &self.principal_codec,
            &self.identity,
        )?;
        outbox::prepare_volume(Arc::clone(volume), &bundle, &self.identity, self.limits)?;

        drop(arena);
        let active = VolumeRegion::new(ARENA_FILE)
            .map_err(|source| io_error("validate active volume arena region", source))?;
        outbox::commit_volume_replacement(
            Arc::clone(volume),
            temporary,
            active,
            &bundle,
            &self.identity,
            self.limits,
        )?;
        self.install_volume_replacement(inner, replacement, Arc::clone(volume))?;
        if let Some(representations) = inner.representations.as_mut() {
            let files = live_files_mut(&mut inner.files)?;
            representations.rebase_compacted_arena(
                &files.arena,
                &inner.index,
                &self.identity,
                self.limits,
            )?;
            if representations.contiguous_object_ids().next().is_none() {
                representations.retire_volume_loose_blobs()?;
            }
        }
        volume
            .sync()
            .map_err(|source| io_error("flush compacted volume before reclaim", source))?;
        volume
            .reclaim()
            .map_err(|source| io_error("physically reclaim compacted volume", source))?;
        Ok(CompactionReport {
            objects_before,
            objects_after,
            objects_reclaimed,
            arena_bytes_before,
            arena_bytes_after: inner.files.as_ref().map_or(0, |files| files.arena_len),
            fact_snapshot: authorization.facts.snapshot,
            gc_commit: bundle.commit_id(),
        })
    }

    fn install_volume_replacement(
        &self,
        inner: &mut DurableInner<P>,
        replacement: ReplacementState<P>,
        volume: Arc<dyn AstridVolume>,
    ) -> Result<(), DurableError> {
        let index_state = IndexState {
            arena_len: replacement.arena_len,
            arena_tail: replacement.arena_tail,
            objects: replacement.index.clone(),
        };
        let index_cache =
            replace_volume_index(Arc::clone(&volume), &index_state, self.identity.scheme());
        let mut arena = File::volume(Arc::clone(&volume), ARENA_FILE, false)?;
        let mut roots = File::volume(volume, ROOT_FILE, false)?;
        arena
            .seek(SeekFrom::End(0))
            .map_err(|source| io_error("seek compacted volume arena", source))?;
        roots
            .seek(SeekFrom::End(0))
            .map_err(|source| io_error("seek compacted volume roots", source))?;
        let arena_reader = arena
            .try_clone()
            .map_err(|source| io_error("clone compacted volume arena", source))?;
        let arena_generation = inner.arena_generation.wrapping_add(1);
        self.object_cache
            .retain_objects(|object| replacement.index.contains_key(&object));
        inner.roots_by_principal = replacement.roots;
        inner.index = replacement.index;
        inner.pending_index_locations.clear();
        inner.pending_direct_objects.clear();
        inner.validated = replacement.validated;
        inner.files = Some(DurableFiles {
            arena,
            roots,
            index_cache,
            arena_len: replacement.arena_len,
            arena_tail: replacement.arena_tail,
        });
        *self.arena_reader.write() = Some(super::super::ArenaReader {
            file: arena_reader,
            generation: arena_generation,
        });
        inner.arena_generation = arena_generation;
        Ok(())
    }
}
