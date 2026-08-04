//! Durable-engine integration for authoritative physical representations.

use std::collections::BTreeSet;

use astrid_storage_model::{ObjectId, RepresentationStateId};

use super::representations::{DirectArenaObject, PendingDirectUpdate, RepresentationStore};
use super::{
    DurableEngine, DurableError, DurableInner, PersistentObjectIdentity, PrincipalCodec,
    canonical_record_bytes, encode_object_frame, live_files_mut, read_indexed_object,
};

impl<P, I, C> DurableEngine<P, I, C>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    /// Ensure the authoritative direct-representation catalogue is active.
    ///
    /// Activation describes the already-verified generation-zero object arena
    /// without rewriting its bytes. `bootstrap_objects` are terminal objects
    /// named by `store.meta`; they remain recoverable through that independent
    /// bootstrap path and are deliberately absent from the representation
    /// catalogue. A completed activation is idempotent across process restarts.
    ///
    /// # Errors
    ///
    /// Returns an authoritative recovery, object-decoding, physical-model, or
    /// filesystem error. Failure before `representations/CURRENT` is published
    /// leaves the existing arena-only store authoritative.
    pub fn ensure_direct_representation_catalogue(
        &self,
        frozen_specification: ObjectId,
        bootstrap_objects: &[ObjectId],
    ) -> Result<RepresentationStateId, DurableError> {
        let mut inner = self.lock_usable()?;
        let excluded: BTreeSet<_> = bootstrap_objects.iter().copied().collect();
        if !excluded.contains(&frozen_specification)
            || !inner.index.contains_key(&frozen_specification)
        {
            return Err(DurableError::InvalidRepresentationState(
                "frozen specification is not a persisted bootstrap object",
            ));
        }
        if inner.representations.is_some() {
            return self.repair_direct_coverage(&mut inner, frozen_specification, &excluded);
        }
        let scheme = self.identity.scheme();
        let direct_profile = RepresentationStore::direct_profile_for(frozen_specification)?;
        let representations = {
            let DurableInner { files, index, .. } = &mut *inner;
            let files = live_files_mut(files)?;
            let objects = index.iter().filter_map(|(object, location)| {
                if excluded.contains(object) {
                    return None;
                }
                let record = read_indexed_object(
                    &files.arena,
                    *object,
                    *location,
                    &self.identity,
                    self.limits,
                );
                Some(record.and_then(|record| {
                    let payload = encode_object_frame(scheme, *object, &record)?;
                    DirectArenaObject::identify(
                        direct_profile,
                        *object,
                        canonical_record_bytes(&payload, scheme)?,
                        *location,
                    )
                }))
            });
            RepresentationStore::activate(
                &self.directory,
                self.limits,
                frozen_specification,
                objects,
            )?
        };
        let active = representations.active();
        inner.representations = Some(representations);
        Ok(active)
    }

    fn repair_direct_coverage(
        &self,
        inner: &mut DurableInner<P>,
        frozen_specification: ObjectId,
        excluded: &BTreeSet<ObjectId>,
    ) -> Result<RepresentationStateId, DurableError> {
        let representations =
            inner
                .representations
                .as_ref()
                .ok_or(DurableError::InvalidRepresentationState(
                    "active representation store disappeared",
                ))?;
        if representations.frozen_specification()? != frozen_specification {
            return Err(DurableError::InvalidRepresentationState(
                "active direct profile names a different frozen specification",
            ));
        }
        let missing = inner
            .index
            .iter()
            .filter(|(object, _)| {
                !excluded.contains(object) && !representations.contains_direct(**object)
            })
            .map(|(object, location)| (*object, *location))
            .collect::<Vec<_>>();
        if missing.is_empty() {
            return Ok(representations.active());
        }
        let scheme = self.identity.scheme();
        let appended = {
            let DurableInner {
                files,
                representations,
                ..
            } = inner;
            let files = live_files_mut(files)?;
            let representations =
                representations
                    .as_ref()
                    .ok_or(DurableError::InvalidRepresentationState(
                        "active representation store disappeared during repair",
                    ))?;
            missing
                .into_iter()
                .map(|(object, location)| {
                    let record = read_indexed_object(
                        &files.arena,
                        object,
                        location,
                        &self.identity,
                        self.limits,
                    )?;
                    let payload = encode_object_frame(scheme, object, &record)?;
                    representations.describe_direct(
                        object,
                        canonical_record_bytes(&payload, scheme)?,
                        location,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?
        };
        let update = match self.append_pending_direct_update(inner, &appended) {
            Ok(update) => update,
            Err(error) => {
                self.mark_requires_recovery(inner);
                return Err(error);
            },
        };
        if let Err(error) = Self::flush_standalone(inner, update) {
            self.mark_requires_recovery(inner);
            return Err(error);
        }
        if let Some(representations) = &mut inner.representations
            && let Err(error) = representations.flush()
        {
            self.mark_requires_recovery(inner);
            return Err(error);
        }
        inner
            .representations
            .as_ref()
            .map(RepresentationStore::active)
            .ok_or(DurableError::InvalidRepresentationState(
                "repaired representation store disappeared",
            ))
    }

    pub(super) fn append_pending_direct_update(
        &self,
        inner: &mut DurableInner<P>,
        appended: &[DirectArenaObject],
    ) -> Result<Option<PendingDirectUpdate>, DurableError> {
        let DurableInner {
            files,
            representations,
            pending_index_locations,
            ..
        } = inner;
        let Some(representations) = representations else {
            return Ok(None);
        };
        let files = live_files_mut(files)?;
        let mut direct = Vec::new();
        direct
            .try_reserve(pending_index_locations.len().saturating_add(appended.len()))
            .map_err(|_| DurableError::EncodingOverflow)?;
        let mut seen = BTreeSet::new();
        for (id, location) in pending_index_locations.iter().copied() {
            if !seen.insert(id) || representations.contains_direct(id) {
                continue;
            }
            let record =
                read_indexed_object(&files.arena, id, location, &self.identity, self.limits)?;
            let payload = encode_object_frame(self.identity.scheme(), id, &record)?;
            direct.push(representations.describe_direct(
                id,
                canonical_record_bytes(&payload, self.identity.scheme())?,
                location,
            )?);
        }
        direct.extend(
            appended
                .iter()
                .filter(|object| seen.insert(object.object))
                .cloned(),
        );
        representations.append_direct_update(&direct)
    }
}
