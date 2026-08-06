//! Durable-engine integration for authoritative physical representations.

use std::collections::BTreeSet;

use astrid_storage_model::{ObjectId, RepresentationStateId};

use super::representations::{DirectArenaObject, PendingRepresentationUpdate, RepresentationStore};
use super::{
    DurableEngine, DurableError, DurableInner, PersistentObjectIdentity, PrincipalCodec,
    canonical_record_bytes, live_files_mut, read_indexed_object_with_payload,
    visit_indexed_objects,
};

const ACTIVATION_READ_TARGET_BYTES: u64 = 8 * 1024 * 1024;

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
        self.ensure_direct_representation_catalogue_compatible_with(
            frozen_specification,
            &[],
            bootstrap_objects,
        )
    }

    /// Ensure the direct catalogue while retaining an explicitly compatible
    /// predecessor profile.
    ///
    /// Physical-format amendments can change the in-band specification
    /// without changing the direct-canonical recipe. Existing catalogues keep
    /// their original profile identity; callers must name every predecessor
    /// specification whose semantics remain valid. The active specification
    /// must still be a persisted bootstrap object.
    ///
    /// # Errors
    ///
    /// Applies the same recovery checks as
    /// [`Self::ensure_direct_representation_catalogue`] and rejects an active
    /// profile not explicitly named by either specification argument.
    pub fn ensure_direct_representation_catalogue_compatible_with(
        &self,
        frozen_specification: ObjectId,
        compatible_frozen_specifications: &[ObjectId],
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
            return self.repair_direct_coverage(
                &mut inner,
                frozen_specification,
                compatible_frozen_specifications,
                &excluded,
            );
        }
        let scheme = self.identity.scheme();
        let direct_profile = RepresentationStore::direct_profile_for(frozen_specification)?;
        let representations = {
            let DurableInner { files, index, .. } = &mut *inner;
            let files = live_files_mut(files)?;
            let requested = index
                .iter()
                .filter(|(object, _)| !excluded.contains(object))
                .map(|(object, location)| (*object, *location))
                .collect::<Vec<_>>();
            let mut objects = Vec::new();
            objects
                .try_reserve_exact(requested.len())
                .map_err(|_| DurableError::EncodingOverflow)?;
            visit_indexed_objects(
                &files.arena,
                &requested,
                ACTIVATION_READ_TARGET_BYTES,
                &self.identity,
                self.limits,
                |object, location, _record, payload| {
                    objects.push(DirectArenaObject::identify(
                        direct_profile,
                        object,
                        canonical_record_bytes(payload, scheme)?,
                        location,
                    )?);
                    Ok(())
                },
            )?;
            RepresentationStore::activate(
                &self.directory,
                &self.directory_capability,
                self.limits,
                frozen_specification,
                objects.into_iter().map(Ok),
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
        compatible_frozen_specifications: &[ObjectId],
        excluded: &BTreeSet<ObjectId>,
    ) -> Result<RepresentationStateId, DurableError> {
        let representations =
            inner
                .representations
                .as_ref()
                .ok_or(DurableError::InvalidRepresentationState(
                    "active representation store disappeared",
                ))?;
        let active_specification = representations.frozen_specification()?;
        if active_specification != frozen_specification
            && !compatible_frozen_specifications.contains(&active_specification)
        {
            return Err(DurableError::InvalidRepresentationState(
                "active direct profile names a different frozen specification",
            ));
        }
        if !excluded.contains(&active_specification)
            || !inner.index.contains_key(&active_specification)
        {
            return Err(DurableError::InvalidRepresentationState(
                "active direct profile specification is not a persisted bootstrap object",
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
                    let (_, payload) = read_indexed_object_with_payload(
                        &files.arena,
                        object,
                        location,
                        &self.identity,
                        self.limits,
                    )?;
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
    ) -> Result<Option<PendingRepresentationUpdate>, DurableError> {
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
        direct.extend(
            appended
                .iter()
                .filter(|object| seen.insert(object.object))
                .cloned(),
        );
        for (id, location) in pending_index_locations.iter().copied() {
            if !seen.insert(id) || representations.contains_direct(id) {
                continue;
            }
            let (_, payload) = read_indexed_object_with_payload(
                &files.arena,
                id,
                location,
                &self.identity,
                self.limits,
            )?;
            direct.push(representations.describe_direct(
                id,
                canonical_record_bytes(&payload, self.identity.scheme())?,
                location,
            )?);
        }
        representations.append_direct_update(&direct)
    }
}
