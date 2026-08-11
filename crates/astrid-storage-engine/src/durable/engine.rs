use super::{
    ARENA_FILE, ARENA_MAGIC, Arc, BTreeMap, BTreeSet, ClosureObjects, DurableEngine, DurableError,
    DurableInner, FaultPoint, InsertOutcome, LIFECYCLE_CLOSED, LIFECYCLE_REQUIRES_RECOVERY,
    LIFECYCLE_USABLE, ModelError, ObjectCacheStats, ObjectId, ObjectRecord,
    PersistentObjectIdentity, Prepared, PrincipalCodec, PrincipalUsage, ProjectionCacheEntry,
    ProjectionCacheKey, ROOT_FILE, RecoveryScope, RootGeneration, RootSnapshot, RootState,
    RootTransaction, append_frame, canonical_record_bytes, encode_object_frame, encode_root_record,
    ensure_payload_limit, io_error, live_files_mut, materialize_closure, read_indexed_object,
    read_indexed_objects, usage_from_closure, validate_incremental_closure,
};
use crate::{ProjectionObserver, ProjectionPhase};

impl<P, I, C> DurableEngine<P, I, C>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    /// Compute the logical identity of a canonical object.
    #[must_use]
    pub fn identify(&self, record: &ObjectRecord) -> ObjectId {
        self.identity.identify(record)
    }

    /// Return one immutable object through the principal-accounted decoded
    /// cache.
    ///
    /// Cache policy never changes read correctness. A bypass or miss performs
    /// the ordinary positional frame read and full validation before the
    /// resulting record can be retained.
    ///
    /// # Errors
    ///
    /// Returns a recovery error when authoritative reopen cannot complete, or
    /// a frame/identity error when the arena cannot supply the requested object.
    pub fn object_for(
        &self,
        principal: &P,
        id: ObjectId,
    ) -> Result<Option<ObjectRecord>, DurableError> {
        self.shared_object_for(principal, id)
            .map(|record| record.map(|record| record.as_ref().clone()))
    }

    /// Return one immutable object through the principal-accounted decoded
    /// cache without cloning its allocation.
    ///
    /// Cache policy never changes read correctness. A bypass or miss performs
    /// the ordinary positional frame read and full validation before the
    /// resulting record can be retained.
    ///
    /// # Errors
    ///
    /// Returns a recovery error when authoritative reopen cannot complete, or
    /// a frame/identity error when the arena cannot supply the requested object.
    pub fn shared_object_for(
        &self,
        principal: &P,
        id: ObjectId,
    ) -> Result<Option<Arc<ObjectRecord>>, DurableError> {
        let mut recovery = RecoveryScope::default();
        loop {
            self.ensure_cached_read_usable_with(&mut recovery)?;
            if let Some(record) = self.object_cache.get(principal, id) {
                return Ok(Some(record));
            }
            let (location, contiguous, generation) = {
                let inner = self.lock_usable_with(&mut recovery)?;
                let contiguous = match inner.representations.as_ref() {
                    Some(store) => store.open_contiguous_read(id)?,
                    None => None,
                };
                (
                    inner.index.get(&id).copied(),
                    contiguous,
                    inner.arena_generation,
                )
            };
            if location.is_none()
                && let Some((file, location)) = contiguous
            {
                let record = super::representations::read_contiguous_object(
                    file,
                    location,
                    id,
                    &self.identity,
                )?;
                if let Some(record) = self.retain_loaded_object_if_current_with(
                    principal,
                    id,
                    generation,
                    record,
                    &mut recovery,
                )? {
                    return Ok(Some(record));
                }
                continue;
            }
            let Some(location) = location else {
                return Ok(None);
            };
            let reader_guard = self.arena_reader.read();
            let Some(reader) = reader_guard.as_ref() else {
                return Err(DurableError::Closed);
            };
            if reader.generation != generation {
                continue;
            }
            let record =
                read_indexed_object(&reader.file, id, location, &self.identity, self.limits)?;
            drop(reader_guard);
            if let Some(record) = self.retain_loaded_object_if_current_with(
                principal,
                id,
                generation,
                record,
                &mut recovery,
            )? {
                return Ok(Some(record));
            }
        }
    }

    /// Return immutable objects in request order through the
    /// principal-accounted decoded cache.
    ///
    /// Cache misses are resolved from one index snapshot. Physically adjacent
    /// arena frames are read as one span and each frame retains its complete
    /// checksum, identity, and canonical decode validation.
    ///
    /// # Errors
    ///
    /// Returns a recovery error when authoritative reopen cannot complete, or
    /// a frame/identity error when the arena cannot supply a requested object.
    pub fn objects_for(
        &self,
        principal: &P,
        ids: &[ObjectId],
    ) -> Result<Vec<Option<ObjectRecord>>, DurableError> {
        self.shared_objects_for(principal, ids).map(|records| {
            records
                .into_iter()
                .map(|record| record.map(|record| record.as_ref().clone()))
                .collect()
        })
    }

    /// Return immutable objects in request order through shared cache
    /// allocations.
    ///
    /// Cache misses are resolved from one index snapshot. Physically adjacent
    /// arena frames are read as one span and each frame retains its complete
    /// checksum, identity, and canonical decode validation.
    ///
    /// # Errors
    ///
    /// Returns a recovery error when authoritative reopen cannot complete, or
    /// a frame/identity error when the arena cannot supply a requested object.
    pub fn shared_objects_for(
        &self,
        principal: &P,
        ids: &[ObjectId],
    ) -> Result<Vec<Option<Arc<ObjectRecord>>>, DurableError> {
        let mut recovery = RecoveryScope::default();
        self.ensure_cached_read_usable_with(&mut recovery)?;
        let mut results = vec![None; ids.len()];
        let mut missing = BTreeMap::<ObjectId, Vec<usize>>::new();
        for (index, id) in ids.iter().copied().enumerate() {
            if let Some(record) = self.object_cache.get(principal, id) {
                results[index] = Some(record);
            } else {
                missing.entry(id).or_default().push(index);
            }
        }
        if missing.is_empty() {
            return Ok(results);
        }

        loop {
            let (locations, contiguous, generation) = {
                let inner = self.lock_usable_with(&mut recovery)?;
                let locations = missing
                    .keys()
                    .filter_map(|id| inner.index.get(id).copied().map(|location| (*id, location)))
                    .collect::<Vec<_>>();
                let mut contiguous = Vec::new();
                if let Some(store) = inner.representations.as_ref() {
                    for id in missing.keys() {
                        if !inner.index.contains_key(id)
                            && let Some((file, location)) = store.open_contiguous_read(*id)?
                        {
                            contiguous.push((*id, file, location));
                        }
                    }
                }
                (locations, contiguous, inner.arena_generation)
            };
            let reader_guard = self.arena_reader.read();
            let Some(reader) = reader_guard.as_ref() else {
                return Err(DurableError::Closed);
            };
            if reader.generation != generation {
                continue;
            }
            let mut loaded =
                read_indexed_objects(&reader.file, &locations, &self.identity, self.limits)?;
            drop(reader_guard);
            for (id, file, location) in contiguous {
                loaded.insert(
                    id,
                    super::representations::read_contiguous_object(
                        file,
                        location,
                        id,
                        &self.identity,
                    )?,
                );
            }

            let inner = self.lock_usable_with(&mut recovery)?;
            if inner.arena_generation != generation
                || loaded.keys().any(|id| {
                    !inner.index.contains_key(id)
                        && !inner
                            .representations
                            .as_ref()
                            .is_some_and(|store| store.contains_contiguous(*id))
                })
            {
                continue;
            }
            for (id, record) in loaded {
                let cached = self.object_cache.insert(principal, id, record);
                if let Some(indices) = missing.get(&id) {
                    for index in indices {
                        results[*index] = Some(Arc::clone(&cached));
                    }
                }
            }
            return Ok(results);
        }
    }

    #[cfg(test)]
    pub(super) fn retain_loaded_object_if_current(
        &self,
        principal: &P,
        id: ObjectId,
        generation: u64,
        record: ObjectRecord,
    ) -> Result<Option<Arc<ObjectRecord>>, DurableError> {
        self.retain_loaded_object_if_current_with(
            principal,
            id,
            generation,
            record,
            &mut RecoveryScope::default(),
        )
    }

    fn retain_loaded_object_if_current_with(
        &self,
        principal: &P,
        id: ObjectId,
        generation: u64,
        record: ObjectRecord,
        recovery: &mut RecoveryScope,
    ) -> Result<Option<Arc<ObjectRecord>>, DurableError> {
        let inner = self.lock_usable_with(recovery)?;
        if inner.arena_generation != generation
            || (!inner.index.contains_key(&id)
                && !inner
                    .representations
                    .as_ref()
                    .is_some_and(|store| store.contains_contiguous(id)))
        {
            return Ok(None);
        }
        Ok(Some(self.object_cache.insert(principal, id, record)))
    }

    fn ensure_cached_read_usable(&self) -> Result<(), DurableError> {
        self.ensure_cached_read_usable_with(&mut RecoveryScope::default())
    }

    fn ensure_cached_read_usable_with(
        &self,
        recovery: &mut RecoveryScope,
    ) -> Result<(), DurableError> {
        match self.lifecycle.load(std::sync::atomic::Ordering::Acquire) {
            LIFECYCLE_USABLE => Ok(()),
            LIFECYCLE_CLOSED => Err(DurableError::Closed),
            _ => self.lock_usable_with(recovery).map(|_| ()),
        }
    }

    pub(super) fn mark_requires_recovery(&self, inner: &mut DurableInner<P>) {
        inner.poisoned = true;
        self.lifecycle.store(
            LIFECYCLE_REQUIRES_RECOVERY,
            std::sync::atomic::Ordering::Release,
        );
    }

    /// Return privileged cache diagnostics.
    #[must_use]
    pub fn object_cache_stats(&self) -> ObjectCacheStats {
        self.object_cache.stats()
    }

    /// Return the bytes currently charged to one principal.
    ///
    /// This is kernel/operator accounting and must not be exposed to guests,
    /// because cache residency is a performance detail.
    #[must_use]
    pub fn object_cache_principal_charge(&self, principal: &P) -> u64 {
        self.object_cache.principal_charge(principal)
    }

    /// Evict decoded objects until the latest external memory targets hold.
    ///
    /// Cache exhaustion never changes authoritative reads; discarded entries
    /// are reconstructed and verified from the arena on demand.
    pub fn reclaim_object_cache(&self) {
        self.object_cache.reclaim();
    }

    /// Load one projection-owned process-local accelerator from governed
    /// cache memory.
    ///
    /// A disabled budget, eviction, missing object association, or type
    /// mismatch returns `None`. The authoritative object path is unaffected.
    #[must_use]
    pub fn projection_cache(
        &self,
        principal: &P,
        object: ObjectId,
        key: ProjectionCacheKey,
    ) -> Option<ProjectionCacheEntry> {
        self.ensure_cached_read_usable().ok()?;
        self.object_cache.projection(principal, object, key)
    }

    /// Retain one projection-owned process-local accelerator under the same
    /// total and per-principal budgets as decoded immutable objects.
    ///
    /// Returns `false` when policy declines retention. Projection correctness
    /// must not depend on this value remaining resident.
    pub fn retain_projection_cache(
        &self,
        principal: &P,
        object: ObjectId,
        key: ProjectionCacheKey,
        value: ProjectionCacheEntry,
    ) -> bool {
        if self.ensure_cached_read_usable().is_err() {
            return false;
        }
        self.object_cache
            .retain_projection(principal, object, key, value)
    }

    /// Discard one projection-owned accelerator and release its cache charge.
    pub fn discard_projection_cache(
        &self,
        principal: &P,
        object: ObjectId,
        key: ProjectionCacheKey,
    ) -> bool {
        if self.ensure_cached_read_usable().is_err() {
            return false;
        }
        self.object_cache.discard_projection(principal, object, key)
    }

    /// Persist one standalone immutable object outside a principal root.
    ///
    /// This narrow path exists for store-level bootstrap evidence referenced
    /// by `store.meta`, such as the in-band format specification. The object
    /// must not own another object; graph publication remains a root
    /// transaction. Successful insertion flushes the arena before returning.
    ///
    /// # Errors
    ///
    /// Returns a model, encoding, I/O, recovery-required, or bootstrap-shape
    /// error. An I/O failure poisons this engine instance.
    pub fn persist_standalone_object(
        &self,
        record: &ObjectRecord,
    ) -> Result<(ObjectId, InsertOutcome), DurableError> {
        if record.owning_references().next().is_some() {
            return Err(DurableError::BootstrapObjectOwnsState);
        }
        let id = self.identify(record);
        let mut inner = self.lock_usable()?;
        if let Some(location) = inner.index.get(&id).copied() {
            return self.persist_existing_standalone(&mut inner, id, location, record);
        }
        self.persist_new_standalone(&mut inner, id, record)
    }

    fn persist_existing_standalone(
        &self,
        inner: &mut DurableInner<P>,
        id: ObjectId,
        location: super::ArenaLocation,
        record: &ObjectRecord,
    ) -> Result<(ObjectId, InsertOutcome), DurableError> {
        let (existing, needs_flush) = {
            let files = live_files_mut(&mut inner.files)?;
            let existing =
                read_indexed_object(&files.arena, id, location, &self.identity, self.limits)?;
            (existing, location.offset >= files.arena_len)
        };
        if &existing != record {
            return Err(ModelError::ObjectCollision(id).into());
        }
        let payload = encode_object_frame(self.identity.scheme(), id, &existing)?;
        let appended = if let Some(representations) = &inner.representations
            && !representations.contains_direct(id)
        {
            vec![representations.describe_direct(
                id,
                canonical_record_bytes(&payload, self.identity.scheme())?,
                location,
            )?]
        } else {
            Vec::new()
        };
        let representation_update = match self.append_pending_direct_update(inner, &appended) {
            Ok(update) => update,
            Err(error) => {
                self.mark_requires_recovery(inner);
                return Err(error);
            },
        };
        if needs_flush || representation_update.is_some() {
            let persisted = Self::flush_standalone(inner, representation_update);
            match persisted {
                Ok(arena_len) if needs_flush => {
                    if let Err(error) = self.advance_index_frontier(inner, arena_len) {
                        self.mark_requires_recovery(inner);
                        return Err(error);
                    }
                },
                Ok(_) => {},
                Err(error) => {
                    self.mark_requires_recovery(inner);
                    return Err(error);
                },
            }
        }
        Ok((id, InsertOutcome::AlreadyPresent))
    }

    fn persist_new_standalone(
        &self,
        inner: &mut DurableInner<P>,
        id: ObjectId,
        record: &ObjectRecord,
    ) -> Result<(ObjectId, InsertOutcome), DurableError> {
        let payload = encode_object_frame(self.identity.scheme(), id, record)?;
        ensure_payload_limit(ARENA_FILE, 0, payload.len(), self.limits)?;
        let previous_arena_len = live_files_mut(&mut inner.files)?.arena_len;
        let location = match (|| {
            let files = live_files_mut(&mut inner.files)?;
            append_frame(&mut files.arena, ARENA_MAGIC, &payload)
        })() {
            Ok(location) => location,
            Err(error) => {
                self.mark_requires_recovery(inner);
                return Err(error);
            },
        };
        let appended = if let Some(representations) = &inner.representations {
            vec![representations.describe_direct(
                id,
                canonical_record_bytes(&payload, self.identity.scheme())?,
                location,
            )?]
        } else {
            Vec::new()
        };
        let representation_update = match self.append_pending_direct_update(inner, &appended) {
            Ok(update) => update,
            Err(error) => {
                self.mark_requires_recovery(inner);
                return Err(error);
            },
        };
        let arena_len = match Self::flush_standalone(inner, representation_update) {
            Ok(arena_len) => arena_len,
            Err(error) => {
                self.mark_requires_recovery(inner);
                return Err(error);
            },
        };
        inner.index.insert(id, location);
        inner.pending_index_locations.push((id, location));
        inner.validated.insert(id);
        debug_assert_eq!(
            previous_arena_len,
            live_files_mut(&mut inner.files)?.arena_len
        );
        if let Err(error) = self.advance_index_frontier(inner, arena_len) {
            self.mark_requires_recovery(inner);
            return Err(error);
        }
        Ok((id, InsertOutcome::Inserted))
    }

    pub(super) fn flush_standalone(
        inner: &mut DurableInner<P>,
        representation_update: Option<super::representations::PendingRepresentationUpdate>,
    ) -> Result<u64, DurableError> {
        let DurableInner {
            files,
            representations,
            ..
        } = inner;
        let files = live_files_mut(files)?;
        files
            .arena
            .sync_data()
            .map_err(|source| io_error("flush standalone object frame", source))?;
        if let (Some(representations), Some(update)) = (representations, representation_update) {
            representations.publish_direct_update(update)?;
        }
        files
            .arena
            .metadata()
            .map_err(|source| io_error("read standalone arena metadata", source))
            .map(|metadata| metadata.len())
    }

    /// Return the current durable root for one principal.
    ///
    /// # Errors
    ///
    /// Returns a recovery error when authoritative reopen cannot complete.
    pub fn root(&self, principal: &P) -> Result<Option<RootState>, DurableError> {
        let inner = self.lock_usable()?;
        Ok(inner.roots_by_principal.get(principal).copied())
    }

    /// Return a consistent copy of every current principal root.
    ///
    /// This is a privileged maintenance surface for ordered store migrations,
    /// compaction, and operator diagnostics. Projection APIs must continue to
    /// address one authorized principal at a time.
    ///
    /// # Errors
    ///
    /// Returns a recovery error when authoritative reopen cannot complete.
    pub fn roots(&self) -> Result<Vec<(P, RootState)>, DurableError> {
        let inner = self.lock_usable()?;
        Ok(inner
            .roots_by_principal
            .iter()
            .map(|(principal, root)| (principal.clone(), *root))
            .collect())
    }

    /// Capture one current root and its complete owning closure.
    ///
    /// # Errors
    ///
    /// Returns an authoritative recovery or graph-validation error.
    pub fn snapshot(&self, principal: &P) -> Result<Option<RootSnapshot>, DurableError> {
        let mut inner = self.lock_usable()?;
        let Some(root) = inner.roots_by_principal.get(principal).copied() else {
            return Ok(None);
        };
        let DurableInner {
            files,
            index,
            representations,
            ..
        } = &mut *inner;
        let files = live_files_mut(files)?;
        let records = materialize_closure(
            &mut ClosureObjects {
                arena: &mut files.arena,
                index,
                incoming: &BTreeMap::new(),
                representations: representations.as_ref(),
                identity: &self.identity,
                limits: self.limits,
            },
            root.commit,
        )?;
        Ok(Some(RootSnapshot { root, records }))
    }

    /// Calculate stable logical usage for one principal.
    ///
    /// # Errors
    ///
    /// Returns a recovery, missing-principal, graph, or arithmetic
    /// error.
    pub fn principal_usage(&self, principal: &P) -> Result<PrincipalUsage, DurableError> {
        let mut inner = self.lock_usable()?;
        let root = inner
            .roots_by_principal
            .get(principal)
            .copied()
            .ok_or(ModelError::PrincipalMissing)?;
        let DurableInner {
            files,
            index,
            representations,
            ..
        } = &mut *inner;
        let files = live_files_mut(files)?;
        let records = materialize_closure(
            &mut ClosureObjects {
                arena: &mut files.arena,
                index,
                incoming: &BTreeMap::new(),
                representations: representations.as_ref(),
                identity: &self.identity,
                limits: self.limits,
            },
            root.commit,
        )?;
        usage_from_closure(&records, root.commit).map_err(Into::into)
    }

    pub(super) fn prepare(
        &self,
        inner: &mut DurableInner<P>,
        transaction: RootTransaction<P>,
        pending_roots: &BTreeMap<P, RootState>,
        observer: Option<&dyn ProjectionObserver>,
    ) -> Result<Prepared<P>, DurableError> {
        let RootTransaction {
            principal,
            expected,
            commit: commit_id,
            records,
        } = transaction;
        for (declared, record) in &records {
            let computed = self.identify(record);
            if computed != *declared {
                return Err(ModelError::ObjectIdentityMismatch {
                    declared: *declared,
                    computed,
                }
                .into());
            }
        }
        let actual = pending_roots
            .get(&principal)
            .copied()
            .or_else(|| inner.roots_by_principal.get(&principal).copied());
        if actual != expected {
            return Err(ModelError::RootConflict { expected, actual }.into());
        }
        let generation = match actual {
            Some(root) => root
                .generation
                .checked_next()
                .ok_or(ModelError::ArithmeticOverflow)?,
            None => RootGeneration::INITIAL,
        };
        let root = RootState {
            generation,
            commit: commit_id,
        };

        let mut unique = BTreeMap::new();
        for (id, record) in records {
            match unique.get(&id) {
                Some(existing) if existing == &record => {},
                Some(_) => return Err(ModelError::ObjectCollision(id).into()),
                None => {
                    unique.insert(id, record);
                },
            }
        }
        let closure_started = std::time::Instant::now();
        let reachable = self.validate_pending_closure(inner, &unique, commit_id);
        if let Some(observer) = observer {
            observer.record(
                ProjectionPhase::ClosureValidation,
                closure_started.elapsed(),
            );
        }
        let reachable = reachable?;

        let mut objects = Vec::new();
        let mut commit_frame = None;
        for (id, record) in unique {
            if !reachable.contains(&id) {
                continue;
            }
            if let Some(location) = inner.index.get(&id).copied() {
                let files = live_files_mut(&mut inner.files)?;
                let existing =
                    read_indexed_object(&files.arena, id, location, &self.identity, self.limits)?;
                if existing != record {
                    return Err(ModelError::ObjectCollision(id).into());
                }
                continue;
            }
            let payload: Arc<[u8]> =
                encode_object_frame(self.identity.scheme(), id, &record)?.into();
            ensure_payload_limit(ARENA_FILE, 0, payload.len(), self.limits)?;
            if id == commit_id {
                commit_frame = Some((id, payload));
            } else {
                objects.push((id, payload));
            }
        }
        let principal_bytes = self.principal_codec.encode(&principal);
        let journal = encode_root_record(self.identity.scheme(), &principal_bytes, expected, root)?;
        ensure_payload_limit(ROOT_FILE, 0, journal.len(), self.limits)?;

        Ok(Prepared {
            principal,
            root,
            objects_inserted: u64::try_from(objects.len())
                .map_err(|_| ModelError::ArithmeticOverflow)?
                .checked_add(u64::from(commit_frame.is_some()))
                .ok_or(ModelError::ArithmeticOverflow)?,
            objects,
            commit: commit_frame,
            journal,
            validated: reachable,
        })
    }

    pub(super) fn validate_pending_closure(
        &self,
        inner: &mut DurableInner<P>,
        incoming: &BTreeMap<ObjectId, ObjectRecord>,
        commit: ObjectId,
    ) -> Result<BTreeSet<ObjectId>, DurableError> {
        let DurableInner {
            files,
            index,
            validated,
            representations,
            ..
        } = inner;
        let files = live_files_mut(files)?;
        validate_incremental_closure(
            &mut ClosureObjects {
                arena: &mut files.arena,
                index,
                incoming,
                representations: representations.as_ref(),
                identity: &self.identity,
                limits: self.limits,
            },
            validated,
            commit,
        )
    }

    pub(super) fn fail_if(&self, point: FaultPoint) -> Result<(), DurableError> {
        if self.faults.should_fail(point) {
            return Err(DurableError::FaultInjected(point));
        }
        Ok(())
    }
}
