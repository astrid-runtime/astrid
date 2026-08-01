use super::{
    ARENA_FILE, ARENA_MAGIC, Arc, ArenaReader, BTreeMap, BTreeSet, CommitOutcome, DurableEngine,
    DurableError, DurableFiles, DurableInner, FaultInjector, FaultPoint, FileExt, INDEX_FILE,
    IndexState, InsertOutcome, LOCK_FILE, ModelError, Mutex, NoFaults, ObjectCache,
    ObjectCacheConfig, ObjectCacheStats, ObjectId, ObjectRecord, Path, Persisted,
    PersistentObjectIdentity, Prepared, PrincipalCodec, PrincipalUsage, ProjectionCacheEntry,
    ProjectionCacheKey, ROOT_FILE, ROOT_MAGIC, RecoveryLimits, RootGeneration, RootSnapshot,
    RootState, RootTransaction, RwLock, Seek, SeekFrom, append_frame, encode_object_frame,
    encode_root_record, ensure_payload_limit, ensure_usable, io, io_error, live_files_mut,
    materialize_closure, open_rw, read_indexed_object, read_indexed_objects, recover_arena,
    recover_index, recover_interrupted_compaction, recover_roots, replace_index,
    sync_store_directory, usage_from_closure, validate_incremental_closure,
};

impl<P, I, C> DurableEngine<P, I, C>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    /// Open or create a durable store with no injected faults.
    ///
    /// # Errors
    ///
    /// Returns an I/O, lock, frame, identity, principal-codec, or model
    /// recovery error. An incomplete or physically invalid final frame is
    /// treated as an uncommitted tail only when no valid frame follows it;
    /// semantic invalidity and interior corruption remain fatal.
    pub fn open(
        path: impl AsRef<Path>,
        identity: I,
        principal_codec: C,
        limits: RecoveryLimits,
    ) -> Result<Self, DurableError> {
        Self::open_with_options(
            path,
            identity,
            principal_codec,
            limits,
            Arc::new(NoFaults),
            ObjectCacheConfig::disabled(),
        )
    }

    /// Open or create a durable store with an explicitly governed decoded
    /// object cache.
    ///
    /// The engine never selects a hidden default cache ceiling. The embedding
    /// runtime owns both the live total controller and per-principal budget.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::open`].
    pub fn open_with_object_cache(
        path: impl AsRef<Path>,
        identity: I,
        principal_codec: C,
        limits: RecoveryLimits,
        object_cache: ObjectCacheConfig<P>,
    ) -> Result<Self, DurableError> {
        Self::open_with_options(
            path,
            identity,
            principal_codec,
            limits,
            Arc::new(NoFaults),
            object_cache,
        )
    }

    /// Open or create a durable store with an explicit fault injector.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::open`].
    pub fn open_with_faults(
        path: impl AsRef<Path>,
        identity: I,
        principal_codec: C,
        limits: RecoveryLimits,
        faults: Arc<dyn FaultInjector>,
    ) -> Result<Self, DurableError> {
        Self::open_with_options(
            path,
            identity,
            principal_codec,
            limits,
            faults,
            ObjectCacheConfig::disabled(),
        )
    }

    fn open_with_options(
        path: impl AsRef<Path>,
        identity: I,
        principal_codec: C,
        limits: RecoveryLimits,
        faults: Arc<dyn FaultInjector>,
        object_cache: ObjectCacheConfig<P>,
    ) -> Result<Self, DurableError> {
        let path = path.as_ref().to_path_buf();
        std::fs::create_dir_all(&path)
            .map_err(|source| io_error("create principal-store directory", source))?;
        let lock_path = path.join(LOCK_FILE);
        let lock = open_rw(&lock_path)?;
        if let Err(source) = lock.try_lock_exclusive() {
            if source.kind() == io::ErrorKind::WouldBlock {
                return Err(DurableError::LockHeld(lock_path));
            }
            return Err(io_error("lock principal store", source));
        }

        recover_interrupted_compaction(&path, &principal_codec, &identity, limits)?;
        let mut arena = open_rw(&path.join(ARENA_FILE))?;
        let mut roots = open_rw(&path.join(ROOT_FILE))?;
        let mut index_cache = open_rw(&path.join(INDEX_FILE)).ok();
        sync_store_directory(&path)?;
        let scheme = identity.scheme();
        let arena_len = arena
            .metadata()
            .map_err(|source| io_error("read object-arena metadata", source))?
            .len();
        let cached = index_cache
            .as_mut()
            .and_then(|file| recover_index(file, &mut arena, scheme, limits, arena_len));
        let (index, arena_tail) = if let Some(state) = cached {
            (state.objects, state.arena_tail)
        } else {
            let (index, arena_tail) = recover_arena(&mut arena, &identity, limits)?;
            let state = IndexState {
                arena_len: arena
                    .metadata()
                    .map_err(|source| io_error("read recovered arena metadata", source))?
                    .len(),
                arena_tail,
                objects: index,
            };
            drop(index_cache.take());
            index_cache = replace_index(&path, &state, scheme);
            (state.objects, state.arena_tail)
        };
        let (roots_by_principal, validated) = recover_roots(
            &mut roots,
            &mut arena,
            &index,
            &principal_codec,
            &identity,
            limits,
        )?;
        let arena_len = arena
            .metadata()
            .map_err(|source| io_error("read recovered arena metadata", source))?
            .len();
        arena
            .seek(SeekFrom::End(0))
            .map_err(|source| io_error("seek object arena", source))?;
        roots
            .seek(SeekFrom::End(0))
            .map_err(|source| io_error("seek root journal", source))?;
        let arena_reader = arena
            .try_clone()
            .map_err(|source| io_error("clone object arena for positional reads", source))?;

        Ok(Self {
            directory: path,
            identity,
            principal_codec,
            limits,
            faults,
            arena_reader: RwLock::new(ArenaReader {
                file: arena_reader,
                generation: 0,
            }),
            object_cache: ObjectCache::new(object_cache),
            inner: Mutex::new(DurableInner {
                roots_by_principal,
                index,
                pending_index_locations: Vec::new(),
                validated,
                files: Some(DurableFiles {
                    arena,
                    roots,
                    index_cache,
                    arena_len,
                    arena_tail,
                }),
                lock: Some(lock),
                poisoned: false,
                arena_generation: 0,
            }),
        })
    }

    /// Compute the logical identity of a canonical object.
    #[must_use]
    pub fn identify(&self, record: &ObjectRecord) -> ObjectId {
        self.identity.identify(record)
    }

    /// Return the number of recovered immutable objects.
    ///
    /// # Errors
    ///
    /// Returns [`DurableError::RequiresRecovery`] after a failed write.
    pub fn object_count(&self) -> Result<usize, DurableError> {
        let inner = self.inner.lock();
        ensure_usable(&inner)?;
        Ok(inner.index.len())
    }

    /// Return one recovered immutable object.
    ///
    /// # Errors
    ///
    /// Returns [`DurableError::RequiresRecovery`] after a failed write.
    pub fn object(&self, id: ObjectId) -> Result<Option<ObjectRecord>, DurableError> {
        loop {
            let (location, generation) = {
                let inner = self.inner.lock();
                ensure_usable(&inner)?;
                let Some(location) = inner.index.get(&id).copied() else {
                    return Ok(None);
                };
                (location, inner.arena_generation)
            };
            let reader = self.arena_reader.read();
            if reader.generation != generation {
                continue;
            }
            return read_indexed_object(&reader.file, id, location, &self.identity, self.limits)
                .map(Some);
        }
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
    /// Returns [`DurableError::RequiresRecovery`] after a failed write, or a
    /// frame/identity error when the arena cannot supply the requested object.
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
    /// Returns [`DurableError::RequiresRecovery`] after a failed write, or a
    /// frame/identity error when the arena cannot supply the requested object.
    pub fn shared_object_for(
        &self,
        principal: &P,
        id: ObjectId,
    ) -> Result<Option<Arc<ObjectRecord>>, DurableError> {
        if let Some(record) = self.object_cache.get(principal, id) {
            return Ok(Some(record));
        }
        let Some(record) = self.object(id)? else {
            return Ok(None);
        };
        let record = self.object_cache.insert(principal, id, record);
        Ok(Some(record))
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
    /// Returns [`DurableError::RequiresRecovery`] after a failed write, or a
    /// frame/identity error when the arena cannot supply a requested object.
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
    /// Returns [`DurableError::RequiresRecovery`] after a failed write, or a
    /// frame/identity error when the arena cannot supply a requested object.
    pub fn shared_objects_for(
        &self,
        principal: &P,
        ids: &[ObjectId],
    ) -> Result<Vec<Option<Arc<ObjectRecord>>>, DurableError> {
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

        let loaded = loop {
            let (locations, generation) = {
                let inner = self.inner.lock();
                ensure_usable(&inner)?;
                let locations = missing
                    .keys()
                    .filter_map(|id| inner.index.get(id).copied().map(|location| (*id, location)))
                    .collect::<Vec<_>>();
                (locations, inner.arena_generation)
            };
            let reader = self.arena_reader.read();
            if reader.generation != generation {
                continue;
            }
            break read_indexed_objects(&reader.file, &locations, &self.identity, self.limits)?;
        };
        for (id, record) in loaded {
            let cached = self.object_cache.insert(principal, id, record);
            if let Some(indices) = missing.get(&id) {
                for index in indices {
                    results[*index] = Some(Arc::clone(&cached));
                }
            }
        }
        Ok(results)
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
        let mut inner = self.inner.lock();
        ensure_usable(&inner)?;
        if let Some(location) = inner.index.get(&id).copied() {
            let (existing, needs_flush) = {
                let files = live_files_mut(&mut inner.files)?;
                let existing =
                    read_indexed_object(&files.arena, id, location, &self.identity, self.limits)?;
                (existing, location.offset >= files.arena_len)
            };
            if &existing != record {
                return Err(ModelError::ObjectCollision(id).into());
            }
            if needs_flush {
                let persisted = {
                    let files = live_files_mut(&mut inner.files)?;
                    (|| {
                        files
                            .arena
                            .sync_data()
                            .map_err(|source| io_error("flush standalone object frame", source))?;
                        files
                            .arena
                            .metadata()
                            .map_err(|source| io_error("read standalone arena metadata", source))
                            .map(|metadata| metadata.len())
                    })()
                };
                match persisted {
                    Ok(arena_len) => {
                        if let Err(error) = self.advance_index_frontier(&mut inner, arena_len) {
                            inner.poisoned = true;
                            return Err(error);
                        }
                    },
                    Err(error) => {
                        inner.poisoned = true;
                        return Err(error);
                    },
                }
            }
            return Ok((id, InsertOutcome::AlreadyPresent));
        }
        let payload = encode_object_frame(self.identity.scheme(), id, record)?;
        ensure_payload_limit(ARENA_FILE, 0, payload.len(), self.limits)?;
        let (previous_arena_len, persisted) = {
            let files = live_files_mut(&mut inner.files)?;
            let previous_arena_len = files.arena_len;
            let persisted = (|| {
                let location = append_frame(&mut files.arena, ARENA_MAGIC, &payload)?;
                files
                    .arena
                    .sync_data()
                    .map_err(|source| io_error("flush standalone object frame", source))?;
                let arena_len = files
                    .arena
                    .metadata()
                    .map_err(|source| io_error("read standalone arena metadata", source))?
                    .len();
                Ok((location, arena_len))
            })();
            (previous_arena_len, persisted)
        };
        match persisted {
            Ok((location, arena_len)) => {
                inner.index.insert(id, location);
                inner.pending_index_locations.push((id, location));
                inner.validated.insert(id);
                debug_assert_eq!(
                    previous_arena_len,
                    live_files_mut(&mut inner.files)?.arena_len
                );
                if let Err(error) = self.advance_index_frontier(&mut inner, arena_len) {
                    inner.poisoned = true;
                    return Err(error);
                }
                Ok((id, InsertOutcome::Inserted))
            },
            Err(error) => {
                inner.poisoned = true;
                Err(error)
            },
        }
    }

    /// Return the current durable root for one principal.
    ///
    /// # Errors
    ///
    /// Returns [`DurableError::RequiresRecovery`] after a failed write.
    pub fn root(&self, principal: &P) -> Result<Option<RootState>, DurableError> {
        let inner = self.inner.lock();
        ensure_usable(&inner)?;
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
    /// Returns [`DurableError::RequiresRecovery`] after a failed write.
    pub fn roots(&self) -> Result<Vec<(P, RootState)>, DurableError> {
        let inner = self.inner.lock();
        ensure_usable(&inner)?;
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
    /// Returns a recovery-required or graph-validation error.
    pub fn snapshot(&self, principal: &P) -> Result<Option<RootSnapshot>, DurableError> {
        let mut inner = self.inner.lock();
        ensure_usable(&inner)?;
        let Some(root) = inner.roots_by_principal.get(principal).copied() else {
            return Ok(None);
        };
        let DurableInner { files, index, .. } = &mut *inner;
        let files = live_files_mut(files)?;
        let records = materialize_closure(
            &mut files.arena,
            index,
            &BTreeMap::new(),
            root.commit,
            &self.identity,
            self.limits,
        )?;
        Ok(Some(RootSnapshot { root, records }))
    }

    /// Calculate stable logical usage for one principal.
    ///
    /// # Errors
    ///
    /// Returns a recovery-required, missing-principal, graph, or arithmetic
    /// error.
    pub fn principal_usage(&self, principal: &P) -> Result<PrincipalUsage, DurableError> {
        let mut inner = self.inner.lock();
        ensure_usable(&inner)?;
        let root = inner
            .roots_by_principal
            .get(principal)
            .copied()
            .ok_or(ModelError::PrincipalMissing)?;
        let DurableInner { files, index, .. } = &mut *inner;
        let files = live_files_mut(files)?;
        let records = materialize_closure(
            &mut files.arena,
            index,
            &BTreeMap::new(),
            root.commit,
            &self.identity,
            self.limits,
        )?;
        usage_from_closure(&records, root.commit).map_err(Into::into)
    }

    /// Persist a complete immutable transaction and publish its root.
    ///
    /// Known-stale transactions and all model/encoding errors are rejected
    /// before any bytes are appended. Once I/O starts, any error poisons this
    /// instance; drop and reopen it so recovery can reconcile disk state.
    ///
    /// # Errors
    ///
    /// Returns an identity, collision, graph, root-conflict, encoding, I/O, or
    /// injected-fault error. A returned I/O/fault error requires reopen.
    pub fn commit(&self, transaction: RootTransaction<P>) -> Result<CommitOutcome, DurableError> {
        let mut inner = self.inner.lock();
        ensure_usable(&inner)?;
        let prepared = self.prepare(&mut inner, transaction)?;
        let previous_arena_len = live_files_mut(&mut inner.files)?.arena_len;
        match self.persist(&mut inner, &prepared) {
            Ok(persisted) => {
                for location in persisted.locations {
                    inner.index.insert(location.0, location.1);
                    inner.pending_index_locations.push(location);
                }
                inner.validated.extend(prepared.validated.iter().copied());
                inner
                    .roots_by_principal
                    .insert(prepared.principal.clone(), prepared.root);
                debug_assert_eq!(
                    previous_arena_len,
                    live_files_mut(&mut inner.files)?.arena_len
                );
                if let Err(error) = self.advance_index_frontier(&mut inner, persisted.arena_len) {
                    inner.poisoned = true;
                    return Err(error);
                }
                Ok(CommitOutcome {
                    root: prepared.root,
                    objects_inserted: prepared.objects_inserted,
                })
            },
            Err(error) => {
                inner.poisoned = true;
                Err(error)
            },
        }
    }

    fn prepare(
        &self,
        inner: &mut DurableInner<P>,
        transaction: RootTransaction<P>,
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
        let actual = inner.roots_by_principal.get(&principal).copied();
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
        let reachable = self.validate_pending_closure(inner, &unique, commit_id)?;

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
            let payload = encode_object_frame(self.identity.scheme(), id, &record)?;
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
            ..
        } = inner;
        let files = live_files_mut(files)?;
        validate_incremental_closure(
            &mut files.arena,
            index,
            incoming,
            validated,
            commit,
            &self.identity,
            self.limits,
        )
    }

    fn persist(
        &self,
        inner: &mut DurableInner<P>,
        prepared: &Prepared<P>,
    ) -> Result<Persisted, DurableError> {
        let files = live_files_mut(&mut inner.files)?;
        let mut locations = Vec::new();
        for (id, payload) in &prepared.objects {
            let location = append_frame(&mut files.arena, ARENA_MAGIC, payload)?;
            locations.push((*id, location));
        }
        self.fail_if(FaultPoint::AfterObjectAppend)?;
        if let Some((id, payload)) = &prepared.commit {
            let location = append_frame(&mut files.arena, ARENA_MAGIC, payload)?;
            locations.push((*id, location));
        }
        self.fail_if(FaultPoint::AfterCommitAppend)?;
        files
            .arena
            .sync_data()
            .map_err(|source| io_error("flush transaction object frames", source))?;
        self.fail_if(FaultPoint::AfterObjectFlush)?;
        self.fail_if(FaultPoint::AfterCommitFlush)?;
        self.fail_if(FaultPoint::BeforeRootCas)?;

        append_frame(&mut files.roots, ROOT_MAGIC, &prepared.journal)?;
        files
            .roots
            .sync_data()
            .map_err(|source| io_error("flush root-journal frame", source))?;
        self.fail_if(FaultPoint::AfterRootCas)?;
        let arena_len = files
            .arena
            .metadata()
            .map_err(|source| io_error("read committed arena metadata", source))?
            .len();
        Ok(Persisted {
            locations,
            arena_len,
        })
    }

    pub(super) fn fail_if(&self, point: FaultPoint) -> Result<(), DurableError> {
        if self.faults.should_fail(point) {
            return Err(DurableError::FaultInjected(point));
        }
        Ok(())
    }
}
