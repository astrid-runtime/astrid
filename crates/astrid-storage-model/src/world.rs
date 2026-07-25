//! In-memory executable world for principal-store operations.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;

use super::{
    BlobId, GcReport, InsertOutcome, ModelError, ObjectClass, ObjectId, ObjectKind, ObjectRecord,
    PinId, PlacementEpoch, PrincipalUsage, ReplicaCount, RepresentationOutcome, RootGeneration,
    RootState, StorageNodeId,
};

/// In-memory reference world for principal-store operations.
///
/// `P` is the integration layer's principal identifier. The model requires
/// stable ordering only; it does not prescribe Astrid's public principal wire
/// representation.
#[derive(Clone, Debug)]
pub struct World<P: Ord> {
    objects: BTreeMap<ObjectId, ObjectRecord>,
    representations: BTreeMap<BlobId, ObjectId>,
    roots: BTreeMap<P, RootState>,
    pins: BTreeMap<PinId, ObjectId>,
    placement_epochs: BTreeSet<PlacementEpoch>,
    placements: BTreeMap<(PlacementEpoch, BlobId), BTreeSet<StorageNodeId>>,
    active_placement_epoch: Option<PlacementEpoch>,
}

impl<P: Ord> Default for World<P> {
    fn default() -> Self {
        Self {
            objects: BTreeMap::new(),
            representations: BTreeMap::new(),
            roots: BTreeMap::new(),
            pins: BTreeMap::new(),
            placement_epochs: BTreeSet::new(),
            placements: BTreeMap::new(),
            active_placement_epoch: None,
        }
    }
}

impl<P: Ord> World<P> {
    /// Construct an empty model world.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the number of immutable objects held by the world.
    #[must_use]
    pub fn object_count(&self) -> usize {
        self.objects.len()
    }

    /// Borrow one immutable object by its logical identifier.
    #[must_use]
    pub fn object(&self, id: ObjectId) -> Option<&ObjectRecord> {
        self.objects.get(&id)
    }

    /// Return the current root for `principal`.
    #[must_use]
    pub fn root(&self, principal: &P) -> Option<RootState> {
        self.roots.get(principal).copied()
    }

    /// Insert an immutable object.
    ///
    /// Re-inserting an identical record is idempotent. Reusing an identifier
    /// for any different record is a fatal collision.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::ObjectCollision`] when an existing identifier has
    /// different canonical content.
    pub fn insert_object(
        &mut self,
        id: ObjectId,
        record: ObjectRecord,
    ) -> Result<InsertOutcome, ModelError> {
        match self.objects.get(&id) {
            Some(existing) if existing == &record => Ok(InsertOutcome::AlreadyPresent),
            Some(_) => Err(ModelError::ObjectCollision(id)),
            None => {
                self.objects.insert(id, record);
                Ok(InsertOutcome::Inserted)
            },
        }
    }

    /// Register an encoded physical blob as a representation of a logical
    /// object.
    ///
    /// A logical object may have several blobs. A blob may represent only one
    /// logical object.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::MissingObject`] when the logical object is absent
    /// or [`ModelError::BlobCollision`] when the blob is already assigned to
    /// different content.
    pub fn register_representation(
        &mut self,
        object: ObjectId,
        blob: BlobId,
    ) -> Result<RepresentationOutcome, ModelError> {
        if !self.objects.contains_key(&object) {
            return Err(ModelError::MissingObject(object));
        }
        match self.representations.get(&blob) {
            Some(existing) if *existing == object => Ok(RepresentationOutcome::AlreadyPresent),
            Some(_) => Err(ModelError::BlobCollision(blob)),
            None => {
                self.representations.insert(blob, object);
                Ok(RepresentationOutcome::Registered)
            },
        }
    }

    /// Calculate the complete, cycle-free closure rooted at `root`.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::MissingObject`] for an incomplete graph or
    /// [`ModelError::ObjectCycle`] for a cyclic graph.
    pub fn closure(&self, root: ObjectId) -> Result<BTreeSet<ObjectId>, ModelError> {
        closure_in(&self.objects, root)
    }

    /// Atomically install a principal's root using compare-and-swap semantics.
    ///
    /// `expected = None` creates a new principal at generation zero.
    /// Updating an existing principal requires its exact current root. The
    /// complete commit closure is validated before any visible root mutation.
    ///
    /// # Errors
    ///
    /// Returns a graph-validation error, root conflict, or generation
    /// overflow without changing the visible root.
    pub fn compare_and_swap_root(
        &mut self,
        principal: P,
        expected: Option<RootState>,
        commit: ObjectId,
    ) -> Result<RootState, ModelError> {
        let actual = self.roots.get(&principal).copied();
        if actual != expected {
            return Err(ModelError::RootConflict { expected, actual });
        }
        let record = self
            .objects
            .get(&commit)
            .ok_or(ModelError::MissingObject(commit))?;
        if record.kind() != ObjectKind::Commit {
            return Err(ModelError::RootNotCommit {
                object: commit,
                actual: record.kind(),
            });
        }
        self.closure(commit)?;
        let generation = match actual {
            Some(root) => root
                .generation
                .checked_next()
                .ok_or(ModelError::ArithmeticOverflow)?,
            None => RootGeneration::INITIAL,
        };
        let next = RootState { generation, commit };
        self.roots.insert(principal, next);
        Ok(next)
    }

    /// Atomically remove a principal's current root.
    ///
    /// Object bytes remain until garbage collection proves they are
    /// unreachable from every other principal and pin. This distinction is
    /// what makes deletion safe for shared immutable objects.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::RootConflict`] when `expected` is stale or the
    /// principal does not exist.
    pub fn compare_and_remove_root(
        &mut self,
        principal: &P,
        expected: RootState,
    ) -> Result<RootState, ModelError> {
        let actual = self.roots.get(principal).copied();
        if actual != Some(expected) {
            return Err(ModelError::RootConflict {
                expected: Some(expected),
                actual,
            });
        }
        self.roots.remove(principal);
        Ok(expected)
    }

    /// Export a deterministic copy of a complete root closure.
    ///
    /// # Errors
    ///
    /// Returns a graph-validation error when the root is incomplete or cyclic.
    pub fn export_closure(
        &self,
        root: ObjectId,
    ) -> Result<Vec<(ObjectId, ObjectRecord)>, ModelError> {
        let ids = self.closure(root)?;
        let mut records = Vec::with_capacity(ids.len());
        for id in ids {
            let record = self.objects.get(&id).ok_or(ModelError::MissingObject(id))?;
            records.push((id, record.clone()));
        }
        Ok(records)
    }

    /// Atomically import and validate an immutable closure.
    ///
    /// No staged record becomes visible when any record collides or the
    /// declared root is incomplete. The returned value counts newly inserted
    /// objects; importing the same closure again returns zero.
    ///
    /// # Errors
    ///
    /// Returns a collision or graph-validation error without mutating the
    /// world.
    pub fn import_closure(
        &mut self,
        records: &[(ObjectId, ObjectRecord)],
        root: ObjectId,
    ) -> Result<u64, ModelError> {
        let mut staged = self.objects.clone();
        let mut inserted = 0_u64;
        for (id, record) in records {
            match staged.get(id) {
                Some(existing) if existing == record => {},
                Some(_) => return Err(ModelError::ObjectCollision(*id)),
                None => {
                    staged.insert(*id, record.clone());
                    inserted = inserted
                        .checked_add(1)
                        .ok_or(ModelError::ArithmeticOverflow)?;
                },
            }
        }
        let closure = closure_in(&staged, root)?;
        if let Some(extraneous) = records
            .iter()
            .map(|(id, _)| id)
            .find(|id| !closure.contains(id))
        {
            return Err(ModelError::ExtraneousImportObject(*extraneous));
        }
        self.objects = staged;
        Ok(inserted)
    }

    /// Retain a root independently of a principal's current root.
    ///
    /// # Errors
    ///
    /// Returns a graph-validation error or [`ModelError::PinAlreadyExists`].
    pub fn pin(&mut self, pin: PinId, root: ObjectId) -> Result<(), ModelError> {
        self.closure(root)?;
        if self.pins.contains_key(&pin) {
            return Err(ModelError::PinAlreadyExists(pin));
        }
        self.pins.insert(pin, root);
        Ok(())
    }

    /// Release a retained root.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::PinMissing`] when the pin is unknown.
    pub fn unpin(&mut self, pin: PinId) -> Result<ObjectId, ModelError> {
        self.pins.remove(&pin).ok_or(ModelError::PinMissing(pin))
    }

    /// Calculate stable usage for a principal's current root.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::PrincipalMissing`], a graph-validation error, or
    /// an accounting overflow.
    pub fn principal_usage(&self, principal: &P) -> Result<PrincipalUsage, ModelError> {
        let root = self
            .roots
            .get(principal)
            .ok_or(ModelError::PrincipalMissing)?;
        let closure = self.closure(root.commit)?;
        let mut usage = PrincipalUsage::default();
        for id in closure {
            let record = self.objects.get(&id).ok_or(ModelError::MissingObject(id))?;
            let retained = u64::try_from(record.canonical_bytes.len())
                .map_err(|_| ModelError::ArithmeticOverflow)?;
            usage.object_count = usage
                .object_count
                .checked_add(1)
                .ok_or(ModelError::ArithmeticOverflow)?;
            usage.logical_bytes = usage
                .logical_bytes
                .checked_add(record.logical_bytes)
                .ok_or(ModelError::ArithmeticOverflow)?;
            usage.retained_object_bytes = usage
                .retained_object_bytes
                .checked_add(retained)
                .ok_or(ModelError::ArithmeticOverflow)?;
            if record.class == ObjectClass::Metadata {
                usage.metadata_bytes = usage
                    .metadata_bytes
                    .checked_add(retained)
                    .ok_or(ModelError::ArithmeticOverflow)?;
            }
        }
        Ok(usage)
    }

    /// Remove every object unreachable from all current roots and pins.
    ///
    /// # Errors
    ///
    /// Returns a graph-validation error or accounting overflow. No object is
    /// removed if an authoritative root is invalid.
    pub fn collect_garbage(&mut self) -> Result<GcReport, ModelError> {
        let live = self.live_objects()?;
        let mut report = GcReport::default();
        let garbage: Vec<ObjectId> = self
            .objects
            .keys()
            .filter(|id| !live.contains(id))
            .copied()
            .collect();
        for id in &garbage {
            let record = self.objects.get(id).ok_or(ModelError::MissingObject(*id))?;
            let bytes = u64::try_from(record.canonical_bytes.len())
                .map_err(|_| ModelError::ArithmeticOverflow)?;
            report.objects_removed = report
                .objects_removed
                .checked_add(1)
                .ok_or(ModelError::ArithmeticOverflow)?;
            report.bytes_removed = report
                .bytes_removed
                .checked_add(bytes)
                .ok_or(ModelError::ArithmeticOverflow)?;
        }
        for id in garbage {
            self.objects.remove(&id);
        }
        self.representations
            .retain(|_, object| self.objects.contains_key(object));
        self.placements
            .retain(|(_, blob), _| self.representations.contains_key(blob));
        Ok(report)
    }

    /// Publish a complete physical placement epoch atomically.
    ///
    /// Every logically live object must have at least `minimum_replicas`
    /// distinct nodes in the supplied plan. Old epochs remain present so
    /// production integrations can honor reader leases before retiring them.
    /// Logical principal roots are never modified.
    ///
    /// # Errors
    ///
    /// Returns an epoch conflict, graph-validation error, missing placement,
    /// insufficient replica count, or numeric conversion error.
    pub fn publish_placement_epoch(
        &mut self,
        epoch: PlacementEpoch,
        plan: &[(BlobId, Vec<StorageNodeId>)],
        minimum_replicas: ReplicaCount,
    ) -> Result<(), ModelError> {
        if self.placement_epochs.contains(&epoch) {
            return Err(ModelError::PlacementEpochAlreadyExists(epoch));
        }
        if let Some(active) = self.active_placement_epoch
            && epoch <= active
        {
            return Err(ModelError::StalePlacementEpoch {
                proposed: epoch,
                active,
            });
        }

        let live = self.live_objects()?;
        let mut staged = BTreeMap::<BlobId, BTreeSet<StorageNodeId>>::new();
        for (blob, nodes) in plan {
            if !self.representations.contains_key(blob) {
                return Err(ModelError::UnregisteredBlob(*blob));
            }
            let entry = staged.entry(*blob).or_default();
            entry.extend(nodes.iter().copied());
        }
        for object in live {
            let registered: Vec<BlobId> = self
                .representations
                .iter()
                .filter(|(_, content)| **content == object)
                .map(|(blob, _)| *blob)
                .collect();
            if registered.is_empty() {
                return Err(ModelError::MissingRepresentation(object));
            }
            let mut best: Option<(BlobId, u32)> = None;
            for blob in registered {
                let Some(nodes) = staged.get(&blob) else {
                    continue;
                };
                let actual =
                    u32::try_from(nodes.len()).map_err(|_| ModelError::ArithmeticOverflow)?;
                if best.is_none_or(|(_, best_actual)| actual > best_actual) {
                    best = Some((blob, actual));
                }
            }
            let Some((blob, actual)) = best else {
                return Err(ModelError::MissingPlacement { epoch, object });
            };
            if actual < minimum_replicas.get() {
                return Err(ModelError::InsufficientReplicas {
                    epoch,
                    blob,
                    required: minimum_replicas,
                    actual,
                });
            }
        }

        for (blob, nodes) in staged {
            self.placements.insert((epoch, blob), nodes);
        }
        self.placement_epochs.insert(epoch);
        self.active_placement_epoch = Some(epoch);
        Ok(())
    }

    /// Return the active physical placement epoch.
    #[must_use]
    pub const fn active_placement_epoch(&self) -> Option<PlacementEpoch> {
        self.active_placement_epoch
    }

    /// Borrow the replica set for a blob in a placement epoch.
    #[must_use]
    pub fn replicas(
        &self,
        epoch: PlacementEpoch,
        blob: BlobId,
    ) -> Option<&BTreeSet<StorageNodeId>> {
        self.placements.get(&(epoch, blob))
    }

    /// Retire a non-active placement epoch.
    ///
    /// Production code additionally waits for old-epoch reader and replication
    /// leases. This model operation represents the point after those leases
    /// have drained.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::ActivePlacementEpoch`] when `epoch` is active.
    pub fn retire_placement_epoch(&mut self, epoch: PlacementEpoch) -> Result<(), ModelError> {
        if self.active_placement_epoch == Some(epoch) {
            return Err(ModelError::ActivePlacementEpoch(epoch));
        }
        if !self.placement_epochs.contains(&epoch) {
            return Err(ModelError::PlacementEpochMissing(epoch));
        }
        self.placements
            .retain(|(stored_epoch, _), _| *stored_epoch != epoch);
        self.placement_epochs.remove(&epoch);
        Ok(())
    }

    fn live_objects(&self) -> Result<BTreeSet<ObjectId>, ModelError> {
        let mut live = BTreeSet::new();
        for root in self.roots.values() {
            live.extend(self.closure(root.commit)?);
        }
        for root in self.pins.values() {
            live.extend(self.closure(*root)?);
        }
        Ok(live)
    }
}

pub(super) fn closure_in(
    objects: &BTreeMap<ObjectId, ObjectRecord>,
    root: ObjectId,
) -> Result<BTreeSet<ObjectId>, ModelError> {
    let mut result = BTreeSet::new();
    let mut marks = BTreeMap::<ObjectId, u8>::new();
    let mut stack = vec![(root, false)];

    while let Some((id, expanded)) = stack.pop() {
        if expanded {
            marks.insert(id, 2);
            result.insert(id);
            continue;
        }
        match marks.get(&id).copied() {
            Some(2) => continue,
            Some(1) => return Err(ModelError::ObjectCycle(id)),
            Some(_) | None => {},
        }
        let record = objects.get(&id).ok_or(ModelError::MissingObject(id))?;
        marks.insert(id, 1);
        stack.push((id, true));
        for child in record.owning_references().rev() {
            stack.push((child, false));
        }
    }

    Ok(result)
}
