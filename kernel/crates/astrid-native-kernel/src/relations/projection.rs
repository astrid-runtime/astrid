//! Fixed-capacity projection state, readers, snapshots, and replay.

use super::delta::{DeltaCursor, DeltaRing, PageCursor, RelationDelta};
use super::types::{
    CapabilityInstance, DomainProjectionToken, MAX_OBJECT_OBSERVATIONS, MAX_RELATION_ROWS,
    ObjectRef, ProjectionError, READER_SLOTS, ReaderIdentity, ReclaimObservation, ReclaimOutcome,
    Relation, RelationChange, RelationKey,
};
use crate::ipc::DomainToken;

mod evidence;

/// A generation-checked projection reader bound to one domain identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReaderLease {
    token: DomainProjectionToken,
    reader: ReaderId,
}

impl ReaderLease {
    pub const fn token(self) -> DomainProjectionToken {
        self.token
    }

    pub const fn reader_generation(self) -> u64 {
        self.reader.domain.generation().get()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ReaderId {
    domain: DomainToken,
}

#[derive(Clone, Copy)]
struct Reader {
    token: DomainProjectionToken,
    identity: ReaderId,
    epoch: u64,
    deltas: DeltaRing,
}

impl Reader {
    const fn new(token: DomainProjectionToken, identity: ReaderId) -> Self {
        Self {
            token,
            identity,
            epoch: 0,
            deltas: DeltaRing::empty(),
        }
    }
}

/// Full canonical snapshot. Rows outside the reader's authority are absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    epoch: u64,
    rows: [Option<Relation>; MAX_RELATION_ROWS],
    len: usize,
}

impl Snapshot {
    pub fn rows(&self) -> impl Iterator<Item = Relation> + '_ {
        self.rows[..self.len].iter().copied().flatten()
    }

    pub const fn row(&self, index: usize) -> Option<Relation> {
        if index < self.len {
            self.rows[index]
        } else {
            None
        }
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub const fn epoch(&self) -> u64 {
        self.epoch
    }
}

/// One canonical snapshot page, bounded by `RELATION_PAGE_ROWS`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotPage {
    epoch: u64,
    page: u32,
    rows: [Option<Relation>; super::types::RELATION_PAGE_ROWS],
    len: usize,
    has_more: bool,
}

impl SnapshotPage {
    pub fn rows(&self) -> impl Iterator<Item = Relation> + '_ {
        self.rows[..self.len].iter().copied().flatten()
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub const fn has_more(&self) -> bool {
        self.has_more
    }
}

/// An atomically validated sequence of authoritative relation mutations.
#[derive(Clone, Copy)]
pub struct RelationMutation {
    reader: ReaderLease,
    change: RelationChange,
}

impl RelationMutation {
    pub const fn new(reader: ReaderLease, change: RelationChange) -> Self {
        Self { reader, change }
    }
}

#[derive(Clone, Copy)]
pub struct AuthoritativeBatch {
    entries: [Option<RelationMutation>; MAX_RELATION_ROWS],
    len: usize,
}

impl AuthoritativeBatch {
    pub const fn empty() -> Self {
        Self {
            entries: [None; MAX_RELATION_ROWS],
            len: 0,
        }
    }

    pub fn push(&mut self, mutation: RelationMutation) -> Result<(), ProjectionError> {
        if self.len == self.entries.len() {
            return Err(ProjectionError::NoSpace);
        }
        self.entries[self.len] = Some(mutation);
        self.len += 1;
        Ok(())
    }

    fn mutations(&self) -> impl Iterator<Item = RelationMutation> + '_ {
        self.entries[..self.len].iter().copied().flatten()
    }
}

#[derive(Clone, Copy)]
struct BatchPlan {
    reader_indexes: [usize; MAX_RELATION_ROWS],
    batch_epochs: [u64; READER_SLOTS],
    effective: [bool; MAX_RELATION_ROWS],
    len: usize,
}

impl BatchPlan {
    const fn empty() -> Self {
        Self {
            reader_indexes: [READER_SLOTS; MAX_RELATION_ROWS],
            batch_epochs: [0; READER_SLOTS],
            effective: [false; MAX_RELATION_ROWS],
            len: 0,
        }
    }
}

/// Projection state only. Authoritative tables remain outside this type.
#[derive(Clone, Copy)]
pub struct ProjectionStore {
    next_token: u64,
    readers: [Option<Reader>; READER_SLOTS],
    rows: [Option<Relation>; MAX_RELATION_ROWS],
    row_count: usize,
    reclaim: [Option<ReclaimObservation>; MAX_OBJECT_OBSERVATIONS],
    logical_deletions: [Option<RelationKey>; MAX_RELATION_ROWS],
    logical_deletions_overflowed: bool,
    #[cfg(test)]
    retired_delete_counts: [usize; READER_SLOTS],
}

impl ProjectionStore {
    pub const fn empty() -> Self {
        Self {
            next_token: 1,
            readers: [None; READER_SLOTS],
            rows: [None; MAX_RELATION_ROWS],
            row_count: 0,
            reclaim: [None; MAX_OBJECT_OBSERVATIONS],
            logical_deletions: [None; MAX_RELATION_ROWS],
            logical_deletions_overflowed: false,
            #[cfg(test)]
            retired_delete_counts: [0; READER_SLOTS],
        }
    }

    pub fn register_reader(&mut self, domain: DomainToken) -> Result<ReaderLease, ProjectionError> {
        let slot = domain.slot().index();
        if slot >= READER_SLOTS {
            return Err(ProjectionError::Denied);
        }
        let identity = ReaderId { domain };
        if let Some(existing) = self.readers[slot]
            && existing.identity == identity
        {
            return Ok(ReaderLease {
                token: existing.token,
                reader: identity,
            });
        }

        let retirement_epoch = self.readers[slot]
            .as_ref()
            .map(|old| {
                old.epoch
                    .checked_add(1)
                    .ok_or(ProjectionError::ResnapshotRequired)
            })
            .transpose()?;
        let token = self.mint_token()?;
        if let Some(mut old) = self.readers[slot].take() {
            let epoch = retirement_epoch.expect("checked before retirement");
            let mut index = 0usize;
            while index < self.row_count {
                let Some(row) = self.rows[index] else {
                    index += 1;
                    continue;
                };
                if row.key().scope() == old.token {
                    let key = row.key();
                    old.deltas
                        .push(RelationDelta::new(epoch, RelationChange::Delete(key)));
                    remove_row_at(&mut self.rows, &mut self.row_count, index);
                } else {
                    index += 1;
                }
            }
            #[cfg(test)]
            {
                self.retired_delete_counts[slot] = old
                    .deltas
                    .deltas()
                    .iter()
                    .filter(|delta| {
                        delta.is_some_and(|delta| {
                            delta.epoch() == epoch
                                && matches!(
                                    delta.change(),
                                    RelationChange::Delete(key) if key.scope() == old.token
                                )
                        })
                    })
                    .count();
            }
        }

        self.readers[slot] = Some(Reader::new(token, identity));
        Ok(ReaderLease {
            token,
            reader: identity,
        })
    }

    pub(crate) fn reader_lease(&self, domain: DomainToken) -> Option<ReaderLease> {
        let reader = self.readers[domain.slot().index()].as_ref()?;
        (reader.identity.domain == domain).then_some(ReaderLease {
            token: reader.token,
            reader: reader.identity,
        })
    }

    fn lease_for_token(&self, token: DomainProjectionToken) -> Option<ReaderLease> {
        self.readers.iter().flatten().find_map(|reader| {
            (reader.token == token).then_some(ReaderLease {
                token,
                reader: reader.identity,
            })
        })
    }

    /// Retire a generation explicitly when its authoritative domain is torn
    /// down. This is the same DELETE path that later generation reuse uses.
    pub(crate) fn retire_reader(&mut self, domain: DomainToken) -> Result<(), ProjectionError> {
        let slot = domain.slot().index();
        let Some(old) = self.readers[slot].as_ref() else {
            return Err(ProjectionError::Denied);
        };
        if old.identity.domain != domain {
            return Err(ProjectionError::ResnapshotRequired);
        }
        let token = old.token;
        let retirement_epoch = old
            .epoch
            .checked_add(1)
            .ok_or(ProjectionError::ResnapshotRequired)?;
        let mut old_deltas = DeltaRing::empty();
        let mut index = 0usize;
        while index < self.row_count {
            let Some(row) = self.rows[index] else {
                index += 1;
                continue;
            };
            if row.key().scope() == token {
                let key = row.key();
                old_deltas.push(RelationDelta::new(
                    retirement_epoch,
                    RelationChange::Delete(key),
                ));
                remove_row_at(&mut self.rows, &mut self.row_count, index);
            } else {
                index += 1;
            }
        }
        self.readers[slot] = None;
        Ok(())
    }

    /// Remove every projection row that names a capability instance. Derives
    /// rows are charged to the reader whose token owns that full row key.
    pub(crate) fn remove_capability(
        &mut self,
        capability: CapabilityInstance,
    ) -> Result<usize, ProjectionError> {
        let mut removed = 0usize;
        let mut index = 0usize;
        while index < self.row_count {
            let Some(relation) = self.rows[index] else {
                index += 1;
                continue;
            };
            let names_capability = match relation.key() {
                RelationKey::Holds {
                    capability: held, ..
                } => held == capability,
                RelationKey::Derives { parent, child, .. } => {
                    parent == capability || child == capability
                },
                RelationKey::Object { .. } => false,
            };
            if !names_capability {
                index += 1;
                continue;
            }

            let key = relation.key();
            let lease = self
                .lease_for_token(key.scope())
                .ok_or(ProjectionError::Denied)?;
            self.apply_mutation(lease, RelationChange::Delete(key))?;
            removed += 1;
        }
        Ok(removed)
    }

    /// Record a physical object-generation reclaim for every live reader. The
    /// projection rejects a scope if that scope still names the live object.
    pub(crate) fn record_object_reclaim(
        &mut self,
        object: ObjectRef,
    ) -> Result<usize, ProjectionError> {
        let mut recorded = 0usize;
        self.remove_object_rows(object)?;
        let mut leases = [None; READER_SLOTS];
        for (index, reader) in self.readers.iter().enumerate() {
            leases[index] = reader.map(|reader| ReaderLease {
                token: reader.token,
                reader: reader.identity,
            })
        }
        for lease in leases.into_iter().flatten() {
            if self.record_reclaim(lease, object, ReclaimOutcome::ReleaseFailed)? {
                recorded += 1;
            }
        }
        Ok(recorded)
    }

    fn remove_object_rows(&mut self, object: ObjectRef) -> Result<usize, ProjectionError> {
        let mut removed = 0usize;
        let mut index = 0usize;
        while index < self.row_count {
            let Some(relation) = self.rows[index] else {
                index += 1;
                continue;
            };
            if !relation_is_dead(relation, object) {
                index += 1;
                continue;
            }

            let key = relation.key();
            let lease = self
                .lease_for_token(key.scope())
                .ok_or(ProjectionError::Denied)?;
            self.apply_mutation(lease, RelationChange::Delete(key))?;
            removed += 1;
        }
        Ok(removed)
    }

    fn mint_token(&mut self) -> Result<DomainProjectionToken, ProjectionError> {
        let token = DomainProjectionToken::new(self.next_token).ok_or(ProjectionError::NoSpace)?;
        self.next_token = self
            .next_token
            .checked_add(1)
            .ok_or(ProjectionError::NoSpace)?;
        Ok(token)
    }

    fn reader_at(&self, lease: ReaderLease) -> Result<&Reader, ProjectionError> {
        let slot = lease.reader.domain.slot().index();
        match &self.readers[slot] {
            None => Err(ProjectionError::Denied),
            Some(reader) if reader.token == lease.token && reader.identity == lease.reader => {
                Ok(reader)
            },
            Some(_) => Err(ProjectionError::ResnapshotRequired),
        }
    }

    fn reader_index(&self, lease: ReaderLease) -> Result<usize, ProjectionError> {
        let reader = self.reader_at(lease)?;
        Ok(reader.identity.domain.slot().index())
    }

    fn reader_identity(&self, reader: &Reader) -> Result<ReaderIdentity, ProjectionError> {
        ReaderIdentity::new(
            reader.identity.domain.slot().index(),
            reader.identity.domain.generation().get(),
            reader.token,
        )
        .ok_or(ProjectionError::Denied)
    }

    pub fn relation_epoch(&self, lease: ReaderLease) -> Result<u64, ProjectionError> {
        Ok(self.reader_at(lease)?.epoch)
    }

    pub fn delta_cursor(&self, lease: ReaderLease) -> Result<DeltaCursor, ProjectionError> {
        let reader = self.reader_at(lease)?;
        let identity = self.reader_identity(reader)?;
        Ok(DeltaCursor::new(identity, reader.epoch))
    }

    pub fn page_cursor(
        &self,
        lease: ReaderLease,
        page: u32,
    ) -> Result<PageCursor, ProjectionError> {
        let reader = self.reader_at(lease)?;
        let identity = self.reader_identity(reader)?;
        Ok(PageCursor::new(identity, reader.epoch, page))
    }

    pub fn snapshot(&self, lease: ReaderLease) -> Result<Snapshot, ProjectionError> {
        let reader = self.reader_at(lease)?;
        if reader.deltas.overflowed() {
            return Err(ProjectionError::ResnapshotRequired);
        }
        let (rows, len) = scoped_rows(&self.rows, lease.token);
        Ok(Snapshot {
            epoch: reader.epoch,
            rows,
            len,
        })
    }

    fn direct_snapshot(&self, lease: ReaderLease) -> Result<Snapshot, ProjectionError> {
        let reader = self.reader_at(lease)?;
        let (rows, len) = scoped_rows(&self.rows, lease.token);
        Ok(Snapshot {
            epoch: reader.epoch,
            rows,
            len,
        })
    }

    pub fn snapshot_page(
        &self,
        lease: ReaderLease,
        cursor: PageCursor,
    ) -> Result<SnapshotPage, ProjectionError> {
        let reader = self.reader_at(lease)?;
        let identity = self.reader_identity(reader)?;
        if reader.deltas.overflowed()
            || cursor.reader != identity
            || cursor.epoch != reader.epoch
            || cursor.page as usize * super::types::RELATION_PAGE_ROWS > MAX_RELATION_ROWS
        {
            return Err(ProjectionError::ResnapshotRequired);
        }

        let (rows, len) = scoped_rows(&self.rows, lease.token);
        let start = cursor.page as usize * super::types::RELATION_PAGE_ROWS;
        let mut page = [None; super::types::RELATION_PAGE_ROWS];
        let mut page_len = 0usize;
        if start > len {
            return Err(ProjectionError::ResnapshotRequired);
        }
        for row in rows
            .iter()
            .skip(start)
            .take(((start + super::types::RELATION_PAGE_ROWS).min(len)) - start)
        {
            page[page_len] = *row;
            page_len += 1;
        }
        Ok(SnapshotPage {
            epoch: reader.epoch,
            page: cursor.page,
            rows: page,
            len: page_len,
            has_more: start + page_len < len,
        })
    }

    pub fn base_snapshot(&mut self, lease: ReaderLease) -> Result<Snapshot, ProjectionError> {
        let snapshot = self.direct_snapshot(lease)?;
        let index = self.reader_index(lease)?;
        if let Some(reader) = &mut self.readers[index] {
            reader.deltas = DeltaRing::empty();
        }
        Ok(snapshot)
    }

    pub(crate) fn current_fold(
        &mut self,
        lease: ReaderLease,
    ) -> Result<(Snapshot, Option<Snapshot>), ProjectionError> {
        let base = self.base_snapshot(lease)?;
        let cursor = self.delta_cursor(lease)?;
        let replayed = self.fold(lease, base, cursor)?;
        Ok((base, Some(replayed)))
    }

    pub fn fold(
        &self,
        lease: ReaderLease,
        base: Snapshot,
        cursor: DeltaCursor,
    ) -> Result<Snapshot, ProjectionError> {
        let reader = self.reader_at(lease)?;
        let identity = self.reader_identity(reader)?;
        if reader.deltas.overflowed()
            || !cursor.matches(identity, base.epoch)
            || base.epoch > reader.epoch
        {
            return Err(ProjectionError::ResnapshotRequired);
        }

        let mut rows = [None; MAX_RELATION_ROWS];
        let mut len = 0usize;
        for relation in base.rows().filter(|row| row.key().scope() == lease.token) {
            rows[len] = Some(relation);
            len += 1;
        }
        sort_rows(&mut rows, &mut len);

        let mut expected_epoch = base.epoch;
        let deltas = reader.deltas.deltas();
        let mut delta_index = 0usize;
        while delta_index < deltas.len() {
            let Some(delta) = deltas[delta_index] else {
                delta_index += 1;
                continue;
            };
            if delta.epoch() <= base.epoch {
                delta_index += 1;
                continue;
            }
            if delta.epoch() != expected_epoch.saturating_add(1) {
                return Err(ProjectionError::ResnapshotRequired);
            }
            expected_epoch = delta.epoch();

            // A batch is one projection-local epoch even when it contains many
            // full-row changes; every change still participates in the replay.
            // Replays order deletes before upserts within the epoch, matching
            // the authoritative staged mutation order, so a later DELETE still
            // funds an earlier UPSERT at the fixed row ceiling.
            let batch_epoch = delta.epoch();
            let mut batch_end = delta_index;
            while batch_end < deltas.len() {
                match deltas[batch_end] {
                    Some(batch_delta) if batch_delta.epoch() == batch_epoch => batch_end += 1,
                    Some(_) => break,
                    None => batch_end += 1,
                }
            }
            for replay_deletes in [true, false] {
                let mut scan = delta_index;
                while scan < batch_end {
                    if let Some(batch_delta) = deltas[scan] {
                        let is_delete = matches!(batch_delta.change(), RelationChange::Delete(_));
                        if is_delete == replay_deletes {
                            apply_to_rows(&mut rows, &mut len, batch_delta.change());
                        }
                    }
                    scan += 1;
                }
            }
            delta_index = batch_end;
        }
        if expected_epoch != reader.epoch {
            return Err(ProjectionError::ResnapshotRequired);
        }
        sort_rows(&mut rows, &mut len);
        Ok(Snapshot {
            epoch: reader.epoch,
            rows,
            len,
        })
    }

    pub fn apply(&mut self, batch: AuthoritativeBatch) -> Result<usize, ProjectionError> {
        let plan = self.plan_batch(batch)?;

        // Stage capacity-sensitive row mutations before publishing them. This
        // lets a later DELETE fund an earlier UPSERT in the same batch without
        // exposing intermediate state.
        let mut planned_rows = self.rows;
        let mut planned_row_count = self.row_count;
        let mut changed = [false; READER_SLOTS];
        let mut applied = 0usize;
        for index in 0..plan.len {
            if !plan.effective[index] {
                continue;
            }
            let mutation = batch.mutations().nth(index).expect("planned batch index");
            if !matches!(mutation.change, RelationChange::Delete(_)) {
                continue;
            }
            let reader_index = plan.reader_indexes[index];
            let mutated = apply_to_rows(&mut planned_rows, &mut planned_row_count, mutation.change);
            debug_assert!(mutated);
            changed[reader_index] = true;
            applied += 1;
        }
        for index in 0..plan.len {
            if !plan.effective[index] {
                continue;
            }
            let mutation = batch.mutations().nth(index).expect("planned batch index");
            if !matches!(mutation.change, RelationChange::Upsert(_)) {
                continue;
            }
            let reader_index = plan.reader_indexes[index];
            let mutated = apply_to_rows(&mut planned_rows, &mut planned_row_count, mutation.change);
            debug_assert!(mutated);
            changed[reader_index] = true;
            applied += 1;
        }

        self.rows = planned_rows;
        self.row_count = planned_row_count;
        for index in 0..plan.len {
            if !plan.effective[index] {
                continue;
            }
            let mutation = batch.mutations().nth(index).expect("planned batch index");
            let reader_index = plan.reader_indexes[index];
            let delta = RelationDelta::new(plan.batch_epochs[reader_index], mutation.change);
            if let Some(reader) = &mut self.readers[reader_index] {
                reader.deltas.push(delta);
            }
            if let RelationChange::Delete(key) = mutation.change {
                self.record_logical_deletion(key);
            }
        }

        for (index, reader) in self.readers.iter_mut().enumerate() {
            if changed[index]
                && let Some(reader) = reader
            {
                reader.epoch += 1;
            }
        }
        Ok(applied)
    }

    /// Stack-frugal production path for one authoritative relation change.
    /// This mirrors the single-entry case of `apply` without staging the
    /// fixed-capacity batch on the small kernel stack.
    pub(crate) fn apply_mutation(
        &mut self,
        reader: ReaderLease,
        change: RelationChange,
    ) -> Result<(), ProjectionError> {
        let reader_index = self.reader_index(reader)?;
        let batch_epoch = self.readers[reader_index]
            .as_ref()
            .and_then(|reader| reader.epoch.checked_add(1))
            .ok_or(ProjectionError::ResnapshotRequired)?;
        let existing = relation_index(&self.rows, change.key());
        let mut next_row_count = self.row_count;

        let effective = match change {
            RelationChange::Upsert(relation) => {
                let is_new = existing.is_none();
                if is_new {
                    next_row_count = next_row_count
                        .checked_add(1)
                        .ok_or(ProjectionError::NoSpace)?;
                }
                self.validate_upsert(relation, is_new, next_row_count)?;
                existing.is_none_or(|at| self.rows[at] != Some(relation))
            },
            RelationChange::Delete(_) => existing.is_some(),
        };
        if !effective {
            return Ok(());
        }

        if apply_to_rows(&mut self.rows, &mut self.row_count, change) {
            if let Some(reader) = &mut self.readers[reader_index] {
                reader.deltas.push(RelationDelta::new(batch_epoch, change));
                reader.epoch = batch_epoch;
            }
            if let RelationChange::Delete(key) = change {
                self.record_logical_deletion(key);
            }
            Ok(())
        } else {
            Err(ProjectionError::NoSpace)
        }
    }

    fn plan_batch(&self, batch: AuthoritativeBatch) -> Result<BatchPlan, ProjectionError> {
        let mut plan = BatchPlan::empty();
        let mut final_row_count = self.row_count;

        // A batch is atomic, so count every effective mutation before
        // validating capacity. A later DELETE can make room for an earlier
        // UPSERT even at the fixed ceiling.
        for mutation in batch.mutations() {
            let existing = relation_index(&self.rows, mutation.change.key());
            match mutation.change {
                RelationChange::Upsert(_) if existing.is_none() => {
                    final_row_count = final_row_count
                        .checked_add(1)
                        .ok_or(ProjectionError::NoSpace)?;
                },
                RelationChange::Delete(_) if existing.is_some() => {
                    final_row_count = final_row_count.saturating_sub(1);
                },
                _ => {},
            }
        }

        for (index, mutation) in batch.mutations().enumerate() {
            let key = mutation.change.key();
            if mutation.reader.token != key.scope()
                || batch
                    .mutations()
                    .take(index)
                    .any(|previous| previous.change.key() == key)
            {
                return Err(ProjectionError::Denied);
            }

            let reader_index = self.reader_index(mutation.reader)?;
            let Some(reader) = &self.readers[reader_index] else {
                return Err(ProjectionError::Denied);
            };
            let Some(batch_epoch) = reader.epoch.checked_add(1) else {
                return Err(ProjectionError::ResnapshotRequired);
            };
            plan.batch_epochs[reader_index] = batch_epoch;
            plan.reader_indexes[index] = reader_index;

            let existing = relation_index(&self.rows, key);
            let is_new = existing.is_none();
            match mutation.change {
                RelationChange::Upsert(relation) => {
                    self.validate_upsert(relation, is_new, final_row_count)?;
                    plan.effective[index] =
                        existing.is_none_or(|at| self.rows[at] != Some(relation));
                },
                RelationChange::Delete(_) => {
                    plan.effective[index] = existing.is_some();
                },
            }
            plan.len = index + 1;
        }

        if final_row_count > MAX_RELATION_ROWS {
            return Err(ProjectionError::NoSpace);
        }
        Ok(plan)
    }

    fn record_logical_deletion(&mut self, key: RelationKey) {
        if self.logical_deletions.contains(&Some(key)) {
            return;
        }
        let Some(slot) = self
            .logical_deletions
            .iter_mut()
            .find(|slot| slot.is_none())
        else {
            self.logical_deletions_overflowed = true;
            return;
        };
        *slot = Some(key);
    }

    fn validate_upsert(
        &self,
        relation: Relation,
        is_new: bool,
        final_row_count: usize,
    ) -> Result<(), ProjectionError> {
        if is_new && (final_row_count > MAX_RELATION_ROWS || self.logical_deletions_overflowed) {
            return Err(ProjectionError::NoSpace);
        }
        if self.logical_deletions.contains(&Some(relation.key())) {
            return Err(ProjectionError::Resurrection);
        }
        if relation
            .key()
            .object_refs()
            .into_iter()
            .flatten()
            .any(|object| {
                self.reclaim_for_object(relation.key().scope(), object)
                    .is_some()
            })
        {
            return Err(ProjectionError::Resurrection);
        }
        Ok(())
    }

    fn reclaim_for_object(
        &self,
        scope: DomainProjectionToken,
        object: ObjectRef,
    ) -> Option<ReclaimObservation> {
        self.reclaim
            .into_iter()
            .flatten()
            .find(|observation| observation.scope() == scope && observation.object_ref() == object)
    }

    pub fn record_reclaim(
        &mut self,
        lease: ReaderLease,
        object: ObjectRef,
        outcome: ReclaimOutcome,
    ) -> Result<bool, ProjectionError> {
        self.reader_at(lease)?;
        if self.rows.iter().any(|row| {
            row.is_some_and(|relation| {
                relation.key().scope() == lease.token && relation_is_dead(relation, object)
            })
        }) {
            return Err(ProjectionError::Denied);
        }
        if self.reclaim.iter().any(|observation| {
            observation.is_some_and(|existing| {
                existing.scope() == lease.token && existing.object_ref() == object
            })
        }) {
            return Ok(false);
        }
        let Some(slot) = self.reclaim.iter_mut().find(|slot| slot.is_none()) else {
            return Err(ProjectionError::NoSpace);
        };
        *slot = Some(ReclaimObservation::new(lease.token, object, outcome));
        Ok(true)
    }

    pub fn reclaim_observation(
        &self,
        lease: ReaderLease,
        object: ObjectRef,
    ) -> Result<ReclaimObservation, ProjectionError> {
        self.reader_at(lease)?;
        self.reclaim_for_object(lease.token, object)
            .ok_or(ProjectionError::Denied)
    }

    #[cfg(test)]
    pub(crate) fn force_epoch_overflow(
        &mut self,
        lease: ReaderLease,
    ) -> Result<(), ProjectionError> {
        let index = self.reader_index(lease)?;
        if let Some(reader) = &mut self.readers[index] {
            reader.epoch = u64::MAX;
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn retired_delete_count(&self, slot: usize) -> usize {
        self.retired_delete_counts[slot]
    }
}

fn relation_is_dead(relation: Relation, object: ObjectRef) -> bool {
    relation
        .key()
        .object_refs()
        .into_iter()
        .flatten()
        .any(|candidate| candidate == object)
}

fn relation_index(rows: &[Option<Relation>; MAX_RELATION_ROWS], key: RelationKey) -> Option<usize> {
    rows.iter()
        .position(|row| row.is_some_and(|relation| relation.key() == key))
}

fn remove_row_at(rows: &mut [Option<Relation>; MAX_RELATION_ROWS], len: &mut usize, index: usize) {
    debug_assert!(index < *len);
    for source in index + 1..*len {
        rows[source - 1] = rows[source];
    }
    *len -= 1;
    rows[*len] = None;
}

fn apply_to_rows(
    rows: &mut [Option<Relation>; MAX_RELATION_ROWS],
    len: &mut usize,
    change: RelationChange,
) -> bool {
    let key = change.key();
    let index = relation_index(rows, key);
    match change {
        RelationChange::Upsert(relation) => {
            if let Some(index) = index {
                rows[index] = Some(relation);
                true
            } else if *len < rows.len() {
                rows[*len] = Some(relation);
                *len += 1;
                true
            } else {
                false
            }
        },
        RelationChange::Delete(_) => index
            .map(|index| {
                rows[index] = None;
                *len -= 1;
                for source in index + 1..*len + 1 {
                    rows[source - 1] = rows[source];
                }
                rows[*len] = None;
            })
            .is_some(),
    }
}

fn scoped_rows(
    rows: &[Option<Relation>; MAX_RELATION_ROWS],
    scope: DomainProjectionToken,
) -> ([Option<Relation>; MAX_RELATION_ROWS], usize) {
    let mut scoped = [None; MAX_RELATION_ROWS];
    let mut len = 0usize;
    for relation in rows.iter().copied().flatten() {
        if relation.key().scope() == scope {
            scoped[len] = Some(relation);
            len += 1;
        }
    }
    sort_rows(&mut scoped, &mut len);
    (scoped, len)
}

fn sort_rows(rows: &mut [Option<Relation>; MAX_RELATION_ROWS], len: &mut usize) {
    for index in 1..*len {
        let mut target = index;
        while target > 0
            && rows[target - 1]
                .is_some_and(|left| rows[target].is_some_and(|right| right.key() < left.key()))
        {
            rows.swap(target - 1, target);
            target -= 1;
        }
    }
    rows.iter_mut().skip(*len).for_each(|row| *row = None);
}
