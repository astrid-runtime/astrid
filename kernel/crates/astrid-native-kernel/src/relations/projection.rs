//! Fixed-capacity projection state, readers, snapshots, and replay.

use super::delta::{DeltaCursor, DeltaRing, PageCursor, RelationDelta};
use super::types::{
    DomainProjectionToken, MAX_OBJECT_OBSERVATIONS, MAX_RELATION_ROWS, ObjectToken,
    ProjectionError, READER_SLOTS, ReclaimObservation, ReclaimOutcome, Relation, RelationChange,
    RelationKey,
};
use crate::ipc::DomainToken;

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

/// Projection state only. Authoritative tables remain outside this type.
#[derive(Clone, Copy)]
pub struct ProjectionStore {
    next_token: u64,
    readers: [Option<Reader>; READER_SLOTS],
    rows: [Option<Relation>; MAX_RELATION_ROWS],
    row_count: usize,
    reclaim: [Option<ReclaimObservation>; MAX_OBJECT_OBSERVATIONS],
}

impl ProjectionStore {
    pub const fn empty() -> Self {
        Self {
            next_token: 1,
            readers: [None; READER_SLOTS],
            rows: [None; MAX_RELATION_ROWS],
            row_count: 0,
            reclaim: [None; MAX_OBJECT_OBSERVATIONS],
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

        let token = self.mint_token()?;
        self.readers[slot] = Some(Reader::new(token, identity));
        Ok(ReaderLease {
            token,
            reader: identity,
        })
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

    pub fn relation_epoch(&self, lease: ReaderLease) -> Result<u64, ProjectionError> {
        Ok(self.reader_at(lease)?.epoch)
    }

    pub fn delta_cursor(&self, lease: ReaderLease) -> Result<DeltaCursor, ProjectionError> {
        let reader = self.reader_at(lease)?;
        Ok(DeltaCursor::new(
            reader.identity.domain.generation().get(),
            reader.epoch,
        ))
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
        if reader.deltas.overflowed()
            || cursor.reader_generation != reader.identity.domain.generation().get()
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

    pub fn fold(
        &self,
        lease: ReaderLease,
        base: Snapshot,
        cursor: DeltaCursor,
    ) -> Result<Snapshot, ProjectionError> {
        let reader = self.reader_at(lease)?;
        if reader.deltas.overflowed()
            || !cursor.matches(reader.identity.domain.generation().get(), base.epoch)
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

        let deltas = reader.deltas.deltas();
        if reader.epoch != base.epoch {
            let Some(first) = deltas.iter().copied().flatten().next() else {
                return Err(ProjectionError::ResnapshotRequired);
            };
            if first.epoch() != base.epoch.saturating_add(1) {
                return Err(ProjectionError::ResnapshotRequired);
            }
        }

        let mut expected_epoch = base.epoch;
        for delta in deltas.into_iter().flatten() {
            if delta.epoch() <= base.epoch {
                continue;
            }
            expected_epoch = match expected_epoch.checked_add(1) {
                Some(epoch) => epoch,
                None => return Err(ProjectionError::ResnapshotRequired),
            };
            if delta.epoch() != expected_epoch {
                return Err(ProjectionError::ResnapshotRequired);
            }
            apply_to_rows(&mut rows, &mut len, delta.change());
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
        let mut reader_indexes = [None; MAX_RELATION_ROWS];
        let mut next_epochs = [0u64; MAX_RELATION_ROWS];
        for (index, mutation) in batch.mutations().enumerate() {
            if mutation.reader.token != mutation.change.key().scope() {
                return Err(ProjectionError::Denied);
            }
            let reader_index = self.reader_index(mutation.reader)?;
            let Some(reader) = &self.readers[reader_index] else {
                return Err(ProjectionError::Denied);
            };
            let Some(next_epoch) = reader.epoch.checked_add(1) else {
                return Err(ProjectionError::ResnapshotRequired);
            };
            next_epochs[index] = next_epoch;
            reader_indexes[index] = Some(reader_index);
            if let RelationChange::Upsert(relation) = mutation.change {
                self.validate_upsert(relation)?;
            }
        }

        let mut changed = [false; READER_SLOTS];
        let mut applied = 0usize;
        for (index, mutation) in batch.mutations().enumerate() {
            let reader_index = reader_indexes[index].unwrap_or(READER_SLOTS);
            let mutated = apply_to_rows(&mut self.rows, &mut self.row_count, mutation.change);
            if mutated {
                changed[reader_index] = true;
                applied += 1;
                let delta = RelationDelta::new(next_epochs[index], mutation.change);
                if let Some(reader) = &mut self.readers[reader_index] {
                    reader.deltas.push(delta);
                }
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

    fn validate_upsert(&self, relation: Relation) -> Result<(), ProjectionError> {
        if relation_index(&self.rows, relation.key()).is_none()
            && self.row_count == MAX_RELATION_ROWS
        {
            return Err(ProjectionError::NoSpace);
        }
        if relation
            .key()
            .object_tokens()
            .into_iter()
            .flatten()
            .any(|object| self.reclaim_for_object(object).is_some())
        {
            return Err(ProjectionError::Resurrection);
        }
        Ok(())
    }

    fn reclaim_for_object(&self, object: ObjectToken) -> Option<ReclaimObservation> {
        self.reclaim
            .into_iter()
            .flatten()
            .find(|observation| observation.object() == object)
    }

    pub fn record_reclaim(
        &mut self,
        lease: ReaderLease,
        object: ObjectToken,
        outcome: ReclaimOutcome,
    ) -> Result<bool, ProjectionError> {
        self.reader_at(lease)?;
        if self
            .rows
            .iter()
            .any(|row| row.is_some_and(|relation| relation_is_dead(relation, object)))
        {
            return Err(ProjectionError::Denied);
        }
        if self.reclaim.iter().any(|observation| {
            observation.is_some_and(|existing| {
                existing.scope() == lease.token && existing.object() == object
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
        object: ObjectToken,
    ) -> Result<ReclaimObservation, ProjectionError> {
        self.reader_at(lease)?;
        self.reclaim_for_object(object)
            .filter(|observation| observation.scope() == lease.token)
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
}

fn relation_is_dead(relation: Relation, object: ObjectToken) -> bool {
    relation
        .key()
        .object_tokens()
        .into_iter()
        .flatten()
        .any(|candidate| candidate == object)
}

fn relation_index(rows: &[Option<Relation>; MAX_RELATION_ROWS], key: RelationKey) -> Option<usize> {
    rows.iter()
        .position(|row| row.is_some_and(|relation| relation.key() == key))
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
