//! Atomic fixed-capacity mutation batches for the relation projection.

use super::{
    ProjectionStore, ReaderLease, RelationChange, RelationMutation, apply_to_rows, relation_index,
};
use crate::relations::delta::RelationDelta;
use crate::relations::types::{MAX_RELATION_ROWS, ProjectionError, READER_SLOTS};

impl RelationMutation {
    pub(crate) const fn new(reader: ReaderLease, change: RelationChange) -> Self {
        Self { reader, change }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct AuthoritativeBatch {
    entries: [Option<RelationMutation>; MAX_RELATION_ROWS],
    len: usize,
}

impl AuthoritativeBatch {
    pub(crate) const fn empty() -> Self {
        Self {
            entries: [None; MAX_RELATION_ROWS],
            len: 0,
        }
    }

    pub(crate) fn push(&mut self, mutation: RelationMutation) -> Result<(), ProjectionError> {
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

impl ProjectionStore {
    pub(crate) fn apply(&mut self, batch: AuthoritativeBatch) -> Result<usize, ProjectionError> {
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
}
