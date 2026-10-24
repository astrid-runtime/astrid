//! Bounded recovery sort followed by grouped immutable reverse-link emission.
use super::{
    ArenaLocation, DurableError, Link, LocationIndexMemoryBudget, MAGIC, ObjectId,
    RepresentationRecordId, ReverseIndex,
};
use crate::engine::durable::locations::{PagedLocations, SortedLocationBuilder};
use std::num::NonZeroUsize;
mod run;
use run::{Row, Run, Writer};
mod links;
use links::BufferedLinks;

pub(in super::super) struct Rebuild {
    rows: Vec<Row>,
    runs: Vec<Option<Run>>,
    limit: NonZeroUsize,
    budget: LocationIndexMemoryBudget,
    ordinal: u64,
    failed: bool,
}

impl Rebuild {
    pub(in super::super) fn new(budget: LocationIndexMemoryBudget) -> Self {
        Self {
            rows: Vec::new(),
            runs: Vec::new(),
            limit: budget.durable_entries(),
            budget,
            ordinal: 0,
            failed: false,
        }
    }

    pub(in super::super) fn push(
        &mut self,
        object: ObjectId,
        representation: RepresentationRecordId,
    ) -> Result<(), DurableError> {
        self.require_healthy()?;
        let result = (|| {
            let row = Row {
                object,
                representation,
                ordinal: self.ordinal,
            };
            self.ordinal = self
                .ordinal
                .checked_add(1)
                .ok_or(DurableError::EncodingOverflow)?;
            if self.limit.get() == 1 {
                // The borrowed quarter may be smaller than one row. Direct
                // spilling reserves no resident vector slot in that case.
                let mut writer = Writer::new()?;
                writer.push(row)?;
                return self.add_run(writer.finish()?);
            }
            if self.rows.capacity() == 0 {
                self.rows
                    .try_reserve_exact(self.limit.get())
                    .map_err(|_| DurableError::EncodingOverflow)?;
            }
            self.rows.push(row);
            if self.rows.len() == self.limit.get() {
                self.flush()?;
            }
            Ok(())
        })();
        self.failed |= result.is_err();
        result
    }

    fn flush(&mut self) -> Result<(), DurableError> {
        if self.rows.is_empty() {
            return Ok(());
        }
        self.rows.sort_unstable();
        let mut writer = Writer::new()?;
        for row in self.rows.drain(..) {
            writer.push(row)?;
        }
        self.add_run(writer.finish()?)
    }

    fn add_run(&mut self, mut run: Run) -> Result<(), DurableError> {
        let mut level = 0_usize;
        loop {
            if level == self.runs.len() {
                self.runs.push(None);
            }
            if let Some(older) = self.runs[level].take() {
                run = older.merge(run)?;
            } else {
                self.runs[level] = Some(run);
                return Ok(());
            }
            level = level.checked_add(1).ok_or(DurableError::EncodingOverflow)?;
        }
    }

    pub(in super::super) fn finish(
        mut self,
        mut first: impl FnMut(ObjectId, RepresentationRecordId) -> Result<(), DurableError>,
    ) -> Result<ReverseIndex, DurableError> {
        self.require_healthy()?;
        self.flush()?;
        let mut merged: Option<Run> = None;
        for run in self.runs.into_iter().flatten() {
            merged = Some(match merged {
                Some(older) => older.merge(run)?,
                None => run,
            });
        }
        // Sorting no longer needs the borrowed staging partition. Release its
        // vector before constructing the final paged head table.
        drop(self.rows);
        let mut index = ReverseIndex::new(self.budget)?;
        let mut links = BufferedLinks::new(
            index
                .file
                .try_clone()
                .map_err(|source| super::io_error("clone reverse rebuild output", source))?,
            self.budget.buffered_output_bytes(),
        )?;
        // Grouped objects are already unique and sorted. The page builder
        // checks that order directly without spilling and merging them again.
        let mut heads = SortedLocationBuilder::new()?;
        let mut group: Option<(ObjectId, RepresentationRecordId, ArenaLocation)> = None;
        if let Some(run) = merged {
            let mut reader = run.reader();
            while let Some(row) = reader.next()? {
                if group.is_some_and(|(object, _, _)| object != row.object) {
                    let (object, _, location) = group.take().expect("group present");
                    heads.push(object, location)?;
                }
                let (earliest, previous) = if let Some((_, earliest, location)) = group {
                    // Readback must authenticate the emitted media, including
                    // links still pending in the private output buffer.
                    links.flush()?;
                    let prior = index.link(row.object, location)?;
                    if prior.first != earliest {
                        return Err(DurableError::InvalidRepresentationState(
                            "grouped reverse earliest identity changed",
                        ));
                    }
                    (earliest, Some(location))
                } else {
                    first(row.object, row.representation)?;
                    (row.representation, None)
                };
                let link = Link {
                    id: row.representation,
                    first: earliest,
                    previous,
                };
                let location = links.append(&link.encode(row.object))?;
                group = Some((row.object, earliest, location));
            }
        }
        if let Some((object, _, location)) = group {
            heads.push(object, location)?;
        }
        links.finish()?;
        index.heads = PagedLocations::from_sorted_builder(self.budget.durable_entries(), heads)?;
        Ok(index)
    }

    fn require_healthy(&self) -> Result<(), DurableError> {
        if self.failed {
            return Err(DurableError::InvalidRepresentationState(
                "reverse rebuild failed",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
