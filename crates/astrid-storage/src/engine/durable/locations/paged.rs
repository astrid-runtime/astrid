//! Complete locator with geometric anonymous runs and a bounded resident table.
//!
//! Every admitted location is held in the table or an authenticated run.
//! `Ok(None)` proves absence from the complete locator, never a cache miss.
//! Scratch failures set a recovery fence; the engine rebuilds from durable media.

use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, Ordering};

use super::run::{Builder, Run};
use super::{ArenaLocation, ClosureProof, DurableError, LocationLookup, LocatorValue, ObjectId};

type RowEntries<'a> = Box<dyn Iterator<Item = Result<(ObjectId, LocatorValue), DurableError>> + 'a>;

#[derive(Debug)]
pub(in crate::engine::durable) struct PagedLocations {
    resident: Vec<(ObjectId, LocatorValue)>,
    runs: Vec<Option<Run>>,
    limit: NonZeroUsize,
    count: usize,
    failed: AtomicBool,
    #[cfg(test)]
    damage_after_inserts: Option<usize>,
}

impl PagedLocations {
    pub(in crate::engine::durable) fn new(limit: NonZeroUsize) -> Self {
        Self {
            resident: Vec::new(),
            runs: Vec::new(),
            limit,
            count: 0,
            failed: AtomicBool::new(false),
            #[cfg(test)]
            damage_after_inserts: None,
        }
    }

    #[cfg(test)]
    pub(in crate::engine::durable) fn from_map(
        map: BTreeMap<ObjectId, ArenaLocation>,
        limit: NonZeroUsize,
    ) -> Result<Self, DurableError> {
        Self::from_map_with_proofs(map, &std::collections::BTreeSet::new(), limit)
    }

    pub(in crate::engine::durable) fn from_map_with_proofs(
        map: BTreeMap<ObjectId, ArenaLocation>,
        proven: &std::collections::BTreeSet<ObjectId>,
        limit: NonZeroUsize,
    ) -> Result<Self, DurableError> {
        let row = |id, location| {
            (
                id,
                LocatorValue {
                    location,
                    proof: if proven.contains(&id) {
                        ClosureProof::Complete
                    } else {
                        ClosureProof::Unknown
                    },
                },
            )
        };
        if map.len() < limit.get() {
            return Ok(Self {
                count: map.len(),
                resident: map
                    .into_iter()
                    .map(|(id, location)| row(id, location))
                    .collect(),
                runs: Vec::new(),
                limit,
                failed: AtomicBool::new(false),
                #[cfg(test)]
                damage_after_inserts: None,
            });
        }
        let count = map.len();
        let mut builder = Builder::new()?;
        for (id, location) in map {
            let (id, value) = row(id, location);
            builder.push_row(id, value)?;
        }
        let run = builder
            .finish()?
            .ok_or(DurableError::InvalidRepresentationState(
                "nonempty locator lost its run",
            ))?;
        let mut capacity = limit.get();
        let mut level = 0_usize;
        while capacity < count {
            capacity = capacity.saturating_mul(2);
            level = level.checked_add(1).ok_or(DurableError::EncodingOverflow)?;
        }
        let mut runs = Vec::new();
        runs.resize_with(level.strict_add(1), || None);
        // A recovered catalogue may start above empty lower levels. Those
        // holes reserve newer geometric runs without rebuilding this run after
        // every staging-table spill.
        runs[level] = Some(run);
        Ok(Self {
            resident: Vec::new(),
            runs,
            limit,
            count,
            failed: AtomicBool::new(false),
            #[cfg(test)]
            damage_after_inserts: None,
        })
    }

    pub(in crate::engine::durable) fn insert(
        &mut self,
        id: ObjectId,
        location: ArenaLocation,
    ) -> Result<(), DurableError> {
        let prior = self.row(id)?;
        self.insert_row(
            id,
            LocatorValue {
                location,
                proof: prior.map_or(ClosureProof::Unknown, |prior| prior.proof),
            },
        )
    }

    #[cfg(test)]
    pub(in crate::engine::durable) fn clear_proofs(&mut self) -> Result<(), DurableError> {
        let entries = self.locations().collect::<Result<Vec<_>, _>>()?;
        for (id, location) in entries {
            self.insert_row(id, LocatorValue::unknown(location))?;
        }
        Ok(())
    }

    pub(in crate::engine::durable) fn closure_proven(
        &self,
        id: ObjectId,
    ) -> Result<bool, DurableError> {
        Ok(self
            .row(id)?
            .is_some_and(|row| row.proof == ClosureProof::Complete))
    }

    pub(in crate::engine::durable) fn mark_proven(
        &mut self,
        id: ObjectId,
    ) -> Result<(), DurableError> {
        let mut row = self
            .row(id)?
            .ok_or(DurableError::InvalidRepresentationState(
                "closure proof has no object locator",
            ))?;
        row.proof = ClosureProof::Complete;
        let result = self.insert_row(id, row);
        if result.is_err() {
            self.failed.store(true, Ordering::Release);
        }
        result
    }

    fn row(&self, id: ObjectId) -> Result<Option<LocatorValue>, DurableError> {
        self.lookup(id)
            .inspect_err(|_| self.failed.store(true, Ordering::Release))
    }

    fn insert_row(&mut self, id: ObjectId, location: LocatorValue) -> Result<(), DurableError> {
        #[cfg(test)]
        if let Some(remaining) = self.damage_after_inserts.as_mut() {
            if *remaining == 0 {
                self.damage_after_inserts = None;
                self.truncate_test_run();
            } else {
                *remaining = remaining.strict_sub(1);
            }
        }
        let previous = self.row(id)?;
        if previous == Some(location) {
            return Ok(());
        }
        let count = if previous.is_none() {
            self.count
                .checked_add(1)
                .ok_or(DurableError::EncodingOverflow)?
        } else {
            self.count
        };
        let position = self.resident.binary_search_by_key(&id, |entry| entry.0);
        let resident_count = self
            .resident
            .len()
            .checked_add(usize::from(position.is_err()))
            .ok_or(DurableError::EncodingOverflow)?;
        if resident_count >= self.limit.get() {
            self.flush_with(id, location, count)?;
        } else {
            match position {
                Ok(at) => self.resident[at].1 = location,
                Err(at) => {
                    if self.resident.len() == self.resident.capacity() {
                        let target = self
                            .resident
                            .capacity()
                            .max(1)
                            .saturating_mul(2)
                            .min(self.limit.get());
                        self.resident
                            .try_reserve_exact(target.saturating_sub(self.resident.len()))
                            .map_err(|_| DurableError::EncodingOverflow)?;
                    }
                    self.resident.insert(at, (id, location));
                },
            }
        }
        self.count = count;
        Ok(())
    }

    fn flush_with(
        &mut self,
        id: ObjectId,
        location: LocatorValue,
        count: usize,
    ) -> Result<(), DurableError> {
        // Include the prospective mutation in the new run without publishing it
        // in memory. An I/O failure must leave the entire logical index intact.
        let sources: Vec<Box<dyn Iterator<Item = Result<_, DurableError>>>> = vec![
            Box::new(std::iter::once(Ok((id, location)))),
            Box::new(
                self.resident
                    .iter()
                    .map(|(id, location)| Ok((*id, *location))),
            ),
        ];
        let mut builder = Builder::new()?;
        for entry in MergedEntries::new(sources)? {
            let (id, location) = entry?;
            builder.push_row(id, location)?;
        }
        let mut carry = builder
            .finish()?
            .ok_or(DurableError::InvalidRepresentationState(
                "nonempty locator lost its memtable",
            ))?;
        let mut level = 0_usize;
        while let Some(Some(older)) = self.runs.get(level) {
            carry = merge(&carry, older)?;
            level = level.checked_add(1).ok_or(DurableError::EncodingOverflow)?;
        }
        let physical_entries = self
            .runs
            .iter()
            .skip(level)
            .flatten()
            .try_fold(carry.count, |sum, run| sum.checked_add(run.count))
            .ok_or(DurableError::EncodingOverflow)?;
        let compact_all = physical_entries > count.saturating_mul(2);
        if compact_all {
            // Location replacements can otherwise leave one obsolete copy per
            // level indefinitely. A geometric full merge bounds this metadata
            // duplication without removing any distinct historical object.
            for older in self.runs.iter().skip(level).flatten() {
                carry = merge(&carry, older)?;
            }
            level = 0;
            let mut capacity = self.limit.get();
            while capacity < carry.count {
                capacity = capacity.saturating_mul(2);
                level = level.checked_add(1).ok_or(DurableError::EncodingOverflow)?;
            }
        }
        // No old input owner is released before every new page is written.
        // A failed merge leaves both the old run set and memtable available.
        if compact_all {
            self.runs.clear();
        }
        if self.runs.len() <= level {
            self.runs.resize_with(level.strict_add(1), || None);
        }
        for slot in &mut self.runs[..level] {
            *slot = None;
        }
        self.runs[level] = Some(carry);
        self.resident.clear();
        Ok(())
    }

    pub(in crate::engine::durable) fn len(&self) -> usize {
        self.count
    }

    #[cfg(test)]
    pub(in crate::engine::durable) fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub(in crate::engine::durable) fn clear(&mut self) {
        self.resident = Vec::new();
        self.runs.clear();
        self.runs.shrink_to_fit();
        self.count = 0;
        self.failed.store(false, Ordering::Release);
    }

    /// Damage a real anonymous run at an admission boundary, after callers
    /// have persisted bytes. The ordinary authenticated read detects the fault.
    #[cfg(test)]
    pub(in crate::engine::durable) fn damage_run_after_inserts(&mut self, count: usize) {
        self.damage_after_inserts = Some(count);
    }

    #[cfg(test)]
    pub(in crate::engine::durable) fn truncate_test_run(&self) {
        self.runs
            .iter()
            .flatten()
            .next()
            .expect("test requires a spilled run")
            .test_file()
            .set_len(0)
            .unwrap();
    }

    #[cfg(test)]
    pub(in crate::engine::durable) fn resident_entries(&self) -> usize {
        self.resident.len()
    }

    #[cfg(test)]
    pub(in crate::engine::durable) fn resident_capacity_bytes(&self) -> usize {
        self.resident
            .capacity()
            .strict_mul(std::mem::size_of::<(ObjectId, LocatorValue)>())
    }

    pub(in crate::engine::durable) fn set_limit(
        &mut self,
        limit: NonZeroUsize,
    ) -> Result<(), DurableError> {
        if self.resident.len() >= limit.get() {
            let (id, location) = self.resident[0];
            self.flush_with(id, location, self.count)?;
        }
        // Shrink an over-budget allocation after any required spill succeeds.
        // Raising a target does not eagerly reserve its entire allowance.
        if self.resident.capacity() > limit.get() {
            let mut resident = Vec::new();
            resident
                .try_reserve_exact(self.resident.len())
                .map_err(|_| DurableError::EncodingOverflow)?;
            resident.append(&mut self.resident);
            self.resident = resident;
        }
        self.limit = limit;
        Ok(())
    }

    pub(in crate::engine::durable) fn failed(&self) -> bool {
        self.failed.load(Ordering::Acquire)
    }

    fn lookup(&self, id: ObjectId) -> Result<Option<LocatorValue>, DurableError> {
        if let Ok(at) = self.resident.binary_search_by_key(&id, |entry| entry.0) {
            return Ok(Some(self.resident[at].1));
        }
        for run in self.runs.iter().flatten() {
            if let Some(location) = run.lookup_row(id)? {
                return Ok(Some(location));
            }
        }
        Ok(None)
    }
}

impl LocationLookup for PagedLocations {
    fn location(&self, id: ObjectId) -> Result<Option<ArenaLocation>, DurableError> {
        self.row(id).map(|row| row.map(|row| row.location))
    }

    fn location_count(&self) -> usize {
        self.count
    }

    fn locations(
        &self,
    ) -> Box<dyn Iterator<Item = Result<(ObjectId, ArenaLocation), DurableError>> + '_> {
        let mut sources: Vec<RowEntries<'_>> = vec![Box::new(
            self.resident
                .iter()
                .map(|(id, location)| Ok((*id, *location))),
        )];
        sources.extend(
            self.runs
                .iter()
                .flatten()
                .map(|run| Box::new(run.rows()) as Box<dyn Iterator<Item = Result<_, _>>>),
        );
        let entries: Box<dyn Iterator<Item = Result<_, _>>> = match MergedEntries::new(sources) {
            Ok(entries) => Box::new(entries),
            Err(error) => Box::new(std::iter::once(Err(error))),
        };
        Box::new(entries.map(|entry| {
            entry
                .map(|(id, row)| (id, row.location))
                .inspect_err(|_| self.failed.store(true, Ordering::Release))
        }))
    }
}

fn merge(newer: &Run, older: &Run) -> Result<Run, DurableError> {
    let sources: Vec<RowEntries<'_>> = vec![Box::new(newer.rows()), Box::new(older.rows())];
    let mut builder = Builder::new()?;
    for entry in MergedEntries::new(sources)? {
        let (id, location) = entry?;
        builder.push_row(id, location)?;
    }
    builder
        .finish()?
        .ok_or(DurableError::InvalidRepresentationState(
            "merged locator lost all entries",
        ))
}

struct MergedEntries<'a> {
    sources: Vec<RowEntries<'a>>,
    heads: Vec<Option<(ObjectId, LocatorValue)>>,
    failed: bool,
}

impl<'a> MergedEntries<'a> {
    fn new(mut sources: Vec<RowEntries<'a>>) -> Result<Self, DurableError> {
        let heads = sources
            .iter_mut()
            .map(|source| source.next().transpose())
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            sources,
            heads,
            failed: false,
        })
    }
}

impl Iterator for MergedEntries<'_> {
    type Item = Result<(ObjectId, LocatorValue), DurableError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        let mut selected = None;
        for entry in self.heads.iter().flatten() {
            if selected.is_none_or(|previous: (ObjectId, LocatorValue)| previous.0 > entry.0) {
                selected = Some(*entry);
            }
        }
        let selected = selected?;
        for (head, source) in self.heads.iter_mut().zip(&mut self.sources) {
            if head.is_some_and(|head| head.0 == selected.0) {
                match source.next().transpose() {
                    Ok(next) => *head = next,
                    Err(error) => {
                        self.failed = true;
                        return Some(Err(error));
                    },
                }
            }
        }
        Some(Ok(selected))
    }
}

#[cfg(test)]
mod tests;
