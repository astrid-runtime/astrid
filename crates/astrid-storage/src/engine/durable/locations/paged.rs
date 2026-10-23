//! Complete locator with geometric anonymous runs and a bounded resident table.
//!
//! Every admitted location is held in the table or an authenticated run.
//! `Ok(None)` proves absence from the complete locator, never a cache miss.
//! Scratch failures set a recovery fence; the engine rebuilds from durable media.

use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, Ordering};

use super::run::{Builder, Run};
use super::{ArenaLocation, DurableError, LocationEntries, LocationLookup, ObjectId};

#[derive(Debug)]
pub(in crate::engine::durable) struct PagedLocations {
    resident: Vec<(ObjectId, ArenaLocation)>,
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

    pub(in crate::engine::durable) fn from_map(
        map: BTreeMap<ObjectId, ArenaLocation>,
        limit: NonZeroUsize,
    ) -> Result<Self, DurableError> {
        if map.len() < limit.get() {
            return Ok(Self {
                count: map.len(),
                resident: map.into_iter().collect(),
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
            builder.push(id, location)?;
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
        #[cfg(test)]
        if let Some(remaining) = self.damage_after_inserts.as_mut() {
            if *remaining == 0 {
                self.damage_after_inserts = None;
                self.truncate_test_run();
            } else {
                *remaining = remaining.strict_sub(1);
            }
        }
        if self.resident.capacity() < self.limit.get() {
            self.resident
                .try_reserve_exact(self.limit.get().saturating_sub(self.resident.len()))
                .map_err(|_| DurableError::EncodingOverflow)?;
        }
        let previous = self.location(id)?;
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
                Err(at) => self.resident.insert(at, (id, location)),
            }
        }
        self.count = count;
        Ok(())
    }

    fn flush_with(
        &mut self,
        id: ObjectId,
        location: ArenaLocation,
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
            builder.push(id, location)?;
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
            .strict_mul(std::mem::size_of::<(ObjectId, ArenaLocation)>())
    }

    pub(in crate::engine::durable) fn set_limit(
        &mut self,
        limit: NonZeroUsize,
    ) -> Result<(), DurableError> {
        if self.resident.len() >= limit.get() {
            let (id, location) = self.resident[0];
            self.flush_with(id, location, self.count)?;
        }
        // Replace the staging allocation only after any required spill succeeds.
        let mut resident = Vec::new();
        resident
            .try_reserve_exact(limit.get())
            .map_err(|_| DurableError::EncodingOverflow)?;
        resident.append(&mut self.resident);
        self.resident = resident;
        self.limit = limit;
        Ok(())
    }

    pub(in crate::engine::durable) fn failed(&self) -> bool {
        self.failed.load(Ordering::Acquire)
    }

    fn lookup(&self, id: ObjectId) -> Result<Option<ArenaLocation>, DurableError> {
        if let Ok(at) = self.resident.binary_search_by_key(&id, |entry| entry.0) {
            return Ok(Some(self.resident[at].1));
        }
        for run in self.runs.iter().flatten() {
            if let Some(location) = run.lookup(id)? {
                return Ok(Some(location));
            }
        }
        Ok(None)
    }
}

impl LocationLookup for PagedLocations {
    fn location(&self, id: ObjectId) -> Result<Option<ArenaLocation>, DurableError> {
        self.lookup(id)
            .inspect_err(|_| self.failed.store(true, Ordering::Release))
    }

    fn location_count(&self) -> usize {
        self.count
    }

    fn locations(
        &self,
    ) -> Box<dyn Iterator<Item = Result<(ObjectId, ArenaLocation), DurableError>> + '_> {
        let mut sources: Vec<LocationEntries<'_>> = vec![Box::new(
            self.resident
                .iter()
                .map(|(id, location)| Ok((*id, *location))),
        )];
        sources.extend(
            self.runs
                .iter()
                .flatten()
                .map(|run| Box::new(run.entries()) as Box<dyn Iterator<Item = Result<_, _>>>),
        );
        let entries: Box<dyn Iterator<Item = Result<_, _>>> = match MergedEntries::new(sources) {
            Ok(entries) => Box::new(entries),
            Err(error) => Box::new(std::iter::once(Err(error))),
        };
        Box::new(
            entries.map(|entry| entry.inspect_err(|_| self.failed.store(true, Ordering::Release))),
        )
    }
}

fn merge(newer: &Run, older: &Run) -> Result<Run, DurableError> {
    let sources: Vec<LocationEntries<'_>> =
        vec![Box::new(newer.entries()), Box::new(older.entries())];
    let mut builder = Builder::new()?;
    for entry in MergedEntries::new(sources)? {
        let (id, location) = entry?;
        builder.push(id, location)?;
    }
    builder
        .finish()?
        .ok_or(DurableError::InvalidRepresentationState(
            "merged locator lost all entries",
        ))
}

struct MergedEntries<'a> {
    sources: Vec<LocationEntries<'a>>,
    heads: Vec<Option<(ObjectId, ArenaLocation)>>,
    failed: bool,
}

impl<'a> MergedEntries<'a> {
    fn new(mut sources: Vec<LocationEntries<'a>>) -> Result<Self, DurableError> {
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
    type Item = Result<(ObjectId, ArenaLocation), DurableError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        let mut selected = None;
        for entry in self.heads.iter().flatten() {
            if selected.is_none_or(|previous: (ObjectId, ArenaLocation)| previous.0 > entry.0) {
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
