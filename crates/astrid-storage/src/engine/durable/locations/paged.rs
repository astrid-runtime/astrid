//! Complete locator with geometric anonymous runs and a bounded resident table.
//!
//! Every admitted location is held in the table or an authenticated run.
//! `Ok(None)` proves absence from the complete locator, never a cache miss.
//! Scratch failures set a recovery fence; the engine rebuilds from durable media.

use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::run::{Builder, PageMemo, Run};
use super::{ArenaLocation, ClosureProof, DurableError, LocationLookup, LocatorValue, ObjectId};

type RowEntries<'a> = Box<dyn Iterator<Item = Result<(ObjectId, LocatorValue), DurableError>> + 'a>;

/// Operation-scoped authenticated page reuse across geometric runs.
///
/// Bound by run count × tree height (one page per level per run). Rebinds or
/// clears whenever `PagedLocations` replaces run storage (`runs_epoch`), so a
/// flushed/merged incarnation cannot satisfy lookups from a prior run.
#[derive(Debug, Default)]
pub(in crate::engine::durable) struct AuthenticatedPageMemo {
    runs_epoch: u64,
    runs: Vec<Option<PageMemo>>,
}

impl AuthenticatedPageMemo {
    fn sync(&mut self, locations: &PagedLocations) {
        let epoch = locations.runs_epoch.load(Ordering::Acquire);
        if self.runs_epoch != epoch || self.runs.len() != locations.runs.len() {
            self.runs_epoch = epoch;
            self.runs.clear();
            self.runs.resize_with(locations.runs.len(), || None);
        }
    }

    fn run_memo(&mut self, index: usize, run: &Run) -> &mut PageMemo {
        if index >= self.runs.len() {
            self.runs.resize_with(index.strict_add(1), || None);
        }
        let slot = &mut self.runs[index];
        if slot.is_none() {
            *slot = Some(PageMemo::default());
        }
        let memo = slot.as_mut().expect("just installed");
        memo.bind(run);
        memo
    }

    #[cfg(test)]
    pub(in crate::engine::durable) fn test_hit_miss(&self) -> (usize, usize) {
        self.runs
            .iter()
            .flatten()
            .fold((0, 0), |(hits, misses), memo| {
                (
                    hits.strict_add(memo.test_hits()),
                    misses.strict_add(memo.test_misses()),
                )
            })
    }
}

#[derive(Debug)]
pub(in crate::engine::durable) struct PagedLocations {
    resident: Vec<(ObjectId, LocatorValue)>,
    runs: Vec<Option<Run>>,
    /// Bumped whenever `runs` is replaced or cleared so page memos rebind.
    runs_epoch: AtomicU64,
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
            runs_epoch: AtomicU64::new(0),
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
                runs_epoch: AtomicU64::new(0),
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
            runs_epoch: AtomicU64::new(0),
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
        self.insert_memo(id, location, &mut AuthenticatedPageMemo::default())
    }

    pub(in crate::engine::durable) fn insert_memo(
        &mut self,
        id: ObjectId,
        location: ArenaLocation,
        memo: &mut AuthenticatedPageMemo,
    ) -> Result<(), DurableError> {
        let prior = self.row_before_insert_memo(id, memo)?;
        let result = self.insert_row(
            id,
            LocatorValue {
                location,
                proof: prior.map_or(ClosureProof::Unknown, |prior| prior.proof),
            },
            prior,
        );
        memo.sync(self);
        result
    }

    pub(in crate::engine::durable) fn clear_proofs(&mut self) -> Result<(), DurableError> {
        if self.failed() {
            return Err(DurableError::InvalidRepresentationState(
                "cannot reset failed locator proofs",
            ));
        }
        let mut rebuild = RebuildLocations::new(self.limit);
        for entry in self.locations() {
            let (id, location) = entry?;
            rebuild.push(id, location, ClosureProof::Unknown)?;
        }
        let (replacement, _) = rebuild.finish()?;
        self.runs_epoch.fetch_add(1, Ordering::AcqRel);
        replacement
            .runs_epoch
            .store(self.runs_epoch.load(Ordering::Acquire), Ordering::Release);
        *self = replacement;
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
        let previous = self.row_before_insert(id)?;
        let mut row = previous.ok_or(DurableError::InvalidRepresentationState(
            "closure proof has no object locator",
        ))?;
        row.proof = ClosureProof::Complete;
        let result = self.insert_row(id, row, previous);
        if result.is_err() {
            self.failed.store(true, Ordering::Release);
        }
        result
    }

    fn row(&self, id: ObjectId) -> Result<Option<LocatorValue>, DurableError> {
        self.lookup(id)
            .inspect_err(|_| self.failed.store(true, Ordering::Release))
    }

    fn row_before_insert(&mut self, id: ObjectId) -> Result<Option<LocatorValue>, DurableError> {
        #[cfg(test)]
        if let Some(remaining) = self.damage_after_inserts.as_mut() {
            if *remaining == 0 {
                self.damage_after_inserts = None;
                self.truncate_test_run();
            } else {
                *remaining = remaining.strict_sub(1);
            }
        }
        self.row(id)
    }

    fn insert_row(
        &mut self,
        id: ObjectId,
        location: LocatorValue,
        previous: Option<LocatorValue>,
    ) -> Result<(), DurableError> {
        // The exclusive borrow keeps the authenticated prior row valid through
        // the mutation; proof preservation and count admission share that read.
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
        // Bump before publishing replacement runs so in-flight page memos cannot
        // authenticate against a superseded incarnation at the same level/offset.
        self.runs_epoch.fetch_add(1, Ordering::AcqRel);
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

    #[cfg(test)]
    pub(in crate::engine::durable) fn test_spilled_run_count(&self) -> usize {
        self.runs.iter().flatten().count()
    }

    pub(in crate::engine::durable) fn clear(&mut self) {
        self.resident = Vec::new();
        self.runs.clear();
        self.runs.shrink_to_fit();
        self.runs_epoch.fetch_add(1, Ordering::AcqRel);
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
        // Anonymous run bytes are immutable in production. Test fault injection
        // bumps the epoch so operation memos cannot serve pre-damage pages.
        self.runs_epoch.fetch_add(1, Ordering::AcqRel);
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

    fn rows(&self) -> RowEntries<'_> {
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
        Box::new(
            entries.map(|entry| entry.inspect_err(|_| self.failed.store(true, Ordering::Release))),
        )
    }

    fn lookup(&self, id: ObjectId) -> Result<Option<LocatorValue>, DurableError> {
        self.lookup_memo(id, &mut AuthenticatedPageMemo::default())
    }

    fn lookup_memo(
        &self,
        id: ObjectId,
        memo: &mut AuthenticatedPageMemo,
    ) -> Result<Option<LocatorValue>, DurableError> {
        memo.sync(self);
        if let Ok(at) = self.resident.binary_search_by_key(&id, |entry| entry.0) {
            return Ok(Some(self.resident[at].1));
        }
        for (index, slot) in self.runs.iter().enumerate() {
            let Some(run) = slot else {
                continue;
            };
            let run_memo = memo.run_memo(index, run);
            if let Some(location) = run.lookup_row_memoized(id, run_memo)? {
                return Ok(Some(location));
            }
        }
        Ok(None)
    }

    pub(in crate::engine::durable) fn closure_proven_memo(
        &self,
        id: ObjectId,
        memo: &mut AuthenticatedPageMemo,
    ) -> Result<bool, DurableError> {
        Ok(self
            .row_memo(id, memo)?
            .is_some_and(|row| row.proof == ClosureProof::Complete))
    }

    pub(in crate::engine::durable) fn location_memo(
        &self,
        id: ObjectId,
        memo: &mut AuthenticatedPageMemo,
    ) -> Result<Option<ArenaLocation>, DurableError> {
        Ok(self.row_memo(id, memo)?.map(|row| row.location))
    }

    pub(in crate::engine::durable) fn mark_proven_memo(
        &mut self,
        id: ObjectId,
        memo: &mut AuthenticatedPageMemo,
    ) -> Result<(), DurableError> {
        let previous = self.row_before_insert_memo(id, memo)?;
        let mut row = previous.ok_or(DurableError::InvalidRepresentationState(
            "closure proof has no object locator",
        ))?;
        row.proof = ClosureProof::Complete;
        let result = self.insert_row(id, row, previous);
        if result.is_err() {
            self.failed.store(true, Ordering::Release);
        }
        // insert_row may have flushed and bumped runs_epoch; drop stale pages.
        memo.sync(self);
        result
    }

    fn row_memo(
        &self,
        id: ObjectId,
        memo: &mut AuthenticatedPageMemo,
    ) -> Result<Option<LocatorValue>, DurableError> {
        self.lookup_memo(id, memo)
            .inspect_err(|_| self.failed.store(true, Ordering::Release))
    }

    fn row_before_insert_memo(
        &mut self,
        id: ObjectId,
        memo: &mut AuthenticatedPageMemo,
    ) -> Result<Option<LocatorValue>, DurableError> {
        #[cfg(test)]
        if let Some(remaining) = self.damage_after_inserts.as_mut() {
            if *remaining == 0 {
                self.damage_after_inserts = None;
                self.truncate_test_run();
                memo.sync(self);
            } else {
                *remaining = remaining.strict_sub(1);
            }
        }
        self.row_memo(id, memo)
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
        Box::new(
            self.rows()
                .map(|entry| entry.map(|(id, row)| (id, row.location))),
        )
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

mod rebuild;
pub(in crate::engine::durable) use rebuild::RebuildLocations;

#[cfg(test)]
mod tests;
