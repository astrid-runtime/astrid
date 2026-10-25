//! Complete reverse catalogue backed by one anonymous authenticated link arena.
//!
//! Every admitted representation stays in its original order. Only paged heads
//! and bounded merge workspace stay resident; canonical maps remain authority.

use super::super::locations::{
    AuthenticatedPageMemo, LocationIndexMemoryBudget, LocationLookup, PagedLocations,
};
use super::super::{ArenaLocation, DurableError, File, append_frame, io_error};
use crate::storage_model::{ObjectId, RepresentationRecordId};
use std::sync::atomic::{AtomicBool, Ordering};

mod chain;
use chain::{Link, MAGIC};

#[derive(Debug)]
pub(super) struct ReverseIndex {
    file: File,
    heads: PagedLocations,
    failed: AtomicBool,
}

impl ReverseIndex {
    pub(super) fn new(budget: LocationIndexMemoryBudget) -> Result<Self, DurableError> {
        Ok(Self {
            file: File::native(
                tempfile::tempfile().map_err(|e| io_error("create reverse locator arena", e))?,
            ),
            heads: PagedLocations::new(budget.durable_entries()),
            failed: AtomicBool::new(false),
        })
    }

    pub(super) fn insert(
        &mut self,
        object: ObjectId,
        id: RepresentationRecordId,
    ) -> Result<(), DurableError> {
        self.insert_first(object, id).map(|_| ())
    }

    /// Return whether this is the earliest admitted representation for object.
    pub(super) fn insert_first(
        &mut self,
        object: ObjectId,
        id: RepresentationRecordId,
    ) -> Result<bool, DurableError> {
        self.insert_first_memo(object, id, &mut AuthenticatedPageMemo::default())
    }

    /// Reuse immutable locator pages during one exclusive catalogue rebuild.
    /// Link bodies are always read and authenticated, even with a warm memo.
    pub(super) fn insert_first_memo(
        &mut self,
        object: ObjectId,
        id: RepresentationRecordId,
        memo: &mut AuthenticatedPageMemo,
    ) -> Result<bool, DurableError> {
        let result = (|| {
            let previous = self
                .heads
                .location_memo(object, memo)?
                .map(|location| self.link(object, location).map(|link| (location, link)))
                .transpose()?;
            let first = previous.is_none();
            let link = Link {
                id,
                first: previous.as_ref().map_or(id, |(_, link)| link.first),
                previous: previous.map(|(location, _)| location),
            };
            let location = append_frame(&mut self.file, MAGIC, &link.encode(object))?;
            self.heads.insert_memo(object, location, memo)?;
            Ok(first)
        })();
        if result.is_err() {
            self.failed.store(true, Ordering::Release);
        }
        result
    }

    fn head(&self, object: ObjectId) -> Result<Option<(ArenaLocation, Link)>, DurableError> {
        self.heads
            .location(object)?
            .map(|location| self.link(object, location).map(|link| (location, link)))
            .transpose()
    }

    pub(super) fn first(
        &self,
        object: ObjectId,
    ) -> Result<Option<RepresentationRecordId>, DurableError> {
        Ok(self.head(object)?.map(|(_, link)| link.first))
    }

    pub(super) fn contains(&self, object: ObjectId) -> Result<bool, DurableError> {
        Ok(self.head(object)?.is_some())
    }

    pub(super) fn keys(&self) -> impl Iterator<Item = Result<ObjectId, DurableError>> + '_ {
        self.heads
            .locations()
            .map(|entry| entry.map(|(object, _)| object))
    }

    pub(super) fn ids_newest_first(&self, object: ObjectId) -> Result<Ids<'_>, DurableError> {
        let head = self.head(object)?;
        Ok(Ids {
            index: self,
            object,
            first: head.as_ref().map(|(_, link)| link.first),
            pending: head.map(|(_, link)| link),
            next: None,
        })
    }

    pub(super) fn equivalent(&self, other: &Self) -> Result<bool, DurableError> {
        let mut left = self.keys();
        let mut right = other.keys();
        loop {
            match (left.next().transpose()?, right.next().transpose()?) {
                (None, None) => return Ok(true),
                (Some(a), Some(b)) if a == b => {
                    let mut a_ids = self.ids_newest_first(a)?;
                    let mut b_ids = other.ids_newest_first(b)?;
                    loop {
                        match (a_ids.next().transpose()?, b_ids.next().transpose()?) {
                            (None, None) => break,
                            (Some(a), Some(b)) if a == b => {},
                            _ => return Ok(false),
                        }
                    }
                },
                _ => return Ok(false),
            }
        }
    }

    pub(super) fn set_memory(
        &mut self,
        budget: LocationIndexMemoryBudget,
    ) -> Result<(), DurableError> {
        let result = self.heads.set_limit(budget.durable_entries());
        if result.is_err() {
            self.failed.store(true, Ordering::Release);
        }
        result
    }

    pub(super) fn failed(&self) -> bool {
        self.failed.load(Ordering::Acquire) || self.heads.failed()
    }

    #[cfg(test)]
    pub(super) fn damage_run_after_inserts(&mut self, count: usize) {
        self.heads.damage_run_after_inserts(count);
    }

    #[cfg(test)]
    pub(super) fn truncate_test_run(&self) {
        self.heads.truncate_test_run();
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.heads.len()
    }

    #[cfg(test)]
    pub(super) fn resident_capacity_bytes(&self) -> usize {
        self.heads.resident_capacity_bytes()
    }

    #[cfg(test)]
    pub(super) fn snapshot(
        &self,
    ) -> Result<std::collections::BTreeMap<ObjectId, Vec<RepresentationRecordId>>, DurableError>
    {
        self.keys()
            .map(|object| {
                let object = object?;
                let mut ids = self
                    .ids_newest_first(object)?
                    .collect::<Result<Vec<_>, _>>()?;
                ids.reverse();
                Ok((object, ids))
            })
            .collect()
    }
}

pub(super) struct Ids<'a> {
    index: &'a ReverseIndex,
    object: ObjectId,
    first: Option<RepresentationRecordId>,
    pending: Option<Link>,
    next: Option<ArenaLocation>,
}

impl Iterator for Ids<'_> {
    type Item = Result<RepresentationRecordId, DurableError>;
    fn next(&mut self) -> Option<Self::Item> {
        let link = if let Some(link) = self.pending.take() {
            Ok(link)
        } else {
            self.index.link(self.object, self.next.take()?)
        };
        match link {
            Ok(link) if Some(link.first) == self.first => {
                self.next = link.previous;
                Some(Ok(link.id))
            },
            Ok(_) => {
                self.next = None;
                self.index.failed.store(true, Ordering::Release);
                Some(Err(chain::corrupt(
                    "reverse link changed its earliest identity",
                )))
            },
            Err(error) => {
                self.next = None;
                Some(Err(error))
            },
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod persistence_tests;
