//! In-memory authority for transaction-WAL commits awaiting canonical folding.
//!
//! A transaction-WAL publication makes its object and root records durable in
//! `transactions.wal` before the canonical arena and root journal are touched.
//! This overlay keeps those records visible to the live engine while the WAL
//! remains the publication authority.  Checkpointing consumes the overlay once
//! and folds its entries into the canonical files before retiring the WAL.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::storage_model::{ObjectId, ObjectRecord, RootState};

use super::super::representations::DirectArenaObject;
use super::super::{ArenaLocation, DurableError, ModelError};

/// One immutable object retained by the pending WAL overlay.
///
/// `location` is populated for an object that was already appended to the
/// canonical arena by staging.  WAL-created objects have no canonical
/// location until the next checkpoint folds them.
#[derive(Clone, Debug)]
pub(in crate::engine::durable) struct PendingWalObject {
    payload: Arc<[u8]>,
    record: Arc<ObjectRecord>,
    location: Option<ArenaLocation>,
    direct: Option<DirectArenaObject>,
}

impl PendingWalObject {
    pub(in crate::engine::durable) fn staged(
        payload: Arc<[u8]>,
        record: Arc<ObjectRecord>,
        location: ArenaLocation,
        direct: Option<DirectArenaObject>,
    ) -> Self {
        Self {
            payload,
            record,
            location: Some(location),
            direct,
        }
    }

    pub(in crate::engine::durable) fn prepared(
        payload: Arc<[u8]>,
        record: Arc<ObjectRecord>,
    ) -> Self {
        Self {
            payload,
            record,
            location: None,
            direct: None,
        }
    }

    pub(in crate::engine::durable) fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub(in crate::engine::durable) fn payload_arc(&self) -> Arc<[u8]> {
        Arc::clone(&self.payload)
    }

    pub(in crate::engine::durable) fn record(&self) -> &ObjectRecord {
        &self.record
    }

    pub(in crate::engine::durable) const fn location(&self) -> Option<ArenaLocation> {
        self.location
    }

    pub(in crate::engine::durable) fn direct(&self) -> Option<&DirectArenaObject> {
        self.direct.as_ref()
    }
}

/// One root transition retained until the canonical root journal is folded.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub(in crate::engine::durable) struct PendingWalRoot<P> {
    principal: P,
    expected: Option<RootState>,
    replacement: RootState,
    journal: Vec<u8>,
}

#[allow(dead_code)]
impl<P> PendingWalRoot<P> {
    pub(in crate::engine::durable) fn new(
        principal: P,
        expected: Option<RootState>,
        replacement: RootState,
        journal: Vec<u8>,
    ) -> Self {
        Self {
            principal,
            expected,
            replacement,
            journal,
        }
    }

    pub(in crate::engine::durable) fn principal(&self) -> &P {
        &self.principal
    }

    pub(in crate::engine::durable) const fn expected(&self) -> Option<RootState> {
        self.expected
    }

    pub(in crate::engine::durable) const fn replacement(&self) -> RootState {
        self.replacement
    }

    pub(in crate::engine::durable) fn journal(&self) -> &[u8] {
        &self.journal
    }
}

/// Committed WAL state that has not yet been folded into canonical files.
#[derive(Debug)]
pub(in crate::engine::durable) struct PendingWalOverlay<P: Ord> {
    objects: BTreeMap<ObjectId, PendingWalObject>,
    roots: Vec<PendingWalRoot<P>>,
}

impl<P: Ord> Default for PendingWalOverlay<P> {
    fn default() -> Self {
        Self {
            objects: BTreeMap::new(),
            roots: Vec::new(),
        }
    }
}

impl<P: Ord> PendingWalOverlay<P> {
    #[allow(dead_code)]
    pub(in crate::engine::durable) fn is_empty(&self) -> bool {
        self.objects.is_empty() && self.roots.is_empty()
    }

    /// Return whether the overlay already carries this immutable object.
    pub(in crate::engine::durable) fn contains_object(&self, id: &ObjectId) -> bool {
        self.objects.contains_key(id)
    }

    /// Return all overlay objects in identity order.
    pub(in crate::engine::durable) fn objects(
        &self,
    ) -> impl Iterator<Item = (&ObjectId, &PendingWalObject)> {
        self.objects.iter()
    }

    /// Return an overlay object by identity.
    #[allow(dead_code)]
    pub(in crate::engine::durable) fn get_object(
        &self,
        id: &ObjectId,
    ) -> Option<&PendingWalObject> {
        self.objects.get(id)
    }

    /// Add a staged object whose canonical frame already has a physical
    /// location. Equal identities are idempotent; divergent bytes are a
    /// content-addressed collision.
    pub(in crate::engine::durable) fn insert_staged(
        &mut self,
        id: ObjectId,
        payload: Arc<[u8]>,
        record: Arc<ObjectRecord>,
        location: ArenaLocation,
        direct: Option<DirectArenaObject>,
    ) -> Result<(), DurableError> {
        self.insert(
            id,
            PendingWalObject::staged(payload, record, location, direct),
        )
    }

    /// Add a newly WAL-published object awaiting canonical folding.
    pub(in crate::engine::durable) fn insert_prepared(
        &mut self,
        id: ObjectId,
        payload: Arc<[u8]>,
        record: Arc<ObjectRecord>,
    ) -> Result<(), DurableError> {
        self.insert(id, PendingWalObject::prepared(payload, record))
    }

    fn insert(&mut self, id: ObjectId, incoming: PendingWalObject) -> Result<(), DurableError> {
        match self.objects.entry(id) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(incoming);
                Ok(())
            },
            std::collections::btree_map::Entry::Occupied(entry)
                if entry.get().payload() == incoming.payload() =>
            {
                // A staged location is stronger evidence than a pending
                // location.  Preserve it when a later group repeats an equal
                // WAL object.
                if entry.get().location().is_none() && incoming.location().is_some() {
                    let existing = entry.into_mut();
                    existing.location = incoming.location;
                    existing.direct = incoming.direct;
                }
                Ok(())
            },
            std::collections::btree_map::Entry::Occupied(_) => {
                Err(ModelError::ObjectCollision(id).into())
            },
        }
    }

    /// Retain one root transition in publication order.
    pub(in crate::engine::durable) fn push_root(
        &mut self,
        principal: P,
        expected: Option<RootState>,
        replacement: RootState,
        journal: Vec<u8>,
    ) {
        self.roots.push(PendingWalRoot::new(
            principal,
            expected,
            replacement,
            journal,
        ));
    }

    /// Return root transitions in the order they were WAL-published.
    pub(in crate::engine::durable) fn roots(&self) -> &[PendingWalRoot<P>] {
        &self.roots
    }

    /// Remove all pending state for one checkpoint fold.
    pub(in crate::engine::durable) fn take(&mut self) -> Self {
        std::mem::take(self)
    }
}
