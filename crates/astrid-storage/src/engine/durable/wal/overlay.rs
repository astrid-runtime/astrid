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
use super::super::root_transition::PreparedRoot;
use super::super::{ArenaLocation, DurableError, ModelError};

#[path = "overlay_object.rs"]
mod overlay_object;
pub(in crate::engine::durable) use overlay_object::read_snapshot;

/// One immutable object retained by the pending WAL overlay.
///
/// `location` is populated for an object that was already appended to the
/// canonical arena by staging.  WAL-created objects have no canonical
/// location until the next checkpoint folds them.
pub(in crate::engine::durable) type PendingWalObject =
    overlay_object::Object<Arc<ObjectRecord>, ArenaLocation, DirectArenaObject>;

impl PendingWalObject {
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

/// Committed WAL state that has not yet been folded into canonical files.
#[derive(Debug)]
pub(in crate::engine::durable) struct PendingWalOverlay<P: Ord> {
    objects: BTreeMap<ObjectId, PendingWalObject>,
    roots: Vec<PreparedRoot<P, RootState>>,
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

    /// Borrow the committed object index for transaction closure lookup.
    pub(in crate::engine::durable) fn object_index(&self) -> &BTreeMap<ObjectId, PendingWalObject> {
        &self.objects
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
        overlay_object::install(&mut self.objects, id, incoming)
            .map_err(|()| ModelError::ObjectCollision(id).into())
    }

    /// Retain one root transition in publication order.
    pub(in crate::engine::durable) fn retain_root(&mut self, root: &PreparedRoot<P, RootState>)
    where
        P: Clone,
    {
        root.retain(&mut self.roots);
    }

    /// Borrow the journal payloads in the order retained by publication.
    pub(in crate::engine::durable) fn journals(&self) -> Vec<&[u8]> {
        super::super::frontier::journals(&self.roots, PreparedRoot::journal_bytes)
    }

    /// Remove all pending state for one checkpoint fold.
    pub(in crate::engine::durable) fn take(&mut self) -> Self {
        std::mem::take(self)
    }
}
