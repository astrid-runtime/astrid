//! Prepared and placed direct-canonical arena representations.

use crate::storage_model::{BlobId, ObjectId, RepresentationProfileId};

use super::{ArenaLocation, Blake3PhysicalIdentity, DurableError};

/// Physical identity work that does not depend on the eventual arena offset.
pub(in crate::engine::durable) type PreparedDirectArenaObject =
    super::super::direct_placement::Prepared<ObjectId, BlobId>;

impl PreparedDirectArenaObject {
    pub(in crate::engine::durable) fn identify(
        profile: RepresentationProfileId,
        object: ObjectId,
        canonical_record: &[u8],
    ) -> Result<Self, DurableError> {
        Self::from_bytes(object, profile, canonical_record, |profile, bytes| {
            BlobId::identify(&Blake3PhysicalIdentity, profile, bytes).map_err(DurableError::from)
        })
    }
}

pub(in crate::engine::durable) type DirectArenaObject =
    super::super::direct_placement::Placed<ObjectId, BlobId, ArenaLocation>;

impl DirectArenaObject {
    pub(in crate::engine::durable) fn identify(
        profile: RepresentationProfileId,
        object: ObjectId,
        canonical_record: &[u8],
        location: ArenaLocation,
    ) -> Result<Self, DurableError> {
        Ok(PreparedDirectArenaObject::identify(profile, object, canonical_record)?.place(location))
    }
}

mod update;

#[cfg(test)]
mod tests;
