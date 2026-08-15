//! Prepared and placed direct-canonical arena representations.

use crate::storage_model::{BlobId, ObjectId, RepresentationProfileId};

use super::{ArenaLocation, Blake3PhysicalIdentity, DurableError};

/// Physical identity work that does not depend on the eventual arena offset.
#[derive(Clone, Debug)]
pub(in crate::engine::durable) struct PreparedDirectArenaObject {
    object: ObjectId,
    blob: BlobId,
    canonical_length: u64,
}

impl PreparedDirectArenaObject {
    pub(in crate::engine::durable) fn identify(
        profile: RepresentationProfileId,
        object: ObjectId,
        canonical_record: &[u8],
    ) -> Result<Self, DurableError> {
        Ok(Self {
            object,
            blob: BlobId::identify(&Blake3PhysicalIdentity, profile, canonical_record)?,
            canonical_length: u64::try_from(canonical_record.len())
                .map_err(|_| DurableError::EncodingOverflow)?,
        })
    }

    pub(in crate::engine::durable) const fn place(
        self,
        location: ArenaLocation,
    ) -> DirectArenaObject {
        DirectArenaObject {
            object: self.object,
            blob: self.blob,
            canonical_length: self.canonical_length,
            location,
        }
    }
}

#[derive(Clone, Debug)]
pub(in crate::engine::durable) struct DirectArenaObject {
    pub(in crate::engine::durable) object: ObjectId,
    pub(in crate::engine::durable) blob: BlobId,
    pub(in crate::engine::durable) canonical_length: u64,
    pub(in crate::engine::durable) location: ArenaLocation,
}

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
