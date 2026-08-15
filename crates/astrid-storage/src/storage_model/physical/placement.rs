//! Canonical physical blob placement and replica locators.

use alloc::vec::Vec;

use crate::storage_model::{BlobId, StorageNodeId};

use super::PhysicalModelError;
use super::codec::{Decoder, Encoder};
use super::identity::{
    PhysicalIdentity, PhysicalMapNodeId, PlacementSetId, RepresentationProfileId, decode_blob_id,
    decode_map_node_id, decode_profile_id, encode_blob_id, encode_map_node_id, encode_profile_id,
};

const PLACEMENT_SET_VERSION: u16 = 1;
const FRAME_HEADER_BYTES: u64 = 52;

/// Canonical location of one encoded blob replica.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplicaLocator {
    /// One frame in an append-only blob or legacy object arena.
    ArenaFrame {
        /// Arena generation; zero selects the legacy `objects.arena`.
        arena_generation: u64,
        /// Byte offset of the physical frame header.
        offset: u64,
        /// Exact frame payload length.
        payload_length: u64,
        /// Exact checksum copied from the frame header.
        frame_checksum: [u8; 32],
    },
    /// One raw blob under a generation-scoped namespace.
    LooseBlob {
        /// Namespace generation containing the blob and its metadata sibling.
        namespace_generation: u64,
    },
    /// One complete frame within an immutable pack.
    PackFrame {
        /// Pack generation containing the frame.
        pack_generation: u64,
        /// Byte offset of the frame header.
        offset: u64,
        /// Complete header-plus-payload byte length.
        frame_length: u64,
        /// Exact checksum copied from the frame header.
        frame_checksum: [u8; 32],
    },
}

impl ReplicaLocator {
    const fn code(self) -> u8 {
        match self {
            Self::ArenaFrame { .. } => 0,
            Self::LooseBlob { .. } => 1,
            Self::PackFrame { .. } => 2,
        }
    }

    fn validate(self) -> Result<(), PhysicalModelError> {
        match self {
            Self::ArenaFrame {
                payload_length: 0, ..
            } => Err(PhysicalModelError::InvalidPlacement(
                "arena payload length is zero",
            )),
            Self::PackFrame { frame_length, .. } if frame_length <= FRAME_HEADER_BYTES => Err(
                PhysicalModelError::InvalidPlacement("pack frame has no payload"),
            ),
            _ => Ok(()),
        }
    }

    fn encode_into(self, encoder: &mut Encoder) {
        encoder.u8(self.code());
        match self {
            Self::ArenaFrame {
                arena_generation,
                offset,
                payload_length,
                frame_checksum,
            } => {
                encoder.u64(arena_generation);
                encoder.u64(offset);
                encoder.u64(payload_length);
                encoder.raw(&frame_checksum);
            },
            Self::LooseBlob {
                namespace_generation,
            } => encoder.u64(namespace_generation),
            Self::PackFrame {
                pack_generation,
                offset,
                frame_length,
                frame_checksum,
            } => {
                encoder.u64(pack_generation);
                encoder.u64(offset);
                encoder.u64(frame_length);
                encoder.raw(&frame_checksum);
            },
        }
    }

    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, PhysicalModelError> {
        let locator = match decoder.u8()? {
            0 => Self::ArenaFrame {
                arena_generation: decoder.u64()?,
                offset: decoder.u64()?,
                payload_length: decoder.u64()?,
                frame_checksum: decoder
                    .take(32)?
                    .try_into()
                    .map_err(|_| PhysicalModelError::Truncated)?,
            },
            1 => Self::LooseBlob {
                namespace_generation: decoder.u64()?,
            },
            2 => Self::PackFrame {
                pack_generation: decoder.u64()?,
                offset: decoder.u64()?,
                frame_length: decoder.u64()?,
                frame_checksum: decoder
                    .take(32)?
                    .try_into()
                    .map_err(|_| PhysicalModelError::Truncated)?,
            },
            tag => return Err(PhysicalModelError::UnknownTag("replica-locator", tag)),
        };
        locator.validate()?;
        Ok(locator)
    }

    fn canonical_bytes(self) -> Vec<u8> {
        let mut encoder = Encoder::new();
        self.encode_into(&mut encoder);
        encoder.finish()
    }
}

/// One placed copy of an encoded blob.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Replica {
    storage_node: StorageNodeId,
    locator: ReplicaLocator,
}

impl Replica {
    /// Construct one checked replica.
    ///
    /// # Errors
    ///
    /// Rejects a structurally impossible locator.
    pub fn new(
        storage_node: StorageNodeId,
        locator: ReplicaLocator,
    ) -> Result<Self, PhysicalModelError> {
        locator.validate()?;
        Ok(Self {
            storage_node,
            locator,
        })
    }

    /// Return the operator-configured storage node.
    #[must_use]
    pub const fn storage_node(self) -> StorageNodeId {
        self.storage_node
    }

    /// Return the canonical replica locator.
    #[must_use]
    pub const fn locator(self) -> ReplicaLocator {
        self.locator
    }

    fn canonical_key(self) -> (u32, u8, Vec<u8>) {
        (
            self.storage_node.get(),
            self.locator.code(),
            self.locator.canonical_bytes(),
        )
    }

    fn encode_into(self, encoder: &mut Encoder) {
        encoder.u32(self.storage_node.get());
        self.locator.encode_into(encoder);
    }

    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, PhysicalModelError> {
        Self::new(
            StorageNodeId::new(decoder.u32()?),
            ReplicaLocator::decode_from(decoder)?,
        )
    }
}

impl Ord for Replica {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.canonical_key().cmp(&other.canonical_key())
    }
}

impl PartialOrd for Replica {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Canonical placement metadata for one encoded blob.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlacementEntry {
    blob: BlobId,
    profile: RepresentationProfileId,
    encoded_length: u64,
    replicas: Vec<Replica>,
}

impl PlacementEntry {
    /// Construct one canonical placement and sort its replica set.
    ///
    /// # Errors
    ///
    /// Rejects an empty or duplicated replica set.
    pub fn new(
        blob: BlobId,
        profile: RepresentationProfileId,
        encoded_length: u64,
        mut replicas: Vec<Replica>,
    ) -> Result<Self, PhysicalModelError> {
        replicas.sort_unstable();
        if replicas.is_empty() {
            return Err(PhysicalModelError::InvalidPlacement("replica set is empty"));
        }
        if replicas.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(PhysicalModelError::InvalidPlacement(
                "replica set contains a duplicate",
            ));
        }
        Ok(Self {
            blob,
            profile,
            encoded_length,
            replicas,
        })
    }

    /// Return the placed blob identity.
    #[must_use]
    pub const fn blob(&self) -> BlobId {
        self.blob
    }

    /// Return the profile required to decode the blob.
    #[must_use]
    pub const fn profile(&self) -> RepresentationProfileId {
        self.profile
    }

    /// Return the exact encoded blob length.
    #[must_use]
    pub const fn encoded_length(&self) -> u64 {
        self.encoded_length
    }

    /// Borrow the sorted non-empty replica set.
    #[must_use]
    pub fn replicas(&self) -> &[Replica] {
        &self.replicas
    }

    /// Encode the byte-exact format-one placement entry.
    ///
    /// # Errors
    ///
    /// Returns a length overflow when the replica count cannot fit `u64`.
    pub fn encode(&self) -> Result<Vec<u8>, PhysicalModelError> {
        let mut encoder = Encoder::new();
        encode_blob_id(&mut encoder, self.blob);
        encode_profile_id(&mut encoder, self.profile);
        encoder.u64(self.encoded_length);
        encoder.count(self.replicas.len())?;
        for replica in &self.replicas {
            replica.encode_into(&mut encoder);
        }
        Ok(encoder.finish())
    }

    /// Decode one canonical format-one placement entry.
    ///
    /// # Errors
    ///
    /// Rejects invalid locators, unordered replicas, trailing bytes, and
    /// second encodings.
    pub fn decode(bytes: &[u8]) -> Result<Self, PhysicalModelError> {
        let mut decoder = Decoder::new(bytes);
        let blob = decode_blob_id(&mut decoder)?;
        let profile = decode_profile_id(&mut decoder)?;
        let encoded_length = decoder.u64()?;
        let replica_count = decoder.length()?;
        if replica_count > decoder.remaining() / 13 {
            return Err(PhysicalModelError::Truncated);
        }
        let mut replicas = Vec::new();
        replicas
            .try_reserve(replica_count)
            .map_err(|_| PhysicalModelError::LengthOverflow)?;
        for _ in 0..replica_count {
            replicas.push(Replica::decode_from(&mut decoder)?);
        }
        decoder.finish()?;
        if replicas.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(PhysicalModelError::NonCanonicalCollection("replica"));
        }
        let value = Self::new(blob, profile, encoded_length, replicas)?;
        if value.encode()?.as_slice() != bytes {
            return Err(PhysicalModelError::NonCanonicalEncoding);
        }
        Ok(value)
    }
}

/// Root and exact summaries of the authoritative placement map.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlacementSet {
    epoch: u64,
    entries_root: Option<PhysicalMapNodeId>,
    blob_count: u64,
    replica_extent_count: u64,
}

impl PlacementSet {
    /// Construct one checked placement-set root.
    ///
    /// # Errors
    ///
    /// Empty and non-empty root/count shapes must agree. Closure validation
    /// proves both positive counts exactly.
    pub fn new(
        epoch: u64,
        entries_root: Option<PhysicalMapNodeId>,
        blob_count: u64,
        replica_extent_count: u64,
    ) -> Result<Self, PhysicalModelError> {
        if entries_root.is_some() != (blob_count != 0) {
            return Err(PhysicalModelError::InvalidPlacement(
                "placement root and blob count disagree",
            ));
        }
        if (blob_count == 0) != (replica_extent_count == 0) {
            return Err(PhysicalModelError::InvalidPlacement(
                "blob and replica counts disagree",
            ));
        }
        if replica_extent_count < blob_count {
            return Err(PhysicalModelError::InvalidPlacement(
                "replica count is smaller than blob count",
            ));
        }
        Ok(Self {
            epoch,
            entries_root,
            blob_count,
            replica_extent_count,
        })
    }

    /// Return the placement epoch.
    #[must_use]
    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    /// Return the authenticated placement-map root.
    #[must_use]
    pub const fn entries_root(self) -> Option<PhysicalMapNodeId> {
        self.entries_root
    }

    /// Return the exact placed-blob count.
    #[must_use]
    pub const fn blob_count(self) -> u64 {
        self.blob_count
    }

    /// Return the exact sum of replica extents.
    #[must_use]
    pub const fn replica_extent_count(self) -> u64 {
        self.replica_extent_count
    }

    /// Encode the byte-exact format-one placement-set grammar.
    #[must_use]
    pub fn encode(self) -> Vec<u8> {
        let mut encoder = Encoder::new();
        encoder.u16(PLACEMENT_SET_VERSION);
        encoder.u64(self.epoch);
        match self.entries_root {
            Some(root) => {
                encoder.u8(1);
                encode_map_node_id(&mut encoder, root);
            },
            None => encoder.u8(0),
        }
        encoder.u64(self.blob_count);
        encoder.u64(self.replica_extent_count);
        encoder.finish()
    }

    /// Decode one canonical format-one placement set.
    ///
    /// # Errors
    ///
    /// Rejects contradictory counts, invalid options, trailing bytes, and
    /// second encodings.
    pub fn decode(bytes: &[u8]) -> Result<Self, PhysicalModelError> {
        let mut decoder = Decoder::new(bytes);
        if decoder.u16()? != PLACEMENT_SET_VERSION {
            return Err(PhysicalModelError::InvalidPlacement(
                "unsupported placement-set version",
            ));
        }
        let value = Self::new(
            decoder.u64()?,
            decoder.option(decode_map_node_id)?,
            decoder.u64()?,
            decoder.u64()?,
        )?;
        decoder.finish()?;
        if value.encode().as_slice() != bytes {
            return Err(PhysicalModelError::NonCanonicalEncoding);
        }
        Ok(value)
    }

    /// Derive the domain-separated placement-set identity.
    #[must_use]
    pub fn identify<I: PhysicalIdentity>(self, identity: &I) -> PlacementSetId {
        PlacementSetId::from_digest(identity.identify("astrid-placement-set-v1\0", &self.encode()))
    }
}
