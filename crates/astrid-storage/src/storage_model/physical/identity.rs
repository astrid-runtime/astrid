//! Domain-separated current physical identifiers and tagged wire encoding.

use alloc::vec::Vec;

use crate::storage_model::{BlobId, ObjectId};

use super::PhysicalModelError;
use super::codec::{Decoder, Encoder};

const BLAKE3_ALGORITHM: u16 = 1;
const LOGICAL_CONSTRUCTION: u16 = 1;
const PHYSICAL_CONSTRUCTION: u16 = 2;
const CURRENT_DIGEST_BYTES: u32 = 32;

macro_rules! physical_id_newtype {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Construct an identifier from the current physical digest bytes.
            #[must_use]
            pub const fn new(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            /// Borrow the current physical digest bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }
    };
}

physical_id_newtype!(
    /// Identity of one immutable physical representation profile.
    RepresentationProfileId
);
physical_id_newtype!(
    /// Identity of one exact physical representation recipe and coverage record.
    RepresentationRecordId
);
physical_id_newtype!(
    /// Identity of one canonical authenticated physical-map node.
    PhysicalMapNodeId
);
physical_id_newtype!(
    /// Identity of one canonical representation-catalogue root.
    RepresentationCatalogueRootId
);
physical_id_newtype!(
    /// Identity of one atomic representation catalogue and placement pair.
    RepresentationStateId
);

/// Identity of one complete physical placement set.
///
/// The `ObjectId` constructor and accessor retain source compatibility with
/// the pre-catalogue GC evidence grammar. New physical-state code should use
/// [`Self::from_digest`] and [`Self::as_bytes`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PlacementSetId([u8; 32]);

impl PlacementSetId {
    /// Construct the identifier from the legacy logical wrapper.
    #[must_use]
    pub const fn new(object: ObjectId) -> Self {
        Self(*object.as_bytes())
    }

    /// Construct an identifier from the current physical digest bytes.
    #[must_use]
    pub const fn from_digest(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the current physical digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Return the legacy logical wrapper used by GC evidence records.
    #[must_use]
    pub const fn object_id(self) -> ObjectId {
        ObjectId::new(self.0)
    }
}

/// Computes current domain-separated physical identities.
///
/// Native composition pins BLAKE3 construction two. Keeping the primitive
/// injected lets this `no_std` executable model remain hash-agile and lets
/// collision paths be tested without weakening collision comparison.
pub trait PhysicalIdentity {
    /// Hash canonical physical `material` under the exact derive-key context.
    fn identify(&self, context: &'static str, material: &[u8]) -> [u8; 32];

    /// Hash the exact concatenation of canonical material segments.
    ///
    /// Implementations with an incremental primitive should override this to
    /// avoid materializing large representation bytes a second time. The
    /// default preserves source compatibility for injected test and successor
    /// identities by presenting [`Self::identify`] with the same concatenated
    /// preimage as before.
    fn identify_parts(&self, context: &'static str, parts: &[&[u8]]) -> [u8; 32] {
        let capacity = parts
            .iter()
            .fold(0_usize, |total, part| total.saturating_add(part.len()));
        let mut material = Vec::with_capacity(capacity);
        for part in parts {
            material.extend_from_slice(part);
        }
        self.identify(context, &material)
    }
}

pub(super) fn encode_object_id(encoder: &mut Encoder, id: ObjectId) {
    encode_tagged(
        encoder,
        BLAKE3_ALGORITHM,
        LOGICAL_CONSTRUCTION,
        id.as_bytes(),
    );
}

pub(super) fn decode_object_id(decoder: &mut Decoder<'_>) -> Result<ObjectId, PhysicalModelError> {
    decode_tagged(decoder, BLAKE3_ALGORITHM, LOGICAL_CONSTRUCTION).map(ObjectId::new)
}

pub(super) fn encode_blob_id(encoder: &mut Encoder, id: BlobId) {
    encode_tagged(
        encoder,
        BLAKE3_ALGORITHM,
        PHYSICAL_CONSTRUCTION,
        id.as_bytes(),
    );
}

pub(super) fn decode_blob_id(decoder: &mut Decoder<'_>) -> Result<BlobId, PhysicalModelError> {
    decode_tagged(decoder, BLAKE3_ALGORITHM, PHYSICAL_CONSTRUCTION).map(BlobId::new)
}

pub(super) fn encode_profile_id(encoder: &mut Encoder, id: RepresentationProfileId) {
    encode_tagged(
        encoder,
        BLAKE3_ALGORITHM,
        PHYSICAL_CONSTRUCTION,
        id.as_bytes(),
    );
}

pub(super) fn decode_profile_id(
    decoder: &mut Decoder<'_>,
) -> Result<RepresentationProfileId, PhysicalModelError> {
    decode_tagged(decoder, BLAKE3_ALGORITHM, PHYSICAL_CONSTRUCTION)
        .map(RepresentationProfileId::new)
}

pub(super) fn encode_record_id(encoder: &mut Encoder, id: RepresentationRecordId) {
    encode_tagged(
        encoder,
        BLAKE3_ALGORITHM,
        PHYSICAL_CONSTRUCTION,
        id.as_bytes(),
    );
}

pub(super) fn encode_map_node_id(encoder: &mut Encoder, id: PhysicalMapNodeId) {
    encode_physical_digest(encoder, id.as_bytes());
}

pub(super) fn decode_map_node_id(
    decoder: &mut Decoder<'_>,
) -> Result<PhysicalMapNodeId, PhysicalModelError> {
    decode_physical_digest(decoder).map(PhysicalMapNodeId::new)
}

pub(super) fn encode_catalogue_root_id(encoder: &mut Encoder, id: RepresentationCatalogueRootId) {
    encode_physical_digest(encoder, id.as_bytes());
}

pub(super) fn decode_catalogue_root_id(
    decoder: &mut Decoder<'_>,
) -> Result<RepresentationCatalogueRootId, PhysicalModelError> {
    decode_physical_digest(decoder).map(RepresentationCatalogueRootId::new)
}

pub(super) fn encode_placement_set_id(encoder: &mut Encoder, id: PlacementSetId) {
    encode_physical_digest(encoder, id.as_bytes());
}

pub(super) fn decode_placement_set_id(
    decoder: &mut Decoder<'_>,
) -> Result<PlacementSetId, PhysicalModelError> {
    decode_physical_digest(decoder).map(PlacementSetId::from_digest)
}

pub(super) fn encode_state_id(encoder: &mut Encoder, id: RepresentationStateId) {
    encode_physical_digest(encoder, id.as_bytes());
}

pub(super) fn decode_state_id(
    decoder: &mut Decoder<'_>,
) -> Result<RepresentationStateId, PhysicalModelError> {
    decode_physical_digest(decoder).map(RepresentationStateId::new)
}

pub(super) fn decode_record_id(
    decoder: &mut Decoder<'_>,
) -> Result<RepresentationRecordId, PhysicalModelError> {
    decode_tagged(decoder, BLAKE3_ALGORITHM, PHYSICAL_CONSTRUCTION).map(RepresentationRecordId::new)
}

pub(super) fn tagged_profile_bytes(id: RepresentationProfileId) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encode_profile_id(&mut encoder, id);
    encoder.finish()
}

fn encode_tagged(encoder: &mut Encoder, algorithm: u16, construction: u16, digest: &[u8; 32]) {
    encoder.u16(algorithm);
    encoder.u16(construction);
    encoder.u32(CURRENT_DIGEST_BYTES);
    encoder.raw(digest);
}

pub(super) fn encode_physical_digest(encoder: &mut Encoder, digest: &[u8; 32]) {
    encode_tagged(encoder, BLAKE3_ALGORITHM, PHYSICAL_CONSTRUCTION, digest);
}

pub(super) fn decode_physical_digest(
    decoder: &mut Decoder<'_>,
) -> Result<[u8; 32], PhysicalModelError> {
    decode_tagged(decoder, BLAKE3_ALGORITHM, PHYSICAL_CONSTRUCTION)
}

fn decode_tagged(
    decoder: &mut Decoder<'_>,
    expected_algorithm: u16,
    expected_construction: u16,
) -> Result<[u8; 32], PhysicalModelError> {
    let algorithm = decoder.u16()?;
    let construction = decoder.u16()?;
    let digest_length = decoder.u32()?;
    if algorithm == 0 || construction == 0 || digest_length == 0 {
        return Err(PhysicalModelError::ZeroIdentityField);
    }
    if algorithm != expected_algorithm || construction != expected_construction {
        return Err(PhysicalModelError::WrongIdentityScheme);
    }
    let digest_length =
        usize::try_from(digest_length).map_err(|_| PhysicalModelError::LengthOverflow)?;
    let digest = decoder.take(digest_length)?;
    digest
        .try_into()
        .map_err(|_| PhysicalModelError::WrongIdentityDigestLength)
}

impl BlobId {
    /// Derive the format-one identity of profile-bound encoded bytes.
    ///
    /// The encoded profile identity and byte length are part of the preimage,
    /// so equal bytes under incompatible decoders cannot collapse.
    ///
    /// # Errors
    ///
    /// Returns [`PhysicalModelError::LengthOverflow`] when the encoded byte
    /// length does not fit the format-one `u64` field.
    pub fn identify<I: PhysicalIdentity>(
        identity: &I,
        profile: RepresentationProfileId,
        encoded_bytes: &[u8],
    ) -> Result<Self, PhysicalModelError> {
        let length =
            u64::try_from(encoded_bytes.len()).map_err(|_| PhysicalModelError::LengthOverflow)?;
        let mut prefix = tagged_profile_bytes(profile);
        prefix.extend_from_slice(&length.to_le_bytes());
        Ok(Self::new(identity.identify_parts(
            "astrid-blob-identity-v1\0",
            &[&prefix, encoded_bytes],
        )))
    }
}
