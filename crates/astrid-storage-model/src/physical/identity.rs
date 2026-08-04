//! Domain-separated current physical identifiers and tagged wire encoding.

use alloc::vec::Vec;

use crate::{BlobId, ObjectId};

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

/// Computes current domain-separated physical identities.
///
/// Native composition pins BLAKE3 construction two. Keeping the primitive
/// injected lets this `no_std` executable model remain hash-agile and lets
/// collision paths be tested without weakening collision comparison.
pub trait PhysicalIdentity {
    /// Hash canonical physical `material` under the exact derive-key context.
    fn identify(&self, context: &'static str, material: &[u8]) -> [u8; 32];
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
        let mut material = tagged_profile_bytes(profile);
        material.extend_from_slice(&length.to_le_bytes());
        material.extend_from_slice(encoded_bytes);
        Ok(Self::new(
            identity.identify("astrid-blob-identity-v1\0", &material),
        ))
    }
}
