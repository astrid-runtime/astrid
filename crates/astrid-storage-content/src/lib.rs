//! Canonical content-defined chunk DAGs for Astrid principal state.
//!
//! This crate turns ordinary bytes into immutable [`ObjectRecord`] values:
//! raw chunks, bounded-fanout chunk trees, and one file descriptor. It does
//! not own principal roots, quotas, placement, encryption, or authorization.
//! Those remain responsibilities of the embedding principal store.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(unreachable_pub)]
#![deny(clippy::unwrap_used)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

extern crate alloc;

#[cfg(feature = "std")]
use alloc::collections::BTreeMap;
#[cfg(feature = "std")]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use astrid_storage_model::ObjectRecord;
use astrid_storage_model::{ModelError, ObjectId};
use core::fmt;

#[cfg(feature = "std")]
mod build;
mod read;
#[cfg(feature = "std")]
mod stream;
#[cfg(all(test, feature = "std"))]
mod stream_tests;
#[cfg(all(test, feature = "std"))]
mod tests;

#[cfg(feature = "std")]
pub use build::{BuiltContent, build_content};
pub use read::{
    ContentReadError, ContentSource, describe_content, read_content, read_content_range,
};
#[cfg(feature = "std")]
pub use stream::{ContentObjectSink, ContentStreamError, StreamedContent, build_content_streaming};

/// Maximum children in one canonical chunk-tree node.
///
/// The value is part of the version-one file-DAG construction profile. It
/// bounds traversal metadata while keeping trees shallow for large content.
pub const CHUNK_TREE_FANOUT: usize = 128;

/// Persistent content-defined chunking parameters.
///
/// The algorithm code, implementation revision, normalization, and gear seed
/// are identity-bearing. Changing any field produces a different file object
/// even when the reconstructed bytes remain the same.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChunkingProfile {
    minimum_bytes: u32,
    average_bytes: u32,
    maximum_bytes: u32,
    gear_seed: u64,
}

impl ChunkingProfile {
    /// Astrid's first pinned `FastCDC` 2020 profile.
    ///
    /// It targets 64 `KiB` average chunks, permits 16–256 `KiB` boundaries,
    /// uses normalization level one, and uses the canonical unseeded gear
    /// table.
    pub const ASTRID_V1: Self = Self {
        minimum_bytes: 16 * 1024,
        average_bytes: 64 * 1024,
        maximum_bytes: 256 * 1024,
        gear_seed: 0,
    };

    /// Construct a validated `FastCDC` 2020 profile.
    ///
    /// # Errors
    ///
    /// Returns [`ContentError::InvalidProfile`] unless sizes are supported by
    /// the pinned implementation and satisfy `minimum < average < maximum`.
    pub fn fastcdc_v2020(
        minimum_bytes: u32,
        average_bytes: u32,
        maximum_bytes: u32,
        gear_seed: u64,
    ) -> Result<Self, ContentError> {
        let minimum = usize::try_from(minimum_bytes)
            .map_err(|_| ContentError::InvalidProfile("minimum size is not addressable"))?;
        let average = usize::try_from(average_bytes)
            .map_err(|_| ContentError::InvalidProfile("average size is not addressable"))?;
        let maximum = usize::try_from(maximum_bytes)
            .map_err(|_| ContentError::InvalidProfile("maximum size is not addressable"))?;
        if !(64..=1_048_576).contains(&minimum)
            || !(256..=4_194_304).contains(&average)
            || !(1024..=16_777_216).contains(&maximum)
        {
            return Err(ContentError::InvalidProfile(
                "chunk sizes are outside FastCDC 2020 bounds",
            ));
        }
        if !(minimum < average && average < maximum) {
            return Err(ContentError::InvalidProfile(
                "chunk sizes must satisfy minimum < average < maximum",
            ));
        }
        if !average.is_power_of_two() {
            return Err(ContentError::InvalidProfile(
                "average chunk size must be a power of two",
            ));
        }
        Ok(Self {
            minimum_bytes,
            average_bytes,
            maximum_bytes,
            gear_seed,
        })
    }

    /// Return the minimum chunk size.
    #[must_use]
    pub const fn minimum_bytes(self) -> u32 {
        self.minimum_bytes
    }

    /// Return the target average chunk size.
    #[must_use]
    pub const fn average_bytes(self) -> u32 {
        self.average_bytes
    }

    /// Return the maximum chunk size.
    #[must_use]
    pub const fn maximum_bytes(self) -> u32 {
        self.maximum_bytes
    }

    /// Return the pinned gear-table seed.
    #[must_use]
    pub const fn gear_seed(self) -> u64 {
        self.gear_seed
    }
}

impl Default for ChunkingProfile {
    fn default() -> Self {
        Self::ASTRID_V1
    }
}

/// Identity and reconstruction metadata for one canonical file object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContentDescriptor {
    file: ObjectId,
    logical_bytes: u64,
    chunk_count: u64,
    profile: ChunkingProfile,
}

impl ContentDescriptor {
    pub(crate) const fn new(
        file: ObjectId,
        logical_bytes: u64,
        chunk_count: u64,
        profile: ChunkingProfile,
    ) -> Self {
        Self {
            file,
            logical_bytes,
            chunk_count,
            profile,
        }
    }

    /// Return the canonical file object identifier.
    #[must_use]
    pub const fn file(self) -> ObjectId {
        self.file
    }

    /// Return the reconstructed byte length.
    #[must_use]
    pub const fn logical_bytes(self) -> u64 {
        self.logical_bytes
    }

    /// Return the number of chunk occurrences in the file.
    #[must_use]
    pub const fn chunk_count(self) -> u64 {
        self.chunk_count
    }

    /// Return the persistent chunking profile.
    #[must_use]
    pub const fn profile(self) -> ChunkingProfile {
        self.profile
    }
}

/// Failure to construct or decode a canonical content DAG.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContentError {
    /// Chunking parameters are unsupported or internally inconsistent.
    InvalidProfile(&'static str),
    /// Input or aggregate metadata exceeded a canonical integer field.
    LengthOverflow,
    /// The object model rejected a canonical record.
    Model(ModelError),
    /// A required object was absent.
    MissingObject(ObjectId),
    /// An object did not match the content-DAG grammar.
    InvalidObject {
        /// Invalid object's identity.
        object: ObjectId,
        /// Stable diagnostic detail.
        detail: &'static str,
    },
    /// A requested range did not fit inside the file.
    RangeOutOfBounds {
        /// Requested start offset.
        offset: u64,
        /// Requested byte length.
        length: u64,
        /// Actual file length.
        file_length: u64,
    },
}

impl fmt::Display for ContentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProfile(detail) => write!(formatter, "invalid chunking profile: {detail}"),
            Self::LengthOverflow => formatter.write_str("content length overflow"),
            Self::Model(error) => write!(formatter, "content object model: {error}"),
            Self::MissingObject(object) => {
                write!(formatter, "content object {object:?} is missing")
            },
            Self::InvalidObject { object, detail } => {
                write!(formatter, "invalid content object {object:?}: {detail}")
            },
            Self::RangeOutOfBounds {
                offset,
                length,
                file_length,
            } => write!(
                formatter,
                "content range {offset}+{length} exceeds file length {file_length}"
            ),
        }
    }
}

impl core::error::Error for ContentError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Model(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ModelError> for ContentError {
    fn from(error: ModelError) -> Self {
        Self::Model(error)
    }
}

pub(crate) const CONTENT_LABEL: &[u8] = b"content";
pub(crate) const FORMAT_VERSION: astrid_storage_model::ObjectFormatVersion =
    astrid_storage_model::ObjectFormatVersion::V1;
pub(crate) const FILE_HEADER_BYTES: usize = 40;

#[cfg(feature = "std")]
pub(crate) fn encode_file_header(
    profile: ChunkingProfile,
    logical_bytes: u64,
    chunk_count: u64,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(FILE_HEADER_BYTES);
    bytes.push(1);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.push(1);
    bytes.extend_from_slice(&profile.minimum_bytes.to_le_bytes());
    bytes.extend_from_slice(&profile.average_bytes.to_le_bytes());
    bytes.extend_from_slice(&profile.maximum_bytes.to_le_bytes());
    bytes.extend_from_slice(&profile.gear_seed.to_le_bytes());
    bytes.extend_from_slice(&logical_bytes.to_le_bytes());
    bytes.extend_from_slice(&chunk_count.to_le_bytes());
    bytes
}

pub(crate) fn decode_file_header(
    object: ObjectId,
    bytes: &[u8],
) -> Result<(ChunkingProfile, u64, u64), ContentError> {
    if bytes.len() != FILE_HEADER_BYTES
        || bytes[0] != 1
        || bytes[1..3] != 1_u16.to_le_bytes()
        || bytes[3] != 1
    {
        return Err(ContentError::InvalidObject {
            object,
            detail: "unsupported file chunking profile",
        });
    }
    let minimum = u32::from_le_bytes(
        bytes[4..8]
            .try_into()
            .map_err(|_| ContentError::LengthOverflow)?,
    );
    let average = u32::from_le_bytes(
        bytes[8..12]
            .try_into()
            .map_err(|_| ContentError::LengthOverflow)?,
    );
    let maximum = u32::from_le_bytes(
        bytes[12..16]
            .try_into()
            .map_err(|_| ContentError::LengthOverflow)?,
    );
    let seed = u64::from_le_bytes(
        bytes[16..24]
            .try_into()
            .map_err(|_| ContentError::LengthOverflow)?,
    );
    let logical_bytes = u64::from_le_bytes(
        bytes[24..32]
            .try_into()
            .map_err(|_| ContentError::LengthOverflow)?,
    );
    let chunk_count = u64::from_le_bytes(
        bytes[32..40]
            .try_into()
            .map_err(|_| ContentError::LengthOverflow)?,
    );
    Ok((
        ChunkingProfile::fastcdc_v2020(minimum, average, maximum, seed)?,
        logical_bytes,
        chunk_count,
    ))
}

#[cfg(feature = "std")]
pub(crate) fn insert_record<I: astrid_storage_model::ObjectIdentity>(
    identity: &I,
    records: &mut BTreeMap<ObjectId, ObjectRecord>,
    record: ObjectRecord,
) -> Result<ObjectId, ContentError> {
    let id = identity.identify(&record);
    match records.get(&id) {
        Some(existing) if existing == &record => {},
        Some(_) => return Err(ContentError::Model(ModelError::ObjectCollision(id))),
        None => {
            records.insert(id, record);
        },
    }
    Ok(id)
}
