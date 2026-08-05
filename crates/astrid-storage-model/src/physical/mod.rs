//! Canonical exact-byte physical representation model.
//!
//! These values sit below logical [`crate::ObjectId`] identity. They describe
//! how exact canonical object records can be reconstructed without changing
//! principal roots, logical accounting, or materialized exports.

use core::fmt;

mod catalogue;
mod codec;
mod identity;
mod map;
mod placement;
mod profile;
mod representation;
mod state;

pub use catalogue::RepresentationCatalogueRoot;
pub use identity::{
    PhysicalIdentity, PhysicalMapNodeId, PlacementSetId, RepresentationCatalogueRootId,
    RepresentationProfileId, RepresentationRecordId, RepresentationStateId,
};
pub use map::{CanonicalPhysicalMap, PhysicalMapDomain, PhysicalMapKey, PhysicalMapNode};
pub use placement::{PlacementEntry, PlacementSet, Replica, ReplicaLocator};
pub use profile::{
    Dependency, ProfileDependency, ProfileKind, ReconstructionBounds, RepresentationProfile,
};
pub use representation::{CanonicalChunkingProfile, Coverage, Recipe, RepresentationRecord};
pub use state::RepresentationState;

/// Validation or canonical-wire failure in the physical representation model.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PhysicalModelError {
    /// A collection or byte string did not fit the format-one `u64` length.
    LengthOverflow,
    /// Canonical bytes ended before a complete field could be decoded.
    Truncated,
    /// Canonical bytes contained data after the one complete value.
    TrailingBytes,
    /// An identity carried zero algorithm, construction, or digest length.
    ZeroIdentityField,
    /// An identity used a scheme not accepted for that typed field.
    WrongIdentityScheme,
    /// An identity digest did not have the current construction's width.
    WrongIdentityDigestLength,
    /// An option tag was neither absent nor present.
    InvalidOptionTag,
    /// A discriminant was not assigned by the format-one grammar.
    UnknownTag(&'static str, u8),
    /// A set-like sequence was duplicated or not strictly ordered.
    NonCanonicalCollection(&'static str),
    /// A reconstruction bound was zero.
    ZeroReconstructionBound(&'static str),
    /// A profile combined fields or dependencies that its kind forbids.
    InvalidProfile(&'static str),
    /// File coverage contradicted its chunking shape.
    InvalidCoverage(&'static str),
    /// A recipe contradicted its coverage or evidence requirements.
    InvalidRecipe(&'static str),
    /// A reconstruction byte bound was smaller than the canonical output.
    ReconstructionBoundTooSmall,
    /// Decoding and canonical re-encoding did not reproduce the input bytes.
    NonCanonicalEncoding,
    /// An authenticated physical map violated its canonical trie grammar.
    InvalidMap(&'static str),
    /// A representation catalogue root contradicted its map roots or counts.
    InvalidCatalogue(&'static str),
    /// A blob placement or placement set violated its canonical grammar.
    InvalidPlacement(&'static str),
    /// A representation-state transition violated generation or pairing rules.
    InvalidRepresentationState(&'static str),
}

impl fmt::Display for PhysicalModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LengthOverflow => formatter.write_str("physical value length overflow"),
            Self::Truncated => formatter.write_str("truncated physical value"),
            Self::TrailingBytes => formatter.write_str("trailing physical value bytes"),
            Self::ZeroIdentityField => formatter.write_str("zero tagged-identity field"),
            Self::WrongIdentityScheme => formatter.write_str("wrong tagged-identity scheme"),
            Self::WrongIdentityDigestLength => {
                formatter.write_str("wrong tagged-identity digest length")
            },
            Self::InvalidOptionTag => formatter.write_str("invalid physical option tag"),
            Self::UnknownTag(field, tag) => write!(formatter, "unknown {field} tag {tag}"),
            Self::NonCanonicalCollection(field) => {
                write!(formatter, "non-canonical {field} collection")
            },
            Self::ZeroReconstructionBound(field) => {
                write!(formatter, "zero reconstruction bound {field}")
            },
            Self::InvalidProfile(detail) => write!(formatter, "invalid profile: {detail}"),
            Self::InvalidCoverage(detail) => write!(formatter, "invalid coverage: {detail}"),
            Self::InvalidRecipe(detail) => write!(formatter, "invalid recipe: {detail}"),
            Self::ReconstructionBoundTooSmall => {
                formatter.write_str("reconstruction bound is smaller than canonical output")
            },
            Self::NonCanonicalEncoding => {
                formatter.write_str("physical value has a second non-canonical encoding")
            },
            Self::InvalidMap(detail) => write!(formatter, "invalid physical map: {detail}"),
            Self::InvalidCatalogue(detail) => {
                write!(formatter, "invalid representation catalogue: {detail}")
            },
            Self::InvalidPlacement(detail) => write!(formatter, "invalid placement: {detail}"),
            Self::InvalidRepresentationState(detail) => {
                write!(formatter, "invalid representation state: {detail}")
            },
        }
    }
}

impl core::error::Error for PhysicalModelError {}

#[cfg(test)]
mod catalogue_tests;
#[cfg(test)]
mod tests;
