//! Canonical exact-byte physical representation model.
//!
//! These values sit below logical [`crate::ObjectId`] identity. They describe
//! how exact canonical object records can be reconstructed without changing
//! principal roots, logical accounting, or materialized exports.

use core::fmt;

mod codec;
mod identity;
mod profile;
mod representation;

pub use identity::{PhysicalIdentity, RepresentationProfileId, RepresentationRecordId};
pub use profile::{
    Dependency, ProfileDependency, ProfileKind, ReconstructionBounds, RepresentationProfile,
};
pub use representation::{CanonicalChunkingProfile, Coverage, Recipe, RepresentationRecord};

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
        }
    }
}

impl core::error::Error for PhysicalModelError {}

#[cfg(test)]
mod tests;
