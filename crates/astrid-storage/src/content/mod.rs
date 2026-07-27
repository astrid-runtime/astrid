//! Named principal-owned content over canonical chunk DAGs.
//!
//! Content values share the same principal root and immutable object arena as
//! KV. The catalog charges every visible name and byte logically even when
//! chunks or complete files are physically deduplicated.

mod catalog;
mod store;
#[cfg(test)]
mod tests;

use std::fmt;

use astrid_storage_engine::PrincipalProjectionError;
use astrid_storage_model::{ObjectId, RootState};

pub use astrid_storage_content::{ChunkingProfile, ContentDescriptor};
pub use store::PrincipalContentStore;

use astrid_storage_content::ContentError;

pub(crate) use catalog::{CONTENT_COMPONENT_LABEL, catalog_quota};

/// Canonical name of one principal-owned content value.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContentName(String);

impl ContentName {
    /// Validate a principal content name.
    ///
    /// Names are opaque UTF-8 catalog keys, not host paths. Slash is permitted
    /// and has no traversal semantics.
    ///
    /// # Errors
    ///
    /// Returns [`PrincipalContentError::InvalidName`] for an empty name or one
    /// containing a null byte.
    pub fn new(value: impl Into<String>) -> Result<Self, PrincipalContentError> {
        let value = value.into();
        if value.is_empty() || value.as_bytes().contains(&0) {
            return Err(PrincipalContentError::InvalidName);
        }
        Ok(Self(value))
    }

    /// Borrow the canonical UTF-8 name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, PrincipalContentError> {
        let value = std::str::from_utf8(bytes)
            .map_err(|_| PrincipalContentError::InvalidName)?
            .to_owned();
        Self::new(value)
    }
}

impl AsRef<str> for ContentName {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// One named entry in a principal's content catalog.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContentEntry {
    name: ContentName,
    file: ObjectId,
    logical_bytes: u64,
}

impl ContentEntry {
    pub(crate) const fn new(name: ContentName, file: ObjectId, logical_bytes: u64) -> Self {
        Self {
            name,
            file,
            logical_bytes,
        }
    }

    /// Borrow the catalog name.
    #[must_use]
    pub const fn name(&self) -> &ContentName {
        &self.name
    }

    /// Return the immutable file object.
    #[must_use]
    pub const fn file(&self) -> ObjectId {
        self.file
    }

    /// Return the visible byte length.
    #[must_use]
    pub const fn logical_bytes(&self) -> u64 {
        self.logical_bytes
    }
}

/// Result of one successful content publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContentWriteOutcome {
    descriptor: ContentDescriptor,
    principal_root: RootState,
    objects_inserted: u64,
}

impl ContentWriteOutcome {
    pub(crate) const fn new(
        descriptor: ContentDescriptor,
        principal_root: RootState,
        objects_inserted: u64,
    ) -> Self {
        Self {
            descriptor,
            principal_root,
            objects_inserted,
        }
    }

    /// Return the immutable file descriptor.
    #[must_use]
    pub const fn descriptor(self) -> ContentDescriptor {
        self.descriptor
    }

    /// Return the newly authoritative principal root.
    #[must_use]
    pub const fn principal_root(self) -> RootState {
        self.principal_root
    }

    /// Return the number of newly admitted physical objects.
    #[must_use]
    pub const fn objects_inserted(self) -> u64 {
        self.objects_inserted
    }
}

/// Failure to read or mutate principal-owned content.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PrincipalContentError {
    /// Content name was empty, non-UTF-8 on decode, or contained a null byte.
    InvalidName,
    /// Canonical content-DAG construction or decoding failed.
    Content(ContentError),
    /// Streaming byte source failed before a complete file was staged.
    ContentSource(String),
    /// Shared principal projection engine failed.
    Projection(PrincipalProjectionError),
    /// Principal state or catalog did not match its canonical grammar.
    InvalidGraph {
        /// Invalid object.
        object: ObjectId,
        /// Stable diagnostic detail.
        detail: &'static str,
    },
    /// Accounting exceeded its integer representation.
    AccountingOverflow,
    /// A growth operation exceeded the principal's live storage budget.
    QuotaExceeded {
        /// Logical and name bytes after the proposed write.
        used: u64,
        /// Effective principal limit.
        limit: u64,
    },
    /// Live quota resolution failed.
    QuotaPolicy(String),
}

impl fmt::Display for PrincipalContentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName => formatter.write_str("invalid principal content name"),
            Self::Content(error) => error.fmt(formatter),
            Self::ContentSource(error) => write!(formatter, "principal content source: {error}"),
            Self::Projection(error) => error.fmt(formatter),
            Self::InvalidGraph { object, detail } => {
                write!(
                    formatter,
                    "invalid principal content graph {object:?}: {detail}"
                )
            },
            Self::AccountingOverflow => {
                formatter.write_str("principal content accounting overflow")
            },
            Self::QuotaExceeded { used, limit } => {
                write!(
                    formatter,
                    "principal content quota exceeded: {used} > {limit}"
                )
            },
            Self::QuotaPolicy(error) => {
                write!(formatter, "resolve principal content quota: {error}")
            },
        }
    }
}

impl std::error::Error for PrincipalContentError {}

impl From<ContentError> for PrincipalContentError {
    fn from(error: ContentError) -> Self {
        Self::Content(error)
    }
}

impl From<PrincipalProjectionError> for PrincipalContentError {
    fn from(error: PrincipalProjectionError) -> Self {
        Self::Projection(error)
    }
}
