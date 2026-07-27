//! Named principal-owned content over canonical chunk DAGs.
//!
//! Content values share the same principal root and immutable object arena as
//! KV. The catalog charges every visible name and byte logically even when
//! chunks or complete files are physically deduplicated.

mod catalog;
mod store;
#[cfg(test)]
mod tests;

use std::{fmt, io};

use astrid_storage_engine::PrincipalProjectionError;
use astrid_storage_model::{ObjectId, RootState};

pub use astrid_storage_content::{ChunkingProfile, ContentDescriptor};
pub use store::{PrincipalContentReadHandle, PrincipalContentStore};

use astrid_storage_content::ContentError;

pub(crate) use catalog::{CONTENT_COMPONENT_LABEL, catalog_quota};

use crate::error::StorageError;

/// Canonical name of one principal-owned content value.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContentName(String);

/// Failure to validate a principal content name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContentNameError {
    /// The name was empty.
    Empty,
    /// The name contained a null byte.
    ContainsNull,
    /// Persisted name bytes were not valid UTF-8.
    InvalidUtf8,
}

impl fmt::Display for ContentNameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("principal content name is empty"),
            Self::ContainsNull => {
                formatter.write_str("principal content name contains a null byte")
            },
            Self::InvalidUtf8 => formatter.write_str("principal content name is not valid UTF-8"),
        }
    }
}

impl std::error::Error for ContentNameError {}

impl ContentName {
    /// Validate a principal content name.
    ///
    /// Names are opaque UTF-8 catalog keys, not host paths. Slash is permitted
    /// and has no traversal semantics.
    ///
    /// # Errors
    ///
    /// Returns [`ContentNameError::Empty`] or
    /// [`ContentNameError::ContainsNull`] when validation fails.
    pub fn new(value: impl Into<String>) -> Result<Self, ContentNameError> {
        let value = value.into();
        if value.is_empty() {
            return Err(ContentNameError::Empty);
        }
        if value.as_bytes().contains(&0) {
            return Err(ContentNameError::ContainsNull);
        }
        Ok(Self(value))
    }

    /// Borrow the canonical UTF-8 name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the name and return its UTF-8 representation.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, PrincipalContentError> {
        let value = std::str::from_utf8(bytes)
            .map_err(|_| PrincipalContentError::InvalidName(ContentNameError::InvalidUtf8))?
            .to_owned();
        Self::new(value).map_err(PrincipalContentError::InvalidName)
    }
}

impl AsRef<str> for ContentName {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for ContentName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::str::FromStr for ContentName {
    type Err = ContentNameError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<String> for ContentName {
    type Error = ContentNameError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ContentName> for String {
    fn from(value: ContentName) -> Self {
        value.into_inner()
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
    ///
    /// This is a kernel-side diagnostic for tests and operations. It must not
    /// cross a capsule, mount, or other principal-visible API boundary because
    /// it reveals whether content already existed in the shared store.
    #[must_use]
    pub const fn objects_inserted(self) -> u64 {
        self.objects_inserted
    }
}

/// Failure to read or mutate principal-owned content.
#[derive(Debug)]
#[non_exhaustive]
pub enum PrincipalContentError {
    /// Content name validation failed.
    InvalidName(ContentNameError),
    /// Canonical content-DAG construction or decoding failed.
    Content(ContentError),
    /// Streaming byte source failed before a complete file was staged.
    ContentSource(io::Error),
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
    QuotaPolicy(StorageError),
}

impl fmt::Display for PrincipalContentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName(error) => error.fmt(formatter),
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

impl std::error::Error for PrincipalContentError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidName(error) => Some(error),
            Self::Content(error) => Some(error),
            Self::ContentSource(error) => Some(error),
            Self::Projection(error) => Some(error),
            Self::QuotaPolicy(error) => Some(error),
            _ => None,
        }
    }
}

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
