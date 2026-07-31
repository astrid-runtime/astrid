//! Deterministic host-filesystem names for byte-exact content keys.
//!
//! The principal catalog remains authoritative. These types describe a
//! disposable, rebuildable mapping for one target volume and never change a
//! [`ContentName`](super::ContentName).

mod planner;
#[cfg(test)]
mod tests;

use std::fmt;
use std::num::NonZeroU16;

use serde::{Deserialize, Serialize};

use super::ContentName;
use astrid_core::kernel_api::{
    ProjectionNameCollisionDiagnostic, ProjectionNameDiagnostic, ProjectionNameEscapeDiagnostic,
    ProjectionNamePolicyPreset,
};

pub use planner::plan_projection_names;

/// Versioned Unicode comparison applied independently to each path segment.
///
/// Canonical variants pin Unicode 17.0 normalization tables; caseless
/// variants pin Unicode 16.0 full-fold tables. A future table change receives
/// a new variant rather than changing an existing comparison key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ProjectionNameComparison {
    /// Compare exact UTF-8 bytes.
    ByteExactV1,
    /// Compare Unicode canonical equivalents while preserving case.
    UnicodeCanonicalV1,
    /// Compare full default case folds without canonical normalization.
    UnicodeCaselessV1,
    /// Compare canonical equivalents after full default case folding.
    UnicodeCanonicalCaselessV1,
}

impl ProjectionNameComparison {
    /// Stable policy token used in diagnostics and persisted provider metadata.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::ByteExactV1 => "byte-exact-v1",
            Self::UnicodeCanonicalV1 => "unicode17-nfd-v1",
            Self::UnicodeCaselessV1 => "unicode16-default-fold-v1",
            Self::UnicodeCanonicalCaselessV1 => "unicode17-nfd-unicode16-default-fold-v1",
        }
    }
}

/// Target-volume syntax and segment-length accounting.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ProjectionNameSyntax {
    /// POSIX-style names, measured as UTF-8 bytes.
    PosixUtf8V1,
    /// Windows-compatible names, measured as UTF-16 code units.
    WindowsUtf16V1,
}

impl ProjectionNameSyntax {
    /// Stable policy token used in diagnostics and persisted provider metadata.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::PosixUtf8V1 => "posix-utf8-v1",
            Self::WindowsUtf16V1 => "windows-utf16-v1",
        }
    }
}

/// Target-volume naming contract selected from probed volume behavior.
///
/// The operating-system name is not sufficient: APFS, ext4, and NTFS-family
/// volumes can expose different comparison behavior depending on volume and
/// directory configuration. Providers persist the selected policy beside
/// disposable projection metadata and pass the same value to doctor. A
/// conservative comparison superset is safe; a policy weaker than the target
/// volume is not.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectionNamePolicy {
    comparison: ProjectionNameComparison,
    syntax: ProjectionNameSyntax,
    max_segment_units: NonZeroU16,
}

impl ProjectionNamePolicy {
    /// Construct a detected or explicitly selected target-volume policy.
    #[must_use]
    pub const fn new(
        comparison: ProjectionNameComparison,
        syntax: ProjectionNameSyntax,
        max_segment_units: NonZeroU16,
    ) -> Self {
        Self {
            comparison,
            syntax,
            max_segment_units,
        }
    }

    /// Byte-exact POSIX policy with the common 255-byte segment ceiling.
    #[must_use]
    pub fn posix_exact_v1() -> Self {
        Self::new(
            ProjectionNameComparison::ByteExactV1,
            ProjectionNameSyntax::PosixUtf8V1,
            common_segment_limit(),
        )
    }

    /// Canonical-equivalence POSIX policy with a 255-byte segment ceiling.
    #[must_use]
    pub fn unicode_canonical_v1() -> Self {
        Self::new(
            ProjectionNameComparison::UnicodeCanonicalV1,
            ProjectionNameSyntax::PosixUtf8V1,
            common_segment_limit(),
        )
    }

    /// Canonical-and-caseless POSIX policy with a 255-byte segment ceiling.
    #[must_use]
    pub fn unicode_canonical_caseless_v1() -> Self {
        Self::new(
            ProjectionNameComparison::UnicodeCanonicalCaselessV1,
            ProjectionNameSyntax::PosixUtf8V1,
            common_segment_limit(),
        )
    }

    /// Caseless Windows-compatible policy with a 255 UTF-16-unit ceiling.
    #[must_use]
    pub fn windows_caseless_v1() -> Self {
        Self::new(
            ProjectionNameComparison::UnicodeCaselessV1,
            ProjectionNameSyntax::WindowsUtf16V1,
            common_segment_limit(),
        )
    }

    /// Return the segment comparison behavior.
    #[must_use]
    pub const fn comparison(self) -> ProjectionNameComparison {
        self.comparison
    }

    /// Return the target syntax behavior.
    #[must_use]
    pub const fn syntax(self) -> ProjectionNameSyntax {
        self.syntax
    }

    /// Return the target's segment-length ceiling in syntax-specific units.
    #[must_use]
    pub const fn max_segment_units(self) -> NonZeroU16 {
        self.max_segment_units
    }

    /// Return a stable, complete diagnostic identifier for this policy.
    #[must_use]
    pub fn identifier(self) -> String {
        format!(
            "astrid-projection-names-v1/{}/{}/{}",
            self.comparison.token(),
            self.syntax.token(),
            self.max_segment_units
        )
    }
}

impl From<ProjectionNamePolicyPreset> for ProjectionNamePolicy {
    fn from(preset: ProjectionNamePolicyPreset) -> Self {
        match preset {
            ProjectionNamePolicyPreset::PosixExactV1 => Self::posix_exact_v1(),
            ProjectionNamePolicyPreset::UnicodeCanonicalV1 => Self::unicode_canonical_v1(),
            ProjectionNamePolicyPreset::UnicodeCanonicalCaselessV1 => {
                Self::unicode_canonical_caseless_v1()
            },
            ProjectionNamePolicyPreset::WindowsCaselessV1 => Self::windows_caseless_v1(),
        }
    }
}

fn common_segment_limit() -> NonZeroU16 {
    match NonZeroU16::new(255) {
        Some(limit) => limit,
        None => unreachable!("255 is non-zero"),
    }
}

/// One target-safe projected path segment.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProjectedNameSegment(String);

impl ProjectedNameSegment {
    pub(crate) fn new(value: String) -> Self {
        Self(value)
    }

    /// Borrow the segment text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProjectedNameSegment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One relative target path. Separators are adapter concerns, not stored text.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProjectedContentPath(Vec<ProjectedNameSegment>);

impl ProjectedContentPath {
    pub(crate) fn new(segments: Vec<ProjectedNameSegment>) -> Self {
        Self(segments)
    }

    /// Borrow the ordered path segments.
    #[must_use]
    pub fn segments(&self) -> &[ProjectedNameSegment] {
        &self.0
    }

    /// Render a diagnostic form with `/` separators.
    ///
    /// Adapters must materialize [`Self::segments`] directly and must not parse
    /// this display string back into authority.
    #[must_use]
    pub fn display_path(&self) -> String {
        self.0
            .iter()
            .map(ProjectedNameSegment::as_str)
            .collect::<Vec<_>>()
            .join("/")
    }
}

impl fmt::Display for ProjectedContentPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.display_path())
    }
}

/// Rebuildable mapping from one exact catalog key to one projected path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectionNameMapping {
    source: ContentName,
    projected: ProjectedContentPath,
}

impl ProjectionNameMapping {
    pub(crate) const fn new(source: ContentName, projected: ProjectedContentPath) -> Self {
        Self { source, projected }
    }

    /// Borrow the exact authoritative content name.
    #[must_use]
    pub const fn source(&self) -> &ContentName {
        &self.source
    }

    /// Borrow the target-safe projected path.
    #[must_use]
    pub const fn projected(&self) -> &ProjectedContentPath {
        &self.projected
    }
}

/// Reason a set of source names cannot share their natural projected spelling.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ProjectionCollisionKind {
    /// Distinct segments compare equal under the selected policy.
    EquivalentSegments,
    /// One source requires a file where another requires a directory.
    FileDirectoryConflict,
}

impl ProjectionCollisionKind {
    /// Stable token used by diagnostics.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::EquivalentSegments => "equivalent-segments",
            Self::FileDirectoryConflict => "file-directory-conflict",
        }
    }
}

/// One collision group reported without mutating the catalog or projection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectionCollisionGroup {
    kind: ProjectionCollisionKind,
    sources: Vec<ContentName>,
    projected: Vec<ProjectedContentPath>,
}

impl ProjectionCollisionGroup {
    pub(crate) fn new(
        kind: ProjectionCollisionKind,
        sources: Vec<ContentName>,
        projected: Vec<ProjectedContentPath>,
    ) -> Self {
        Self {
            kind,
            sources,
            projected,
        }
    }

    /// Return the collision class.
    #[must_use]
    pub const fn kind(&self) -> ProjectionCollisionKind {
        self.kind
    }

    /// Borrow the exact authoritative names in deterministic byte order.
    #[must_use]
    pub fn sources(&self) -> &[ContentName] {
        &self.sources
    }

    /// Borrow the final non-colliding display paths in source order.
    #[must_use]
    pub fn projected(&self) -> &[ProjectedContentPath] {
        &self.projected
    }
}

/// Reason a source name required an escaped target spelling.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ProjectionEscapeReason {
    /// The source segment was empty, `.` or `..`.
    StructuralSegment,
    /// The target syntax rejects at least one source character.
    InvalidTargetCharacter,
    /// The target syntax reserves the source basename.
    ReservedTargetName,
    /// The source ends in a target-significant character.
    SignificantTrailingCharacter,
    /// The source contains Astrid's reserved disambiguation marker.
    ReservedProjectionMarker,
    /// The natural segment exceeds the target's length ceiling.
    SegmentTooLong,
}

impl ProjectionEscapeReason {
    /// Stable token used by diagnostics.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::StructuralSegment => "structural-segment",
            Self::InvalidTargetCharacter => "invalid-target-character",
            Self::ReservedTargetName => "reserved-target-name",
            Self::SignificantTrailingCharacter => "significant-trailing-character",
            Self::ReservedProjectionMarker => "reserved-projection-marker",
            Self::SegmentTooLong => "segment-too-long",
        }
    }
}

/// One name whose natural spelling cannot be represented without escaping.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectionEscapedName {
    source: ContentName,
    segment_index: u32,
    reason: ProjectionEscapeReason,
    projected: ProjectedContentPath,
}

impl ProjectionEscapedName {
    pub(crate) const fn new(
        source: ContentName,
        segment_index: u32,
        reason: ProjectionEscapeReason,
        projected: ProjectedContentPath,
    ) -> Self {
        Self {
            source,
            segment_index,
            reason,
            projected,
        }
    }

    /// Borrow the exact authoritative name.
    #[must_use]
    pub const fn source(&self) -> &ContentName {
        &self.source
    }

    /// Return the zero-based source segment index.
    #[must_use]
    pub const fn segment_index(&self) -> u32 {
        self.segment_index
    }

    /// Return the reason an escaped spelling was required.
    #[must_use]
    pub const fn reason(&self) -> ProjectionEscapeReason {
        self.reason
    }

    /// Borrow the final target-safe path.
    #[must_use]
    pub const fn projected(&self) -> &ProjectedContentPath {
        &self.projected
    }
}

/// Complete read-only result for one catalog and target-volume policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectionNamePlan {
    policy: ProjectionNamePolicy,
    mappings: Vec<ProjectionNameMapping>,
    collisions: Vec<ProjectionCollisionGroup>,
    escaped: Vec<ProjectionEscapedName>,
}

impl ProjectionNamePlan {
    pub(crate) fn new(
        policy: ProjectionNamePolicy,
        mappings: Vec<ProjectionNameMapping>,
        collisions: Vec<ProjectionCollisionGroup>,
        escaped: Vec<ProjectionEscapedName>,
    ) -> Self {
        Self {
            policy,
            mappings,
            collisions,
            escaped,
        }
    }

    /// Return the exact target policy used.
    #[must_use]
    pub const fn policy(&self) -> ProjectionNamePolicy {
        self.policy
    }

    /// Borrow every reversible mapping, sorted by exact source name.
    #[must_use]
    pub fn mappings(&self) -> &[ProjectionNameMapping] {
        &self.mappings
    }

    /// Borrow collision groups reported by doctor.
    #[must_use]
    pub fn collisions(&self) -> &[ProjectionCollisionGroup] {
        &self.collisions
    }

    /// Borrow names that required escaping for the target.
    #[must_use]
    pub fn escaped(&self) -> &[ProjectionEscapedName] {
        &self.escaped
    }

    /// Find the projected path for an exact source key.
    #[must_use]
    pub fn projected_path(&self, source: &ContentName) -> Option<&ProjectedContentPath> {
        self.mappings
            .binary_search_by(|mapping| mapping.source().cmp(source))
            .ok()
            .map(|index| self.mappings[index].projected())
    }
}

impl From<ProjectionNamePlan> for ProjectionNameDiagnostic {
    fn from(plan: ProjectionNamePlan) -> Self {
        Self {
            policy: plan.policy().identifier(),
            catalog_entries: u64::try_from(plan.mappings().len()).unwrap_or(u64::MAX),
            collisions: plan
                .collisions()
                .iter()
                .map(|collision| ProjectionNameCollisionDiagnostic {
                    kind: collision.kind().token().to_owned(),
                    sources: collision
                        .sources()
                        .iter()
                        .map(|source| source.as_str().to_owned())
                        .collect(),
                    projected_segments: collision
                        .projected()
                        .iter()
                        .map(projected_segments)
                        .collect(),
                })
                .collect(),
            escaped: plan
                .escaped()
                .iter()
                .map(|escaped| ProjectionNameEscapeDiagnostic {
                    source: escaped.source().as_str().to_owned(),
                    segment_index: escaped.segment_index(),
                    reason: escaped.reason().token().to_owned(),
                    projected_segments: projected_segments(escaped.projected()),
                })
                .collect(),
        }
    }
}

fn projected_segments(path: &ProjectedContentPath) -> Vec<String> {
    path.segments()
        .iter()
        .map(|segment| segment.as_str().to_owned())
        .collect()
}

/// Planning failure that must stop projection publication.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProjectionNameError {
    /// The target segment ceiling cannot hold Astrid's collision-safe suffix.
    SegmentLimitTooSmall {
        /// Configured target ceiling.
        configured: NonZeroU16,
        /// Minimum required units for the selected syntax.
        minimum: u16,
    },
    /// Two distinct source candidates produced the same digest suffix.
    DigestCollision {
        /// First exact source name.
        first: ContentName,
        /// Second exact source name.
        second: ContentName,
    },
    /// Final projected paths still collide under the selected comparison.
    OutputCollision {
        /// First exact source name.
        first: ContentName,
        /// Second exact source name.
        second: ContentName,
    },
    /// A catalog path contains more segments than the diagnostic wire shape.
    TooManySegments {
        /// Exact source name.
        source: ContentName,
    },
    /// Planner state lost the projected path for an exact source.
    MissingPlannedMapping {
        /// Exact source name.
        source: ContentName,
    },
}

impl fmt::Display for ProjectionNameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SegmentLimitTooSmall {
                configured,
                minimum,
            } => write!(
                formatter,
                "target segment limit {configured} is smaller than the collision-safe minimum {minimum}"
            ),
            Self::DigestCollision { first, second } => write!(
                formatter,
                "projection suffix digest collision between exact names '{first}' and '{second}'"
            ),
            Self::OutputCollision { first, second } => write!(
                formatter,
                "projected paths still collide for exact names '{first}' and '{second}'"
            ),
            Self::TooManySegments { source } => {
                write!(
                    formatter,
                    "content name has too many path segments: '{source}'"
                )
            },
            Self::MissingPlannedMapping { source } => {
                write!(
                    formatter,
                    "projection planner lost the mapping for exact name '{source}'"
                )
            },
        }
    }
}

impl std::error::Error for ProjectionNameError {}

/// Result of one adapter-owned atomic target-path reservation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProjectionReservationOutcome {
    /// The caller exclusively reserved the path for this exact source.
    Reserved,
    /// The path already belongs to the same exact source; retry is idempotent.
    AlreadyReservedForSource,
}

/// Atomic publication-time reservation implemented by each filesystem adapter.
///
/// The check and reservation must be one target-filesystem operation. A
/// preflight `exists()` followed by `create()` does not implement this trait's
/// contract. Adapters must compare the exact source name stored in their
/// disposable mapping metadata before returning an idempotent outcome.
pub trait AtomicProjectionNameReservation {
    /// Adapter-specific failure.
    type Error;

    /// Atomically reserve `mapping.projected()` for `mapping.source()`.
    ///
    /// A path owned by another exact source must return an error and must
    /// never overwrite, alias, or silently reuse the existing path.
    ///
    /// # Errors
    ///
    /// Returns the adapter error when the reservation cannot be completed
    /// atomically, including when another exact source owns the target path.
    fn reserve_atomically(
        &self,
        mapping: &ProjectionNameMapping,
    ) -> Result<ProjectionReservationOutcome, Self::Error>;
}
