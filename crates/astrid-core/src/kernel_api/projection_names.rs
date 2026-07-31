//! Caller-scoped projection-name diagnostics carried over the management API.

use serde::{Deserialize, Serialize};

/// Wire method for the additive caller-scoped projection diagnostic protocol.
pub const PROJECTION_NAME_DIAGNOSTIC_METHOD: &str = "ProjectionNameDiagnosticV1";

/// Topic suffix for projection diagnostic request/response correlation.
pub const PROJECTION_NAME_DIAGNOSTIC_TOPIC: &str = "projection_names";

/// Named target-volume policy accepted by `astrid doctor`.
///
/// These are behavior profiles, not operating-system labels. The caller
/// selects the profile matching the volume or provider metadata it is
/// inspecting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProjectionNamePolicyPreset {
    /// Byte-exact POSIX-style comparison and syntax.
    PosixExactV1,
    /// Canonical-equivalence comparison with POSIX-style syntax.
    UnicodeCanonicalV1,
    /// Canonical-and-caseless comparison with POSIX-style syntax.
    UnicodeCanonicalCaselessV1,
    /// Caseless comparison with Windows-compatible syntax.
    WindowsCaselessV1,
}

/// Read-only caller-scoped projection-name diagnostic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectionNameDiagnostic {
    /// Complete versioned policy identifier evaluated by the daemon.
    pub policy: String,
    /// Number of exact authoritative catalog entries evaluated.
    pub catalog_entries: u64,
    /// Natural-name collision groups.
    pub collisions: Vec<ProjectionNameCollisionDiagnostic>,
    /// Names whose natural spelling required escaping.
    pub escaped: Vec<ProjectionNameEscapeDiagnostic>,
}

/// One natural-name collision group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectionNameCollisionDiagnostic {
    /// Stable collision-kind token.
    pub kind: String,
    /// Exact source names in byte order.
    pub sources: Vec<String>,
    /// Final target-safe paths aligned with `sources`.
    pub projected_segments: Vec<Vec<String>>,
}

/// One exact source whose natural spelling required escaping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectionNameEscapeDiagnostic {
    /// Exact source name.
    pub source: String,
    /// Zero-based source segment index.
    pub segment_index: u32,
    /// Stable escape-reason token.
    pub reason: String,
    /// Final target-safe path.
    pub projected_segments: Vec<String>,
}
