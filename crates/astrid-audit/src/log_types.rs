use astrid_capabilities::AuditEntryId;
use astrid_crypto::ContentHash;

/// O(1) system-wide audit accounting and retention state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditGlobalStats {
    /// Number of entries represented by the global projection.
    pub total_count: u64,
    /// Canonical bytes represented by the global projection.
    pub total_bytes: u64,
    /// Number of sealed segments in the ordered segment projection.
    pub sealed_segments: u64,
    /// Number of active and sealed segments in the ordered projection.
    pub segments: u64,
    /// Number of sealed segments eligible for retention pruning.
    pub eligible_segments: u64,
    /// Maximum entries before the system enters degraded retention state.
    pub cap_entries: u64,
    /// Maximum bytes before the system enters degraded retention state.
    pub cap_bytes: u64,
    /// Whether the configured cap has been exceeded or metadata is degraded.
    pub degraded: bool,
    /// Most recent cap or metadata error, if degraded.
    pub last_error: Option<String>,
}

/// Result of chain verification.
#[derive(Debug, Clone)]
pub struct ChainVerificationResult {
    /// Whether the chain is valid.
    pub valid: bool,
    /// Number of entries verified.
    pub entries_verified: usize,
    /// Issues found (empty if valid).
    pub issues: Vec<ChainIssue>,
}

/// An issue found during chain verification.
#[derive(Debug, Clone)]
pub enum ChainIssue {
    /// First entry doesn't have zero previous hash.
    InvalidGenesis {
        /// The entry with invalid genesis.
        entry_id: AuditEntryId,
    },
    /// Entry has invalid signature.
    InvalidSignature {
        /// Entry with invalid signature.
        entry_id: AuditEntryId,
    },
    /// Chain link is broken.
    BrokenLink {
        /// The entry with broken link.
        entry_id: AuditEntryId,
        /// Expected previous hash.
        expected_previous: ContentHash,
        /// Actual previous hash in entry.
        actual_previous: ContentHash,
    },
}

impl std::fmt::Display for ChainIssue {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidGenesis { entry_id } => {
                write!(formatter, "Invalid genesis at {entry_id}")
            },
            Self::InvalidSignature { entry_id } => {
                write!(formatter, "Invalid signature at {entry_id}")
            },
            Self::BrokenLink { entry_id, .. } => {
                write!(formatter, "Broken chain link at {entry_id}")
            },
        }
    }
}
