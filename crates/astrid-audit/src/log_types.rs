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
    /// Set while the cap is exceeded because every prunable segment holds
    /// history that is not anchored; says why.
    pub retention_hold: Option<String>,
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
#[non_exhaustive]
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
    /// A format-v2 entry's sequence number does not follow its predecessor.
    SequenceGap {
        /// The entry out of sequence.
        entry_id: AuditEntryId,
        /// The sequence number the chain position requires.
        expected: u64,
        /// The signed sequence number.
        actual: u64,
    },
    /// A format-v2 entry is signed by a key the key registry does not list
    /// for the audit role at the entry's key epoch (or there is no registry),
    /// or a format-v1 entry's key is not registered when that is required.
    UnregisteredKey {
        /// The entry.
        entry_id: AuditEntryId,
    },
    /// A format-v2 entry's chain id does not match the registry, session and
    /// principal it is derived from.
    ChainIdMismatch {
        /// The entry.
        entry_id: AuditEntryId,
    },
    /// A format-v1 entry follows a format-v2 entry in the same chain.
    FormatDowngrade {
        /// The v1 entry.
        entry_id: AuditEntryId,
    },
    /// A format-v2 entry names an older key epoch than its predecessor.
    KeyEpochRegression {
        /// The entry.
        entry_id: AuditEntryId,
    },
    /// An entry cannot be interpreted under its format.
    MalformedEntry {
        /// The entry.
        entry_id: AuditEntryId,
        /// What is wrong.
        reason: String,
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
            Self::SequenceGap {
                entry_id,
                expected,
                actual,
            } => write!(
                formatter,
                "Sequence gap at {entry_id}: expected {expected}, found {actual}"
            ),
            Self::UnregisteredKey { entry_id } => {
                write!(
                    formatter,
                    "Entry {entry_id} is signed by an unregistered key"
                )
            },
            Self::ChainIdMismatch { entry_id } => {
                write!(formatter, "Chain id mismatch at {entry_id}")
            },
            Self::FormatDowngrade { entry_id } => {
                write!(
                    formatter,
                    "Format-v1 entry {entry_id} follows a format-v2 entry"
                )
            },
            Self::KeyEpochRegression { entry_id } => {
                write!(formatter, "Key epoch regresses at {entry_id}")
            },
            Self::MalformedEntry { entry_id, reason } => {
                write!(formatter, "Malformed entry {entry_id}: {reason}")
            },
        }
    }
}
