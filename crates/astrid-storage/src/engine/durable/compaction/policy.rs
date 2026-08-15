//! Explicit native liveness policy for destructive compaction.

use crate::storage_model::{ObjectId, RetentionPolicyId};

/// Explicit liveness policy supplied by native composition.
///
/// Current principal roots are always retained. Additional roots cover
/// operator pins, independent audit anchors, open-handle closures, and
/// externally rooted bootstrap objects. There is intentionally no default
/// history policy: the caller must identify the exact retained policy object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactionRetention {
    operation_contract: ObjectId,
    policy: RetentionPolicyId,
    additional_roots: Vec<CompactionRetainedRoot>,
}

/// Native reason an object closure remains live during compaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum CompactionRootKind {
    /// Store or runtime bootstrap data retained independently of a principal.
    System,
    /// Named checkpoint, legal hold, or operator-selected history pin.
    ExplicitPin,
    /// Export, import, ingest, placement, or other bounded operation lease.
    OperationLease,
    /// Immutable content selected by a currently open read handle.
    ReadHandle,
    /// Condemned content awaiting the selected resurrection-fence epoch.
    Quarantine,
    /// Evidence retained by an audit or re-attestation custody policy.
    AuditCustody,
}

impl CompactionRootKind {
    pub(super) const fn code(self) -> u8 {
        match self {
            Self::System => 0,
            Self::ExplicitPin => 1,
            Self::OperationLease => 2,
            Self::ReadHandle => 3,
            Self::Quarantine => 4,
            Self::AuditCustody => 5,
        }
    }
}

/// One typed non-principal root interpreted by a retention policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CompactionRetainedRoot {
    kind: CompactionRootKind,
    object: ObjectId,
}

impl CompactionRetainedRoot {
    /// Construct one explicit retained-root fact.
    #[must_use]
    pub const fn new(kind: CompactionRootKind, object: ObjectId) -> Self {
        Self { kind, object }
    }

    /// Return why this root remains live.
    #[must_use]
    pub const fn kind(self) -> CompactionRootKind {
        self.kind
    }

    /// Return the root object whose complete owning closure remains live.
    #[must_use]
    pub const fn object(self) -> ObjectId {
        self.object
    }
}

impl CompactionRetention {
    /// Construct a canonical retained-root set under one identified policy.
    #[must_use]
    pub fn new(
        operation_contract: ObjectId,
        policy: RetentionPolicyId,
        additional_roots: impl IntoIterator<Item = CompactionRetainedRoot>,
    ) -> Self {
        let mut additional_roots = additional_roots.into_iter().collect::<Vec<_>>();
        additional_roots.sort_unstable();
        additional_roots.dedup();
        Self {
            operation_contract,
            policy,
            additional_roots,
        }
    }

    /// Return the pinned native compaction operation contract.
    #[must_use]
    pub const fn operation_contract(&self) -> ObjectId {
        self.operation_contract
    }

    /// Return the exact retention-policy identity.
    #[must_use]
    pub const fn policy(&self) -> RetentionPolicyId {
        self.policy
    }

    /// Borrow the strictly ordered additional retained roots.
    #[must_use]
    pub fn additional_roots(&self) -> &[CompactionRetainedRoot] {
        &self.additional_roots
    }
}
