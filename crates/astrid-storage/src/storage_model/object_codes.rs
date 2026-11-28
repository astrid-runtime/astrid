//! Stable identity codes used by object storage and recovery.
use vstd::prelude::*;

verus! {
/// Accounting class of an object record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectClass {
    /// User-visible data such as a file chunk or KV value.
    Data,
    /// Structural data such as a directory, tree branch, or commit.
    Metadata,
}

impl ObjectClass {
    pub open spec fn wire_code(self) -> u8 {
        match self {
            Self::Data => 0,
            Self::Metadata => 1,
        }
    }

    /// Return the stable identity code for this accounting class.
    #[must_use]
    pub const fn code(self) -> (value:u8)
        ensures value == self.wire_code(),
    {
        match self {
            Self::Data => 0,
            Self::Metadata => 1,
        }
    }

    /// Decode a stable accounting-class code.
    #[must_use]
    pub const fn from_code(code: u8) -> (out:Option<Self>)
        ensures out.is_some() == (code < 2), out matches Some(value) ==> value.wire_code() == code,
    {
        match code {
            0 => Some(Self::Data),
            1 => Some(Self::Metadata),
            _ => None,
        }
    }
}

/// Versioned semantic kind of one immutable object.
///
/// The numeric codes are part of logical identity. Persistent encodings may
/// use different framing, but must preserve this value when computing
/// [`ObjectId`](super::ObjectId).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum ObjectKind {
    /// Raw user-visible bytes.
    Chunk,
    /// Ordered tree over large content chunks.
    ChunkTree,
    /// File metadata and content root.
    File,
    /// Symlink target bytes, never followed during validation.
    Symlink,
    /// Canonical directory entries.
    Directory,
    /// Canonical key/value leaf.
    KvLeaf,
    /// Internal key/value tree branch.
    KvBranch,
    /// Capsule namespace to KV-root mapping.
    NamespaceMap,
    /// Complete principal-owned durable state.
    PrincipalState,
    /// Principal-root transition envelope.
    Commit,
    /// Durable owner-internal workspace branch record.
    WorkspaceBranch,
    /// Observation, receipt, or audit evidence.
    Evidence,
    /// Rebuildable index or materialization.
    Derived,
    /// Semantics-visible execution surface shared by compatible engine builds.
    RuntimeSemanticProfile,
    /// Complete canonical request for one derivation.
    DerivationInvocation,
    /// Verified relation from one derivation invocation to its results.
    DerivationEvidence,
    /// Garbage-collection plan and its closed-world safety proof.
    GcPlanEvidence,
    /// Executed garbage-collection transition bound to one exact plan.
    GcCommitEvidence,
}

impl ObjectKind {
    pub open spec fn wire_code(self) -> u16 {
        match self {
            Self::Chunk => 0,
            Self::ChunkTree => 1,
            Self::File => 2,
            Self::Symlink => 3,
            Self::Directory => 4,
            Self::KvLeaf => 5,
            Self::KvBranch => 6,
            Self::NamespaceMap => 7,
            Self::PrincipalState => 8,
            Self::Commit => 9,
            Self::WorkspaceBranch => 17,
            Self::Evidence => 10,
            Self::Derived => 11,
            Self::RuntimeSemanticProfile => 12,
            Self::DerivationInvocation => 13,
            Self::DerivationEvidence => 14,
            Self::GcPlanEvidence => 15,
            Self::GcCommitEvidence => 16,
        }
    }

    /// Return the stable identity code for this kind.
    #[must_use]
    pub const fn code(self) -> (value:u16)
        ensures value == self.wire_code(),
    {
        match self {
            Self::Chunk => 0,
            Self::ChunkTree => 1,
            Self::File => 2,
            Self::Symlink => 3,
            Self::Directory => 4,
            Self::KvLeaf => 5,
            Self::KvBranch => 6,
            Self::NamespaceMap => 7,
            Self::PrincipalState => 8,
            Self::Commit => 9,
            Self::WorkspaceBranch => 17,
            Self::Evidence => 10,
            Self::Derived => 11,
            Self::RuntimeSemanticProfile => 12,
            Self::DerivationInvocation => 13,
            Self::DerivationEvidence => 14,
            Self::GcPlanEvidence => 15,
            Self::GcCommitEvidence => 16,
        }
    }

    /// Decode a stable semantic-kind code.
    #[must_use]
    pub const fn from_code(code: u16) -> (out:Option<Self>)
        ensures out.is_some() == (code < 18), out matches Some(value) ==> value.wire_code() == code,
    {
        match code {
            0 => Some(Self::Chunk),
            1 => Some(Self::ChunkTree),
            2 => Some(Self::File),
            3 => Some(Self::Symlink),
            4 => Some(Self::Directory),
            5 => Some(Self::KvLeaf),
            6 => Some(Self::KvBranch),
            7 => Some(Self::NamespaceMap),
            8 => Some(Self::PrincipalState),
            9 => Some(Self::Commit),
            17 => Some(Self::WorkspaceBranch),
            10 => Some(Self::Evidence),
            11 => Some(Self::Derived),
            12 => Some(Self::RuntimeSemanticProfile),
            13 => Some(Self::DerivationInvocation),
            14 => Some(Self::DerivationEvidence),
            15 => Some(Self::GcPlanEvidence),
            16 => Some(Self::GcCommitEvidence),
            _ => None,
        }
    }
}

}
