//! Identity codes and ownership semantics for object references.
use vstd::prelude::*;

verus! {
/// Reachability meaning of a reference between immutable objects.
///
/// Only [`Self::Owns`] contributes to a principal's durable closure, usage,
/// default export, and garbage-collection reachability. Other relations bind
/// identity without silently transferring ownership or retention.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReferenceKind {
    /// Strong ownership: the target is required to reconstruct the source.
    Owns,
    /// Observation or audit evidence retained under its own root or pin.
    Evidence,
    /// Historical/fork/merge lineage that does not import the target closure.
    Lineage,
    /// Rebuildable index or materialization.
    Derived,
}

impl ReferenceKind {
    /// Return the stable identity code for this reachability meaning.
    #[must_use]
    pub const fn code(self) -> (code:u8)
        ensures code == match self {Self::Owns=>0u8,Self::Evidence=>1u8,Self::Lineage=>2u8,Self::Derived=>3u8},
    {
        match self {
            Self::Owns => 0,
            Self::Evidence => 1,
            Self::Lineage => 2,
            Self::Derived => 3,
        }
    }

    /// Decode a stable reachability code.
    #[must_use]
    pub const fn from_code(code: u8) -> (out:Option<Self>)
        ensures out == match code {0=>Some(Self::Owns),1=>Some(Self::Evidence),2=>Some(Self::Lineage),3=>Some(Self::Derived),_=>None},
    {
        match code {
            0 => Some(Self::Owns),
            1 => Some(Self::Evidence),
            2 => Some(Self::Lineage),
            3 => Some(Self::Derived),
            _ => None,
        }
    }
    /// Return the target only for strong ownership.
    pub(crate) fn owned_target<K>(self,target:K) -> (out:Option<K>)
        ensures out == if self is Owns {Some(target)} else {None},
    {
        match self {
            Self::Owns => Some(target),
            Self::Evidence | Self::Lineage | Self::Derived => None,
        }
    }

}

}
