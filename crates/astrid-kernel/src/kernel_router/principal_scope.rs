//! Principal and shared-target scope decisions used by management admission.

use vstd::prelude::*;

verus! {

/// The authority surface a management request operates over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityScope {
    /// Request operates on the caller's own principal.
    Self_,
    /// Request operates on global or another principal's state.
    Global,
}

impl AuthorityScope {
    /// Shared state and cross-principal targets require global authority.
    pub(super) fn for_target(caller: &[u8], target: &[u8], shared: bool) -> (scope: Self)
        ensures
            (scope == Self::Self_) == (!shared && caller@ == target@),
            (scope == Self::Global) == (shared || caller@ != target@),
    {
        if shared || caller != target {
            Self::Global
        } else {
            assert(caller@ =~= target@);
            Self::Self_
        }
    }
}

}
