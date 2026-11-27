//! Scope assigned to an admitted runtime in the registry.
use super::PrincipalUid;
use vstd::prelude::*;

verus! {
/// Authority scope of one executable runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuntimeScope {
    /// Mutable runtime state belongs exclusively to this durable principal.
    Principal(PrincipalUid),
    /// Explicit kernel service runtime with neutral host state.
    SystemResident,
}

impl RuntimeScope {
    /// Build the authority scope from the admitted directory owner.
    #[must_use]
    pub fn from_owner(owner: Option<PrincipalUid>) -> (scope: Self)
        ensures scope == match owner {
            Some(uid) => Self::Principal(uid),
            None => Self::SystemResident,
        },
    {
        match owner {
            Some(uid) => Self::Principal(uid),
            None => Self::SystemResident,
        }
    }
}
}
