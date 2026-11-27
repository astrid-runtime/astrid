//! Operator classification and owner lookup shared by initial load and live replacement.
use vstd::prelude::*;

verus! {
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RuntimeResidency { Principal, SystemResident }
pub(super) enum Refusal { UnapprovedProvider, SystemMcp }

pub(super) fn classify(allowed: bool, provides: bool, uplink: bool, has_servers: bool)
    -> (out: Result<RuntimeResidency, Refusal>)
    ensures out == if provides && !allowed { Err(Refusal::UnapprovedProvider) }
        else if allowed && (provides || uplink) {
            if has_servers { Err(Refusal::SystemMcp) } else { Ok(RuntimeResidency::SystemResident) }
        } else { Ok(RuntimeResidency::Principal) },
{
    if provides && !allowed { return Err(Refusal::UnapprovedProvider); }
    if allowed && (provides || uplink) {
        if has_servers { Err(Refusal::SystemMcp) } else { Ok(RuntimeResidency::SystemResident) }
    } else { Ok(RuntimeResidency::Principal) }
}

impl RuntimeResidency {
    pub(super) fn is_system(self) -> (yes: bool)
        ensures yes == (self == Self::SystemResident),
    { matches!(self, Self::SystemResident) }

    pub(super) fn owner<P, U, E, F: FnOnce(P, Option<U>) -> Result<U,E>>(
        self, principal: P, expected: Option<U>, lookup: F,
    ) -> (out: Result<Option<U>,E>)
        requires self == Self::Principal ==> lookup.requires((principal,expected)),
        ensures if self == Self::SystemResident { out == Ok(None) }
            else { match out {
                Ok(Some(uid)) => lookup.ensures((principal,expected), Ok(uid)),
                Err(e) => lookup.ensures((principal,expected), Err(e)),
                Ok(None) => false,
            }},
    {
        match self {
            Self::SystemResident => Ok(None),
            Self::Principal => Ok(Some(lookup(principal,expected)?)),
        }
    }
}
}
