//! Principal admission at routed IPC matching and enqueue.

use vstd::prelude::*;

verus! {

pub(super) enum Scope<'a> {
    All,
    System,
    Principal(&'a [u8]),
    PrincipalOrSystem(&'a [u8]),
}

impl Scope<'_> {
    pub(super) fn accepts(&self, publisher: Option<&[u8]>) -> (admitted: bool)
        ensures admitted == match self {
            Scope::All => true,
            Scope::System => publisher.is_none(),
            Scope::Principal(owner) => publisher matches Some(p) && p@ == owner@,
            Scope::PrincipalOrSystem(owner) => publisher.is_none() || (publisher matches Some(p) && p@ == owner@),
        },
    {
        match (self, publisher) {
            (Scope::All, _) | (Scope::System | Scope::PrincipalOrSystem(_), None) => true,
            (Scope::Principal(owner) | Scope::PrincipalOrSystem(owner), Some(actual)) => {
                if *owner != actual { return false; }
                assert(owner@ =~= actual@);
                true
            },
            _ => false,
        }
    }
}

}
