//! Kernel-selected logical directories available through owner subtree leases.
use vstd::prelude::*;

verus! {

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Subtree { PrincipalHome, FleetShared }

pub(crate) enum Owner<P, F> { System, Principal(P), Fleet(F) }

#[derive(Clone, Copy)]
pub(crate) enum BoundSubtree<P, F> { PrincipalHome(P), FleetShared(F) }

impl Subtree {
    pub(crate) fn bind<P, F>(self, owner: Owner<P, F>) -> (target: Option<BoundSubtree<P, F>>)
        ensures target == match (self, owner) {
            (Self::PrincipalHome, Owner::Principal(uid)) => Some(BoundSubtree::PrincipalHome(uid)),
            (Self::FleetShared, Owner::Fleet(uid)) => Some(BoundSubtree::FleetShared(uid)),
            _ => None,
        },
    {
        match (self, owner) {
            (Self::PrincipalHome, Owner::Principal(uid)) => Some(BoundSubtree::PrincipalHome(uid)),
            (Self::FleetShared, Owner::Fleet(uid)) => Some(BoundSubtree::FleetShared(uid)),
            _ => None,
        }
    }

    pub(crate) fn parse(prefix: &str) -> (selected: Option<Self>)
        ensures
            (selected == Some(Self::PrincipalHome)) == (prefix@ == "home"@),
            (selected == Some(Self::FleetShared)) == (prefix@ == "shared"@),
    {
        if prefix == "home" { Some(Self::PrincipalHome) }
        else if prefix == "shared" { Some(Self::FleetShared) }
        else { None }
    }

    pub(crate) fn prefix(self) -> (name: &'static str)
        ensures match self {
            Self::PrincipalHome => name@ == "home"@,
            Self::FleetShared => name@ == "shared"@,
        },
    {
        match self { Self::PrincipalHome => "home", Self::FleetShared => "shared" }
    }
}

}
