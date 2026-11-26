//! A lease preparation can publish only once and only before retirement.
use vstd::prelude::*;

verus! {

pub(crate) enum Reservation<R> { Preparing(R), Closed }

impl<R> Reservation<R> {
    pub(crate) fn requester(&self) -> (requester: Option<&R>)
        ensures match self {
            Self::Preparing(value) => requester == Some(value),
            Self::Closed => requester.is_none(),
        },
    {
        match self { Self::Preparing(value) => Some(value), Self::Closed => None }
    }

    pub(crate) fn retire(&mut self, affected: bool)
        ensures *final(self) == if affected { Self::Closed } else { *old(self) },
    {
        if affected { *self = Self::Closed; }
    }

    pub(crate) fn claim_publication(&mut self) -> (admitted: bool)
        ensures
            *final(self) == Self::Closed,
            admitted == (*old(self) is Preparing),
    {
        let admitted = matches!(self, Self::Preparing(_));
        *self = Self::Closed;
        admitted
    }
}

pub(crate) enum RequesterKey<'a> { Registered([u8; 32]), Management(&'a str) }

impl RequesterKey<'_> {
    pub(crate) fn retires(self, alias: &str, uid: Option<[u8; 32]>) -> (affected: bool)
        ensures affected == match self {
            Self::Registered(id) => match uid { Some(current) => current@ == id@, None => false },
            Self::Management(name) => name@ == alias@,
        },
    {
        match self {
            Self::Registered(id) => super::requester::same_requester(Some(id), uid),
            Self::Management(name) => name == alias,
        }
    }
}

}
