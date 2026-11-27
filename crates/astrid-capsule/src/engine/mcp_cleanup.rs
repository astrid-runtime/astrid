//! Registration and cleanup transitions serialized by the teardown mutex.
use vstd::prelude::*;

verus! {

pub(super) enum Phase {
    Open(Option<String>),
    Draining(Option<String>),
    Done,
}

/// Owned by the single worker elected by begin.
pub(super) struct Cleanup {
    target: Option<String>,
}

impl Cleanup {
    pub(super) closed spec fn name(&self) -> Option<Seq<char>> {
        match self.target { Some(s) => Some(s@), None => None }
    }

    pub(super) fn target(&self) -> (value: Option<&str>)
        ensures self.name() == match value { Some(s) => Some(s@), None => None },
    {
        match &self.target { Some(s) => Some(s.as_str()), None => None }
    }
}

impl Phase {
    pub(super) open spec fn name(&self) -> Option<Seq<char>> {
        match self {
            Self::Open(Some(s)) | Self::Draining(Some(s)) => Some(s@),
            _ => None,
        }
    }

    pub(super) fn register(&mut self, target: String) -> (accepted: bool)
        ensures accepted == ((*old(self)) is Open),
            accepted ==> (*final(self)) is Open && final(self).name() == Some(target@),
            !accepted ==> *final(self) == *old(self),
    {
        match self {
            Self::Open(slot) => { *slot = Some(target); true },
            _ => false,
        }
    }

    pub(super) fn target(&self) -> (value: Option<String>)
        ensures self.name() == match value { Some(s) => Some(s@), None => None },
    {
        match self {
            Self::Open(Some(s)) | Self::Draining(Some(s)) => Some(s.clone()),
            _ => None,
        }
    }

    pub(super) fn begin(&mut self) -> (work: Option<Cleanup>)
        ensures work.is_some() == ((*old(self)) is Open),
            work matches Some(task) ==> (*final(self)) is Draining
                && task.name() == old(self).name() && final(self).name() == task.name(),
            work.is_none() ==> *final(self) == *old(self),
    {
        if let Self::Open(slot) = self {
            let retained = slot.clone();
            let target = slot.take();
            *self = Self::Draining(retained);
            Some(Cleanup { target })
        } else { None }
    }

    pub(super) fn finish(&mut self, work: Cleanup) -> (completed: bool)
        ensures completed == ((*old(self)) is Draining && old(self).name() == work.name()),
            completed ==> (*final(self)) is Done,
            !completed ==> *final(self) == *old(self),
    {
        let matches = match (&*self, work.target()) {
            (Self::Draining(Some(owned)), Some(done)) => owned.as_str() == done,
            (Self::Draining(None), None) => true,
            _ => false,
        };
        if matches { *self = Self::Done; }
        matches
    }
}
}
