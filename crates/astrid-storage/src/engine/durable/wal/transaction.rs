//! Accumulate descriptors until the scanner commits this exact transaction.
use super::commit_wire::CheckedMarker;
use vstd::prelude::*;

verus! {

#[derive(Copy, Clone)]
pub(super) struct Origin {
    pub(super) sequence: u64,
    pub(super) offset: u64,
}

pub(super) struct Batch<O,R> {
    origin: Origin,
    pub(super) objects: Vec<O>,
    pub(super) roots: Vec<R>,
}

pub(super) enum Event<O,R> {
    Begin(Origin),
    Object(O),
    Root(R),
    Commit { offset: u64, marker: CheckedMarker },
    Tail,
    Eof,
}

pub(super) enum Step<O,R> {
    Pending(Batch<O,R>),
    Committed(Batch<O,R>),
    End,
}

pub(super) enum Error { Nested, ObjectBeforeBegin, RootBeforeBegin, CommitBeforeBegin, Mismatch, Unfinished }

#[cfg(verus_keep_ghost)]
pub(super) ghost struct Contents<O,R> {
    pub origin: Origin,
    pub objects: Seq<O>,
    pub roots: Seq<R>,
}

impl<O,R> Batch<O,R> {
    pub(super) closed spec fn contents(&self) -> Contents<O,R> {
        Contents { origin: self.origin, objects: self.objects@, roots: self.roots@ }
    }
}

pub(super) open spec fn matches_commit<O,R>(group: Contents<O,R>, origin: Origin, objects: u64, roots: u64) -> bool {
    group.origin == origin && roots > 0 && group.objects.len() == objects && group.roots.len() == roots
}

pub(super) fn advance<O,R>(pending: Option<Batch<O,R>>, event: Event<O,R>)
    -> (result: Result<Step<O,R>,Error>)
    ensures
        match event {
            Event::Begin(origin) => match pending {
                None => result matches Ok(Step::Pending(b)) && b.contents() == (Contents { origin, objects: Seq::empty(), roots: Seq::empty() }),
                Some(_) => result matches Err(Error::Nested),
            },
            Event::Object(object) => match pending {
                None => result matches Err(Error::ObjectBeforeBegin),
                Some(p) => result matches Ok(Step::Pending(b)) && b.contents() ==
                    (Contents { objects: p.contents().objects.push(object), ..p.contents() }),
            },
            Event::Root(root) => match pending {
                None => result matches Err(Error::RootBeforeBegin),
                Some(p) => result matches Ok(Step::Pending(b)) && b.contents() ==
                    (Contents { roots: p.contents().roots.push(root), ..p.contents() }),
            },
            Event::Commit { offset, marker } => match pending {
                None => result matches Err(Error::CommitBeforeBegin),
                Some(p) => if matches_commit(p.contents(), Origin { offset, sequence: marker.marker().counts.sequence }, marker.marker().counts.objects, marker.marker().counts.roots) {
                    result matches Ok(Step::Committed(b)) && b == p
                } else { result matches Err(Error::Mismatch) },
            },
            Event::Tail => result matches Ok(Step::End),
            Event::Eof => if pending.is_some() { result matches Err(Error::Unfinished) } else { result matches Ok(Step::End) },
        },
{
    match event {
        Event::Begin(origin) => {
            if pending.is_some() { return Err(Error::Nested); }
            Ok(Step::Pending(Batch { origin, objects: Vec::new(), roots: Vec::new() }))
        },
        Event::Object(object) => {
            let mut batch = pending.ok_or(Error::ObjectBeforeBegin)?;
            batch.objects.push(object);
            Ok(Step::Pending(batch))
        },
        Event::Root(root) => {
            let mut batch = pending.ok_or(Error::RootBeforeBegin)?;
            batch.roots.push(root);
            Ok(Step::Pending(batch))
        },
        Event::Commit { offset, marker } => {
            let counts = marker.counts();
            let batch = pending.ok_or(Error::CommitBeforeBegin)?;
            if batch.origin.sequence != counts.sequence || batch.origin.offset != offset ||
                counts.roots == 0 || batch.objects.len() as u128 != u128::from(counts.objects) || batch.roots.len() as u128 != u128::from(counts.roots) {
                return Err(Error::Mismatch);
            }
            Ok(Step::Committed(batch))
        },
        Event::Tail => Ok(Step::End),
        Event::Eof => if pending.is_some() { Err(Error::Unfinished) } else { Ok(Step::End) },
    }
}

}
