//! Dispatch a guest record while the caller retains its resolved file guard.
use vstd::prelude::*;

verus! {

pub(crate) enum DaemonPolicy { Always, OnFailure }

impl DaemonPolicy {
    pub(crate) fn emit(&self, written: bool) -> (result: bool)
        ensures result == (!written || *self is Always),
    {
        !written || matches!(self, Self::Always)
    }
}

#[cfg(verus_keep_ghost)]
pub(crate) enum Event<F,G,R> { Write(F,Option<G>,R,bool), Daemon(R) }

pub(crate) trait Output<F,G,R> {
    spec fn events(&self) -> Seq<Event<F,G,R>>;

    fn write(&mut self, file: &F, guard: Option<&G>, record: &R) -> (written: bool)
        ensures final(self).events() == old(self).events().push(Event::Write(*file,match guard { Some(g) => Some(*g), None => None },*record,written));

    fn daemon(&mut self, record: &R)
        ensures final(self).events() == old(self).events().push(Event::Daemon(*record));
}

/// Managed files retain the destination owner's borrowed or owned operation.
pub(crate) enum Destination<F,G> {
    Managed(F,G),
    Explicit(F),
    Absent,
}

impl<F,G> Destination<F,G> {
    pub(crate) fn file(&self) -> (file: Option<&F>)
        ensures match self {
            Self::Managed(f,_) | Self::Explicit(f) => file == Some(f),
            Self::Absent => file.is_none(),
        },
    {
        match self {
            Self::Managed(f,_) | Self::Explicit(f) => Some(f),
            Self::Absent => None,
        }
    }
}

pub(crate) fn dispatch<F,G,R,O:Output<F,G,R>>(output: &mut O, destination: &Destination<F,G>, record: &R, policy: DaemonPolicy)
    ensures ({
        let prior = old(output).events();
        let after = final(output).events();
        let guard = match destination { Destination::Managed(_,g) => Some(*g), _ => None };
        match destination {
            Destination::Absent => after == prior.push(Event::Daemon(*record)),
            Destination::Managed(f,_) | Destination::Explicit(f) => match after[prior.len() as int] {
                Event::Write(target,held,line,written) => target == *f && held == guard && line == *record && {
                    let attempted = prior.push(Event::Write(*f,guard,*record,written));
                    after == if !written || policy is Always { attempted.push(Event::Daemon(*record)) } else { attempted }
                },
                _ => false,
            },
        }
    }),
{
    let written = match destination {
        Destination::Managed(file,guard) => output.write(file, Some(guard), record),
        Destination::Explicit(file) => output.write(file, None, record),
        Destination::Absent => false,
    };
    if policy.emit(written) {
        output.daemon(record);
    }
}

}
