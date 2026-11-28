//! Disposal of a detached registry entry after sampling child liveness.
use vstd::prelude::*;

verus! {
#[cfg(verus_keep_ghost)]
pub(super) enum Action<M> { Kill(u32), Abort(M) }

pub(super) trait Disposal<M> {
    spec fn calls(&self) -> Seq<Action<M>>;

    fn kill(&mut self, pid: u32)
        ensures final(self).calls() == old(self).calls().push(Action::Kill(pid));

    fn abort(&mut self, monitor: M)
        ensures final(self).calls() == old(self).calls().push(Action::Abort(monitor));
}

pub(super) fn dispose<M, D: Disposal<M>>(live: bool, pid: u32, monitor: M, sink: &mut D)
    ensures final(sink).calls() == (if live { old(sink).calls().push(Action::Kill(pid)) }
        else { old(sink).calls() }).push(Action::Abort(monitor)),
{
    if live {
        sink.kill(pid);
    }
    sink.abort(monitor);
}
}
