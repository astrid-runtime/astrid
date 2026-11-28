//! Transfer a concrete effect and its serialization guard into synchronous execution.
use vstd::prelude::*;

verus! {

/// The blocking worker owns the guard. The sink can borrow it during execution.
pub(crate) struct Worker<G, E> {
    guard: G,
    effect: E,
}

impl<G, E> Worker<G, E> {
    pub(crate) closed spec fn binding(self) -> (G, E) { (self.guard, self.effect) }

    pub(crate) fn new(guard: G, effect: E) -> (worker: Self)
        ensures worker.binding() == (guard, effect),
    {
        Self { guard, effect }
    }

    pub(crate) fn run<R, F>(self, sink: F) -> (result: R)
        where F: FnOnce(&G, E) -> R,
        requires sink.requires((&self.binding().0, self.binding().1)),
        ensures sink.ensures((&self.binding().0, self.binding().1), result),
    {
        sink(&self.guard, self.effect)
    }
}

}
