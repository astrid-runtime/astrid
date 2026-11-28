//! Select the invocation's scoped store and retain owner admission through a host call.
use vstd::prelude::*;

verus! {

pub(crate) fn select<S>(invocation: Option<S>, runtime: S) -> (selected: S)
    ensures selected == match invocation { Some(store) => store, None => runtime },
{
    match invocation { Some(store) => store, None => runtime }
}

/// The host sink returns only after the awaited store operation completes.
/// Borrowing the owned guard keeps the admission in this frame for the call.
pub(crate) fn dispatch<G, S, E, R, F>(guard: G, store: S, effect: E, sink: F) -> (result: R)
    where F: FnOnce(&G, S, E) -> R,
    requires sink.requires((&guard, store, effect)),
    ensures sink.ensures((&guard, store, effect), result),
{
    sink(&guard, store, effect)
}

}
