//! Composition for a tracked guest KV call. Store construction, guard lifetime,
//! device admission and backend atomicity require separate runtime refinement.
use crate::{guest_authority, guest_kv_dispatch, principal_invocation_state::PrincipalInvocation};
use crate::root_transition::{Advance, Replay, Version, advance, replay};
use vstd::prelude::*;

verus! {

#[derive(Clone, Copy)]
enum Store<'a> { Neutral, Pinned { namespace: &'a [u8], owner: [u8;32] } }

#[derive(Clone, Copy)]
enum Destination { Neutral, Principal([u8;32]) }

spec fn destination(store: Store, request: &[u8], observed: [u8;32]) -> Option<Destination> {
    match store {
        Store::Neutral => Some(Destination::Neutral),
        Store::Pinned {namespace, owner} =>
            if namespace@ == request@ && owner@ == observed@ { Some(Destination::Principal(owner)) }
            else { None },
    }
}

spec fn completed<E,R,F>(sink: F, before: usize, d: Destination, effect: E, receipt: R) -> bool
    where F: FnOnce(&&PrincipalInvocation, Destination, E) -> R,
{
    exists|held: &PrincipalInvocation|
        !held.is_retired() && held.active_count() as int == before as int + 1
            && #[trigger] sink.ensures((&held, d, effect), receipt)
}

fn tracked_call<E,R,F>(tracker: &mut PrincipalInvocation, runtime: Store,
    invocation: Option<Store>, namespace: &[u8], observed: [u8;32], effect: E, sink: F)
    -> (result: Option<R>)
    where F: FnOnce(&&PrincipalInvocation, Destination, E) -> R,
    requires forall|held: &PrincipalInvocation, d: Destination|
        !held.is_retired() && held.active_count() as int == old(tracker).active_count() as int + 1
            ==> #[trigger] sink.requires((&held, d, effect)),
    ensures
        final(tracker).active_count() == old(tracker).active_count(),
        final(tracker).is_retired() == old(tracker).is_retired(),
        ({
            let selected = match invocation { Some(store) => store, None => runtime };
            let target = destination(selected, namespace, observed);
            &&& result.is_some() == (!old(tracker).is_retired() &&
                old(tracker).active_count() < usize::MAX && target.is_some())
            &&& result matches Some(receipt) ==> completed(sink, old(tracker).active_count(), target.unwrap(), effect, receipt)
        }),
{
    let ghost before = tracker.active_count();
    if !tracker.begin() { return None; }
    let store = guest_kv_dispatch::select(invocation, runtime);
    let target = match store {
        Store::Neutral => Some(Destination::Neutral),
        Store::Pinned { namespace: scope, owner } =>
            match guest_authority::select(scope, namespace, owner, observed) {
                Some(uid) => Some(Destination::Principal(uid)),
                None => None,
            },
    };
    assert(target == destination(store, namespace, observed));
    let result = match target {
        Some(d) => {
            let guard = &*tracker;
            let receipt = guest_kv_dispatch::dispatch(guard, d, effect, sink);
            assert(sink.ensures((&guard, d, effect), receipt));
            assert(completed(sink, before, d, effect, receipt));
            Some(receipt)
        },
        None => None,
    };
    tracker.finish();
    result
}

/// An admitted live publication can be replayed from the prior root exactly
/// once. A second replay sees the published version, even with the same digest
/// as the prior generation.
fn replay_admitted(expected: Option<Version>, commit: [u8;32]) {
    if let Advance::Next(generation) = advance(expected, expected) {
        let replacement = Version { generation, commit };
        let first = replay(expected, expected, replacement);
        assert(first is Apply);
        let second = replay(Some(replacement), expected, replacement);
        assert(second is AlreadyPublished);
    }
}

}
