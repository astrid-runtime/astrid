//! Composition for a tracked guest KV call. Store construction, guard lifetime,
//! device admission and backend atomicity require separate runtime refinement.
use crate::{guest_authority, guest_kv_dispatch, principal_invocation_state::PrincipalInvocation};
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

fn tracked_call<G,E,R,F>(tracker: &mut PrincipalInvocation, guard: G, runtime: Store,
    invocation: Option<Store>, namespace: &[u8], observed: [u8;32], effect: E, sink: F)
    -> (result: Option<R>)
    where F: FnOnce(&G, Destination, E) -> R,
    requires forall|d: Destination| #[trigger] sink.requires((&guard, d, effect)),
    ensures
        final(tracker).active_count() == old(tracker).active_count(),
        final(tracker).is_retired() == old(tracker).is_retired(),
        ({
            let selected = match invocation { Some(store) => store, None => runtime };
            let target = destination(selected, namespace, observed);
            &&& result.is_some() == (!old(tracker).is_retired() &&
                old(tracker).active_count() < usize::MAX && target.is_some())
            &&& result matches Some(receipt) ==> sink.ensures((&guard, target.unwrap(), effect), receipt)
        }),
{
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
        Some(d) => Some(guest_kv_dispatch::dispatch(guard, d, effect, sink)),
        None => None,
    };
    tracker.finish();
    result
}

}
