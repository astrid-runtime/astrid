//! Bind uplink registry mutations and sends to the descriptor on this Wasmtime store.
use vstd::prelude::*;

verus! {

pub(super) enum RegistrationError { Full, Duplicate }

pub(super) fn same_endpoint(name: &str, platform: &str, other_name: &str, other_platform: &str)
    -> (same: bool) ensures same == (name@ == other_name@ && platform@ == other_platform@),
{
    name == other_name && platform == other_platform
}

/// The manifest check runs in the host before registration. Preserve the
/// registry on refusal, and append the exact descriptor exactly once on success.
pub(super) fn register<D,F>(registry: &mut Vec<D>, descriptor: D, limit: usize, same: F)
    -> (result: Result<(),RegistrationError>) where F: Fn(&D,&D) -> bool,
    requires forall|a:&D,b:&D| #[trigger] same.requires((a,b)),
    ensures
        (result matches Err(RegistrationError::Full)) == (old(registry).len() >= limit),
        result matches Err(RegistrationError::Duplicate) ==> exists|i:int| 0 <= i < old(registry).len()
            && #[trigger] same.ensures((&old(registry)@[i],&descriptor),true),
        result.is_ok() ==> forall|i:int| 0 <= i < old(registry).len() ==>
            #[trigger] same.ensures((&old(registry)@[i],&descriptor),false),
        final(registry)@ == if result.is_ok() { old(registry)@.push(descriptor) } else { old(registry)@ },
{
    if registry.len() >= limit { return Err(RegistrationError::Full); }
    let mut i = 0;
    while i < registry.len()
        invariant i <= registry.len(), registry.len() < limit, registry@ == old(registry)@,
            forall|a:&D,b:&D| #[trigger] same.requires((a,b)),
            forall|j:int| 0 <= j < i ==> #[trigger] same.ensures((&registry@[j],&descriptor),false),
        decreases registry.len() - i,
    {
        if same(&registry[i],&descriptor) { return Err(RegistrationError::Duplicate); }
        i = i.saturating_add(1);
    }
    registry.push(descriptor);
    Ok(())
}

pub(super) open spec fn skipped<D,I: Fn(&D) -> u128>(identify: I, descriptor: &D, requested: u128) -> bool {
    exists|other:u128| #[trigger] identify.ensures((descriptor,),other) && other != requested
}

/// Select the first matching registered descriptor. Only that descriptor and
/// the unchanged event arguments are handed to the enqueue operation.
pub(super) fn send<G,D,E,T,I,F>(guard: G, registry: &[D], requested: u128, event: E, identify: I, enqueue: F)
    -> (outcome: Option<T>) where I: Fn(&D) -> u128, F: FnOnce(&G,&D,E) -> T,
    requires forall|d:&D| #[trigger] identify.requires((d,)),
        forall|d:&D| #[trigger] enqueue.requires((&guard,d,event)),
    ensures
        outcome matches Some(value) ==> exists|i:int| 0 <= i < registry.len()
            && #[trigger] identify.ensures((&registry@[i],),requested)
            && enqueue.ensures((&guard,&registry@[i],event),value)
            && forall|j:int| 0 <= j < i ==> #[trigger] skipped(identify,&registry@[j],requested),
        outcome.is_none() ==> forall|j:int| 0 <= j < registry.len() ==> #[trigger] skipped(identify,&registry@[j],requested),
{
    let mut i = 0;
    while i < registry.len()
        invariant i <= registry.len(), forall|d:&D| #[trigger] identify.requires((d,)),
            forall|d:&D| #[trigger] enqueue.requires((&guard,d,event)),
            forall|j:int| 0 <= j < i ==> #[trigger] skipped(identify,&registry@[j],requested),
        decreases registry.len() - i,
    {
        let descriptor = &registry[i];
        let id = identify(descriptor);
        if id == requested {
            let result = enqueue(&guard,descriptor,event);
            assert(identify.ensures((&registry@[i as int],),requested));
            return Some(result);
        }
        assert(identify.ensures((&registry@[i as int],),id));
        assert(skipped(identify,&registry@[i as int],requested));
        i = i.saturating_add(1);
    }
    None
}

}
