//! Compose descriptor lookup with tracked admission and the enqueue arguments.
//! The runtime supplies the store-local registry, guard and channel.
use crate::{guest_uplink, principal_invocation_state::PrincipalInvocation};
use vstd::prelude::*;

verus! {

#[derive(Clone, Copy)]
struct Descriptor<'a> { id: u128, name: &'a str, platform: &'a str }

spec fn duplicate(a: Descriptor, b: Descriptor) -> bool {
    a.name@ == b.name@ && a.platform@ == b.platform@
}

fn register<'a>(entries: &mut Vec<Descriptor<'a>>, d: Descriptor<'a>, limit: usize)
    -> (ok: bool)
    ensures
        ok == (old(entries).len() < limit &&
            forall|i:int| 0 <= i < old(entries).len() ==> !duplicate(#[trigger] old(entries)@[i], d)),
        final(entries)@ == if ok { old(entries)@.push(d) } else { old(entries)@ },
{
    let same = |a: &Descriptor, b: &Descriptor| -> (same: bool)
        ensures same == duplicate(*a,*b),
    { guest_uplink::same_endpoint(a.name,a.platform,b.name,b.platform) };
    let ghost before = entries@;
    let outcome = guest_uplink::register(entries,d,limit,same);
    if outcome.is_ok() {
        assert forall|i:int| 0 <= i < before.len() implies !duplicate(#[trigger] before[i],d) by {
            assert(same.ensures((&before[i],&d),false));
        }
    }
    outcome.is_ok()
}

fn tracked_send<'a>(tracker: &mut PrincipalInvocation, entries: &[Descriptor<'a>],
    requested: u128, user: &'a str, content: &'a str)
    -> (receipt: Option<(u128,&'a str,&'a str,&'a str,usize)>)
    ensures
        final(tracker).active_count() == old(tracker).active_count(),
        final(tracker).is_retired() == old(tracker).is_retired(),
        receipt.is_some() == (!old(tracker).is_retired() && old(tracker).active_count() < usize::MAX
            && exists|i:int| 0 <= i < entries.len() && (#[trigger] entries@[i]).id == requested),
        receipt matches Some(r) ==> exists|i:int| 0 <= i < entries.len() &&
            (#[trigger] entries@[i]).id == requested &&
            r == (requested, entries@[i].platform, user, content, (old(tracker).active_count() + 1) as usize) &&
            forall|j:int| 0 <= j < i ==> (#[trigger] entries@[j]).id != requested,
{
    if !tracker.begin() { return None; }
    let identify = |d:&Descriptor| -> (id:u128) ensures id == d.id, { d.id };
    let enqueue = |held: &&PrincipalInvocation, d: &Descriptor<'a>, event: (&'a str,&'a str)|
        -> (r:(u128,&'a str,&'a str,&'a str,usize))
        ensures r == (d.id,d.platform,event.0,event.1,held.active_count()),
    { (d.id,d.platform,event.0,event.1,held.active()) };
    let result = guest_uplink::send(&*tracker,entries,requested,(user,content),identify,enqueue);
    if result.is_none() {
        assert forall|j:int| 0 <= j < entries.len() implies (#[trigger] entries@[j]).id != requested by {
            assert(guest_uplink::skipped(identify,&entries@[j],requested));
        }
    } else {
        let ghost r = result.unwrap();
        let ghost i = choose|i:int| 0 <= i < entries.len()
            && #[trigger] identify.ensures((&entries@[i],),requested)
            && enqueue.ensures((&&*tracker,&entries@[i],(user,content)),r)
            && forall|j:int| 0 <= j < i ==> #[trigger] guest_uplink::skipped(identify,&entries@[j],requested);
        assert forall|j:int| 0 <= j < i implies (#[trigger] entries@[j]).id != requested by {
            assert(guest_uplink::skipped(identify,&entries@[j],requested));
        }
        assert(entries@[i].id == requested);
        assert(enqueue.ensures((&&*tracker,&entries@[i],(user,content)),r));
    }
    tracker.finish();
    result
}

}
