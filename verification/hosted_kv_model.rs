//! Composition for a tracked guest KV call. Store construction, guard lifetime,
//! device admission and backend atomicity require separate runtime refinement.
use crate::{guest_authority, guest_kv_dispatch, principal_invocation_state::PrincipalInvocation};
use crate::owner_codec::{self, Owner};
use crate::root_transition::{Advance, PreparedRoot, Replay, Version, advance, replay};
use crate::root_wire;
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

/// The physical owner spelling selected for a pinned guest namespace can
/// recover only the admitted principal, including when a fleet has the same UID bytes.
fn recovered_guest_owner(scope: &[u8], requested: &[u8], admitted: [u8;32], current: [u8;32])
    -> (owner: Option<Owner>)
    ensures
        owner.is_some() == (scope@ == requested@ && admitted@ == current@),
        owner matches Some(o) ==> (o matches Owner::Principal(id) && id@ == admitted@),
{
    let uid = match guest_authority::select(scope, requested, admitted, current) {
        Some(uid) => uid,
        None => return None,
    };
    let bytes = Owner::Principal(uid).encode();
    assert(bytes@[0] == 1);
    let recovered = owner_codec::decode(&bytes);
    match recovered {
        Some(Owner::Principal(id)) => {
            assert(id@ =~= admitted@) by {
                assert forall|i:int| 0 <= i < 32 implies #[trigger] id@[i] == admitted@[i] by {
                    assert(bytes@[1+i] == id@[i]);
                    assert(bytes@[1+i] == uid@[i]);
                }
            }
        },
        _ => { assert(false); },
    }
    recovered
}

spec fn recorded<R: Copy,E,U,W,A>(admitted: [u8;32], expected: Option<R>, replacement: R,
    encode: W, append: A, result: Result<U,E>) -> bool
    where W: FnOnce(&[u8;32],Option<R>,R) -> Result<Vec<u8>,E>,
          A: FnOnce(&[u8;32],Option<R>,R,&Vec<u8>) -> Result<U,E>,
{
    exists|j: &Vec<u8>| encode.ensures((&admitted, expected, replacement), Ok(*j))
        && #[trigger] append.ensures((&admitted,expected,replacement,j), result)
}

/// Compose pinned selection with the checked callbacks. Concrete encoder,
/// append and publication semantics are obligations of this model’s caller.
fn guest_publication<R: Copy, E, U, T, W, A, F>(scope: &[u8], requested: &[u8], admitted: [u8;32],
    observed: [u8;32], expected: Option<R>, replacement: R, encode: W, append: A, publish: F)
    -> (outcome: Option<Result<(R,U,T), E>>)
    where W: FnOnce(&[u8;32],Option<R>,R) -> Result<Vec<u8>,E>,
          A: FnOnce(&[u8;32], Option<R>, R, &Vec<u8>) -> Result<U,E>,
          F: FnOnce(&[u8;32],R) -> T,
    requires encode.requires((&admitted, expected, replacement)),
        publish.requires((&admitted, replacement)),
        forall|j: &Vec<u8>| encode.ensures((&admitted, expected, replacement), Ok(*j))
            ==> #[trigger] append.requires((&admitted,expected,replacement,j)),
    ensures
        outcome.is_some() == (scope@ == requested@ && admitted@ == observed@),
        outcome matches Some(Err(e)) ==> encode.ensures((&admitted, expected, replacement), Err(e))
            || recorded(admitted, expected, replacement, encode, append, Err(e)),
        outcome matches Some(Ok((ack, written, receipt))) ==> {
            &&& ack == replacement
            &&& publish.ensures((&admitted, ack), receipt)
            &&& recorded(admitted, expected, replacement, encode, append, Ok(written))
        },
{
    let owner = match guest_authority::select(scope, requested, admitted, observed) {
        Some(id) => id,
        None => return None,
    };
    let prepared = match PreparedRoot::encode(owner, expected, replacement, encode) {
        Ok(prepared) => prepared,
        Err(e) => return Some(Err(e)),
    };
    let journal = prepared.journal();
    assert(encode.ensures((&admitted, expected, replacement), Ok(*journal)));
    let written = prepared.write_wal(append);
    assert(append.ensures((&admitted,expected,replacement,journal), written));
    assert(recorded(admitted, expected, replacement, encode, append, written));
    match written {
        Ok(staged) => {
            assert(recorded(admitted, expected, replacement, encode, append, Ok(staged)));
            let (ack, receipt) = prepared.publish(publish);
            assert(ack == replacement);
            assert(publish.ensures((&admitted, ack), receipt));
            Some(Ok((ack,staged,receipt)))
        },
        Err(e) => Some(Err(e)),
    }
}

/// Durable transition bytes for a guest-selected principal recover that
/// principal and both prepared root fields, without a model decoder.
fn guest_wal_round_trip(scope: &[u8], requested: &[u8], admitted: [u8;32], current: [u8;32],
    scheme: root_wire::Scheme, expected: Option<root_wire::Root>, replacement: root_wire::Root)
    -> (decoded: Option<(Owner, Option<root_wire::Root>, root_wire::Root)>)
    ensures
        decoded.is_some() == (scope@ == requested@ && admitted@ == current@),
        decoded matches Some((owner,e,r)) ==> {
            &&& (owner matches Owner::Principal(id) && id@ == admitted@)
            &&& root_wire::same_expected(e,expected)
            &&& root_wire::same(r,replacement)
        },
{
    let owner = match guest_authority::select(scope,requested,admitted,current) {
        Some(uid) => Owner::Principal(uid),
        None => return None,
    };
    let name = owner.encode();
    let encoder = |selected: &Owner, e: Option<root_wire::Root>, r: root_wire::Root| -> (out: Result<Vec<u8>,()>)
        ensures out matches Ok(bytes) && bytes@ == vstd::bytes::spec_u64_to_le_bytes(selected.bytes().len() as u64)
            + selected.bytes() + root_wire::prior(e,scheme) + r.wire(scheme),
    {
        let key = (*selected).encode();
        match root_wire::encode(&key,scheme,e,r) {
            Some(bytes) => Ok(bytes),
            None => { assert(false); Err(()) },
        }
    };
    let prepared = match PreparedRoot::encode(owner,expected,replacement,encoder) {
        Ok(prepared) => prepared,
        Err(()) => { assert(false); return None; },
    };
    let frame = prepared.journal();
    proof { vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes(); }
    assert(frame@.take(8) =~= vstd::bytes::spec_u64_to_le_bytes(33));
    let (saved,mut cursor) = match root_wire::read_owner(frame) {
        Ok(binding) => binding,
        Err(_) => { assert(false); return None; },
    };
    assert(saved@ =~= name@);
    let restored = match owner_codec::decode(saved) {
        Some(Owner::Principal(id)) => {
            assert(id@ =~= admitted@) by {
                assert forall|i:int| 0 <= i < 32 implies #[trigger] id@[i] == admitted@[i] by {
                    assert(saved@[1+i] == id@[i]);
                    assert(name@[1+i] == admitted@[i]);
                }
            }
            Owner::Principal(id)
        },
        _ => { assert(false); return None; },
    };
    let ghost start = cursor as int;
    assert(frame@.skip(start) =~= root_wire::prior(expected,scheme) + replacement.wire(scheme));
    assert(root_wire::tail(frame@,start,scheme,expected,replacement));
    let (e,r) = match root_wire::read_tail(frame,&mut cursor,scheme) {
        Ok(roots) => roots,
        Err(_) => { assert(false); return None; },
    };
    proof { root_wire::unique_tail(frame@,start,scheme,e,r,expected,replacement); }
    Some((restored,e,r))
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
