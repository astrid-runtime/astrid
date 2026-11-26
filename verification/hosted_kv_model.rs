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
    sequence: [u8;8], ordinal: [u8;8], expected_sequence: u64, expected_ordinal: u64,
    scheme: root_wire::Scheme, expected: Option<root_wire::Root>, replacement: root_wire::Root)
    -> (decoded: Option<(Owner, Option<root_wire::Root>, root_wire::Root)>)
    requires expected_sequence > 0,
    ensures
        decoded.is_some() == (scope@ == requested@ && admitted@ == current@
            && vstd::bytes::spec_u64_from_le_bytes(sequence@) == expected_sequence
            && vstd::bytes::spec_u64_from_le_bytes(ordinal@) == expected_ordinal),
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
    let journal = prepared.journal();
    let mut payload = Vec::new();
    let header = crate::wal_record_wire::Header {
        kind: 3, flags: 0, reserved: [0;2], sequence, ordinal,
    };
    header.append(&mut payload,journal);
    assert(payload@ =~= header.bytes() + journal@);
    let (scanned,frame) = match crate::wal_record_wire::split(&payload) {
        Some(parts) => parts,
        None => { assert(false); return None; },
    };
    assert(payload@.subrange(4,12) =~= sequence@);
    assert(payload@.subrange(12,20) =~= ordinal@);
    assert(scanned.sequence@ =~= sequence@);
    assert(scanned.ordinal@ =~= ordinal@);
    assert(scanned.kind == 3 && scanned.flags == 0);
    assert(frame@ =~= journal@);
    let frame = match crate::wal_record_wire::body_at_position(frame,u64::from_le_bytes(scanned.sequence),
        u64::from_le_bytes(scanned.ordinal),expected_sequence,expected_ordinal) {
        Ok(body) => body,
        Err(_) => return None,
    };
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
    let bound = root_wire::bind_owner(name,saved,expected,e,replacement,r);
    assert(bound.is_ok());
    Some((restored,e,r))
}

/// A completed batch is acknowledged only on sync success. A failed sync
/// leaves the entire pending count available to recovery and poisons the writer.
fn publish_completed_batch(count: u64, success: bool, current: u64, observed: u64,
    tail: Option<u64>, pending_tail: Option<u64>)
    requires count > 0,
{
    let mut pending = count;
    let mut poisoned = false;
    let sync = || -> (result: Result<(),()>) ensures result.is_ok() == success {
        if success { Ok(()) } else { Err(()) }
    };
    match crate::group_frontier::sync_pending(false,&mut pending,&mut poisoned,sync) {
        Ok(reported) => {
            assert(success && reported == count && pending == 0 && !poisoned);
            let position = crate::group_frontier::wal_position(current,tail,observed,pending_tail);
            assert(position.is_some() == (current <= observed));
            if let Some((end,last)) = position {
                assert(end == observed);
                assert(last == if current < observed && pending_tail.is_some() { pending_tail } else { tail });
            }
        },
        Err(crate::group_frontier::PublicationError::Sync(_)) => {
            assert(!success && poisoned && pending == count);
        },
        Err(_) => assert(false),
    }
}

/// A success receipt for the group requires both operations to have accepted
/// the very same persisted frontier, preserving all entries and their order.
fn complete_group<B,D,T,E,P,F>(batch: B, persist: P, advance: F)
    -> (outcome: Result<(B,T),(B,E)>)
    where P: FnOnce(&B) -> Result<D,E>, F: FnOnce(D) -> Result<T,E>,
    requires
        persist.requires((&batch,)),
        forall|d: D| #[trigger] persist.ensures((&batch,), Ok(d)) ==> advance.requires((d,)),
    ensures
        outcome matches Ok((entries,receipt)) ==> entries == batch && exists|d: D|
            #[trigger] persist.ensures((&batch,), Ok(d)) && advance.ensures((d,), Ok(receipt)),
        outcome matches Err((entries,error)) ==> entries == batch && (
            persist.ensures((&batch,), Err(error)) || exists|d: D|
                #[trigger] persist.ensures((&batch,), Ok(d)) && advance.ensures((d,), Err(error))),
{
    let staged = crate::group_frontier::PersistedGroup::persist(batch, persist)?;
    staged.publish(advance)
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
