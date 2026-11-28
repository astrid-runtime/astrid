//! Composition for a tracked guest KV call. Store construction, guard lifetime,
//! device admission and backend atomicity require separate runtime refinement.
use crate::{guest_authority, guest_kv_dispatch, principal_invocation_state::PrincipalInvocation};
use crate::owner_codec::{self, Owner};
use crate::root_transition::{Advance, PreparedRoot, Replay, Version, advance, replay};
use crate::root_wire;
use std::collections::BTreeMap;
use vstd::laws_cmp::{obeys_cmp,obeys_cmp_concrete_eq};
use vstd::pervasive::obeys_clone_eq;
use vstd::std_specs::btree::btree_map_inv;
use vstd::prelude::*;

verus! {

/// Once a purge advances the epoch, even an unchanged root for the same
/// owner cannot revive an older ticket. A saturated counter stays closed.
fn memo_after_purge<P>(before:u64,later:u64,owner:&P,expected:Option<crate::RootState>) -> (ok:bool)
    requires later >= before,
    ensures !ok,
{
    let captured = crate::memo_admission::MemoEpoch::new(before);
    let after = crate::memo_admission::MemoEpoch::new(later).after_purge();
    captured.admits_root(crate::memo_admission::MemoEpoch::new(after),owner,expected,
        |_p:&P| -> (r:Result<Option<crate::RootState>,()>) ensures r == Ok(expected) { Ok(expected) })
}

/// Matching the root includes its full generation and commit, including
/// the absent-root case used when seeding an empty destination.
fn memo_for_sample<P>(epoch:u64,owner:&P,expected:Option<crate::RootState>,sample:Result<Option<crate::RootState>,()>)
    -> (ok:bool)
    ensures ok == (epoch < u64::MAX && sample == Ok(expected)),
{
    let captured = crate::memo_admission::MemoEpoch::new(epoch);
    captured.admits_root(captured,owner,expected,
        |_p:&P| -> (r:Result<Option<crate::RootState>,()>) ensures r == sample { sample })
}

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
fn guest_publication<R: Copy, E, U, T, W, A, F, V>(scope: &[u8], requested: &[u8], admitted: [u8;32],
    observed: [u8;32], expected: Option<R>, replacement: R, encode: W, append: A, writer:&mut BTreeMap<[u8;32],R>, memo:F, visible:V)
    -> (outcome: Option<Result<(R,U,T), E>>)
    where W: FnOnce(&[u8;32],Option<R>,R) -> Result<Vec<u8>,E>,
          A: FnOnce(&[u8;32], Option<R>, R, &Vec<u8>) -> Result<U,E>,
          F: FnOnce(&BTreeMap<[u8;32],R>,&[u8;32],R) -> T, V:FnOnce(&[u8;32],R,&T),
    requires encode.requires((&admitted, expected, replacement)),
        obeys_cmp::<[u8;32]>(), obeys_cmp_concrete_eq::<[u8;32]>(), obeys_clone_eq::<[u8;32]>(), btree_map_inv(old(writer)),
        forall|w:&BTreeMap<[u8;32],R>| w@ == old(writer)@.insert(admitted,replacement) ==> #[trigger] memo.requires((w,&admitted,replacement)),
        forall|w:&BTreeMap<[u8;32],R>,t:&T| w@ == old(writer)@.insert(admitted,replacement) && #[trigger] memo.ensures((w,&admitted,replacement),*t)
            ==> visible.requires((&admitted,replacement,t)),
        forall|j: &Vec<u8>| encode.ensures((&admitted, expected, replacement), Ok(*j))
            ==> #[trigger] append.requires((&admitted,expected,replacement,j)),
    ensures
        btree_map_inv(final(writer)),
        final(writer)@ == if outcome matches Some(Ok(_)) {old(writer)@.insert(admitted,replacement)} else {old(writer)@},
        outcome.is_some() == (scope@ == requested@ && admitted@ == observed@),
        outcome matches Some(Err(e)) ==> encode.ensures((&admitted, expected, replacement), Err(e))
            || recorded(admitted, expected, replacement, encode, append, Err(e)),
        outcome matches Some(Ok((ack, written, receipt))) ==> {
            &&& ack == replacement
            &&& memo.ensures((&*final(writer),&admitted, ack), receipt)
            &&& visible.ensures((&admitted,ack,&receipt),())
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
            let (ack, receipt) = prepared.publish(writer,memo,visible);
            assert(ack == replacement);

            Some(Ok((ack,staged,receipt)))
        },
        Err(e) => Some(Err(e)),
    }
}

/// The visibility callback installed after WAL success can address only the
/// selected owner's current slot, or request a new slot for that owner.
fn guest_slot_publication<S,U,N>(scope:&[u8],requested:&[u8],admitted:[u8;32],observed:[u8;32],
    prior:Option<crate::RootState>,root:crate::RootState,writer:&mut BTreeMap<[u8;32],crate::RootState>,
    slots:&BTreeMap<[u8;32],S>,update:U,new:N,append_ok:bool) -> (ok:bool)
    where U:FnOnce(&S,crate::RootState),N:FnOnce(&BTreeMap<[u8;32],S>,&[u8;32],crate::RootState),
    requires btree_map_inv(old(writer)),btree_map_inv(slots),obeys_cmp::<[u8;32]>(),obeys_cmp_concrete_eq::<[u8;32]>(),obeys_clone_eq::<[u8;32]>(),
        if slots@.contains_key(admitted) { update.requires((&slots@[admitted],root)) }
        else { new.requires((slots,&admitted,root)) },
    ensures ok == (scope@ == requested@ && admitted@ == observed@ && append_ok),
        final(writer)@ == if ok {old(writer)@.insert(admitted,root)} else {old(writer)@},
        ok ==> if slots@.contains_key(admitted) {update.ensures((&slots@[admitted],root),())}
            else {new.ensures((slots,&admitted,root),())},
{
    let encode = |_:&[u8;32],_:Option<crate::RootState>,_:crate::RootState| -> (r:Result<Vec<u8>,()>)
        ensures r is Ok, {Ok(Vec::new())};
    let append = |_:&[u8;32],_:Option<crate::RootState>,_:crate::RootState,_:&Vec<u8>| -> (r:Result<(),()>)
        ensures r.is_ok() == append_ok, {if append_ok {Ok(())} else {Err(())}};
    let memo = |_:&BTreeMap<[u8;32],crate::RootState>,_:&[u8;32],_:crate::RootState| {};
    let visible = |p:&[u8;32],r:crate::RootState,_:&()| -> (out:())
        requires *p == admitted,r == root,
        ensures if slots@.contains_key(*p) {update.ensures((&slots@[*p],r),out)} else {new.ensures((slots,p,r),out)},
    {crate::root_transition::publish_slot(slots,p,r,update,new)};
    matches!(guest_publication(scope,requested,admitted,observed,prior,root,encode,append,writer,memo,visible),Some(Ok(_)))
}

/// Durable transition bytes for a guest-selected principal recover that
/// principal and both prepared root fields, without a model decoder. The
/// scanner represents a sequence as nonzero; an ordinal may start at zero.
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
        kind: crate::wal_record_wire::WalRecordKind::Root.tag(), flags: 0, reserved: [0;2], sequence, ordinal,
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
    let kind = crate::wal_record_wire::WalRecordKind::from_tag(scanned.kind);
    assert(kind matches Some(crate::wal_record_wire::WalRecordKind::Root));
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

/// Even a valid body cannot publish for another owner or a different pair of roots.
fn reject_other_binding(live: Vec<u8>, saved: &[u8], expected: Option<root_wire::Root>,
    prior: Option<root_wire::Root>, replacement: root_wire::Root, next: root_wire::Root)
    requires live@ != saved@ || !root_wire::same_expected(expected,prior) || !root_wire::same(replacement,next),
{
    let result = root_wire::bind_owner(live,saved,expected,prior,replacement,next);
    proof {
        if live@ != saved@ { assert(result matches Err(root_wire::BindingError::Owner)); }
        else { assert(result matches Err(root_wire::BindingError::Roots)); }
    }
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
        Ok((reported, ())) => {
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
    let (published,receipt)=staged.publish(advance)?;
    Ok((published.into_batch(),receipt))
}

type WriterRoots=BTreeMap<u64,crate::RootState>;
type AcceptedRoot=crate::group_receipt::Accepted<PreparedRoot<u64,crate::RootState>,u64,()>;
type RootReplies=Vec<(u64,Result<crate::RootState,u64>)>;

/// Publish each accepted root into one owner map and correlate its result with the original receipt.
/// A persistence or frontier refusal returns every receipt with an error before publishing roots.
fn group_root_receipts<D,P,F>(batch:Vec<AcceptedRoot>,writer:WriterRoots,persist:P,advance:F,unavailable:u64)
    -> (out:(WriterRoots,RootReplies))
    where P:FnOnce(&Vec<AcceptedRoot>)->Result<D,u64>,F:FnOnce(D)->Result<(),u64>,
    requires btree_map_inv(&writer),obeys_cmp::<u64>(),obeys_cmp_concrete_eq::<u64>(),obeys_clone_eq::<u64>(),
        persist.requires((&batch,)),forall|d:D| #[trigger] persist.ensures((&batch,),Ok(d)) ==> advance.requires((d,)),
    ensures out.1.len()==batch.len(),btree_map_inv(&out.0),
        forall|i:int| 0<=i<batch.len() ==> (#[trigger] out.1@[i]).0==batch@[i].receipt,
        ({
            let rows=out.1@;
            ||| (exists|d:D| #[trigger] persist.ensures((&batch,),Ok(d)) && advance.ensures((d,),Ok(()))) &&
                (exists|history:Seq<WriterRoots>| history.len()==batch.len()+1 && history[0]==writer && history.last()==out.0 &&
                    forall|i:int| 0<=i<batch.len() ==> {
                        let root=batch@[i].prepared.binding();
                        &&& #[trigger] history[i+1]@==history[i]@.insert(root.0,root.2)
                        &&& rows[i].1==Ok(root.2)
                    })
            ||| out.0==writer && exists|error:u64| (persist.ensures((&batch,),Err(error)) ||
                exists|d:D| #[trigger] persist.ensures((&batch,),Ok(d)) && advance.ensures((d,),Err(error))) &&
                forall|i:int| 0<=i<batch.len() ==> #[trigger] rows[i].1==Err(if i==0 {error} else {unavailable})
        }),
{
    use crate::{group_frontier::PersistedGroup,group_receipt};
    let mut done=RootReplies::new();
    let published=match PersistedGroup::persist(batch,persist) {
        Ok(group)=>group.publish(advance),Err(failure)=>Err(failure),
    };
    let group=match published {
        Ok((token,()))=>token,
        Err((failed,error))=>{
            let ghost start=done.len() as int;
            assert(start==0 && failed==batch);
            group_receipt::reject(failed,&mut done,error,|| -> (e:u64) ensures e==unavailable {unavailable});
            assert forall|i:int| 0<=i<batch.len() implies (#[trigger] done@[i]).0==batch@[i].receipt &&
                done@[i].1==Err(if i==0 {error} else {unavailable}) by {
                assert(done@[start+i].0==failed@[i].receipt);
            }
            return (writer,done);
        },
    };
    let publish=|mut roots:WriterRoots,root:PreparedRoot<u64,crate::RootState>| -> (v:(WriterRoots,crate::RootState))
        requires btree_map_inv(&roots),
        ensures btree_map_inv(&v.0),v.0@==roots@.insert(root.binding().0,root.binding().2),v.1==root.binding().2,
    {
        let (replacement,())=root.publish(&mut roots,|_,_,_| (),|_,_,_| ());
        (roots,replacement)
    };
    let ghost valid=|roots:WriterRoots| btree_map_inv(&roots);
    assert(group_receipt::preserves(valid,publish));
    let final_roots=group_receipt::release(group,&mut done,writer,publish);
    proof {
        assert(done@.skip(0) =~= done@);
        let history=choose|h:Seq<WriterRoots>| #[trigger] group_receipt::completed(batch@,writer,h,done@,publish) && h.last()==final_roots;
        assert forall|i:int| 0<=i<batch.len() implies {
            let root=batch@[i].prepared.binding();
            &&& #[trigger] history[i+1]@==history[i]@.insert(root.0,root.2)
            &&& done@[i].1==Ok(root.2)
        } by {
            let row=done@[i];
            assert(row.1 is Ok);
            let value=choose|v:crate::RootState| row.1==Ok(v);
            assert(publish.ensures((history[i],batch@[i].prepared),(history[i+1],value)));
        }
        if batch.len()>0 {
            let i=batch.len() as int-1;
            assert(history[i+1]==history.last());
            assert(done@[i].1==Ok(batch@[i].prepared.binding().2));
            assert(publish.ensures((history[i],batch@[i].prepared),(history[i+1],batch@[i].prepared.binding().2)));
        } else {assert(final_roots==writer);}
    };
    (final_roots,done)
}

struct ReceiptTrace {sent:Ghost<Seq<(u64,Result<u64,u64>)>>}

impl crate::group_receipt::Delivery<u64,Result<u64,u64>> for ReceiptTrace {
    closed spec fn sent(&self) -> Seq<(u64,Result<u64,u64>)> {self.sent@}
    fn send(&mut self,receipt:u64,result:Result<u64,u64>) {
        self.sent = Ghost(self.sent@.push((receipt,result)));
    }
}

fn deliver_group<D,E,P,F>(batch:Vec<(u64,Result<u64,u64>)>,persist:P,advance:F)
    where P:FnOnce(&Vec<(u64,Result<u64,u64>)>)->Result<D,E>,F:FnOnce(D)->Result<(),E>,
    requires persist.requires((&batch,)),
        forall|d:D| #[trigger] persist.ensures((&batch,),Ok(d)) ==> advance.requires((d,)),
{
    let ghost original = batch@;
    if let Ok((released,())) = complete_group(batch,persist,advance) {
        let mut trace = ReceiptTrace {sent:Ghost(Seq::empty())};
        crate::group_receipt::deliver(&mut trace,released);
        assert(trace.sent@ =~= original);
    }
}

// A prior rejected request, the current published root, and an unsuccessful
// peer all share one completion vector without exchanging receipts.
fn mixed_receipts(prior:u64,submitted:u64,peer:u64,root:u64,error:u64) {
    use crate::group_receipt::Accepted;
    let mut done = vec![(prior,Err(error))];
    let first = Accepted {prepared:root,receipt:submitted,observer:()};
    first.published(&mut done,|r:u64| -> (o:((),u64)) ensures o == ((),r), {((),r)});
    let second = Accepted {prepared:(),receipt:peer,observer:()};
    second.failed(&mut done,error);
    let mut trace = ReceiptTrace {sent:Ghost(Seq::empty())};
    crate::group_receipt::deliver(&mut trace,done);
    assert(trace.sent@ =~= seq![(prior,Err(error)),(submitted,Ok(root)),(peer,Err(error))]);
}

// Submit two independent callers, hand off leadership without dequeuing,
// drain their FIFO and prepare their transactions under the original observers.
fn departing_leader(a:u64,b:u64,owns_front:bool) {
    use crate::group_receipt::Submission;
    use std::sync::Arc;
    let first = Arc::new(a);
    let second = Arc::new(b);
    let mut queue = Vec::new();
    let mut active = false;
    Submission::enqueue(&mut queue,&mut active,a,&first,0u8);
    Submission::enqueue(&mut queue,&mut active,b,&second,1u8);
    let (removed,next) = Submission::handoff(&mut queue,&mut active,owns_front);
    if owns_front {
        assert(removed == Some(Submission {transaction:a,receipt:first,observer:0u8}));
        assert(next == Some(second) && active && queue.len() == 1);
        let (last,none) = Submission::handoff(&mut queue,&mut active,true);
        assert(last == Some(Submission {transaction:b,receipt:second,observer:1u8}));
        assert(none.is_none() && !active && queue.len() == 0);
    } else {
        assert(removed.is_none() && next == Some(first) && active && queue.len() == 2);
        assert(queue@[1] == Submission {transaction:b,receipt:second,observer:1u8});
    }
}

fn queued_callers(a:u64,b:u64,tx:u64,other:u64,observer:u64,peer_observer:u64,error:u64) {
    use crate::group_receipt::Submission;
    use std::sync::Arc;
    let first = Arc::new(a);
    let second = Arc::new(b);
    let mut queue = Vec::new();
    let mut leader = false;
    let elected = Submission::enqueue(&mut queue,&mut leader,tx,&first,observer);
    assert(elected && leader);
    let competing = Submission::enqueue(&mut queue,&mut leader,other,&second,peer_observer);
    assert(!competing && leader);
    let next = Submission::successor(&queue,&mut leader);
    assert(next == Some(first) && leader);
    let batch = Submission::drain(&mut queue);
    assert(batch.len() == 2 && queue.len() == 0);
    let no_next = Submission::successor(&queue,&mut leader);
    assert(no_next.is_none() && !leader);
    let mut it = batch.into_iter();
    let Some(request) = it.next() else {assert(false);return;};
    let Some(peer) = it.next() else {assert(false);return;};
    let accepted = request.prepare(|v:u64,o:&u64| -> (r:Result<(u64,u64),u64>)
        ensures r == Ok((v,*o)), {Ok((v,*o))});
    let failed = peer.prepare(|v:u64,o:&u64| -> (r:Result<(),(u64,u64,u64)>)
        ensures r == Err((v,*o,error)), {Err((v,*o,error))});
    let Ok(accepted) = accepted else {assert(false);return;};
    assert(accepted.receipt == first && accepted.observer == observer && accepted.prepared == (tx,observer));
    assert(failed == Err((second,(other,peer_observer,error))));
    let mut done = Vec::<(Arc<u64>,Result<u64,u64>)>::new();
    accepted.published(&mut done,|p:(u64,u64)| -> (root:((),u64)) ensures root == ((),p.0),{((),p.0)});
    assert(done@ == seq![(first,Ok(tx))]);
}

// A completion replaces a pending leadership signal. Neither a second
// completion nor a late promotion can replace the result before polling.
fn receive_result<T>(first:T,late:T,after:T) {
    use crate::group_receipt::{Action,Slot};
    let mut slot = Slot::Waiting;
    let empty = slot.poll();
    assert(empty.is_none());
    let promoted = slot.promote();
    assert(promoted);
    let duplicate = slot.promote();
    assert(!duplicate);
    let leadership = slot.poll();
    assert(leadership == Some(Action::Lead));
    let _ = slot.promote();
    let ready = slot.complete(first);
    assert(ready);
    let overwrite = slot.complete(late);
    let promote = slot.promote();
    assert(!overwrite && !promote);
    let received = slot.poll();
    assert(received == Some(Action::Complete(first)));
    let refill = slot.complete(after);
    let reelect = slot.promote();
    assert(!refill && !reelect);
    let again = slot.poll();
    assert(again.is_none());
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
