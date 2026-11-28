//! Track canonical media from replay through the next buffered WAL resize.
use crate::recovery_barrier::{self as barrier,Error,Files,Target};
use vstd::prelude::*;
use crate::{ObjectId,RootState,recovered_closure as closure};
use std::collections::{BTreeMap,BTreeSet};
use vstd::{laws_cmp::{obeys_cmp,obeys_cmp_concrete_eq},std_specs::btree::btree_map_inv};

verus! {

/// Carry the actual WAL state through stabilization. Every error identifies the last attempted sync.
fn handoff<M:Files,W,V,F:FnOnce(W)->V>(files:&mut M,wal:W,finish:F) -> (out:Result<V,Error<M::Error>>)
    requires finish.requires((wal,)),old(files).pending().contains_key(Target::Arena),
        old(files).pending().contains_key(Target::Roots),
        old(files).has_representations() ==> old(files).pending().contains_key(Target::Representations),
    ensures ({
        let a = Target::Arena; let r = Target::Roots; let x = Target::Representations;
        let first = old(files).calls().push(a); let second = first.push(r); let third = second.push(x);
        match out {
            Ok(result) => {
                &&& finish.ensures((wal,),result)
                &&& old(files).volume_id().is_none() ==> final(files).durable()[a] == old(files).pending()[a]
                &&& old(files).volume_id().is_none() ==> final(files).durable()[r] == old(files).pending()[r]
                &&& if old(files).has_representations() {
                    final(files).calls() == third && (old(files).volume_id().is_none() ==> final(files).durable()[x] == old(files).pending()[x])
                } else {final(files).calls() == second && (old(files).volume_id().is_none() ==> final(files).durable().get(x) == old(files).durable().get(x))}
            },
            Err(Error::Arena(_)) => final(files).calls() == first,
            Err(Error::Roots(_)) => final(files).calls() == second,
            Err(Error::Representations(_)) => old(files).has_representations() && final(files).calls() == third,
        }
    }),
{
    let stable = barrier::stabilize(files,wal)?;
    Ok(stable.finish(finish))
}
/// Match the WAL to its canonical files, then observe the images at the actual
/// truncate attempt. On a volume the buffered flush makes the canonical writes stable.
fn checkpoint_resize<M:Files,W:Copy,S:crate::group_frontier::ResizeWal,F:FnOnce(W,&M)->S>(
    files:&mut M,wal:W,bind:F,target:Ghost<spec_fn(W)->(int,Seq<u8>)>,wal_bytes:Ghost<Seq<u8>>,previous:Ghost<Seq<(u64,crate::group_frontier::CanonicalImages)>>,length:u64)
    -> (out:Result<(S,Result<(),S::Error>),Error<M::Error>>)
    requires length<=wal_bytes@.len(),old(files).pending().contains_key(Target::Arena),
        old(files).pending().contains_key(Target::Roots),
        old(files).has_representations() ==> old(files).pending().contains_key(Target::Representations),
        forall|m:&M| #[trigger] bind.requires((wal,m)),
        forall|m:&M,s:S| #[trigger] bind.ensures((wal,m),s) ==> s.wal_target()==(target@)(wal) && s.buffered_image()==wal_bytes@ &&
            s.resizes()==previous@ && s.volume_wal()==m.volume_id().is_some() &&
            (m.volume_id() matches Some(id) ==> id==s.wal_target().0) &&
            s.canonical_pending()==m.pending() && s.canonical_stable()==m.durable(),
    ensures out matches Ok((s,result)) ==> {
        let attempts=s.resizes().skip(previous@.len() as int);
        &&& s.resizes()==previous@+attempts
        &&& s.wal_target()==(target@)(wal)
        &&& old(files).volume_id() matches Some(id) ==> s.wal_target().0==id
        &&& attempts.len()<=1
        &&& (result.is_ok() ==> attempts.len()==1 && s.buffered_image()==wal_bytes@.take(length as int))
        &&& attempts.len()==1 ==> {
            let snapshot=attempts[0].1;
            &&& attempts[0].0==length
            &&& snapshot.contains_key(Target::Arena) && snapshot.contains_key(Target::Roots)
            &&& old(files).has_representations() ==> snapshot.contains_key(Target::Representations)
            &&& snapshot[Target::Arena]==old(files).pending()[Target::Arena]
            &&& snapshot[Target::Roots]==old(files).pending()[Target::Roots]
            &&& old(files).has_representations() ==> snapshot[Target::Representations]==old(files).pending()[Target::Representations]
            &&& result.is_ok() ==> s.canonical_stable()==snapshot
        }
    },
{
    let prepared=barrier::stabilize(files,wal)?;
    let original=prepared.finish(|w:W| -> (out:W) ensures out==w, {w});
    let mut sink=bind(original,files);
    let result=crate::group_frontier::resize_buffered(&mut sink,length);
    proof {
        let calls=sink.resizes();
        if calls.len()>previous@.len() {
            assert(calls.skip(previous@.len() as int) =~= seq![calls.last()]);
        } else {assert(calls.skip(previous@.len() as int) =~= Seq::empty());}
        assert(calls =~= previous@+calls.skip(previous@.len() as int));
    }
    Ok((sink,result))
}

/// Complete the writer's final checkpoint on the prepared handle. A successful seek
/// to zero on this drained buffer moves the cursor and preserves the file images.
fn retire_wal<S:crate::group_frontier::ResizeWal,R:FnOnce(S)->Result<S,S::Error>>(sink:S,rewind:R)
    -> (out:Result<S,crate::group_frontier::CheckpointError<S::Error>>)
    requires forall|s:S| #[trigger] rewind.requires((s,)),
        forall|s:S,r:S| #[trigger] rewind.ensures((s,),Ok(r)) ==>
            r.roots_target()==s.roots_target() && r.arena_target()==s.arena_target() && r.wal_target()==s.wal_target() && r.volume_wal()==s.volume_wal() &&
            r.canonical_pending()==s.canonical_pending() && r.canonical_stable()==s.canonical_stable() &&
            r.buffered_image()==s.buffered_image(),
    ensures out matches Ok(s) ==> s.roots_target()==sink.roots_target() && s.arena_target()==sink.arena_target() && s.wal_target()==sink.wal_target() && s.stable_image()==Seq::<u8>::empty() &&
        s.canonical_stable()==(if sink.volume_wal() {sink.canonical_pending()} else {sink.canonical_stable()}),
{
    use crate::group_frontier::{checkpoint_io,resize_buffered,publish_buffer};
    checkpoint_io(sink,|mut s:S| -> (out:Result<S,S::Error>)
        ensures out matches Ok(t) ==> t.roots_target()==s.roots_target() && t.arena_target()==s.arena_target() && t.wal_target()==s.wal_target() && t.volume_wal()==s.volume_wal() &&
            t.canonical_pending()==s.canonical_pending() && t.buffered_image()==Seq::<u8>::empty() &&
            t.canonical_stable()==(if s.volume_wal() {s.canonical_pending()} else {s.canonical_stable()}),
        {
            resize_buffered(&mut s,0)?;
            assert(s.buffered_image() =~= Seq::<u8>::empty());
            Ok(s)
        },rewind,|mut s:S| -> (out:Result<S,S::Error>)
        ensures out matches Ok(t) ==> t.roots_target()==s.roots_target() && t.arena_target()==s.arena_target() && t.wal_target()==s.wal_target() && t.stable_image()==s.buffered_image() &&
            t.canonical_stable()==(if s.volume_wal() {s.canonical_pending()} else {s.canonical_stable()}),
        {
            publish_buffer(&mut s)?;
            Ok(s)
        })
}

/// Every sync acts on the same checkpoint and keeps its pending root and arena images.
pub(super) open spec fn same_fold<S:crate::group_frontier::ResizeWal>(before:S,after:S) -> bool {
    &&& after.arena_target()==before.arena_target() && after.roots_target()==before.roots_target()
    &&& after.wal_target()==before.wal_target() && after.volume_wal()==before.volume_wal()
    &&& after.canonical_pending()==before.canonical_pending() && after.buffered_image()==before.buffered_image()
}

/// File sync installs only the selected canonical image. Volume durability comes from container sync.
pub(super) open spec fn synced<S:crate::group_frontier::ResizeWal>(before:S,after:S,which:Target) -> bool {
    &&& same_fold(before,after)
    &&& !before.volume_wal() ==> after.canonical_stable()==
        (if before.canonical_pending().contains_key(which) {
            before.canonical_stable().insert(which,before.canonical_pending()[which])
        } else {before.canonical_stable()})
}

pub(super) open spec fn live_phases<S,A,R,J,V,Seek>(initial:S,arena:A,representations:R,roots:J,volume:V,rewind:Seek) -> bool
    where S:crate::group_frontier::ResizeWal,A:FnOnce(S)->Result<S,S::Error>,R:FnOnce(S)->Result<S,S::Error>,
        J:FnOnce(S)->Result<S,S::Error>,V:FnOnce(S)->Result<S,S::Error>,Seek:FnOnce(S)->Result<S,S::Error>
{
    &&& initial.canonical_pending().contains_key(Target::Arena) && initial.canonical_pending().contains_key(Target::Roots)
    &&& arena.requires((initial,))
    &&& forall|s:S| #[trigger] representations.requires((s,))
    &&& forall|s:S| #[trigger] roots.requires((s,))
    &&& forall|s:S| #[trigger] volume.requires((s,))
    &&& forall|a:S| #[trigger] arena.ensures((initial,),Ok(a)) ==> synced(initial,a,Target::Arena)
    &&& forall|a:S,r:S| #[trigger] representations.ensures((a,),Ok(r)) ==> synced(a,r,Target::Representations)
    &&& forall|r:S,j:S| #[trigger] roots.ensures((r,),Ok(j)) ==> synced(r,j,Target::Roots)
    &&& forall|j:S,v:S| #[trigger] volume.ensures((j,),Ok(v)) ==> same_fold(j,v) &&
        v.canonical_stable()==(if j.volume_wal() {j.canonical_pending()} else {j.canonical_stable()})
    &&& forall|s:S| #[trigger] rewind.requires((s,))
    &&& forall|s:S,r:S| #[trigger] rewind.ensures((s,),Ok(r)) ==> same_fold(s,r) && r.canonical_stable()==s.canonical_stable()
}

/// Use the live fold barrier before the production writer's WAL resize, rewind and final sync.
pub(super) fn retire_live_fold<S,A,R,J,V,Seek>(initial:S,arena:A,representations:R,roots:J,volume:V,rewind:Seek)
    -> (out:Result<Result<S,crate::group_frontier::CheckpointError<S::Error>>,S::Error>)
    where S:crate::group_frontier::ResizeWal,A:FnOnce(S)->Result<S,S::Error>,R:FnOnce(S)->Result<S,S::Error>,
        J:FnOnce(S)->Result<S,S::Error>,V:FnOnce(S)->Result<S,S::Error>,Seek:FnOnce(S)->Result<S,S::Error>,
    requires live_phases(initial,arena,representations,roots,volume,rewind),
    ensures out matches Ok(Ok(s)) ==> {
        &&& s.wal_target()==initial.wal_target() && s.roots_target()==initial.roots_target() && s.arena_target()==initial.arena_target()
        &&& s.stable_image()==Seq::<u8>::empty()
        &&& s.canonical_stable().get(Target::Roots)==initial.canonical_pending().get(Target::Roots)
        &&& s.canonical_stable().get(Target::Arena)==initial.canonical_pending().get(Target::Arena)
        &&& initial.canonical_pending().contains_key(Target::Representations) ==>
            s.canonical_stable().get(Target::Representations)==initial.canonical_pending().get(Target::Representations)
    },
{
    let stable=barrier::stabilize_fold(initial,arena,representations,roots,volume)?;
    let media=stable.finish(|s:S| -> (v:S) ensures v==s, {s});
    proof {
        let (a,r,j)=choose|a:S,r:S,j:S| #[trigger] arena.ensures((initial,),Ok(a)) &&
            #[trigger] representations.ensures((a,),Ok(r)) && #[trigger] roots.ensures((r,),Ok(j)) && volume.ensures((j,),Ok(media));
        assert(same_fold(initial,media));
        assert(media.canonical_stable().get(Target::Roots)==initial.canonical_pending().get(Target::Roots));
    }
    Ok(retire_wal(media,rewind))
}

/// Match the writer to the canonical handles that recovery just handed off.
pub(crate) fn recovered_checkpoint<M:Files,W:Copy,S:crate::group_frontier::ResizeWal,F:FnOnce(W,&M)->S,R:FnOnce(S)->Result<S,S::Error>>(
    files:&mut M,wal:W,bind:F,rewind:R,target:Ghost<spec_fn(W)->(int,Seq<u8>)>)
    -> (out:Result<Result<S,crate::group_frontier::CheckpointError<S::Error>>,Error<M::Error>>)
    requires old(files).pending().contains_key(Target::Arena),old(files).pending().contains_key(Target::Roots),
        old(files).has_representations() ==> old(files).pending().contains_key(Target::Representations),
        forall|m:&M| #[trigger] bind.requires((wal,m)),
        forall|m:&M,s:S| #[trigger] bind.ensures((wal,m),s) ==> s.wal_target()==(target@)(wal) &&
            s.roots_target()==m.roots_target() && s.arena_target()==m.arena_target() && s.volume_wal()==m.volume_id().is_some() && (m.volume_id() matches Some(id) ==> id==s.wal_target().0) &&
            s.canonical_pending()==m.pending() && s.canonical_stable()==m.durable(),
        forall|s:S| #[trigger] rewind.requires((s,)),
        forall|s:S,r:S| #[trigger] rewind.ensures((s,),Ok(r)) ==>
            r.roots_target()==s.roots_target() && r.arena_target()==s.arena_target() && r.wal_target()==s.wal_target() && r.volume_wal()==s.volume_wal() &&
            r.canonical_pending()==s.canonical_pending() && r.canonical_stable()==s.canonical_stable() &&
            r.buffered_image()==s.buffered_image(),
    ensures out matches Ok(Ok(s)) ==> {
        let stable=s.canonical_stable(); let pending=old(files).pending();
        &&& s.arena_target()==old(files).arena_target()
        &&& s.roots_target()==old(files).roots_target()
        &&& s.wal_target()==(target@)(wal) && s.stable_image()==Seq::<u8>::empty()
        &&& old(files).volume_id() matches Some(id) ==> s.wal_target().0==id
        &&& stable.get(Target::Arena)==pending.get(Target::Arena)
        &&& stable.get(Target::Roots)==pending.get(Target::Roots)
        &&& old(files).has_representations() ==> stable.get(Target::Representations)==pending.get(Target::Representations)
    },
{
    let prepared=barrier::stabilize(files,wal)?;
    let original=prepared.finish(|w:W| -> (out:W) ensures out==w, {w});
    Ok(retire_wal(bind(original,files),rewind))
}

/// A root and child enter the known set together only after the validator accepts their loaded records.
fn validate_pair(known:&mut std::collections::BTreeSet<u64>,commit:u64,child:u64,at:u64,readable:bool,accepted:bool)
    -> (out:Result<(),u8>)
    requires vstd::std_specs::btree::btree_set_inv(old(known)),
    ensures (match out {Ok(()) => readable && accepted,Err(e) => (!readable && e == 1) || (readable && !accepted && e == 2)}),
        final(known)@ == if out.is_ok() {old(known)@.insert(commit).insert(child)} else {old(known)@},
{
    use crate::recovered_closure as closure;
    let load = |id:u64,pos:u64| -> (out:Result<Vec<(u64,u64)>,u8>)
        ensures if readable && pos == at && id == commit {
            out matches Ok(v) && v@ == seq![(commit,child),(child,child)]
        } else {out == Err(1u8)},
    {
        if readable && pos == at && id == commit {Ok(vec![(commit,child),(child,child)])} else {Err(1)}
    };
    let validate = |rows:&Vec<(u64,u64)>,id:u64,pos:u64| -> (out:Result<(),u8>)
        ensures out == if accepted && pos == at && id == commit && rows@ == seq![(commit,child),(child,child)] {Ok(())} else {Err(2u8)},
    {
        if accepted && pos == at && id == commit && rows.len() == 2 &&
            rows[0].0 == commit && rows[0].1 == child && rows[1].0 == child && rows[1].1 == child {
            assert(rows@ =~= seq![(commit,child),(child,child)]);
            Ok(())
        } else {Err(2)}
    };
    let out = closure::check(known,commit,at,load,validate);
    if out.is_ok() {
        let ghost rows = choose|v:Vec<(u64,u64)>| #[trigger] load.ensures((commit,at),Ok(v)) &&
            validate.ensures((&v,commit,at),Ok(())) && known@ == old(known)@.union(closure::ids(v@));
        let ghost keys = rows@.map(|i:int,row:(u64,u64)| row.0);
        assert(keys =~= seq![commit,child]);
        assert(keys.to_set() =~= set![commit,child]) by {
            assert forall|k:u64| keys.contains(k) implies k == commit || k == child by {
                let i = keys.index_of(k); assert(keys[i] == k);
            }
        }
        assert(known@ =~= old(known)@.insert(commit).insert(child));
        assert(readable && accepted);
    } else {
        let ghost e = out.unwrap_err();
        assert(out == Err(e));
        proof {
            if load.ensures((commit,at),Err(e)) {assert(!readable && e == 1);}
            else {
                let rows = choose|v:Vec<(u64,u64)>| #[trigger] load.ensures((commit,at),Ok(v)) && validate.ensures((&v,commit,at),Err(e));
                assert(readable && rows@ == seq![(commit,child),(child,child)]);
                assert(!accepted && e == 2);
            }
            assert((!readable && e == 1) || (readable && !accepted && e == 2));
        }
    }
    out
}

/// Every journal owner has an accepted closure, and every returned ID came from such a closure.
fn validate_owners<P:Ord,R,E,L,V>(history:&BTreeMap<P,(RootState,u64)>,load:L,validate:V)
    -> (out:Result<BTreeSet<ObjectId>,E>)
    where L:Fn(ObjectId,u64)->Result<Vec<(ObjectId,R)>,E>,V:Fn(&Vec<(ObjectId,R)>,ObjectId,u64)->Result<(),E>,
    requires btree_map_inv(history),obeys_cmp::<P>(),obeys_cmp_concrete_eq::<P>(),
        obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
        forall|k:ObjectId,at:u64| #[trigger] load.requires((k,at)),
        forall|r:Vec<(ObjectId,R)>,k:ObjectId,at:u64| #[trigger] validate.requires((&r,k,at)),
    ensures match out {
        Ok(known) => {
            &&& forall|p:P| #[trigger] history@.contains_key(p) ==> exists|r:Vec<(ObjectId,R)>|
                #[trigger] closure::accepted(history@[p],r,load,validate) && closure::ids(r@).subset_of(known@)
            &&& forall|k:ObjectId| #[trigger] known@.contains(k) ==> exists|p:P,r:Vec<(ObjectId,R)>|
                history@.contains_key(p) && #[trigger] closure::accepted(history@[p],r,load,validate) && closure::ids(r@).contains(k)
        },
        Err(e) => exists|p:P| #[trigger] history@.contains_key(p) && ({
            let (root,at) = history@[p];
            load.ensures((root.commit,at),Err(e)) || exists|r:Vec<(ObjectId,R)>| #[trigger] load.ensures((root.commit,at),Ok(r)) &&
                validate.ensures((&r,root.commit,at),Err(e))
        }),
    },
{
    let known = closure::check_all(history,load,validate)?;
    proof {
        let (entries,sets) = choose|es:Seq<(P,(RootState,u64))>,rs:Seq<Vec<(ObjectId,R)>>|
            es.to_set() == history@.kv_pairs() && es.len() == history.len() &&
                #[trigger] closure::complete(es,rs,known@,load,validate);
        assert forall|p:P| #[trigger] history@.contains_key(p) implies exists|r:Vec<(ObjectId,R)>|
            #[trigger] closure::accepted(history@[p],r,load,validate) && closure::ids(r@).subset_of(known@) by {
            let pair = (p,history@[p]);
            assert(entries.to_set().contains(pair));
            let i = entries.index_of(pair);
            assert(entries[i] == pair);
            assert(closure::accepted(entries[i].1,sets[i],load,validate));
            assert forall|k:ObjectId| #[trigger] closure::ids(sets[i]@).contains(k) implies known@.contains(k) by {
                assert(closure::recorded(sets,k));
            }
            assert(closure::ids(sets[i]@).subset_of(known@));
        }
        assert forall|k:ObjectId| #[trigger] known@.contains(k) implies exists|p:P,r:Vec<(ObjectId,R)>|
            history@.contains_key(p) && #[trigger] closure::accepted(history@[p],r,load,validate) && closure::ids(r@).contains(k) by {
            assert(closure::recorded(sets,k));
            let i = choose|i:int| 0 <= i < sets.len() && #[trigger] closure::ids(sets[i]@).contains(k);
            let (p,entry) = entries[i];
            assert(entries.to_set().contains((p,entry)));
            assert(history@.contains_key(p) && history@[p] == entry);
            assert(closure::accepted(entry,sets[i],load,validate));
        }
    }
    Ok(known)
}

}
