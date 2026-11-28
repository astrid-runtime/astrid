//! Canonical media must be stable before handing the scanned WAL to its continuation.
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
                &&& final(files).durable()[a] == old(files).pending()[a]
                &&& final(files).durable()[r] == old(files).pending()[r]
                &&& if old(files).has_representations() {
                    final(files).calls() == third && final(files).durable()[x] == old(files).pending()[x]
                } else {final(files).calls() == second && final(files).durable().get(x) == old(files).durable().get(x)}
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
