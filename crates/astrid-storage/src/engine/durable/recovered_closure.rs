//! Admit recovered object IDs only after validating the loaded records for the same journal root.
use super::{ObjectId, RootState};
use std::collections::{BTreeMap, BTreeSet};
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_cmp::{obeys_cmp, obeys_cmp_concrete_eq},
    std_specs::{
        btree::{btree_map_inv, btree_set_inv},
        iter::IteratorSpec,
    },
};

verus! {
pub(super) open spec fn ids<K,R>(rows:Seq<(K,R)>) -> Set<K> {
    rows.map(|i:int,row:(K,R)| row.0).to_set()
}

proof fn membership<K,R>(rows:Seq<(K,R)>,k:K)
    ensures ids(rows).contains(k) == (exists|i:int| 0 <= i < rows.len() && #[trigger] rows[i].0 == k),
{
    let keys = rows.map(|i:int,row:(K,R)| row.0);
    if keys.contains(k) {
        let i = keys.index_of(k);
        assert(rows[i].0 == k);
    } else if exists|i:int| 0 <= i < rows.len() && #[trigger] rows[i].0 == k {
        let i = choose|i:int| 0 <= i < rows.len() && #[trigger] rows[i].0 == k;
        assert(keys[i] == k);
    }
}

pub(super) fn check<K:Ord+Copy,R,E,L,V>(known:&mut BTreeSet<K>,commit:K,offset:u64,load:L,validate:V) -> (out:Result<(),E>)
    where L:FnOnce(K,u64)->Result<Vec<(K,R)>,E>,V:FnOnce(&Vec<(K,R)>,K,u64)->Result<(),E>,
    requires btree_set_inv(old(known)),obeys_cmp::<K>(),obeys_cmp_concrete_eq::<K>(),
        load.requires((commit,offset)),
        forall|rows:Vec<(K,R)>| #[trigger] load.ensures((commit,offset),Ok(rows)) ==> validate.requires((&rows,commit,offset)),
    ensures btree_set_inv(final(known)), match out {
        Ok(()) => exists|rows:Vec<(K,R)>| #[trigger] load.ensures((commit,offset),Ok(rows)) &&
            validate.ensures((&rows,commit,offset),Ok(())) && final(known)@ == old(known)@.union(ids(rows@)),
        Err(e) => final(known)@ == old(known)@ && (load.ensures((commit,offset),Err(e)) ||
            exists|rows:Vec<(K,R)>| #[trigger] load.ensures((commit,offset),Ok(rows)) && validate.ensures((&rows,commit,offset),Err(e))),
    },
{
    let rows = load(commit,offset)?;
    validate(&rows,commit,offset)?;
    let mut iter = rows.into_iter();
    let ghost mut n = 0int;
    loop
        invariant 0 <= n <= rows.len(), iter.remaining() == rows@.skip(n),
            btree_set_inv(known),obeys_cmp::<K>(),obeys_cmp_concrete_eq::<K>(),
            known@ == old(known)@.union(ids(rows@.take(n))),
        ensures n == rows.len(),btree_set_inv(known),known@ == old(known)@.union(ids(rows@.take(n))),
        decreases rows.len() - n,
    {
        let Some((id,_)) = iter.next() else {assert(n == rows.len());break;};
        assert(id == rows@[n].0);
        known.insert(id);
        proof {
            assert forall|k:K| ids(rows@.take(n+1)).contains(k) == ids(rows@.take(n)).insert(id).contains(k) by {
                membership(rows@.take(n+1),k); membership(rows@.take(n),k);
                if ids(rows@.take(n+1)).contains(k) {
                    let i = choose|i:int| 0 <= i < n+1 && #[trigger] rows@.take(n+1)[i].0 == k;
                    if i < n {assert(rows@.take(n)[i].0 == k);}
                } else if ids(rows@.take(n)).contains(k) {
                    let i = choose|i:int| 0 <= i < n && #[trigger] rows@.take(n)[i].0 == k;
                    assert(rows@.take(n+1)[i].0 == k);
                } else {assert(rows@.take(n+1)[n].0 == id);}
            }
            assert(ids(rows@.take(n+1)) =~= ids(rows@.take(n)).insert(id));
            assert(known@ =~= old(known)@.union(ids(rows@.take(n+1))));
            assert(iter.remaining() =~= rows@.skip(n+1));
            n = n+1;
        };
    }
    assert(rows@.take(n) =~= rows@);
    Ok(())
}
#[cfg(verus_keep_ghost)]
type JournalRow<P> = (P,(RootState,u64));
type Records<R> = Vec<(ObjectId,R)>;

pub(super) open spec fn accepted<R,E,L:Fn(ObjectId,u64)->Result<Records<R>,E>,V:Fn(&Records<R>,ObjectId,u64)->Result<(),E>>(
    entry:(RootState,u64),rows:Records<R>,load:L,validate:V) -> bool {
    load.ensures((entry.0.commit,entry.1),Ok(rows)) && validate.ensures((&rows,entry.0.commit,entry.1),Ok(()))
}

pub(super) open spec fn recorded<R>(sets:Seq<Records<R>>,k:ObjectId) -> bool {
    exists|i:int| 0 <= i < sets.len() && #[trigger] ids(sets[i]@).contains(k)
}

pub(super) open spec fn complete<P,R,E,L:Fn(ObjectId,u64)->Result<Records<R>,E>,V:Fn(&Records<R>,ObjectId,u64)->Result<(),E>>(
    entries:Seq<JournalRow<P>>,sets:Seq<Records<R>>,known:Set<ObjectId>,load:L,validate:V) -> bool {
    &&& entries.len() == sets.len()
    &&& forall|i:int| 0 <= i < entries.len() ==> #[trigger] accepted(entries[i].1,sets[i],load,validate)
    &&& forall|k:ObjectId| known.contains(k) == #[trigger] recorded(sets,k)
}

/// Iterate the recovered map itself, stopping on the first failed root.
pub(super) fn check_all<P:Ord,R,E,L,V>(history:&BTreeMap<P,(RootState,u64)>,load:L,validate:V)
    -> (out:Result<BTreeSet<ObjectId>,E>)
    where L:Fn(ObjectId,u64)->Result<Records<R>,E>,V:Fn(&Records<R>,ObjectId,u64)->Result<(),E>,
    requires btree_map_inv(history),obeys_cmp::<P>(),obeys_cmp_concrete_eq::<P>(),
        obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
        forall|k:ObjectId,at:u64| #[trigger] load.requires((k,at)),
        forall|r:Records<R>,k:ObjectId,at:u64| #[trigger] validate.requires((&r,k,at)),
    ensures match out {
        Ok(known) => btree_set_inv(&known) && exists|entries:Seq<JournalRow<P>>,sets:Seq<Records<R>>|
            entries.to_set() == history@.kv_pairs() && entries.len() == history.len() &&
            #[trigger] complete(entries,sets,known@,load,validate),
        Err(e) => exists|p:P| #[trigger] history@.contains_key(p) && ({
            let (root,at) = history@[p];
            load.ensures((root.commit,at),Err(e)) || exists|r:Records<R>| #[trigger] load.ensures((root.commit,at),Ok(r)) &&
                validate.ensures((&r,root.commit,at),Err(e))
        }),
    },
{
    let mut known = BTreeSet::new();
    let mut it = history.iter();
    let ghost all = it.remaining();
    let ghost mut sets = Seq::<Records<R>>::empty();
    loop
        invariant forall|k:ObjectId,at:u64| #[trigger] load.requires((k,at)),
            forall|r:Records<R>,k:ObjectId,at:u64| #[trigger] validate.requires((&r,k,at)),
            all.len() == history.len(), all.unref().to_set() == history@.kv_pairs(),
            sets.len() <= all.len(),it.remaining() == all.skip(sets.len() as int),
            complete(all.unref().take(sets.len() as int),sets,known@,load,validate),
            btree_set_inv(&known),obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
        ensures all.unref().to_set() == history@.kv_pairs(),all.unref().len() == history.len(),sets.len() == all.len(),btree_set_inv(&known),complete(all.unref(),sets,known@,load,validate),
        decreases history.len() - sets.len(),
    {
        let ghost n = sets.len() as int;
        let Some((_owner,entry)) = it.next() else {
            assert(n == all.len());assert(all.unref().take(n) =~= all.unref());break;
        };
        let (root,at) = *entry;
        assert(all.unref()[n] == (*_owner,*entry));
        assert(history@.kv_pairs().contains((*_owner,*entry)));
        let ghost before = known@;
        let read = |k:ObjectId,a:u64| -> (v:Result<Records<R>,E>) ensures load.ensures((k,a),v), {load(k,a)};
        let verify = |r:&Records<R>,k:ObjectId,a:u64| -> (v:Result<(),E>) ensures validate.ensures((r,k,a),v), {validate(r,k,a)};
        if let Err(e) = check(&mut known,root.commit,at,read,verify) {
            proof {
                if !read.ensures((root.commit,at),Err(e)) {
                    let r = choose|r:Records<R>| #[trigger] read.ensures((root.commit,at),Ok(r)) && verify.ensures((&r,root.commit,at),Err(e));
                    assert(load.ensures((root.commit,at),Ok(r)) && validate.ensures((&r,root.commit,at),Err(e)));
                }
                assert(history@.contains_key(*_owner) && history@[*_owner] == *entry);
            }
            return Err(e);
        }
        proof {
            let r = choose|r:Records<R>| #[trigger] read.ensures((root.commit,at),Ok(r)) &&
                verify.ensures((&r,root.commit,at),Ok(())) && known@ == before.union(ids(r@));
            assert(accepted(*entry,r,load,validate));
            assert forall|i:int| 0 <= i < n+1 implies
                #[trigger] accepted(all.unref().take(n+1)[i].1,sets.push(r)[i],load,validate) by {
                if i < n {assert(accepted(all.unref().take(n)[i].1,sets[i],load,validate));}
            }
            assert forall|k:ObjectId| known@.contains(k) == #[trigger] recorded(sets.push(r),k) by {
                if recorded(sets.push(r),k) {
                    let i = choose|i:int| 0 <= i < n+1 && #[trigger] ids(sets.push(r)[i]@).contains(k);
                    if i < n {assert(ids(sets[i]@).contains(k));assert(recorded(sets,k));}
                } else if recorded(sets,k) {
                    let i = choose|i:int| 0 <= i < n && #[trigger] ids(sets[i]@).contains(k);
                    assert(ids(sets.push(r)[i]@).contains(k));
                } else {assert(sets.push(r)[n] == r);}
            }
            assert(it.remaining() =~= all.skip(n+1));
            sets = sets.push(r);
        };
    }
    assert(exists|entries:Seq<JournalRow<P>>,w:Seq<Records<R>>| entries.to_set() == history@.kv_pairs() &&
        entries.len() == history.len() && #[trigger] complete(entries,w,known@,load,validate));
    Ok(known)
}

}
