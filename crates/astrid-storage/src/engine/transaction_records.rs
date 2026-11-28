//! Immutable object declarations retained in a transaction.
use super::ObjectId;
use std::collections::BTreeMap;
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_cmp::{obeys_cmp, obeys_cmp_concrete_eq},
    laws_eq::obeys_concrete_eq,
    std_specs::{btree::btree_map_inv, iter::IteratorSpec},
};

verus! {

/// Compute a declaration before moving the same record into staging.
pub(crate) fn identify<K,R,F>(record:R,derive_id:F) -> (row:(K,R))
    where F:FnOnce(&R)->K,
    requires derive_id.requires((&record,)),
    ensures row.1 == record && derive_id.ensures((&row.1,),row.0),
{
    let id = derive_id(&record);
    (id,record)
}

/// Check the digest computed over this exact record before it enters an
/// externally supplied transaction or restore snapshot.
pub(crate) fn check_identity<R,F>(declared:ObjectId,record:&R,identify:&F)
    -> (out:Result<(),(ObjectId,ObjectId)>)
    where F:Fn(&R)->ObjectId,
    requires identify.requires((record,)),
    ensures match out {
        Ok(()) => exists|computed:ObjectId| #[trigger] identify.ensures((record,),computed) && computed.digest() == declared.digest(),
        Err((name,computed)) => name == declared && identify.ensures((record,),computed) && computed.digest() != declared.digest(),
    },
{
    let computed = identify(record);
    if computed.as_bytes().as_slice() == declared.as_bytes().as_slice() {Ok(())}
    else {Err((declared,computed))}
}

pub(crate) open spec fn authentic<R,F:Fn(&R)->ObjectId>(row:(ObjectId,R),identify:F) -> bool {
    exists|computed:ObjectId| #[trigger] identify.ensures((&row.1,),computed) && computed.digest() == row.0.digest()
}

/// Preserve the first mismatched declaration and check every earlier row.
pub(crate) fn check_transaction<R,F>(records:&[(ObjectId,R)],identify:F)
    -> (out:Result<(),(ObjectId,ObjectId)>)
    where F:Fn(&R)->ObjectId,
    requires forall|r:&R| #[trigger] identify.requires((r,)),
    ensures match out {
        Ok(()) => forall|i:int| 0 <= i < records.len() ==> #[trigger] authentic(records@[i],identify),
        Err((name,computed)) => exists|i:int| 0 <= i < records.len() && name == records@[i].0 &&
            #[trigger] identify.ensures((&records@[i].1,),computed) && computed.digest() != name.digest() &&
            forall|j:int| 0 <= j < i ==> #[trigger] authentic(records@[j],identify),
    },
{
    let mut i = 0;
    while i < records.len()
        invariant i <= records.len(),
            forall|r:&R| #[trigger] identify.requires((r,)),
            forall|j:int| 0 <= j < i ==> #[trigger] authentic(records@[j],identify),
        decreases records.len()-i,
    {
        let row = &records[i];
        if let Err((name,computed)) = check_identity(row.0,&row.1,&identify) {
            assert(identify.ensures((&records@[i as int].1,),computed));
            return Err((name,computed));
        }
        i = i.saturating_add(1);
    }
    Ok(())
}

/// Process-local evidence retained by an engine-built transaction.
#[derive(Debug)]
pub(crate) enum IdentityProof<A> { Untrusted, Engine(A) }

pub(crate) enum Admission { SameEngine, Rechecked }

impl Admission {
    /// A projection can be published only by the engine that prepared it.
    pub(crate) fn take_checkpoint<C>(self,value:&mut Option<C>) -> (out:Option<C>)
        ensures if self is SameEngine {out == *old(value) && final(value).is_none()} else {out.is_none() && *final(value) == *old(value)},
    {
        match self {Self::SameEngine => value.take(),Self::Rechecked => None}
    }
}

impl<A> IdentityProof<A> {
    pub(crate) open spec fn compared<F:Fn(&A,&A)->bool>(&self,current:&A,same:F,result:bool) -> bool {
        match self {Self::Untrusted => !result,Self::Engine(bound) => same.ensures((bound,current),result)}
    }

    pub(crate) fn admit<R,F:Fn(&A,&A)->bool,H:Fn(&R)->ObjectId>(&self,current:&A,same:F,rows:&[(ObjectId,R)],identify:H)
        -> (out:Result<Admission,(ObjectId,ObjectId)>)
        requires forall|bound:&A| #[trigger] same.requires((bound,current)),
            forall|r:&R| #[trigger] identify.requires((r,)),
        ensures match out {
            Ok(Admission::SameEngine) => self.compared(current,same,true),
            Ok(Admission::Rechecked) => self.compared(current,same,false) &&
                forall|i:int| 0 <= i < rows.len() ==> #[trigger] authentic(rows@[i],identify),
            Err((name,computed)) => self.compared(current,same,false) &&
                exists|i:int| 0 <= i < rows.len() && name == rows@[i].0 &&
                    #[trigger] identify.ensures((&rows@[i].1,),computed) && name.digest() != computed.digest() &&
                    forall|j:int| 0 <= j < i ==> #[trigger] authentic(rows@[j],identify),
        },
    {
        let matches = match self {Self::Untrusted => false,Self::Engine(bound) => same(bound,current)};
        if matches {return Ok(Admission::SameEngine);}
        check_transaction(rows,identify)?;
        Ok(Admission::Rechecked)
    }
}

/// Keep the original value on repeated declarations. Divergent values under
/// the same key reject the transaction without changing the map.
pub(crate) fn insert<K:Ord+Copy,R:PartialEq>(map:&mut BTreeMap<K,R>,id:K,record:R)
    -> (out:Result<K,K>)
    requires obeys_cmp::<K>(),obeys_cmp_concrete_eq::<K>(),btree_map_inv(old(map)),obeys_concrete_eq::<R>(),
    ensures btree_map_inv(final(map)),
        if old(map)@.contains_key(id) {
            final(map)@ == old(map)@ && out == if old(map)@[id] == record {Ok(id)} else {Err(id)}
        } else {final(map)@ == old(map)@.insert(id,record) && out == Ok(id)},
{
    proof {reveal(obeys_concrete_eq);}
    match map.get(&id) {
        Some(existing) if existing == &record => Ok(id),
        Some(_) => Err(id),
        None => {map.insert(id,record); Ok(id)}
    }
}

/// Bind a newly built record to the engine's identity before inserting it.
pub(crate) fn stage<K:Ord+Copy,R:PartialEq,F:FnOnce(&R)->K>(map:&mut BTreeMap<K,R>,record:R,derive_id:F)
    -> (out:Result<K,K>)
    requires obeys_cmp::<K>(), obeys_cmp_concrete_eq::<K>(), btree_map_inv(old(map)), obeys_concrete_eq::<R>(),
        derive_id.requires((&record,)),
    ensures btree_map_inv(final(map)),
        match out {
            Ok(id) => derive_id.ensures((&record,),id) && final(map)@ == old(map)@.insert(id,record)
                && (!old(map)@.contains_key(id) || old(map)@[id] == record),
            Err(id) => derive_id.ensures((&record,),id) && final(map)@ == old(map)@
                && old(map)@.contains_key(id) && old(map)@[id] != record,
        },
{
    let (id,row) = identify(record,derive_id);
    let out = insert(map,id,row);
    proof { if out.is_ok() && old(map)@.contains_key(id) {
        assert(old(map)@.insert(id,record) =~= old(map)@);
    } }
    out
}

pub(crate) open spec fn represents<K,R>(map:Map<K,R>,rows:Seq<(K,R)>) -> bool {
    &&& forall|i:int| 0 <= i < rows.len() ==> map.contains_key(#[trigger] rows[i].0) && map[rows[i].0] == rows[i].1
    &&& forall|k:K| #[trigger] map.contains_key(k) ==> exists|i:int| 0 <= i < rows.len() && #[trigger] rows[i].0 == k
}

pub(crate) fn unique<K:Ord+Copy,R:PartialEq>(records:Vec<(K,R)>)
    -> (out:Result<BTreeMap<K,R>,K>)
    requires obeys_cmp::<K>(),obeys_cmp_concrete_eq::<K>(),obeys_concrete_eq::<R>(),
    ensures match out {
        Ok(map) => btree_map_inv(&map) && represents(map@,records@),
        Err(key) => exists|i:int,j:int| 0 <= i < j < records.len() &&
            #[trigger] records@[i].0 == key && #[trigger] records@[j].0 == key && records@[i].1 != records@[j].1,
    },
{
    let mut map = BTreeMap::new();
    let mut iter = records.into_iter();
    let ghost mut n:int = 0;
    loop
        invariant 0 <= n <= records.len(), iter.remaining() == records@.skip(n),
            btree_map_inv(&map), represents(map@,records@.take(n)),
            obeys_cmp::<K>(),obeys_cmp_concrete_eq::<K>(),obeys_concrete_eq::<R>(),
        decreases records.len() - n,
    {
        let Some((id,record)) = iter.next() else {
            assert(n == records.len());
            assert(records@.take(n) =~= records@);
            return Ok(map);
        };
        let ghost before = map@;
        assert((id,record) == records@[n]);
        if let Err(key) = insert(&mut map,id,record) {
            let ghost i = choose|i:int| 0 <= i < n && #[trigger] records@.take(n)[i].0 == key;
            assert(records@.take(n)[i] == records@[i]);
            assert(before[key] == records@[i].1);
            return Err(key);
        }
        proof {
            let prefix = records@.take(n+1);
            assert forall|i:int| 0 <= i < prefix.len() implies map@.contains_key(#[trigger] prefix[i].0) && map@[prefix[i].0] == prefix[i].1 by {
                if i < n {assert(prefix[i] == records@.take(n)[i]);}
            }
            assert forall|k:K| #[trigger] map@.contains_key(k) implies exists|i:int| 0 <= i < prefix.len() && #[trigger] prefix[i].0 == k by {
                if k == id {assert(prefix[n].0 == k);}
                else {
                    let i = choose|i:int| 0 <= i < n && #[trigger] records@.take(n)[i].0 == k;
                    assert(prefix[i] == records@.take(n)[i]);
                }
            }
            n = n+1;
        };
    }
}

}
