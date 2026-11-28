//! Validate a retirement reservation against the same snapshot's indexes.
use std::collections::BTreeMap;
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::std_specs::iter::IteratorSpec;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_cmp::{obeys_cmp, obeys_cmp_concrete_eq},
    std_specs::btree::btree_map_inv,
};

verus! {
pub(super) enum Error<'a,K,F> { Fleet(F), Owned(K), Alias(&'a str,K,K) }

pub(super) fn check<'a,K:Ord+Copy,F:Ord+Copy,O,V>(uid:K,fleet:Option<F>,alias:Option<&'a str>,
    owners:&BTreeMap<K,O>,fleets:&BTreeMap<F,V>,seen:&mut BTreeMap<&'a str,K>)
    -> (out:Result<(),Error<'a,K,F>>)
    requires btree_map_inv(owners),btree_map_inv(fleets),btree_map_inv(old(seen)),
        obeys_cmp::<K>(),obeys_cmp_concrete_eq::<K>(),obeys_cmp::<F>(),obeys_cmp_concrete_eq::<F>(),
        obeys_cmp::<&str>(),obeys_cmp_concrete_eq::<&str>(),
    ensures btree_map_inv(final(seen)),
        if fleet matches Some(f) && !fleets@.contains_key(f) {
            out == Err(Error::Fleet(fleet.unwrap())) && final(seen)@ == old(seen)@
        } else if owners@.contains_key(uid) {
            out == Err(Error::Owned(uid)) && final(seen)@ == old(seen)@
        } else {match alias {
            None => out == Ok(()) && final(seen)@ == old(seen)@,
            Some(name) => final(seen)@ == old(seen)@.insert(name,uid) &&
                out == if old(seen)@.contains_key(name) {Err(Error::Alias(name,old(seen)@[name],uid))} else {Ok(())},
        }},
{
    match fleet {Some(f) if !fleets.contains_key(&f) => return Err(Error::Fleet(f)), _ => {}}
    if owners.contains_key(&uid) {return Err(Error::Owned(uid));}
    let Some(name) = alias else {return Ok(());};
    if let Some(other) = seen.insert(name,uid) {return Err(Error::Alias(name,other,uid));}
    Ok(())
}
pub(super) open spec fn projected<'a,A:'a,F,N:Fn(&'a A)->&'a str>(row:super::pending::Reservation<A,F>,name:N) -> Option<&'a str> {
    match row.alias {None => None,Some(a) => Some(choose|n:&'a str| name.ensures((&a,),n))}
}
pub(super) open spec fn named<'a,K,A:'a,F,N:Fn(&'a A)->&'a str>(rows:Map<K,super::pending::Reservation<A,F>>,
    k:K,n:&'a str,name:N) -> bool {
    rows.contains_key(k) && projected(rows[k],name) == Some(n)
}
pub(super) fn validate<'a,K:Ord+Copy,A:'a,F:Ord+Copy,O,V,N:Fn(&'a A)->&'a str+Copy>(
    rows:&'a BTreeMap<K,super::pending::Reservation<A,F>>,owners:&BTreeMap<K,O>,fleets:&BTreeMap<F,V>,name:N)
    -> (out:Result<(),Error<'a,K,F>>)
    requires btree_map_inv(rows),btree_map_inv(owners),btree_map_inv(fleets),
        obeys_cmp::<K>(),obeys_cmp_concrete_eq::<K>(),obeys_cmp::<F>(),obeys_cmp_concrete_eq::<F>(),
        obeys_cmp::<&str>(),obeys_cmp_concrete_eq::<&str>(),
        forall|a:&A| #[trigger] name.requires((a,)),
        forall|a:&A,n:&str,m:&str| #[trigger] name.ensures((a,),n) && #[trigger] name.ensures((a,),m) ==> n == m,
    ensures match out {
        Ok(()) => (forall|k:K| #[trigger] rows@.contains_key(k) ==> !owners@.contains_key(k) &&
            (rows@[k].fleet matches Some(f) ==> fleets@.contains_key(f))) &&
            (forall|i:K,j:K,n:&str| #[trigger] named(rows@,i,n,name) && #[trigger] named(rows@,j,n,name) ==> i==j),
        Err(Error::Fleet(f)) => !fleets@.contains_key(f) && exists|k:K| #[trigger] rows@.contains_key(k) && rows@[k].fleet == Some(f),
        Err(Error::Owned(k)) => rows@.contains_key(k) && owners@.contains_key(k),
        Err(Error::Alias(n,i,j)) => i!=j && named(rows@,i,n,name) && named(rows@,j,n,name),
    },
{

    let mut cursor = super::pending::scan(rows);
    let ghost all = cursor.remaining();
    let ghost mut i:int = 0;
    let mut seen = BTreeMap::new();
    loop
        invariant cursor.decrease().is_some(), 0 <= i <= all.len(), all.no_duplicates(),cursor.remaining() == all.skip(i),
            forall|k:K,r:super::pending::Reservation<A,F>| #[trigger] all.contains((&k,&r)) == (rows@.get(k) == Some(r)),
            btree_map_inv(&seen),btree_map_inv(owners),btree_map_inv(fleets),
            obeys_cmp::<K>(),obeys_cmp_concrete_eq::<K>(),obeys_cmp::<F>(),obeys_cmp_concrete_eq::<F>(),
            obeys_cmp::<&str>(),obeys_cmp_concrete_eq::<&str>(),
            forall|a:&A| #[trigger] name.requires((a,)),
            forall|a:&A,n:&str,m:&str| #[trigger] name.ensures((a,),n) && #[trigger] name.ensures((a,),m) ==> n == m,
            forall|j:int| 0 <= j < i ==> !owners@.contains_key(*all[j].0) &&
                (all[j].1.fleet matches Some(f) ==> fleets@.contains_key(f)) &&
                (projected(*(#[trigger] all[j]).1,name) matches Some(n) ==> seen@.get(n) == Some(*all[j].0)),
            forall|n:&str| #[trigger] seen@.contains_key(n) ==> exists|j:int| 0 <= j < i && *all[j].0 == seen@[n] &&
                projected(*(#[trigger] all[j]).1,name) == Some(n),
        decreases cursor.decrease().unwrap(),
    {
        let ghost before = cursor.remaining();
        let Some((uid,row)) = cursor.next() else {
            assert(i==all.len());
            assert forall|k:K| #[trigger] rows@.contains_key(k) implies !owners@.contains_key(k) &&
                (rows@[k].fleet matches Some(f) ==> fleets@.contains_key(f)) by {
                let r=(&k,&rows@[k]);assert(all.contains(r));let j=all.index_of(r);assert(all[j]==r);
            }
            assert forall|a:K,b:K,n:&str| #[trigger] named(rows@,a,n,name) && #[trigger] named(rows@,b,n,name) implies a==b by {
                let x=(&a,&rows@[a]);let y=(&b,&rows@[b]);assert(all.contains(x) && all.contains(y));
                assert(all[all.index_of(x)]==x && all[all.index_of(y)]==y);
            }
            return Ok(());
        };
        assert(before[0] == all[i] && all.contains(all[i]));
        assert(rows@.get(*uid) == Some(*row));
        let alias = row.alias.as_ref().map(name);
        assert(alias == projected(*row,name));
        let ghost old_seen = seen@;
        let res = check(*uid,row.fleet,alias,owners,fleets,&mut seen);
        if let Err(e) = res {
            proof {
                if let Error::Alias(n,k,_) = e {
                    assert(old_seen.contains_key(n) && old_seen[n]==k);
                    let j=choose|j:int| 0<=j<i && *all[j].0==old_seen[n] && projected(*(#[trigger] all[j]).1,name)==Some(n);
                    assert(0<=j<i);
                    assert(all.contains(all[j]));
                    assert(rows@.get(*all[j].0)==Some(*all[j].1));
                    assert(all.contains(all[j]) && rows@.get(k)==Some(*all[j].1));
                    if k==*uid {assert(all[j]==all[i]);assert(false);}
                }
            }
            return Err(e);
        }
        proof {
            assert(cursor.remaining() =~= all.skip(i+1));
            assert forall|n:&str| #[trigger] seen@.contains_key(n) implies exists|j:int| 0<=j<i+1 && *all[j].0==seen@[n] &&
                projected(*(#[trigger] all[j]).1,name)==Some(n) by {
                if alias == Some(n) {assert(*all[i].0==seen@[n]);}
                else {let j=choose|j:int| 0<=j<i && *all[j].0==old_seen[n] && projected(*all[j].1,name)==Some(n);
                    assert(*all[j].0==seen@[n]);}
            }
            i=i+1;
        };
    }
}

}
