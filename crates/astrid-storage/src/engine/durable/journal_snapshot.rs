//! Seed replay history only after every compacted root has been accepted.
use super::RootState;
use std::collections::BTreeMap;
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_cmp::{obeys_cmp, obeys_cmp_concrete_eq},
    std_specs::{btree::btree_map_inv, iter::IteratorSpec},
};

verus! {
type Row = (Vec<u8>,RootState);
pub(super) enum SnapshotError<E> { Position, Noncanonical, Duplicate, Codec(E) }

pub(super) open spec fn decoded<P,E,D:Fn(&Vec<u8>)->Result<P,E>>(rows:Seq<Row>,ids:Seq<P>,decode:D) -> bool {
    forall|i:int| 0 <= i < ids.len() ==> #[trigger] decode.ensures((&rows[i].0,),Ok(ids[i]))
}
pub(super) open spec fn image<P>(rows:Seq<Row>,ids:Seq<P>,history:Map<P,(RootState,u64)>) -> bool {
    &&& ids.no_duplicates()
    &&& history.dom() == ids.to_set()
    &&& forall|i:int| 0 <= i < ids.len() ==> #[trigger] history.get(ids[i]) == Some((rows[i].1,0u64))
}

pub(super) fn restore<P:Ord,E,C,D>(history:&mut BTreeMap<P,(RootState,u64)>,offset:u64,payload:&[u8],
    rows:Vec<Row>,encode:C,decode:D) -> (out:Result<(),SnapshotError<E>>)
    where C:FnOnce(&Vec<Row>)->Result<Vec<u8>,E>, D:Fn(&Vec<u8>)->Result<P,E>,
    requires btree_map_inv(old(history)),obeys_cmp::<P>(),obeys_cmp_concrete_eq::<P>(),
        encode.requires((&rows,)),forall|i:int| 0 <= i < rows.len() ==> decode.requires((&rows@[i].0,)),
    ensures btree_map_inv(final(history)),out.is_err() ==> final(history)@ == old(history)@,
        (out matches Err(SnapshotError::Position)) == (offset != 0 || !old(history)@.is_empty()),
        match out {
            Ok(()) => (exists|wire:Vec<u8>| #[trigger] encode.ensures((&rows,),Ok(wire)) && wire@ == payload@) &&
                exists|ids:Seq<P>| ids.len() == rows.len() && decoded(rows@,ids,decode) && #[trigger] image(rows@,ids,final(history)@),
            Err(SnapshotError::Noncanonical) => exists|wire:Vec<u8>| #[trigger] encode.ensures((&rows,),Ok(wire)) && wire@ != payload@,
            Err(SnapshotError::Codec(e)) => encode.ensures((&rows,),Err(e)) ||
                exists|i:int| 0 <= i < rows.len() && #[trigger] decode.ensures((&rows@[i].0,),Err(e)),
            Err(SnapshotError::Duplicate) => exists|i:int,j:int,p:P| 0 <= i < j < rows.len() &&
                #[trigger] decode.ensures((&rows@[i].0,),Ok(p)) && #[trigger] decode.ensures((&rows@[j].0,),Ok(p)),
            Err(SnapshotError::Position) => true,
        },
{
    if offset != 0 || !history.is_empty() {return Err(SnapshotError::Position);}
    {
        let wire = match encode(&rows) {Ok(w) => w, Err(e) => return Err(SnapshotError::Codec(e))};
        if wire.as_slice() != payload {return Err(SnapshotError::Noncanonical);}
        assert(exists|w:Vec<u8>| #[trigger] encode.ensures((&rows,),Ok(w)) && w@ == payload@);
    }
    let mut restored = BTreeMap::new();
    let mut iter = rows.into_iter();
    let ghost mut ids = Seq::<P>::empty();
    assert(restored@.dom() =~= ids.to_set());
    loop
        invariant offset == 0, history@ == old(history)@, history@.is_empty(), btree_map_inv(history),
            exists|w:Vec<u8>| #[trigger] encode.ensures((&rows,),Ok(w)) && w@ == payload@,
            ids.len() <= rows.len(),iter.remaining() == rows@.skip(ids.len() as int),
            btree_map_inv(&restored),obeys_cmp::<P>(),obeys_cmp_concrete_eq::<P>(),
            decoded(rows@,ids,decode),image(rows@,ids,restored@),
            forall|i:int| 0 <= i < rows.len() ==> decode.requires((&rows@[i].0,)),
        ensures ids.len() == rows.len(), decoded(rows@,ids,decode), image(rows@,ids,restored@), btree_map_inv(&restored),
        decreases rows.len() - ids.len(),
    {
        let ghost n = ids.len() as int;
        let Some((name,root)) = iter.next() else {assert(ids.len() == rows.len()); break;};
        assert((name,root) == rows@[n]);
        assert(iter.remaining() =~= rows@.skip(n+1));
        let owner = match decode(&name) {Ok(p) => p, Err(e) => return Err(SnapshotError::Codec(e))};
        let ghost prior = restored@;
        if restored.insert(owner,(root,0)).is_some() {
            let ghost i = ids.index_of(owner);
            assert(decode.ensures((&rows@[i].0,),Ok(owner)));
            assert(decode.ensures((&rows@[n].0,),Ok(owner)));
            return Err(SnapshotError::Duplicate);
        }
        proof {
            assert forall|k:P| ids.push(owner).to_set().contains(k) == ids.to_set().insert(owner).contains(k) by {
                assert(ids.push(owner)[n] == owner);
                if ids.push(owner).contains(k) {
                    let i = ids.push(owner).index_of(k);
                    assert(ids.push(owner)[i] == k);
                    if i < n {assert(ids[i] == k);}
                } else if ids.contains(k) {let i = ids.index_of(k); assert(ids.push(owner)[i] == k);}
            }
            assert(ids.push(owner).to_set() =~= ids.to_set().insert(owner));
            assert(ids.push(owner).no_duplicates());
            assert forall|i:int| 0 <= i < n+1 implies #[trigger] restored@.get(ids.push(owner)[i]) == Some((rows@[i].1,0u64)) by {
                if i < n {assert(prior.get(ids[i]) == Some((rows@[i].1,0u64)));}
            }
            assert forall|i:int| 0 <= i < n+1 implies #[trigger] decode.ensures((&rows@[i].0,),Ok(ids.push(owner)[i])) by {
                if i < n {assert(decode.ensures((&rows@[i].0,),Ok(ids[i])));}
            }
            ids = ids.push(owner);
        };
    }
    *history = restored;
    assert(ids.len() == rows.len());
    assert(decoded(rows@,ids,decode));
    assert(image(rows@,ids,history@));
    assert(exists|xs:Seq<P>| xs.len() == rows.len() && decoded(rows@,xs,decode) && #[trigger] image(rows@,xs,history@));
    Ok(())
}
}
