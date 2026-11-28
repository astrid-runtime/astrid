//! Lazy enumeration of the reservations in one immutable ownership snapshot.
use std::collections::{BTreeMap, btree_map::Iter};
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::std_specs::{
    btree::{btree_map_wf, key_obeys_cmp_spec},
    iter::IteratorSpec,
};

verus! {
#[cfg_attr(not(verus_keep_ghost), derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize))]
#[cfg_attr(not(verus_keep_ghost), serde(rename = "PrincipalDeletionReservation", deny_unknown_fields, bound(deserialize = "A: serde::Deserialize<'de>, F: serde::Deserialize<'de>")))]
pub(super) struct Reservation<A,F> {
    pub(super) alias: Option<A>,
    #[cfg_attr(not(verus_keep_ghost), serde(default, skip_serializing_if = "Option::is_none"))]
    pub(super) fleet: Option<F>,
}

pub(super) enum ReserveError<A,E> { Conflict(A), Admission(E) }

/// Stage a reservation in the candidate graph submitted to ownership CAS.
/// An existing reservation keeps its original fleet and any retained alias.
pub(super) fn reserve<K:Ord+Copy,A:Eq+Clone,F:Copy,E,C>(
    rows:&mut BTreeMap<K,Reservation<A,F>>,uid:K,requested:Option<&A>,fleet:Option<F>,admit:C,
) -> (out:Result<(),ReserveError<A,E>>)
    where C:FnOnce(&BTreeMap<K,Reservation<A,F>>)->Result<(),E>,
    requires vstd::std_specs::btree::btree_map_inv(old(rows)),
        vstd::laws_cmp::obeys_cmp::<K>(),vstd::laws_cmp::obeys_cmp_concrete_eq::<K>(),
        vstd::laws_eq::obeys_concrete_eq::<A>(),vstd::pervasive::obeys_clone_eq::<A>(),
        !old(rows)@.contains_key(uid) ==> admit.requires((&*old(rows),)),
    ensures vstd::std_specs::btree::btree_map_inv(final(rows)),
        out.is_err() ==> final(rows)@ == old(rows)@,
        match out {
            Ok(()) => {
                let alias = match requested {Some(a) => Some(*a),None => None};
                let before = old(rows)@.get(uid);
                &&& final(rows)@ == old(rows)@.insert(uid,match before {
                    Some(r) => Reservation {alias:if r.alias.is_some() {r.alias} else {alias},fleet:r.fleet},
                    None => Reservation {alias,fleet},
                })
                &&& before matches Some(r) ==> !(r.alias matches Some(a) && (alias matches Some(b) && a != b))
                &&& before.is_none() ==> exists|r:Result<(),E>| #[trigger] admit.ensures((&*old(rows),),r) && r.is_ok()
            },
            Err(ReserveError::Conflict(a)) => old(rows)@.contains_key(uid) &&
                old(rows)@[uid].alias == Some(a) && (requested matches Some(b) && a != *b),
            Err(ReserveError::Admission(e)) => !old(rows)@.contains_key(uid) && admit.ensures((&*old(rows),),Err(e)),
        },
{
    proof {reveal(vstd::pervasive::obeys_clone_eq); reveal(vstd::laws_eq::obeys_concrete_eq);}
    if let Some(reservation) = rows.get(&uid) {
        match (&reservation.alias, requested) {
            (Some(existing),Some(alias)) if *existing != *alias => {
                let conflict = existing.clone();
                assert(vstd::pervasive::cloned(*existing,conflict));
                assert(*existing != *alias);
                return Err(ReserveError::Conflict(conflict));
            },
            (None,Some(alias)) => {
                let retained = alias.clone();
                assert(vstd::pervasive::cloned(*alias,retained));
                rows.insert(uid,Reservation {alias:Some(retained),fleet:reservation.fleet});
            },
            _ => {assert(rows@ =~= old(rows)@.insert(uid,*reservation));},
        }
    } else {
        let approval = admit(rows);
        if let Err(e) = approval {return Err(ReserveError::Admission(e));}
        assert(approval.is_ok());
        assert(admit.ensures((&*old(rows),),approval));
        let alias = match requested {Some(a) => {let retained = a.clone();assert(vstd::pervasive::cloned(*a,retained));Some(retained)},None => None};
        rows.insert(uid,Reservation {alias,fleet});
    }
    Ok(())
}

pub(super) fn scan<K: Ord,V>(map: &BTreeMap<K,V>) -> (cursor: Iter<'_,K,V>)
    requires key_obeys_cmp_spec::<K>(), btree_map_wf(map),
    ensures cursor.decrease().is_some(), cursor.remaining().len() == map@.dom().len(),
        cursor.remaining().no_duplicates(),
        forall|k: K, v: V| #[trigger] cursor.remaining().contains((&k,&v)) == (map@.get(k) == Some(v)),
{
    let cursor = map.iter();
    assert forall|k: K, v: V| #[trigger] cursor.remaining().contains((&k,&v)) == (map@.get(k) == Some(v)) by {
        if cursor.remaining().contains((&k,&v)) {
            let i = cursor.remaining().index_of((&k,&v));
            assert(cursor.remaining()[i] == (&k,&v));
            assert(map@.contains_key(*cursor.remaining()[i].0));
            assert(map@[*cursor.remaining()[i].0] == *cursor.remaining()[i].1);
        }
    }
    cursor
}

pub(super) fn next<'a,K: Copy,A,F>(
    cursor: &mut Iter<'a,K,Reservation<A,F>>,
) -> (out: Option<(K,Option<&'a A>)>)
    requires (*old(cursor)).decrease().is_some(),
    ensures ({
        let before = (*old(cursor)).remaining();
        if before.len() == 0 {
            out.is_none() && (*final(cursor)).remaining() == before
        } else {
            &&& (*final(cursor)).decrease().is_some()
            &&& (*final(cursor)).decrease().unwrap() < (*old(cursor)).decrease().unwrap()
            &&& (*final(cursor)).remaining() == before.drop_first()
            &&& out matches Some((key,name)) && key == *before[0].0 && name == match before[0].1.alias { Some(a) => Some(&a), None => None }
        }
    }),
{
    let (uid,value) = cursor.next()?;
    Some((*uid,value.alias.as_ref()))
}
}
