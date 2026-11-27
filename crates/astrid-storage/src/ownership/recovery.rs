//! Replay every loaded deletion against one stable directory before publishing authority.
use super::{pending, recovery_aliases};
use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_eq::obeys_concrete_eq,
    pervasive::{cloned, obeys_clone_eq},
    std_specs::{
        btree::{btree_map_wf, key_obeys_cmp_spec},
        hash::{hash_map_inv, obeys_key_model},
        iter::IteratorSpec,
    },
};

verus! {
/// Startup's paired capability and allowance stores.
pub trait RetirementSink<A> {
    /// Failure returned to startup when a store cannot restore authority.
    type Error;
    #[cfg(verus_keep_ghost)]
    type Bucket;
    spec fn valid(&self) -> bool;
    spec fn failure(&self) -> Option<Self::Error>;
    spec fn authority(&self, alias: A) -> (bool,bool,Option<Self::Bucket>);

    /// Close both fences and remove the grant bucket belonging to this alias.
    ///
    /// # Errors
    ///
    /// Propagates a store error so startup can discard the unpublished state.
    fn restore(&mut self, alias: A) -> (result: Result<(),Self::Error>)
        requires old(self).valid(), old(self).failure().is_none(),
        ensures final(self).valid(), final(self).failure() == (match result { Ok(()) => None, Err(e) => Some(e) }),
            result.is_ok() ==> forall|key:A| #[trigger] final(self).authority(key)
                == if key == alias { (true,true,None) } else { old(self).authority(key) };
}

pub(super) open spec fn names<K,A>(uid: K, retained: Option<A>, directory: Map<K,A>, probe: A) -> bool {
    retained == Some(probe) || directory.get(uid) == Some(probe)
}

spec fn remaining<K,A,F>(rows: Seq<(&K,&pending::Reservation<A,F>)>, directory: Map<K,A>, probe: A) -> bool {
    exists|r: (&K,&pending::Reservation<A,F>)| #[trigger] rows.contains(r) && names(*r.0,r.1.alias,directory,probe)
}

proof fn split<K,A,F>(rows: Seq<(&K,&pending::Reservation<A,F>)>, directory: Map<K,A>, probe: A)
    requires rows.len() > 0,
    ensures remaining(rows,directory,probe) == (names(*rows[0].0,rows[0].1.alias,directory,probe)
        || remaining(rows.drop_first(),directory,probe)),
{
    assert forall|r: (&K,&pending::Reservation<A,F>)| #[trigger] rows.contains(r) == (rows[0] == r || rows.drop_first().contains(r)) by {
        if rows.contains(r) {
            let i = rows.index_of(r);
            if i > 0 { assert(rows.drop_first()[i-1] == r); }
        }
        if rows.drop_first().contains(r) {
            let i = rows.drop_first().index_of(r);
            assert(rows[i+1] == r);
        }
    }
    if remaining(rows,directory,probe) {
        let r = choose|r: (&K,&pending::Reservation<A,F>)| rows.contains(r) && names(*r.0,r.1.alias,directory,probe);
        if r != rows[0] { assert(rows.drop_first().contains(r)); assert(remaining(rows.drop_first(),directory,probe)); }
    }
    if remaining(rows.drop_first(),directory,probe) {
        let r = choose|r: (&K,&pending::Reservation<A,F>)| rows.drop_first().contains(r) && names(*r.0,r.1.alias,directory,probe);
        assert(rows.contains(r));
    }
    assert(rows.contains(rows[0]));
}

pub(super) fn replay<K: Copy + Ord + Hash,A: Eq + Clone,F,S: RetirementSink<A>>(
    reservations: &BTreeMap<K,pending::Reservation<A,F>>, directory: &HashMap<K,A>, sink: &mut S,
) -> (result: Result<(),S::Error>)
    requires old(sink).valid(), old(sink).failure().is_none(), key_obeys_cmp_spec::<K>(), btree_map_wf(reservations),
        hash_map_inv(directory), obeys_key_model::<K>(), obeys_concrete_eq::<K>(), obeys_concrete_eq::<A>(), obeys_clone_eq::<A>(),
    ensures final(sink).valid(), final(sink).failure() == (match result { Ok(()) => None, Err(e) => Some(e) }),
        result.is_ok() ==> forall|key:A| #[trigger] final(sink).authority(key) ==
            if exists|uid:K| #[trigger] reservations@.contains_key(uid) && names(uid,reservations@[uid].alias,directory@,key)
            { (true,true,None) } else { old(sink).authority(key) },
{
    let mut cursor = pending::scan(reservations);
    let ghost initial = cursor.remaining();
    let ghost expected = |key:A| if remaining(initial,directory@,key) { (true,true,None) } else { old(sink).authority(key) };
    assert forall|key:A| remaining(initial,directory@,key) == (exists|uid:K| #[trigger] reservations@.contains_key(uid) && names(uid,reservations@[uid].alias,directory@,key)) by {
        if remaining(initial,directory@,key) {
            let r = choose|r: (&K,&pending::Reservation<A,F>)| initial.contains(r) && names(*r.0,r.1.alias,directory@,key);
            assert(reservations@.get(*r.0) == Some(*r.1));
        } else if exists|uid:K| #[trigger] reservations@.contains_key(uid) && names(uid,reservations@[uid].alias,directory@,key) {
            let k = choose|uid:K| reservations@.contains_key(uid) && names(uid,reservations@[uid].alias,directory@,key);
            assert(initial.contains((&k,&reservations@[k])));
        }
    }
    loop
        invariant sink.valid(), sink.failure().is_none(), cursor.decrease().is_some(), hash_map_inv(directory),
            obeys_key_model::<K>(), obeys_concrete_eq::<K>(), obeys_concrete_eq::<A>(), obeys_clone_eq::<A>(),
            forall|key:A| #[trigger] expected(key) == if exists|uid:K| #[trigger] reservations@.contains_key(uid) && names(uid,reservations@[uid].alias,directory@,key) { (true,true,None) } else { old(sink).authority(key) },
            forall|key:A| (if remaining(cursor.remaining(),directory@,key) { (true,true,None) } else { sink.authority(key) }) == #[trigger] expected(key),
        decreases cursor.decrease().unwrap(),
    {
        let ghost prior = cursor.remaining();
        let Some((uid,retained)) = pending::next(&mut cursor) else {
            assert forall|key:A| !remaining(prior,directory@,key) by {};
            assert forall|key:A| #[trigger] sink.authority(key) == expected(key) by {};
            return Ok(());
        };
        assert forall|key:A| remaining(prior,directory@,key) == (names(uid,prior[0].1.alias,directory@,key) || remaining(cursor.remaining(),directory@,key)) by {
            split(prior,directory@,key);
        }
        let retained = match retained {
            None => None,
            Some(alias) => {
                proof { reveal(obeys_clone_eq); }
                let owned = A::clone(alias);
                assert(cloned(*alias,owned));
                Some(owned)
            },
        };
        let [first, second] = recovery_aliases(directory,&uid,retained);
        if let Some(alias) = first { sink.restore(alias)?; }
        if let Some(alias) = second { sink.restore(alias)?; }
    }
}
}
