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
    spec fn history(&self) -> Seq<(A,Option<Self::Error>)>;
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
            final(self).history() == old(self).history().push((alias,final(self).failure())),
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

// The observable suffix ends at the first store error, even if that store
// partially updated its private state. Earlier attempts in this call succeeded.
pub(super) open spec fn stopped_at_first_error<A,E>(
    before: Seq<(A,Option<E>)>, after: Seq<(A,Option<E>)>, result: Result<(),E>,
) -> bool {
    &&& before.is_prefix_of(after)
    &&& match result {
        Ok(()) => forall|i:int| before.len() <= i < after.len() ==> #[trigger] after[i].1.is_none(),
        Err(error) => {
            &&& before.len() < after.len()
            &&& after.last().1 == Some(error)
            &&& forall|i:int| before.len() <= i < after.len() - 1 ==> #[trigger] after[i].1.is_none()
        }
    }
}

proof fn append_attempt<A,E>(before: Seq<(A,Option<E>)>, prior: Seq<(A,Option<E>)>, alias:A, result:Result<(),E>)
    requires stopped_at_first_error(before,prior,Ok(())),
    ensures stopped_at_first_error(before,prior.push((alias,match result { Ok(()) => None, Err(e) => Some(e) })),result),
{
    let after = prior.push((alias,match result { Ok(()) => None, Err(e) => Some(e) }));
    assert(before.is_prefix_of(after)) by {
        assert(before =~= after.take(before.len() as int));
    }
    assert forall|i:int| before.len() <= i < prior.len() implies #[trigger] after[i].1.is_none() by {
        assert(after[i] == prior[i]);
        assert(prior[i].1.is_none());
    }
    match result {
        Err(error) => { assert(after.last() == (alias,Some(error))); },
        Ok(()) => {
            assert forall|i:int| before.len() <= i < after.len() implies #[trigger] after[i].1.is_none() by {
                if i == prior.len() { assert(after[i] == (alias,None)); }
            }
        },
    }
}

pub(super) open spec fn reserved<K,A,F>(
    reservations: Map<K,pending::Reservation<A,F>>, directory: Map<K,A>, alias:A,
) -> bool {
    exists|uid:K| #[trigger] reservations.contains_key(uid) && names(uid,reservations[uid].alias,directory,alias)
}

pub(super) fn replay<K: Copy + Ord + Hash,A: Eq + Clone,F,S: RetirementSink<A>>(
    reservations: &BTreeMap<K,pending::Reservation<A,F>>, directory: &HashMap<K,A>, sink: &mut S,
) -> (result: Result<(),S::Error>)
    requires old(sink).valid(), old(sink).failure().is_none(), key_obeys_cmp_spec::<K>(), btree_map_wf(reservations),
        hash_map_inv(directory), obeys_key_model::<K>(), obeys_concrete_eq::<K>(), obeys_concrete_eq::<A>(), obeys_clone_eq::<A>(),
    ensures final(sink).valid(), final(sink).failure() == (match result { Ok(()) => None, Err(e) => Some(e) }),
        stopped_at_first_error(old(sink).history(),final(sink).history(),result),
        forall|i:int| old(sink).history().len() <= i < final(sink).history().len() ==>
            reserved(reservations@,directory@,#[trigger] final(sink).history()[i].0),
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
        invariant stopped_at_first_error(old(sink).history(),sink.history(),Ok(())),
            forall|i:int| old(sink).history().len() <= i < sink.history().len() ==>
                reserved(reservations@,directory@,#[trigger] sink.history()[i].0),
            forall|row:(&K,&pending::Reservation<A,F>)| #[trigger] cursor.remaining().contains(row) ==>
                reservations@.get(*row.0) == Some(*row.1),
            sink.valid(), sink.failure().is_none(), cursor.decrease().is_some(), hash_map_inv(directory),
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
        assert(prior.contains(prior[0]));
        assert(reservations@.get(uid) == Some(*prior[0].1));
        assert forall|row:(&K,&pending::Reservation<A,F>)| #[trigger] cursor.remaining().contains(row) implies prior.contains(row) by {
            let i = cursor.remaining().index_of(row);
            assert(prior[i+1] == row);
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
        if let Some(alias) = first {
            let ghost prior_calls = sink.history();
            let result = sink.restore(alias);
            proof { append_attempt(old(sink).history(),prior_calls,alias,result); }
            result?;
        }
        if let Some(alias) = second {
            let ghost prior_calls = sink.history();
            let result = sink.restore(alias);
            proof { append_attempt(old(sink).history(),prior_calls,alias,result); }
            result?;
        }
    }
}
}
