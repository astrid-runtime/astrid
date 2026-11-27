//! Recover membership from every reservation in the loaded ownership snapshot.
use std::collections::{BTreeMap, HashMap, HashSet};
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::std_specs::{btree::btree_map_wf, hash::{hash_map_inv,hash_set_inv}, iter::IteratorSpec};

type Reservation = crate::pending_deletions::Reservation<u64,u64>;

verus! {
spec fn names(uid: u64, retained: Option<u64>, directory: Map<u64,u64>, probe: u64) -> bool {
    retained == Some(probe) || directory.get(uid) == Some(probe)
}

spec fn pending(rows: Seq<(&u64,&Reservation)>, directory: Map<u64,u64>, probe: u64) -> bool {
    exists|row: (&u64,&Reservation)| #[trigger] rows.contains(row) && names(*row.0,row.1.alias,directory,probe)
}

proof fn split(rows: Seq<(&u64,&Reservation)>, directory: Map<u64,u64>, probe: u64)
    requires rows.len() > 0,
    ensures pending(rows,directory,probe) == (names(*rows[0].0,rows[0].1.alias,directory,probe)
        || pending(rows.drop_first(),directory,probe)),
{
    assert forall|r: (&u64,&Reservation)| #[trigger] rows.contains(r) == (rows[0] == r || rows.drop_first().contains(r)) by {
        if rows.contains(r) {
            let i = rows.index_of(r);
            if i > 0 { assert(rows.drop_first()[i-1] == r); }
        }
        if rows.drop_first().contains(r) {
            let i = rows.drop_first().index_of(r);
            assert(rows[i+1] == r);
        }
    }
    if pending(rows,directory,probe) {
        let r = choose|r: (&u64,&Reservation)| rows.contains(r) && names(*r.0,r.1.alias,directory,probe);
        if r != rows[0] {
            assert(rows.drop_first().contains(r));
            assert(pending(rows.drop_first(),directory,probe));
        }
    }
    if pending(rows.drop_first(),directory,probe) {
        let r = choose|r: (&u64,&Reservation)| rows.drop_first().contains(r) && names(*r.0,r.1.alias,directory,probe);
        assert(rows.contains(r));
    }
    assert(rows.contains(rows[0]));
}

fn recover(reservations: &BTreeMap<u64,Reservation>, directory: &HashMap<u64,u64>,
    capabilities: &mut HashSet<u64>, allowances: &mut HashSet<u64>, grants: &mut HashMap<u64,u64>, probe: u64)
    requires hash_map_inv(old(grants)), btree_map_wf(reservations), hash_map_inv(directory),
        hash_set_inv(old(capabilities)), hash_set_inv(old(allowances)),
    ensures ({
        let named = exists|uid:u64| #[trigger] reservations@.contains_key(uid)
            && names(uid,reservations@[uid].alias,directory@,probe);
        &&& final(grants)@.get(probe) == if named { None } else { old(grants)@.get(probe) }
        &&& final(capabilities)@.contains(probe) == (old(capabilities)@.contains(probe) || named)
        &&& final(allowances)@.contains(probe) == (old(allowances)@.contains(probe) || named)
    }),
{
    let mut cursor = crate::pending_deletions::scan(reservations);
    let ghost initial = cursor.remaining();
    let ghost named = exists|uid:u64| #[trigger] reservations@.contains_key(uid)
        && names(uid,reservations@[uid].alias,directory@,probe);
    assert(pending(initial,directory@,probe) == named) by {
        if pending(initial,directory@,probe) {
            let r = choose|r: (&u64,&Reservation)| initial.contains(r) && names(*r.0,r.1.alias,directory@,probe);
            assert(reservations@.get(*r.0) == Some(*r.1));
        }
        if named {
            let k = choose|k:u64| reservations@.contains_key(k) && names(k,reservations@[k].alias,directory@,probe);
            assert(initial.contains((&k,&reservations@[k])));
        }
    }
    loop
        invariant hash_map_inv(grants), hash_map_inv(directory), cursor.decrease().is_some(),
            named == (exists|uid:u64| #[trigger] reservations@.contains_key(uid) && names(uid,reservations@[uid].alias,directory@,probe)), hash_set_inv(capabilities), hash_set_inv(allowances),
            (if pending(cursor.remaining(),directory@,probe) { None } else { grants@.get(probe) })
                == (if named { None } else { old(grants)@.get(probe) }),
            (capabilities@.contains(probe) || pending(cursor.remaining(),directory@,probe))
                == (old(capabilities)@.contains(probe) || named),
            (allowances@.contains(probe) || pending(cursor.remaining(),directory@,probe))
                == (old(allowances)@.contains(probe) || named),
        decreases cursor.decrease().unwrap(),
    {
        let ghost prior = cursor.remaining();
        let row = crate::pending_deletions::next(&mut cursor);
        let Some((uid,alias)) = row else {
            assert(prior.len() == 0);
            assert(!pending(prior,directory@,probe));
            return;
        };
        proof { split(prior,directory@,probe); }
        crate::model::recovered_fence_membership(directory,uid,alias.copied(),capabilities,allowances,grants,probe);
    }
}
}

verus! {
// Finishing one reclamation can never reopen another principal's fence.
fn release_fence(closed: &mut HashSet<u64>, finished: u64, probe: u64) -> (still_closed: bool)
    requires hash_set_inv(old(closed)),
    ensures still_closed == (old(closed)@.contains(probe) && probe != finished),
{
    crate::principal_fences::release(closed,&finished);
    crate::principal_fences::fenced(closed,&probe)
}
}
