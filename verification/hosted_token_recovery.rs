//! Admission after enumerating the two durable token marker namespaces.
use crate::{marker_batch, marker_key, token_authority::{self, Admission, Marker}};
use std::collections::HashMap;
use vstd::prelude::*;
use vstd::{laws_eq::obeys_concrete_eq, std_specs::hash::{hash_map_inv, obeys_key_model}};

verus! {

type Id = [u8; 16];
type Key = [u8; 36];

spec fn valid(key: Key) -> bool { exists|id:Id| #[trigger] marker_key::spells(id@,key@) }

spec fn listed(keys: Seq<Key>, id: Id) -> bool {
    exists|i:int| 0 <= i < keys.len() && #[trigger] marker_key::spells(id@,keys[i]@)
}

fn collect_namespace(
    groups: &mut HashMap<Id,Vec<Marker>>, keys: &[Key], kind: Marker,
)
    requires hash_map_inv(old(groups)), obeys_key_model::<Id>(), obeys_concrete_eq::<Id>(),
        forall|i:int| 0 <= i < keys.len() ==> #[trigger] valid(keys@[i]),
    ensures hash_map_inv(final(groups)),
        forall|id:Id,tag:Marker| #[trigger] marker_batch::has(final(groups)@,id,tag) ==
            (marker_batch::has(old(groups)@,id,tag) || (tag == kind && listed(keys@,id))),
{
    let decode = |key: &Key| -> (out: Result<Id,()>)
        ensures forall|id:Id| #[trigger] marker_key::spells(id@,key@) ==> out == Ok(id),
            out matches Ok(id) ==> marker_key::spells(id@,key@),
            out.is_err() ==> !valid(*key),
    {
        let out = marker_key::decode_compatible(key, |_bytes: &[u8]| -> (result: Result<Id,()>)
            ensures result == Err(()),
        { Err(()) });
        proof {
            if out.is_err() && valid(*key) {
                let id = choose|id:Id| marker_key::spells(id@,key@);
                assert(out == Ok(id));
            }
            if let Ok(id) = out {
                if valid(*key) {
                    let original = choose|original:Id| marker_key::spells(original@,key@);
                    assert(out == Ok(original));
                }
            }
        }
        out
    };
    let result = marker_batch::group(groups,keys,kind,decode);
    let ghost ids = choose|ids: Seq<Id>| marker_batch::grouped(old(groups)@,groups@,ids,kind)
        && marker_batch::decoded(keys@,ids,decode) && match result {
            Ok(()) => ids.len() == keys.len(),
            Err(e) => ids.len() < keys.len() && decode.ensures((&keys@[ids.len() as int],),Err(e)),
        };
    if result.is_err() {
        let ghost n = ids.len() as int;
        assert(valid(keys@[n]));
        let ghost id = choose|id:Id| marker_key::spells(id@,keys@[n]@);
        assert(decode.ensures((&keys@[n],),Err(())));
        assert(marker_key::spells(id@,keys@[n]@));
        assert(false);
    }
    assert forall|id:Id| #[trigger] ids.contains(id) == listed(keys@,id) by {
        if ids.contains(id) {
            let i = choose|i:int| 0 <= i < ids.len() && ids[i] == id;
            assert(decode.ensures((&keys@[i],),Ok(ids[i])));
            assert(marker_key::spells(id@,keys@[i]@));
        }
        if listed(keys@,id) {
            let i = choose|i:int| 0 <= i < keys.len() && marker_key::spells(id@,keys@[i]@);
            assert(decode.ensures((&keys@[i],),Ok(ids[i])));
            assert(ids[i] == id);
        }
    }
}

/// Both namespaces replay into a single store. One token may be present in both.
fn reopen(revoked: &[Key], consumed: &[Key], target: Id, single_use: bool)
    requires obeys_key_model::<Id>(), obeys_concrete_eq::<Id>(),
        forall|i:int| 0 <= i < revoked.len() ==> #[trigger] valid(revoked@[i]),
        forall|i:int| 0 <= i < consumed.len() ==> #[trigger] valid(consumed@[i]),
{
    let mut recorded = HashMap::new();
    let kinds = Marker::recovery_order();
    let revoked_namespace = kinds[0].namespace();
    let consumed_namespace = kinds[1].namespace();
    assert(revoked_namespace@ == "caps:revoked"@ && consumed_namespace@ == "caps:used"@);
    assert(!marker_batch::has(recorded@,target,Marker::Revoked));
    assert(!marker_batch::has(recorded@,target,Marker::Consumed));
    collect_namespace(&mut recorded,revoked,kinds[0]);
    assert(marker_batch::has(recorded@,target,Marker::Revoked) == listed(revoked@,target));
    assert(!marker_batch::has(recorded@,target,Marker::Consumed));
    collect_namespace(&mut recorded,consumed,kinds[1]);
    assert(marker_batch::has(recorded@,target,Marker::Revoked) == listed(revoked@,target));
    assert(marker_batch::has(recorded@,target,Marker::Consumed) == listed(consumed@,target));
    let ghost history = if recorded@.contains_key(target) { recorded@[target]@ } else { Seq::empty() };
    proof { token_authority::replay_keeps_markers(history); }
    let live = token_authority::recover_authority(recorded);
    let decision = token_authority::status(&live,&target).admit(single_use);
    assert((decision is Revoked) == listed(revoked@,target));
    assert((decision is AlreadyUsed) == (!listed(revoked@,target) && single_use && listed(consumed@,target)));
    assert((decision is Allowed) == (!listed(revoked@,target) && (!single_use || !listed(consumed@,target))));
}

/// A rejected second row returns its exact error after recording only the first.
/// This covers the error branch independently of the all-canonical assumption.
fn rejected_row(first: u64, error: u64, later: u64) {
    let mut recorded = HashMap::new();
    let keys: [Result<u64,u64>;3] = [Ok(first),Err(error),Ok(later)];
    let decode = |row: &Result<u64,u64>| -> (out: Result<u64,u64>)
        ensures out == *row,
    { *row };
    let result = marker_batch::group(&mut recorded,&keys,Marker::Revoked,decode);
    let ghost ids = choose|ids:Seq<u64>| marker_batch::grouped(Map::empty(),recorded@,ids,Marker::Revoked)
        && marker_batch::decoded(keys@,ids,decode) && match result {
            Ok(()) => ids.len() == keys.len(),
            Err(e) => ids.len() < keys.len() && decode.ensures((&keys@[ids.len() as int],),Err(e)),
        };
    proof { if ids.len() > 1 { assert(decode.ensures((&keys@[1],),Ok(ids[1]))); } }
    assert(ids.len() == 1);
    assert(decode.ensures((&keys@[0],),Ok(ids[0])));
    assert(result == Err(error));
    assert(recorded@.dom() =~= set![first]);
    assert(marker_batch::has(recorded@,first,Marker::Revoked));
}

}
