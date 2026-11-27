//! Group one enumerated durable marker namespace before publishing the store.
use super::authority::Marker;
use std::{collections::HashMap, hash::Hash};
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_eq::obeys_concrete_eq,
    std_specs::hash::{hash_map_inv, obeys_key_model},
};

verus! {
broadcast use vstd::std_specs::hash::group_hash_axioms;

pub(super) open spec fn has<K>(map: Map<K,Vec<Marker>>, id: K, kind: Marker) -> bool {
    map.contains_key(id) && map[id]@.contains(kind)
}

pub(super) open spec fn grouped<K>(
    before: Map<K,Vec<Marker>>, after: Map<K,Vec<Marker>>, ids: Seq<K>, kind: Marker,
) -> bool {
    &&& forall|id:K| #[trigger] after.contains_key(id) == (before.contains_key(id) || ids.contains(id))
    &&& forall|id:K, tag:Marker| #[trigger] has(after,id,tag) ==
        (has(before,id,tag) || (ids.contains(id) && tag == kind))
}

pub(super) open spec fn decoded<T,K,E,F:Fn(&T)->Result<K,E>>(keys: Seq<T>, ids: Seq<K>, decode: F) -> bool {
    forall|i:int| 0 <= i < ids.len() ==> #[trigger] decode.ensures((&keys[i],),Ok(ids[i]))
}

/// Success covers every supplied row. On failure only the successfully decoded
/// prefix contributed authority, and the error belongs to the next row.
#[allow(clippy::unwrap_or_default, reason = "the verifier specifies Entry::or_insert")]
#[allow(clippy::arithmetic_side_effects, reason = "the verifier bounds the index by the input length")]
pub(super) fn group<T,K: Eq + Hash,E,F: Fn(&T)->Result<K,E>>(
    recorded: &mut HashMap<K,Vec<Marker>>, keys: &[T], kind: Marker, decode: F,
) -> (out: Result<(),E>)
    requires hash_map_inv(old(recorded)), obeys_key_model::<K>(), obeys_concrete_eq::<K>(),
        forall|i:int| 0 <= i < keys.len() ==> decode.requires((&keys@[i],)),
    ensures hash_map_inv(final(recorded)),
        exists|ids: Seq<K>| #[trigger] grouped(old(recorded)@,final(recorded)@,ids,kind)
            && decoded(keys@,ids,decode) && match out {
                Ok(()) => ids.len() == keys.len(),
                Err(e) => ids.len() < keys.len() && decode.ensures((&keys@[ids.len() as int],),Err(e)),
            },
{
    let mut i = 0usize;
    let ghost mut ids: Seq<K> = Seq::empty();
    let ghost initial = recorded@;
    while i < keys.len()
        invariant i <= keys.len(), ids.len() == i, initial == old(recorded)@,
            hash_map_inv(recorded), obeys_key_model::<K>(), obeys_concrete_eq::<K>(),
            forall|n:int| 0 <= n < keys.len() ==> decode.requires((&keys@[n],)),
            grouped(initial,recorded@,ids,kind), decoded(keys@,ids,decode),
        decreases keys.len() - i,
    {
        let id = match decode(&keys[i]) {
            Ok(id) => id,
            Err(e) => {
                assert(grouped(initial,recorded@,ids,kind));
                return Err(e);
            },
        };
        let ghost before = recorded@;
        let bucket = recorded.entry(id).or_insert(Vec::new());
        let ghost prior = bucket@;
        bucket.push(kind);
        proof {
            assert forall|k:K, tag:Marker| #[trigger] has(recorded@,k,tag) ==
                (has(initial,k,tag) || (ids.push(id).contains(k) && tag == kind)) by {
                vstd::seq_lib::lemma_seq_contains_after_push(ids,id,k);
                if k == id { vstd::seq_lib::lemma_seq_contains_after_push(prior,kind,tag); }
                assert(has(before,k,tag) == (has(initial,k,tag) || (ids.contains(k) && tag == kind)));
            }
            assert forall|k:K| #[trigger] recorded@.contains_key(k) ==
                (initial.contains_key(k) || ids.push(id).contains(k)) by {
                vstd::seq_lib::lemma_seq_contains_after_push(ids,id,k);
            }
            assert forall|j:int| 0 <= j < ids.push(id).len() implies
                #[trigger] decode.ensures((&keys@[j],),Ok(ids.push(id)[j])) by {
                if j < i { assert(decode.ensures((&keys@[j],),Ok(ids[j]))); }
            }
            ids = ids.push(id);
        }
        i += 1;
    }
    assert(grouped(initial,recorded@,ids,kind));
    Ok(())
}
}
