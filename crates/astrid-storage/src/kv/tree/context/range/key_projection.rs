//! Enumerate the visible physical keys in a checkpoint and overlay projection.
use std::collections::BTreeMap;
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::std_specs::cmp::OrdSpec;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_cmp::{obeys_cmp, obeys_cmp_deep_eq},
    std_specs::{
        btree::{btree_map_inv, btree_map_wf, increasing_seq, key_obeys_cmp_spec},
        iter::IteratorSpec,
    },
};

verus! {
broadcast use vstd::std_specs::btree::group_btree_axioms;

pub(super) fn checkpoint(map: &mut BTreeMap<Vec<u8>,bool>, key: Vec<u8>)
    requires btree_map_inv(old(map)), obeys_cmp::<Vec<u8>>(), obeys_cmp_deep_eq::<Vec<u8>>(),
    ensures btree_map_inv(final(map)), final(map).deep_view() == old(map).deep_view().insert(key.deep_view(),true),
{
    map.insert(key,true);
}

pub(super) fn overlay(map: &mut BTreeMap<Vec<u8>,bool>, key: Vec<u8>, value: Option<&[u8]>)
    requires btree_map_inv(old(map)), obeys_cmp::<Vec<u8>>(), obeys_cmp_deep_eq::<Vec<u8>>(),
    ensures btree_map_inv(final(map)), final(map).deep_view() == old(map).deep_view().insert(key.deep_view(),value.is_some()),
{
    map.insert(key,value.is_some());
}

/// Strip precisely the encoded namespace, rejecting a short physical key.
pub(super) fn suffix(key: &[u8], strip: usize) -> (out: Option<&[u8]>)
    ensures out.is_some() == (strip <= key.len()),
        out matches Some(bytes) ==> bytes@ == key@.skip(strip as int),
{
    if strip > key.len() { None } else { Some(key.split_at(strip).1) }
}

/// Every visible key is projected once; a tombstone never reaches the decoder.
pub(super) fn collect<K: Ord,V,E,F: Fn(&K)->Result<V,E>>(
    keys: &BTreeMap<K,bool>, project: F,
) -> (result: Result<Vec<V>,E>)
    requires btree_map_wf(keys), key_obeys_cmp_spec::<K>(),
        forall|k:K| keys@.get(k) == Some(true) ==> project.requires((&k,)),
    ensures match result {
        Ok(out) => exists|seen:Seq<K>| seen.no_duplicates() && increasing_seq(seen) && seen.len() == out.len()
            && (forall|k:K| #[trigger] seen.contains(k) == (keys@.get(k) == Some(true)))
            && (forall|i:int| 0 <= i < seen.len() ==> #[trigger] project.ensures((&seen[i],),Ok(out@[i]))),
        Err(e) => exists|k:K| keys@.get(k) == Some(true) && #[trigger] project.ensures((&k,),Err(e)),
    },
{
    let mut cursor = keys.iter();
    let ghost all = cursor.remaining();
    let ghost mut n:int = 0;
    let ghost mut seen:Seq<K> = Seq::empty();
    let mut out = Vec::new();
    loop
        invariant 0 <= n <= all.len(), all.len() == keys@.dom().len(), cursor.remaining() == all.skip(n),
            increasing_seq(all.map_values(|r:(&K,&bool)| *r.0)), key_obeys_cmp_spec::<K>(),
            all.no_duplicates(), increasing_seq(seen), seen.no_duplicates(), seen.len() == out.len(),
            forall|k:K| keys@.get(k) == Some(true) ==> project.requires((&k,)),
            forall|i:int| 0 <= i < all.len() ==> keys@.get(*all[i].0) == Some(*all[i].1),
            forall|k:K| keys@.get(k) == Some(true) ==> all.contains((&k,&true)),
            forall|k:K| #[trigger] seen.contains(k) == exists|i:int| 0 <= i < n && all[i] == (&k,&true),
            forall|i:int| 0 <= i < seen.len() ==> #[trigger] project.ensures((&seen[i],),Ok(out@[i])),
        decreases keys@.dom().len() - n,
    {
        let Some((key,present)) = cursor.next() else {
            assert(n == all.len());
            assert forall|k:K| #[trigger] seen.contains(k) == (keys@.get(k) == Some(true)) by {
                if seen.contains(k) {
                    let i = choose|i:int| 0 <= i < n && all[i] == (&k,&true);
                    assert(keys@.get(*all[i].0) == Some(*all[i].1));
                }
            }
            return Ok(out);
        };
        assert(all[n] == (key,present));
        assert(keys@.get(*key) == Some(*present));
        let ghost previous = seen;
        if *present {
            let value = project(key)?;
            assert(!seen.contains(*key)) by {
                if seen.contains(*key) {
                    let i = choose|i:int| 0 <= i < n && all[i] == (key,&true);
                    assert(all[i] == all[n]);
                }
            }
            out.push(value);
            proof {
                seen = seen.push(*key);
                assert forall|i:int,j:int| 0 <= i < j < seen.len() implies seen[i].cmp_spec(&seen[j]) is Less by {
                    if j == previous.len() {
                        let prior_key = previous[i];
                        assert(previous.contains(prior_key));
                        let p = choose|p:int| 0 <= p < n && all[p] == (&prior_key,&true);
                        let ordered = all.map_values(|r:(&K,&bool)| *r.0);
                        assert(ordered[p].cmp_spec(&ordered[n]) is Less);
                    }
                }
                assert(increasing_seq(seen));
                assert forall|i:int| 0 <= i < seen.len() implies #[trigger] project.ensures((&seen[i],),Ok(out@[i])) by {
                    if i < previous.len() { assert(project.ensures((&previous[i],),Ok(out@[i]))); }
                }
            };
        }
        assert forall|k:K| #[trigger] seen.contains(k) == (exists|i:int| 0 <= i < n+1 && all[i] == (&k,&true)) by {
            if *present { vstd::seq_lib::lemma_seq_contains_after_push(previous,*key,k); }
            if exists|i:int| 0 <= i < n+1 && all[i] == (&k,&true) {
                let i = choose|i:int| 0 <= i < n+1 && all[i] == (&k,&true);
                if i < n { assert(previous.contains(k)); }
            }
        }
        assert(cursor.remaining() =~= all.skip(n+1));
        proof { n = n+1; };
    }
}
}
