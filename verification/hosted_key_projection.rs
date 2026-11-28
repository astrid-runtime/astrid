//! Connect the physical checkpoint/overlay map to reported logical keys.
use std::collections::BTreeMap;
use vstd::prelude::*;
use vstd::std_specs::cmp::OrdSpec;
use vstd::{
    laws_cmp::{obeys_cmp, obeys_cmp_deep_eq},
    std_specs::btree::{btree_map_deep_view_impl, btree_map_inv, group_btree_axioms},
};
use crate::{encoding, key_projection};

verus! {
broadcast use group_btree_axioms;

proof fn byte_view(key: Vec<u8>)
    ensures key.deep_view() == key@,
{ assert(key.deep_view() =~= key@); }

pub(super) proof fn visible(keys: &BTreeMap<Vec<u8>,bool>, bytes: Seq<u8>)
    requires btree_map_inv(keys), obeys_cmp_deep_eq::<Vec<u8>>(),
    ensures (keys.deep_view().get(bytes) == Some(true)) ==
        (exists|key:Vec<u8>| #[trigger] keys@.get(key) == Some(true) && key@ == bytes),
{
    reveal(btree_map_deep_view_impl);
    if keys.deep_view().contains_key(bytes) {
        let k = choose|k:Vec<u8>| keys@.contains_key(k) && #[trigger] k.deep_view() == bytes;
        byte_view(k);
        assert(keys.deep_view()[bytes] == keys@[k]);
        assert forall|other:Vec<u8>| keys@.contains_key(other) && other@ == bytes implies other == k by {
            byte_view(other);
            assert(other.deep_view() == k.deep_view());
            assert(other.cmp_spec(&k) is Equal);
        }
        if keys@[k] { assert(keys@.get(k) == Some(true) && k@ == bytes); }
        if exists|row:Vec<u8>| #[trigger] keys@.get(row) == Some(true) && row@ == bytes {
            let row = choose|row:Vec<u8>| keys@.get(row) == Some(true) && row@ == bytes;
            assert(row == k);
        }
    } else if exists|k:Vec<u8>| #[trigger] keys@.get(k) == Some(true) && k@ == bytes {
        let k = choose|k:Vec<u8>| keys@.get(k) == Some(true) && k@ == bytes;
        byte_view(k);
        assert(keys.deep_view().dom().contains(k.deep_view()));
    }
}

/// The map contains the post-overlay state for the exact byte key even
/// when the overlay allocated a different Vec for the same address.
fn overlay_wins(keys: &mut BTreeMap<Vec<u8>,bool>, original: Vec<u8>, replacement: Vec<u8>, value: Option<&[u8]>)
    requires btree_map_inv(old(keys)), obeys_cmp::<Vec<u8>>(), obeys_cmp_deep_eq::<Vec<u8>>(),
        original@ == replacement@,
    ensures btree_map_inv(final(keys)), final(keys).deep_view() == old(keys).deep_view().insert(original@,value.is_some()),
{
    proof { byte_view(original); byte_view(replacement); }
    key_projection::checkpoint(keys,original);
    assert(keys.deep_view() == old(keys).deep_view().insert(original@,true));
    key_projection::overlay(keys,replacement,value);
}

/// For a single namespace the projected suffix identifies exactly one
/// physical address. A false presence flag cannot return its logical key.
pub(super) fn namespace_keys(keys: &BTreeMap<Vec<u8>,bool>, namespace: &[u8], target: &[u8]) -> (logical: Vec<Vec<u8>>)
    requires btree_map_inv(keys), obeys_cmp::<Vec<u8>>(), obeys_cmp_deep_eq::<Vec<u8>>(),
        forall|k:Vec<u8>| keys@.get(k) == Some(true) ==>
            #[trigger] encoding::matches_prefix(k@,namespace@ + seq![0u8]),
    ensures (exists|i:int| 0 <= i < logical.len() && #[trigger] logical@[i]@ == target@)
            == (keys.deep_view().get(namespace@ + seq![0u8] + target@) == Some(true)),
        forall|i:int| 0 <= i < logical.len() ==>
            keys.deep_view().get(namespace@ + seq![0u8] + #[trigger] logical@[i]@) == Some(true),
{
    let start = encoding::composite(namespace,&[]);
    let address = encoding::composite(namespace,target);
    let project = |key: &Vec<u8>| -> (out: Result<Vec<u8>,()>)
        ensures out.is_ok() == (key.len() >= start.len()),
            out matches Ok(bytes) ==> bytes@ == key@.skip(start.len() as int),
    {
        match key_projection::suffix(key.as_slice(),start.len()) {
            Some(bytes) => { let mut out = Vec::new(); out.extend_from_slice(bytes); assert(out@ =~= bytes@); Ok(out) },
            None => Err(()),
        }
    };
    let result = key_projection::collect(keys,project);
    proof {
        if result.is_err() {
            let k = choose|k:Vec<u8>| keys@.get(k) == Some(true) && project.ensures((&k,),Err(()));
            assert(encoding::matches_prefix(k@,start@));
        }
    }
    assert(result.is_ok());
    let out = result.unwrap();
    let ghost seen = choose|seen:Seq<Vec<u8>>| seen.no_duplicates() && seen.len() == out.len()
        && (forall|k:Vec<u8>| #[trigger] seen.contains(k) == (keys@.get(k) == Some(true)))
        && (forall|i:int| 0 <= i < seen.len() ==> #[trigger] project.ensures((&seen[i],),Ok(out@[i])));
    assert forall|i:int| 0 <= i < out.len() implies
        keys.deep_view().get(start@ + #[trigger] out@[i]@) == Some(true) by {
        let k = seen[i];
        assert(seen.contains(k));
        assert(keys@.get(k) == Some(true));
        assert(project.ensures((&k,),Ok(out@[i])));
        assert(encoding::matches_prefix(k@,start@));
        assert(k@.take(start.len() as int) =~= start@);
        assert(k@ =~= start@ + out@[i]@);
        visible(keys,k@);
    }
    proof { visible(keys,address@); }
    assert((exists|i:int| 0 <= i < out.len() && #[trigger] out@[i]@ == target@)
        == (keys.deep_view().get(address@) == Some(true))) by {
        if exists|i:int| 0 <= i < out.len() && #[trigger] out@[i]@ == target@ {
            let i = choose|i:int| 0 <= i < out.len() && #[trigger] out@[i]@ == target@;
            let k = seen[i];
            assert(seen.contains(k));
            assert(project.ensures((&seen[i],),Ok(out@[i])));
            assert(encoding::matches_prefix(k@,start@));
            assert(k@.take(start.len() as int) =~= start@);
            assert(k@ =~= start@ + target@);
            assert(keys@.get(k) == Some(true));
        }
        if keys.deep_view().get(address@) == Some(true) {
            let k = choose|k:Vec<u8>| keys@.get(k) == Some(true) && k@ == address@;
            assert(seen.contains(k));
            let i = seen.index_of(k);
            assert(project.ensures((&seen[i],),Ok(out@[i])));
            assert(out@[i]@ =~= target@);
        }
    }
    out
}

/// A physical checkpoint marker overridden by a separately allocated overlay
/// key is returned precisely when the overlay still has a value for it.
fn marker_after_overlay(namespace: &[u8], id: &[u8;16], value: Option<&[u8]>)
    requires obeys_cmp::<Vec<u8>>(), obeys_cmp_deep_eq::<Vec<u8>>(),
{
    let text = crate::marker_key::encode(id);
    let checkpoint = encoding::composite(namespace,&text);
    let replacement = encoding::composite(namespace,&text);
    let ghost address = checkpoint@;
    let mut keys = BTreeMap::new();
    proof { reveal(btree_map_deep_view_impl); assert(keys.deep_view() =~= Map::empty()); }
    overlay_wins(&mut keys,checkpoint,replacement,value);
    assert forall|k:Vec<u8>| keys@.get(k) == Some(true) implies
        #[trigger] encoding::matches_prefix(k@,namespace@ + seq![0u8]) by {
        visible(&keys,k@);
        assert(keys.deep_view().get(k@) == Some(true));
        assert(k@ == address);
        assert(k@.take(namespace.len() + 1) =~= namespace@ + seq![0u8]);
    }
    let logical = namespace_keys(&keys,namespace,&text);
    assert((exists|i:int| 0 <= i < logical.len() && #[trigger] logical@[i]@ == text@) == value.is_some());
    if value.is_some() {
        let ghost row = choose|i:int| 0 <= i < logical.len() && #[trigger] logical@[i]@ == text@;
        assert(crate::marker_key::spells(id@, logical@[row]@));
    }

}
}
