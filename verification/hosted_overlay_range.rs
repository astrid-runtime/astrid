//! A recovered overlay range updates exactly the visible keys of its snapshot.
use std::{collections::BTreeMap,sync::Arc};
use vstd::prelude::*;
use vstd::{laws_cmp::{obeys_cmp,obeys_cmp_deep_eq}, std_specs::btree::btree_map_inv};
use crate::{encoding,overlay_range::{self,fold,names,rows},traversal::{self,Entry,Node}};

verus! {

spec fn has_key(entries: Seq<Arc<Entry>>, key: Seq<u8>) -> bool {
    exists|i:int| 0 <= i < entries.len() && #[trigger] entries[i].key@ == key
}

// All rows with this address agree with point lookup in the same ordered snapshot.
proof fn fold_target(keys: Map<Seq<u8>,bool>, entries: Seq<Arc<Entry>>, key: Seq<u8>, present: bool)
    requires forall|i:int| 0 <= i < entries.len() && #[trigger] entries[i].key@ == key
        ==> entries[i].value.is_some() == present,
    ensures fold(keys,entries).get(key) == if has_key(entries,key) { Some(present) } else { keys.get(key) },
    decreases entries.len(),
{
    if entries.len() != 0 {
        let head = entries[0];
        let rest = entries.drop_first();
        let next = keys.insert(head.key@,head.value.is_some());
        assert forall|i:int| 0 <= i < rest.len() && #[trigger] rest[i].key@ == key implies
            rest[i].value.is_some() == present by { assert(rest[i] == entries[i+1]); }
        fold_target(next,rest,key,present);
        assert(has_key(entries,key) == (head.key@ == key || has_key(rest,key))) by {
            if has_key(entries,key) {
                let i = choose|i:int| 0 <= i < entries.len() && #[trigger] entries[i].key@ == key;
                if i > 0 { assert(rest[i-1] == entries[i]); }
            }
            if has_key(rest,key) {
                let i = choose|i:int| 0 <= i < rest.len() && #[trigger] rest[i].key@ == key;
                assert(rest[i] == entries[i+1]);
            }
        }
    }
}

spec fn increasing(entries: Seq<Arc<Entry>>) -> bool {
    forall|i:int,j:int| 0 <= i < j < entries.len() ==>
        #[trigger] encoding::below(entries[i].key@,entries[j].key@)
}

proof fn ordered_rows(tree: Option<Arc<Node>>, start:Seq<u8>, end:Seq<u8>)
    requires traversal::ordered(tree),
    ensures increasing(rows(tree,start,end)),
    decreases tree,
{
    if let Some(n) = tree {
        let ghost l = n.left;
        let ghost r = n.right;
        if encoding::below(n.entry.key@,start) { ordered_rows(r,start,end); }
        else if !encoding::below(n.entry.key@,end) { ordered_rows(l,start,end); }
        else {
            ordered_rows(l,start,end);
            ordered_rows(r,start,end);
            let left = rows(l,start,end);
            let right = rows(r,start,end);
            let all = rows(tree,start,end);
            assert forall|i:int,j:int| 0 <= i < j < all.len() implies
                #[trigger] encoding::below(all[i].key@,all[j].key@) by {
                if j < left.len() {
                    assert(all[i] == left[i] && all[j] == left[j]);
                } else if i > left.len() {
                    assert(all[i] == right[i-left.len()-1] && all[j] == right[j-left.len()-1]);
                } else {
                    if i < left.len() {
                        assert(all[i] == left[i]);
                        assert(names(left,all[i].key@,all[i].value));
                        overlay_range::membership(l,start,end,all[i].key@,all[i].value);
                        assert(encoding::below(all[i].key@,n.entry.key@));
                    }
                    if j > left.len() {
                        assert(all[j] == right[j-left.len()-1]);
                        assert(names(right,all[j].key@,all[j].value));
                        overlay_range::membership(r,start,end,all[j].key@,all[j].value);
                        assert(encoding::below(n.entry.key@,all[j].key@));
                    }
                    if i < left.len() && j > left.len() {
                        traversal::transitive(all[i].key@,n.entry.key@,all[j].key@);
                    }
                }
            }
        }
    }
}

/// Successive lazy calls preserve physical order, including across stack unwinding.
fn first_two(root: Option<&Arc<Node>>, start: &[u8], end: &[u8])
    requires traversal::ordered(traversal::deref_option(root)),
{
    let mut range = overlay_range::Range::new(root,start,end);
    let ghost all = range.remaining();
    proof { ordered_rows(traversal::deref_option(root),start@,end@); }
    let first = range.next_entry();
    let second = range.next_entry();
    assert(first.is_some() == (all.len() >= 1));
    assert(second.is_some() == (all.len() >= 2));
    if let (Some(a),Some(b)) = (first,second) {
        assert(a == &*all[0] && b == &*all[1]);
        assert(encoding::below(a.key@,b.key@));
    }
}

/// Run the same cursor and map updates as a keys-only storage read, starting
/// from any well-formed checkpoint presence map and ordered overlay root.
fn apply_snapshot(root: Option<&Arc<Node>>, start: &[u8], end: &[u8], keys: &mut BTreeMap<Vec<u8>,bool>, target: &[u8])
    requires traversal::ordered(traversal::deref_option(root)), btree_map_inv(old(keys)),
        obeys_cmp::<Vec<u8>>(), obeys_cmp_deep_eq::<Vec<u8>>(),
    ensures final(keys).deep_view().get(target@) == ({
        let found = traversal::lookup_spec(traversal::deref_option(root),target@);
        if encoding::range_contains(start@,end@,target@) && found.is_some() { Some(found.unwrap().is_some()) }
        else { old(keys).deep_view().get(target@) }
    }),
{
    let ghost tree = traversal::deref_option(root);
    let ghost entries = rows(tree,start@,end@);
    let ghost found = traversal::lookup_spec(tree,target@);
    overlay_range::apply_presence(root,start,end,keys);
    proof {
        assert forall|v:Option<Vec<u8>>| #[trigger] names(entries,target@,v) ==
            (encoding::range_contains(start@,end@,target@) && found == Some(v)) by {
            overlay_range::membership(tree,start@,end@,target@,v);
            traversal::lookup_membership(tree,target@,v);
        }
        let present = found.is_some() && found.unwrap().is_some();
        assert forall|i:int| 0 <= i < entries.len() && #[trigger] entries[i].key@ == target@ implies
            entries[i].value.is_some() == present by { assert(names(entries,target@,entries[i].value)); }
        fold_target(old(keys).deep_view(),entries,target@,present);
        if has_key(entries,target@) {
            let i = choose|i:int| 0 <= i < entries.len() && #[trigger] entries[i].key@ == target@;
            assert(names(entries,target@,entries[i].value));
        }
        if found.is_some() && encoding::range_contains(start@,end@,target@) {
            assert(names(entries,target@,found.unwrap()));
            let i = choose|i:int| 0 <= i < entries.len() && (#[trigger] entries[i]).key@ == target@ && entries[i].value == found.unwrap();
        }
    }
}

}
