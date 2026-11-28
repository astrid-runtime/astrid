//! Persistent insertion and balancing for the hosted KV overlay.

use super::checkpoint_value::ValueSlot;
use super::delta_mutation::Mutation;
use super::encoding;
use super::traversal::{Entry, Node};
#[cfg(verus_keep_ghost)]
use super::traversal::{
    contains_entry, lookup_membership, lookup_spec, ordered, strict_order, transitive,
};
use std::cmp::Ordering;
use std::sync::Arc;
use vstd::prelude::*;

verus! {

/// Install the addressed bytes and accounting of the same admitted replay row.
pub(super) fn replay(root:&mut Option<Arc<Node>>,change:super::delta_totals::Prepared,
    totals:&mut super::checkpoint_totals::NodeTotals)
    requires ordered(*old(root)),
    ensures *final(totals) == change.totals, ordered(*final(root)),
        forall|q:Seq<u8>| #[trigger] lookup_spec(*final(root),q) ==
            if q == change.key@ {Some(change.value)} else {lookup_spec(*old(root),q)},
{
    *totals = change.totals;
    put(root,change.key,change.value);
}

/// Stage the resolved bytes and return the corresponding durable mutation.
pub(super) fn stage<E,F:FnOnce(&Vec<u8>)->Result<ValueSlot,E>>(
    root:&mut Option<Arc<Node>>, key:Vec<u8>, replacement:Option<Vec<u8>>, encode:F,
) -> (out:Result<Mutation,E>)
    requires ordered(*old(root)), replacement matches Some(data) ==> encode.requires((&data,)),
    ensures ordered(*final(root)),
        match out {
            Err(e) => *final(root) == *old(root) && (replacement matches Some(data) &&
                encode.ensures((&data,),Err(e))),
            Ok(row) => {
                &&& row.key@ == key@
                &&& match replacement {
                    None => row.value.is_none(),
                    Some(data) => row.value matches Some(slot) && encode.ensures((&data,),Ok(slot)),
                }
                &&& forall|q:Seq<u8>| #[trigger] lookup_spec(*final(root),q) ==
                    if q == key@ {Some(replacement)} else {lookup_spec(*old(root),q)}
            },
        },
{
    let value = match &replacement {
        None => None,
        Some(data) => Some(encode(data)?),
    };
    let mut address = Vec::with_capacity(key.len());
    address.extend_from_slice(&key);
    assert(address@ =~= key@);
    put(root,address,replacement);
    Ok(Mutation {key,value})
}

spec fn same_entries(a: Arc<Node>, b: Arc<Node>) -> bool {
    forall|k: Seq<u8>, v: Option<Vec<u8>>| #[trigger] contains_entry(Some(a), k, v) == contains_entry(Some(b), k, v)
}

/// Starting with an empty root, every published overlay snapshot is ordered.
/// Replacing a value with a tombstone is a write of an explicit entry.
pub(super) fn put(root: &mut Option<Arc<Node>>, key: Vec<u8>, value: Option<Vec<u8>>)
    requires ordered(*old(root)),
    ensures
        ordered(*final(root)),
        forall|query: Seq<u8>| #[trigger] lookup_spec(*final(root), query) ==
            (if query == key@ { Some(value) } else { lookup_spec(*old(root), query) }),
{
    let ghost before = *root;
    let updated = insert(root.take(), Arc::new(Entry { key, value }));
    *root = Some(updated);
    assert forall|query: Seq<u8>| #[trigger] lookup_spec(*root, query) ==
        (if query == key@ { Some(value) } else { lookup_spec(before, query) }) by {
        if query == key@ {
            lookup_membership(*root, query, value);
        } else if let Some(v) = lookup_spec(before, query) {
            lookup_membership(before, query, v);
            lookup_membership(*root, query, v);
        } else if let Some(v) = lookup_spec(*root, query) {
            lookup_membership(*root, query, v);
            lookup_membership(before, query, v);
        }
    };
}

fn insert(root: Option<Arc<Node>>, entry: Arc<Entry>) -> (out: Arc<Node>)
    requires ordered(root),
    ensures ordered(Some(out)),
        forall|k: Seq<u8>, v: Option<Vec<u8>>| #[trigger] contains_entry(Some(out), k, v) ==
            (if k == entry.key@ { v == entry.value } else { contains_entry(root, k, v) }),
    decreases root,
{
    reveal_with_fuel(ordered, 3);
    reveal_with_fuel(contains_entry, 4);
    let Some(node) = root else {
        return make_node(entry, None, None);
    };
    proof { strict_order(entry.key@, node.entry.key@); }
    let rebuilt = match encoding::bytewise_cmp(&entry.key, &node.entry.key) {
        Ordering::Less => {
            let child = insert(node.left.clone(), entry);
            let out = make_node(Arc::clone(&node.entry), Some(child), node.right.clone());
            assert forall|k: Seq<u8>, v: Option<Vec<u8>>| #[trigger] contains_entry(Some(out), k, v)
                == (if k == entry.key@ { v == entry.value } else { contains_entry(root, k, v) }) by {
                assert(contains_entry(Some(child), k, v) ==
                    (if k == entry.key@ { v == entry.value } else { contains_entry(node.left, k, v) }));
                if k == entry.key@ { assert(!contains_entry(node.right, k, v)); }
            }
            out
        }
        Ordering::Greater => {
            let child = insert(node.right.clone(), entry);
            let out = make_node(Arc::clone(&node.entry), node.left.clone(), Some(child));
            assert forall|k: Seq<u8>, v: Option<Vec<u8>>| #[trigger] contains_entry(Some(out), k, v)
                == (if k == entry.key@ { v == entry.value } else { contains_entry(root, k, v) }) by {
                assert(contains_entry(Some(child), k, v) ==
                    (if k == entry.key@ { v == entry.value } else { contains_entry(node.right, k, v) }));
                if k == entry.key@ { assert(!contains_entry(node.left, k, v)); }
            }
            out
        }
        Ordering::Equal => {
            let out = make_node(entry, node.left.clone(), node.right.clone());
            assert forall|k: Seq<u8>, v: Option<Vec<u8>>| #[trigger] contains_entry(Some(out), k, v)
                == (if k == entry.key@ { v == entry.value } else { contains_entry(root, k, v) }) by {
                if k == entry.key@ {
                    assert(!contains_entry(node.left, k, v));
                    assert(!contains_entry(node.right, k, v));
                }
            }
            out
        }
    };
    let out = rebalance(rebuilt);
    assert forall|k: Seq<u8>, v: Option<Vec<u8>>| #[trigger] contains_entry(Some(out), k, v)
        == (if k == entry.key@ { v == entry.value } else { contains_entry(root, k, v) }) by {
        assert(contains_entry(Some(out), k, v) == contains_entry(Some(rebuilt), k, v));
    }
    out
}

fn make_node(entry: Arc<Entry>, left: Option<Arc<Node>>, right: Option<Arc<Node>>) -> (out: Arc<Node>)
    ensures out.entry == entry, out.left == left, out.right == right,
{
    Arc::new(Node {
        entry,
        height: height(left.as_ref())
            .max(height(right.as_ref()))
            .saturating_add(1),
        left,
        right,
    })
}

fn rebalance(node: Arc<Node>) -> (out: Arc<Node>)
    requires ordered(Some(node)),
    ensures ordered(Some(out)), same_entries(out, node),
{
    reveal_with_fuel(ordered, 3);
    reveal_with_fuel(contains_entry, 4);
    let ghost original = node;
    let left_height = height(node.left.as_ref());
    let right_height = height(node.right.as_ref());
    if left_height > right_height.saturating_add(1) {
        let Some(left) = node.left.as_ref() else {
            return node;
        };
        let node = if height(left.left.as_ref()) < height(left.right.as_ref()) {
            let rotated = rotate_left(left);
            let rebuilt = make_node(
                Arc::clone(&node.entry),
                Some(rotated),
                node.right.clone(),
            );
            assert forall|k: Seq<u8>, v: Option<Vec<u8>>| #[trigger] contains_entry(Some(rebuilt), k, v)
                == contains_entry(Some(node), k, v) by {
                assert(contains_entry(Some(rotated), k, v) == contains_entry(node.left, k, v));
            }
            rebuilt
        } else {
            node
        };
        assert(same_entries(node, original));
        let out = rotate_right(&node);
        assert forall|k: Seq<u8>, v: Option<Vec<u8>>| #[trigger] contains_entry(Some(out), k, v)
            == contains_entry(Some(original), k, v) by { assert(contains_entry(Some(out), k, v) == contains_entry(Some(node), k, v)); }
        return out;
    }
    if right_height > left_height.saturating_add(1) {
        let Some(right) = node.right.as_ref() else {
            return node;
        };
        let node = if height(right.right.as_ref()) < height(right.left.as_ref()) {
            let rotated = rotate_right(right);
            let rebuilt = make_node(
                Arc::clone(&node.entry),
                node.left.clone(),
                Some(rotated),
            );
            assert forall|k: Seq<u8>, v: Option<Vec<u8>>| #[trigger] contains_entry(Some(rebuilt), k, v)
                == contains_entry(Some(node), k, v) by {
                assert(contains_entry(Some(rotated), k, v) == contains_entry(node.right, k, v));
            }
            rebuilt
        } else {
            node
        };
        assert(same_entries(node, original));
        let out = rotate_left(&node);
        assert forall|k: Seq<u8>, v: Option<Vec<u8>>| #[trigger] contains_entry(Some(out), k, v)
            == contains_entry(Some(original), k, v) by { assert(contains_entry(Some(out), k, v) == contains_entry(Some(node), k, v)); }
        return out;
    }
    node
}

fn rotate_left(node: &Arc<Node>) -> (out: Arc<Node>)
    requires ordered(Some(*node)),
    ensures ordered(Some(out)), same_entries(out, *node),
{
    reveal_with_fuel(ordered, 3);
    reveal_with_fuel(contains_entry, 4);
    let Some(right) = node.right.as_ref() else {
        return Arc::clone(node);
    };
    let left = make_node(
        Arc::clone(&node.entry),
        node.left.clone(),
        right.left.clone(),
    );
    assert(contains_entry(node.right, right.entry.key@, right.entry.value));
    assert(ordered(Some(*right)));
    assert forall|k: Seq<u8>, v: Option<Vec<u8>>| #[trigger] contains_entry(Some(left), k, v)
        implies encoding::below(k, right.entry.key@) by {
        if contains_entry(node.left, k, v) { transitive(k, node.entry.key@, right.entry.key@); }
        else if k != node.entry.key@ { assert(contains_entry(right.left, k, v)); assert(encoding::below(k, right.entry.key@)); }
    }
    assert forall|k: Seq<u8>, v: Option<Vec<u8>>| #[trigger] contains_entry(right.left, k, v)
        implies encoding::below(node.entry.key@, k) by {
        assert(contains_entry(node.right, k, v));
    }
    make_node(Arc::clone(&right.entry), Some(left), right.right.clone())
}

fn rotate_right(node: &Arc<Node>) -> (out: Arc<Node>)
    requires ordered(Some(*node)),
    ensures ordered(Some(out)), same_entries(out, *node),
{
    reveal_with_fuel(ordered, 3);
    reveal_with_fuel(contains_entry, 4);
    let Some(left) = node.left.as_ref() else {
        return Arc::clone(node);
    };
    let right = make_node(
        Arc::clone(&node.entry),
        left.right.clone(),
        node.right.clone(),
    );
    assert(contains_entry(node.left, left.entry.key@, left.entry.value));
    assert(ordered(Some(*left)));
    assert forall|k: Seq<u8>, v: Option<Vec<u8>>| #[trigger] contains_entry(Some(right), k, v)
        implies encoding::below(left.entry.key@, k) by {
        if contains_entry(node.right, k, v) { transitive(left.entry.key@, node.entry.key@, k); }
        else if k != node.entry.key@ { assert(contains_entry(left.right, k, v)); assert(encoding::below(left.entry.key@, k)); }
    }
    assert forall|k: Seq<u8>, v: Option<Vec<u8>>| #[trigger] contains_entry(left.right, k, v)
        implies encoding::below(k, node.entry.key@) by {
        assert(contains_entry(node.left, k, v));
    }
    make_node(Arc::clone(&left.entry), left.left.clone(), Some(right))
}

fn height(node: Option<&Arc<Node>>) -> u32 {
    match node { Some(n) => n.height, None => 0 }
}

}
