//! Searches over an immutable snapshot of the hosted KV overlay.

use super::encoding;
use std::cmp::Ordering;
use std::sync::Arc;
use vstd::prelude::*;

verus! {

#[derive(Debug)]
pub(super) struct Entry {
    pub(super) key: Vec<u8>,
    pub(super) value: Option<Vec<u8>>,
}

#[derive(Debug)]
pub(super) struct Node {
    pub(super) entry: Arc<Entry>,
    pub(super) left: Option<Arc<Self>>,
    pub(super) right: Option<Arc<Self>>,
    pub(super) height: u32,
}

pub(super) open spec fn deref_option<T>(o: Option<&T>) -> Option<T> {
    match o { Some(r) => Some(*r), None => None }
}

/// A lookup distinguishes an absent overlay entry from an explicit tombstone.
pub(super) open spec fn lookup_spec(node: Option<Arc<Node>>, key: Seq<u8>) -> Option<Option<Vec<u8>>>
    decreases node,
{
    match node {
        None => None,
        Some(n) => {
            if key == n.entry.key@ { Some(n.entry.value) }
            else if encoding::below(key, n.entry.key@) { lookup_spec(n.left, key) }
            else { lookup_spec(n.right, key) }
        }
    }
}

pub(super) open spec fn contains_entry(node: Option<Arc<Node>>, key: Seq<u8>, value: Option<Vec<u8>>) -> bool
    decreases node,
{
    match node {
        Some(n) => (n.entry.key@ == key && n.entry.value == value)
            || contains_entry(n.left, key, value) || contains_entry(n.right, key, value),
        None => false,
    }
}

pub(super) open spec fn ordered(node: Option<Arc<Node>>) -> bool
    decreases node,
{
    match node {
        None => true,
        Some(n) => {
            &&& ordered(n.left) && ordered(n.right)
            &&& forall|k: Seq<u8>, v: Option<Vec<u8>>| #[trigger] contains_entry(n.left, k, v)
                ==> encoding::below(k, n.entry.key@)
            &&& forall|k: Seq<u8>, v: Option<Vec<u8>>| #[trigger] contains_entry(n.right, k, v)
                ==> encoding::below(n.entry.key@, k)
        }
    }
}

pub(super) proof fn strict_order(a: Seq<u8>, b: Seq<u8>)
    ensures encoding::below(a, b) ==> !encoding::below(b, a) && a != b,
            !encoding::below(a,b) && a != b ==> encoding::below(b,a),
    decreases a.len(),
{
    reveal_with_fuel(encoding::below, 2);
    if a.len() == 0 && b.len() == 0 { assert(a =~= b); }
    if a.len() > 0 && b.len() > 0 && a[0] == b[0] {
        strict_order(a.skip(1), b.skip(1));
        if a.skip(1) == b.skip(1) {
            assert(a =~= b) by {
                assert forall|i: int| 0 <= i < a.len() implies a[i] == b[i] by {
                    if i > 0 { assert(a.skip(1)[i-1] == b.skip(1)[i-1]); }
                }
            }
        }
    }
}

pub(super) proof fn transitive(a: Seq<u8>, b: Seq<u8>, c: Seq<u8>)
    requires encoding::below(a, b), encoding::below(b, c),
    ensures encoding::below(a, c),
    decreases c.len(),
{
    reveal_with_fuel(encoding::below, 2);
    if a.len() > 0 && b.len() > 0 && c.len() > 0 && a[0] == b[0] && b[0] == c[0] {
        transitive(a.skip(1), b.skip(1), c.skip(1));
    }
}

pub(super) proof fn lookup_membership(node: Option<Arc<Node>>, key: Seq<u8>, value: Option<Vec<u8>>)
    requires ordered(node),
    ensures (lookup_spec(node, key) == Some(value)) == contains_entry(node, key, value),
    decreases node,
{
    if let Some(n) = node {
        strict_order(key, n.entry.key@);
        strict_order(n.entry.key@, key);
        let ghost left = n.left;
        let ghost right = n.right;
        if contains_entry(left, key, value) { assert(encoding::below(key, n.entry.key@)); }
        if contains_entry(right, key, value) { assert(encoding::below(n.entry.key@, key)); }
        if key != n.entry.key@ {
            if encoding::below(key, n.entry.key@) { lookup_membership(left, key, value); }
            else { lookup_membership(right, key, value); }
        }
    }
}

pub(super) fn lookup<'a>(root: Option<&'a Arc<Node>>, key: &[u8]) -> (result: Option<&'a Option<Vec<u8>>>)
    ensures
        deref_option(result) == lookup_spec(deref_option(root), key@),
        ordered(deref_option(root)) ==> forall|v: Option<Vec<u8>>|
            #[trigger] contains_entry(deref_option(root), key@, v) == (deref_option(result) == Some(v)),
{
    let result = search(root, key);
    proof {
        if ordered(deref_option(root)) {
            assert forall|v: Option<Vec<u8>>| #[trigger] contains_entry(deref_option(root), key@, v)
                == (deref_option(result) == Some(v)) by {
                lookup_membership(deref_option(root), key@, v);
            }
        }
    }
    result
}

#[inline]
fn search<'a>(root: Option<&'a Arc<Node>>, key: &[u8]) -> (result: Option<&'a Option<Vec<u8>>>)
    ensures deref_option(result) == lookup_spec(deref_option(root), key@),
{
    let mut cursor = root;
    loop
        invariant lookup_spec(deref_option(root), key@) == lookup_spec(deref_option(cursor), key@),
        decreases cursor,
    {
        let node = cursor?;
        cursor = match encoding::bytewise_cmp(key, node.entry.key.as_slice()) {
            Ordering::Equal => return Some(&node.entry.value),
            Ordering::Less => node.left.as_ref(),
            Ordering::Greater => node.right.as_ref(),
        };
    }
}

}
