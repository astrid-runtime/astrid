//! Lazy half-open range traversal of one immutable overlay root.
use super::key_projection;
#[cfg(verus_keep_ghost)]
use super::traversal::{contains_entry, deref_option, ordered, transitive};
use super::{
    encoding,
    traversal::{Entry, Node},
};
use std::{collections::BTreeMap, sync::Arc};
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_cmp::{obeys_cmp, obeys_cmp_deep_eq},
    std_specs::btree::btree_map_inv,
};

verus! {

pub(super) open spec fn rows(root: Option<Arc<Node>>, start: Seq<u8>, end: Seq<u8>) -> Seq<Arc<Entry>>
    decreases root,
{
    match root {
        None => Seq::empty(),
        Some(n) => if encoding::below(n.entry.key@,start) { rows(n.right,start,end) }
            else if !encoding::below(n.entry.key@,end) { rows(n.left,start,end) }
            else { rows(n.left,start,end) + seq![n.entry] + rows(n.right,start,end) },
    }
}

pub(super) open spec fn names(entries: Seq<Arc<Entry>>, key: Seq<u8>, value: Option<Vec<u8>>) -> bool {
    exists|i:int| 0 <= i < entries.len() && (#[trigger] entries[i]).key@ == key && entries[i].value == value
}

proof fn names_concat(a: Seq<Arc<Entry>>, b: Seq<Arc<Entry>>, key: Seq<u8>, value: Option<Vec<u8>>)
    ensures names(a+b,key,value) == (names(a,key,value) || names(b,key,value)),
{
    if names(a+b,key,value) {
        let i = choose|i:int| 0 <= i < (a+b).len() && (#[trigger] (a+b)[i]).key@ == key && (a+b)[i].value == value;
        if i < a.len() { assert(a[i] == (a+b)[i]); } else { assert(b[i-a.len()] == (a+b)[i]); }
    }
    if names(a,key,value) {
        let i = choose|i:int| 0 <= i < a.len() && (#[trigger] a[i]).key@ == key && a[i].value == value;
        assert((a+b)[i] == a[i]);
    }
    if names(b,key,value) {
        let i = choose|i:int| 0 <= i < b.len() && (#[trigger] b[i]).key@ == key && b[i].value == value;
        assert((a+b)[a.len()+i] == b[i]);
    }
}

pub(super) proof fn membership(root: Option<Arc<Node>>, start: Seq<u8>, end: Seq<u8>, key: Seq<u8>, value: Option<Vec<u8>>)
    requires ordered(root),
    ensures names(rows(root,start,end),key,value) == (contains_entry(root,key,value) && encoding::range_contains(start,end,key)),
    decreases root,
{
    if let Some(n) = root {
        let ghost l = n.left;
        let ghost r = n.right;
        let ghost entry = n.entry;
        if encoding::below(n.entry.key@,start) {
            membership(r,start,end,key,value);
            if contains_entry(l,key,value) { transitive(key,n.entry.key@,start); }
        } else if !encoding::below(n.entry.key@,end) {
            membership(l,start,end,key,value);
            if contains_entry(r,key,value) && encoding::below(key,end) { transitive(n.entry.key@,key,end); }
        } else {
            membership(l,start,end,key,value);
            membership(r,start,end,key,value);
            let left = rows(l,start,end);
            let right = rows(r,start,end);
            let mid = seq![entry];
            names_concat(left,mid,key,value);
            names_concat(left+mid,right,key,value);
            assert(names(mid,key,value) == (n.entry.key@ == key && n.entry.value == value)) by {
                assert(mid[0] == n.entry);
            }
        }
    }
}

spec fn ancestors(stack: Seq<&Arc<Node>>, start: Seq<u8>, end: Seq<u8>) -> Seq<Arc<Entry>>
    decreases stack.len(),
{
    if stack.len() == 0 { Seq::empty() } else {
        let n = stack.last();
        seq![n.entry] + rows(n.right,start,end) + ancestors(stack.drop_last(),start,end)
    }
}

pub(super) struct Range<'a> {
    cursor: Option<&'a Arc<Node>>,
    stack: Vec<&'a Arc<Node>>,
    start: &'a [u8],
    end: &'a [u8],
}

impl<'a> Range<'a> {
    pub(super) closed spec fn remaining(&self) -> Seq<Arc<Entry>> {
        rows(deref_option(self.cursor),self.start@,self.end@) + ancestors(self.stack@,self.start@,self.end@)
    }

    pub(super) fn new(root: Option<&'a Arc<Node>>, start: &'a [u8], end: &'a [u8]) -> (out: Self)
        ensures out.remaining() == rows(deref_option(root),start@,end@),
    {
        Self { cursor: root, stack: Vec::new(), start, end }
    }

    pub(super) fn next_entry(&mut self) -> (result: Option<&'a Entry>)
        ensures if old(self).remaining().len() == 0 {
            result.is_none() && final(self).remaining().len() == 0
        } else {
            result == Some(&*old(self).remaining()[0]) &&
            final(self).remaining() == old(self).remaining().drop_first()
        },
    {
        while let Some(node) = self.cursor
            invariant self.remaining() == old(self).remaining(), self.start == old(self).start, self.end == old(self).end,
            ensures self.remaining() == old(self).remaining(), self.cursor.is_none(),
            decreases self.cursor,
        {
            let ghost prior = self.stack@;
            if encoding::bytewise_less(&node.entry.key,self.start) {
                self.cursor = node.right.as_ref();
            } else if !encoding::bytewise_less(&node.entry.key,self.end) {
                self.cursor = node.left.as_ref();
            } else {
                self.stack.push(node);
                self.cursor = node.left.as_ref();
                assert(self.stack@.drop_last() =~= prior);
                assert(self.remaining() =~= old(self).remaining());
            }
        }
        let ghost before = self.stack@;
        assert(old(self).remaining() == ancestors(before,self.start@,self.end@));
        let Some(node) = self.stack.pop() else {
            assert(before.len() == 0);
            return None;
        };
        assert(before.last() == node);
        self.cursor = node.right.as_ref();
        assert(before.drop_last() =~= self.stack@);
        assert(ancestors(before,self.start@,self.end@) == seq![node.entry] + rows(node.right,self.start@,self.end@) + ancestors(before.drop_last(),self.start@,self.end@));
        assert(old(self).remaining() =~= seq![node.entry] + self.remaining());
        assert(self.remaining() =~= old(self).remaining().drop_first());
        Some(&node.entry)
    }
}
pub(super) open spec fn fold(keys: Map<Seq<u8>,bool>, entries: Seq<Arc<Entry>>) -> Map<Seq<u8>,bool>
    decreases entries.len(),
{
    if entries.len() == 0 { keys } else {
        fold(keys.insert(entries[0].key@,entries[0].value.is_some()),entries.drop_first())
    }
}

/// Apply the complete selected overlay, including tombstones, to checkpoint presence.
pub(super) fn apply_presence(root: Option<&Arc<Node>>, start: &[u8], end: &[u8], keys: &mut BTreeMap<Vec<u8>,bool>)
    requires btree_map_inv(old(keys)), obeys_cmp::<Vec<u8>>(), obeys_cmp_deep_eq::<Vec<u8>>(),
    ensures btree_map_inv(final(keys)), final(keys).deep_view() ==
        fold(old(keys).deep_view(),rows(deref_option(root),start@,end@)),
{
    let mut range = Range::new(root,start,end);
    loop
        invariant btree_map_inv(keys), obeys_cmp::<Vec<u8>>(), obeys_cmp_deep_eq::<Vec<u8>>(),
            fold(keys.deep_view(), range.remaining()) == fold(old(keys).deep_view(),rows(deref_option(root),start@,end@)),
        decreases range.remaining().len(),
    {
        let ghost before = range.remaining();
        let Some(entry) = range.next_entry() else { return; };
        let mut key = Vec::with_capacity(entry.key.len());
        key.extend_from_slice(entry.key.as_slice());
        assert(key.deep_view() =~= entry.key@);
        let value = entry.value.as_ref();
        let ghost previous = keys.deep_view();
        key_projection::overlay(keys,key,value);
        assert(before[0].key@ == entry.key@);
        assert(fold(previous,before) == fold(keys.deep_view(),range.remaining()));
    }
}

}
