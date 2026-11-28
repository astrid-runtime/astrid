//! Point lookup in an owned, decoded checkpoint leaf.
use super::{
    ObjectId, checkpoint_entries::Row, checkpoint_range::Child, checkpoint_totals::NodeTotals,
    checkpoint_value::ValueSlot, encoding,
};
#[cfg(verus_keep_ghost)]
use super::{checkpoint_leaf_summary::ordered, checkpoint_summary};
#[cfg(verus_keep_ghost)]
use crate::byte_order::{strict_order, transitive};
use std::cmp::Ordering;
use vstd::prelude::*;

verus! {
proof fn ordered_pair(rows:Seq<Row>,i:int,j:int)
    requires ordered(rows,rows.len()),0 <= i < j < rows.len(),
    ensures encoding::below(rows[i].key@,rows[j].key@),
    decreases j-i,
{
    if i+1 < j {
        ordered_pair(rows,i,j-1);
        transitive(rows[i].key@,rows[j-1].key@,rows[j].key@);
    }
}

/// A hit always has the requested key. Canonical order also rules out false misses.
pub(super) fn leaf(input:Vec<Row>,key:&[u8]) -> (out:Option<ValueSlot>)
    ensures
        out matches Some(v) ==> exists|i:int| 0 <= i < input.len() &&
            (#[trigger] input@[i]).key@ == key@ && input@[i].value == v,
        ordered(input@,input.len() as nat) ==> forall|i:int| 0 <= i < input.len() &&
            (#[trigger] input@[i]).key@ == key@ ==> out == Some(input@[i].value),
{
    let mut lo = 0usize;
    let mut hi = input.len();
    while lo < hi
        invariant lo <= hi <= input.len(),
            ordered(input@,input.len() as nat) ==> forall|i:int| 0 <= i < input.len() &&
                (#[trigger] input@[i]).key@ == key@ ==> lo <= i < hi,
        decreases hi-lo,
    {
        let mid = lo.saturating_add(hi.saturating_sub(lo)/2);
        let order = encoding::bytewise_cmp(&input[mid].key,key);
        proof {
            if ordered(input@,input.len() as nat) {
                assert forall|i:int| 0 <= i < input.len() && (#[trigger] input@[i]).key@ == key@ implies
                    (i < mid ==> order == Ordering::Greater) && (i > mid ==> order == Ordering::Less) by {
                    if i < mid {ordered_pair(input@,i,mid as int);strict_order(key@,input@[mid as int].key@);}
                    if i > mid {ordered_pair(input@,mid as int,i);}
                }
            }
        }
        match order {
            Ordering::Less => lo = mid.saturating_add(1),
            Ordering::Greater => hi = mid,
            Ordering::Equal => {
                let mut rows = input;
                let selected = rows.swap_remove(mid);
                return Some(selected.value);
            },
        }
    }
    None
}
type Pointer = Child<ObjectId,NodeTotals>;

proof fn bounds(rows:Seq<Pointer>,i:int,j:int)
    requires checkpoint_summary::ordered(rows,rows.len()),0 <= i < j < rows.len(),
    ensures encoding::below(rows[i].lower_bound@,rows[j].lower_bound@),
    decreases j-i,
{
    if i+1 < j {
        bounds(rows,i,j-1);
        transitive(rows[i].lower_bound@,rows[j-1].lower_bound@,rows[j].lower_bound@);
    }
}

/// Route to the last child whose lower bound is at or below the key.
/// Keys before the first fence use the first child, including for insertion.
pub(super) fn child(children:&[Pointer],key:&[u8]) -> (index:usize)
    ensures
        children.len() == 0 ==> index == 0,
        children.len() > 0 ==> index < children.len(),
        checkpoint_summary::ordered(children@,children.len() as nat) ==> {
            &&& forall|i:int| 0 <= i <= index && i < children.len() && index > 0 ==>
                !encoding::below(key@,(#[trigger] children@[i]).lower_bound@)
            &&& forall|i:int| index < i < children.len() ==>
                encoding::below(key@,(#[trigger] children@[i]).lower_bound@)
        },
{
    let mut lo = 0usize;
    let mut hi = children.len();
    while lo < hi
        invariant lo <= hi <= children.len(),
            checkpoint_summary::ordered(children@,children.len() as nat) ==> {
                &&& forall|i:int| 0 <= i < lo ==> !encoding::below(key@,(#[trigger] children@[i]).lower_bound@)
                &&& forall|i:int| hi <= i < children.len() ==> encoding::below(key@,(#[trigger] children@[i]).lower_bound@)
            },
        decreases hi-lo,
    {
        let mid = lo.saturating_add(hi.saturating_sub(lo)/2);
        if encoding::bytewise_less(key,&children[mid].lower_bound) {
            proof {
                if checkpoint_summary::ordered(children@,children.len() as nat) {
                    assert forall|i:int| mid < i < children.len() implies encoding::below(key@,(#[trigger] children@[i]).lower_bound@) by {
                        bounds(children@,mid as int,i);
                        transitive(key@,children@[mid as int].lower_bound@,children@[i].lower_bound@);
                    }
                }
            }
            hi = mid;
        } else {
            proof {
                if checkpoint_summary::ordered(children@,children.len() as nat) {
                    assert forall|i:int| 0 <= i < mid implies !encoding::below(key@,(#[trigger] children@[i]).lower_bound@) by {
                        if encoding::below(key@,children@[i].lower_bound@) {
                            bounds(children@,i,mid as int);
                            transitive(key@,children@[i].lower_bound@,children@[mid as int].lower_bound@);
                        }
                    }
                }
            }
            lo = mid.saturating_add(1);
        }
    }
    lo.saturating_sub(1)
}

}
