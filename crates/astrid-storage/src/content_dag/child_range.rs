//! Select chunk-tree children for a range using their decoded order and lengths.
use super::ObjectId;
use vstd::prelude::*;

verus! {
pub(super) struct Visit {
    pub(super) index: usize,
    pub(super) object: ObjectId,
    pub(super) length: u64,
    pub(super) chunks: u64,
    pub(super) base: u64,
}

pub(super) open spec fn length(children:Seq<(ObjectId,u64,u64)>) -> nat
    decreases children.len(),
{
    if children.len() == 0 { 0 } else { length(children.drop_last()) + children.last().1 as nat }
}

pub(super) open spec fn visits(children:Seq<(ObjectId,u64,u64)>, base:u64, start:u64, end:u64) -> Seq<Visit>
    decreases children.len(),
{
    if children.len() == 0 { Seq::empty() } else {
        let prefix = children.drop_last();
        let before = visits(prefix,base,start,end);
        let at = base + length(prefix);
        let (object,len,chunks) = children.last();
        if start < at+len && end > at {
            before.push(Visit { index:prefix.len() as usize,object,length:len,chunks,base:at as u64 })
        } else { before }
    }
}

pub(super) fn select(children:&[(ObjectId,u64,u64)],base:u64,start:u64,end:u64)
    -> (out:Option<Vec<Visit>>)
    ensures out.is_some() == (base + length(children@) <= u64::MAX),
        out matches Some(plan) ==> plan@ == visits(children@,base,start,end),
{
    let mut chosen = Vec::new();
    let mut cursor = base;
    let mut index = 0usize;
    while index < children.len()
        invariant index <= children.len(), cursor == base + length(children@.take(index as int)),
            chosen@ == visits(children@.take(index as int),base,start,end),
        decreases children.len()-index,
    {
        let (object,len,chunks) = children[index];
        let ghost prefix = children@.take(index as int);
        let ghost next_prefix = children@.take(index as int+1);
        assert(next_prefix.drop_last() =~= prefix);
        assert(next_prefix.last() == children@[index as int]);
        let Some(next) = cursor.checked_add(len) else {
            proof { prefix_bound(children@,index as nat+1); }
            return None;
        };
        if start < next && end > cursor {
            chosen.push(Visit { index,object,length:len,chunks,base:cursor });
        }
        cursor = next;
        index = index.saturating_add(1);
    }
    assert(children@.take(index as int) =~= children@);
    Some(chosen)
}

proof fn prefix_bound(children:Seq<(ObjectId,u64,u64)>,n:nat)
    requires n <= children.len(),
    ensures length(children.take(n as int)) <= length(children),
    decreases children.len()-n,
{
    if n < children.len() {
        assert(children.drop_last().take(n as int) =~= children.take(n as int));
        prefix_bound(children.drop_last(),n);
    } else { assert(children.take(n as int) =~= children); }
}
}
