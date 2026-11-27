//! The authenticated range stack decreases when a branch expands into its children.
use crate::checkpoint_range::{Child,Page,scheduled,selected};
use vstd::prelude::*;

verus! {

// This is a ghost upper bound on the fan-out of any Rust Vec, including a
// decoder that accepts more entries than the current on-disk format.
pub(super) open spec fn capacity(height:nat) -> nat
    decreases height,
{
    if height == 0 { 1 } else { 1 + (usize::MAX as nat)*capacity((height-1) as nat) }
}

pub(super) open spec fn weight<I,T>(page:Page<I,T>) -> nat {
    match page {
        Page::Root(_) => capacity(u16::MAX as nat+1),
        Page::Child(child) => capacity(child.level as nat),
    }
}

pub(super) open spec fn rank<I,T>(stack:Seq<Page<I,T>>) -> nat
    decreases stack.len(),
{
    if stack.len()==0 { 0 } else { rank(stack.drop_last()) + weight(stack.last()) }
}

proof fn append_rank<I,T>(prefix:Seq<Page<I,T>>, suffix:Seq<Page<I,T>>)
    ensures rank(prefix+suffix) == rank(prefix)+rank(suffix),
    decreases suffix.len(),
{
    if suffix.len()>0 {
        assert((prefix+suffix).drop_last() =~= prefix+suffix.drop_last());
        assert((prefix+suffix).last() == suffix.last());
        append_rank(prefix,suffix.drop_last());
    } else { assert(prefix+suffix =~= prefix); }
}

proof fn child_bound<I,T>(rows:Seq<Child<I,T>>, at:nat, h:nat, start:Seq<u8>, end:Seq<u8>)
    requires at <= rows.len(), forall|i:int| 0 <= i < rows.len() ==> (#[trigger] rows[i]).level as nat == h,
    ensures rank(scheduled(rows,at,start,end)) <= (rows.len()-at)*capacity(h),
    decreases rows.len()-at,
{
    if at < rows.len() {
        child_bound(rows,at+1,h,start,end);
        let tail = scheduled(rows,at+1,start,end);
        if selected(rows,at as int,start,end) {
            let added = tail.push(Page::Child(rows[at as int]));
            assert(added.drop_last() =~= tail);
            assert(added.last() == Page::Child(rows[at as int]));
            assert(rows[at as int].level as nat == h);
        }
        let factor = capacity(h);
        assert((rows.len()-at)*factor == (rows.len()-(at+1))*factor + factor) by(nonlinear_arith);
    }
}

proof fn capacity_monotone(low:nat,high:nat)
    requires low <= high,
    ensures capacity(low) <= capacity(high),
    decreases high-low,
{
    if low < high {
        capacity_monotone(low,(high-1) as nat);
        let prior = capacity((high-1) as nat);
        assert(usize::MAX >= 1);
        assert(prior <= (usize::MAX as nat)*prior) by(nonlinear_arith)
            requires usize::MAX >= 1;
    }
}

// The old stack ends in the page just read. Its child level comes from the
// decoder and, for a non-root page, must agree with the authenticated pointer.
proof fn branch_progress<I,T>(pending:Seq<Page<I,T>>, page:Page<I,T>, rows:Vec<Child<I,T>>,
    level:u16,start:Seq<u8>,end:Seq<u8>)
    requires level > 0, page matches Page::Child(c) ==> c.level == level,
        forall|i:int| 0 <= i < rows.len() ==> (#[trigger] rows@[i]).level as nat+1 == level,
    ensures rank(pending+scheduled(rows@,0,start,end)) < rank(pending.push(page)),
{
    let h = (level-1) as nat;
    let w = capacity(h);
    child_bound(rows@,0,h,start,end);
    append_rank(pending,scheduled(rows@,0,start,end));
    assert(pending.push(page).drop_last() =~= pending);
    assert(pending.push(page).last() == page);
    assert(rows.len() as nat <= usize::MAX as nat);
    assert(rows.len()*w <= (usize::MAX as nat)*w) by(nonlinear_arith)
        requires rows.len() as nat <= usize::MAX as nat;
    if page is Root { capacity_monotone(level as nat,u16::MAX as nat+1); }
}
}
