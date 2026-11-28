//! An authenticated child containing a requested key must reach the traversal stack.
use crate::{checkpoint_range::{self,Child,Page,scheduled,selected},encoding};
use vstd::prelude::*;

verus! {

proof fn scheduled_contains<I,T>(rows:Seq<Child<I,T>>, at:nat, i:int, start:Seq<u8>, end:Seq<u8>)
    requires at <= i < rows.len(), selected(rows,i,start,end),
    ensures scheduled(rows,at,start,end).contains(Page::Child(rows[i])),
    decreases i-at,
{
    let tail = scheduled(rows,at+1,start,end);
    let all = scheduled(rows,at,start,end);
    if at < i {
        scheduled_contains(rows,at+1,i,start,end);
        let j = choose|j:int| 0 <= j < tail.len() && #[trigger] tail[j] == Page::Child(rows[i]);
        assert(all[j] == tail[j]);
    } else {
        assert(all[tail.len() as int] == Page::Child(rows[i]));
    }
}

fn schedule_covering<I:Copy,T>(rows:Vec<Child<I,T>>, stack:&mut Vec<Page<I,T>>,
    i:usize, key:&[u8], start:&[u8], end:&[u8])
    requires i < rows.len(), encoding::range_contains(start@,end@,key@),
        !encoding::below(key@,rows@[i as int].lower_bound@),
        i+1 < rows.len() ==> encoding::below(key@,rows@[i+1].lower_bound@),
    ensures final(stack)@.contains(Page::Child(rows@[i as int])),
        final(stack)@ == old(stack)@ + scheduled(rows@,0,start@,end@),
{
    let upper = if i < rows.len()-1 { Some(rows[i+1].lower_bound.as_slice()) } else { None };
    let included = encoding::visit_child(&rows[i].lower_bound,upper,start,end);
    assert(included);
    proof { scheduled_contains(rows@,0,i as int,start@,end@); }
    let ghost tail = scheduled(rows@,0,start@,end@);
    let ghost j = choose|j:int| 0 <= j < tail.len() && #[trigger] tail[j] == Page::Child(rows@[i as int]);
    let ghost offset = stack@.len();
    checkpoint_range::schedule(rows,stack,start,end);
    assert(stack@[offset+j] == tail[j]);
}

// A left-to-right visit pops the full left pointer before its sibling.
fn siblings<I,T>(rows:Vec<Child<I,T>>, stack:&mut Vec<Page<I,T>>, start:&[u8], end:&[u8])
    requires rows.len() == 2, selected(rows@,0,start@,end@), selected(rows@,1,start@,end@),
    ensures final(stack)@ == old(stack)@.push(Page::Child(rows@[1])).push(Page::Child(rows@[0])),
{
    proof { reveal_with_fuel(scheduled,3); }
    checkpoint_range::schedule(rows,stack,start,end);
    assert(stack@ =~= old(stack)@.push(Page::Child(rows@[1])).push(Page::Child(rows@[0])));
}

fn authenticate(child:&Child<u64,u64>, object:u64, lower:&[u8], level:u16, totals:u64)
    -> (accepted:bool)
    ensures accepted == (child.object == object && child.lower_bound@ == lower@ &&
        child.level == level && child.totals == totals),
{
    let equal = |a:&u64,b:&u64| -> (yes:bool) ensures yes == (*a == *b) {*a == *b};
    child.matches(&object,lower,level,&totals,equal,equal)
}

// The decoder receives the object ID from the popped pointer, with the same
// lower fence, level and totals still available for authentication.
fn pop_child<I:Copy,T>(stack:&mut Vec<Page<I,T>>) -> (out:Option<I>)
    requires old(stack)@.len() > 0,
    ensures out == Some(match old(stack)@.last() { Page::Root(id) => id, Page::Child(c) => c.object }),
        final(stack)@ == old(stack)@.drop_last(),
{
    let page = stack.pop()?;
    Some(page.object())
}
}
