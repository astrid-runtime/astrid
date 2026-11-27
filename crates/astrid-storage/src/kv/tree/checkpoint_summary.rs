//! Validate the order and aggregate advertised by a checkpoint branch.
use super::{
    checkpoint_page::Branch, checkpoint_range::Child, checkpoint_totals::NodeTotals, encoding,
};
use vstd::prelude::*;

verus! {

pub(super) open spec fn ordered<I>(rows:Seq<Child<I,NodeTotals>>, n:nat) -> bool {
    forall|i:int| 1 <= i < n ==> encoding::below(rows[i-1].lower_bound@, #[trigger] rows[i].lower_bound@)
}

pub(super) open spec fn counts<I>(rows:Seq<Child<I,NodeTotals>>, n:nat) -> (nat,nat,nat)
    decreases n,
{
    if n == 0 { (0,0,0) } else {
        let prev = counts(rows,(n-1) as nat);
        let t = rows[n-1].totals;
        (prev.0+t.entries as nat,prev.1+t.logical_bytes as nat,prev.2+t.quota_bytes as nat)
    }
}

proof fn monotone<I>(rows:Seq<Child<I,NodeTotals>>,a:nat,b:nat)
    requires a <= b <= rows.len(),
    ensures counts(rows,a).0 <= counts(rows,b).0 && counts(rows,a).1 <= counts(rows,b).1 &&
        counts(rows,a).2 <= counts(rows,b).2,
    decreases b-a,
{
    if b > a { monotone(rows,a,(b-1) as nat); }
}

pub(super) fn sum<I>(rows:&[Child<I,NodeTotals>]) -> (out:Option<NodeTotals>)
    ensures ({
        let c = counts(rows@,rows.len() as nat);
        &&& out.is_some() == (c.0 <= u64::MAX && c.1 <= u64::MAX && c.2 <= u64::MAX)
        &&& out matches Some(t) ==> (t.entries as nat,t.logical_bytes as nat,t.quota_bytes as nat) == c
    }),
{
    let mut i = 0usize;
    let mut total = NodeTotals {entries:0,logical_bytes:0,quota_bytes:0};
    while i < rows.len()
        invariant i <= rows.len(),
            (total.entries as nat,total.logical_bytes as nat,total.quota_bytes as nat) == counts(rows@,i as nat),
        decreases rows.len()-i,
    {
        let value = rows[i].totals;
        proof { monotone(rows@,i as nat+1,rows.len() as nat); }
        total = NodeTotals {
            entries:total.entries.checked_add(value.entries)?,
            logical_bytes:total.logical_bytes.checked_add(value.logical_bytes)?,
            quota_bytes:total.quota_bytes.checked_add(value.quota_bytes)?,
        };
        i = i.saturating_add(1);
    }
    Some(total)
}

/// Check fence ordering before evaluating sums, preserving native error precedence.
fn canonical<I>(rows:&[Child<I,NodeTotals>],expected:NodeTotals) -> (out:Option<bool>)
    ensures out == if !ordered(rows@,rows.len() as nat) { Some(false) } else {
        let c = counts(rows@,rows.len() as nat);
        if c.0 > u64::MAX || c.1 > u64::MAX || c.2 > u64::MAX { None }
        else { Some(c == (expected.entries as nat,expected.logical_bytes as nat,expected.quota_bytes as nat)) }
    },
{
    let mut i = 1usize;
    while i < rows.len()
        invariant 1 <= i && ordered(rows@,i as nat),
        decreases rows.len()-i,
    {
        if !encoding::bytewise_less(&rows[i.saturating_sub(1)].lower_bound,&rows[i].lower_bound) { return Some(false); }
        i = i.saturating_add(1);
    }
    let t = sum(rows)?;
    Some(t.entries == expected.entries && t.logical_bytes == expected.logical_bytes && t.quota_bytes == expected.quota_bytes)
}

pub(super) enum FinishError { Trailing, NonCanonical, Overflow }

pub(super) open spec fn finished<I>(end:usize,length:usize,level:u16,children:Vec<Child<I,NodeTotals>>,totals:NodeTotals)
    -> Result<Branch<I,NodeTotals>,FinishError> {
        let c = counts(children@,children.len() as nat);
        if end != length { Err(FinishError::Trailing) }
        else if !ordered(children@,children.len() as nat) { Err(FinishError::NonCanonical) }
        else if c.0 > u64::MAX || c.1 > u64::MAX || c.2 > u64::MAX { Err(FinishError::Overflow) }
        else if c != (totals.entries as nat,totals.logical_bytes as nat,totals.quota_bytes as nat) {
            Err(FinishError::NonCanonical)
        } else { Ok(Branch {level,children,totals}) }
}

pub(super) fn finish<I>(end:usize, length:usize, level:u16, children:Vec<Child<I,NodeTotals>>, totals:NodeTotals)
    -> (out:Result<Branch<I,NodeTotals>,FinishError>)
    ensures out == finished(end,length,level,children,totals),
{
    if end != length { return Err(FinishError::Trailing); }
    match canonical(&children,totals) {
        None => Err(FinishError::Overflow),
        Some(false) => Err(FinishError::NonCanonical),
        Some(true) => Ok(Branch {level,children,totals}),
    }
}
}
