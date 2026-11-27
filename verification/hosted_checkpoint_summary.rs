//! Check the native branch admission at its header, finish and decoded page boundaries.
use crate::{ObjectId,ObjectReference,checkpoint_page::Branch,checkpoint_range::Child,
    checkpoint_branch::{self,Header,DecodeError},checkpoint_summary::{self as summary,FinishError},
    checkpoint_totals::NodeTotals,encoding};
use vstd::prelude::*;

verus! {

fn pair<I>(end:usize,len:usize,left:Child<I,NodeTotals>,right:Child<I,NodeTotals>,claimed:NodeTotals)
    -> (out:Result<Branch<I,NodeTotals>,FinishError>)
    ensures ({
        let a = left.totals; let b = right.totals;
        let entries = a.entries as int+b.entries;
        let logical = a.logical_bytes as int+b.logical_bytes;
        let quota = a.quota_bytes as int+b.quota_bytes;
        if end != len { out == Err(FinishError::Trailing) }
        else if !encoding::below(left.lower_bound@,right.lower_bound@) { out == Err(FinishError::NonCanonical) }
        else if entries > u64::MAX || logical > u64::MAX || quota > u64::MAX { out == Err(FinishError::Overflow) }
        else if entries != claimed.entries || logical != claimed.logical_bytes || quota != claimed.quota_bytes {
            out == Err(FinishError::NonCanonical)
        } else { out matches Ok(b) && b.level == 1 && b.totals == claimed && b.children@ == seq![left,right] }
    }),
{
    let mut rows = Vec::new();
    rows.push(left); rows.push(right);
    proof {
        reveal_with_fuel(summary::counts,3);
        assert(rows@ =~= seq![left,right]);
        assert(summary::ordered(rows@,2) == encoding::below(left.lower_bound@,right.lower_bound@));
    }
    summary::finish(end,len,1,rows,claimed)
}

fn from_record(bytes:&[u8],refs:&[ObjectReference],start:usize,level:u16,count:usize,totals:NodeTotals)
    -> (out:Result<Branch<ObjectId,NodeTotals>,DecodeError<()>>)
    ensures (out matches Err(DecodeError::Header)) ==
        (level == 0 || level > 16 || count < 2 || count > 64 || count != refs.len()),
        out matches Ok(b) ==> b.level == level && b.totals == totals && b.children.len() == count &&
            summary::counts(b.children@,b.children.len() as nat) ==
                (totals.entries as nat,totals.logical_bytes as nat,totals.quota_bytes as nat) &&
            (forall|i:int| 1 <= i < count ==> encoding::below(b.children@[i-1].lower_bound@,#[trigger] b.children@[i].lower_bound@)) &&
            (forall|i:int| 0 <= i < count ==> (#[trigger] b.children@[i]).object == refs@[i].fields().1),
{
    let accept = |_:&[u8]| -> (r:Result<(),()>) ensures r is Ok { Ok(()) };
    let header = Header {level,count,totals};
    let out = header.decode(bytes,refs,start,accept);
    proof {
        if out is Ok {
            let b = out->Ok_0;
            let p = choose|p:Seq<usize>| #[trigger] checkpoint_branch::layout(bytes@,refs@,start,bytes.len(),level,b.children@,p,accept);
            assert forall|i:int| 0 <= i < count implies (#[trigger] b.children@[i]).object == refs@[i].fields().1 by {
                assert(checkpoint_branch::row_at(bytes@,refs@,i,p[i],p[i+1],level,b.children@[i],accept));
            }
        }
    }
    out
}
}
