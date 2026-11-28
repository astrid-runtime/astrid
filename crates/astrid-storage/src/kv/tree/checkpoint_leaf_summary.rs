//! Canonical fence order and checked logical and quota sums over decoded leaf entries.
use super::{
    checkpoint_entries::Row, checkpoint_page::Leaf, checkpoint_totals::NodeTotals,
    checkpoint_value::ValueSlot, encoding,
};
use vstd::prelude::*;

verus! {
pub(super) open spec fn size(v:ValueSlot) -> nat {
    match v {ValueSlot::Inline(d) => d.len() as nat,ValueSlot::Spilled {length,..} => length as nat}
}
pub(super) open spec fn usage(rows:Seq<Row>,n:nat) -> (nat,nat)
    decreases n,
{
    if n == 0 {(0,0)} else {
        let prior = usage(rows,(n-1) as nat);
        let row = rows[n-1];
        (prior.0+size(row.value),prior.1+size(row.value)+row.key.len() as nat)
    }
}

proof fn monotone(rows:Seq<Row>,i:nat,n:nat)
    requires i <= n <= rows.len(),
    ensures usage(rows,i).0 <= usage(rows,n).0 && usage(rows,i).1 <= usage(rows,n).1,
    decreases n-i,
{
    if n > i {monotone(rows,i,(n-1) as nat);}
}

pub(super) fn length(value:&ValueSlot) -> (out:Option<u64>)
    ensures out.is_some() == (size(*value) <= u64::MAX), out matches Some(n) ==> n == size(*value),
{
    match value {ValueSlot::Inline(d)=>u64::try_from(d.len()).ok(),ValueSlot::Spilled {length,..}=>Some(*length)}
}

pub(super) fn charge(row:&Row) -> (out:Option<NodeTotals>)
    ensures out.is_some() == (size(row.value)+row.key.len() <= u64::MAX),
        out matches Some(t) ==> t.entries == 1 && t.logical_bytes == size(row.value) &&
            t.quota_bytes == size(row.value)+row.key.len(),
{
    let key = u64::try_from(row.key.len()).ok()?;
    let bytes = length(&row.value)?;
    Some(NodeTotals {entries:1,logical_bytes:bytes,quota_bytes:key.checked_add(bytes)?})
}

pub(super) fn sum(rows:&[Row]) -> (out:Option<NodeTotals>)
    ensures ({
        let u = usage(rows@,rows.len() as nat);
        &&& out.is_some() == (rows.len() <= u64::MAX && u.0 <= u64::MAX && u.1 <= u64::MAX)
        &&& out matches Some(t) ==> t.entries == rows.len() && t.logical_bytes == u.0 && t.quota_bytes == u.1
    }),
{
    let mut i = 0usize;
    let mut logical = 0u64; let mut quota = 0u64;
    while i < rows.len()
        invariant i <= rows.len(), (logical as nat,quota as nat) == usage(rows@,i as nat),
        decreases rows.len()-i,
    {
        proof {monotone(rows@,i as nat+1,rows.len() as nat);}
        let t = charge(&rows[i])?;
        logical = logical.checked_add(t.logical_bytes)?;
        quota = quota.checked_add(t.quota_bytes)?;
        i = i.saturating_add(1);
    }
    Some(NodeTotals {entries:u64::try_from(rows.len()).ok()?,logical_bytes:logical,quota_bytes:quota})
}

pub(super) open spec fn ordered(rows:Seq<Row>,n:nat) -> bool {
    forall|i:int| 1 <= i < n ==> encoding::below(rows[i-1].key@,#[trigger] rows[i].key@)
}

pub(super) enum Error { NonCanonical, Overflow }

pub(super) open spec fn outcome(rows:Vec<Row>,totals:NodeTotals) -> Result<Leaf<ValueSlot,NodeTotals>,Error> {
    let n = rows.len() as nat;
    let u = usage(rows@,n);
    if !ordered(rows@,n) {Err(Error::NonCanonical)}
    else if n > u64::MAX || u.0 > u64::MAX || u.1 > u64::MAX {Err(Error::Overflow)}
    else if n != totals.entries || u.0 != totals.logical_bytes || u.1 != totals.quota_bytes {Err(Error::NonCanonical)}
    else {Ok(Leaf {entries:rows,totals})}
}

pub(super) fn finish(rows:Vec<Row>,totals:NodeTotals) -> (out:Result<Leaf<ValueSlot,NodeTotals>,Error>)
    ensures out == outcome(rows,totals),
{
    let mut i = 1usize;
    while i < rows.len()
        invariant i >= 1 && ordered(rows@,i as nat),
        decreases rows.len()-i,
    {
        if !encoding::bytewise_less(&rows[i.saturating_sub(1)].key,&rows[i].key) {return Err(Error::NonCanonical);}
        i = i.saturating_add(1);
    }
    let Some(t) = sum(&rows) else {return Err(Error::Overflow);};
    if t.entries != totals.entries || t.logical_bytes != totals.logical_bytes || t.quota_bytes != totals.quota_bytes {
        return Err(Error::NonCanonical);
    }
    Ok(Leaf {entries:rows,totals})
}
}
