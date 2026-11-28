//! Decode the declared KV mutations in wire order and consume the whole row section.
#[cfg(verus_keep_ghost)]
use super::delta_mutation;
use super::{
    ObjectReference,
    delta_mutation::{DecodeError, Mutation},
};
use super::{checkpoint_leaf_summary, checkpoint_value::ValueSlot, encoding};
use vstd::prelude::*;

verus! {
pub(super) enum Error<E> { Row(DecodeError<E>), Trailing }

pub(super) open spec fn layout<E,F:Fn(&[u8])->Option<E>>(bytes:&[u8],refs:&[ObjectReference],
    start:usize,finish:usize,rows:Seq<Mutation>,path:Seq<usize>,validate:F) -> bool {
    &&& path.len() == rows.len()+1 && path[0] == start && path.last() == finish
    &&& forall|i:int| 0 <= i < rows.len() ==> delta_mutation::decoded(bytes,path[i] as int,path[i+1],
        refs,i as usize,validate,Ok(#[trigger] rows[i]))
}

pub(super) open spec fn stopped<E,F:Fn(&[u8])->Option<E>>(bytes:&[u8],refs:&[ObjectReference],
    start:usize,count:usize,validate:F,rows:Seq<Mutation>,path:Seq<usize>,finish:usize,err:Error<E>) -> bool {
    &&& layout(bytes,refs,start,finish,rows,path,validate)
    &&& match err {
        Error::Trailing => rows.len() == count && finish != bytes.len(),
        Error::Row(e) => rows.len() < count && exists|end:usize| #[trigger] delta_mutation::decoded(
            bytes,finish as int,end,refs,rows.len() as usize,validate,Err(e)),
    }
}

pub(super) fn read<E,F:Fn(&[u8])->Option<E>+Copy>(bytes:&[u8],refs:&[ObjectReference],
    start:usize,count:usize,validate:F) -> (out:Result<Vec<Mutation>,Error<E>>)
    requires forall|key:&[u8]| #[trigger] validate.requires((key,)),
    ensures match out {
        Ok(rows) => rows.len() == count && exists|path:Seq<usize>| #[trigger] layout(bytes,refs,start,bytes.len(),rows@,path,validate),
        Err(e) => exists|rows:Seq<Mutation>,path:Seq<usize>,finish:usize| #[trigger] stopped(bytes,refs,start,count,validate,rows,path,finish,e),
    },
{
    let mut rows = Vec::with_capacity(count);
    let mut cursor = start;
    let ghost mut path = seq![start];
    while rows.len() < count
        invariant rows.len() <= count, layout(bytes,refs,start,cursor,rows@,path,validate),
            forall|key:&[u8]| #[trigger] validate.requires((key,)),
        decreases count-rows.len(),
    {
        let ghost prior = path;
        let ghost prefix = rows@;
        let ghost before = cursor;
        let i = rows.len();
        let row = match Mutation::decode(bytes,&mut cursor,refs,i,validate) {
            Ok(row) => row,
            Err(e) => {
                assert(delta_mutation::decoded(bytes,before as int,cursor,refs,rows.len() as usize,validate,Err(e)));
                assert(exists|end:usize| #[trigger] delta_mutation::decoded(bytes,before as int,end,refs,rows.len() as usize,validate,Err(e)));
                assert(layout(bytes,refs,start,before,rows@,path,validate));
                assert(stopped(bytes,refs,start,count,validate,rows@,path,before,Error::Row(e)));
                return Err(Error::Row(e));
            },
        };
        rows.push(row);
        proof {
            path = path.push(cursor);
            assert forall|j:int| 0 <= j < rows.len() implies delta_mutation::decoded(bytes,path[j] as int,path[j+1],
                refs,j as usize,validate,Ok(#[trigger] rows@[j])) by {
                if j < i {assert(rows@[j] == prefix[j] && path[j+1] == prior[j+1]);}
            }
        };
    }
    if cursor != bytes.len() {
        assert(stopped(bytes,refs,start,count,validate,rows@,path,cursor,Error::<E>::Trailing));
        return Err(Error::Trailing);
    }
    assert(layout(bytes,refs,start,bytes.len(),rows@,path,validate));
    assert(exists|p:Seq<usize>| #[trigger] layout(bytes,refs,start,bytes.len(),rows@,p,validate));
    Ok(rows)
}

pub(super) open spec fn ordered(rows:Seq<Mutation>) -> bool {
    forall|i:int| 0 < i < rows.len() ==> #[trigger] encoding::below(rows[i-1].key@,rows[i].key@)
}

pub(super) fn keys_ordered(rows:&[Mutation]) -> (ok:bool)
    ensures ok == ordered(rows@),
{
    let mut i = 1usize;
    while i < rows.len()
        invariant 1 <= i, forall|j:int| 0 < j < i && j < rows.len() ==>
            #[trigger] encoding::below(rows@[j-1].key@,rows@[j].key@),
        decreases rows.len()-i,
    {
        if !encoding::bytewise_less(&rows[i.saturating_sub(1)].key,&rows[i].key) {
            assert(!encoding::below(rows@[i as int-1].key@,rows@[i as int].key@));
            return false;
        }
        i = i.saturating_add(1);
    }
    true
}

pub(super) open spec fn usage(rows:Seq<Mutation>,n:nat) -> (nat,nat)
    decreases n,
{
    if n == 0 { (0,0) } else {
        let prior = usage(rows,(n-1) as nat);
        let row = rows[n-1];
        (prior.0 + row.key.len() as nat + match row.value {None=>0nat,Some(v)=>checkpoint_leaf_summary::size(v)},
         prior.1 + if row.value matches Some(ValueSlot::Spilled {..}) {1nat} else {0nat})
    }
}

proof fn monotone(rows:Seq<Mutation>,i:nat,n:nat)
    requires i <= n <= rows.len(),
    ensures usage(rows,i).0 <= usage(rows,n).0,
    decreases n-i,
{
    if i < n {monotone(rows,i,(n-1) as nat);}
}

/// Key bytes plus logical value lengths, and the number of owning spill edges.
pub(super) fn measure(rows:&[Mutation]) -> (out:Option<(u64,usize)>)
    ensures out.is_some() == (usage(rows@,rows.len() as nat).0 <= u64::MAX),
        out matches Some((n,s)) ==> (n as nat,s as nat) == usage(rows@,rows.len() as nat),
{
    let mut total = 0u64;
    let mut spills = 0usize;
    let mut i = 0usize;
    while i < rows.len()
        invariant i <= rows.len(), spills <= i, (total as nat,spills as nat) == usage(rows@,i as nat),
        decreases rows.len()-i,
    {
        proof {monotone(rows@,i as nat+1,rows.len() as nat);}
        let row = &rows[i];
        let width = u64::try_from(row.key.len()).ok()?;
        total = total.checked_add(width)?;
        if let Some(value) = &row.value {
            total = total.checked_add(checkpoint_leaf_summary::length(value)?)?;
            if matches!(value,ValueSlot::Spilled {..}) {spills = spills.saturating_add(1);}
        }
        i = i.saturating_add(1);
    }
    Some((total,spills))
}

pub(super) enum AuditError { NonCanonical, Overflow, References }

pub(super) fn audit(rows:&[Mutation],delta_bytes:u64,previous:bool,edges:usize) -> (out:Result<(),AuditError>)
    ensures ({
        let (n,s) = usage(rows@,rows.len() as nat);
        let expected = s + if previous {1nat} else {0nat};
        out == if !ordered(rows@) {Err(AuditError::NonCanonical)}
            else if n > u64::MAX {Err(AuditError::Overflow)}
            else if n > delta_bytes {Err(AuditError::NonCanonical)}
            else if expected > usize::MAX {Err(AuditError::Overflow)}
            else if expected != edges {Err(AuditError::References)} else {Ok(())}
    }),
{
    if !keys_ordered(rows) {return Err(AuditError::NonCanonical);}
    let (n,spills) = measure(rows).ok_or(AuditError::Overflow)?;
    if n > delta_bytes {return Err(AuditError::NonCanonical);}
    let expected = if previous {
        spills.checked_add(1).ok_or(AuditError::Overflow)?
    } else {
        spills
    };
    if expected != edges {return Err(AuditError::References);}
    Ok(())
}
}
