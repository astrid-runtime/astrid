//! Assemble the replay head from a selected delta record.
#[cfg(verus_keep_ghost)]
use super::ObjectReference;
use super::{
    ObjectId, ObjectRecord, checkpoint_totals::NodeTotals, delta_batch as batch,
    delta_header as header, delta_mutation::Mutation,
};
use vstd::prelude::*;

verus! {
pub(super) struct Recovered {
    pub(super) previous:Option<ObjectId>,
    pub(super) depth:u64,
    pub(super) delta_bytes:u64,
    pub(super) rows:Vec<Mutation>,
    pub(super) totals:NodeTotals,
}

pub(super) enum Error<E> {
    Truncated, Count, Empty, NonOwning, Batch(batch::Error<E>), Audit(batch::AuditError),
}

pub(super) open spec fn admitted<E,F:Fn(&[u8])->Option<E>>(record:&ObjectRecord,validate:F,r:Recovered,
    bytes:&[u8],refs:&[ObjectReference],path:Seq<usize>) -> bool {
    let stored = record.contents();
    let h = header::Header {depth:r.depth,delta_bytes:r.delta_bytes,entries:r.totals.entries,
        quota_bytes:r.totals.quota_bytes,count:r.rows.len() as u32};
    let predecessor = super::reference_lookup::selected(refs@,header::PREVIOUS@,0,refs.len() as int);
    let (charge,spills) = batch::usage(r.rows@,r.rows.len() as nat);
    &&& bytes@ == stored.2 && refs@ == stored.3 && r.totals.logical_bytes == stored.4
    &&& bytes.len() >= 37 && bytes@.subrange(1,37) == h.wire()
    &&& 0 < r.rows.len() <= u32::MAX && r.depth != 0
    &&& match predecessor {
        Some(edge) => edge.fields().2 is Owns && r.previous == Some(edge.fields().1),
        None => r.previous.is_none(),
    }
    &&& batch::layout(bytes,refs,37,bytes.len(),r.rows@,path,validate)
    &&& batch::ordered(r.rows@) && charge <= r.delta_bytes
    &&& refs.len() == spills + (if r.previous.is_some() {1nat} else {0nat})
}

pub(super) open spec fn audit_refusal(rows:Seq<Mutation>,limit:u64,previous:bool,edges:nat,ae:batch::AuditError) -> bool {
    let (n,spills) = batch::usage(rows,rows.len());
    let expected = spills + if previous {1nat} else {0nat};
    match ae {
        batch::AuditError::NonCanonical => !batch::ordered(rows) || (n <= u64::MAX && n > limit),
        batch::AuditError::Overflow => batch::ordered(rows) && (n > u64::MAX || (n <= limit && expected > usize::MAX)),
        batch::AuditError::References => batch::ordered(rows) && n <= limit && expected <= usize::MAX && expected != edges,
    }
}

pub(super) open spec fn refused<E,F:Fn(&[u8])->Option<E>>(bytes:&[u8],refs:&[ObjectReference],
    validate:F,h:header::Header,e:Error<E>) -> bool {
    let pred = super::reference_lookup::selected(refs@,header::PREVIOUS@,0,refs.len() as int);
    let count = h.count as usize;
    &&& bytes.len() >= 37 && bytes@.subrange(1,37) == h.wire()
    &&& match e {
        Error::Truncated => false,
        Error::Count => h.count > usize::MAX,
        Error::Empty => h.count <= usize::MAX && (count == 0 || h.depth == 0),
        _ => {
            &&& h.count <= usize::MAX && count > 0 && h.depth > 0
            &&& match e {
                Error::NonOwning => pred matches Some(r) && !(r.fields().2 is Owns),
                _ => {
                    &&& pred matches Some(r) ==> r.fields().2 is Owns
                    &&& match e {
                        Error::Batch(be) => exists|rows:Seq<Mutation>,p:Seq<usize>,end:usize|
                            #[trigger] batch::stopped(bytes,refs,37,count,validate,rows,p,end,be),
                        Error::Audit(ae) => exists|rows:Seq<Mutation>,p:Seq<usize>| {
                            &&& rows.len() == count && #[trigger] batch::layout(bytes,refs,37,bytes.len(),rows,p,validate)
                            &&& audit_refusal(rows,h.delta_bytes,pred.is_some(),refs.len() as nat,ae)
                        },
                        _ => false,
                    }
                },
            }
        },
    }
}

pub(super) fn decode<E,F:Fn(&[u8])->Option<E>+Copy>(record:&ObjectRecord,validate:F)
    -> (out:Result<Recovered,Error<E>>)
    requires forall|k:&[u8]| #[trigger] validate.requires((k,)),
    ensures out matches Ok(r) ==> exists|bytes:&[u8],refs:&[ObjectReference],path:Seq<usize>|
        #[trigger] admitted(record,validate,r,bytes,refs,path),
        (out matches Err(Error::Truncated)) == (record.contents().2.len() < 37),
        out matches Err(e) ==> !(e is Truncated) ==> exists|h:header::Header,bytes:&[u8],refs:&[ObjectReference]|
            bytes@ == record.contents().2 && refs@ == record.contents().3 && #[trigger] refused(bytes,refs,validate,h,e),
{
    let bytes = record.canonical_bytes();
    let refs = record.references();
    let Ok((h,offset)) = header::Header::read(bytes) else {return Err(Error::Truncated);};
    let Ok(count) = usize::try_from(h.count) else {assert(refused(bytes,refs,validate,h,Error::<E>::Count)); return Err(Error::Count);};
    if h.depth == 0 || count == 0 {assert(refused(bytes,refs,validate,h,Error::<E>::Empty)); return Err(Error::Empty);}
    let Ok(previous) = header::predecessor(refs) else {assert(refused(bytes,refs,validate,h,Error::<E>::NonOwning)); return Err(Error::NonOwning);};
    let rows = match batch::read(bytes,refs,offset,count,validate) {
        Ok(rows) => rows, Err(e) => {assert(refused(bytes,refs,validate,h,Error::Batch(e))); return Err(Error::Batch(e));},
    };
    if let Err(e) = batch::audit(&rows,h.delta_bytes,previous.is_some(),refs.len()) {
        proof {
            let p = choose|p:Seq<usize>| #[trigger] batch::layout(bytes,refs,37,bytes.len(),rows@,p,validate);
            assert(batch::layout(bytes,refs,37,bytes.len(),rows@,p,validate));
            assert(refused(bytes,refs,validate,h,Error::<E>::Audit(e)));
        }
        return Err(Error::Audit(e));
    }
    let totals = NodeTotals {entries:h.entries,logical_bytes:record.logical_bytes(),quota_bytes:h.quota_bytes};
    let recovered = Recovered {previous,depth:h.depth,delta_bytes:h.delta_bytes,rows,totals};
    proof {
        let p = choose|p:Seq<usize>| #[trigger] batch::layout(bytes,refs,37,bytes.len(),recovered.rows@,p,validate);
        assert(admitted(record,validate,recovered,bytes,refs,p));
    }
    Ok(recovered)
}

pub(super) enum CounterError { Disagree, RowOverflow, ChainOverflow }

/// Reconcile the declared cumulative fields against the preceding replay step.
pub(super) fn counters(prior_depth:u64,prior_bytes:u64,depth:u64,bytes:u64,rows:&[Mutation])
    -> (out:Result<(),CounterError>)
    ensures ({
        let charge = batch::usage(rows@,rows.len() as nat).0;
        let next_depth = if prior_depth < u64::MAX {prior_depth as nat+1} else {u64::MAX as nat};
        out == if depth != next_depth {Err(CounterError::Disagree)}
            else if charge > u64::MAX {Err(CounterError::RowOverflow)}
            else if prior_bytes as nat + charge > u64::MAX {Err(CounterError::ChainOverflow)}
            else if bytes != prior_bytes as nat + charge {Err(CounterError::Disagree)}
            else {Ok(())}
    }),
{
    if depth != prior_depth.saturating_add(1) {return Err(CounterError::Disagree);}
    let (charge,_) = batch::measure(rows).ok_or(CounterError::RowOverflow)?;
    let expected = prior_bytes.checked_add(charge).ok_or(CounterError::ChainOverflow)?;
    if bytes != expected {return Err(CounterError::Disagree);}
    Ok(())
}
}
