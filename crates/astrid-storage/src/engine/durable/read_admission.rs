//! Recheck a loaded record against the current arena before offering it to the cache.
use super::ObjectId;
use vstd::prelude::*;

verus! {
pub(super) fn retain<P,R,C,M,F>(principal:&P,id:ObjectId,observed:u64,current:u64,
    record:R,present:M,insert:F) -> (out:Option<C>)
    where M:FnOnce(ObjectId)->bool, F:FnOnce(&P,ObjectId,R)->C,
    requires observed == current ==> present.requires((id,)),
        observed == current && present.ensures((id,),true) ==> insert.requires((principal,id,record)),
    ensures match out {
        None => observed != current || present.ensures((id,),false),
        Some(kept) => observed == current && present.ensures((id,),true) &&
            insert.ensures((principal,id,record),kept),
    },
{
    if observed != current || !present(id) { return None; }
    Some(insert(principal,id,record))
}
pub(super) enum Attempt<C> { Missing, Retry, Found(C) }

pub(super) open spec fn offered<R,L,E,D:FnOnce(u64,ObjectId,L)->Result<Option<R>,E>>(
    id:ObjectId,generation:u64,pending:Option<R>,location:Option<L>,read:D,r:R,
) -> bool {
    match pending {
        Some(p) => r == p,
        None => location matches Some(loc) && read.ensures((generation,id,loc),Ok(Some(r))),
    }
}

/// Resolve one locked snapshot. A pending WAL record takes precedence over its
/// arena location. Losing either generation check asks the caller to resample.
pub(super) fn attempt<P,R,L,C,E,D,F>(principal:&P,id:ObjectId,generation:u64,pending:Option<R>,location:Option<L>,
    read:D,retain:F) -> (out:Result<Attempt<C>,E>)
    where D:FnOnce(u64,ObjectId,L)->Result<Option<R>,E>,F:FnOnce(&P,ObjectId,u64,R)->Result<Option<C>,E>,
    requires pending.is_none() ==> (location matches Some(loc) ==> read.requires((generation,id,loc))),
        forall|r:R| #[trigger] offered(id,generation,pending,location,read,r) ==> retain.requires((principal,id,generation,r)),
    ensures match out {
        Ok(Attempt::Missing) => pending.is_none() && location.is_none(),
        Ok(Attempt::Found(c)) => exists|r:R| #[trigger] offered(id,generation,pending,location,read,r) &&
            retain.ensures((principal,id,generation,r),Ok(Some(c))),
        Ok(Attempt::Retry) => (pending.is_none() && (location matches Some(loc) && read.ensures((generation,id,loc),Ok(None)))) ||
            exists|r:R| #[trigger] offered(id,generation,pending,location,read,r) && retain.ensures((principal,id,generation,r),Ok(None)),
        Err(e) => (pending.is_none() && (location matches Some(loc) && read.ensures((generation,id,loc),Err(e)))) ||
            exists|r:R| #[trigger] offered(id,generation,pending,location,read,r) && retain.ensures((principal,id,generation,r),Err(e)),
    },
{
    let r = if let Some(r) = pending { r } else {
        let Some(loc) = location else { return Ok(Attempt::Missing); };
        let Some(r) = read(generation,id,loc)? else { return Ok(Attempt::Retry); };
        r
    };
    assert(offered(id,generation,pending,location,read,r));
    match retain(principal,id,generation,r)? {Some(c)=>Ok(Attempt::Found(c)),None=>Ok(Attempt::Retry)}
}

}
