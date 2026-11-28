//! Recheck a loaded record against the current arena before offering it to the cache.
use super::{ArenaLocation, ObjectId, ObjectRecord, RootState};
use std::{collections::BTreeMap, sync::Arc};
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_cmp::{obeys_cmp, obeys_cmp_concrete_eq},
    std_specs::btree::btree_map_inv,
};

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

/// Retained after the durable frontier and root publication. Cache warming
/// must still match the principal's root, the arena generation and placement.
pub(super) struct PublishedCommitPayload {
    pub(super) root: RootState,
    pub(super) arena_generation: u64,
    pub(super) location: ArenaLocation,
    pub(super) payload: Arc<[u8]>,
}

impl PublishedCommitPayload {
    pub(super) open spec fn current<P>(&self,owner:P,generation:u64,roots:Map<P,RootState>,index:Map<ObjectId,ArenaLocation>) -> bool {
        &&& self.arena_generation == generation
        &&& roots.contains_key(owner) && roots[owner] == self.root
        &&& index.contains_key(self.root.commit) && index[self.root.commit] == self.location
    }

    pub(super) fn prepare<H,D>(&self,checksum:H,confirm:D) -> (out:Option<WarmRecord<'_>>)
        where H:FnOnce(u64,&[u8])->[u8;32],D:FnOnce(&[u8],ObjectId)->Option<ObjectRecord>,
        requires checksum.requires(((*self.payload).len() as u64,&*self.payload)),
            confirm.requires((&*self.payload,self.root.commit)),
        ensures ({
            let b = &*self.payload;
            match out {
                Some(w) => w.parts().0 == *self && b.len() == self.location.payload_len &&
                    checksum.ensures((self.location.payload_len,b),self.location.checksum) &&
                    confirm.ensures((b,self.root.commit),Some(w.parts().1)),
                None => b.len() != self.location.payload_len ||
                    (exists|s:[u8;32]| #[trigger] checksum.ensures((self.location.payload_len,b),s) && s != self.location.checksum) ||
                    confirm.ensures((b,self.root.commit),None),
            }
        }),
    {
        let bytes:&[u8] = &self.payload;
        let len = u64::try_from(bytes.len()).ok()?;
        if len != self.location.payload_len {return None;}
        let sum = checksum(len,bytes);
        if sum.as_slice() != self.location.checksum.as_slice() {return None;}
        assert(sum =~= self.location.checksum);
        Some(WarmRecord { published:self, record:confirm(bytes,self.root.commit)? })
    }
}

pub(super) struct WarmRecord<'a> {
    published:&'a PublishedCommitPayload,
    record:ObjectRecord,
}

impl WarmRecord<'_> {
    pub(super) closed spec fn parts(&self) -> (PublishedCommitPayload,ObjectRecord) {(*self.published,self.record)}

    pub(super) fn warm<P:Ord,C,F>(self,owner:&P,generation:u64,roots:&BTreeMap<P,RootState>,
        index:&BTreeMap<ObjectId,ArenaLocation>,insert:F) -> (out:Option<C>)
        where F:FnOnce(&P,ObjectId,ObjectRecord)->C,
        requires btree_map_inv(roots),btree_map_inv(index),obeys_cmp::<P>(),obeys_cmp_concrete_eq::<P>(),
            obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
            self.parts().0.current(*owner,generation,roots@,index@) ==> insert.requires((owner,self.parts().0.root.commit,self.parts().1)),
        ensures out.is_some() == self.parts().0.current(*owner,generation,roots@,index@),
            out matches Some(c) ==> insert.ensures((owner,self.parts().0.root.commit,self.parts().1),c),
    {
        let p = self.published;
        if generation != p.arena_generation {return None;}
        let published = roots.get(owner)?;
        if !p.root.same(*published) {return None;}
        let loc = index.get(&p.root.commit)?;
        if loc.offset != p.location.offset || loc.payload_len != p.location.payload_len ||
            loc.checksum.as_slice() != p.location.checksum.as_slice() {return None;}
        assert(loc.checksum =~= p.location.checksum);
        Some(insert(owner,p.root.commit,self.record))
    }
}
}
