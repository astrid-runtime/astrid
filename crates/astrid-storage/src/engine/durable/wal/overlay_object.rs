//! Merge repeated WAL declarations without replacing an immutable record.
use std::sync::Arc;
use vstd::prelude::*;

verus! {

#[derive(Debug)]
pub(crate) struct Object<R,L,D> {
    pub(super) payload:Arc<[u8]>,
    pub(super) record:R,
    pub(super) location:Option<L>,
    pub(super) direct:Option<D>,
}

impl<R,L,D> Object<R,L,D> {
    /// The only permitted update to an existing object upgrades a missing
    /// physical location using an identical frame and its paired direct metadata.
    pub(super) fn merge(&mut self,incoming:Self) -> (out:Result<(),()>)
        ensures out.is_ok() == ((*old(self).payload)@ == (*incoming.payload)@),
            final(self).payload == old(self).payload && final(self).record == old(self).record,
            if out.is_ok() && old(self).location.is_none() && incoming.location.is_some() {
                final(self).location == incoming.location && final(self).direct == incoming.direct
            } else { *final(self) == *old(self) },
    {
        let before:&[u8] = &self.payload;
        let after:&[u8] = &incoming.payload;
        if before != after {return Err(());}
        assert(before@ =~= after@);
        if self.location.is_none() && incoming.location.is_some() {
            self.location = incoming.location;
            self.direct = incoming.direct;
        }
        Ok(())
    }
}

}
