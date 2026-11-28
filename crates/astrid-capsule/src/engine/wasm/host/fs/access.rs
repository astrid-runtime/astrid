//! Retain the access that passed policy and derive file-open permissions from it.
use vstd::prelude::*;

verus! {
#[derive(Clone,Copy)]
pub(super) enum Access<H> { Probe, Read, Write(Option<H>), Delete }

#[derive(Clone,Copy,PartialEq,Eq)]
pub(super) enum Policy { Read, Write, Delete }

impl<H> Access<H> {
    pub(super) open spec fn policy(&self) -> Policy {
        match self { Self::Probe | Self::Read => Policy::Read, Self::Write(_) => Policy::Write, Self::Delete => Policy::Delete }
    }

    pub(super) fn authorize<K,G,E,F:FnOnce(Policy,K)->Result<G,E>>(self, path:K, check:F)
        -> (result:Result<(G,Self),E>)
        requires check.requires((self.policy(),path)),
        ensures match result {
            Ok((guard,access)) => access == self && check.ensures((self.policy(),path),Ok(guard)),
            Err(e) => check.ensures((self.policy(),path),Err(e)),
        },
    {
        let policy = match &self { Self::Probe | Self::Read => Policy::Read,
            Self::Write(_) => Policy::Write, Self::Delete => Policy::Delete };
        let guard = check(policy,path)?;
        Ok((guard,self))
    }

    pub(super) fn open<D,P,R,F:FnOnce(D,P,bool,bool)->R>(&self, dir:D, path:P, apply:F) -> (out:Option<R>)
        requires
            self is Read ==> apply.requires((dir,path,false,false)),
            self is Write ==> apply.requires((dir,path,true,true)),
        ensures out.is_some() == (self is Read || self is Write),
            out matches Some(r) ==> apply.ensures((dir,path,self is Write,self is Write),r),
    {
        let write = match self { Self::Read => false, Self::Write(_) => true, _ => return None };
        Some(apply(dir,path,write,write))
    }
}
}
