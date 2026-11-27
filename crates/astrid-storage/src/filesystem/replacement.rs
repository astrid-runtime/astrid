//! Keep the selected owner or branch and replacement bytes attached to the checked catalog key.
use crate::ContentName;
use vstd::prelude::*;

verus! {
pub(crate) struct Replacement<'a,D> { destination:D, name:ContentName, bytes:&'a [u8] }

impl<'a,D> Replacement<'a,D> {
    pub(crate) closed spec fn arguments(&self) -> (D,ContentName,&'a [u8]) {
        (self.destination,self.name,self.bytes)
    }

    pub(crate) fn submit<R,F:FnOnce(D,ContentName,&'a [u8])->R>(self, put:F) -> (result:R)
        requires put.requires(self.arguments()),
        ensures put.ensures(self.arguments(),result),
    { put(self.destination,self.name,self.bytes) }
}

/// Both namespaces require a live parent and reject directory targets before deriving a file key.
pub(crate) fn prepare<'a,D,P:Copy,E,A,G,K,T>(destination:D, path:P, bytes:&'a [u8],
    parent:A, directory:G, key:K, is_directory:T) -> (out:Result<Replacement<'a,D>,E>)
    where A:FnOnce(P)->Result<(),E>, G:FnOnce(P)->Result<bool,E>, K:FnOnce(P)->Result<ContentName,E>, T:FnOnce(P)->E,
    requires parent.requires((path,)),directory.requires((path,)),key.requires((path,)),is_directory.requires((path,)),
    ensures match out {
        Ok(write) => parent.ensures((path,),Ok(())) && directory.ensures((path,),Ok(false))
            && key.ensures((path,),Ok(write.arguments().1)) && write.arguments().0 == destination
            && write.arguments().2 == bytes,
        Err(error) => parent.ensures((path,),Err(error)) || (parent.ensures((path,),Ok(())) && (
            directory.ensures((path,),Err(error)) ||
            (directory.ensures((path,),Ok(true)) && is_directory.ensures((path,),error)) ||
            (directory.ensures((path,),Ok(false)) && key.ensures((path,),Err(error))))),
    },
{
    parent(path)?;
    if directory(path)? { return Err(is_directory(path)); }
    let name = key(path)?;
    Ok(Replacement { destination,name,bytes })
}
}
