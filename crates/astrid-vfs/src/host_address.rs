//! Capture a native handle under its table lock before dispatching filesystem work.
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;
use vstd::prelude::*;

verus! {
broadcast use vstd::std_specs::hash::group_hash_axioms;

pub(super) fn retain<K:Eq+Hash,T>(table:&HashMap<K,Arc<T>>, handle:&K) -> (out:Option<Arc<T>>)
    requires vstd::std_specs::hash::hash_map_inv(table), vstd::std_specs::hash::obeys_key_model::<K>(),
        vstd::laws_eq::obeys_concrete_eq::<K>(),
    ensures out.is_some() == table@.contains_key(*handle),
        out matches Some(owner) ==> owner == table@[*handle],
{
    match table.get(handle) { Some(owner) => Some(Arc::clone(owner)), None => None }
}

/// Native registration permits replacement of a handle.
pub(super) fn install<K:Eq+Hash,T>(table:&mut HashMap<K,Arc<T>>, handle:K, entry:Arc<T>)
    requires vstd::std_specs::hash::hash_map_inv(old(table)), vstd::std_specs::hash::obeys_key_model::<K>(),
        vstd::laws_eq::obeys_concrete_eq::<K>(),
    ensures vstd::std_specs::hash::hash_map_inv(final(table)), final(table)@ == old(table)@.insert(handle,entry),
{ table.insert(handle,entry); }

pub(super) fn close<K:Eq+Hash,T>(table:&mut HashMap<K,Arc<T>>, handle:&K) -> (removed:bool)
    requires vstd::std_specs::hash::hash_map_inv(old(table)), vstd::std_specs::hash::obeys_key_model::<K>(),
        vstd::laws_eq::obeys_concrete_eq::<K>(),
    ensures vstd::std_specs::hash::hash_map_inv(final(table)), final(table)@ == old(table)@.remove(*handle),
        removed == old(table)@.contains_key(*handle),
{ table.remove(handle).is_some() }

pub(super) struct Address<D,P> {
    directory: Arc<D>,
    path: P,
}

impl<D,P> Address<D,P> {
    pub(super) closed spec fn parts(&self) -> (Arc<D>,P) { (self.directory,self.path) }

    pub(super) fn new<'a,F:FnOnce(&'a str)->P>(directory:Arc<D>, path:&'a str, normalize:F) -> (out:Self)
        requires normalize.requires((path,)),
        ensures out.parts().0 == directory, normalize.ensures((path,),out.parts().1),
    { Self { directory, path:normalize(path) } }

    pub(super) fn path(&self) -> (p:&P)
        ensures *p == self.parts().1,
    { &self.path }

    pub(super) fn run<R,F:FnOnce(Arc<D>,P)->R>(self, operation:F) -> (out:R)
        requires operation.requires(self.parts()),
        ensures operation.ensures(self.parts(),out),
    { operation(self.directory,self.path) }
}
}
