//! Publish the installed capsule and all of its generation-scoped lookup entries.
use super::{RuntimeScope, generation::RuntimeId, instance_swap::Entry, view_lookup};
use std::{collections::HashMap, hash::Hash};
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_eq::obeys_concrete_eq,
    pervasive::obeys_clone_eq,
    std_specs::hash::{hash_map_inv, obeys_key_model},
};

type Id<K, A> = RuntimeId<K, A, RuntimeScope>;

verus! {
broadcast use vstd::std_specs::hash::group_hash_axioms;

pub(super) struct Registration<K,A,P,U,C: ?Sized> {
    pub(super) runtime: Id<K,A>,
    pub(super) principal: P,
    pub(super) source: U,
    pub(super) entry: Entry<C,P>,
}

fn clone_key<K:Clone>(key: &K) -> (out:K)
    requires obeys_clone_eq::<K>(),
    ensures out == *key,
{
    proof { reveal(obeys_clone_eq); }
    let out = key.clone();
    assert(vstd::pervasive::cloned(*key,out));
    out
}

impl<K: Eq + Hash + Clone,A: Eq + Hash + Clone,P: Eq + Hash + Clone,U: Eq + Hash + Copy,C: ?Sized>
    Registration<K,A,P,U,C> {
    pub(super) fn publish(self, instances: &mut HashMap<Id<K,A>,Entry<C,P>>,
        views: &mut HashMap<P,HashMap<K,Id<K,A>>>, routes: &mut HashMap<(U,P),Id<K,A>>,
        sources: &mut HashMap<Id<K,A>,U>, names: &mut HashMap<U,K>) -> (runtime: Id<K,A>)
        requires hash_map_inv(old(instances)), hash_map_inv(old(views)), hash_map_inv(old(routes)),
            hash_map_inv(old(sources)), hash_map_inv(old(names)),
            old(views)@.contains_key(self.principal) ==> hash_map_inv(&old(views)@[self.principal]),
            obeys_key_model::<Id<K,A>>(), obeys_concrete_eq::<Id<K,A>>(), obeys_clone_eq::<Id<K,A>>(),
            obeys_key_model::<K>(), obeys_concrete_eq::<K>(), obeys_clone_eq::<K>(),
            obeys_key_model::<P>(), obeys_concrete_eq::<P>(), obeys_clone_eq::<P>(),
            obeys_key_model::<U>(), obeys_concrete_eq::<U>(),
            obeys_key_model::<(U,P)>(), obeys_concrete_eq::<(U,P)>(),
        ensures runtime == self.runtime,
            hash_map_inv(final(instances)), hash_map_inv(final(views)), hash_map_inv(final(routes)),
            hash_map_inv(final(sources)), hash_map_inv(final(names)),
            final(instances)@ == old(instances)@.insert(runtime,self.entry),
            final(routes)@ == old(routes)@.insert((self.source,self.principal),runtime),
            final(sources)@ == old(sources)@.insert(runtime,self.source),
            final(names)@ == old(names)@.insert(self.source,runtime.identity().0.0),
            final(views)@.remove(self.principal) == old(views)@.remove(self.principal),
            final(views)@.contains_key(self.principal), hash_map_inv(&final(views)@[self.principal]),
            final(views)@[self.principal]@ == (if old(views)@.contains_key(self.principal) {
                old(views)@[self.principal]@
            } else { Map::empty() }).insert(runtime.identity().0.0,runtime),
    {
        let runtime = self.runtime;
        instances.insert(clone_key(&runtime),self.entry);
        view_lookup::bind(views,clone_key(&self.principal),clone_key(&runtime));
        routes.insert((self.source,self.principal),clone_key(&runtime));
        sources.insert(clone_key(&runtime),self.source);
        let package = runtime.key().capsule_id();
        names.insert(self.source,clone_key(package));
        runtime
    }
}
}
