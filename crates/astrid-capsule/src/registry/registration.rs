//! Publish the installed capsule and all of its generation-scoped lookup entries.
use super::{RuntimeScope, generation::RuntimeId, instance_swap::Entry, view_lookup};
use std::{collections::HashMap, hash::Hash};
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_eq::obeys_concrete_eq,
    pervasive::obeys_clone_eq,
    std_specs::hash::{hash_map_inv, obeys_key_model},
    std_specs::iter::IteratorSpec,
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
spec fn scanned<P,K: Eq + Hash,V>(rows:Seq<(&P,&HashMap<K,V>)>, n:int, principal:P, runtime:V) -> bool {
    exists|i:int| 0 <= i < n && *rows[i].0 == principal && (#[trigger] rows[i].1)@.values().contains(runtime)
}

/// Give the replacement source to precisely the principals with a view of that generation.
pub(super) fn publish_viewer_routes<P: Eq + Hash + Clone,K: Eq + Hash,U: Eq + Hash + Copy,V: Eq + Clone>(
    views: &HashMap<P,HashMap<K,V>>, routes: &mut HashMap<(U,P),V>, source: U, runtime: &V)
    requires hash_map_inv(views), hash_map_inv(old(routes)), obeys_key_model::<P>(), obeys_key_model::<K>(),
        obeys_key_model::<(U,P)>(), obeys_concrete_eq::<(U,P)>(), obeys_concrete_eq::<V>(),
        obeys_clone_eq::<V>(), obeys_clone_eq::<P>(),
        forall|p:P| views@.contains_key(p) ==> hash_map_inv(&views@[p]),
    ensures hash_map_inv(final(routes)),
        forall|key:(U,P)| #[trigger] final(routes)@.contains_key(key) == (old(routes)@.contains_key(key) ||
            (key.0 == source && views@.contains_key(key.1) && views@[key.1]@.values().contains(*runtime))),
        forall|key:(U,P)| final(routes)@.contains_key(key) ==> #[trigger] final(routes)@[key] ==
            if key.0 == source && views@.contains_key(key.1) && views@[key.1]@.values().contains(*runtime) {
                *runtime
            } else { old(routes)@[key] },
{
    let ghost before = routes@;
    let mut rows = views.iter();
    let ghost all = rows.remaining();
    let ghost mut n:int = 0;
    loop
        invariant
            before == old(routes)@, hash_map_inv(routes), 0 <= n <= all.len(), all.len() == views@.dom().len(), rows.remaining() == all.skip(n),
            obeys_key_model::<K>(), obeys_concrete_eq::<V>(), obeys_key_model::<(U,P)>(), obeys_concrete_eq::<(U,P)>(),
            obeys_clone_eq::<P>(), obeys_clone_eq::<V>(),
            forall|p:P| views@.contains_key(p) ==> all.contains((&p,&views@[p])) && hash_map_inv(&views@[p]),
            forall|i:int| 0 <= i < all.len() ==> views@.contains_key(*all[i].0) && #[trigger] views@[*all[i].0] == *all[i].1,
            forall|key:(U,P)| #[trigger] routes@.contains_key(key) == (before.contains_key(key) ||
                (key.0 == source && scanned(all,n,key.1,*runtime))),
            forall|key:(U,P)| routes@.contains_key(key) ==> #[trigger] routes@[key] == if key.0 == source &&
                scanned(all,n,key.1,*runtime) { *runtime } else { before[key] },
        decreases views@.dom().len() - n,
    {
        let Some((principal,view)) = rows.next() else {
            assert(n == all.len());
            assert forall|p:P| (#[trigger] views@.contains_key(p) && views@[p]@.values().contains(*runtime)) ==
                scanned(all,n,p,*runtime) by {
                if views@.contains_key(p) {
                    let i = all.index_of((&p,&views@[p]));
                    assert(0 <= i < n);
                    assert(all[i] == (&p,&views@[p]));
                    assert(all[i].1@ == views@[p]@);
                }
                if exists|i:int| 0 <= i < n && *all[i].0 == p && (#[trigger] all[i].1)@.values().contains(*runtime) {
                    let i = choose|i:int| 0 <= i < n && *all[i].0 == p && (#[trigger] all[i].1)@.values().contains(*runtime);
                    assert(views@.contains_key(*all[i].0));
                    assert(views@[*all[i].0] == *all[i].1);
                }
            }
            assert forall|key:(U,P)| #[trigger] routes@.contains_key(key) == (before.contains_key(key) ||
                (key.0 == source && views@.contains_key(key.1) && views@[key.1]@.values().contains(*runtime))) by {
                assert(scanned(all,n,key.1,*runtime) == (views@.contains_key(key.1) && views@[key.1]@.values().contains(*runtime)));
            }
            assert forall|key:(U,P)| routes@.contains_key(key) implies #[trigger] routes@[key] ==
                (if key.0 == source && views@.contains_key(key.1) && views@[key.1]@.values().contains(*runtime) {
                    *runtime
                } else { before[key] }) by {
                assert(scanned(all,n,key.1,*runtime) == (views@.contains_key(key.1) && views@[key.1]@.values().contains(*runtime)));
            }
            return;
        };
        assert(all[n] == (principal,view));
        assert(views@.contains_key(*principal));
        assert(views@[*principal] == *view);
        if super::viewers::attached(view,runtime) {
            routes.insert((source,clone_key(principal)),clone_key(runtime));
        }
        assert(rows.remaining() =~= all.skip(n+1));
        proof { n = n+1; }
    }
}

}
