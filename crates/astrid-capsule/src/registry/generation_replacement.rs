//! Publish a replacement and withdraw its predecessor across the registry's lookup tables.
use super::{RuntimeScope, dependent_views, generation::RuntimeId, instance_swap, registration};
use std::{collections::HashMap, hash::Hash, sync::Arc};
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

pub(super) enum PrincipalRefusal {
    Reservation,
    Uplink,
    Superseded,
}

/// Check the reserved scope, candidate package and principal's current slot in error-reporting order.
pub(super) fn admit_principal<K: Eq + Hash,A: Eq + Hash,P: Eq + Hash,F: FnOnce() -> bool>(
    views: &HashMap<P,HashMap<K,Id<K,A>>>, principal: &P, package: &K, uid: super::PrincipalUid,
    expected: &Id<K,A>, reserved: &Id<K,A>, has_uplinks: F)
    -> (decision:Result<(),PrincipalRefusal>)
    requires has_uplinks.requires(()), hash_map_inv(views), views@.contains_key(*principal) ==> hash_map_inv(&views@[*principal]),
        obeys_key_model::<P>(), obeys_concrete_eq::<P>(), obeys_key_model::<K>(), obeys_concrete_eq::<K>(),
        obeys_concrete_eq::<Id<K,A>>(), obeys_concrete_eq::<RuntimeScope>(),
    ensures if reserved.identity().0.2 != RuntimeScope::Principal(uid) || reserved.identity().0.0 != *package {
        decision == Err(PrincipalRefusal::Reservation)
    } else {
        exists|provides:bool| #[trigger] has_uplinks.ensures((),provides) && decision == if provides {
            Err(PrincipalRefusal::Uplink)
        } else if expected.identity().0.2 != RuntimeScope::Principal(uid) ||
            super::view_lookup::slot(views@,*principal,*package) != Some(*expected) {
            Err(PrincipalRefusal::Superseded)
        } else { Ok(()) }
    },
{
    proof { reveal(obeys_concrete_eq); }
    let scope = RuntimeScope::Principal(uid);
    if !RuntimeScope::eq(&reserved.key().scope(),&scope) || !K::eq(reserved.key().capsule_id(),package) {
        return Err(PrincipalRefusal::Reservation);
    }
    if has_uplinks() { return Err(PrincipalRefusal::Uplink); }
    if !RuntimeScope::eq(&expected.key().scope(),&scope) || !super::view_lookup::current(views,principal,package,expected) {
        return Err(PrincipalRefusal::Superseded);
    }
    Ok(())
}

pub(super) struct Replacement<'a,K,A,P,U,T,F> {
    pub(super) expected: &'a Id<K,A>,
    pub(super) reserved: &'a Id<K,A>,
    pub(super) source: U,
    pub(super) candidate: T,
    pub(super) materialize: F,
    pub(super) owner_alias: Option<P>,
}

impl<K: Eq + Hash + Clone,A: Eq + Hash + Clone,P: Eq + Hash + Clone,U: Eq + Hash + Copy,T,F>
    Replacement<'_,K,A,P,U,T,F> {
    pub(super) fn apply<C: ?Sized>(self, instances: &mut HashMap<Id<K,A>,instance_swap::Entry<C,P>>,
        views: &mut HashMap<P,HashMap<K,Id<K,A>>>, routes: &mut HashMap<(U,P),Id<K,A>>,
        sources: &mut HashMap<Id<K,A>,U>, names: &mut HashMap<U,K>, aliases: &mut HashMap<U,A>)
        -> (previous:Result<Arc<C>,T>)
        where F: FnOnce(T) -> Arc<C>
        requires self.materialize.requires((self.candidate,)), hash_map_inv(old(instances)), hash_map_inv(old(views)), hash_map_inv(old(routes)),
            hash_map_inv(old(sources)), hash_map_inv(old(names)), hash_map_inv(old(aliases)),
            forall|p:P| old(views)@.contains_key(p) ==> hash_map_inv(&old(views)@[p]),
            obeys_key_model::<Id<K,A>>(), obeys_concrete_eq::<Id<K,A>>(), obeys_clone_eq::<Id<K,A>>(),
            obeys_key_model::<K>(), obeys_concrete_eq::<K>(), obeys_clone_eq::<K>(),
            obeys_key_model::<P>(), obeys_concrete_eq::<P>(), obeys_clone_eq::<P>(),
            obeys_key_model::<U>(), obeys_concrete_eq::<U>(), obeys_clone_eq::<U>(), obeys_concrete_eq::<A>(),
            obeys_key_model::<(U,P)>(), obeys_concrete_eq::<(U,P)>(), obeys_clone_eq::<(U,P)>(),
        ensures hash_map_inv(final(instances)), hash_map_inv(final(views)), hash_map_inv(final(routes)),
            hash_map_inv(final(sources)), hash_map_inv(final(names)), hash_map_inv(final(aliases)),
            ({
                let retired = *self.expected;
                let next = *self.reserved;
                if !old(instances)@.contains_key(retired) {
                    &&& previous == Err(self.candidate)
                    &&& final(instances)@ == old(instances)@ && final(views)@ == old(views)@ && final(routes)@ == old(routes)@
                    &&& final(sources)@ == old(sources)@ && final(names)@ == old(names)@ && final(aliases)@ == old(aliases)@
                } else {
                    let reverse = old(sources)@.remove(retired);
                    let old_source = old(sources)@[retired];
                    let retained_names = if old(sources)@.contains_key(retired) && !reverse.values().contains(old_source) {
                        old(names)@.remove(old_source)
                    } else { old(names)@ };
                    &&& previous == Ok(old(instances)@[retired].capsule)
                    &&& self.materialize.ensures((self.candidate,),final(instances)@[next].capsule)
                    &&& final(instances)@ == old(instances)@.remove(retired).insert(next,instance_swap::Entry { capsule:final(instances)@[next].capsule, owner_alias:self.owner_alias })
                    &&& final(sources)@ == reverse.insert(next,self.source)
                    &&& final(names)@ == retained_names.insert(self.source,next.identity().0.0)
                    &&& final(aliases)@ == if exists|id:Id<K,A>| final(instances)@.contains_key(id) &&
                        id.identity().0.1 == retired.identity().0.1 { old(aliases)@ }
                        else { dependent_views::kept(old(aliases)@,retired.identity().0.1) }
                    &&& final(views)@.dom() == old(views)@.dom()
                    &&& forall|p:P| final(views)@.contains_key(p) ==> hash_map_inv(&final(views)@[p]) &&
                        instance_swap::retargeted(old(views)@[p]@,(#[trigger] final(views)@[p])@,retired,next)
                    &&& forall|key:(U,P)| #[trigger] final(routes)@.contains_key(key) ==
                        ((old(routes)@.contains_key(key) && old(routes)@[key] != retired) ||
                         (key.0 == self.source && final(views)@.contains_key(key.1) && final(views)@[key.1]@.values().contains(next)))
                    &&& forall|key:(U,P)| final(routes)@.contains_key(key) ==> #[trigger] final(routes)@[key] ==
                        if key.0 == self.source && final(views)@.contains_key(key.1) && final(views)@[key.1]@.values().contains(next) {
                            next
                        } else { old(routes)@[key] }
                }
            }),
    {
        proof { reveal(obeys_clone_eq); }
        let installed = self.reserved.clone();
        assert(vstd::pervasive::cloned(*self.reserved,installed));
        let previous = instance_swap::replace(instances,self.expected,installed,self.candidate,self.owner_alias,self.materialize)?;
        dependent_views::withdraw_source(sources,names,self.expected);
        registration::replace_viewer_routes(views,routes,self.source,self.expected,self.reserved);
        registration::record_source(sources,names,self.reserved,self.source);
        dependent_views::prune_legacy(aliases,instances,self.expected.key().artifact());
        Ok(previous)
    }
}
}
