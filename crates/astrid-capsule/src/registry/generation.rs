//! Generation allocation under the capsule registry write lock.

use vstd::prelude::*;

verus! {

pub(super) fn reserve(next: &mut u64) -> (generation: Option<u64>)
    ensures
        generation.is_some() == (*old(next) < u64::MAX),
        generation matches Some(value) ==> value == *old(next) && *final(next) as int == value as int + 1,
        generation.is_none() ==> *final(next) == *old(next),
{
    let current = *next;
    let successor = current.checked_add(1)?;
    *next = successor;
    Some(current)
}

/// The logical key of a loaded capsule, specialized to the native domain types by the registry.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RuntimeKey<I,A,S> {
    capsule_id: I,
    artifact: A,
    scope: S,
}

impl<I,A,S> RuntimeKey<I,A,S> {
    pub closed spec fn parts(&self) -> (I,A,S) { (self.capsule_id,self.artifact,self.scope) }

    /// Construct a key for this artifact in the selected authority scope.
    #[must_use]
    pub fn new(capsule_id: I, artifact: A, scope: S) -> (key: Self)
        ensures key.parts() == (capsule_id,artifact,scope),
    {
        Self { capsule_id, artifact, scope }
    }

    /// Capsule package identifier.
    #[must_use]
    pub fn capsule_id(&self) -> (value: &I) ensures *value == self.parts().0, { &self.capsule_id }

    /// Immutable artifact identifier.
    #[must_use]
    pub fn artifact(&self) -> (value: &A) ensures *value == self.parts().1, { &self.artifact }
}

impl<I,A,S: Copy> RuntimeKey<I,A,S> {
    /// Authority scope selected at admission.
    #[must_use]
    pub const fn scope(&self) -> (value: S) ensures value == self.parts().2, { self.scope }
}

/// One incarnation of a logical runtime slot.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RuntimeId<I,A,S> {
    key: RuntimeKey<I,A,S>,
    generation: u64,
}

impl<I,A,S> RuntimeId<I,A,S> {
    pub closed spec fn identity(&self) -> ((I,A,S),u64) {
        (self.key.parts(),self.generation)
    }

    /// Generation reserved for this incarnation.
    #[must_use]
    pub const fn generation(&self) -> (value: u64) ensures value == self.identity().1, { self.generation }

    /// Logical slot of this incarnation.
    #[must_use]
    pub const fn key(&self) -> (value: &RuntimeKey<I,A,S>) ensures value.parts() == self.identity().0, { &self.key }
}

/// Construct the registry's actual runtime ID, including its key, under the generation lock.
pub(super) fn issue<I,A,S>(next: &mut u64, id: I, artifact: A, scope: S) -> (out: Option<RuntimeId<I,A,S>>)
    ensures out.is_some() == (*old(next) < u64::MAX),
        out matches Some(r) ==> r.identity() == ((id,artifact,scope),*old(next)) && *final(next) as int == *old(next) as int + 1,
        out.is_none() ==> *final(next) == *old(next),
{
    let generation = reserve(next)?;
    Some(RuntimeId { key: RuntimeKey::new(id,artifact,scope), generation })
}
}
