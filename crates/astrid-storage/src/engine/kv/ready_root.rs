//! Resident root samples for the KV point-read cache.
use super::RootState;
use vstd::prelude::*;

verus! {
/// A root that is already resident without taking the engine writer lock.
///
/// Durable engines publish this from an in-process snapshot used by the
/// disposable KV hot cache. It is not recovery authority: WAL replay and
/// writer-locked [`crate::engine::KvProjectionEngine::current_kv_root`] remain the source of
/// committed truth. Embeddings may see `None` while the engine is recovering
/// or closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadyKvRoot(Option<RootState>);

impl ReadyKvRoot {
    pub closed spec fn sampled(self) -> Option<RootState> { self.0 }

    /// Wrap a resident root, including the valid empty-store state.
    #[must_use]
    pub const fn new(root: Option<RootState>) -> (out:Self) ensures out.sampled() == root {
        Self(root)
    }

    /// Return the resident root.
    #[must_use]
    pub const fn get(self) -> (root:Option<RootState>) ensures root == self.sampled() {
        self.0
    }

    /// Bracket the owner's published-root load with both lifecycle observations.
    /// An unavailable sample triggers fallback. A wrapped empty root is usable.
    pub(crate) fn sample_ready<P,B,L,A>(owner:&P,before:B,load:L,after:A) -> (out:Option<Self>)
        where B:FnOnce()->bool,L:FnOnce(&P)->Option<Self>,A:FnOnce()->bool,
        requires before.requires(()),before.ensures((),true) ==> load.requires((owner,)) && after.requires(()),
        ensures match out {
            Some(root) => before.ensures((),true) && load.ensures((owner,),Some(root)) && after.ensures((),true),
            None => before.ensures((),false) || after.ensures((),false) || load.ensures((owner,),None),
        },
    {
        if !before() {return None;}
        let root = load(owner);
        if after() {root} else {None}
    }
}
}
