//! Compact inverse membership; small sharing sets need no heap tree.
// Three one-word references occupy the same space as a BTreeSet header;
// the representation adds only its discriminant to that fixed storage.
// Spill only above that capacity and release when the sole owner remains.
// Distinct thresholds avoid allocator churn when a shared owner retires and
// reattaches; they impose no sharing limit or cache-budget policy.
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::sync::Arc;

pub(super) struct PrincipalRef<P>(Arc<P>);

impl<P> PrincipalRef<P> {
    pub(super) fn new(principal: Arc<P>) -> Self {
        Self(principal)
    }
    pub(super) fn principal(&self) -> &P {
        &self.0
    }
    fn address(&self) -> usize {
        Arc::as_ptr(&self.0).addr()
    }
}

impl<P> Clone for PrincipalRef<P> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

// Each live principal partition has exactly one allocation. Strong references
// prevent its address being reused while any inverse membership still exists.
// This ordering is private cache bookkeeping, never authority or a wire ID.
impl<P> PartialEq for PrincipalRef<P> {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
impl<P> Eq for PrincipalRef<P> {}
impl<P> PartialOrd for PrincipalRef<P> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl<P> Ord for PrincipalRef<P> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.address().cmp(&other.address())
    }
}

pub(super) enum CachedPrincipals<P> {
    Inline([Option<PrincipalRef<P>>; 3]),
    Shared(BTreeSet<PrincipalRef<P>>),
}

impl<P> CachedPrincipals<P> {
    pub(super) fn new(principal: PrincipalRef<P>) -> Self {
        Self::Inline([Some(principal), None, None])
    }

    pub(super) fn insert(&mut self, principal: PrincipalRef<P>) {
        match self {
            Self::Inline(inline) => {
                if inline.iter().flatten().any(|old| old == &principal) {
                    return;
                }
                if let Some(slot) = inline.iter_mut().find(|slot| slot.is_none()) {
                    *slot = Some(principal);
                } else {
                    let mut shared = BTreeSet::new();
                    for old in inline.iter_mut().filter_map(Option::take) {
                        shared.insert(old);
                    }
                    shared.insert(principal);
                    *self = Self::Shared(shared);
                }
            },
            Self::Shared(shared) => {
                shared.insert(principal);
            },
        }
    }

    #[cfg(any(debug_assertions, test))]
    pub(super) fn contains(&self, principal: &PrincipalRef<P>) -> bool {
        match self {
            Self::Inline(inline) => inline.iter().flatten().any(|old| old == principal),
            Self::Shared(shared) => shared.contains(principal),
        }
    }

    pub(super) fn remove(&mut self, principal: &PrincipalRef<P>) {
        match self {
            Self::Inline(inline) => {
                if let Some(slot) = inline
                    .iter_mut()
                    .find(|slot| slot.as_ref() == Some(principal))
                {
                    *slot = None;
                }
            },
            Self::Shared(shared) => {
                shared.remove(principal);
                if shared.len() <= 1 {
                    *self = Self::Inline([shared.pop_first(), None, None]);
                }
            },
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        match self {
            Self::Inline(inline) => inline.iter().all(Option::is_none),
            Self::Shared(shared) => shared.is_empty(),
        }
    }

    pub(super) fn into_iter(self) -> impl Iterator<Item = PrincipalRef<P>> {
        let (inline, shared) = match self {
            Self::Inline(inline) => (inline, None),
            Self::Shared(shared) => ([None, None, None], Some(shared)),
        };
        inline
            .into_iter()
            .flatten()
            .chain(shared.into_iter().flatten())
    }
}

#[cfg(test)]
mod tests;
