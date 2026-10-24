//! Exact inverse cache membership without a heap tree for the usual sole user.
use std::collections::BTreeSet;

pub(super) enum CachedPrincipals<P> {
    Inline(Option<P>),
    Shared(BTreeSet<P>),
}

impl<P: Ord> CachedPrincipals<P> {
    pub(super) fn new(principal: P) -> Self {
        Self::Inline(Some(principal))
    }

    pub(super) fn insert(&mut self, principal: P) {
        match self {
            Self::Inline(single) => {
                if single.as_ref() == Some(&principal) {
                    return;
                }
                if let Some(previous) = single.take() {
                    *self = Self::Shared(BTreeSet::from([previous, principal]));
                } else {
                    *single = Some(principal);
                }
            },
            Self::Shared(principals) => {
                principals.insert(principal);
            },
        }
    }

    pub(super) fn remove(&mut self, principal: &P) {
        match self {
            Self::Inline(single) => {
                if single.as_ref() == Some(principal) {
                    *single = None;
                }
            },
            Self::Shared(principals) => {
                principals.remove(principal);
                if principals.len() <= 1 {
                    *self = Self::Inline(principals.pop_first());
                }
            },
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        match self {
            Self::Inline(principal) => principal.is_none(),
            Self::Shared(principals) => principals.is_empty(),
        }
    }

    pub(super) fn into_iter(self) -> impl Iterator<Item = P> {
        let (single, shared) = match self {
            Self::Inline(principal) => (principal, None),
            Self::Shared(principals) => (None, Some(principals)),
        };
        single.into_iter().chain(shared.into_iter().flatten())
    }
}

#[cfg(test)]
mod tests;
