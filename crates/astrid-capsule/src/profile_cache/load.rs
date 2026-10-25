//! In-flight load identity; invalidated aliases leave no permanent generations.

use super::{Arc, PrincipalId, PrincipalProfileCache, ProfileCacheState, Weak};

#[derive(Debug)]
pub(super) struct ProfileLoadToken;

/// The map owns only a weak token. The final loader removes its entry on every
/// exit, including disk errors and unwinding; invalidation removes it sooner.
pub(super) struct ProfileLoad<'a> {
    cache: &'a PrincipalProfileCache,
    principal: &'a PrincipalId,
    token: Option<Arc<ProfileLoadToken>>,
}

impl PrincipalProfileCache {
    pub(super) fn begin_load<'a>(&'a self, principal: &'a PrincipalId) -> ProfileLoad<'a> {
        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let token = state
            .loads
            .get(principal)
            .and_then(Weak::upgrade)
            .unwrap_or_else(|| {
                let token = Arc::new(ProfileLoadToken);
                state
                    .loads
                    .insert(principal.clone(), Arc::downgrade(&token));
                token
            });
        ProfileLoad {
            cache: self,
            principal,
            token: Some(token),
        }
    }
}

impl ProfileLoad<'_> {
    pub(super) fn principal(&self) -> &PrincipalId {
        self.principal
    }

    pub(super) fn is_current(&self, state: &ProfileCacheState) -> bool {
        self.token.as_ref().is_some_and(|token| {
            state
                .loads
                .get(self.principal)
                .is_some_and(|current| Weak::ptr_eq(current, &Arc::downgrade(token)))
        })
    }

    pub(super) fn finish(&mut self) {
        let mut state = self
            .cache
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let is_current = self.is_current(&state);
        // Release the strong reference before unlocking: two finishing loaders
        // must not both count the other's not-yet-dropped struct field.
        drop(self.token.take());
        if is_current
            && state
                .loads
                .get(self.principal)
                .is_some_and(|current| current.strong_count() == 0)
        {
            state.loads.remove(self.principal);
        }
    }
}

impl Drop for ProfileLoad<'_> {
    fn drop(&mut self) {
        self.finish();
    }
}
