//! In-flight load identity; invalidated aliases leave no permanent generations.

use super::{Arc, PrincipalId, PrincipalProfileCache, ProfileCacheState, Weak};

#[derive(Debug)]
pub(super) struct ProfileLoadToken;

/// The map owns only a weak token. The final loader removes its entry on every
/// exit, including disk errors and unwinding; invalidation removes it sooner.
pub(super) struct ProfileLoad<'a> {
    cache: &'a PrincipalProfileCache,
    principal: &'a PrincipalId,
    token: Arc<ProfileLoadToken>,
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
            token,
        }
    }
}

impl ProfileLoad<'_> {
    pub(super) fn principal(&self) -> &PrincipalId {
        self.principal
    }

    pub(super) fn is_current(&self, state: &ProfileCacheState) -> bool {
        state
            .loads
            .get(self.principal)
            .is_some_and(|current| Weak::ptr_eq(current, &Arc::downgrade(&self.token)))
    }
}

impl Drop for ProfileLoad<'_> {
    fn drop(&mut self) {
        let mut state = self
            .cache
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // begin_load shares this token under the same lock. A new loader
        // cannot acquire it between the last-owner test and removing the slot.
        if Arc::strong_count(&self.token) == 1 && self.is_current(&state) {
            state.loads.remove(self.principal);
        }
    }
}
