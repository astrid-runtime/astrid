//! Live mappings from mutable principal aliases to stable durable identities.

use std::collections::HashMap;
use std::sync::Arc;

use astrid_core::identity::PrincipalUid;
use astrid_core::principal::PrincipalId;
use parking_lot::{RwLock, RwLockReadGuard};

use crate::error::{StorageError, StorageResult};

mod binding;
pub(crate) use binding::recovery_aliases;

/// Live, capability-bound mapping between mutable principal aliases and
/// stable durable UIDs.
///
/// The root journal never stores an alias. This directory is populated from
/// validated principal identity records before user-owned namespaces are
/// served. Renaming updates the two maps without changing any durable root.
#[derive(Clone, Debug, Default)]
pub struct PrincipalDirectory {
    inner: Arc<RwLock<PrincipalDirectoryState>>,
}

#[derive(Clone, Debug, Default)]
struct PrincipalDirectoryState {
    aliases: HashMap<PrincipalId, PrincipalUid>,
    principals: HashMap<PrincipalUid, PrincipalId>,
}

/// Borrowed live-membership view that fairly admits writers between lookups.
/// Keep the scope synchronous and limited to bounded in-memory checks.
pub(crate) struct AdmittedPrincipals<'a> {
    state: RwLockReadGuard<'a, PrincipalDirectoryState>,
}

impl AdmittedPrincipals<'_> {
    #[inline]
    pub(crate) fn contains_uid(&mut self, uid: PrincipalUid) -> bool {
        RwLockReadGuard::bump(&mut self.state);
        self.state.principals.contains_key(&uid)
    }
}

impl PrincipalDirectory {
    /// Register one validated alias-to-UID binding.
    ///
    /// Repeating the same binding is idempotent. Reusing either side for a
    /// different identity fails closed.
    ///
    /// # Errors
    ///
    /// Returns an error when either the alias or UID is already bound to a
    /// different identity.
    pub fn register(&self, alias: PrincipalId, uid: PrincipalUid) -> StorageResult<()> {
        let mut state = self.inner.write();
        if state
            .aliases
            .get(&alias)
            .is_some_and(|existing| *existing != uid)
        {
            return Err(StorageError::Internal(format!(
                "principal alias {alias} is already bound to a different uid"
            )));
        }
        if let Some(existing) = state
            .principals
            .get(&uid)
            .filter(|existing| *existing != &alias)
        {
            return Err(StorageError::Internal(format!(
                "principal uid {uid} is already bound to alias {existing}"
            )));
        }
        state.aliases.insert(alias.clone(), uid);
        state.principals.insert(uid, alias);
        Ok(())
    }

    pub(crate) fn unregister(&self, alias: &PrincipalId, uid: PrincipalUid) {
        let mut state = self.inner.write();
        if state.aliases.get(alias) == Some(&uid) && state.principals.get(&uid) == Some(alias) {
            state.aliases.remove(alias);
            state.principals.remove(&uid);
        }
    }

    pub(crate) fn replace_all(
        &self,
        bindings: impl IntoIterator<Item = (PrincipalId, PrincipalUid)>,
    ) -> StorageResult<()> {
        let replacement = Self::default();
        for (alias, uid) in bindings {
            replacement.register(alias, uid)?;
        }
        *self.inner.write() = replacement.inner.read().clone();
        Ok(())
    }

    /// Resolve a current alias to its stable durable UID.
    ///
    /// # Errors
    ///
    /// Returns an error when the alias has no admitted durable identity.
    pub fn uid_for(&self, alias: &PrincipalId) -> StorageResult<PrincipalUid> {
        self.inner
            .read()
            .aliases
            .get(alias)
            .copied()
            .ok_or_else(|| {
                StorageError::InvalidKey(format!(
                    "principal alias {alias} has no registered durable identity"
                ))
            })
    }

    /// Resolve the alias and keep a previously admitted owner when supplied.
    ///
    /// # Errors
    ///
    /// Returns an error if the alias is missing or has changed owners.
    pub fn bound_uid(
        &self,
        alias: &PrincipalId,
        expected: Option<PrincipalUid>,
    ) -> StorageResult<PrincipalUid> {
        let observed = self.uid_for(alias)?;
        binding::select(expected.map(|uid| *uid.as_bytes()), *observed.as_bytes())
            .map(PrincipalUid::from_bytes)
            .ok_or_else(|| StorageError::InvalidKey(format!("principal {alias} changed owners")))
    }

    /// Run a synchronous native operation while this UID remains registered.
    ///
    /// The current alias is borrowed under the directory read lock. Renames,
    /// unregister and replacement wait until the callback finishes. The UID,
    /// rather than an earlier alias spelling, remains the destination authority.
    /// Missing or inconsistent bindings return `None` without calling `operation`.
    ///
    /// The callback must not re-enter this directory or wait for work that needs
    /// its write lock. Runtime callers separately hold lifecycle admission through
    /// their complete operation; this guard covers the namespace binding only.
    ///
    /// # Errors
    ///
    /// Propagates the callback's IO error after releasing the binding guard.
    pub fn with_live_uid_binding<T>(
        &self,
        uid: PrincipalUid,
        operation: impl FnOnce(&PrincipalId) -> std::io::Result<T>,
    ) -> std::io::Result<Option<T>> {
        let state = self.inner.read();
        let result = binding::with_live_alias(&state.aliases, &state.principals, &uid, operation);
        drop(state);
        result.ok().transpose()
    }

    /// Run a synchronous operation with an owned input while both sides of the
    /// captured binding match. The callback must not re-enter the directory
    /// or wait for work requiring its write lock.
    ///
    /// # Errors
    ///
    /// Returns the original input for cleanup when either binding has changed.
    pub fn with_bound_input<T, R>(
        &self,
        alias: &PrincipalId,
        uid: PrincipalUid,
        input: T,
        operation: impl FnOnce(T) -> R,
    ) -> Result<R, T> {
        let state = self.inner.read();
        let result = binding::with_pair(
            alias.as_str().as_bytes(),
            uid.as_bytes(),
            state.aliases.get(alias).map(PrincipalUid::as_bytes),
            state.principals.get(&uid).map(|id| id.as_str().as_bytes()),
            input,
            operation,
        );
        drop(state);
        result
    }

    /// Resolve a durable UID to its current alias.
    ///
    /// # Errors
    ///
    /// Returns an error when the UID has no current live alias.
    pub fn alias_for(&self, uid: PrincipalUid) -> StorageResult<PrincipalId> {
        self.inner
            .read()
            .principals
            .get(&uid)
            .cloned()
            .ok_or_else(|| {
                StorageError::InvalidKey(format!(
                    "principal uid {uid} has no registered live alias"
                ))
            })
    }

    /// Replay the ownership snapshot under one stable principal-directory read guard.
    /// The sink runs synchronously and must not re-enter the directory.
    ///
    /// # Errors
    ///
    /// Returns the first error from the sink and stops recovery.
    pub fn replay_retirements<S: crate::RetirementSink<PrincipalId>>(
        &self,
        ownership: &crate::OwnershipSnapshot,
        sink: &mut S,
    ) -> Result<(), S::Error> {
        ownership.replay_retirements(&self.inner.read().principals, sink)
    }

    /// Whether a durable UID currently names an admitted live principal.
    #[must_use]
    pub fn contains_uid(&self, uid: PrincipalUid) -> bool {
        self.inner.read().principals.contains_key(&uid)
    }

    /// Check a UID batch without allocating or repeatedly acquiring the lock.
    /// Only membership lookups run under the read guard; callers perform graph
    /// decoding and structural validation outside it. Pending writers can proceed
    /// between lookups, as with individual checks. Empty batches take no lock.
    pub(crate) fn first_missing_uid(
        &self,
        uids: impl IntoIterator<Item = PrincipalUid>,
    ) -> Option<PrincipalUid> {
        let mut uids = uids.into_iter();
        let first = uids.next()?;
        let mut admitted = self.admitted();
        std::iter::once(first)
            .chain(uids)
            .find(|uid| !admitted.contains_uid(*uid))
    }

    /// Borrow membership for synchronous checks without repeated lock acquisition.
    pub(crate) fn admitted(&self) -> AdmittedPrincipals<'_> {
        AdmittedPrincipals {
            state: self.inner.read(),
        }
    }

    /// Snapshot every admitted alias-to-UID binding in deterministic order.
    #[must_use]
    pub fn bindings(&self) -> Vec<(PrincipalId, PrincipalUid)> {
        let state = self.inner.read();
        let mut bindings = state
            .aliases
            .iter()
            .map(|(alias, uid)| (alias.clone(), *uid))
            .collect::<Vec<_>>();
        bindings.sort_by(|left, right| left.0.as_str().cmp(right.0.as_str()));
        bindings
    }

    /// Rebind one existing UID to a new validated alias.
    ///
    /// The old alias must currently name `uid`, and the replacement alias must
    /// be unused. No root-journal bytes change.
    ///
    /// # Errors
    ///
    /// Returns an error when the source binding is stale or the replacement
    /// alias is already in use.
    pub fn rename(
        &self,
        uid: PrincipalUid,
        old_alias: &PrincipalId,
        new_alias: PrincipalId,
    ) -> StorageResult<()> {
        let mut state = self.inner.write();
        if state.aliases.get(old_alias) != Some(&uid)
            || state.principals.get(&uid) != Some(old_alias)
        {
            return Err(StorageError::InvalidKey(format!(
                "principal rename source {old_alias} does not match uid {uid}"
            )));
        }
        if let Some(existing) = state.aliases.get(&new_alias) {
            return Err(StorageError::InvalidKey(format!(
                "principal rename target {new_alias} is already bound to uid {existing}"
            )));
        }
        state.aliases.remove(old_alias);
        state.aliases.insert(new_alias.clone(), uid);
        state.principals.insert(uid, new_alias);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
