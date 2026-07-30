//! Live mappings from mutable principal aliases to stable durable identities.

use std::collections::HashMap;
use std::sync::Arc;

use astrid_core::identity::PrincipalUid;
use astrid_core::principal::PrincipalId;
use parking_lot::RwLock;

use crate::error::{StorageError, StorageResult};

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
