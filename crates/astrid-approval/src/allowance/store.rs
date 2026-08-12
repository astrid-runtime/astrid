//! In-memory store for active allowances, keyed per-principal.
//!
//! Every [`Allowance`] carries the [`PrincipalId`] it was granted to.
//! The store maintains a two-level map `PrincipalId → AllowanceId → Allowance`,
//! so lookups filter by the invoking principal up front. Agent A's allowance
//! can never authorise Agent B's action, even if the patterns would otherwise
//! match. This is Layer 4 of the production multi-tenancy work (issue #668).

use crate::error::{ApprovalError, ApprovalResult};
use astrid_core::principal::PrincipalId;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt;
use std::path::Path;
use std::sync::RwLock;

use super::{Allowance, AllowanceId};
use crate::action::SensitiveAction;

/// In-memory store for active allowances.
///
/// Thread-safe via internal [`RwLock`]. Supports pattern-based matching,
/// use tracking, expiration cleanup, and session clearing — all scoped by
/// the invoking [`PrincipalId`].
///
/// # Example
///
/// ```
/// use astrid_approval::AllowanceStore;
///
/// let store = AllowanceStore::new();
/// assert_eq!(store.count(), 0);
/// ```
pub struct AllowanceStore {
    retiring_principals: RwLock<HashSet<PrincipalId>>,
    /// Two-level map: `principal → allowance id → allowance`.
    ///
    /// Outer key isolates principals; inner map keeps lookups cheap within
    /// a single principal's set. A principal with no allowances has no
    /// inner-map entry.
    allowances: RwLock<HashMap<PrincipalId, HashMap<AllowanceId, Allowance>>>,
}

impl AllowanceStore {
    /// Create a new empty allowance store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            retiring_principals: RwLock::new(HashSet::new()),
            allowances: RwLock::new(HashMap::new()),
        }
    }

    /// Add an allowance to the store.
    ///
    /// The allowance is inserted under its own [`Allowance::principal`] —
    /// the only source of truth for principal assignment. Callers cannot
    /// override it.
    ///
    /// # Errors
    ///
    /// Returns a storage error if the internal lock is poisoned.
    pub fn add_allowance(&self, allowance: Allowance) -> ApprovalResult<()> {
        let retirement = self
            .retiring_principals
            .read()
            .map_err(|e| ApprovalError::Storage(e.to_string()))?;
        if retirement.contains(&allowance.principal) {
            return Err(ApprovalError::Storage(format!(
                "principal {} is retiring",
                allowance.principal
            )));
        }
        let mut store = self
            .allowances
            .write()
            .map_err(|e| ApprovalError::Storage(e.to_string()))?;
        store
            .entry(allowance.principal.clone())
            .or_default()
            .insert(allowance.id.clone(), allowance);
        Ok(())
    }

    /// Find the first valid allowance owned by `principal` that matches an action.
    ///
    /// An allowance matches when:
    /// 1. Its pattern covers the action
    /// 2. It has not expired
    /// 3. It has uses remaining (if limited)
    /// 4. For workspace-scoped allowances (`workspace_root: Some(..)`),
    ///    the allowance's `workspace_root` must match the current `workspace_root`
    ///
    /// Only allowances granted to `principal` are considered; other principals'
    /// allowances are invisible to the scan.
    ///
    /// Returns a clone of the matching allowance, or `None`.
    #[must_use]
    pub fn find_matching(
        &self,
        principal: &PrincipalId,
        action: &SensitiveAction,
        workspace_root: Option<&Path>,
    ) -> Option<Allowance> {
        if self
            .retiring_principals
            .read()
            .map_or(true, |retiring| retiring.contains(principal))
        {
            return None;
        }
        let store = self.allowances.read().unwrap_or_else(|e| {
            tracing::warn!("AllowanceStore read lock poisoned, recovering");
            e.into_inner()
        });
        let principal_map = store.get(principal)?;
        principal_map
            .values()
            .find(|a| allowance_matches(a, action, workspace_root))
            .cloned()
    }

    /// Atomically find a matching allowance for `principal` and consume one use.
    ///
    /// This combines [`find_matching`](Self::find_matching) and
    /// [`consume_use`](Self::consume_use) under a single write lock to prevent
    /// race conditions where two concurrent callers both find the same
    /// single-use allowance.
    ///
    /// Also cleans up `principal`'s expired entries while the lock is held.
    ///
    /// Returns a clone of the matching allowance (before consumption), or `None`.
    #[must_use]
    pub fn find_matching_and_consume(
        &self,
        principal: &PrincipalId,
        action: &SensitiveAction,
        workspace_root: Option<&Path>,
    ) -> Option<Allowance> {
        if self
            .retiring_principals
            .read()
            .map_or(true, |retiring| retiring.contains(principal))
        {
            return None;
        }
        let mut store = self.allowances.write().unwrap_or_else(|e| {
            tracing::warn!("AllowanceStore lock poisoned, recovering");
            e.into_inner()
        });
        let principal_map = store.get_mut(principal)?;
        // Clean expired entries for this principal only.
        principal_map.retain(|_, a| !a.is_expired());
        let id = principal_map
            .values()
            .find(|a| allowance_matches(a, action, workspace_root))?
            .id
            .clone();
        let allowance = principal_map.get(&id)?.clone();
        // Consume use atomically
        if let Some(remaining) = principal_map
            .get_mut(&id)
            .and_then(|a| a.uses_remaining.as_mut())
        {
            *remaining = remaining.saturating_sub(1);
        }
        Some(allowance)
    }

    /// Consume one use of an allowance belonging to `principal`.
    ///
    /// For unlimited allowances (`uses_remaining: None`), this is a no-op.
    /// For limited allowances, decrements `uses_remaining` by 1.
    ///
    /// Returns `true` if the allowance still has uses remaining after consumption,
    /// `false` if this was the last use.
    ///
    /// # Errors
    ///
    /// Returns an error if the allowance is not found under `principal`, or
    /// the lock is poisoned.
    pub fn consume_use(
        &self,
        principal: &PrincipalId,
        allowance_id: &AllowanceId,
    ) -> ApprovalResult<bool> {
        let mut store = self
            .allowances
            .write()
            .map_err(|e| ApprovalError::Storage(e.to_string()))?;

        let principal_map = store.get_mut(principal).ok_or_else(|| {
            ApprovalError::Storage(format!(
                "no allowances for principal '{principal}' (looked up {allowance_id})"
            ))
        })?;

        let allowance = principal_map.get_mut(allowance_id).ok_or_else(|| {
            ApprovalError::Storage(format!("allowance not found: {allowance_id}"))
        })?;

        if let Some(remaining) = &mut allowance.uses_remaining {
            *remaining = remaining.saturating_sub(1);
            Ok(*remaining > 0)
        } else {
            // Unlimited — always has uses remaining
            Ok(true)
        }
    }

    /// Remove all expired allowances from the store, across every principal.
    ///
    /// Returns the number of allowances removed.
    pub fn cleanup_expired(&self) -> usize {
        let mut store = self.allowances.write().unwrap_or_else(|e| {
            tracing::warn!("AllowanceStore write lock poisoned in cleanup_expired, recovering");
            e.into_inner()
        });
        let mut removed: usize = 0;
        for principal_map in store.values_mut() {
            let before = principal_map.len();
            principal_map.retain(|_, a| !a.is_expired());
            removed = removed.saturating_add(before.saturating_sub(principal_map.len()));
        }
        store.retain(|_, m| !m.is_empty());
        removed
    }

    /// Remove `principal`'s session-only allowances.
    ///
    /// Called when the connection owned by `principal` closes. Other
    /// principals' allowances are untouched — Alice disconnecting never
    /// clears Bob's state.
    pub fn clear_session_allowances(&self, principal: &PrincipalId) {
        let mut store = self.allowances.write().unwrap_or_else(|e| {
            tracing::warn!(
                "AllowanceStore write lock poisoned in clear_session_allowances, recovering"
            );
            e.into_inner()
        });
        if let Some(principal_map) = store.get_mut(principal) {
            principal_map.retain(|_, a| !a.session_only);
            if principal_map.is_empty() {
                store.remove(principal);
            }
        }
    }

    /// Remove every allowance owned by `principal`, regardless of scope.
    ///
    /// Identity deletion uses this stronger operation: an alias may later be
    /// recreated as a new identity, and neither session nor persistent
    /// approvals may cross that generation boundary.
    pub fn clear_for_principal(&self, principal: &PrincipalId) {
        let mut store = self.allowances.write().unwrap_or_else(|e| {
            tracing::warn!("AllowanceStore write lock poisoned in clear_for_principal, recovering");
            e.into_inner()
        });
        store.remove(principal);
    }

    /// Atomically fence future allowance creation and clear existing grants.
    ///
    /// # Errors
    ///
    /// Returns a storage error if either internal lock is poisoned.
    pub fn begin_principal_retirement(&self, principal: &PrincipalId) -> ApprovalResult<()> {
        let mut retirement = self
            .retiring_principals
            .write()
            .map_err(|e| ApprovalError::Storage(e.to_string()))?;
        retirement.insert(principal.clone());
        let mut allowances = self
            .allowances
            .write()
            .map_err(|e| ApprovalError::Storage(e.to_string()))?;
        allowances.remove(principal);
        Ok(())
    }

    /// Release an in-process retirement fence after durable reclamation.
    pub fn finish_principal_retirement(&self, principal: &PrincipalId) {
        self.retiring_principals
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(principal);
    }

    /// Remove every principal's session-only allowances.
    ///
    /// Reserved for kernel-initiated global clears (shutdown). The normal
    /// disconnect path uses the principal-scoped
    /// [`clear_session_allowances`](Self::clear_session_allowances).
    pub fn clear_all_session_allowances(&self) {
        let mut store = self.allowances.write().unwrap_or_else(|e| {
            tracing::warn!(
                "AllowanceStore write lock poisoned in clear_all_session_allowances, recovering"
            );
            e.into_inner()
        });
        for principal_map in store.values_mut() {
            principal_map.retain(|_, a| !a.session_only);
        }
        store.retain(|_, m| !m.is_empty());
    }

    /// Get the total number of allowances in the store, across every principal.
    #[must_use]
    pub fn count(&self) -> usize {
        let store = self.allowances.read().unwrap_or_else(|e| {
            tracing::warn!("AllowanceStore read lock poisoned in count, recovering");
            e.into_inner()
        });
        store.values().map(HashMap::len).sum()
    }

    /// Number of allowances stored for `principal`.
    #[must_use]
    pub fn count_for(&self, principal: &PrincipalId) -> usize {
        let store = self.allowances.read().unwrap_or_else(|e| {
            tracing::warn!("AllowanceStore read lock poisoned in count_for, recovering");
            e.into_inner()
        });
        store.get(principal).map_or(0, HashMap::len)
    }

    /// Export `principal`'s session-scoped allowances for persistence.
    ///
    /// Returns allowances owned by `principal` that have `session_only: true`.
    /// Other principals' allowances are not included.
    #[must_use]
    pub fn export_session_allowances(&self, principal: &PrincipalId) -> Vec<Allowance> {
        let store = self.allowances.read().unwrap_or_else(|e| {
            tracing::warn!(
                "AllowanceStore read lock poisoned in export_session_allowances, recovering"
            );
            e.into_inner()
        });
        store.get(principal).map_or_else(Vec::new, |m| {
            m.values()
                .filter(|a| a.session_only && a.is_valid())
                .cloned()
                .collect()
        })
    }

    /// Export `principal`'s workspace-scoped allowances for persistence.
    ///
    /// Returns allowances owned by `principal` that have `session_only: false`
    /// and a `workspace_root` set.
    #[must_use]
    pub fn export_workspace_allowances(&self, principal: &PrincipalId) -> Vec<Allowance> {
        let store = self.allowances.read().unwrap_or_else(|e| {
            tracing::warn!(
                "AllowanceStore read lock poisoned in export_workspace_allowances, recovering"
            );
            e.into_inner()
        });
        store.get(principal).map_or_else(Vec::new, |m| {
            m.values()
                .filter(|a| !a.session_only && a.workspace_root.is_some() && a.is_valid())
                .cloned()
                .collect()
        })
    }

    /// Import allowances into the store, merging with existing ones.
    ///
    /// Each imported allowance is inserted under its own
    /// [`Allowance::principal`]. Used to restore session allowances from a
    /// persisted session.
    pub fn import_allowances(&self, allowances: Vec<Allowance>) {
        let mut store = self.allowances.write().unwrap_or_else(|e| {
            tracing::warn!("AllowanceStore write lock poisoned in import_allowances, recovering");
            e.into_inner()
        });
        for allowance in allowances {
            if allowance.is_valid() {
                store
                    .entry(allowance.principal.clone())
                    .or_default()
                    .insert(allowance.id.clone(), allowance);
            }
        }
    }
}

/// Pattern-match helper shared by [`AllowanceStore::find_matching`] and
/// [`AllowanceStore::find_matching_and_consume`]. Takes the allowance by
/// reference so both lock modes can reuse it.
fn allowance_matches(
    allowance: &Allowance,
    action: &SensitiveAction,
    workspace_root: Option<&Path>,
) -> bool {
    if !allowance.is_valid() {
        return false;
    }
    // Workspace-scoped allowances only match when the workspace root matches.
    if let Some(allowance_ws) = &allowance.workspace_root
        && workspace_root != Some(allowance_ws.as_path())
    {
        return false;
    }
    allowance.action_pattern.matches(action, workspace_root)
}

impl Default for AllowanceStore {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for AllowanceStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (principals, total) = {
            let store = self.allowances.read().unwrap_or_else(|e| {
                tracing::warn!("AllowanceStore read lock poisoned in Debug, recovering");
                e.into_inner()
            });
            (store.len(), store.values().map(HashMap::len).sum::<usize>())
        };
        let retiring = self
            .retiring_principals
            .read()
            .map_or(0, |principals| principals.len());
        f.debug_struct("AllowanceStore")
            .field("principals", &principals)
            .field("count", &total)
            .field("retiring_principals", &retiring)
            .finish()
    }
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;
