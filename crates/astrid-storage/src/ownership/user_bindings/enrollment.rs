//! Bind enrollment to one explicit delegation, including its revocation epoch.

use super::{OwnershipError, OwnershipStore, PrincipalUid, UserDeviceBinding};
use crate::ownership::{GRAPH_KEY, OWNERSHIP_NAMESPACE};
use serde::{Deserialize, Serialize};

#[cfg(test)]
mod tests;
use crate::{KvBatchCondition, KvBatchMutation, KvEntryKey, KvMutationBatch};

/// Server-issued ownership context. This is not proof of transport authentication.
/// Store only in trusted enrollment records, never accept it from a request body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreationDelegation {
    binding: UserDeviceBinding,
}

impl CreationDelegation {
    /// Principal whose live device and capabilities must still be checked.
    #[must_use]
    pub fn principal(&self) -> PrincipalUid {
        self.binding.principal
    }

    /// Exact issuer key; never the newly enrolling device's key.
    #[must_use]
    pub fn public_key(&self) -> &[u8; 32] {
        &self.binding.public_key
    }
}

impl OwnershipStore {
    /// Capture a current manager delegation after independent authentication.
    ///
    /// # Errors
    /// Rejects absent delegation or insufficient current membership.
    pub async fn capture_creation_delegation(
        &self,
        principal: PrincipalUid,
        public_key: &[u8; 32],
    ) -> Result<CreationDelegation, OwnershipError> {
        let graph = self.load().await?;
        let user = graph
            .user_for_device(principal, public_key)
            .ok_or(OwnershipError::UserDeviceNotBound(principal))?;
        let binding = graph
            .user_bindings
            .iter()
            .find(|binding| binding.principal == principal && &binding.public_key == public_key)
            .ok_or(OwnershipError::UserDeviceNotBound(principal))?;
        let fleet = graph
            .fleet(binding.fleet)
            .ok_or(OwnershipError::FleetNotFound(binding.fleet))?;
        Self::require_manager(fleet, user)?;
        Ok(CreationDelegation {
            binding: binding.clone(),
        })
    }

    /// Commit first ownership and a caller's conditional enrollment mutation together.
    ///
    /// Both use this store's backend. A stale graph or token condition returns
    /// false without changing either. No retry silently accepts a new delegation.
    /// The caller must check token expiry and the issuer's current transport key
    /// and capability before calling. Companion mutations must not target ownership.
    /// No user delegation is granted to the child device.
    ///
    /// # Errors
    /// Rejects revoked/replaced authority, invalid assignments/batches and backend
    /// failures. Backend errors may have ambiguous commit outcome: do not delete
    /// provisioned identities on an unconfirmed error.
    pub async fn commit_enrolled_principal(
        &self,
        child: PrincipalUid,
        delegation: &CreationDelegation,
        mut conditions: Vec<KvBatchCondition>,
        mut mutations: Vec<KvBatchMutation>,
    ) -> Result<bool, OwnershipError> {
        let _guard = self.mutation_lock.lock().await;
        let backend = self.storage.backend();
        if !backend.supports_atomic_batch() {
            return Err(OwnershipError::Storage(crate::StorageError::Internal(
                "enrollment requires an atomic ownership backend".into(),
            )));
        }
        if conditions
            .iter()
            .any(|condition| condition.key().namespace() == OWNERSHIP_NAMESPACE)
            || mutations
                .iter()
                .any(|mutation| mutation.key().namespace() == OWNERSHIP_NAMESPACE)
        {
            return Err(OwnershipError::CorruptGraph(
                "enrollment cannot supply ownership mutations".into(),
            ));
        }
        let current = self.storage.get(GRAPH_KEY).await?;
        let mut graph = self.decode(current.as_deref())?;
        let binding = &delegation.binding;
        if !graph.user_bindings.contains(binding)
            || graph.user_for_device(binding.principal, &binding.public_key) != Some(binding.user)
            || !graph
                .fleet(binding.fleet)
                .and_then(|fleet| fleet.membership(binding.user))
                .is_some_and(|membership| membership.role.can_manage())
        {
            return Ok(false);
        }
        self.assign_creation_in_graph(&mut graph, child, binding.principal, binding.user)?;
        graph.validate(&self.principals)?;
        let encoded = serde_json::to_vec(&graph)
            .map_err(|error| OwnershipError::Serialization(error.to_string()))?;
        let key = KvEntryKey::new(OWNERSHIP_NAMESPACE, GRAPH_KEY)?;
        conditions.push(KvBatchCondition::ValueEquals {
            key: key.clone(),
            expected: current,
        });
        mutations.push(KvBatchMutation::Set {
            key,
            value: encoded,
        });
        let batch = KvMutationBatch::new(conditions, mutations)?;
        Ok(backend.apply_batch(&batch).await?.applied)
    }
}
