//! Two-step durable invite redemption.
//!
//! These operations let a handler inspect a bearer, complete fallible
//! provisioning, and then atomically consume the exact record it inspected.

use super::{DurableInviteStore, Invite, SYSTEM_KV_NAMESPACE, now_epoch};

impl DurableInviteStore {
    /// Read one currently redeemable invite without consuming it.
    ///
    /// Handlers use this to prepare fallible provisioning before the atomic
    /// consume that commits a redemption. Callers must commit with
    /// [`Self::consume_if_unchanged`] so a stale provisioned identity cannot
    /// win after another daemon consumed the same record.
    ///
    /// # Errors
    ///
    /// Returns a storage error if the record cannot be read or decoded.
    pub async fn redeemable(
        &self,
        token_hash: &str,
    ) -> astrid_storage::StorageResult<Option<Invite>> {
        let key = Self::key(token_hash);
        let Some(value) = self.backend.get(SYSTEM_KV_NAMESPACE, &key).await? else {
            return Ok(None);
        };
        let invite = Self::decode(&value)?;
        let now = now_epoch();
        if invite.remaining_uses == 0
            || invite
                .expires_at_epoch
                .is_some_and(|expires| expires <= now)
        {
            return Ok(None);
        }
        Ok(Some(invite))
    }

    /// Consume the exact invite previously returned by [`Self::redeemable`].
    ///
    /// This is the commit operation for prepare-then-consume handlers. It
    /// fails closed if the record changed, expired, or was consumed while the
    /// caller performed provisioning.
    ///
    /// # Errors
    ///
    /// Returns a storage error if the conditional mutation cannot be applied.
    pub async fn consume_if_unchanged(
        &self,
        expected: &Invite,
    ) -> astrid_storage::StorageResult<bool> {
        let now = now_epoch();
        if expected.remaining_uses == 0
            || expected
                .expires_at_epoch
                .is_some_and(|expires| expires <= now)
        {
            return Ok(false);
        }
        let key = Self::key(&expected.token_hash);
        let expected_value = Self::encode(expected)?;
        let mut consumed = expected.clone();
        consumed.remaining_uses = consumed.remaining_uses.saturating_sub(1);
        let mutation = if consumed.remaining_uses == 0 {
            astrid_storage::KvBatchMutation::Delete {
                key: astrid_storage::KvEntryKey::new(SYSTEM_KV_NAMESPACE, &key)?,
            }
        } else {
            astrid_storage::KvBatchMutation::Set {
                key: astrid_storage::KvEntryKey::new(SYSTEM_KV_NAMESPACE, &key)?,
                value: Self::encode(&consumed)?,
            }
        };
        self.apply(
            vec![astrid_storage::KvBatchCondition::ValueEquals {
                key: astrid_storage::KvEntryKey::new(SYSTEM_KV_NAMESPACE, &key)?,
                expected: Some(expected_value),
            }],
            vec![mutation],
        )
        .await
    }
}
