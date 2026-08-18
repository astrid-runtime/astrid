//! Two-step durable pair-token redemption and reservation operations.
//!
//! Pair-device provisioning is fallible: the handler must prepare the device
//! profile before it can consume the bearer. These methods reserve the exact
//! record that was inspected, then either release that reservation after a
//! preparation failure or consume it after the profile update succeeds.

use super::{
    DurablePairToken, DurablePairTokenStore, RECORD_PREFIX, SYSTEM_KV_NAMESPACE, TokenHash,
    now_epoch,
};

const RESERVATION_PREFIX: &str = "reservation:";

/// Durable locations for one pair token. The only legal movements are
/// `Redeemable -> Reserved` while provisioning and `Reserved -> Redeemable`
/// on preparation failure, or `Reserved -> Absent` on successful consume.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReservationState {
    Redeemable,
    Reserved,
}

impl ReservationState {
    fn key(self, hash: &TokenHash) -> String {
        match self {
            Self::Redeemable => format!("{RECORD_PREFIX}{}", hash.as_str()),
            Self::Reserved => format!("{RESERVATION_PREFIX}{}", hash.as_str()),
        }
    }
}

impl DurablePairTokenStore {
    fn reservation_key(hash: &TokenHash) -> String {
        ReservationState::Reserved.key(hash)
    }

    /// Read one unexpired token without consuming it.
    ///
    /// The redeem handler uses this before claiming the exact record with
    /// [`Self::reserve_if_unchanged`]. A claimed record is not redeemable by
    /// another caller until its owner releases the reservation.
    ///
    /// # Errors
    ///
    /// Returns a storage error if the record cannot be read or decoded.
    pub async fn redeemable(
        &self,
        token_hash: &str,
    ) -> astrid_storage::StorageResult<Option<DurablePairToken>> {
        let hash = TokenHash::parse(token_hash)?;
        let key = ReservationState::Redeemable.key(&hash);
        let Some(value) = self.backend.get(SYSTEM_KV_NAMESPACE, &key).await? else {
            return Ok(None);
        };
        let token = Self::decode(&value)?;
        if token.expires_at_epoch <= now_epoch() {
            return Ok(None);
        }
        Ok(Some(token))
    }

    /// Reserve the exact token previously returned by [`Self::redeemable`].
    ///
    /// The reservation atomically moves the exact record to a non-redeemable
    /// reservation key. A failed profile update can restore that exact record,
    /// but only while no replacement has occupied the redeemable key.
    ///
    /// # Errors
    ///
    /// Returns a storage error if the conditional mutation cannot be applied.
    pub async fn reserve_if_unchanged(
        &self,
        expected: &DurablePairToken,
    ) -> astrid_storage::StorageResult<bool> {
        if expected.expires_at_epoch <= now_epoch() {
            return Ok(false);
        }
        let expected_value = Self::encode(expected)?;
        let hash = TokenHash::parse(&expected.token_hash)?;
        let key = ReservationState::Redeemable.key(&hash);
        let reservation_key = Self::reservation_key(&hash);
        self.apply(
            vec![
                astrid_storage::KvBatchCondition::ValueEquals {
                    key: astrid_storage::KvEntryKey::new(SYSTEM_KV_NAMESPACE, &key)?,
                    expected: Some(expected_value.clone()),
                },
                astrid_storage::KvBatchCondition::ValueEquals {
                    key: astrid_storage::KvEntryKey::new(SYSTEM_KV_NAMESPACE, &reservation_key)?,
                    expected: None,
                },
            ],
            vec![
                astrid_storage::KvBatchMutation::Delete {
                    key: astrid_storage::KvEntryKey::new(SYSTEM_KV_NAMESPACE, key)?,
                },
                astrid_storage::KvBatchMutation::Set {
                    key: astrid_storage::KvEntryKey::new(SYSTEM_KV_NAMESPACE, reservation_key)?,
                    value: expected_value,
                },
            ],
        )
        .await
    }

    /// Read the raw outstanding reservation for one identifier.
    async fn reservation(
        &self,
        token_hash: &str,
    ) -> astrid_storage::StorageResult<Option<Vec<u8>>> {
        let hash = TokenHash::parse(token_hash)?;
        self.backend
            .get(SYSTEM_KV_NAMESPACE, &Self::reservation_key(&hash))
            .await
    }

    /// Release the exact reservation back to its original redeemable record.
    ///
    /// Returns `false` if this caller no longer owns the reservation or if a
    /// replacement now occupies the redeemable key. In particular, this cannot
    /// overwrite a replacement issued after the reservation was created.
    ///
    /// # Errors
    ///
    /// Returns a storage error if the conditional mutation cannot be applied.
    pub async fn release_reservation(
        &self,
        expected: &DurablePairToken,
    ) -> astrid_storage::StorageResult<bool> {
        if expected.expires_at_epoch <= now_epoch() {
            return Ok(false);
        }
        let expected_value = Self::encode(expected)?;
        let hash = TokenHash::parse(&expected.token_hash)?;
        let key = ReservationState::Redeemable.key(&hash);
        let reservation_key = Self::reservation_key(&hash);
        self.apply(
            vec![
                astrid_storage::KvBatchCondition::ValueEquals {
                    key: astrid_storage::KvEntryKey::new(SYSTEM_KV_NAMESPACE, &reservation_key)?,
                    expected: Some(expected_value.clone()),
                },
                astrid_storage::KvBatchCondition::ValueEquals {
                    key: astrid_storage::KvEntryKey::new(SYSTEM_KV_NAMESPACE, &key)?,
                    expected: None,
                },
            ],
            vec![
                astrid_storage::KvBatchMutation::Set {
                    key: astrid_storage::KvEntryKey::new(SYSTEM_KV_NAMESPACE, key)?,
                    value: expected_value,
                },
                astrid_storage::KvBatchMutation::Delete {
                    key: astrid_storage::KvEntryKey::new(SYSTEM_KV_NAMESPACE, reservation_key)?,
                },
            ],
        )
        .await
    }

    /// Commit the exact reservation by deleting the token.
    ///
    /// # Errors
    ///
    /// Returns a storage error if the conditional delete cannot be applied.
    pub async fn consume_reservation(
        &self,
        expected: &DurablePairToken,
    ) -> astrid_storage::StorageResult<bool> {
        if expected.expires_at_epoch <= now_epoch() {
            return Ok(false);
        }
        let expected_value = Self::encode(expected)?;
        let hash = TokenHash::parse(&expected.token_hash)?;
        let reservation_key = Self::reservation_key(&hash);
        self.apply(
            vec![astrid_storage::KvBatchCondition::ValueEquals {
                key: astrid_storage::KvEntryKey::new(SYSTEM_KV_NAMESPACE, &reservation_key)?,
                expected: Some(expected_value),
            }],
            vec![astrid_storage::KvBatchMutation::Delete {
                key: astrid_storage::KvEntryKey::new(SYSTEM_KV_NAMESPACE, reservation_key)?,
            }],
        )
        .await
    }

    /// Remove one token by canonical fingerprint.
    ///
    /// A token currently being prepared is revoked from its reservation key;
    /// this prevents the preparation owner from restoring a revoked record.
    ///
    /// # Errors
    ///
    /// Returns a storage error if the conditional delete cannot be applied.
    pub async fn revoke(&self, token_hash: &str) -> astrid_storage::StorageResult<bool> {
        let hash = TokenHash::parse(token_hash)?;
        let key = ReservationState::Redeemable.key(&hash);
        if let Some(value) = self.backend.get(SYSTEM_KV_NAMESPACE, &key).await? {
            Self::decode(&value)?;
            return self
                .apply(
                    vec![astrid_storage::KvBatchCondition::ValueEquals {
                        key: astrid_storage::KvEntryKey::new(SYSTEM_KV_NAMESPACE, &key)?,
                        expected: Some(value),
                    }],
                    vec![astrid_storage::KvBatchMutation::Delete {
                        key: astrid_storage::KvEntryKey::new(SYSTEM_KV_NAMESPACE, key)?,
                    }],
                )
                .await;
        }

        let reservation_key = Self::reservation_key(&hash);
        let Some(value) = self.reservation(token_hash).await? else {
            return Ok(false);
        };
        Self::decode(&value)?;
        self.apply(
            vec![astrid_storage::KvBatchCondition::ValueEquals {
                key: astrid_storage::KvEntryKey::new(SYSTEM_KV_NAMESPACE, &reservation_key)?,
                expected: Some(value),
            }],
            vec![astrid_storage::KvBatchMutation::Delete {
                key: astrid_storage::KvEntryKey::new(SYSTEM_KV_NAMESPACE, reservation_key)?,
            }],
        )
        .await
    }

    /// Prune expired tokens and abandoned reservations with conditional
    /// deletes.
    ///
    /// # Errors
    ///
    /// Returns a storage error if records cannot be read or a conditional
    /// delete cannot be applied.
    pub async fn prune(&self) -> astrid_storage::StorageResult<usize> {
        let reservation_keys = self
            .backend
            .list_keys_with_prefix(SYSTEM_KV_NAMESPACE, RESERVATION_PREFIX)
            .await?;
        let now = now_epoch();
        let mut removed = 0usize;
        for key in reservation_keys {
            let Some(value) = self.backend.get(SYSTEM_KV_NAMESPACE, &key).await? else {
                continue;
            };
            let token = Self::decode(&value)?;
            if token.expires_at_epoch > now {
                continue;
            }
            if self
                .apply(
                    vec![astrid_storage::KvBatchCondition::ValueEquals {
                        key: astrid_storage::KvEntryKey::new(SYSTEM_KV_NAMESPACE, &key)?,
                        expected: Some(value),
                    }],
                    vec![astrid_storage::KvBatchMutation::Delete {
                        key: astrid_storage::KvEntryKey::new(SYSTEM_KV_NAMESPACE, key)?,
                    }],
                )
                .await?
            {
                removed = removed.saturating_add(1);
            }
        }

        let records = self.list().await?;
        for token in records {
            if token.expires_at_epoch > now {
                continue;
            }
            let hash = TokenHash::parse(&token.token_hash)?;
            let key = ReservationState::Redeemable.key(&hash);
            let Some(value) = self.backend.get(SYSTEM_KV_NAMESPACE, &key).await? else {
                continue;
            };
            if self
                .apply(
                    vec![astrid_storage::KvBatchCondition::ValueEquals {
                        key: astrid_storage::KvEntryKey::new(SYSTEM_KV_NAMESPACE, &key)?,
                        expected: Some(value),
                    }],
                    vec![astrid_storage::KvBatchMutation::Delete {
                        key: astrid_storage::KvEntryKey::new(SYSTEM_KV_NAMESPACE, key)?,
                    }],
                )
                .await?
            {
                removed = removed.saturating_add(1);
            }
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reservation_state_keys_are_distinct_and_canonical() {
        let hash = TokenHash::parse(&crate::pair_token::hash_token("reservation key"))
            .expect("hash_token emits a canonical fingerprint");
        let redeemable = ReservationState::Redeemable.key(&hash);
        let reserved = ReservationState::Reserved.key(&hash);
        assert_ne!(redeemable, reserved);
        assert!(redeemable.starts_with(RECORD_PREFIX));
        assert!(reserved.starts_with(RESERVATION_PREFIX));
    }

    #[test]
    fn token_hash_rejects_noncanonical_identifiers_before_key_derivation() {
        assert!(TokenHash::parse("sha256:deadbeef").is_err());
        assert!(TokenHash::parse("blake3:ABCDEF").is_err());
    }
}
