//! Bounded, canonical conditional key/value mutations.
//!
//! A [`KvMutationBatch`] is validated before it reaches a backend.  The
//! validation is deliberately independent of the backend so that every
//! implementation observes the same operation count, payload, key, and
//! duplicate rules.

use std::cmp::Ordering;

use crate::error::{StorageError, StorageResult};

use super::{composite_key, validate_key, validate_namespace};

/// Maximum number of conditions and mutations accepted by one batch.
pub const MAX_KV_BATCH_OPERATIONS: usize = 1024;

/// Maximum declared key/value payload accepted by one batch.
pub const MAX_KV_BATCH_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;

/// A validated namespace/key pair used by batch conditions and mutations.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct KvEntryKey {
    namespace: String,
    key: String,
}

impl KvEntryKey {
    /// Construct a validated namespace/key pair.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::InvalidKey`] when either component is empty or
    /// contains the reserved NUL separator.
    pub fn new(namespace: impl Into<String>, key: impl Into<String>) -> StorageResult<Self> {
        let namespace = namespace.into();
        let key = key.into();
        validate_namespace(&namespace)?;
        validate_key(&key)?;
        Ok(Self { namespace, key })
    }

    /// Return the namespace containing this key.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Return the key within the namespace.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Return this key's canonical namespaced byte representation.
    #[must_use]
    pub(crate) fn composite(&self) -> Vec<u8> {
        composite_key(&self.namespace, &self.key)
    }
}

/// A condition evaluated against the one root snapshot used by a batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KvBatchCondition {
    /// Match when the current value equals `expected`.
    ///
    /// `None` means that the key must be absent.
    ValueEquals {
        /// Key whose current value is checked.
        key: KvEntryKey,
        /// Expected value, or `None` when the key must be absent.
        expected: Option<Vec<u8>>,
    },
}

impl KvBatchCondition {
    /// Return the key checked by this condition.
    #[must_use]
    pub fn key(&self) -> &KvEntryKey {
        match self {
            Self::ValueEquals { key, .. } => key,
        }
    }

    /// Return the expected value, or `None` when absence is required.
    #[must_use]
    pub fn expected(&self) -> Option<&[u8]> {
        match self {
            Self::ValueEquals { expected, .. } => expected.as_deref(),
        }
    }
}

/// A mutation applied after every batch condition matches.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KvBatchMutation {
    /// Set a key to the supplied value.
    Set {
        /// Key receiving the value.
        key: KvEntryKey,
        /// Bytes stored at the key.
        value: Vec<u8>,
    },
    /// Delete a key if it exists.
    Delete {
        /// Key to remove.
        key: KvEntryKey,
    },
}

impl KvBatchMutation {
    /// Return the key changed by this mutation.
    #[must_use]
    pub fn key(&self) -> &KvEntryKey {
        match self {
            Self::Set { key, .. } | Self::Delete { key } => key,
        }
    }

    /// Return the value written by this mutation, or `None` for deletion.
    #[must_use]
    pub fn value(&self) -> Option<&[u8]> {
        match self {
            Self::Set { value, .. } => Some(value),
            Self::Delete { .. } => None,
        }
    }

    pub(crate) fn replacement(&self) -> Option<&[u8]> {
        self.value()
    }
}

/// Canonical bounded conditions and mutations for one atomic KV operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KvMutationBatch {
    conditions: Vec<KvBatchCondition>,
    mutations: Vec<KvBatchMutation>,
}

impl KvMutationBatch {
    /// Construct and canonicalize a bounded mutation batch.
    ///
    /// Conditions and mutations are independently sorted by their canonical
    /// composite key.  A batch must contain at least one mutation.  A key may
    /// appear once as a condition and once as a mutation, but duplicate
    /// conditions or duplicate/conflicting mutations are rejected.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::InvalidKey`] for an invalid key,
    /// [`StorageError::Serialization`] for duplicate entries, an empty
    /// mutation list, or a bound violation, and [`StorageError::Internal`]
    /// when the bounded payload arithmetic overflows.
    pub fn new<C, M>(conditions: C, mutations: M) -> StorageResult<Self>
    where
        C: IntoIterator<Item = KvBatchCondition>,
        M: IntoIterator<Item = KvBatchMutation>,
    {
        let mut canonical_conditions = Vec::new();
        let mut payload = 0_usize;
        for condition in conditions {
            if canonical_conditions.len() >= MAX_KV_BATCH_OPERATIONS {
                return Err(operation_bound_error());
            }
            payload = add_declared_payload(
                payload,
                condition.key(),
                condition.expected().map_or(0, <[u8]>::len),
            )?;
            if payload > MAX_KV_BATCH_PAYLOAD_BYTES {
                return Err(payload_bound_error());
            }
            canonical_conditions.push(condition);
        }

        let mut canonical_mutations = Vec::new();
        for mutation in mutations {
            if canonical_conditions
                .len()
                .saturating_add(canonical_mutations.len())
                >= MAX_KV_BATCH_OPERATIONS
            {
                return Err(operation_bound_error());
            }
            payload = add_declared_payload(
                payload,
                mutation.key(),
                mutation.value().map_or(0, <[u8]>::len),
            )?;
            if payload > MAX_KV_BATCH_PAYLOAD_BYTES {
                return Err(payload_bound_error());
            }
            canonical_mutations.push(mutation);
        }
        Self::try_from_parts(canonical_conditions, canonical_mutations)
    }

    /// Alias for [`Self::new`] emphasizing that construction performs bounds
    /// and duplicate validation.
    ///
    /// # Errors
    ///
    /// Returns the same validation errors as [`Self::new`].
    pub fn try_new<C, M>(conditions: C, mutations: M) -> StorageResult<Self>
    where
        C: IntoIterator<Item = KvBatchCondition>,
        M: IntoIterator<Item = KvBatchMutation>,
    {
        Self::new(conditions, mutations)
    }

    fn try_from_parts(
        mut conditions: Vec<KvBatchCondition>,
        mut mutations: Vec<KvBatchMutation>,
    ) -> StorageResult<Self> {
        if mutations.is_empty() {
            return Err(StorageError::Serialization(
                "KV mutation batch must contain at least one mutation".to_owned(),
            ));
        }
        let operation_count = conditions.len().saturating_add(mutations.len());
        if operation_count > MAX_KV_BATCH_OPERATIONS {
            return Err(operation_bound_error());
        }

        let mut payload = 0_usize;
        for condition in &conditions {
            payload = add_declared_payload(
                payload,
                condition.key(),
                condition.expected().map_or(0, <[u8]>::len),
            )?;
        }
        for mutation in &mutations {
            payload = add_declared_payload(
                payload,
                mutation.key(),
                mutation.value().map_or(0, <[u8]>::len),
            )?;
        }
        if payload > MAX_KV_BATCH_PAYLOAD_BYTES {
            return Err(payload_bound_error());
        }

        conditions.sort_by(|left, right| canonical_key_cmp(left.key(), right.key()));
        if conditions
            .windows(2)
            .any(|pair| pair[0].key() == pair[1].key())
        {
            return Err(StorageError::Serialization(
                "KV mutation batch contains duplicate conditions".to_owned(),
            ));
        }

        mutations.sort_by(|left, right| canonical_key_cmp(left.key(), right.key()));
        if mutations
            .windows(2)
            .any(|pair| pair[0].key() == pair[1].key())
        {
            return Err(StorageError::Serialization(
                "KV mutation batch contains duplicate or conflicting mutations".to_owned(),
            ));
        }

        Ok(Self {
            conditions,
            mutations,
        })
    }

    /// Return conditions in canonical composite-key order.
    #[must_use]
    pub fn conditions(&self) -> &[KvBatchCondition] {
        &self.conditions
    }

    /// Return mutations in canonical composite-key order.
    #[must_use]
    pub fn mutations(&self) -> &[KvBatchMutation] {
        &self.mutations
    }

    /// Return the number of declared conditions and mutations.
    #[must_use]
    pub fn operation_count(&self) -> usize {
        self.conditions.len().saturating_add(self.mutations.len())
    }

    /// Return the declared key/value payload in bytes.
    #[must_use]
    pub fn payload_bytes(&self) -> usize {
        self.conditions
            .iter()
            .map(|condition| {
                condition
                    .key()
                    .namespace()
                    .len()
                    .saturating_add(1)
                    .saturating_add(condition.key().key().len())
                    .saturating_add(condition.expected().map_or(0, <[u8]>::len))
            })
            .chain(self.mutations.iter().map(|mutation| {
                mutation
                    .key()
                    .namespace()
                    .len()
                    .saturating_add(1)
                    .saturating_add(mutation.key().key().len())
                    .saturating_add(mutation.value().map_or(0, <[u8]>::len))
            }))
            .fold(0, usize::saturating_add)
    }
}

fn add_payload(current: usize, key: &KvEntryKey) -> StorageResult<usize> {
    let key_bytes = key
        .namespace()
        .len()
        .checked_add(1)
        .and_then(|length| length.checked_add(key.key().len()))
        .ok_or_else(|| {
            StorageError::Internal("KV mutation batch payload length overflow".to_owned())
        })?;
    let payload = current.checked_add(key_bytes).ok_or_else(|| {
        StorageError::Internal("KV mutation batch payload length overflow".to_owned())
    })?;
    Ok(payload)
}

fn add_declared_payload(
    current: usize,
    key: &KvEntryKey,
    value_bytes: usize,
) -> StorageResult<usize> {
    add_payload(current, key)?
        .checked_add(value_bytes)
        .ok_or_else(|| {
            StorageError::Internal("KV mutation batch payload length overflow".to_owned())
        })
}

fn operation_bound_error() -> StorageError {
    StorageError::Serialization(format!(
        "KV mutation batch exceeds {MAX_KV_BATCH_OPERATIONS} conditions and mutations"
    ))
}

fn payload_bound_error() -> StorageError {
    StorageError::Serialization(format!(
        "KV mutation batch payload exceeds {MAX_KV_BATCH_PAYLOAD_BYTES} bytes"
    ))
}

fn canonical_key_cmp(left: &KvEntryKey, right: &KvEntryKey) -> Ordering {
    left.composite().cmp(&right.composite())
}

/// The result of evaluating one condition against the batch snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KvConditionResult {
    /// Key checked by the condition.
    pub key: KvEntryKey,
    /// Whether the key matched its expected value.
    pub matched: bool,
}

/// The outcome of one atomic mutation batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KvBatchOutcome {
    /// Whether every condition matched and mutations were accepted.
    pub applied: bool,
    /// Result for every condition, in canonical condition order.
    pub conditions: Vec<KvConditionResult>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(namespace: &str, value: &str) -> KvEntryKey {
        KvEntryKey::new(namespace, value).unwrap()
    }

    #[test]
    fn canonicalizes_by_composite_key() {
        let batch = KvMutationBatch::new(
            [
                KvBatchCondition::ValueEquals {
                    key: key("z", "b"),
                    expected: None,
                },
                KvBatchCondition::ValueEquals {
                    key: key("a", "z"),
                    expected: Some(vec![1]),
                },
            ],
            [
                KvBatchMutation::Delete { key: key("z", "a") },
                KvBatchMutation::Set {
                    key: key("a", "a"),
                    value: vec![2],
                },
            ],
        )
        .unwrap();
        assert_eq!(batch.conditions()[0].key(), &key("a", "z"));
        assert_eq!(batch.mutations()[0].key(), &key("a", "a"));
    }

    #[test]
    fn rejects_empty_mutations_and_duplicates() {
        let k = key("ns", "k");
        assert!(
            KvMutationBatch::new(
                Vec::<KvBatchCondition>::new(),
                Vec::<KvBatchMutation>::new()
            )
            .is_err()
        );
        assert!(
            KvMutationBatch::new(
                [
                    KvBatchCondition::ValueEquals {
                        key: k.clone(),
                        expected: None
                    },
                    KvBatchCondition::ValueEquals {
                        key: k.clone(),
                        expected: None
                    }
                ],
                [KvBatchMutation::Delete { key: k.clone() }],
            )
            .is_err()
        );
        assert!(
            KvMutationBatch::new(
                [],
                [
                    KvBatchMutation::Delete { key: k.clone() },
                    KvBatchMutation::Set {
                        key: k,
                        value: vec![1]
                    }
                ],
            )
            .is_err()
        );
    }
}
