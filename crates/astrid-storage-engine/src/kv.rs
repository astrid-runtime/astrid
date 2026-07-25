//! Typed key/value projection over principal-state objects.
//!
//! This module supplies the logical grammar needed by the compatibility
//! `KvStore` adapter. It deliberately does not select a persistent byte
//! framing or production digest. Values remain canonical object bytes and the
//! engine's injected [`ObjectIdentity`] implementation supplies identifiers.

use std::collections::BTreeMap;
use std::fmt;

use astrid_storage_model::{
    ModelError, ObjectClass, ObjectFormatVersion, ObjectId, ObjectIdentity, ObjectKind,
    ObjectRecord, ObjectReference, ReferenceKind, RootState,
};

use crate::{CommitOutcome, InMemoryEngine, RootSnapshot, RootTransaction};

const FORMAT_VERSION: ObjectFormatVersion = ObjectFormatVersion::new(1);
const KV_LABEL: &[u8] = b"kv";
const PARENT_LABEL: &[u8] = b"parent";
const STATE_LABEL: &[u8] = b"state";

/// Complete logical key/value state owned by one principal.
///
/// Namespaces and keys are maintained in bytewise UTF-8 order. Empty
/// namespaces are omitted, so deleting the final key restores the same
/// canonical state as a namespace that never existed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KvState {
    namespaces: BTreeMap<String, BTreeMap<String, Vec<u8>>>,
}

impl KvState {
    /// Construct empty key/value state.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            namespaces: BTreeMap::new(),
        }
    }

    /// Borrow one value.
    #[must_use]
    pub fn get(&self, namespace: &str, key: &str) -> Option<&[u8]> {
        self.namespaces
            .get(namespace)
            .and_then(|entries| entries.get(key))
            .map(Vec::as_slice)
    }

    /// Return whether one key exists.
    #[must_use]
    pub fn contains_key(&self, namespace: &str, key: &str) -> bool {
        self.get(namespace, key).is_some()
    }

    /// Return every key in one namespace in canonical order.
    #[must_use]
    pub fn keys(&self, namespace: &str) -> Vec<String> {
        self.namespaces
            .get(namespace)
            .map(|entries| entries.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Return keys beginning with `prefix` in canonical order.
    #[must_use]
    pub fn keys_with_prefix(&self, namespace: &str, prefix: &str) -> Vec<String> {
        self.namespaces
            .get(namespace)
            .map(|entries| {
                entries
                    .keys()
                    .filter(|key| key.starts_with(prefix))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Set one value, returning the previous value when present.
    ///
    /// # Errors
    ///
    /// Returns [`KvProjectionError::InvalidName`] when the namespace or key
    /// cannot be represented by the version-one projection grammar.
    pub fn set(
        &mut self,
        namespace: String,
        key: String,
        value: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, KvProjectionError> {
        validate_state_name(&namespace, "namespace")?;
        validate_state_name(&key, "key")?;
        Ok(self
            .namespaces
            .entry(namespace)
            .or_default()
            .insert(key, value))
    }

    /// Delete one key, returning its previous value when present.
    pub fn delete(&mut self, namespace: &str, key: &str) -> Option<Vec<u8>> {
        let entries = self.namespaces.get_mut(namespace)?;
        let removed = entries.remove(key);
        if entries.is_empty() {
            self.namespaces.remove(namespace);
        }
        removed
    }

    /// Delete one namespace and return its former key count.
    pub fn clear_namespace(&mut self, namespace: &str) -> u64 {
        self.namespaces
            .remove(namespace)
            .map_or(0, |entries| entries.len() as u64)
    }

    /// Delete keys beginning with `prefix` and return the removed count.
    pub fn clear_prefix(&mut self, namespace: &str, prefix: &str) -> u64 {
        let Some(entries) = self.namespaces.get_mut(namespace) else {
            return 0;
        };
        let keys: Vec<_> = entries
            .keys()
            .filter(|key| key.starts_with(prefix))
            .cloned()
            .collect();
        let count = keys.len() as u64;
        for key in keys {
            entries.remove(&key);
        }
        if entries.is_empty() {
            self.namespaces.remove(namespace);
        }
        count
    }

    /// Return whether the complete projection is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.namespaces.is_empty()
    }

    fn logical_bytes(&self) -> Result<u64, KvProjectionError> {
        self.namespaces
            .values()
            .flat_map(BTreeMap::values)
            .try_fold(0_u64, |total, value| {
                let value_len = u64::try_from(value.len())
                    .map_err(|_| KvProjectionError::LogicalBytesOverflow)?;
                total
                    .checked_add(value_len)
                    .ok_or(KvProjectionError::LogicalBytesOverflow)
            })
    }
}

/// Consistent principal root plus its decoded key/value projection.
///
/// A snapshot retains non-KV state-component and commit references. Consuming
/// it through [`InMemoryEngine::commit_kv`] replaces only the `kv` component
/// and preserves those other typed edges.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KvStateSnapshot<P> {
    principal: P,
    root: Option<RootState>,
    state: KvState,
    preserved_components: Vec<ObjectReference>,
    preserved_commit_references: Vec<ObjectReference>,
}

impl<P> KvStateSnapshot<P> {
    /// Borrow the principal whose state was captured.
    #[must_use]
    pub const fn principal(&self) -> &P {
        &self.principal
    }

    /// Return the exact root captured for compare-and-swap.
    #[must_use]
    pub const fn root(&self) -> Option<RootState> {
        self.root
    }

    /// Borrow the decoded key/value state.
    #[must_use]
    pub const fn state(&self) -> &KvState {
        &self.state
    }

    /// Mutate the decoded key/value state before committing this snapshot.
    #[must_use]
    pub const fn state_mut(&mut self) -> &mut KvState {
        &mut self.state
    }
}

/// Failure to decode or commit the typed key/value projection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KvProjectionError {
    /// The underlying object/root model rejected the operation.
    Model(ModelError),
    /// A typed projection object did not match the version-one grammar.
    InvalidFormat {
        /// Object whose record was invalid.
        object: ObjectId,
        /// Static explanation suitable for diagnostics.
        detail: &'static str,
    },
    /// A namespace or key label was not valid UTF-8.
    InvalidUtf8Label {
        /// Object containing the invalid label.
        object: ObjectId,
    },
    /// A namespace or key cannot be represented by the projection grammar.
    InvalidName {
        /// Name category that failed validation.
        name: &'static str,
    },
    /// Summed user-visible KV bytes exceeded the accounting type.
    LogicalBytesOverflow,
}

impl fmt::Display for KvProjectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Model(error) => write!(formatter, "{error}"),
            Self::InvalidFormat { object, detail } => {
                write!(
                    formatter,
                    "invalid KV projection object {object:?}: {detail}"
                )
            },
            Self::InvalidUtf8Label { object } => {
                write!(
                    formatter,
                    "KV projection object {object:?} has a non-UTF-8 label"
                )
            },
            Self::InvalidName { name } => {
                write!(
                    formatter,
                    "KV projection {name} is empty or contains a null byte"
                )
            },
            Self::LogicalBytesOverflow => formatter.write_str("KV logical-byte total overflowed"),
        }
    }
}

impl std::error::Error for KvProjectionError {}

impl From<ModelError> for KvProjectionError {
    fn from(error: ModelError) -> Self {
        Self::Model(error)
    }
}

impl<P: Ord, I> InMemoryEngine<P, I> {
    /// Decode one principal's current key/value projection under a consistent
    /// root snapshot.
    ///
    /// # Errors
    ///
    /// Returns a graph or typed-format error when the current root cannot be
    /// interpreted as the version-one projection grammar.
    pub fn kv_snapshot(&self, principal: P) -> Result<KvStateSnapshot<P>, KvProjectionError> {
        let Some(snapshot) = self.snapshot(&principal)? else {
            return Ok(KvStateSnapshot {
                principal,
                root: None,
                state: KvState::new(),
                preserved_components: Vec::new(),
                preserved_commit_references: Vec::new(),
            });
        };
        decode_snapshot(principal, &snapshot)
    }
}

impl<P: Ord, I: ObjectIdentity> InMemoryEngine<P, I> {
    /// Atomically replace the KV component in a previously captured snapshot.
    ///
    /// The snapshot's exact root is used as the compare-and-swap expectation.
    /// Callers may retry a [`ModelError::RootConflict`] by reading a fresh
    /// snapshot and reapplying their logical mutation.
    ///
    /// # Errors
    ///
    /// Returns an identity, collision, graph, typed-format, root-conflict, or
    /// arithmetic error without publishing a partial state.
    pub fn commit_kv(
        &self,
        snapshot: KvStateSnapshot<P>,
    ) -> Result<CommitOutcome, KvProjectionError> {
        let transaction = encode_transaction(self, snapshot)?;
        self.commit(transaction).map_err(Into::into)
    }
}

fn decode_snapshot<P>(
    principal: P,
    snapshot: &RootSnapshot,
) -> Result<KvStateSnapshot<P>, KvProjectionError> {
    let records: BTreeMap<_, _> = snapshot.records().iter().cloned().collect();
    let commit = typed_record(&records, snapshot.root().commit, ObjectKind::Commit)?;
    require_structural_record(snapshot.root().commit, commit)?;
    if commit
        .reference(PARENT_LABEL)
        .is_some_and(|reference| reference.kind() != ReferenceKind::Lineage)
    {
        return Err(invalid(
            snapshot.root().commit,
            "commit `parent` reference is not lineage",
        ));
    }
    let state_id = owned_target(snapshot.root().commit, commit, STATE_LABEL)?;
    let principal_state = typed_record(&records, state_id, ObjectKind::PrincipalState)?;
    require_structural_record(state_id, principal_state)?;

    let preserved_components = principal_state
        .references()
        .iter()
        .filter(|reference| reference.label() != KV_LABEL)
        .cloned()
        .collect();
    let preserved_commit_references = commit
        .references()
        .iter()
        .filter(|reference| reference.label() != STATE_LABEL && reference.label() != PARENT_LABEL)
        .cloned()
        .collect();

    let state = match principal_state.reference(KV_LABEL) {
        None => KvState::new(),
        Some(reference) if reference.kind() == ReferenceKind::Owns => {
            decode_namespace_map(&records, reference.target())?
        },
        Some(_) => {
            return Err(invalid(
                state_id,
                "principal-state `kv` reference is not owning",
            ));
        },
    };

    Ok(KvStateSnapshot {
        principal,
        root: Some(snapshot.root()),
        state,
        preserved_components,
        preserved_commit_references,
    })
}

fn decode_namespace_map(
    records: &BTreeMap<ObjectId, ObjectRecord>,
    map_id: ObjectId,
) -> Result<KvState, KvProjectionError> {
    let map = typed_record(records, map_id, ObjectKind::NamespaceMap)?;
    require_empty_bytes(map_id, map)?;
    require_class(map_id, map, ObjectClass::Metadata)?;
    let mut state = KvState::new();

    for namespace_reference in map.references() {
        if namespace_reference.kind() != ReferenceKind::Owns {
            return Err(invalid(map_id, "namespace reference is not owning"));
        }
        let namespace = decode_label(map_id, namespace_reference.label())?;
        validate_projection_name(map_id, &namespace, "namespace")?;
        let branch_id = namespace_reference.target();
        let branch = typed_record(records, branch_id, ObjectKind::KvBranch)?;
        require_structural_record(branch_id, branch)?;

        for key_reference in branch.references() {
            if key_reference.kind() != ReferenceKind::Owns {
                return Err(invalid(branch_id, "KV key reference is not owning"));
            }
            let key = decode_label(branch_id, key_reference.label())?;
            validate_projection_name(branch_id, &key, "key")?;
            let leaf_id = key_reference.target();
            let leaf = typed_record(records, leaf_id, ObjectKind::KvLeaf)?;
            require_class(leaf_id, leaf, ObjectClass::Data)?;
            if !leaf.references().is_empty() {
                return Err(invalid(leaf_id, "KV leaf has child references"));
            }
            if leaf.logical_bytes() != 0 {
                return Err(invalid(
                    leaf_id,
                    "KV leaf logical bytes are accounted at the namespace map",
                ));
            }
            state.set(namespace.clone(), key, leaf.canonical_bytes().to_vec())?;
        }
    }

    if map.logical_bytes() != state.logical_bytes()? {
        return Err(invalid(
            map_id,
            "namespace-map logical bytes do not equal visible value bytes",
        ));
    }
    Ok(state)
}

fn encode_transaction<P: Ord, I: ObjectIdentity>(
    engine: &InMemoryEngine<P, I>,
    snapshot: KvStateSnapshot<P>,
) -> Result<RootTransaction<P>, KvProjectionError> {
    let KvStateSnapshot {
        principal,
        root,
        state,
        mut preserved_components,
        mut preserved_commit_references,
    } = snapshot;
    let mut records = BTreeMap::new();
    let mut namespace_references = Vec::new();

    for (namespace, entries) in &state.namespaces {
        validate_state_name(namespace, "namespace")?;
        let mut key_references = Vec::new();
        for (key, value) in entries {
            validate_state_name(key, "key")?;
            let leaf = ObjectRecord::new(
                ObjectKind::KvLeaf,
                FORMAT_VERSION,
                value.clone(),
                Vec::new(),
                0,
                ObjectClass::Data,
            )?;
            let leaf_id = insert_identified(engine, &mut records, leaf)?;
            key_references.push(ObjectReference::owns(key.as_bytes().to_vec(), leaf_id));
        }
        key_references.sort();
        let branch = ObjectRecord::new(
            ObjectKind::KvBranch,
            FORMAT_VERSION,
            Vec::new(),
            key_references,
            0,
            ObjectClass::Metadata,
        )?;
        let branch_id = insert_identified(engine, &mut records, branch)?;
        namespace_references.push(ObjectReference::owns(
            namespace.as_bytes().to_vec(),
            branch_id,
        ));
    }

    namespace_references.sort();
    let namespace_map = ObjectRecord::new(
        ObjectKind::NamespaceMap,
        FORMAT_VERSION,
        Vec::new(),
        namespace_references,
        state.logical_bytes()?,
        ObjectClass::Metadata,
    )?;
    let namespace_map_id = insert_identified(engine, &mut records, namespace_map)?;

    preserved_components.push(ObjectReference::owns(KV_LABEL.to_vec(), namespace_map_id));
    preserved_components.sort();
    let principal_state = ObjectRecord::new(
        ObjectKind::PrincipalState,
        FORMAT_VERSION,
        Vec::new(),
        preserved_components,
        0,
        ObjectClass::Metadata,
    )?;
    let principal_state_id = insert_identified(engine, &mut records, principal_state)?;

    if let Some(previous) = root {
        preserved_commit_references.push(ObjectReference::new(
            PARENT_LABEL.to_vec(),
            previous.commit,
            ReferenceKind::Lineage,
        ));
    }
    preserved_commit_references.push(ObjectReference::owns(
        STATE_LABEL.to_vec(),
        principal_state_id,
    ));
    preserved_commit_references.sort();
    let commit = ObjectRecord::new(
        ObjectKind::Commit,
        FORMAT_VERSION,
        Vec::new(),
        preserved_commit_references,
        0,
        ObjectClass::Metadata,
    )?;
    let commit_id = insert_identified(engine, &mut records, commit)?;

    Ok(RootTransaction::new(
        principal,
        root,
        commit_id,
        records.into_iter().collect(),
    ))
}

fn insert_identified<P: Ord, I: ObjectIdentity>(
    engine: &InMemoryEngine<P, I>,
    records: &mut BTreeMap<ObjectId, ObjectRecord>,
    record: ObjectRecord,
) -> Result<ObjectId, KvProjectionError> {
    let id = engine.identify(&record);
    match records.get(&id) {
        Some(existing) if existing == &record => {},
        Some(_) => return Err(ModelError::ObjectCollision(id).into()),
        None => {
            records.insert(id, record);
        },
    }
    Ok(id)
}

fn typed_record(
    records: &BTreeMap<ObjectId, ObjectRecord>,
    id: ObjectId,
    expected: ObjectKind,
) -> Result<&ObjectRecord, KvProjectionError> {
    let record = records
        .get(&id)
        .ok_or(KvProjectionError::Model(ModelError::MissingObject(id)))?;
    if record.kind() != expected {
        return Err(invalid(id, "object has the wrong semantic kind"));
    }
    if record.format_version() != FORMAT_VERSION {
        return Err(invalid(id, "unsupported projection format version"));
    }
    Ok(record)
}

fn owned_target(
    object: ObjectId,
    record: &ObjectRecord,
    label: &[u8],
) -> Result<ObjectId, KvProjectionError> {
    let reference = record
        .reference(label)
        .ok_or_else(|| invalid(object, "required owned reference is missing"))?;
    if reference.kind() != ReferenceKind::Owns {
        return Err(invalid(object, "required reference is not owning"));
    }
    Ok(reference.target())
}

fn require_structural_record(
    object: ObjectId,
    record: &ObjectRecord,
) -> Result<(), KvProjectionError> {
    require_empty_bytes(object, record)?;
    require_class(object, record, ObjectClass::Metadata)?;
    if record.logical_bytes() != 0 {
        return Err(invalid(object, "structural object has logical bytes"));
    }
    Ok(())
}

fn require_empty_bytes(object: ObjectId, record: &ObjectRecord) -> Result<(), KvProjectionError> {
    if !record.canonical_bytes().is_empty() {
        return Err(invalid(
            object,
            "structural object has canonical payload bytes",
        ));
    }
    Ok(())
}

fn require_class(
    object: ObjectId,
    record: &ObjectRecord,
    expected: ObjectClass,
) -> Result<(), KvProjectionError> {
    if record.class() != expected {
        return Err(invalid(object, "object has the wrong accounting class"));
    }
    Ok(())
}

fn decode_label(object: ObjectId, label: &[u8]) -> Result<String, KvProjectionError> {
    std::str::from_utf8(label)
        .map(str::to_owned)
        .map_err(|_| KvProjectionError::InvalidUtf8Label { object })
}

fn validate_projection_name(
    object: ObjectId,
    value: &str,
    name: &'static str,
) -> Result<(), KvProjectionError> {
    if value.is_empty() {
        return Err(invalid(
            object,
            match name {
                "namespace" => "namespace label is empty",
                _ => "key label is empty",
            },
        ));
    }
    if value.contains('\0') {
        return Err(invalid(
            object,
            match name {
                "namespace" => "namespace label contains a null byte",
                _ => "key label contains a null byte",
            },
        ));
    }
    Ok(())
}

fn validate_state_name(value: &str, name: &'static str) -> Result<(), KvProjectionError> {
    if value.is_empty() || value.contains('\0') {
        return Err(KvProjectionError::InvalidName { name });
    }
    Ok(())
}

const fn invalid(object: ObjectId, detail: &'static str) -> KvProjectionError {
    KvProjectionError::InvalidFormat { object, detail }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy, Debug)]
    struct TestIdentity;

    impl ObjectIdentity for TestIdentity {
        fn identify(&self, record: &ObjectRecord) -> ObjectId {
            let mut hasher =
                blake3::Hasher::new_derive_key("astrid storage engine KV projection test v1");
            hasher.update(&record.kind().code().to_le_bytes());
            hasher.update(&record.format_version().get().to_le_bytes());
            hasher.update(&(record.canonical_bytes().len() as u128).to_le_bytes());
            hasher.update(record.canonical_bytes());
            hasher.update(&record.logical_bytes().to_le_bytes());
            hasher.update(&[record.class().code()]);
            hasher.update(&(record.references().len() as u128).to_le_bytes());
            for reference in record.references() {
                hasher.update(&(reference.label().len() as u128).to_le_bytes());
                hasher.update(reference.label());
                hasher.update(reference.target().as_bytes());
                hasher.update(&[reference.kind().code()]);
            }
            ObjectId::new(*hasher.finalize().as_bytes())
        }
    }

    fn identified(
        engine: &InMemoryEngine<String, TestIdentity>,
        records: &mut BTreeMap<ObjectId, ObjectRecord>,
        record: ObjectRecord,
    ) -> ObjectId {
        let id = engine.identify(&record);
        records.insert(id, record);
        id
    }

    #[test]
    fn projection_round_trips_namespaces_and_values() {
        let engine = InMemoryEngine::new(TestIdentity);
        let mut snapshot = engine.kv_snapshot("alice".to_owned()).unwrap();
        snapshot
            .state_mut()
            .set(
                "alice:capsule:build".to_owned(),
                "toolchain".to_owned(),
                b"rust".to_vec(),
            )
            .unwrap();
        snapshot
            .state_mut()
            .set(
                "alice:capsule:build".to_owned(),
                "empty".to_owned(),
                Vec::new(),
            )
            .unwrap();
        snapshot
            .state_mut()
            .set(
                "alice:capsule:shell".to_owned(),
                "cwd".to_owned(),
                b"/workspace".to_vec(),
            )
            .unwrap();

        let committed = engine.commit_kv(snapshot).unwrap();
        let decoded = engine.kv_snapshot("alice".to_owned()).unwrap();

        assert_eq!(decoded.root(), Some(committed.root()));
        assert_eq!(
            decoded.state().get("alice:capsule:build", "toolchain"),
            Some(b"rust".as_slice())
        );
        assert_eq!(
            decoded.state().get("alice:capsule:build", "empty"),
            Some([].as_slice())
        );
        assert_eq!(decoded.state().keys("alice:capsule:shell"), vec!["cwd"]);
    }

    #[test]
    fn logical_usage_counts_repeated_visible_values() {
        let engine = InMemoryEngine::new(TestIdentity);
        let mut snapshot = engine.kv_snapshot("alice".to_owned()).unwrap();
        snapshot
            .state_mut()
            .set(
                "alice:capsule:a".to_owned(),
                "same".to_owned(),
                b"repeat".to_vec(),
            )
            .unwrap();
        snapshot
            .state_mut()
            .set(
                "alice:capsule:b".to_owned(),
                "same".to_owned(),
                b"repeat".to_vec(),
            )
            .unwrap();
        engine.commit_kv(snapshot).unwrap();

        let usage = engine.principal_usage(&"alice".to_owned()).unwrap();

        assert_eq!(usage.logical_bytes, 12);
        assert_eq!(
            engine
                .snapshot(&"alice".to_owned())
                .unwrap()
                .unwrap()
                .records()
                .iter()
                .filter(|(_, record)| record.kind() == ObjectKind::KvLeaf)
                .count(),
            1
        );
    }

    #[test]
    fn kv_commit_preserves_non_kv_components_and_commit_annotations() {
        let engine = InMemoryEngine::new(TestIdentity);
        let mut records = BTreeMap::new();
        let files = ObjectRecord::new(
            ObjectKind::Directory,
            FORMAT_VERSION,
            Vec::new(),
            Vec::new(),
            0,
            ObjectClass::Metadata,
        )
        .unwrap();
        let files_id = identified(&engine, &mut records, files);
        let namespace_map = ObjectRecord::new(
            ObjectKind::NamespaceMap,
            FORMAT_VERSION,
            Vec::new(),
            Vec::new(),
            0,
            ObjectClass::Metadata,
        )
        .unwrap();
        let namespace_map_id = identified(&engine, &mut records, namespace_map);
        let principal_state = ObjectRecord::new(
            ObjectKind::PrincipalState,
            FORMAT_VERSION,
            Vec::new(),
            vec![
                ObjectReference::owns(b"files".to_vec(), files_id),
                ObjectReference::owns(KV_LABEL.to_vec(), namespace_map_id),
            ],
            0,
            ObjectClass::Metadata,
        )
        .unwrap();
        let state_id = identified(&engine, &mut records, principal_state);
        let annotation_target = ObjectId::new([91; 32]);
        let commit = ObjectRecord::new(
            ObjectKind::Commit,
            FORMAT_VERSION,
            Vec::new(),
            vec![
                ObjectReference::new(
                    b"audit".to_vec(),
                    annotation_target,
                    ReferenceKind::Evidence,
                ),
                ObjectReference::owns(STATE_LABEL.to_vec(), state_id),
            ],
            0,
            ObjectClass::Metadata,
        )
        .unwrap();
        let commit_id = identified(&engine, &mut records, commit);
        engine
            .commit(RootTransaction::new(
                "alice".to_owned(),
                None,
                commit_id,
                records.into_iter().collect(),
            ))
            .unwrap();

        let mut snapshot = engine.kv_snapshot("alice".to_owned()).unwrap();
        snapshot
            .state_mut()
            .set(
                "alice:capsule:shell".to_owned(),
                "cwd".to_owned(),
                b"/workspace".to_vec(),
            )
            .unwrap();
        let outcome = engine.commit_kv(snapshot).unwrap();
        let root_snapshot = engine.snapshot(&"alice".to_owned()).unwrap().unwrap();
        let record_map: BTreeMap<_, _> = root_snapshot.records().iter().cloned().collect();
        let next_commit = record_map.get(&outcome.root().commit).unwrap();
        let next_state_id = next_commit.reference(STATE_LABEL).unwrap().target();
        let next_state = record_map.get(&next_state_id).unwrap();

        assert_eq!(next_state.reference(b"files").unwrap().target(), files_id);
        assert_eq!(
            next_commit.reference(b"audit").unwrap().target(),
            annotation_target
        );
        assert_eq!(
            next_commit.reference(PARENT_LABEL).unwrap().target(),
            commit_id
        );
    }

    #[test]
    fn malformed_state_kind_is_rejected_during_decode() {
        let engine = InMemoryEngine::new(TestIdentity);
        let wrong_state = ObjectRecord::new(
            ObjectKind::Chunk,
            FORMAT_VERSION,
            b"not state".to_vec(),
            Vec::new(),
            0,
            ObjectClass::Data,
        )
        .unwrap();
        let wrong_state_id = engine.identify(&wrong_state);
        let commit = ObjectRecord::new(
            ObjectKind::Commit,
            FORMAT_VERSION,
            Vec::new(),
            vec![ObjectReference::owns(STATE_LABEL.to_vec(), wrong_state_id)],
            0,
            ObjectClass::Metadata,
        )
        .unwrap();
        let commit_id = engine.identify(&commit);
        engine
            .commit(RootTransaction::new(
                "alice".to_owned(),
                None,
                commit_id,
                vec![(wrong_state_id, wrong_state), (commit_id, commit)],
            ))
            .unwrap();

        let result = engine.kv_snapshot("alice".to_owned());

        assert!(matches!(
            result,
            Err(KvProjectionError::InvalidFormat {
                object,
                detail: "object has the wrong semantic kind",
            }) if object == wrong_state_id
        ));
    }

    #[test]
    fn malformed_parent_edge_is_rejected_during_decode() {
        let engine = InMemoryEngine::new(TestIdentity);
        let mut records = BTreeMap::new();
        let state = ObjectRecord::new(
            ObjectKind::PrincipalState,
            FORMAT_VERSION,
            Vec::new(),
            Vec::new(),
            0,
            ObjectClass::Metadata,
        )
        .unwrap();
        let state_id = identified(&engine, &mut records, state);
        let commit = ObjectRecord::new(
            ObjectKind::Commit,
            FORMAT_VERSION,
            Vec::new(),
            vec![
                ObjectReference::new(
                    PARENT_LABEL.to_vec(),
                    ObjectId::new([17; 32]),
                    ReferenceKind::Evidence,
                ),
                ObjectReference::owns(STATE_LABEL.to_vec(), state_id),
            ],
            0,
            ObjectClass::Metadata,
        )
        .unwrap();
        let commit_id = identified(&engine, &mut records, commit);
        engine
            .commit(RootTransaction::new(
                "alice".to_owned(),
                None,
                commit_id,
                records.into_iter().collect(),
            ))
            .unwrap();

        assert!(matches!(
            engine.kv_snapshot("alice".to_owned()),
            Err(KvProjectionError::InvalidFormat {
                object,
                detail: "commit `parent` reference is not lineage",
            }) if object == commit_id
        ));
    }

    #[test]
    fn invalid_names_cannot_enter_a_snapshot() {
        let engine = InMemoryEngine::new(TestIdentity);
        let mut snapshot = engine.kv_snapshot("alice".to_owned()).unwrap();

        assert_eq!(
            snapshot
                .state_mut()
                .set(String::new(), "key".to_owned(), Vec::new()),
            Err(KvProjectionError::InvalidName { name: "namespace" })
        );
        assert_eq!(
            snapshot
                .state_mut()
                .set("namespace".to_owned(), "bad\0key".to_owned(), Vec::new()),
            Err(KvProjectionError::InvalidName { name: "key" })
        );
        assert!(snapshot.state().is_empty());
        assert!(engine.root(&"alice".to_owned()).is_none());
    }
}
