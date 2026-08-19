//! Typed key/value projection over principal-state objects.
//!
//! This module supplies the logical grammar needed by the compatibility
//! `KvStore` adapter. It deliberately does not select a persistent byte
//! framing or production digest. Values remain canonical object bytes and the
//! engine's injected [`ObjectIdentity`] implementation supplies identifiers.

use std::collections::BTreeMap;
use std::fmt;

use crate::storage_model::{
    ModelError, ObjectClass, ObjectFormatVersion, ObjectId, ObjectIdentity, ObjectKind,
    ObjectRecord, ObjectReference, ReferenceKind, ReferenceLabel, RootState,
};

use crate::engine::{CommitOutcome, InMemoryEngine, RootSnapshot, RootTransaction};
#[cfg(not(target_family = "wasm"))]
use crate::engine::{DurableEngine, DurableError, PersistentObjectIdentity, PrincipalCodec};

const FORMAT_VERSION: ObjectFormatVersion = ObjectFormatVersion::V1;
const KV_LABEL: &[u8] = b"kv";
const PARENT_LABEL: &[u8] = b"parent";
const STATE_LABEL: &[u8] = b"state";

/// A root that is already resident without taking the engine writer lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadyKvRoot(Option<RootState>);

impl ReadyKvRoot {
    /// Wrap a resident root, including the valid empty-store state.
    #[must_use]
    pub const fn new(root: Option<RootState>) -> Self {
        Self(root)
    }

    /// Return the resident root.
    #[must_use]
    pub const fn get(self) -> Option<RootState> {
        self.0
    }
}

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

    /// Iterate over every namespace, key, and value in canonical order.
    pub fn entries(&self) -> impl Iterator<Item = (&str, &str, &[u8])> {
        self.namespaces.iter().flat_map(|(namespace, entries)| {
            entries
                .iter()
                .map(move |(key, value)| (namespace.as_str(), key.as_str(), value.as_slice()))
        })
    }

    /// Return the user-visible value bytes represented by this state.
    ///
    /// Namespace and key metadata are intentionally excluded. The result is
    /// the same stable quantity recorded on the typed namespace-map object and
    /// is suitable for enforcing a principal's logical storage budget.
    ///
    /// # Errors
    ///
    /// Returns [`KvProjectionError::LogicalBytesOverflow`] when the sum cannot
    /// be represented by the accounting type.
    pub fn logical_bytes(&self) -> Result<u64, KvProjectionError> {
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
#[non_exhaustive]
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
    /// The underlying durable engine failed outside the portable model.
    Engine(String),
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
            Self::Engine(error) => write!(formatter, "KV projection engine: {error}"),
        }
    }
}

impl std::error::Error for KvProjectionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Model(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ModelError> for KvProjectionError {
    fn from(error: ModelError) -> Self {
        Self::Model(error)
    }
}

/// Minimal engine contract required by the typed key/value projection.
///
/// This keeps the compatibility adapter independent of whether the principal
/// world is held in memory or reconstructed lazily from a durable arena.
pub trait KvProjectionEngine<P>: Send + Sync {
    /// Compute the logical identity of one canonical object.
    fn identify_kv_object(&self, record: &ObjectRecord) -> ObjectId;

    /// Return the current root of one principal without materializing it.
    ///
    /// # Errors
    ///
    /// Returns an engine error when the root index is unavailable.
    fn current_kv_root(&self, principal: &P) -> Result<Option<RootState>, KvProjectionError>;

    /// Return the current root only when it is already available without I/O
    /// or waiting for an engine writer.
    fn current_kv_root_if_ready(&self, _principal: &P) -> Option<ReadyKvRoot> {
        None
    }

    /// Load one immutable object by identity.
    ///
    /// # Errors
    ///
    /// Returns an engine or frame error when the object cannot be read.
    fn load_kv_object(&self, id: ObjectId) -> Result<Option<ObjectRecord>, KvProjectionError>;

    /// Load one immutable object with principal cache attribution.
    ///
    /// The default preserves projection engines without a governed object
    /// cache. Cache policy cannot change the bytes or errors returned by
    /// [`Self::load_kv_object`].
    ///
    /// # Errors
    ///
    /// Returns an engine or frame error when the object cannot be read.
    fn load_kv_object_for(
        &self,
        _principal: &P,
        id: ObjectId,
    ) -> Result<Option<ObjectRecord>, KvProjectionError> {
        self.load_kv_object(id)
    }

    /// Capture one principal's root and owning closure.
    ///
    /// # Errors
    ///
    /// Returns an engine or graph error when the closure cannot be captured.
    fn snapshot_kv_root(&self, principal: &P) -> Result<Option<RootSnapshot>, KvProjectionError>;

    /// Atomically publish one encoded key/value transition.
    ///
    /// # Errors
    ///
    /// Returns an engine, graph, identity, or root-conflict error.
    fn commit_kv_root(
        &self,
        transaction: RootTransaction<P>,
    ) -> Result<CommitOutcome, KvProjectionError>;

    /// Flush authoritative engine state before the embedding store closes.
    ///
    /// # Errors
    ///
    /// Returns an engine I/O or recovery-required error.
    fn flush_kv(&self) -> Result<(), KvProjectionError>;

    /// Release any engine resources owned by the embedding store.
    ///
    /// The default flushes engines that do not distinguish flush from close.
    /// Durable engines override this to release their singleton lock and file
    /// handles while rejecting subsequent operations.
    ///
    /// # Errors
    ///
    /// Returns an engine flush, close, or recovery-required error.
    fn close_kv(&self) -> Result<(), KvProjectionError> {
        self.flush_kv()
    }
}

impl<P, I> KvProjectionEngine<P> for InMemoryEngine<P, I>
where
    P: Clone + Ord + Send + Sync,
    I: ObjectIdentity + Send + Sync,
{
    fn identify_kv_object(&self, record: &ObjectRecord) -> ObjectId {
        self.identify(record)
    }

    fn current_kv_root(&self, principal: &P) -> Result<Option<RootState>, KvProjectionError> {
        Ok(self.root(principal))
    }

    fn current_kv_root_if_ready(&self, principal: &P) -> Option<ReadyKvRoot> {
        self.world
            .try_read()
            .map(|world| ReadyKvRoot::new(world.root(principal)))
    }

    fn load_kv_object(&self, id: ObjectId) -> Result<Option<ObjectRecord>, KvProjectionError> {
        Ok(self.object(id))
    }

    fn snapshot_kv_root(&self, principal: &P) -> Result<Option<RootSnapshot>, KvProjectionError> {
        self.snapshot(principal).map_err(Into::into)
    }

    fn commit_kv_root(
        &self,
        transaction: RootTransaction<P>,
    ) -> Result<CommitOutcome, KvProjectionError> {
        self.commit(transaction).map_err(Into::into)
    }

    fn flush_kv(&self) -> Result<(), KvProjectionError> {
        Ok(())
    }
}

#[cfg(not(target_family = "wasm"))]
impl<P, I, C> KvProjectionEngine<P> for DurableEngine<P, I, C>
where
    P: Clone + Ord + Send + Sync,
    I: PersistentObjectIdentity + Send + Sync,
    C: PrincipalCodec<P> + Send + Sync,
{
    fn identify_kv_object(&self, record: &ObjectRecord) -> ObjectId {
        self.identify(record)
    }

    fn current_kv_root(&self, principal: &P) -> Result<Option<RootState>, KvProjectionError> {
        self.root(principal).map_err(map_durable_error)
    }

    fn current_kv_root_if_ready(&self, principal: &P) -> Option<ReadyKvRoot> {
        self.root_if_ready(principal)
    }

    fn load_kv_object(&self, id: ObjectId) -> Result<Option<ObjectRecord>, KvProjectionError> {
        self.object(id).map_err(map_durable_error)
    }

    fn load_kv_object_for(
        &self,
        principal: &P,
        id: ObjectId,
    ) -> Result<Option<ObjectRecord>, KvProjectionError> {
        self.object_for(principal, id).map_err(map_durable_error)
    }

    fn snapshot_kv_root(&self, principal: &P) -> Result<Option<RootSnapshot>, KvProjectionError> {
        self.snapshot(principal).map_err(map_durable_error)
    }

    fn commit_kv_root(
        &self,
        transaction: RootTransaction<P>,
    ) -> Result<CommitOutcome, KvProjectionError> {
        self.commit(transaction).map_err(map_durable_error)
    }

    fn flush_kv(&self) -> Result<(), KvProjectionError> {
        self.flush().map_err(map_durable_error)
    }

    fn close_kv(&self) -> Result<(), KvProjectionError> {
        self.close().map_err(map_durable_error)
    }
}

#[cfg(not(target_family = "wasm"))]
fn map_durable_error(error: DurableError) -> KvProjectionError {
    match error {
        DurableError::Model(model) => KvProjectionError::Model(model),
        other => KvProjectionError::Engine(other.to_string()),
    }
}

impl<P, I> InMemoryEngine<P, I>
where
    P: Clone + Ord + Send + Sync,
    I: ObjectIdentity + Send + Sync,
{
    /// Decode one principal's current key/value projection under a consistent
    /// root snapshot.
    ///
    /// # Errors
    ///
    /// Returns a graph or typed-format error when the current root cannot be
    /// interpreted as the version-one projection grammar.
    pub fn kv_snapshot(&self, principal: P) -> Result<KvStateSnapshot<P>, KvProjectionError> {
        kv_snapshot_with_engine(self, principal)
    }
}

impl<P, I> InMemoryEngine<P, I>
where
    P: Clone + Ord + Send + Sync,
    I: ObjectIdentity + Send + Sync,
{
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
        commit_kv_with_engine(self, snapshot)
    }
}

#[cfg(not(target_family = "wasm"))]
impl<P, I, C> DurableEngine<P, I, C>
where
    P: Clone + Ord + Send + Sync,
    I: PersistentObjectIdentity + Send + Sync,
    C: PrincipalCodec<P> + Send + Sync,
{
    /// Decode one principal's current key/value projection from the durable
    /// arena under a consistent root snapshot.
    ///
    /// # Errors
    ///
    /// Returns a durable-engine, graph, or typed-format error.
    pub fn kv_snapshot(&self, principal: P) -> Result<KvStateSnapshot<P>, KvProjectionError> {
        kv_snapshot_with_engine(self, principal)
    }

    /// Atomically replace the durable key/value component captured by
    /// `snapshot`.
    ///
    /// # Errors
    ///
    /// Returns a durable-engine, identity, graph, format, or root-conflict
    /// error.
    pub fn commit_kv(
        &self,
        snapshot: KvStateSnapshot<P>,
    ) -> Result<CommitOutcome, KvProjectionError> {
        commit_kv_with_engine(self, snapshot)
    }
}

/// Decode one principal's key/value projection through an arbitrary engine.
///
/// # Errors
///
/// Returns an engine, graph, or typed-format error.
pub fn kv_snapshot_with_engine<P, E>(
    engine: &E,
    principal: P,
) -> Result<KvStateSnapshot<P>, KvProjectionError>
where
    E: KvProjectionEngine<P>,
{
    let Some(snapshot) = engine.snapshot_kv_root(&principal)? else {
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

/// Commit a captured key/value projection through an arbitrary engine.
///
/// # Errors
///
/// Returns an engine, identity, graph, typed-format, or root-conflict error.
pub fn commit_kv_with_engine<P, E>(
    engine: &E,
    snapshot: KvStateSnapshot<P>,
) -> Result<CommitOutcome, KvProjectionError>
where
    P: Ord,
    E: KvProjectionEngine<P>,
{
    let transaction = encode_transaction(engine, snapshot)?;
    engine.commit_kv_root(transaction)
}

fn decode_snapshot<P>(
    principal: P,
    snapshot: &RootSnapshot,
) -> Result<KvStateSnapshot<P>, KvProjectionError> {
    let records: BTreeMap<_, _> = snapshot.records().iter().cloned().collect();
    let commit = typed_record(&records, snapshot.root().commit, ObjectKind::Commit)?;
    require_structural_record(snapshot.root().commit, commit)?;
    if commit
        .reference(&ReferenceLabel::new(PARENT_LABEL))
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
        .filter(|reference| reference.label().as_bytes() != KV_LABEL)
        .cloned()
        .collect();
    let preserved_commit_references = commit
        .references()
        .iter()
        .filter(|reference| {
            reference.label().as_bytes() != STATE_LABEL
                && reference.label().as_bytes() != PARENT_LABEL
        })
        .cloned()
        .collect();

    let state = match principal_state.reference(&ReferenceLabel::new(KV_LABEL)) {
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
        let namespace = decode_label(map_id, namespace_reference.label().as_bytes())?;
        validate_projection_name(map_id, &namespace, "namespace")?;
        let branch_id = namespace_reference.target();
        let branch = typed_record(records, branch_id, ObjectKind::KvBranch)?;
        require_structural_record(branch_id, branch)?;

        for key_reference in branch.references() {
            if key_reference.kind() != ReferenceKind::Owns {
                return Err(invalid(branch_id, "KV key reference is not owning"));
            }
            let key = decode_label(branch_id, key_reference.label().as_bytes())?;
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

fn encode_transaction<P: Ord, E: KvProjectionEngine<P>>(
    engine: &E,
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
            key_references.push(ObjectReference::owns(
                ReferenceLabel::new(key.as_bytes().to_vec()),
                leaf_id,
            ));
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
            ReferenceLabel::new(namespace.as_bytes().to_vec()),
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

    preserved_components.push(ObjectReference::owns(
        ReferenceLabel::new(KV_LABEL.to_vec()),
        namespace_map_id,
    ));
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
            ReferenceLabel::new(PARENT_LABEL.to_vec()),
            previous.commit,
            ReferenceKind::Lineage,
        ));
    }
    preserved_commit_references.push(ObjectReference::owns(
        ReferenceLabel::new(STATE_LABEL.to_vec()),
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

fn insert_identified<P, E: KvProjectionEngine<P>>(
    engine: &E,
    records: &mut BTreeMap<ObjectId, ObjectRecord>,
    record: ObjectRecord,
) -> Result<ObjectId, KvProjectionError> {
    let id = engine.identify_kv_object(&record);
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
        .reference(&ReferenceLabel::new(label))
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
#[path = "kv_tests.rs"]
mod tests;
