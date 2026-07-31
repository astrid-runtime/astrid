//! User-space engine for Astrid principal state.
//!
//! The in-memory reference engine and durable host-file engine share the
//! boundary between immutable object admission, identity verification,
//! complete-closure validation, and atomic principal-root publication. The
//! durable realization adds an append-only object arena, checksummed root
//! journal, recovery, and fault injection without changing those semantics.
//!
//! The engine contains no policy decisions, implicit quotas, clocks, principal
//! parsing, or authorization logic. Callers must authorize a transaction before
//! submitting it. Native composition pins its identity and encoding profile
//! outside this generic engine boundary.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(unreachable_pub)]
#![deny(clippy::unwrap_used)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

use astrid_storage_model::{
    GcReport, InsertOutcome, ModelError, ObjectId, ObjectIdentity, ObjectKind, ObjectRecord, PinId,
    PrincipalUsage, RootState, World,
};
use parking_lot::RwLock;

#[cfg(not(target_family = "wasm"))]
mod durable;
mod kv;
mod muninn;
mod projection;
mod refinery;

#[cfg(not(target_family = "wasm"))]
pub use durable::{
    CompactionEvidenceBundle, CompactionFacts, CompactionProofVerifier, CompactionReport,
    CompactionRetainedRoot, CompactionRetention, CompactionRootKind, DurableEngine, DurableError,
    FaultInjector, FaultPoint, IdentityScheme, NoFaults, PersistentObjectIdentity, PrincipalCodec,
    RecoveryLimits, VerifiedCompactionPlan,
};
pub use kv::{
    KvProjectionEngine, KvProjectionError, KvState, KvStateSnapshot, commit_kv_with_engine,
    kv_snapshot_with_engine,
};
pub use muninn::{
    InMemoryMuninnIndex, MuninnAdmission, MuninnHit, MuninnTrustState, MuninnVerificationError,
    VerifiedDerivationEvidence, verify_derivation_evidence,
};
pub use projection::{PrincipalProjectionEngine, PrincipalProjectionError};
#[cfg(not(target_family = "wasm"))]
pub use refinery::{
    BottomKSketch, BottomKSketchDescriptor, BottomKSketchError, SketchSampleSize, SketchScoreWidth,
    build_bottom_k_sketch, verify_bottom_k_sketch,
};
pub use refinery::{
    CrossHashAttestation, CrossHashSigner, CrossHashVerifier, EngineCompactionPass,
    ProposedRefineryOutput, RefineryBatchContext, RefineryCheckpointId, RefineryOutputClass,
    RefineryPass, RefineryPassDescriptorId, RefineryProposalError, RefineryProposalSink,
    RefineryResourceBudget, RefineryRunError, RefinerySnapshotId, Sha384AttestationError,
    VerifiedRefineryObject, attest_sha384_closure, run_refinery_observer,
    verify_sha384_attestation,
};

/// A root update and the immutable records required to reconstruct it.
///
/// Record identifiers are untrusted declarations. The engine recomputes every
/// identity before admitting any record. Records may be empty when the commit
/// closure is already present.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootTransaction<P> {
    principal: P,
    expected: Option<RootState>,
    commit: ObjectId,
    records: Vec<(ObjectId, ObjectRecord)>,
}

impl<P> RootTransaction<P> {
    /// Construct a root transaction.
    #[must_use]
    pub const fn new(
        principal: P,
        expected: Option<RootState>,
        commit: ObjectId,
        records: Vec<(ObjectId, ObjectRecord)>,
    ) -> Self {
        Self {
            principal,
            expected,
            commit,
            records,
        }
    }

    /// Borrow the target principal.
    #[must_use]
    pub const fn principal(&self) -> &P {
        &self.principal
    }

    /// Return the exact root expected by the caller.
    #[must_use]
    pub const fn expected(&self) -> Option<RootState> {
        self.expected
    }

    /// Return the immutable commit that becomes current on success.
    #[must_use]
    pub const fn commit(&self) -> ObjectId {
        self.commit
    }

    /// Borrow the transaction's declared immutable records.
    #[must_use]
    pub fn records(&self) -> &[(ObjectId, ObjectRecord)] {
        &self.records
    }
}

/// Result of publishing one principal-root transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitOutcome {
    root: RootState,
    objects_inserted: u64,
}

impl CommitOutcome {
    /// Return the newly visible principal root.
    #[must_use]
    pub const fn root(self) -> RootState {
        self.root
    }

    /// Return the number of newly admitted immutable objects.
    ///
    /// This is a privileged engine diagnostic, not principal-visible
    /// accounting. Guest APIs must not expose it or vary admission behavior
    /// from it because doing so would reveal cross-principal deduplication.
    #[must_use]
    pub const fn objects_inserted(self) -> u64 {
        self.objects_inserted
    }
}

/// Consistent exported view of one principal's current root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootSnapshot {
    root: RootState,
    records: Vec<(ObjectId, ObjectRecord)>,
}

impl RootSnapshot {
    /// Return the root captured by this snapshot.
    #[must_use]
    pub const fn root(&self) -> RootState {
        self.root
    }

    /// Borrow the complete owning closure in canonical identifier order.
    #[must_use]
    pub fn records(&self) -> &[(ObjectId, ObjectRecord)] {
        &self.records
    }
}

/// Thread-safe in-memory principal-store engine.
///
/// `P` is the integration layer's domain-bearing principal identifier. `I`
/// supplies the object identity algorithm. Keeping identity injected makes this
/// engine useful as a reference oracle and permits collision-path tests; native
/// composition selects and records its production identity profile explicitly.
#[derive(Debug)]
pub struct InMemoryEngine<P: Ord, I> {
    identity: I,
    world: RwLock<World<P>>,
}

impl<P: Ord, I> InMemoryEngine<P, I> {
    /// Construct an empty engine with an explicit identity implementation.
    #[must_use]
    pub fn new(identity: I) -> Self {
        Self {
            identity,
            world: RwLock::new(World::new()),
        }
    }

    /// Borrow the configured object identity implementation.
    #[must_use]
    pub const fn identity(&self) -> &I {
        &self.identity
    }

    /// Return the number of admitted immutable objects.
    #[must_use]
    pub fn object_count(&self) -> usize {
        self.world.read().object_count()
    }

    /// Return a copy of an immutable object when present.
    #[must_use]
    pub fn object(&self, id: ObjectId) -> Option<ObjectRecord> {
        self.world.read().object(id).cloned()
    }

    /// Return the current root of `principal`.
    #[must_use]
    pub fn root(&self, principal: &P) -> Option<RootState> {
        self.world.read().root(principal)
    }

    /// Atomically remove a principal root using exact compare-and-swap.
    ///
    /// Immutable objects remain present until garbage collection proves that
    /// no other principal or pin retains them.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::RootConflict`] when `expected` is stale.
    pub fn remove_root(&self, principal: &P, expected: RootState) -> Result<RootState, ModelError> {
        self.world
            .write()
            .compare_and_remove_root(principal, expected)
    }

    /// Capture a principal root and complete owning closure under one read
    /// lock.
    ///
    /// # Errors
    ///
    /// Returns a model graph error if an authoritative root is incomplete or
    /// cyclic.
    pub fn snapshot(&self, principal: &P) -> Result<Option<RootSnapshot>, ModelError> {
        let world = self.world.read();
        let Some(root) = world.root(principal) else {
            return Ok(None);
        };
        let records = world.export_closure(root.commit)?;
        Ok(Some(RootSnapshot { root, records }))
    }

    /// Retain a complete root independently of current principal roots.
    ///
    /// # Errors
    ///
    /// Returns a graph-validation or duplicate-pin error.
    pub fn pin(&self, pin: PinId, root: ObjectId) -> Result<(), ModelError> {
        self.world.write().pin(pin, root)
    }

    /// Release a retained root.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::PinMissing`] when the pin is unknown.
    pub fn unpin(&self, pin: PinId) -> Result<ObjectId, ModelError> {
        self.world.write().unpin(pin)
    }

    /// Calculate stable logical usage for one principal.
    ///
    /// # Errors
    ///
    /// Returns a missing-principal, graph-validation, or arithmetic error.
    pub fn principal_usage(&self, principal: &P) -> Result<PrincipalUsage, ModelError> {
        self.world.read().principal_usage(principal)
    }

    /// Remove all immutable objects unreachable from every principal root and
    /// explicit pin.
    ///
    /// # Errors
    ///
    /// Returns without deleting anything if an authoritative graph is invalid
    /// or accounting overflows.
    pub fn collect_garbage(&self) -> Result<GcReport, ModelError> {
        self.world.write().collect_garbage()
    }
}

impl<P: Ord, I: ObjectIdentity> InMemoryEngine<P, I> {
    /// Compute the logical identity of a canonical object.
    #[must_use]
    pub fn identify(&self, record: &ObjectRecord) -> ObjectId {
        self.identity.identify(record)
    }

    /// Admit one immutable object.
    ///
    /// Re-admission is idempotent. The returned identifier is always computed
    /// by the engine rather than accepted from the caller.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::ObjectCollision`] if the configured identity maps
    /// different records to one identifier.
    pub fn put_object(
        &self,
        record: ObjectRecord,
    ) -> Result<(ObjectId, InsertOutcome), ModelError> {
        let id = self.identify(&record);
        let outcome = self.world.write().insert_object(id, record)?;
        Ok((id, outcome))
    }

    /// Stage and validate a complete immutable closure without making it a
    /// principal's current root.
    ///
    /// This is the primitive used by bundle import and pre-root transaction
    /// staging. No record is admitted if an identity declaration, collision,
    /// or closure invariant fails.
    ///
    /// # Errors
    ///
    /// Returns an identity, collision, missing-object, cycle, or arithmetic
    /// error without partial admission.
    pub fn import_closure(
        &self,
        records: &[(ObjectId, ObjectRecord)],
        root: ObjectId,
    ) -> Result<u64, ModelError> {
        self.verify_identities(records)?;
        self.world.write().import_closure(records, root)
    }

    /// Publish a transaction's commit as the principal's current root.
    ///
    /// The expected root is checked before staging so a known-stale caller
    /// cannot consume immutable-object storage. Identity and complete-closure
    /// validation finish before the root becomes visible. The write lock makes
    /// publication linearizable with concurrent root writers.
    ///
    /// # Errors
    ///
    /// Returns an identity, collision, graph, root-conflict, or arithmetic
    /// error without changing the visible root. Identity, graph, and known
    /// root-conflict failures also admit no transaction record.
    pub fn commit(&self, transaction: RootTransaction<P>) -> Result<CommitOutcome, ModelError> {
        self.verify_identities(&transaction.records)?;

        let RootTransaction {
            principal,
            expected,
            commit,
            records,
        } = transaction;
        let mut world = self.world.write();
        let actual = world.root(&principal);
        if actual != expected {
            return Err(ModelError::RootConflict { expected, actual });
        }
        if actual.is_some_and(|root| root.generation.checked_next().is_none()) {
            return Err(ModelError::ArithmeticOverflow);
        }
        Self::validate_transaction_root(&world, &records, commit)?;

        let objects_inserted = world.import_closure(&records, commit)?;
        let root = world.compare_and_swap_root(principal, expected, commit)?;
        Ok(CommitOutcome {
            root,
            objects_inserted,
        })
    }

    /// Point a principal at a previously admitted complete commit closure.
    ///
    /// # Errors
    ///
    /// Returns a graph-validation, root-conflict, or arithmetic error.
    pub fn compare_and_swap_root(
        &self,
        principal: P,
        expected: Option<RootState>,
        commit: ObjectId,
    ) -> Result<RootState, ModelError> {
        self.world
            .write()
            .compare_and_swap_root(principal, expected, commit)
    }

    fn verify_identities(&self, records: &[(ObjectId, ObjectRecord)]) -> Result<(), ModelError> {
        for (declared, record) in records {
            let computed = self.identify(record);
            if computed != *declared {
                return Err(ModelError::ObjectIdentityMismatch {
                    declared: *declared,
                    computed,
                });
            }
        }
        Ok(())
    }

    fn validate_transaction_root(
        world: &World<P>,
        records: &[(ObjectId, ObjectRecord)],
        root: ObjectId,
    ) -> Result<(), ModelError> {
        let mut incoming_root = None;
        for (id, record) in records.iter().filter(|(id, _)| *id == root) {
            debug_assert_eq!(*id, root);
            if incoming_root.is_some_and(|existing| existing != record) {
                return Err(ModelError::ObjectCollision(root));
            }
            incoming_root = Some(record);
        }

        let record = incoming_root
            .or_else(|| world.object(root))
            .ok_or(ModelError::MissingObject(root))?;
        if record.kind() != ObjectKind::Commit {
            return Err(ModelError::RootNotCommit {
                object: root,
                actual: record.kind(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod muninn_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use astrid_storage_model::{
        ObjectClass, ObjectFormatVersion, ObjectKind, ObjectReference, ReferenceKind,
        ReferenceLabel, RootGeneration,
    };
    use std::sync::{Arc, Barrier};
    use std::thread;

    #[derive(Clone, Copy, Debug, Default)]
    struct TestIdentity;

    impl ObjectIdentity for TestIdentity {
        fn identify(&self, record: &ObjectRecord) -> ObjectId {
            let mut hasher =
                blake3::Hasher::new_derive_key("astrid storage engine in-memory test identity v1");
            hasher.update(&record.kind().code().to_le_bytes());
            hasher.update(&record.format_version().get().to_le_bytes());
            hasher.update(&(record.canonical_bytes().len() as u128).to_le_bytes());
            hasher.update(record.canonical_bytes());
            hasher.update(&record.logical_bytes().to_le_bytes());
            hasher.update(&[record.class().code()]);
            hasher.update(&(record.references().len() as u128).to_le_bytes());
            for reference in record.references() {
                hasher.update(&(reference.label().as_bytes().len() as u128).to_le_bytes());
                hasher.update(reference.label().as_bytes());
                hasher.update(reference.target().as_bytes());
                hasher.update(&[reference.kind().code()]);
            }
            ObjectId::new(*hasher.finalize().as_bytes())
        }
    }

    #[derive(Clone, Copy, Debug, Default)]
    struct ConstantIdentity;

    impl ObjectIdentity for ConstantIdentity {
        fn identify(&self, _record: &ObjectRecord) -> ObjectId {
            ObjectId::new([42; 32])
        }
    }

    fn label(bytes: &[u8]) -> ReferenceLabel {
        ReferenceLabel::new(bytes.to_vec())
    }

    fn version(value: u16) -> ObjectFormatVersion {
        ObjectFormatVersion::new(value).unwrap()
    }

    fn data(bytes: &[u8]) -> ObjectRecord {
        ObjectRecord::new(
            ObjectKind::Chunk,
            ObjectFormatVersion::V1,
            bytes.to_vec(),
            Vec::new(),
            u64::try_from(bytes.len()).unwrap(),
            ObjectClass::Data,
        )
        .unwrap()
    }

    fn metadata(bytes: &[u8], references: Vec<ObjectReference>) -> ObjectRecord {
        ObjectRecord::new(
            ObjectKind::Commit,
            ObjectFormatVersion::V1,
            bytes.to_vec(),
            references,
            0,
            ObjectClass::Metadata,
        )
        .unwrap()
    }

    fn closure(
        engine: &InMemoryEngine<&'static str, TestIdentity>,
        payload: &[u8],
    ) -> (ObjectId, Vec<(ObjectId, ObjectRecord)>) {
        let leaf = data(payload);
        let leaf_id = engine.identify(&leaf);
        let commit = metadata(
            b"commit",
            vec![ObjectReference::owns(label(b"state"), leaf_id)],
        );
        let commit_id = engine.identify(&commit);
        (commit_id, vec![(leaf_id, leaf), (commit_id, commit)])
    }

    fn identity_base(target: ObjectId) -> ObjectRecord {
        metadata(
            b"same",
            vec![ObjectReference::new(
                label(b"edge"),
                target,
                ReferenceKind::Owns,
            )],
        )
    }

    fn assert_identities_differ(
        base: &ObjectRecord,
        variants: impl IntoIterator<Item = ObjectRecord>,
    ) {
        let identity = TestIdentity;
        for variant in variants {
            assert_ne!(identity.identify(base), identity.identify(&variant));
        }
    }

    #[test]
    fn object_identity_commits_type_payload_and_accounting_fields() {
        let target = ObjectId::new([7; 32]);
        let base = identity_base(target);
        let variants = [
            ObjectRecord::new(
                ObjectKind::PrincipalState,
                ObjectFormatVersion::V1,
                b"same".to_vec(),
                vec![ObjectReference::new(
                    label(b"edge"),
                    target,
                    ReferenceKind::Owns,
                )],
                0,
                ObjectClass::Metadata,
            )
            .unwrap(),
            ObjectRecord::new(
                ObjectKind::Commit,
                version(2),
                b"same".to_vec(),
                vec![ObjectReference::new(
                    label(b"edge"),
                    target,
                    ReferenceKind::Owns,
                )],
                0,
                ObjectClass::Metadata,
            )
            .unwrap(),
            metadata(
                b"changed",
                vec![ObjectReference::new(
                    label(b"edge"),
                    target,
                    ReferenceKind::Owns,
                )],
            ),
            ObjectRecord::new(
                ObjectKind::Commit,
                ObjectFormatVersion::V1,
                b"same".to_vec(),
                vec![ObjectReference::new(
                    label(b"edge"),
                    target,
                    ReferenceKind::Owns,
                )],
                1,
                ObjectClass::Metadata,
            )
            .unwrap(),
            ObjectRecord::new(
                ObjectKind::Commit,
                ObjectFormatVersion::V1,
                b"same".to_vec(),
                vec![ObjectReference::new(
                    label(b"edge"),
                    target,
                    ReferenceKind::Owns,
                )],
                0,
                ObjectClass::Data,
            )
            .unwrap(),
        ];

        assert_identities_differ(&base, variants);
    }

    #[test]
    fn object_identity_commits_reference_fields() {
        let target = ObjectId::new([7; 32]);
        let base = identity_base(target);
        let variants = [
            ObjectRecord::new(
                ObjectKind::Commit,
                ObjectFormatVersion::V1,
                b"same".to_vec(),
                vec![ObjectReference::new(
                    label(b"other"),
                    target,
                    ReferenceKind::Owns,
                )],
                0,
                ObjectClass::Metadata,
            )
            .unwrap(),
            metadata(
                b"same",
                vec![ObjectReference::new(
                    label(b"edge"),
                    ObjectId::new([8; 32]),
                    ReferenceKind::Owns,
                )],
            ),
            metadata(
                b"same",
                vec![ObjectReference::new(
                    label(b"edge"),
                    target,
                    ReferenceKind::Evidence,
                )],
            ),
        ];

        assert_identities_differ(&base, variants);
    }

    #[test]
    fn commit_publishes_only_a_complete_verified_closure() {
        let engine = InMemoryEngine::new(TestIdentity);
        let (commit, records) = closure(&engine, b"hello");

        let outcome = engine
            .commit(RootTransaction::new("alice", None, commit, records))
            .unwrap();

        assert_eq!(
            outcome.root(),
            RootState {
                generation: RootGeneration::INITIAL,
                commit
            }
        );
        assert_eq!(outcome.objects_inserted(), 2);
        let snapshot = engine.snapshot(&"alice").unwrap().unwrap();
        assert_eq!(snapshot.root(), outcome.root());
        assert_eq!(snapshot.records().len(), 2);
    }

    #[test]
    fn recommitting_one_closure_is_storage_idempotent() {
        let engine = InMemoryEngine::new(TestIdentity);
        let (commit, records) = closure(&engine, b"same");
        let initial = engine
            .commit(RootTransaction::new("alice", None, commit, records.clone()))
            .unwrap()
            .root();

        let repeated = engine
            .commit(RootTransaction::new(
                "alice",
                Some(initial),
                commit,
                records,
            ))
            .unwrap();

        assert_eq!(repeated.objects_inserted(), 0);
        assert_eq!(repeated.root().generation, RootGeneration::new(1));
        assert_eq!(repeated.root().commit, commit);
        assert_eq!(engine.object_count(), 2);
    }

    #[test]
    fn incomplete_transaction_admits_nothing_and_has_no_root() {
        let engine = InMemoryEngine::new(TestIdentity);
        let missing = ObjectId::new([9; 32]);
        let commit_record = metadata(
            b"commit",
            vec![ObjectReference::owns(label(b"state"), missing)],
        );
        let commit = engine.identify(&commit_record);

        let result = engine.commit(RootTransaction::new(
            "alice",
            None,
            commit,
            vec![(commit, commit_record)],
        ));

        assert!(matches!(result, Err(ModelError::MissingObject(id)) if id == missing));
        assert_eq!(engine.object_count(), 0);
        assert_eq!(engine.root(&"alice"), None);
    }

    #[test]
    fn principal_root_must_name_a_typed_commit() {
        let engine = InMemoryEngine::new(TestIdentity);
        let data_id = engine.put_object(data(b"not a commit")).unwrap().0;

        let result = engine.compare_and_swap_root("alice", None, data_id);

        assert_eq!(
            result,
            Err(ModelError::RootNotCommit {
                object: data_id,
                actual: ObjectKind::Chunk,
            })
        );
        assert_eq!(engine.root(&"alice"), None);
    }

    #[test]
    fn non_commit_transaction_admits_nothing() {
        let engine = InMemoryEngine::new(TestIdentity);
        let record = data(b"not a commit");
        let object = engine.identify(&record);

        let result = engine.commit(RootTransaction::new(
            "alice",
            None,
            object,
            vec![(object, record)],
        ));

        assert_eq!(
            result,
            Err(ModelError::RootNotCommit {
                object,
                actual: ObjectKind::Chunk,
            })
        );
        assert_eq!(engine.object_count(), 0);
        assert_eq!(engine.root(&"alice"), None);
    }

    #[test]
    fn identity_collision_never_replaces_an_admitted_object() {
        let engine = InMemoryEngine::<&str, _>::new(ConstantIdentity);
        let first = data(b"first");
        let second = data(b"second");
        let object = engine.put_object(first.clone()).unwrap().0;

        let result = engine.put_object(second);

        assert_eq!(result, Err(ModelError::ObjectCollision(object)));
        assert_eq!(engine.object(object), Some(first));
        assert_eq!(engine.object_count(), 1);
    }

    #[test]
    fn forged_import_identity_admits_nothing() {
        let engine = InMemoryEngine::<&str, _>::new(TestIdentity);
        let record = data(b"real");
        let forged = ObjectId::new([4; 32]);

        let result = engine.import_closure(&[(forged, record)], forged);

        assert!(matches!(
            result,
            Err(ModelError::ObjectIdentityMismatch { declared, .. }) if declared == forged
        ));
        assert_eq!(engine.object_count(), 0);
    }

    #[test]
    fn stale_transaction_is_rejected_before_object_staging() {
        let engine = InMemoryEngine::new(TestIdentity);
        let (first, first_records) = closure(&engine, b"first");
        let initial = engine
            .commit(RootTransaction::new("alice", None, first, first_records))
            .unwrap()
            .root();
        let before = engine.object_count();
        let (second, second_records) = closure(&engine, b"second");

        let result = engine.commit(RootTransaction::new("alice", None, second, second_records));

        assert!(matches!(
            result,
            Err(ModelError::RootConflict {
                expected: None,
                actual: Some(actual),
            }) if actual == initial
        ));
        assert_eq!(engine.root(&"alice"), Some(initial));
        assert_eq!(engine.object_count(), before);
    }

    #[test]
    fn rollback_advances_generation_without_rewriting_objects() {
        let engine = InMemoryEngine::new(TestIdentity);
        let (first, first_records) = closure(&engine, b"first");
        let initial = engine
            .commit(RootTransaction::new("alice", None, first, first_records))
            .unwrap()
            .root();
        let (second, second_records) = closure(&engine, b"second");
        let updated = engine
            .commit(RootTransaction::new(
                "alice",
                Some(initial),
                second,
                second_records,
            ))
            .unwrap()
            .root();
        let count = engine.object_count();

        let rolled_back = engine
            .compare_and_swap_root("alice", Some(updated), first)
            .unwrap();

        assert_eq!(rolled_back.generation, RootGeneration::new(2));
        assert_eq!(rolled_back.commit, first);
        assert_eq!(engine.object_count(), count);
    }

    #[test]
    fn pin_retains_a_snapshot_after_principal_removal() {
        let engine = InMemoryEngine::new(TestIdentity);
        let (commit, records) = closure(&engine, b"retained");
        let root = engine
            .commit(RootTransaction::new("alice", None, commit, records))
            .unwrap()
            .root();
        let pin = PinId::new(7);
        engine.pin(pin, commit).unwrap();
        engine.remove_root(&"alice", root).unwrap();

        assert_eq!(engine.collect_garbage().unwrap().objects_removed, 0);
        engine.unpin(pin).unwrap();
        assert_eq!(engine.collect_garbage().unwrap().objects_removed, 2);
    }

    #[test]
    fn concurrent_compare_and_swap_has_exactly_one_winner() {
        let engine = Arc::new(InMemoryEngine::new(TestIdentity));
        let (initial_commit, initial_records) = closure(&engine, b"initial");
        let initial = engine
            .commit(RootTransaction::new(
                "alice",
                None,
                initial_commit,
                initial_records,
            ))
            .unwrap()
            .root();
        let left = metadata(b"left", Vec::new());
        let left_id = engine.put_object(left).unwrap().0;
        let right = metadata(b"right", Vec::new());
        let right_id = engine.put_object(right).unwrap().0;
        let barrier = Arc::new(Barrier::new(3));

        let handles: Vec<_> = [left_id, right_id]
            .into_iter()
            .map(|commit| {
                let engine = Arc::clone(&engine);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    engine.compare_and_swap_root("alice", Some(initial), commit)
                })
            })
            .collect();
        barrier.wait();
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();

        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(ModelError::RootConflict { .. })))
                .count(),
            1
        );
        let root = engine.root(&"alice").unwrap();
        assert_eq!(root.generation, RootGeneration::new(1));
        assert!(root.commit == left_id || root.commit == right_id);
    }

    #[test]
    fn bounded_root_traces_match_plain_compare_and_swap_specification() {
        const ACTIONS: u64 = 6;
        const DEPTH: u32 = 5;
        let trace_count = ACTIONS.pow(DEPTH);

        for mut trace in 0..trace_count {
            let engine = InMemoryEngine::new(TestIdentity);
            let first = engine.put_object(metadata(b"first", Vec::new())).unwrap().0;
            let second = engine
                .put_object(metadata(b"second", Vec::new()))
                .unwrap()
                .0;
            let mut expected_root = None;

            for _ in 0..DEPTH {
                let action = trace % ACTIONS;
                trace /= ACTIONS;
                match action {
                    0 | 1 => {
                        let commit = if action == 0 { first } else { second };
                        let result = engine.compare_and_swap_root("alice", expected_root, commit);
                        let generation = expected_root
                            .map_or(RootGeneration::INITIAL, |root: RootState| {
                                root.generation.checked_next().unwrap()
                            });
                        let next = RootState { generation, commit };
                        assert_eq!(result, Ok(next));
                        expected_root = Some(next);
                    },
                    2 => {
                        let result = engine.compare_and_swap_root("alice", None, first);
                        if expected_root.is_none() {
                            let next = RootState {
                                generation: RootGeneration::INITIAL,
                                commit: first,
                            };
                            assert_eq!(result, Ok(next));
                            expected_root = Some(next);
                        } else {
                            assert!(matches!(result, Err(ModelError::RootConflict { .. })));
                        }
                    },
                    3 => {
                        let stale = RootState {
                            generation: RootGeneration::new(u64::MAX),
                            commit: second,
                        };
                        let result = engine.compare_and_swap_root("alice", Some(stale), second);
                        assert!(matches!(result, Err(ModelError::RootConflict { .. })));
                    },
                    4 => {
                        if let Some(current) = expected_root {
                            assert_eq!(engine.remove_root(&"alice", current), Ok(current));
                            expected_root = None;
                        } else {
                            let absent = RootState {
                                generation: RootGeneration::INITIAL,
                                commit: first,
                            };
                            assert!(matches!(
                                engine.remove_root(&"alice", absent),
                                Err(ModelError::RootConflict { .. })
                            ));
                        }
                    },
                    5 => {
                        let stale = RootState {
                            generation: RootGeneration::new(u64::MAX),
                            commit: first,
                        };
                        assert!(matches!(
                            engine.remove_root(&"alice", stale),
                            Err(ModelError::RootConflict { .. })
                        ));
                    },
                    _ => unreachable!(),
                }
                assert_eq!(engine.root(&"alice"), expected_root);
            }
        }
    }

    #[test]
    fn projection_model_error_preserves_typed_source() {
        let error = PrincipalProjectionError::from(ModelError::ArithmeticOverflow);
        let source = std::error::Error::source(&error).unwrap();

        assert_eq!(
            source.downcast_ref::<ModelError>(),
            Some(&ModelError::ArithmeticOverflow)
        );
    }
}
