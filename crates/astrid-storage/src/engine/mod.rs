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

use crate::storage_model::{
    GcReport, InsertOutcome, ModelError, ObjectId, ObjectIdentity, ObjectKind, ObjectRecord, PinId,
    PrincipalUsage, RootState, World,
};
use parking_lot::RwLock;

#[cfg(any(test, feature = "crash-replay"))]
pub mod crash_replay;
#[cfg(not(target_family = "wasm"))]
mod durable;
#[cfg(not(target_family = "wasm"))]
mod durable_cache;
mod kv;
mod muninn;
mod projection;
mod refinery;

#[cfg(not(target_family = "wasm"))]
pub use durable::{
    CompactionEvidenceBundle, CompactionFacts, CompactionProofVerifier, CompactionReport,
    CompactionRetainedRoot, CompactionRetention, CompactionRootKind,
    DeterministicCompactionProofVerifier, DurableEngine, DurableEnginePolicy, DurableError,
    FaultInjector, FaultPoint, GroupCommitPolicy, IdentityScheme, NoFaults, ObjectCacheCapacity,
    ObjectCacheConfig, ObjectCacheController, ObjectCacheMemoryBudget, ObjectCacheStats,
    PersistentObjectIdentity, PrincipalCodec, PrincipalObjectCacheBudget, RecoveryLimits,
    RecoveryRetryPolicy, TransactionWalPolicy, VerifiedCompactionPlan,
    deterministic_compaction_proof,
};
pub use kv::{
    KvProjectionEngine, KvProjectionError, KvState, KvStateSnapshot, ReadyKvRoot,
    commit_kv_with_engine, kv_snapshot_with_engine,
};
pub use muninn::{
    InMemoryMuninnIndex, MuninnAdmission, MuninnHit, MuninnTrustState, MuninnVerificationError,
    VerifiedDerivationEvidence, verify_derivation_evidence,
};
pub(crate) use projection::object_record_retained_bytes;
pub use projection::{
    PreparedProjectionBatch, PrincipalProjectionEngine, PrincipalProjectionError,
    ProjectionCacheEntry, ProjectionCacheKey, ProjectionCachePayload, ProjectionObserver,
    ProjectionPhase,
};
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
    preparation_authority: std::sync::Arc<()>,
}

impl<P: Ord, I> InMemoryEngine<P, I> {
    /// Construct an empty engine with an explicit identity implementation.
    #[must_use]
    pub fn new(identity: I) -> Self {
        Self {
            identity,
            world: RwLock::new(World::new()),
            preparation_authority: std::sync::Arc::new(()),
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

        let objects_inserted = world.import_closure_owned(records, commit)?;
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
mod tests;
