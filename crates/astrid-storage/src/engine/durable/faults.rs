//! Named durable-engine crash boundaries and injectable failure decisions.

/// Durability boundary exposed by the durable engine.
///
/// Most points interrupt a mutation and leave the engine requiring recovery.
/// The three `BeforeInProcessRecovery*` points instead inject retryable I/O
/// into one recovery attempt; [`RecoveryRetryPolicy`](super::RecoveryRetryPolicy)
/// decides whether the same foreground operation tries again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FaultPoint {
    /// Non-commit object frames have been appended but not flushed.
    AfterObjectAppend,
    /// The transaction's complete object batch has been flushed.
    AfterObjectFlush,
    /// The transaction's immutable commit frame has been appended.
    AfterCommitAppend,
    /// Compatibility checkpoint after the shared object-batch flush.
    AfterCommitFlush,
    /// All objects are durable but no root-journal frame was appended.
    BeforeRootCas,
    /// The root-journal frame is durable.
    AfterRootCas,
    /// Replacement arena and root snapshot are durable but unpublished.
    AfterCompactionFilesFlush,
    /// The self-contained GC receipt is durable but no deletion intent exists.
    AfterCompactionEvidencePrepare,
    /// The durable compaction intent exists and recovery must finish or roll back.
    AfterCompactionIntentFlush,
    /// The previous arena name is durable and the active name is temporarily absent.
    AfterCompactionArenaBackup,
    /// The compacted arena occupies the active name.
    AfterCompactionArenaPromote,
    /// The previous root journal name is durable and the active name is temporarily absent.
    AfterCompactionRootsBackup,
    /// The compacted root snapshot occupies the active name.
    AfterCompactionRootsPromote,
    /// The compacted authority pair and its directory entries are durable.
    AfterCompactionDirectoryFlush,
    /// The GC receipt is ready for independent audit delivery.
    AfterCompactionEvidenceReady,
    /// Old generations are gone but the durable intent still protects cleanup recovery.
    BeforeCompactionIntentRemoval,
    /// An in-process recovery attempt is about to reopen authoritative files.
    BeforeInProcessRecoveryOpen,
    /// In-process recovery is about to flush the selected object-arena prefix.
    BeforeInProcessRecoveryArenaFlush,
    /// In-process recovery is about to flush the selected root-journal prefix.
    BeforeInProcessRecoveryRootFlush,
    /// Compacted arena placements are active and loose representations are no longer authoritative.
    AfterCompactionRepresentationRebase,
    /// The transaction WAL has been published but canonical files are not folded.
    AfterWalPublication,
    /// A disposable object-index checkpoint is about to be published.
    BeforeIndexCachePublication,
}

/// Injectable crash decision used by recovery tests and harnesses.
pub trait FaultInjector: Send + Sync {
    /// Return `true` to inject the failure associated with `point`.
    ///
    /// Mutation and compaction points stop the operation and require recovery.
    /// In-process recovery points fail the current recovery attempt as I/O and
    /// may be retried within the operation's configured retry budget.
    fn should_fail(&self, point: FaultPoint) -> bool;
}

/// Fault injector that never interrupts a transaction.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoFaults;

impl FaultInjector for NoFaults {
    fn should_fail(&self, _point: FaultPoint) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::FaultPoint;

    #[test]
    fn published_fault_point_discriminants_stay_stable() {
        let points = [
            FaultPoint::AfterObjectAppend,
            FaultPoint::AfterObjectFlush,
            FaultPoint::AfterCommitAppend,
            FaultPoint::AfterCommitFlush,
            FaultPoint::BeforeRootCas,
            FaultPoint::AfterRootCas,
            FaultPoint::AfterCompactionFilesFlush,
            FaultPoint::AfterCompactionEvidencePrepare,
            FaultPoint::AfterCompactionIntentFlush,
            FaultPoint::AfterCompactionArenaBackup,
            FaultPoint::AfterCompactionArenaPromote,
            FaultPoint::AfterCompactionRootsBackup,
            FaultPoint::AfterCompactionRootsPromote,
            FaultPoint::AfterCompactionDirectoryFlush,
            FaultPoint::AfterCompactionEvidenceReady,
            FaultPoint::BeforeCompactionIntentRemoval,
            FaultPoint::BeforeInProcessRecoveryOpen,
            FaultPoint::BeforeInProcessRecoveryArenaFlush,
            FaultPoint::BeforeInProcessRecoveryRootFlush,
            FaultPoint::AfterCompactionRepresentationRebase,
            FaultPoint::AfterWalPublication,
            FaultPoint::BeforeIndexCachePublication,
        ];

        for (expected, point) in points.into_iter().enumerate() {
            assert_eq!(point as usize, expected);
        }
    }
}
