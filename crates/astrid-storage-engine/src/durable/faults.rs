//! Named durable-engine crash boundaries and injectable failure decisions.

/// Crash boundary exposed by the durable engine.
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
}

/// Injectable crash decision used by recovery tests and harnesses.
pub trait FaultInjector: Send + Sync {
    /// Return `true` to stop at `point` and require the engine to be reopened.
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
