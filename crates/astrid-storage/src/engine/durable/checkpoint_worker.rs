//! Engine-owned single-flight representation checkpoint job.
//!
//! The worker is P-free and never holds `Arc<DurableEngine>`. Publication takes
//! the shared arbiter with `try_lock` before the physical store mutex. Clean
//! close drains an in-flight job while holding the arbiter and `inner` (never
//! the physical mutex during join). Drop/recovery/compaction/handoff cancel.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::thread::JoinHandle;

use parking_lot::{Mutex, MutexGuard};

use super::representations::{
    CapturedCheckpoint, CheckpointControl, PreparedCheckpoint, RepresentationStore,
    is_checkpoint_cancelled,
};
use super::{DurableError, LIFECYCLE_REQUIRES_RECOVERY, LIFECYCLE_USABLE, RecoveryLimits};

/// Shared physical representation custody installed into [`DurableInner`].
pub(super) type SharedRepresentationStore = Arc<Mutex<RepresentationStore>>;

/// Shared publication arbiter + single worker slot.
pub(super) type SharedCheckpointArbiter = Arc<Mutex<CheckpointArbiterState>>;

/// Typed result of one owned checkpoint job.
pub(super) enum CheckpointOutcome {
    /// Verified preparation returned only to the immediately joining closer.
    Prepared {
        custody_generation: u64,
        checkpoint: Box<PreparedCheckpoint>,
    },
    /// Worker published CURRENT before observing drain.
    Published,
    /// Cooperative cancel discarded unpublished work.
    Cancelled,
}

/// Wrap an owned recovered/activated store for shared physical custody.
pub(super) fn wrap_representations(store: RepresentationStore) -> SharedRepresentationStore {
    Arc::new(Mutex::new(store))
}

#[cfg(test)]
thread_local! {
    static NEXT_PHYSICAL_LOCK: std::cell::RefCell<Option<std::sync::mpsc::SyncSender<()>>> =
        const { std::cell::RefCell::new(None) };
}

/// Observe entry after the caller's usable-inner check, before physical locking.
#[cfg(test)]
pub(super) fn observe_next_physical_lock(entered: std::sync::mpsc::SyncSender<()>) {
    NEXT_PHYSICAL_LOCK.with(|slot| *slot.borrow_mut() = Some(entered));
}

/// Lock shared representations when present.
pub(super) fn lock_representations(
    representations: Option<&SharedRepresentationStore>,
) -> Option<MutexGuard<'_, RepresentationStore>> {
    #[cfg(test)]
    if let Some(entered) = NEXT_PHYSICAL_LOCK.with(|slot| slot.borrow_mut().take()) {
        let _ = entered.send(());
    }
    representations.map(|store| store.lock())
}

/// Validate lifecycle after acquiring physical custody. A writer may have
/// passed `lock_usable` before a checkpoint failed while it waited here. The
/// worker poisons before releasing this mutex, so this acquire and recheck must
/// precede any foreground publication. Exclusive recovery/compaction instead
/// join the worker under the arbiter before using the raw physical lock.
pub(super) fn lock_live_representations<'a>(
    representations: Option<&'a SharedRepresentationStore>,
    lifecycle: &AtomicU8,
) -> Result<Option<MutexGuard<'a, RepresentationStore>>, DurableError> {
    let guard = lock_representations(representations);
    match lifecycle.load(Ordering::Acquire) {
        LIFECYCLE_USABLE => Ok(guard),
        super::LIFECYCLE_CLOSED => Err(DurableError::Closed),
        _ => Err(DurableError::RequiresRecovery),
    }
}

/// Single in-flight checkpoint job. Collapses to Idle after join.
#[derive(Default)]
pub(super) enum CheckpointWorkerSlot {
    #[default]
    Idle,
    Preparing {
        control: Arc<CheckpointControl>,
        join: JoinHandle<Result<CheckpointOutcome, DurableError>>,
    },
}

/// Shared generation arbiter and at-most-one worker slot.
pub(super) struct CheckpointArbiterState {
    /// Bumped whenever exclusive custody replaces or drops the shared store.
    pub(super) custody_generation: u64,
    pub(super) worker: CheckpointWorkerSlot,
}

impl Default for CheckpointArbiterState {
    fn default() -> Self {
        Self {
            custody_generation: 0,
            worker: CheckpointWorkerSlot::Idle,
        }
    }
}

impl CheckpointArbiterState {
    pub(super) fn bump_custody(&mut self) -> Result<(), DurableError> {
        self.custody_generation = self
            .custody_generation
            .checked_add(1)
            .ok_or(DurableError::EncodingOverflow)?;
        Ok(())
    }
}

/// Poison the shared lifecycle without clearing an already-closed engine.
pub(super) fn poison_lifecycle(lifecycle: &AtomicU8) {
    let _ = lifecycle.compare_exchange(
        LIFECYCLE_USABLE,
        LIFECYCLE_REQUIRES_RECOVERY,
        Ordering::AcqRel,
        Ordering::Acquire,
    );
}

/// Declared after the physical store guard so Drop poisons before releasing it.
pub(super) struct PublicationPoison<'a> {
    lifecycle: &'a AtomicU8,
    armed: bool,
}

impl Drop for PublicationPoison<'_> {
    fn drop(&mut self) {
        if self.armed {
            poison_lifecycle(self.lifecycle);
        }
    }
}

impl<'a> PublicationPoison<'a> {
    pub(super) fn armed(lifecycle: &'a AtomicU8) -> Self {
        Self {
            lifecycle,
            armed: true,
        }
    }

    pub(super) fn disarm(&mut self) {
        self.armed = false;
    }
}

fn absorb_worker_join(
    join_result: std::thread::Result<Result<CheckpointOutcome, DurableError>>,
    lifecycle: &AtomicU8,
) -> Result<CheckpointOutcome, DurableError> {
    match join_result {
        Ok(Ok(outcome)) => Ok(outcome),
        Ok(Err(error)) => {
            poison_lifecycle(lifecycle);
            Err(error)
        },
        Err(_) => {
            poison_lifecycle(lifecycle);
            Err(DurableError::RequiresRecovery)
        },
    }
}

fn discard_unexpected_prepared(outcome: CheckpointOutcome) -> CheckpointOutcome {
    match outcome {
        CheckpointOutcome::Prepared { checkpoint, .. } => {
            drop(checkpoint);
            CheckpointOutcome::Cancelled
        },
        other => other,
    }
}

/// Cancel and join any in-flight job while retaining exclusive arbiter ownership.
///
/// Drop/recovery/compaction/handoff use this path. Clean close uses
/// [`drain_join_slot`] instead so eligible maintenance can finish.
pub(super) fn cancel_join_checkpoint_worker<'a>(
    arbiter: &'a Mutex<CheckpointArbiterState>,
    lifecycle: &AtomicU8,
) -> MutexGuard<'a, CheckpointArbiterState> {
    let mut state = arbiter.lock();
    let slot = std::mem::replace(&mut state.worker, CheckpointWorkerSlot::Idle);
    match slot {
        CheckpointWorkerSlot::Idle => {},
        CheckpointWorkerSlot::Preparing { control, join } => {
            control.cancel();
            match absorb_worker_join(join.join(), lifecycle) {
                Ok(outcome) => {
                    let _ = discard_unexpected_prepared(outcome);
                },
                Err(error) => {
                    tracing::error!(
                        error = %error,
                        "representation checkpoint worker failed during exclusive cancel/join"
                    );
                },
            }
        },
    }
    state
}

/// Result of draining the single worker slot for clean close.
pub(super) enum DrainedWorker {
    Idle,
    Published,
    Cancelled,
    Prepared {
        control: Arc<CheckpointControl>,
        custody_generation: u64,
        checkpoint: Box<PreparedCheckpoint>,
    },
}

/// Request drain and join while the closer already holds the arbiter (and usually
/// `inner`). Does not take the physical representation mutex.
pub(super) fn drain_join_slot(
    state: &mut CheckpointArbiterState,
    lifecycle: &AtomicU8,
) -> Result<DrainedWorker, DurableError> {
    let slot = std::mem::replace(&mut state.worker, CheckpointWorkerSlot::Idle);
    match slot {
        CheckpointWorkerSlot::Idle => Ok(DrainedWorker::Idle),
        CheckpointWorkerSlot::Preparing { control, join } => {
            control.request_drain();
            match absorb_worker_join(join.join(), lifecycle)? {
                CheckpointOutcome::Prepared {
                    custody_generation,
                    checkpoint,
                } => Ok(DrainedWorker::Prepared {
                    control,
                    custody_generation,
                    checkpoint,
                }),
                CheckpointOutcome::Published => Ok(DrainedWorker::Published),
                CheckpointOutcome::Cancelled => Ok(DrainedWorker::Cancelled),
            }
        },
    }
}

/// Join a finished worker without cancelling an in-flight job.
pub(super) fn poll_finished_checkpoint_worker(
    arbiter: &Mutex<CheckpointArbiterState>,
    lifecycle: &AtomicU8,
) -> Result<(), DurableError> {
    let Some(mut state) = arbiter.try_lock() else {
        return Ok(());
    };
    let finished = matches!(
        &state.worker,
        CheckpointWorkerSlot::Preparing { join, .. } if join.is_finished()
    );
    if !finished {
        return Ok(());
    }
    let slot = std::mem::replace(&mut state.worker, CheckpointWorkerSlot::Idle);
    let join_result = match slot {
        CheckpointWorkerSlot::Preparing { join, .. } => join.join(),
        CheckpointWorkerSlot::Idle => return Ok(()),
    };
    drop(state);
    let outcome = absorb_worker_join(join_result, lifecycle)?;
    let _ = discard_unexpected_prepared(outcome);
    Ok(())
}

/// Spawn one off-writer checkpoint job. Caller holds arbiter with Idle slot.
pub(super) fn install_preparing_worker(
    state: &mut CheckpointArbiterState,
    control: Arc<CheckpointControl>,
    join: JoinHandle<Result<CheckpointOutcome, DurableError>>,
) {
    debug_assert!(matches!(state.worker, CheckpointWorkerSlot::Idle));
    state.worker = CheckpointWorkerSlot::Preparing { control, join };
}

/// Worker body: prepare off-lock, catch up, self-publish or hand off on drain.
pub(super) fn run_checkpoint_worker(
    shared: &SharedRepresentationStore,
    arbiter: &SharedCheckpointArbiter,
    capture: CapturedCheckpoint,
    limits: RecoveryLimits,
    control: &CheckpointControl,
    lifecycle: &AtomicU8,
    generation: u64,
) -> Result<CheckpointOutcome, DurableError> {
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        run_checkpoint_worker_inner(
            shared, arbiter, capture, limits, control, lifecycle, generation,
        )
    }));
    match outcome {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(error)) => {
            if is_checkpoint_cancelled(&error) {
                Ok(CheckpointOutcome::Cancelled)
            } else {
                poison_lifecycle(lifecycle);
                Err(error)
            }
        },
        Err(_) => {
            poison_lifecycle(lifecycle);
            Err(DurableError::RequiresRecovery)
        },
    }
}

fn drained_prepared(generation: u64, checkpoint: Box<PreparedCheckpoint>) -> CheckpointOutcome {
    CheckpointOutcome::Prepared {
        custody_generation: generation,
        checkpoint,
    }
}

enum ExclusionTurn {
    Done(CheckpointOutcome),
    Continue(Box<PreparedCheckpoint>),
}

enum ArbiterWait<'a> {
    Ready(MutexGuard<'a, CheckpointArbiterState>),
    Cancelled,
    Draining,
}

fn run_checkpoint_worker_inner(
    shared: &SharedRepresentationStore,
    arbiter: &SharedCheckpointArbiter,
    capture: CapturedCheckpoint,
    limits: RecoveryLimits,
    control: &CheckpointControl,
    lifecycle: &AtomicU8,
    generation: u64,
) -> Result<CheckpointOutcome, DurableError> {
    let mut prepared = match capture.prepare(limits, control) {
        Ok(prepared) => Box::new(prepared),
        Err(error) if is_checkpoint_cancelled(&error) => {
            return Ok(CheckpointOutcome::Cancelled);
        },
        Err(error) => return Err(error),
    };
    loop {
        if control.is_cancelled() {
            return Ok(CheckpointOutcome::Cancelled);
        }
        if control.is_draining() {
            return Ok(drained_prepared(generation, prepared));
        }
        match wait_arbiter_for_publish(arbiter, control) {
            ArbiterWait::Cancelled => return Ok(CheckpointOutcome::Cancelled),
            ArbiterWait::Draining => {
                return Ok(drained_prepared(generation, prepared));
            },
            ArbiterWait::Ready(arbiter_guard) => {
                if arbiter_guard.custody_generation != generation {
                    return Ok(CheckpointOutcome::Cancelled);
                }
                match publish_or_catch_up(
                    shared,
                    arbiter_guard,
                    prepared,
                    limits,
                    control,
                    lifecycle,
                    generation,
                )? {
                    ExclusionTurn::Done(outcome) => return Ok(outcome),
                    ExclusionTurn::Continue(next) => prepared = next,
                }
            },
        }
    }
}

fn wait_arbiter_for_publish<'a>(
    arbiter: &'a SharedCheckpointArbiter,
    control: &CheckpointControl,
) -> ArbiterWait<'a> {
    loop {
        if control.is_cancelled() {
            return ArbiterWait::Cancelled;
        }
        if control.is_draining() {
            return ArbiterWait::Draining;
        }
        match arbiter.try_lock() {
            Some(guard) => {
                if control.is_cancelled() {
                    return ArbiterWait::Cancelled;
                }
                if control.is_draining() {
                    return ArbiterWait::Draining;
                }
                return ArbiterWait::Ready(guard);
            },
            None => std::thread::yield_now(),
        }
    }
}

fn publish_or_catch_up(
    shared: &SharedRepresentationStore,
    arbiter_guard: MutexGuard<'_, CheckpointArbiterState>,
    mut prepared: Box<PreparedCheckpoint>,
    limits: RecoveryLimits,
    control: &CheckpointControl,
    lifecycle: &AtomicU8,
    generation: u64,
) -> Result<ExclusionTurn, DurableError> {
    let mut store = shared.lock();
    // Declared after `store` so Drop poisons before the physical guard releases.
    let mut poison = PublicationPoison::armed(lifecycle);
    if lifecycle.load(Ordering::Acquire) != LIFECYCLE_USABLE {
        poison.disarm();
        return Ok(ExclusionTurn::Done(CheckpointOutcome::Cancelled));
    }
    if control.is_cancelled() {
        poison.disarm();
        return Ok(ExclusionTurn::Done(CheckpointOutcome::Cancelled));
    }
    if control.is_draining() {
        poison.disarm();
        drop(store);
        drop(arbiter_guard);
        return Ok(ExclusionTurn::Done(drained_prepared(generation, prepared)));
    }
    let can_publish = if prepared.tip_matches_live(&store) {
        true
    } else {
        match prepared.can_finish(&store, limits, control) {
            Ok(ready) => ready,
            Err(error) if is_checkpoint_cancelled(&error) => {
                poison.disarm();
                return Ok(ExclusionTurn::Done(CheckpointOutcome::Cancelled));
            },
            Err(error) => return Err(error),
        }
    };
    if can_publish {
        match prepared.finish_publish(&mut store, limits, control) {
            Ok(retired) => {
                poison.disarm();
                drop(store);
                drop(arbiter_guard);
                let mut reclaim_poison = PublicationPoison::armed(lifecycle);
                retired.reclaim()?;
                reclaim_poison.disarm();
                return Ok(ExclusionTurn::Done(CheckpointOutcome::Published));
            },
            Err(error) if is_checkpoint_cancelled(&error) => {
                // Parent returns cancel only before CURRENT rename.
                poison.disarm();
                return Ok(ExclusionTurn::Done(CheckpointOutcome::Cancelled));
            },
            Err(error) => return Err(error),
        }
    }
    let tail = match prepared.capture_tail(&store) {
        Ok(tail) => tail,
        Err(error) if is_checkpoint_cancelled(&error) => {
            poison.disarm();
            return Ok(ExclusionTurn::Done(CheckpointOutcome::Cancelled));
        },
        Err(error) => return Err(error),
    };
    poison.disarm();
    drop(store);
    drop(arbiter_guard);
    match prepared.replay_tail(&tail, limits, control) {
        Ok(()) => Ok(ExclusionTurn::Continue(prepared)),
        Err(error) if is_checkpoint_cancelled(&error) => {
            Ok(ExclusionTurn::Done(CheckpointOutcome::Cancelled))
        },
        Err(error) => {
            poison_lifecycle(lifecycle);
            Err(error)
        },
    }
}
