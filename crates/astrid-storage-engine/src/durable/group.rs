//! Caller-coordinated durability batching for principal-root commits.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use astrid_storage_model::{ModelError, ObjectId};
use parking_lot::{Condvar, Mutex};

use super::{
    ARENA_MAGIC, CommitOutcome, DurableEngine, DurableError, DurableInner, FaultPoint, Persisted,
    PersistentObjectIdentity, Prepared, PrincipalCodec, ROOT_MAGIC, RootTransaction, append_frame,
    io_error, live_files_mut,
};

const DEFAULT_INITIAL_DELAY: Duration = Duration::from_micros(250);
const DEFAULT_BUSY_EXTENSION: Duration = Duration::from_micros(250);

/// Latency policy for strict durable group commit.
///
/// A newly elected leader always waits the initial delay. When more than one
/// caller is queued after that interval, it waits the busy extension once.
/// Neither value is persisted or changes crash semantics. Setting both to zero
/// disables intentional waiting while retaining batching behind an in-flight
/// flush.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupCommitPolicy {
    initial_delay: Duration,
    busy_extension: Duration,
}

impl GroupCommitPolicy {
    /// Construct a fixed-delay policy.
    #[must_use]
    pub const fn new(delay: Duration) -> Self {
        Self {
            initial_delay: delay,
            busy_extension: Duration::ZERO,
        }
    }

    /// Construct an adaptive policy.
    ///
    /// Every newly elected leader waits `initial_delay`. It waits one
    /// additional `busy_extension` only when multiple callers are queued after
    /// that first interval.
    #[must_use]
    pub const fn adaptive(initial_delay: Duration, busy_extension: Duration) -> Self {
        Self {
            initial_delay,
            busy_extension,
        }
    }

    /// Disable intentional coalescing latency.
    #[must_use]
    pub const fn immediate() -> Self {
        Self::new(Duration::ZERO)
    }

    /// Return the initial coalescing delay paid by every leader.
    #[must_use]
    pub const fn initial_delay(self) -> Duration {
        self.initial_delay
    }

    /// Return the additional delay paid only when the queue is busy.
    #[must_use]
    pub const fn busy_extension(self) -> Duration {
        self.busy_extension
    }
}

impl Default for GroupCommitPolicy {
    fn default() -> Self {
        Self::adaptive(DEFAULT_INITIAL_DELAY, DEFAULT_BUSY_EXTENSION)
    }
}

pub(super) struct CommitGroup<P> {
    leader_active: bool,
    queue: VecDeque<QueuedCommit<P>>,
}

impl<P> Default for CommitGroup<P> {
    fn default() -> Self {
        Self {
            leader_active: false,
            queue: VecDeque::new(),
        }
    }
}

struct QueuedCommit<P> {
    transaction: RootTransaction<P>,
    receipt: Arc<CommitReceipt>,
}

struct AcceptedCommit<P: Ord> {
    prepared: Prepared<P>,
    receipt: Arc<CommitReceipt>,
}

#[derive(Default)]
struct ReceiptValue {
    result: Option<Result<CommitOutcome, DurableError>>,
    promoted: bool,
}

#[derive(Default)]
struct CommitReceipt {
    value: Mutex<ReceiptValue>,
    ready: Condvar,
}

enum ReceiptAction {
    Lead,
    Complete(Result<CommitOutcome, DurableError>),
}

impl CommitReceipt {
    fn complete(&self, result: Result<CommitOutcome, DurableError>) {
        let mut value = self.value.lock();
        if value.result.is_none() {
            value.promoted = false;
            value.result = Some(result);
            self.ready.notify_one();
        }
    }

    fn promote(&self) {
        let mut value = self.value.lock();
        if value.result.is_none() && !value.promoted {
            value.promoted = true;
            self.ready.notify_one();
        }
    }

    fn wait(&self) -> ReceiptAction {
        let mut value = self.value.lock();
        loop {
            if let Some(result) = value.result.take() {
                return ReceiptAction::Complete(result);
            }
            if value.promoted {
                value.promoted = false;
                return ReceiptAction::Lead;
            }
            self.ready.wait(&mut value);
        }
    }
}

impl<P, I, C> DurableEngine<P, I, C>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    /// Persist a complete immutable transaction and publish its root.
    ///
    /// Concurrent callers may share one object-arena flush and one
    /// root-journal flush. Transactions are prepared in queue order;
    /// model/root-conflict failures append no bytes and do not cancel
    /// unrelated transactions in the same group. Once group I/O starts, any
    /// error poisons this instance; drop and reopen it so recovery determines
    /// the durable journal prefix.
    ///
    /// # Errors
    ///
    /// Returns an identity, collision, graph, root-conflict, encoding, I/O, or
    /// injected-fault error. A returned I/O/fault/recovery error requires
    /// reopen.
    pub fn commit(&self, transaction: RootTransaction<P>) -> Result<CommitOutcome, DurableError> {
        let receipt = Arc::new(CommitReceipt::default());
        let mut lead = {
            let mut group = self.commit_group.lock();
            group.queue.push_back(QueuedCommit {
                transaction,
                receipt: Arc::clone(&receipt),
            });
            if group.leader_active {
                false
            } else {
                group.leader_active = true;
                true
            }
        };
        loop {
            if lead {
                self.run_one_commit_group();
            }
            match receipt.wait() {
                ReceiptAction::Lead => {
                    lead = true;
                },
                ReceiptAction::Complete(result) => return result,
            }
        }
    }

    fn run_one_commit_group(&self) {
        if !self.group_policy.initial_delay().is_zero() {
            std::thread::sleep(self.group_policy.initial_delay());
        }
        let busy = self.commit_group.lock().queue.len() > 1;
        if busy && !self.group_policy.busy_extension().is_zero() {
            std::thread::sleep(self.group_policy.busy_extension());
        }

        let batch: Vec<_> = {
            let mut group = self.commit_group.lock();
            group.queue.drain(..).collect()
        };
        self.process_commit_group(batch);

        let next_leader = {
            let mut group = self.commit_group.lock();
            if let Some(next) = group.queue.front() {
                Some(Arc::clone(&next.receipt))
            } else {
                group.leader_active = false;
                None
            }
        };
        if let Some(next) = next_leader {
            next.promote();
        }
    }

    fn process_commit_group(&self, batch: Vec<QueuedCommit<P>>) {
        let mut completions = Vec::new();
        let mut inner = self.inner.lock();
        if inner.files.is_none() {
            drop(inner);
            complete_unavailable(batch, UnavailableEngine::Closed);
            return;
        }
        if inner.poisoned {
            drop(inner);
            complete_unavailable(batch, UnavailableEngine::RequiresRecovery);
            return;
        }

        let mut accepted = Vec::new();
        let mut pending_roots = BTreeMap::new();
        let mut pending_frames = BTreeMap::<ObjectId, Arc<[u8]>>::new();
        for request in batch {
            match self.prepare(&mut inner, request.transaction, &pending_roots) {
                Ok(mut prepared) => {
                    if let Err(error) = reserve_group_frames(&mut prepared, &mut pending_frames) {
                        completions.push((request.receipt, Err(error)));
                        continue;
                    }
                    pending_roots.insert(prepared.principal.clone(), prepared.root);
                    accepted.push(AcceptedCommit {
                        prepared,
                        receipt: request.receipt,
                    });
                },
                Err(error) => completions.push((request.receipt, Err(error))),
            }
        }

        if !accepted.is_empty() {
            let previous_arena_len = match live_files_mut(&mut inner.files) {
                Ok(files) => files.arena_len,
                Err(error) => {
                    drop(inner);
                    complete_failed_group(&mut completions, accepted, error);
                    for (receipt, result) in completions {
                        receipt.complete(result);
                    }
                    return;
                },
            };
            match self.persist_group(&mut inner, &accepted) {
                Ok(persisted) => {
                    for location in persisted.locations {
                        inner.index.insert(location.0, location.1);
                        inner.pending_index_locations.push(location);
                    }
                    for accepted in accepted {
                        inner
                            .validated
                            .extend(accepted.prepared.validated.iter().copied());
                        inner
                            .roots_by_principal
                            .insert(accepted.prepared.principal.clone(), accepted.prepared.root);
                        completions.push((
                            accepted.receipt,
                            Ok(CommitOutcome {
                                root: accepted.prepared.root,
                                objects_inserted: accepted.prepared.objects_inserted,
                            }),
                        ));
                    }
                    debug_assert_eq!(
                        previous_arena_len,
                        live_files_mut(&mut inner.files)
                            .map_or(previous_arena_len, |files| files.arena_len)
                    );
                    if let Err(error) = self.advance_index_frontier(&mut inner, persisted.arena_len)
                    {
                        self.mark_requires_recovery(&mut inner);
                        replace_successes_with_recovery(&mut completions, error);
                    }
                },
                Err(error) => {
                    self.mark_requires_recovery(&mut inner);
                    complete_failed_group(&mut completions, accepted, error);
                },
            }
        }
        drop(inner);
        for (receipt, result) in completions {
            receipt.complete(result);
        }
    }

    fn persist_group(
        &self,
        inner: &mut DurableInner<P>,
        accepted: &[AcceptedCommit<P>],
    ) -> Result<Persisted, DurableError> {
        let files = live_files_mut(&mut inner.files)?;
        let mut locations = Vec::new();
        for accepted in accepted {
            for (id, payload) in &accepted.prepared.objects {
                let location = append_frame(&mut files.arena, ARENA_MAGIC, payload)?;
                locations.push((*id, location));
            }
        }
        self.fail_if(FaultPoint::AfterObjectAppend)?;

        for accepted in accepted {
            if let Some((id, payload)) = &accepted.prepared.commit {
                let location = append_frame(&mut files.arena, ARENA_MAGIC, payload)?;
                locations.push((*id, location));
            }
        }
        self.fail_if(FaultPoint::AfterCommitAppend)?;
        files
            .arena
            .sync_data()
            .map_err(|source| io_error("flush grouped transaction object frames", source))?;
        self.fail_if(FaultPoint::AfterObjectFlush)?;
        self.fail_if(FaultPoint::AfterCommitFlush)?;
        self.fail_if(FaultPoint::BeforeRootCas)?;

        for accepted in accepted {
            append_frame(&mut files.roots, ROOT_MAGIC, &accepted.prepared.journal)?;
        }
        files
            .roots
            .sync_data()
            .map_err(|source| io_error("flush grouped root-journal frames", source))?;
        self.fail_if(FaultPoint::AfterRootCas)?;

        let arena_len = files
            .arena
            .metadata()
            .map_err(|source| io_error("read grouped arena metadata", source))?
            .len();
        Ok(Persisted {
            locations,
            arena_len,
        })
    }
}

fn reserve_group_frames<P: Ord>(
    prepared: &mut Prepared<P>,
    pending: &mut BTreeMap<ObjectId, Arc<[u8]>>,
) -> Result<(), DurableError> {
    for (id, payload) in prepared.objects.iter().chain(prepared.commit.iter()) {
        if pending
            .get(id)
            .is_some_and(|existing| existing.as_ref() != payload.as_ref())
        {
            return Err(ModelError::ObjectCollision(*id).into());
        }
    }

    prepared.objects.retain(|(id, payload)| {
        if pending.contains_key(id) {
            false
        } else {
            pending.insert(*id, Arc::clone(payload));
            true
        }
    });
    if let Some((id, payload)) = prepared.commit.as_ref() {
        if pending.contains_key(id) {
            prepared.commit = None;
        } else {
            pending.insert(*id, Arc::clone(payload));
        }
    }
    prepared.objects_inserted = u64::try_from(prepared.objects.len())
        .map_err(|_| ModelError::ArithmeticOverflow)?
        .checked_add(u64::from(prepared.commit.is_some()))
        .ok_or(ModelError::ArithmeticOverflow)?;
    Ok(())
}

#[derive(Clone, Copy)]
enum UnavailableEngine {
    Closed,
    RequiresRecovery,
}

impl UnavailableEngine {
    const fn error(self) -> DurableError {
        match self {
            Self::Closed => DurableError::Closed,
            Self::RequiresRecovery => DurableError::RequiresRecovery,
        }
    }
}

fn complete_unavailable<P>(batch: Vec<QueuedCommit<P>>, unavailable: UnavailableEngine) {
    for request in batch {
        request.receipt.complete(Err(unavailable.error()));
    }
}

fn complete_failed_group<P: Ord>(
    completions: &mut Vec<(Arc<CommitReceipt>, Result<CommitOutcome, DurableError>)>,
    accepted: Vec<AcceptedCommit<P>>,
    error: DurableError,
) {
    let mut first = Some(error);
    for accepted in accepted {
        completions.push((
            accepted.receipt,
            Err(first.take().unwrap_or(DurableError::RequiresRecovery)),
        ));
    }
}

fn replace_successes_with_recovery(
    completions: &mut [(Arc<CommitReceipt>, Result<CommitOutcome, DurableError>)],
    error: DurableError,
) {
    let mut first = Some(error);
    for (_, result) in completions {
        if result.is_ok() {
            *result = Err(first.take().unwrap_or(DurableError::RequiresRecovery));
        }
    }
}
