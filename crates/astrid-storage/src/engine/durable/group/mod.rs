//! Caller-coordinated durability batching for principal-root commits.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::storage_model::{ModelError, ObjectId};
use parking_lot::{Condvar, Mutex};

use super::representations::{PendingRepresentationUpdate, RepresentationStore};

use super::{
    ARENA_MAGIC, CommitOutcome, DurableEngine, DurableError, DurableFiles, DurableInner,
    FaultPoint, File, Persisted, PersistentObjectIdentity, Prepared, PrincipalCodec, ROOT_MAGIC,
    RootTransaction, append_frames, canonical_record_bytes, io_error, live_files_mut,
    read_indexed_object_with_payload,
};
use crate::engine::{ProjectionObserver, ProjectionPhase};

mod wal;

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
    #[cfg(test)]
    drain_gate: Option<(Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>,
}

impl<P> Default for CommitGroup<P> {
    fn default() -> Self {
        Self {
            leader_active: false,
            queue: VecDeque::new(),
            #[cfg(test)]
            drain_gate: None,
        }
    }
}

/// RAII ownership of the one active group-leader role.
///
/// Normal execution hands leadership to the next queued caller explicitly.
/// If the leader unwinds, `Drop` performs the same handoff so a panic cannot
/// leave `leader_active` true forever and wedge later commits.
struct LeaderLease<'a, P> {
    group: &'a Mutex<CommitGroup<P>>,
    active: bool,
}

impl<'a, P> LeaderLease<'a, P> {
    const fn new(group: &'a Mutex<CommitGroup<P>>) -> Self {
        Self {
            group,
            active: true,
        }
    }

    fn release(&mut self) -> Option<Arc<CommitReceipt>> {
        if !self.active {
            return None;
        }
        self.active = false;
        let mut group = self.group.lock();
        group
            .queue
            .front()
            .map(|next| Arc::clone(&next.receipt))
            .or_else(|| {
                group.leader_active = false;
                None
            })
    }
}

impl<P> Drop for LeaderLease<'_, P> {
    fn drop(&mut self) {
        if let Some(next) = self.release() {
            next.promote();
        }
    }
}

struct QueuedCommit<P> {
    transaction: RootTransaction<P>,
    receipt: Arc<CommitReceipt>,
    observer: Option<Arc<dyn ProjectionObserver>>,
}

struct AcceptedCommit<P: Ord> {
    prepared: Prepared<P>,
    receipt: Arc<CommitReceipt>,
    observer: Option<Arc<dyn ProjectionObserver>>,
}

#[derive(Clone, Copy)]
struct PendingRepresentations<'a> {
    locations: &'a [(ObjectId, super::ArenaLocation)],
    direct: &'a BTreeMap<ObjectId, super::representations::DirectArenaObject>,
    validated: &'a BTreeSet<ObjectId>,
}

impl<'a> PendingRepresentations<'a> {
    const fn new(
        locations: &'a [(ObjectId, super::ArenaLocation)],
        direct: &'a BTreeMap<ObjectId, super::representations::DirectArenaObject>,
        validated: &'a BTreeSet<ObjectId>,
    ) -> Self {
        Self {
            locations,
            direct,
            validated,
        }
    }
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
    /// error poisons this instance; the next operation reopens its data files
    /// in place so recovery determines the durable journal prefix.
    ///
    /// # Errors
    ///
    /// Returns an identity, collision, graph, root-conflict, encoding, I/O, or
    /// injected-fault error. An I/O or injected fault leaves the engine
    /// recovery-required; the next operation attempts bounded recovery before
    /// it proceeds.
    pub fn commit(&self, transaction: RootTransaction<P>) -> Result<CommitOutcome, DurableError> {
        self.commit_inner(transaction, None)
    }

    pub(crate) fn commit_observed(
        &self,
        transaction: RootTransaction<P>,
        observer: &dyn ProjectionObserver,
    ) -> Result<CommitOutcome, DurableError> {
        let buffer = Arc::new(crate::engine::projection::ProjectionPhaseBuffer::default());
        let result = self.commit_inner(
            transaction,
            Some(Arc::clone(&buffer) as Arc<dyn ProjectionObserver>),
        );
        buffer.flush_into(observer);
        result
    }

    fn commit_inner(
        &self,
        transaction: RootTransaction<P>,
        observer: Option<Arc<dyn ProjectionObserver>>,
    ) -> Result<CommitOutcome, DurableError> {
        let receipt = Arc::new(CommitReceipt::default());
        let mut lead = {
            let mut group = self.commit_group.lock();
            group.queue.push_back(QueuedCommit {
                transaction,
                receipt: Arc::clone(&receipt),
                observer,
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

    #[cfg(test)]
    pub(super) fn queued_commit_count(&self) -> usize {
        self.commit_group.lock().queue.len()
    }

    #[cfg(test)]
    pub(super) fn gate_next_group_drain(
        &self,
        reached: Arc<std::sync::Barrier>,
        release: Arc<std::sync::Barrier>,
    ) {
        self.commit_group.lock().drain_gate = Some((reached, release));
    }

    fn run_one_commit_group(&self) {
        let mut lease = LeaderLease::new(&self.commit_group);
        if !self.group_policy.initial_delay().is_zero() {
            std::thread::sleep(self.group_policy.initial_delay());
        }
        let busy = self.commit_group.lock().queue.len() > 1;
        if busy && !self.group_policy.busy_extension().is_zero() {
            std::thread::sleep(self.group_policy.busy_extension());
        }

        #[cfg(test)]
        let drain_gate = { self.commit_group.lock().drain_gate.take() };
        #[cfg(test)]
        if let Some((reached, release)) = drain_gate {
            reached.wait();
            release.wait();
        }

        let batch: Vec<_> = {
            let mut group = self.commit_group.lock();
            group.queue.drain(..).collect()
        };
        self.process_commit_group(batch);

        let next_leader = lease.release();
        if let Some(next) = next_leader {
            next.promote();
        }
    }

    fn process_commit_group(&self, batch: Vec<QueuedCommit<P>>) {
        let receipts: Vec<_> = batch
            .iter()
            .map(|request| Arc::clone(&request.receipt))
            .collect();
        let result = catch_unwind(AssertUnwindSafe(|| {
            self.process_commit_batch(batch);
        }));
        if let Err(_error) = result {
            let mut inner = self.inner.lock();
            self.mark_requires_recovery(&mut inner);
            drop(inner);
            for receipt in receipts {
                receipt.complete(Err(DurableError::RequiresRecovery));
            }
        }
    }

    fn process_commit_batch(&self, batch: Vec<QueuedCommit<P>>) {
        let mut completions = Vec::new();
        let mut inner = match self.lock_usable() {
            Ok(inner) => inner,
            Err(error) => {
                complete_unavailable_with_error(batch, error);
                return;
            },
        };

        let mut accepted = Vec::new();
        let mut pending_roots = BTreeMap::new();
        let mut pending_frames = BTreeMap::<ObjectId, Arc<[u8]>>::new();
        Self::seed_pending_wal_frames(
            self.transaction_wal.is_enabled(),
            &inner,
            &mut pending_frames,
        );
        for request in batch {
            match self.prepare(
                &mut inner,
                request.transaction,
                &pending_roots,
                request.observer.as_deref(),
            ) {
                Ok(mut prepared) => {
                    if let Err(error) = reserve_group_frames(&mut prepared, &mut pending_frames) {
                        completions.push((request.receipt, Err(error)));
                        continue;
                    }
                    pending_roots.insert(prepared.principal.clone(), prepared.root);
                    accepted.push(AcceptedCommit {
                        prepared,
                        receipt: request.receipt,
                        observer: request.observer,
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
                    debug_assert!(
                        live_files_mut(&mut inner.files)
                            .map_or(true, |files| files.arena_len >= previous_arena_len)
                    );
                    let frontier = self.publish_commit_frontier(&mut inner, persisted.arena_len);
                    if let Err(error) = frontier {
                        self.mark_requires_recovery(&mut inner);
                        complete_failed_group(&mut completions, accepted, error);
                    } else {
                        for accepted in accepted {
                            inner
                                .validated
                                .extend(accepted.prepared.validated.iter().copied());
                            inner.roots_by_principal.insert(
                                accepted.prepared.principal.clone(),
                                accepted.prepared.root,
                            );
                            self.published_roots
                                .publish(&accepted.prepared.principal, accepted.prepared.root);
                            completions.push((
                                accepted.receipt,
                                Ok(CommitOutcome {
                                    root: accepted.prepared.root,
                                    objects_inserted: accepted.prepared.objects_inserted,
                                }),
                            ));
                        }
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

    fn publish_commit_frontier(
        &self,
        inner: &mut DurableInner<P>,
        arena_len: u64,
    ) -> Result<(), DurableError> {
        if self.transaction_wal.is_enabled() {
            Self::advance_wal_arena_frontier(inner, arena_len)
        } else {
            self.advance_index_frontier(inner, arena_len)?;
            self.sync_volume()
        }
    }

    fn persist_group(
        &self,
        inner: &mut DurableInner<P>,
        accepted: &[AcceptedCommit<P>],
    ) -> Result<Persisted, DurableError> {
        if self.transaction_wal.is_enabled() {
            self.maybe_checkpoint_transaction_wal(inner)?;
            self.persist_group_wal(inner, accepted)
        } else {
            self.persist_group_legacy(inner, accepted)
        }
    }

    fn persist_group_legacy(
        &self,
        inner: &mut DurableInner<P>,
        accepted: &[AcceptedCommit<P>],
    ) -> Result<Persisted, DurableError> {
        let DurableInner {
            files,
            representations,
            pending_index_locations: pending_locations,
            pending_direct_objects: pending_direct,
            index,
            validated,
            ..
        } = inner;
        let files = live_files_mut(files)?;
        let append_started = Instant::now();
        let mut ids = Vec::new();
        let mut payloads = Vec::new();
        for accepted in accepted {
            for (id, payload) in &accepted.prepared.objects {
                ids.push(*id);
                payloads.push(payload.as_ref());
            }
        }
        let object_locations = append_frames(&mut files.arena, ARENA_MAGIC, &payloads)?;
        self.fail_if(FaultPoint::AfterObjectAppend)?;

        let mut commit_ids = Vec::new();
        let mut commit_payloads = Vec::new();
        for accepted in accepted {
            if let Some((id, payload)) = &accepted.prepared.commit {
                commit_ids.push(*id);
                commit_payloads.push(payload.as_ref());
            }
        }
        let commit_locations = append_frames(&mut files.arena, ARENA_MAGIC, &commit_payloads)?;
        record_group(accepted, ProjectionPhase::ArenaAppend, append_started);
        self.fail_if(FaultPoint::AfterCommitAppend)?;
        let map_started = Instant::now();
        let representation_update = if let Some(representations) = representations {
            let appended = ids
                .iter()
                .copied()
                .zip(payloads.iter().copied())
                .zip(object_locations.iter().copied())
                .chain(
                    commit_ids
                        .iter()
                        .copied()
                        .zip(commit_payloads.iter().copied())
                        .zip(commit_locations.iter().copied()),
                )
                .map(|((id, payload), location)| (id, payload, location));
            debug_assert!(
                pending_locations
                    .iter()
                    .all(|(id, location)| index.get(id) == Some(location))
            );
            self.append_group_representations(
                &files.arena,
                representations,
                PendingRepresentations::new(pending_locations, pending_direct, validated),
                accepted.iter().flat_map(|commit| {
                    commit
                        .prepared
                        .validated
                        .iter()
                        .filter_map(|id| index.get(id).map(|location| (*id, *location)))
                }),
                appended,
            )?
        } else {
            None
        };
        record_group(accepted, ProjectionPhase::PhysicalMapUpdate, map_started);
        let flush_started = Instant::now();
        files
            .arena
            .sync_data()
            .map_err(|source| io_error("flush grouped transaction object frames", source))?;
        record_group(accepted, ProjectionPhase::Flush, flush_started);
        self.fail_if(FaultPoint::AfterObjectFlush)?;
        self.fail_if(FaultPoint::AfterCommitFlush)?;
        if let (Some(representations), Some(update)) = (representations, representation_update) {
            let map_started = Instant::now();
            representations.publish_direct_update(update)?;
            record_group(accepted, ProjectionPhase::PhysicalMapUpdate, map_started);
        }
        self.fail_if(FaultPoint::BeforeRootCas)?;

        self.publish_group_roots(files, accepted)?;
        let arena_len = files
            .arena
            .metadata()
            .map_err(|source| io_error("read grouped arena metadata", source))?
            .len();

        Ok(Persisted {
            locations: ids
                .into_iter()
                .zip(object_locations)
                .chain(commit_ids.into_iter().zip(commit_locations))
                .collect(),
            arena_len,
        })
    }

    fn publish_group_roots(
        &self,
        files: &mut DurableFiles,
        accepted: &[AcceptedCommit<P>],
    ) -> Result<(), DurableError> {
        let journals: Vec<_> = accepted
            .iter()
            .map(|accepted| accepted.prepared.journal.as_slice())
            .collect();
        let publication_started = Instant::now();
        append_frames(&mut files.roots, ROOT_MAGIC, &journals)?;
        record_group(
            accepted,
            ProjectionPhase::RootPublication,
            publication_started,
        );
        let flush_started = Instant::now();
        files
            .roots
            .sync_data()
            .map_err(|source| io_error("flush grouped root-journal frames", source))?;
        record_group(accepted, ProjectionPhase::Flush, flush_started);
        self.fail_if(FaultPoint::AfterRootCas)
    }

    fn append_group_representations<'a>(
        &self,
        arena: &File,
        representations: &mut RepresentationStore,
        pending: PendingRepresentations<'_>,
        required: impl Iterator<Item = (ObjectId, super::ArenaLocation)>,
        appended: impl Iterator<Item = (ObjectId, &'a [u8], super::ArenaLocation)>,
    ) -> Result<Option<PendingRepresentationUpdate>, DurableError> {
        let mut direct = Vec::new();
        direct
            .try_reserve(pending.locations.len())
            .map_err(|_| DurableError::EncodingOverflow)?;
        let required = required.collect::<BTreeMap<_, _>>();
        let mut seen = std::collections::BTreeSet::new();
        for (id, location) in pending
            .locations
            .iter()
            .copied()
            .chain(required.iter().map(|(id, location)| (*id, *location)))
        {
            if !seen.insert(id) || representations.contains_direct(id) {
                continue;
            }
            // Admission-created direct descriptions are reusable only after
            // the logical owning closure earned the same process-local token.
            // Otherwise reread and identify the arena frame before promotion.
            if (pending.validated.contains(&id) || required.contains_key(&id))
                && let Some(cached) = pending.direct.get(&id)
                && cached.location == location
            {
                direct.push(cached.clone());
                continue;
            }
            let (_, payload) =
                read_indexed_object_with_payload(arena, id, location, &self.identity, self.limits)?;
            direct.push(representations.describe_direct(
                id,
                canonical_record_bytes(&payload, self.identity.scheme())?,
                location,
            )?);
        }
        for (id, payload, location) in appended {
            if !seen.insert(id) {
                continue;
            }
            direct.push(representations.describe_direct(
                id,
                canonical_record_bytes(payload, self.identity.scheme())?,
                location,
            )?);
        }
        representations.append_direct_update(&direct)
    }
}

fn record_group<P: Ord>(accepted: &[AcceptedCommit<P>], phase: ProjectionPhase, started: Instant) {
    let elapsed = started.elapsed();
    for accepted in accepted {
        if let Some(observer) = accepted.observer.as_deref() {
            observer.record(phase, elapsed);
        }
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

fn complete_unavailable_with_error<P>(batch: Vec<QueuedCommit<P>>, error: DurableError) {
    if matches!(error, DurableError::Closed) {
        for request in batch {
            request.receipt.complete(Err(DurableError::Closed));
        }
        return;
    }

    let mut first = Some(error);
    for request in batch {
        request
            .receipt
            .complete(Err(first.take().unwrap_or(DurableError::RequiresRecovery)));
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
