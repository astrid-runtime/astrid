//! Bounded handoff from parallel content builders to one engine appender.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use super::{BulkPhaseObserver, PendingIngest, WorkerBuild};
use crate::content::PrincipalContentError;
use crate::content::store::projection::{
    BatchAdmission, EngineSink, StagedObjectBatch, admit_prepared_object_batch,
};
use crate::content::store::{
    PrincipalContentStore, PrincipalProjectionEngine, PrincipalProjectionError,
    build_content_streaming, map_stream_error,
};

const ADMISSION_LOOKAHEAD_BATCHES: usize = 1;
const COORDINATOR_STOPPED: &str = "bulk admission coordinator stopped";

pub(super) struct ParallelBuild {
    pub(super) entries: Vec<WorkerBuild>,
    pub(super) objects_inserted: u64,
    pub(super) peak_pending_bytes: usize,
    pub(super) admission_elapsed: Duration,
}

pub(super) fn build_parallel<P, E, R>(
    store: &PrincipalContentStore<P, E>,
    pending: VecDeque<PendingIngest<R>>,
    worker_count: usize,
    observer: Option<&Arc<BulkPhaseObserver>>,
) -> Result<ParallelBuild, PrincipalContentError>
where
    P: Clone + Ord + Send + Sync,
    E: PrincipalProjectionEngine<P>,
    R: std::io::Read + Send,
{
    let queue = Arc::new(Mutex::new(pending));
    let cancelled = Arc::new(AtomicBool::new(false));
    let gauge = Arc::new(PendingByteGauge::default());
    let (sender, receiver) = sync_channel(ADMISSION_LOOKAHEAD_BATCHES);

    std::thread::scope(|scope| {
        let appender_cancelled = Arc::clone(&cancelled);
        let appender_gauge = Arc::clone(&gauge);
        let appender_observer = observer.cloned();
        let appender = scope.spawn(move || {
            run_appender(
                store,
                &receiver,
                appender_cancelled.as_ref(),
                appender_gauge.as_ref(),
                appender_observer.as_deref(),
            )
        });

        let mut workers = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            let queue = Arc::clone(&queue);
            let cancelled = Arc::clone(&cancelled);
            let admission = QueuedAdmission {
                sender: sender.clone(),
                cancelled: Arc::clone(&cancelled),
                gauge: Arc::clone(&gauge),
                handoff_elapsed: Duration::ZERO,
                observer: observer.cloned(),
            };
            workers.push(
                scope.spawn(move || {
                    build_worker(store, queue.as_ref(), cancelled.as_ref(), admission)
                }),
            );
        }
        drop(sender);

        let mut entries = Vec::with_capacity(worker_count);
        let mut worker_error = None;
        for worker in workers {
            match worker.join() {
                Ok(Ok(worker_entries)) => entries.push(worker_entries),
                Ok(Err(error)) => {
                    cancelled.store(true, Ordering::Release);
                    retain_worker_error(&mut worker_error, error);
                },
                Err(_) => {
                    cancelled.store(true, Ordering::Release);
                    worker_error.get_or_insert_with(|| {
                        PrincipalContentError::Projection(PrincipalProjectionError::Engine(
                            "bulk content worker panicked".to_owned(),
                        ))
                    });
                },
            }
        }

        let admission = appender.join().map_err(|_| {
            PrincipalContentError::Projection(PrincipalProjectionError::Engine(
                "bulk admission worker panicked".to_owned(),
            ))
        })??;
        if let Some(error) = worker_error {
            return Err(error);
        }
        Ok(ParallelBuild {
            entries,
            objects_inserted: admission.objects_inserted,
            peak_pending_bytes: gauge.peak(),
            admission_elapsed: admission.elapsed,
        })
    })
}

fn build_worker<P, E, R>(
    store: &PrincipalContentStore<P, E>,
    queue: &Mutex<VecDeque<PendingIngest<R>>>,
    cancelled: &AtomicBool,
    admission: QueuedAdmission,
) -> Result<WorkerBuild, PrincipalContentError>
where
    P: Clone + Ord + Send + Sync,
    E: PrincipalProjectionEngine<P>,
    R: std::io::Read + Send,
{
    let mut sink = EngineSink::<P, E, _>::with_admission(store.engine.as_ref(), admission);
    let mut completed = Vec::new();
    let mut source_build_elapsed = Duration::ZERO;
    loop {
        if cancelled.load(Ordering::Acquire) {
            break;
        }
        let next = queue.lock().pop_front();
        let Some((name, (source, profile, observation))) = next else {
            break;
        };
        let handoff_before = sink.admission().handoff_elapsed();
        let build_started = Instant::now();
        let streamed = match build_content_streaming(profile, source, &mut sink) {
            Ok(streamed) => streamed,
            Err(error) => {
                cancelled.store(true, Ordering::Release);
                return Err(map_stream_error(error));
            },
        };
        let handoff_elapsed = sink
            .admission()
            .handoff_elapsed()
            .saturating_sub(handoff_before);
        source_build_elapsed = source_build_elapsed
            .saturating_add(build_started.elapsed().saturating_sub(handoff_elapsed));
        completed.push((name, streamed.verified_content(), observation));
    }
    if cancelled.load(Ordering::Acquire) {
        return Ok(WorkerBuild {
            entries: completed,
            objects_inserted: 0,
            source_build_elapsed,
            admission_elapsed: Duration::ZERO,
            peak_pending_bytes: sink.peak_pending_bytes(),
        });
    }
    sink.finish()?;
    Ok(WorkerBuild {
        entries: completed,
        objects_inserted: 0,
        source_build_elapsed,
        admission_elapsed: Duration::ZERO,
        peak_pending_bytes: sink.peak_pending_bytes(),
    })
}

fn run_appender<P, E>(
    store: &PrincipalContentStore<P, E>,
    receiver: &Receiver<AdmissionMessage>,
    cancelled: &AtomicBool,
    gauge: &PendingByteGauge,
    observer: Option<&BulkPhaseObserver>,
) -> Result<AdmissionOutcome, PrincipalContentError>
where
    P: Clone + Ord + Send + Sync,
    E: PrincipalProjectionEngine<P>,
{
    let mut inserted = 0_u64;
    let mut elapsed = Duration::ZERO;
    while let Ok(message) = receiver.recv() {
        if cancelled.load(Ordering::Acquire) {
            gauge.release(message.retained_bytes);
            continue;
        }
        let started = Instant::now();
        let outcome = admit_prepared_object_batch(
            store.engine.as_ref(),
            message.expected,
            message.prepared,
            observer.map(|observer| observer as &dyn crate::engine::ProjectionObserver),
        );
        elapsed = elapsed.saturating_add(started.elapsed());
        gauge.release(message.retained_bytes);
        match outcome {
            Ok(batch_inserted) => {
                inserted = inserted
                    .checked_add(batch_inserted)
                    .ok_or(PrincipalContentError::AccountingOverflow)?;
            },
            Err(error) => {
                cancelled.store(true, Ordering::Release);
                return Err(error.into());
            },
        }
    }
    Ok(AdmissionOutcome {
        objects_inserted: inserted,
        elapsed,
    })
}

struct AdmissionOutcome {
    objects_inserted: u64,
    elapsed: Duration,
}

struct QueuedAdmission {
    sender: SyncSender<AdmissionMessage>,
    cancelled: Arc<AtomicBool>,
    gauge: Arc<PendingByteGauge>,
    handoff_elapsed: Duration,
    observer: Option<Arc<BulkPhaseObserver>>,
}

impl QueuedAdmission {
    const fn handoff_elapsed(&self) -> Duration {
        self.handoff_elapsed
    }
}

impl<P, E> BatchAdmission<P, E> for QueuedAdmission
where
    E: PrincipalProjectionEngine<P>,
{
    fn admit(
        &mut self,
        engine: &E,
        batch: StagedObjectBatch,
    ) -> Result<u64, PrincipalProjectionError> {
        let started = Instant::now();
        if self.cancelled.load(Ordering::Acquire) {
            self.handoff_elapsed = self.handoff_elapsed.saturating_add(started.elapsed());
            return Err(coordinator_stopped());
        }
        let expected = batch.expected();
        let prepared = match self.observer.as_deref() {
            Some(observer) => engine.prepare_objects_observed(batch.into_records(), observer)?,
            None => engine.prepare_objects(batch.into_records())?,
        };
        let retained_bytes = prepared.retained_bytes();
        self.gauge.retain(retained_bytes);
        if self
            .sender
            .send(AdmissionMessage {
                expected,
                prepared,
                retained_bytes,
            })
            .is_err()
        {
            self.gauge.release(retained_bytes);
            self.handoff_elapsed = self.handoff_elapsed.saturating_add(started.elapsed());
            return Err(coordinator_stopped());
        }
        self.handoff_elapsed = self.handoff_elapsed.saturating_add(started.elapsed());
        Ok(0)
    }
}

struct AdmissionMessage {
    expected: Vec<crate::storage_model::ObjectId>,
    prepared: crate::engine::PreparedProjectionBatch,
    retained_bytes: usize,
}

#[derive(Default)]
struct PendingByteGauge {
    current: AtomicUsize,
    peak: AtomicUsize,
}

impl PendingByteGauge {
    fn retain(&self, bytes: usize) {
        let current = self
            .current
            .fetch_add(bytes, Ordering::AcqRel)
            .saturating_add(bytes);
        self.peak.fetch_max(current, Ordering::AcqRel);
    }

    fn release(&self, bytes: usize) {
        let previous = self.current.fetch_sub(bytes, Ordering::AcqRel);
        debug_assert!(previous >= bytes);
    }

    fn peak(&self) -> usize {
        self.peak.load(Ordering::Acquire)
    }
}

fn coordinator_stopped() -> PrincipalProjectionError {
    PrincipalProjectionError::Engine(COORDINATOR_STOPPED.to_owned())
}

fn retain_worker_error(
    retained: &mut Option<PrincipalContentError>,
    candidate: PrincipalContentError,
) {
    let candidate_is_cancellation = is_coordinator_stopped(&candidate);
    if retained.is_none()
        || (retained.as_ref().is_some_and(is_coordinator_stopped) && !candidate_is_cancellation)
    {
        *retained = Some(candidate);
    }
}

fn is_coordinator_stopped(error: &PrincipalContentError) -> bool {
    matches!(
        error,
        PrincipalContentError::Projection(PrincipalProjectionError::Engine(detail))
            if detail == COORDINATOR_STOPPED
    )
}
