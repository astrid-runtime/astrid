//! Seal-group coordination and the shared durability boundary.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::{Condvar, Mutex};

use super::format::StagingIntent;
use super::journal::{JournalRecord, StageKey, append_records, flush_journal};
use super::{
    NativeContentStagingArea, PrivateFileIdentity, ReadyStagedContent, StagingFaultPoint,
    open_generation_in,
};
use crate::error::{StorageError, StorageResult};

#[derive(Debug, Default)]
pub(super) struct SealGroup {
    leader_active: bool,
    queue: VecDeque<QueuedSeal>,
    #[cfg(test)]
    drain_gate: Option<(Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>,
}

#[derive(Debug)]
struct QueuedSeal {
    intent: StagingIntent,
    path: PathBuf,
    source_identity: PrivateFileIdentity,
    receipt: Arc<SealReceipt>,
}

#[derive(Debug, Default)]
struct SealReceipt {
    value: Mutex<SealReceiptValue>,
    ready: Condvar,
}

#[derive(Debug, Default)]
struct SealReceiptValue {
    result: Option<StorageResult<ReadyStagedContent>>,
    promoted: bool,
}

enum SealReceiptAction {
    Lead,
    Complete(StorageResult<ReadyStagedContent>),
}

impl NativeContentStagingArea {
    #[cfg(test)]
    pub(super) fn gate_next_seal_group_drain(
        &self,
        reached: Arc<std::sync::Barrier>,
        release: Arc<std::sync::Barrier>,
    ) {
        self.inner.seal_group.lock().drain_gate = Some((reached, release));
    }

    #[cfg(test)]
    pub(super) fn queued_seal_count(&self) -> usize {
        self.inner.seal_group.lock().queue.len()
    }

    pub(super) fn submit_seal(
        &self,
        intent: StagingIntent,
        path: PathBuf,
        source_identity: PrivateFileIdentity,
    ) -> StorageResult<ReadyStagedContent> {
        let receipt = Arc::new(SealReceipt::default());
        let mut lead = {
            let mut group = self.inner.seal_group.lock();
            group.queue.push_back(QueuedSeal {
                intent,
                path,
                source_identity,
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
                self.run_one_seal_group();
            }
            match receipt.wait() {
                SealReceiptAction::Lead => lead = true,
                SealReceiptAction::Complete(result) => return result,
            }
        }
    }

    fn run_one_seal_group(&self) {
        if !self.inner.group_policy.initial_delay().is_zero() {
            std::thread::sleep(self.inner.group_policy.initial_delay());
        }
        let busy = self.inner.seal_group.lock().queue.len() > 1;
        if busy && !self.inner.group_policy.busy_extension().is_zero() {
            std::thread::sleep(self.inner.group_policy.busy_extension());
        }
        #[cfg(test)]
        let drain_gate = { self.inner.seal_group.lock().drain_gate.take() };
        #[cfg(test)]
        if let Some((reached, release)) = drain_gate {
            reached.wait();
            release.wait();
        }
        let batch: Vec<_> = self.inner.seal_group.lock().queue.drain(..).collect();
        self.process_seal_group(batch);

        let next_leader = {
            let mut group = self.inner.seal_group.lock();
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

    fn process_seal_group(&self, batch: Vec<QueuedSeal>) {
        let mut journal = self.inner.journal.lock();
        if journal.poisoned {
            drop(journal);
            complete_failed_seals(batch, "staging journal requires recovery");
            return;
        }
        let result = (|| {
            for request in &batch {
                open_generation_in(
                    &self.inner.generations_directory,
                    &request.path,
                    &request.intent,
                    Some(request.source_identity),
                )?;
            }
            self.inner.generations_directory.sync()?;
            self.fail_if(StagingFaultPoint::GenerationDirectoryFlushed)?;
            let records: Vec<_> = batch
                .iter()
                .map(|request| JournalRecord::Sealed(request.intent.clone()))
                .collect();
            append_records(&mut journal.file, &records)?;
            self.fail_if(StagingFaultPoint::SealJournalAppended)?;
            flush_journal(&journal.file)?;
            self.fail_if(StagingFaultPoint::SealJournalFlushed)
        })();
        match result {
            Ok(()) => {
                #[cfg(test)]
                self.inner
                    .seal_groups_completed
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                for request in batch {
                    let key = StageKey::from_intent(&request.intent);
                    journal.pending.insert(key, request.intent.clone());
                    let ready = ReadyStagedContent::from_intent(
                        self.inner.root.clone(),
                        request.path,
                        request.intent,
                        request.source_identity,
                    );
                    request.receipt.complete(Ok(ready));
                }
            },
            Err(error) => {
                journal.poisoned = true;
                drop(journal);
                complete_failed_seals(batch, &format!("{error}; reopen staging before retry"));
            },
        }
    }
}

impl SealReceipt {
    fn complete(&self, result: StorageResult<ReadyStagedContent>) {
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
        }
        self.ready.notify_one();
    }

    fn wait(&self) -> SealReceiptAction {
        let mut value = self.value.lock();
        loop {
            if let Some(result) = value.result.take() {
                return SealReceiptAction::Complete(result);
            }
            if value.promoted {
                value.promoted = false;
                return SealReceiptAction::Lead;
            }
            self.ready.wait(&mut value);
        }
    }
}

fn complete_failed_seals(batch: Vec<QueuedSeal>, detail: &str) {
    for request in batch {
        request
            .receipt
            .complete(Err(StorageError::Connection(detail.to_owned())));
    }
}
