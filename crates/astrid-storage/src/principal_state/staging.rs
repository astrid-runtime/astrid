//! Crash-recoverable native staging for writable content projections.
//!
//! A provider writes ordinary files here at native filesystem speed. Sealing
//! flushes the bytes and a checksummed publication intent; content addressing
//! and authoritative root publication happen later on a blocking worker.

use std::fmt;
use std::fs::File;
use std::io::Read;
#[cfg(test)]
use std::io::SeekFrom;
use std::panic::{RefUnwindSafe, UnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};

use crate::engine::GroupCommitPolicy;
use uuid::Uuid;

#[cfg(test)]
use super::native_io::open_private_file;
#[cfg(test)]
use super::native_io::private_file_identity;
use super::native_io::{
    PrivateDirectory, PrivateFileIdentity, create_private_file, ensure_private_directory,
};
use super::{NativePrincipalContentStore, StateOwner, ensure_runtime_state_owner_admitted};
use crate::content::{ChunkingProfile, ContentBatchWriteOutcome, ContentName, ContentWriteOutcome};
use crate::error::{StorageError, StorageResult};

mod format;
mod group;
mod journal;
mod legacy;
mod migration;
mod recovery;
mod retirement;
#[cfg(test)]
mod runtime_owner_tests;
#[cfg(test)]
mod tests;
mod writer;

use format::StagingIntent;
#[cfg(test)]
use format::append_generation_footer;
use group::SealGroup;
use journal::{
    JournalRecord, StageKey, append_records, flush_journal, open_journal, truncate_empty,
};
pub(super) use migration::migrate_alias_owner_intents;
use migration::{MigrationDirectories, migrate_legacy};
use recovery::{load_generation, open_generation_in, recover_generations, sealed_generation_name};
use retirement::{establish_in as establish_retired_generation, remove_in as remove_generation};
pub use writer::StagedContentWriter;

const GENERATIONS_DIRECTORY: &str = "generations";
const QUARANTINE_DIRECTORY: &str = "quarantine";
const JOURNAL_FILE: &str = "intents.v1.log";

/// Opaque identifier for one native staged write.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StagedContentId(Uuid);

impl fmt::Display for StagedContentId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Private native staging area shared by hosted filesystem providers.
#[derive(Clone, Debug)]
pub struct NativeContentStagingArea {
    inner: Arc<StagingInner>,
}

#[derive(Debug)]
struct StagingInner {
    root: PathBuf,
    generations: PathBuf,
    generations_directory: PrivateDirectory,
    seal_order: PoisoningMutex<SealOrder>,
    group_policy: GroupCommitPolicy,
    seal_group: PoisoningMutex<SealGroup>,
    journal: PoisoningMutex<JournalState>,
    faults: Arc<dyn StagingFaultInjector>,
    #[cfg(test)]
    seal_groups_completed: AtomicU64,
}

#[derive(Debug)]
struct JournalState {
    file: File,
    pending: std::collections::BTreeMap<StageKey, StagingIntent>,
    completed: std::collections::BTreeSet<StageKey>,
    poisoned: bool,
}

#[derive(Debug)]
struct SealOrder {
    next_sequence: u64,
    active: std::collections::BTreeMap<u64, (StateOwner, ContentName)>,
    reserved_identifiers: std::collections::BTreeSet<StagedContentId>,
    reaped_identifiers: std::collections::BTreeSet<StagedContentId>,
}

/// A poisoned coordination lock preserves the staging handles' unwind-safety.
///
/// Continuing through a panic while the seal queue or journal state was being
/// mutated could acknowledge work against incomplete in-memory bookkeeping.
/// Keep the standard mutex's poison boundary instead of silently recovering it.
#[derive(Debug)]
struct PoisoningMutex<T>(std::sync::Mutex<T>);

impl<T> PoisoningMutex<T> {
    fn new(value: T) -> Self {
        Self(std::sync::Mutex::new(value))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, T> {
        match self.0.lock() {
            Ok(guard) => guard,
            Err(error) => panic!("staging coordination lock poisoned: {error}"),
        }
    }
}

struct ActiveSeal {
    area: NativeContentStagingArea,
    sequence: u64,
}

impl Drop for ActiveSeal {
    fn drop(&mut self) {
        self.area
            .inner
            .seal_order
            .lock()
            .active
            .remove(&self.sequence);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StagingFaultPoint {
    ContentFlushed,
    GenerationRenamed,
    MigrationNamespaceFlushed,
    RecoveryGenerationDirectoryFlushed,
    RecoveryCleanupDirectoryFlushed,
    GenerationDirectoryFlushed,
    SealJournalAppended,
    SealJournalFlushed,
    PublicationJournalAppended,
    PublicationJournalFlushed,
    GenerationRetired,
    GenerationCleaned,
}

trait StagingFaultInjector: fmt::Debug + RefUnwindSafe + Send + Sync + UnwindSafe {
    fn fail(&self, point: StagingFaultPoint) -> StorageResult<()>;
}

#[derive(Debug)]
struct NoStagingFaults;

impl StagingFaultInjector for NoStagingFaults {
    fn fail(&self, _point: StagingFaultPoint) -> StorageResult<()> {
        Ok(())
    }
}

impl NativeContentStagingArea {
    /// Open a private staging area and recover writes interrupted after sealing.
    ///
    /// Unacknowledged `.open` generations are retained under `quarantine/`.
    /// A valid renamed generation whose journal tail was not durable can
    /// reconstruct its intent from the file-local footer.
    ///
    /// The caller must hold the same singleton runtime lock as the principal
    /// store. That lock excludes a second daemon from recovering or publishing
    /// the queue during an upgrade window.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the private directory boundary cannot be
    /// established or an acknowledged ready entry cannot be enumerated.
    pub fn open(root: impl Into<PathBuf>) -> StorageResult<Self> {
        Self::open_with_group_commit_policy(root, GroupCommitPolicy::default())
    }

    /// Open a private staging area with an explicit seal-group latency policy.
    ///
    /// The policy controls only how long a leader gathers concurrent seals.
    /// It never changes the durability boundary or persistent format.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::open`].
    pub fn open_with_group_commit_policy(
        root: impl Into<PathBuf>,
        group_policy: GroupCommitPolicy,
    ) -> StorageResult<Self> {
        Self::open_configured(root.into(), group_policy, Arc::new(NoStagingFaults))
    }

    fn open_configured(
        root: PathBuf,
        group_policy: GroupCommitPolicy,
        faults: Arc<dyn StagingFaultInjector>,
    ) -> StorageResult<Self> {
        ensure_private_directory(&root)?;
        let generations = root.join(GENERATIONS_DIRECTORY);
        let quarantine = root.join(QUARANTINE_DIRECTORY);
        for path in [&generations, &quarantine] {
            ensure_private_directory(path)?;
        }
        let root_directory = PrivateDirectory::open(&root)?;
        let generations_directory = PrivateDirectory::open(&generations)?;
        let quarantine_directory = PrivateDirectory::open(&quarantine)?;
        let (journal_file, recovered) = open_journal(&root_directory, &root.join(JOURNAL_FILE))?;
        // Persist the journal and directory links before any seal can be
        // acknowledged through them.
        root_directory.sync()?;
        let mut journal = JournalState {
            file: journal_file,
            pending: recovered.pending,
            completed: recovered.completed,
            poisoned: false,
        };
        migrate_legacy(
            &MigrationDirectories {
                root_path: &root,
                root: &root_directory,
                generations_path: &generations,
                generations: &generations_directory,
                quarantine_path: &quarantine,
                quarantine: &quarantine_directory,
            },
            &mut journal,
            faults.as_ref(),
        )?;
        recover_generations(
            &generations,
            &generations_directory,
            &quarantine,
            &quarantine_directory,
            &mut journal,
            faults.as_ref(),
        )?;
        let next_sequence = journal
            .pending
            .keys()
            .chain(journal.completed.iter())
            .map(|key| key.sequence)
            .max()
            .map_or(Ok(0), |value| {
                value
                    .checked_add(1)
                    .ok_or_else(|| connection("staged-write sequence exhausted".to_owned()))
            })?;
        if journal.pending.is_empty() {
            truncate_empty(&mut journal.file)?;
            journal.completed.clear();
        }
        let reserved_identifiers = journal
            .pending
            .keys()
            .chain(journal.completed.iter())
            .map(|key| key.id)
            .collect();
        Ok(Self {
            inner: Arc::new(StagingInner {
                root,
                generations,
                generations_directory,
                seal_order: PoisoningMutex::new(SealOrder {
                    next_sequence,
                    active: std::collections::BTreeMap::new(),
                    reserved_identifiers,
                    reaped_identifiers: std::collections::BTreeSet::new(),
                }),
                group_policy,
                seal_group: PoisoningMutex::new(SealGroup::default()),
                journal: PoisoningMutex::new(journal),
                faults,
                #[cfg(test)]
                seal_groups_completed: AtomicU64::new(0),
            }),
        })
    }

    /// Begin one native staged write.
    ///
    /// The returned writer supports random access and explicit truncation so a
    /// filesystem provider can implement ordinary file-write semantics without
    /// buffering the value in memory.
    ///
    /// # Errors
    ///
    /// Returns a storage error when a private staging file cannot be created.
    pub fn begin(
        &self,
        owner: StateOwner,
        name: ContentName,
        profile: ChunkingProfile,
    ) -> StorageResult<StagedContentWriter> {
        self.begin_with_id(owner, name, profile, StagedContentId(Uuid::new_v4()))
    }

    fn begin_with_id(
        &self,
        owner: StateOwner,
        name: ContentName,
        profile: ChunkingProfile,
        id: StagedContentId,
    ) -> StorageResult<StagedContentWriter> {
        ensure_runtime_state_owner_admitted(&owner)?;
        let path = self.inner.generations.join(open_generation_name(id));
        let file = {
            let mut order = self.inner.seal_order.lock();
            if !order.reserved_identifiers.insert(id) {
                return Err(connection(format!(
                    "staged-write identifier {id} is already reserved"
                )));
            }
            match create_private_file(&path) {
                Ok(file) => file,
                Err(error) => {
                    order.reserved_identifiers.remove(&id);
                    return Err(error);
                },
            }
        };
        Ok(StagedContentWriter {
            area: self.clone(),
            id,
            owner,
            name,
            profile,
            path: Some(path),
            file: Some(file),
            preserve_on_drop: false,
        })
    }

    /// Enumerate sealed writes in publication order.
    ///
    /// The sequence is allocated by `seal`, rather than `begin`, so an older
    /// slow handle cannot publish after a newer close and overwrite it.
    /// Published-but-not-cleaned entries are removed idempotently.
    ///
    /// # Errors
    ///
    /// Returns a storage error if an acknowledged entry is malformed,
    /// redirected, or no longer matches its durable intent.
    pub fn ready(&self) -> StorageResult<Vec<ReadyStagedContent>> {
        self.reap_completed()?;
        let pending: Vec<_> = {
            let journal = self.inner.journal.lock();
            if journal.poisoned {
                return Err(connection("staging journal requires recovery".to_owned()));
            }
            journal.pending.values().cloned().collect()
        };
        pending
            .into_iter()
            .map(|intent| {
                let path = self
                    .inner
                    .generations
                    .join(sealed_generation_name(intent.sequence, intent.id));
                load_generation(
                    &self.inner.root,
                    &self.inner.generations_directory,
                    path,
                    intent,
                )
            })
            .collect()
    }

    /// Publish one sealed write through the ordinary principal-root CAS.
    ///
    /// Content ingestion, arena reads, appends, and flushes execute on a
    /// blocking worker. A crash before root publication retains the staging
    /// file for retry. A crash after publication is idempotent: the same bytes
    /// publish the same file identity, and the durable `Published` journal
    /// record permits cleanup on the next scan.
    ///
    /// # Errors
    ///
    /// Returns a storage or content-publication error. The staged bytes remain
    /// available whenever cleanup did not complete.
    #[allow(private_interfaces)]
    pub async fn publish(
        &self,
        staged: ReadyStagedContent,
        content: Arc<NativePrincipalContentStore>,
    ) -> StorageResult<ContentWriteOutcome> {
        if staged.staging_root != self.inner.root {
            return Err(connection(
                "staged write belongs to a different staging area".to_owned(),
            ));
        }
        self.ensure_publication_order(&staged)?;
        let area = self.clone();
        tokio::task::spawn_blocking(move || publish_ready(&area, &staged, &content))
            .await
            .map_err(|error| {
                StorageError::Internal(format!("staged content publication worker failed: {error}"))
            })?
    }

    /// Publish several sealed writes through one authoritative root commit.
    ///
    /// Every entry must belong to this staging area and the same owner. The
    /// batch is visible atomically: content construction may stage unreachable
    /// objects, but only one root compare-and-swap authorizes all names. After
    /// that root is durable, one journal append and flush acknowledges every
    /// staged generation for cleanup.
    ///
    /// # Errors
    ///
    /// Returns a staging or content-publication error while retaining every
    /// unacknowledged generation for idempotent retry.
    #[allow(private_interfaces)]
    pub async fn publish_batch(
        &self,
        staged: Vec<ReadyStagedContent>,
        content: Arc<NativePrincipalContentStore>,
    ) -> StorageResult<ContentBatchWriteOutcome> {
        let first = staged
            .first()
            .ok_or_else(|| connection("staged publication batch is empty".to_owned()))?;
        let owner = first.owner;
        let mut names = std::collections::BTreeSet::new();
        for entry in &staged {
            if entry.staging_root != self.inner.root {
                return Err(connection(
                    "staged write belongs to a different staging area".to_owned(),
                ));
            }
            if entry.owner != owner {
                return Err(connection(
                    "staged publication batch spans multiple owners".to_owned(),
                ));
            }
            if !names.insert(&entry.name) {
                return Err(connection(format!(
                    "staged publication batch repeats content name {}",
                    entry.name
                )));
            }
            self.ensure_publication_order_excluding(entry, &staged)?;
        }
        let area = self.clone();
        tokio::task::spawn_blocking(move || publish_ready_batch(&area, &staged, owner, &content))
            .await
            .map_err(|error| {
                StorageError::Internal(format!("staged content batch worker failed: {error}"))
            })?
    }

    fn ensure_publication_order(&self, staged: &ReadyStagedContent) -> StorageResult<()> {
        self.ensure_publication_order_excluding(staged, std::slice::from_ref(staged))
    }

    fn ensure_publication_order_excluding(
        &self,
        staged: &ReadyStagedContent,
        included: &[ReadyStagedContent],
    ) -> StorageResult<()> {
        let earlier_active =
            self.inner
                .seal_order
                .lock()
                .active
                .iter()
                .any(|(sequence, (owner, name))| {
                    *sequence < staged.sequence && owner == &staged.owner && name == &staged.name
                });
        let earlier_pending = {
            let journal = self.inner.journal.lock();
            if journal.poisoned {
                return Err(connection("staging journal requires recovery".to_owned()));
            }
            journal.pending.values().any(|intent| {
                intent.owner == staged.owner
                    && intent.name == staged.name
                    && intent.sequence < staged.sequence
                    && !included
                        .iter()
                        .any(|entry| entry.sequence == intent.sequence && entry.id == intent.id)
            })
        };
        if earlier_active || earlier_pending {
            return Err(connection(format!(
                "staged write {} has an earlier close for the same owner and name",
                staged.id
            )));
        }
        Ok(())
    }

    /// Return the private host path for diagnostics.
    ///
    /// This path is not a guest capability and must not be used as a projected
    /// filesystem root.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.inner.root
    }

    fn register_seal(&self, owner: &StateOwner, name: &ContentName) -> StorageResult<ActiveSeal> {
        let mut order = self.inner.seal_order.lock();
        let sequence = order.next_sequence;
        order.next_sequence = sequence
            .checked_add(1)
            .ok_or_else(|| connection("staged-write sequence exhausted".to_owned()))?;
        order.active.insert(sequence, (*owner, name.clone()));
        drop(order);
        Ok(ActiveSeal {
            area: self.clone(),
            sequence,
        })
    }

    fn mark_published(&self, staged: &ReadyStagedContent) -> StorageResult<()> {
        self.mark_published_batch(std::slice::from_ref(staged))
    }

    fn mark_published_batch(&self, staged: &[ReadyStagedContent]) -> StorageResult<()> {
        let keys = staged
            .iter()
            .map(|staged| StageKey {
                sequence: staged.sequence,
                id: staged.id,
            })
            .collect::<Vec<_>>();
        {
            let mut journal = self.inner.journal.lock();
            if journal.poisoned {
                return Err(connection("staging journal requires recovery".to_owned()));
            }
            if keys.iter().all(|key| journal.completed.contains(key)) {
                drop(journal);
                return self.reap_completed();
            }
            if let Some(missing) = keys.iter().find(|key| !journal.pending.contains_key(key)) {
                return Err(connection(format!(
                    "staged write {} is no longer pending",
                    missing.id
                )));
            }
            let records = keys
                .iter()
                .copied()
                .map(JournalRecord::Published)
                .collect::<Vec<_>>();
            let durable = append_records(&mut journal.file, &records)
                .and_then(|()| self.fail_if(StagingFaultPoint::PublicationJournalAppended))
                .and_then(|()| flush_journal(&journal.file))
                .and_then(|()| self.fail_if(StagingFaultPoint::PublicationJournalFlushed));
            if let Err(error) = durable {
                journal.poisoned = true;
                return Err(error);
            }
            for key in keys {
                journal.pending.remove(&key);
                journal.completed.insert(key);
            }
        }
        self.reap_completed()
    }

    fn reap_completed(&self) -> StorageResult<()> {
        let mut journal = self.inner.journal.lock();
        if journal.poisoned {
            return Err(connection("staging journal requires recovery".to_owned()));
        }
        let completed: Vec<_> = journal.completed.iter().copied().collect();
        if completed.is_empty() {
            return Ok(());
        }
        let cleanup = (|| {
            for key in &completed {
                establish_retired_generation(&self.inner.generations_directory, *key)?;
                self.fail_if(StagingFaultPoint::GenerationRetired)?;
                remove_generation(&self.inner.generations_directory, *key)?;
            }
            self.inner.generations_directory.sync()?;
            self.fail_if(StagingFaultPoint::GenerationCleaned)
        })();
        cleanup?;
        for key in &completed {
            journal.completed.remove(key);
        }
        let journal_drained = journal.pending.is_empty() && journal.completed.is_empty();
        if journal_drained && let Err(error) = truncate_empty(&mut journal.file) {
            journal.poisoned = true;
            return Err(error);
        }
        drop(journal);
        let mut order = self.inner.seal_order.lock();
        for key in completed {
            order.reaped_identifiers.insert(key.id);
        }
        if journal_drained {
            let reaped = std::mem::take(&mut order.reaped_identifiers);
            for id in reaped {
                order.reserved_identifiers.remove(&id);
            }
        }
        Ok(())
    }

    fn fail_if(&self, point: StagingFaultPoint) -> StorageResult<()> {
        self.inner.faults.fail(point)
    }
}

fn publish_ready(
    area: &NativeContentStagingArea,
    staged: &ReadyStagedContent,
    content: &NativePrincipalContentStore,
) -> StorageResult<ContentWriteOutcome> {
    ensure_runtime_state_owner_admitted(&staged.owner)?;
    let (source, _) = open_generation_in(
        &area.inner.generations_directory,
        &staged.content_path(),
        &staged.intent(),
        Some(staged.source_identity),
    )?;
    let outcome = if let Some((bound, limit)) =
        content
            .quota_staging_bound(&staged.owner)
            .map_err(|error| {
                StorageError::Internal(format!(
                    "resolve staged content {} quota: {error}",
                    staged.id
                ))
            })? {
        let (verified, records) = content
            .stage_deferred_bounded(
                source.take(staged.logical_bytes),
                staged.profile,
                bound,
                limit,
            )
            .map_err(|error| {
                StorageError::Internal(format!(
                    "stage content {} into Astrid storage: {error}",
                    staged.id
                ))
            })?;
        content
            .publish_deferred(&staged.owner, &staged.name, verified, &records)
            .map_err(|error| {
                StorageError::Internal(format!("publish staged content {}: {error}", staged.id))
            })?
    } else {
        let (verified, objects_inserted) = content
            .stage_streaming(source.take(staged.logical_bytes), staged.profile)
            .map_err(|error| {
                StorageError::Internal(format!(
                    "stage content {} into Astrid storage: {error}",
                    staged.id
                ))
            })?;
        content
            .publish_verified_content(&staged.owner, &staged.name, verified, objects_inserted)
            .map_err(|error| {
                StorageError::Internal(format!("publish staged content {}: {error}", staged.id))
            })?
    };
    area.mark_published(staged)?;
    Ok(outcome)
}

fn publish_ready_batch(
    area: &NativeContentStagingArea,
    staged: &[ReadyStagedContent],
    owner: StateOwner,
    content: &NativePrincipalContentStore,
) -> StorageResult<ContentBatchWriteOutcome> {
    ensure_runtime_state_owner_admitted(&owner)?;
    let outcome = if let Some((mut remaining, limit)) =
        content.quota_staging_bound(&owner).map_err(|error| {
            StorageError::Internal(format!("resolve staged content batch quota: {error}"))
        })? {
        let mut completed = Vec::with_capacity(staged.len());
        for entry in staged {
            let (source, _) = open_generation_in(
                &area.inner.generations_directory,
                &entry.content_path(),
                &entry.intent(),
                Some(entry.source_identity),
            )?;
            let (verified, records) = content
                .stage_deferred_bounded(
                    source.take(entry.logical_bytes),
                    entry.profile,
                    remaining,
                    limit,
                )
                .map_err(|error| {
                    StorageError::Internal(format!(
                        "stage content {} into Astrid storage: {error}",
                        entry.id
                    ))
                })?;
            remaining = remaining
                .checked_sub(verified.descriptor().logical_bytes())
                .ok_or_else(|| {
                    StorageError::Internal(
                        "staged content batch quota accounting underflow".to_owned(),
                    )
                })?;
            completed.push((entry.name.clone(), verified, records));
        }
        content
            .publish_verified_batch_deferred(&owner, completed)
            .map_err(|error| {
                StorageError::Internal(format!("publish staged content batch: {error}"))
            })?
    } else {
        publish_ready_batch_unmetered(area, staged, &owner, content)?
    };
    area.mark_published_batch(staged)?;
    Ok(outcome)
}

fn publish_ready_batch_unmetered(
    area: &NativeContentStagingArea,
    staged: &[ReadyStagedContent],
    owner: &StateOwner,
    content: &NativePrincipalContentStore,
) -> StorageResult<ContentBatchWriteOutcome> {
    let mut completed = Vec::with_capacity(staged.len());
    let mut objects_inserted = 0_u64;
    for entry in staged {
        let (source, _) = open_generation_in(
            &area.inner.generations_directory,
            &entry.content_path(),
            &entry.intent(),
            Some(entry.source_identity),
        )?;
        let (verified, inserted) = content
            .stage_streaming(source.take(entry.logical_bytes), entry.profile)
            .map_err(|error| {
                StorageError::Internal(format!(
                    "stage content {} into Astrid storage: {error}",
                    entry.id
                ))
            })?;
        objects_inserted = objects_inserted.checked_add(inserted).ok_or_else(|| {
            StorageError::Internal("staged batch object accounting overflow".to_owned())
        })?;
        completed.push((entry.name.clone(), verified));
    }
    content
        .publish_verified_batch(owner, completed, objects_inserted)
        .map_err(|error| StorageError::Internal(format!("publish staged content batch: {error}")))
}

/// One sealed native write awaiting authoritative content publication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadyStagedContent {
    staging_root: PathBuf,
    path: PathBuf,
    sequence: u64,
    id: StagedContentId,
    owner: StateOwner,
    name: ContentName,
    profile: ChunkingProfile,
    logical_bytes: u64,
    source_identity: PrivateFileIdentity,
}

impl ReadyStagedContent {
    fn from_intent(
        staging_root: PathBuf,
        path: PathBuf,
        intent: StagingIntent,
        source_identity: PrivateFileIdentity,
    ) -> Self {
        Self {
            staging_root,
            path,
            sequence: intent.sequence,
            id: intent.id,
            owner: intent.owner,
            name: intent.name,
            profile: intent.profile,
            logical_bytes: intent.logical_bytes,
            source_identity,
        }
    }

    fn intent(&self) -> StagingIntent {
        StagingIntent {
            sequence: self.sequence,
            id: self.id,
            owner: self.owner,
            name: self.name.clone(),
            profile: self.profile,
            logical_bytes: self.logical_bytes,
        }
    }

    /// Return the close-order sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Return the opaque staging identifier.
    #[must_use]
    pub const fn id(&self) -> StagedContentId {
        self.id
    }

    /// Return the authoritative state owner.
    #[must_use]
    pub const fn owner(&self) -> &StateOwner {
        &self.owner
    }

    /// Return the principal content name.
    #[must_use]
    pub const fn name(&self) -> &ContentName {
        &self.name
    }

    /// Return the staged byte length.
    #[must_use]
    pub const fn logical_bytes(&self) -> u64 {
        self.logical_bytes
    }

    /// Return the pinned chunking profile selected at write creation.
    #[must_use]
    pub const fn profile(&self) -> ChunkingProfile {
        self.profile
    }

    pub(super) fn content_path(&self) -> PathBuf {
        self.path.clone()
    }
}

fn claim_generation_key(
    sequences: &mut std::collections::BTreeMap<u64, StagedContentId>,
    identifiers: &mut std::collections::BTreeMap<StagedContentId, u64>,
    key: StageKey,
) -> StorageResult<()> {
    if let Some(existing) = sequences.insert(key.sequence, key.id)
        && existing != key.id
    {
        return Err(connection(format!(
            "staged generation sequence {} names both {} and {}",
            key.sequence, existing, key.id
        )));
    }
    if let Some(existing) = identifiers.insert(key.id, key.sequence)
        && existing != key.sequence
    {
        return Err(connection(format!(
            "staged generation identifier {} names both sequence {} and {}",
            key.id, existing, key.sequence
        )));
    }
    Ok(())
}

fn open_generation_name(id: StagedContentId) -> String {
    format!("{id}.open")
}

fn connection(message: String) -> StorageError {
    StorageError::Connection(message)
}
