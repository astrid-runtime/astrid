//! Crash-recoverable native staging for writable content projections.
//!
//! A provider writes ordinary files here at native filesystem speed. Sealing
//! flushes the bytes and a checksummed publication intent; content addressing
//! and authoritative root publication happen later on a blocking worker.

use std::fmt;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use astrid_core::identity::PrincipalUid;
use astrid_core::principal::PrincipalId;
use astrid_storage_engine::GroupCommitPolicy;
use parking_lot::Mutex;
use uuid::Uuid;

use super::native_io::{
    atomic_write, create_private_file, ensure_private_directory, open_private_file, sync_directory,
    validate_private_regular_file,
};
use super::{NativePrincipalContentStore, StateOwner};
use crate::content::{ChunkingProfile, ContentName, ContentWriteOutcome};
use crate::error::{StorageError, StorageResult};

mod format;
mod group;
mod journal;
mod legacy;
mod migration;
mod recovery;
#[cfg(test)]
mod tests;

use format::{
    LegacyStagingOwner, StagingIntent, append_generation_footer, encode_intent,
    load_generation_footer, load_intent, load_legacy_intent,
};
use group::SealGroup;
use journal::{
    JournalRecord, StageKey, append_records, flush_journal, open_journal, truncate_empty,
};
use migration::migrate_legacy;
use recovery::{
    load_generation, move_to_quarantine, parse_generation_name, read_directory,
    sealed_generation_name, validate_generation,
};

const GENERATIONS_DIRECTORY: &str = "generations";
const QUARANTINE_DIRECTORY: &str = "quarantine";
const JOURNAL_FILE: &str = "intents.v1.log";
const WRITING_DIRECTORY: &str = "writing";
const READY_DIRECTORY: &str = "ready";
const INTENT_FILE: &str = "intent.v2";
const LEGACY_INTENT_FILE: &str = "intent.v1";

pub(super) fn migrate_alias_owner_intents(
    root: &Path,
    mut resolve: impl FnMut(&PrincipalId) -> StorageResult<PrincipalUid>,
) -> StorageResult<()> {
    match std::fs::symlink_metadata(root) {
        Ok(_) => ensure_private_directory(root)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(connection(format!(
                "inspect legacy staging root {}: {error}",
                root.display()
            )));
        },
    }
    for name in [WRITING_DIRECTORY, READY_DIRECTORY] {
        let queue = root.join(name);
        match std::fs::symlink_metadata(&queue) {
            Ok(_) => ensure_private_directory(&queue)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(connection(format!(
                    "inspect legacy staging queue {}: {error}",
                    queue.display()
                )));
            },
        }
        for entry in read_directory(&queue)? {
            let entry = entry.map_err(|error| {
                connection(format!(
                    "enumerate legacy staging queue {}: {error}",
                    queue.display()
                ))
            })?;
            migrate_entry_intent(&entry.path(), &mut resolve)?;
        }
    }
    Ok(())
}

fn migrate_entry_intent(
    directory: &Path,
    resolve: &mut impl FnMut(&PrincipalId) -> StorageResult<PrincipalUid>,
) -> StorageResult<()> {
    validate_stage_directory(directory)?;
    let legacy_path = directory.join(LEGACY_INTENT_FILE);
    match std::fs::symlink_metadata(&legacy_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(connection(format!(
                "inspect legacy staged intent {}: {error}",
                legacy_path.display()
            )));
        },
        Ok(_) => {},
    }
    let legacy = load_legacy_intent(&legacy_path)?;
    let owner = match &legacy.owner {
        LegacyStagingOwner::System => StateOwner::System,
        LegacyStagingOwner::Principal(alias) => StateOwner::Principal(resolve(alias)?),
    };
    let migrated = StagingIntent {
        sequence: legacy.sequence,
        id: legacy.id,
        owner,
        name: legacy.name,
        profile: legacy.profile,
        logical_bytes: legacy.logical_bytes,
    };
    let current_path = directory.join(INTENT_FILE);
    match std::fs::symlink_metadata(&current_path) {
        Ok(_) => {
            if load_intent(&current_path)? != migrated {
                return Err(connection(format!(
                    "legacy and UID staging intents disagree in {}",
                    directory.display()
                )));
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            atomic_write(&current_path, &encode_intent(&migrated)?)?;
        },
        Err(error) => {
            return Err(connection(format!(
                "inspect UID staged intent {}: {error}",
                current_path.display()
            )));
        },
    }
    std::fs::remove_file(&legacy_path).map_err(|error| {
        connection(format!(
            "remove migrated staged intent {}: {error}",
            legacy_path.display()
        ))
    })?;
    sync_directory(directory)
}

fn validate_stage_directory(path: &Path) -> StorageResult<()> {
    astrid_core::platform_fs::verify_no_redirects(path).map_err(|error| {
        connection(format!(
            "validate staging directory {}: {error}",
            path.display()
        ))
    })?;
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        connection(format!(
            "inspect staging directory {}: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(connection(format!(
            "staging entry {} is redirected or not a directory",
            path.display()
        )));
    }
    Ok(())
}

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
    next_sequence: AtomicU64,
    group_policy: GroupCommitPolicy,
    seal_group: Mutex<SealGroup>,
    journal: Mutex<JournalState>,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StagingFaultPoint {
    ContentFlushed,
    GenerationRenamed,
    GenerationDirectoryFlushed,
    SealJournalAppended,
    SealJournalFlushed,
    PublicationJournalAppended,
    PublicationJournalFlushed,
    GenerationCleaned,
}

trait StagingFaultInjector: fmt::Debug + Send + Sync {
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
    /// Unsealed writer directories are retained under `quarantine/`; they were
    /// never acknowledged as complete. A valid intent left before the final
    /// directory rename is promoted to the ready queue.
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
        let (journal_file, recovered) = open_journal(&root.join(JOURNAL_FILE))?;
        // Persist the journal and directory links before any seal can be
        // acknowledged through them.
        sync_directory(&root)?;
        let mut journal = JournalState {
            file: journal_file,
            pending: recovered.pending,
            completed: recovered.completed,
            poisoned: false,
        };
        migrate_legacy(&root, &generations, &quarantine, &mut journal)?;
        recover_generations(&generations, &quarantine, &mut journal)?;
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
        Ok(Self {
            inner: Arc::new(StagingInner {
                root,
                generations,
                next_sequence: AtomicU64::new(next_sequence),
                group_policy,
                seal_group: Mutex::new(SealGroup::default()),
                journal: Mutex::new(journal),
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
        let id = StagedContentId(Uuid::new_v4());
        let path = self.inner.generations.join(open_generation_name(id));
        match create_private_file(&path) {
            Ok(file) => Ok(StagedContentWriter {
                area: self.clone(),
                id,
                owner,
                name,
                profile,
                path: Some(path),
                file: Some(file),
                preserve_on_drop: false,
            }),
            Err(error) => {
                let _ = std::fs::remove_file(&path);
                Err(error)
            },
        }
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
                load_generation(&self.inner.root, path, intent)
            })
            .collect()
    }

    /// Publish one sealed write through the ordinary principal-root CAS.
    ///
    /// Content ingestion, arena reads, appends, and flushes execute on a
    /// blocking worker. A crash before root publication retains the staging
    /// file for retry. A crash after publication is idempotent: the same bytes
    /// publish the same file identity, and the durable publication marker
    /// permits cleanup on the next scan.
    ///
    /// # Errors
    ///
    /// Returns a storage or content-publication error. The staged bytes remain
    /// available whenever cleanup did not complete.
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
        if self.ready()?.iter().any(|queued| {
            queued.owner == staged.owner
                && queued.name == staged.name
                && queued.sequence < staged.sequence
        }) {
            return Err(connection(format!(
                "staged write {} has an earlier close for the same owner and name",
                staged.id
            )));
        }
        let area = self.clone();
        tokio::task::spawn_blocking(move || {
            let source = open_private_file(&staged.content_path())?.take(staged.logical_bytes);
            let outcome = content
                .put_streaming_with_profile(&staged.owner, &staged.name, source, staged.profile)
                .map_err(|error| {
                    StorageError::Internal(format!("publish staged content {}: {error}", staged.id))
                })?;
            area.mark_published(&staged)?;
            Ok(outcome)
        })
        .await
        .map_err(|error| {
            StorageError::Internal(format!("staged content publication worker failed: {error}"))
        })?
    }

    /// Return the private host path for diagnostics.
    ///
    /// This path is not a guest capability and must not be used as a projected
    /// filesystem root.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.inner.root
    }

    fn allocate_sequence(&self) -> StorageResult<u64> {
        self.inner
            .next_sequence
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                current.checked_add(1)
            })
            .map_err(|_| connection("staged-write sequence exhausted".to_owned()))
    }

    fn mark_published(&self, staged: &ReadyStagedContent) -> StorageResult<()> {
        let key = StageKey {
            sequence: staged.sequence,
            id: staged.id,
        };
        {
            let mut journal = self.inner.journal.lock();
            if journal.poisoned {
                return Err(connection("staging journal requires recovery".to_owned()));
            }
            if !journal.pending.contains_key(&key) {
                return Err(connection(format!(
                    "staged write {} is no longer pending",
                    staged.id
                )));
            }
            let durable = append_records(&mut journal.file, &[JournalRecord::Published(key)])
                .and_then(|()| self.fail_if(StagingFaultPoint::PublicationJournalAppended))
                .and_then(|()| flush_journal(&journal.file))
                .and_then(|()| self.fail_if(StagingFaultPoint::PublicationJournalFlushed));
            if let Err(error) = durable {
                journal.poisoned = true;
                return Err(error);
            }
            journal.pending.remove(&key);
            journal.completed.insert(key);
        }
        self.reap_completed()
    }

    fn reap_completed(&self) -> StorageResult<()> {
        let completed: Vec<_> = {
            let journal = self.inner.journal.lock();
            journal.completed.iter().copied().collect()
        };
        if completed.is_empty() {
            return Ok(());
        }
        for key in &completed {
            let path = self
                .inner
                .generations
                .join(sealed_generation_name(key.sequence, key.id));
            remove_generation(&path)?;
        }
        sync_directory(&self.inner.generations)?;
        self.fail_if(StagingFaultPoint::GenerationCleaned)?;

        let mut journal = self.inner.journal.lock();
        for key in completed {
            journal.completed.remove(&key);
        }
        if journal.pending.is_empty()
            && journal.completed.is_empty()
            && let Err(error) = truncate_empty(&mut journal.file)
        {
            journal.poisoned = true;
            return Err(error);
        }
        Ok(())
    }

    fn fail_if(&self, point: StagingFaultPoint) -> StorageResult<()> {
        self.inner.faults.fail(point)
    }
}

/// Random-access native file being prepared for later content publication.
#[derive(Debug)]
pub struct StagedContentWriter {
    area: NativeContentStagingArea,
    id: StagedContentId,
    owner: StateOwner,
    name: ContentName,
    profile: ChunkingProfile,
    path: Option<PathBuf>,
    file: Option<File>,
    preserve_on_drop: bool,
}

impl StagedContentWriter {
    /// Return the staging identifier.
    #[must_use]
    pub const fn id(&self) -> StagedContentId {
        self.id
    }

    /// Resize the native staging file.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the host filesystem cannot resize the file.
    pub fn set_len(&self, length: u64) -> std::io::Result<()> {
        self.file
            .as_ref()
            .ok_or_else(closed_writer)?
            .set_len(length)
    }

    /// Flush bytes and intent, then make this write recoverably publishable.
    ///
    /// Returning from this method is the hosted-provider acknowledgement
    /// boundary. It does not wait for chunking, hashing, or root publication.
    ///
    /// # Errors
    ///
    /// Returns a storage error if bytes or intent cannot be made durable or the
    /// ready transition fails.
    pub fn seal(mut self) -> StorageResult<ReadyStagedContent> {
        let mut file = self
            .file
            .take()
            .ok_or_else(|| connection("staged writer is already closed".to_owned()))?;
        // `seal` consumes the writer. Preserve unacknowledged bytes for
        // quarantine/recovery if any durability step fails.
        self.preserve_on_drop = true;
        let path = self
            .path
            .as_ref()
            .ok_or_else(|| connection("staged writer has no generation path".to_owned()))?;
        let logical_bytes = validate_private_regular_file(path)?;
        let sequence = self.area.allocate_sequence()?;
        let intent = StagingIntent {
            sequence,
            id: self.id,
            owner: self.owner,
            name: self.name.clone(),
            profile: self.profile,
            logical_bytes,
        };
        append_generation_footer(&mut file, &intent)?;
        file.sync_all()
            .map_err(|error| connection(format!("flush staged content {}: {error}", self.id)))?;
        self.area.fail_if(StagingFaultPoint::ContentFlushed)?;
        drop(file);
        let sealed_path = self
            .area
            .inner
            .generations
            .join(sealed_generation_name(sequence, self.id));
        std::fs::rename(path, &sealed_path).map_err(|error| {
            connection(format!(
                "seal staged generation {} as {}: {error}",
                path.display(),
                sealed_path.display()
            ))
        })?;
        self.area.fail_if(StagingFaultPoint::GenerationRenamed)?;
        self.path = None;
        self.area.submit_seal(intent, sealed_path)
    }
}

impl Read for StagedContentWriter {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.file.as_mut().ok_or_else(closed_writer)?.read(buffer)
    }
}

impl Write for StagedContentWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.file.as_mut().ok_or_else(closed_writer)?.write(buffer)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.as_mut().ok_or_else(closed_writer)?.flush()
    }
}

impl Seek for StagedContentWriter {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        self.file.as_mut().ok_or_else(closed_writer)?.seek(position)
    }
}

impl Drop for StagedContentWriter {
    fn drop(&mut self) {
        if self.preserve_on_drop {
            return;
        }
        self.file.take();
        if let Some(path) = self.path.take() {
            let _ = std::fs::remove_file(path);
        }
    }
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
}

impl ReadyStagedContent {
    fn from_intent(staging_root: PathBuf, path: PathBuf, intent: StagingIntent) -> Self {
        Self {
            staging_root,
            path,
            sequence: intent.sequence,
            id: intent.id,
            owner: intent.owner,
            name: intent.name,
            profile: intent.profile,
            logical_bytes: intent.logical_bytes,
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

fn recover_generations(
    generations: &Path,
    quarantine: &Path,
    journal: &mut JournalState,
) -> StorageResult<()> {
    let mut removed = false;
    let mut recovered = Vec::new();
    for entry in read_directory(generations)? {
        let entry = entry.map_err(|error| {
            connection(format!(
                "enumerate staged generations {}: {error}",
                generations.display()
            ))
        })?;
        let path = entry.path();
        match parse_generation_name(&entry.file_name().to_string_lossy()) {
            Ok(recovery::GenerationName::Open) => {
                move_to_quarantine(&path, quarantine, "unsealed")?;
            },
            Ok(recovery::GenerationName::Sealed(key)) if journal.completed.contains(&key) => {
                remove_generation(&path)?;
                removed = true;
            },
            Ok(recovery::GenerationName::Sealed(key)) if journal.pending.contains_key(&key) => {},
            Ok(recovery::GenerationName::Sealed(key)) => {
                let Ok(intent) = load_generation_footer(&path) else {
                    move_to_quarantine(&path, quarantine, "orphan")?;
                    continue;
                };
                if StageKey::from_intent(&intent) != key {
                    return Err(connection(format!(
                        "orphan staged generation footer disagrees with {}",
                        path.display()
                    )));
                }
                recovered.push(intent);
            },
            Err(_) => {
                move_to_quarantine(&path, quarantine, "orphan")?;
            },
        }
    }
    if !recovered.is_empty() {
        let records: Vec<_> = recovered
            .iter()
            .cloned()
            .map(JournalRecord::Sealed)
            .collect();
        append_records(&mut journal.file, &records)?;
        flush_journal(&journal.file)?;
        for intent in recovered {
            journal
                .pending
                .insert(StageKey::from_intent(&intent), intent);
        }
    }
    if removed {
        sync_directory(generations)?;
    }
    for intent in journal.pending.values() {
        let path = generations.join(sealed_generation_name(intent.sequence, intent.id));
        validate_generation(&path, intent)?;
    }
    Ok(())
}

fn open_generation_name(id: StagedContentId) -> String {
    format!("{id}.open")
}

fn remove_generation(path: &Path) -> StorageResult<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(connection(format!(
            "remove staged generation {}: {error}",
            path.display()
        ))),
    }
}

fn closed_writer() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::BrokenPipe,
        "staged content writer is closed",
    )
}

fn connection(message: String) -> StorageError {
    StorageError::Connection(message)
}
