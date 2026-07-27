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

use uuid::Uuid;

use super::native_io::{
    atomic_write, create_private_file, ensure_private_directory, open_private_file, sync_directory,
    validate_private_regular_file,
};
use super::{NativePrincipalContentStore, StateOwner};
use crate::content::{ChunkingProfile, ContentName, ContentWriteOutcome};
use crate::error::{StorageError, StorageResult};

mod format;
mod recovery;
#[cfg(test)]
mod tests;

use format::{StagingIntent, encode_intent};
use recovery::{
    load_ready, next_sequence, parse_ready_name, read_directory, ready_name, recover_writing,
    remove_known_stage_files,
};

const WRITING_DIRECTORY: &str = "writing";
const READY_DIRECTORY: &str = "ready";
const QUARANTINE_DIRECTORY: &str = "quarantine";
const CONTENT_FILE: &str = "content.bin";
const INTENT_FILE: &str = "intent.v1";
const PUBLISHED_FILE: &str = "published.v1";
const PUBLISHED_MARKER: &[u8] = b"astrid-content-stage-published-v1\n";

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
    writing: PathBuf,
    ready: PathBuf,
    next_sequence: AtomicU64,
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
        let root = root.into();
        ensure_private_directory(&root)?;
        let writing = root.join(WRITING_DIRECTORY);
        let ready = root.join(READY_DIRECTORY);
        let quarantine = root.join(QUARANTINE_DIRECTORY);
        for path in [&writing, &ready, &quarantine] {
            ensure_private_directory(path)?;
        }
        recover_writing(&writing, &ready, &quarantine)?;
        let next_sequence = next_sequence(&ready)?;
        Ok(Self {
            inner: Arc::new(StagingInner {
                root,
                writing,
                ready,
                next_sequence: AtomicU64::new(next_sequence),
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
        let directory = self.inner.writing.join(id.to_string());
        ensure_private_directory(&directory)?;
        let content_path = directory.join(CONTENT_FILE);
        match create_private_file(&content_path) {
            Ok(file) => Ok(StagedContentWriter {
                area: self.clone(),
                id,
                owner,
                name,
                profile,
                directory: Some(directory),
                file: Some(file),
                preserve_on_drop: false,
            }),
            Err(error) => {
                let _ = std::fs::remove_dir(&directory);
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
        let mut ready = Vec::new();
        for entry in read_directory(&self.inner.ready)? {
            let entry = entry.map_err(|error| {
                connection(format!(
                    "enumerate staging queue {}: {error}",
                    self.inner.ready.display()
                ))
            })?;
            let path = entry.path();
            let (sequence, id) = parse_ready_name(&entry.file_name().to_string_lossy())?;
            let staged = load_ready(&self.inner.root, path, sequence, id)?;
            if staged.is_published()? {
                staged.cleanup()?;
            } else {
                ready.push(staged);
            }
        }
        ready.sort_by_key(|entry| (entry.sequence, entry.id));
        Ok(ready)
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
        tokio::task::spawn_blocking(move || {
            let source = open_private_file(&staged.content_path())?;
            let outcome = content
                .put_streaming_with_profile(&staged.owner, &staged.name, source, staged.profile)
                .map_err(|error| {
                    StorageError::Internal(format!("publish staged content {}: {error}", staged.id))
                })?;
            atomic_write(&staged.directory.join(PUBLISHED_FILE), PUBLISHED_MARKER)?;
            staged.cleanup()?;
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
}

/// Random-access native file being prepared for later content publication.
#[derive(Debug)]
pub struct StagedContentWriter {
    area: NativeContentStagingArea,
    id: StagedContentId,
    owner: StateOwner,
    name: ContentName,
    profile: ChunkingProfile,
    directory: Option<PathBuf>,
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
        let file = self
            .file
            .take()
            .ok_or_else(|| connection("staged writer is already closed".to_owned()))?;
        file.sync_all()
            .map_err(|error| connection(format!("flush staged content {}: {error}", self.id)))?;
        drop(file);
        let directory = self
            .directory
            .as_ref()
            .ok_or_else(|| connection("staged writer has no directory".to_owned()))?;
        let content_path = directory.join(CONTENT_FILE);
        let logical_bytes = validate_private_regular_file(&content_path)?;
        let sequence = self.area.allocate_sequence()?;
        let intent = StagingIntent {
            sequence,
            id: self.id,
            owner: self.owner.clone(),
            name: self.name.clone(),
            profile: self.profile,
            logical_bytes,
        };
        atomic_write(&directory.join(INTENT_FILE), &encode_intent(&intent)?)?;
        self.preserve_on_drop = true;

        let ready_path = self.area.inner.ready.join(ready_name(sequence, self.id));
        std::fs::rename(directory, &ready_path).map_err(|error| {
            connection(format!(
                "publish sealed staging directory {} as {}: {error}",
                directory.display(),
                ready_path.display()
            ))
        })?;
        sync_directory(&self.area.inner.writing)?;
        sync_directory(&self.area.inner.ready)?;
        self.directory = None;
        Ok(ReadyStagedContent::from_intent(
            self.area.inner.root.clone(),
            ready_path,
            intent,
        ))
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
        if let Some(directory) = self.directory.take() {
            let _ = remove_known_stage_files(&directory);
        }
    }
}

/// One sealed native write awaiting authoritative content publication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadyStagedContent {
    staging_root: PathBuf,
    directory: PathBuf,
    sequence: u64,
    id: StagedContentId,
    owner: StateOwner,
    name: ContentName,
    profile: ChunkingProfile,
    logical_bytes: u64,
}

impl ReadyStagedContent {
    fn from_intent(staging_root: PathBuf, directory: PathBuf, intent: StagingIntent) -> Self {
        Self {
            staging_root,
            directory,
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
        self.directory.join(CONTENT_FILE)
    }

    fn is_published(&self) -> StorageResult<bool> {
        let path = self.directory.join(PUBLISHED_FILE);
        match std::fs::read(&path) {
            Ok(marker) => Ok(marker == PUBLISHED_MARKER),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(connection(format!(
                "read staged publication marker {}: {error}",
                path.display()
            ))),
        }
    }

    fn cleanup(&self) -> StorageResult<()> {
        remove_known_stage_files(&self.directory)?;
        sync_directory(
            self.directory
                .parent()
                .ok_or_else(|| connection("ready staging directory has no parent".to_owned()))?,
        )
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
