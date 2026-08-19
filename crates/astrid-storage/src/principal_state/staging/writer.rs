use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use super::format::{StagingIntent, append_generation_footer};
use super::recovery::sealed_generation_name;
use super::{
    NativeContentStagingArea, ReadyStagedContent, StagedContentId, StagingFaultPoint, connection,
};
use crate::content::{ChunkingProfile, ContentName};
use crate::error::StorageResult;
use crate::principal_state::StateOwner;
use crate::principal_state::native_io::private_file_identity;

/// Random-access native file being prepared for later content publication.
#[derive(Debug)]
pub struct StagedContentWriter {
    pub(super) area: NativeContentStagingArea,
    pub(super) id: StagedContentId,
    pub(super) owner: StateOwner,
    pub(super) name: ContentName,
    pub(super) profile: ChunkingProfile,
    pub(super) path: Option<PathBuf>,
    pub(super) file: Option<File>,
    pub(super) preserve_on_drop: bool,
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
        let source_identity = private_file_identity(&file)?;
        let logical_bytes = file
            .metadata()
            .map_err(|error| {
                connection(format!(
                    "inspect staged content handle {}: {error}",
                    self.id
                ))
            })?
            .len();
        let active = self.area.register_seal(&self.owner, &self.name)?;
        let sequence = active.sequence;
        let intent = StagingIntent {
            sequence,
            id: self.id,
            owner: self.owner,
            name: self.name.clone(),
            profile: self.profile,
            logical_bytes,
        };
        append_generation_footer(&mut file, &intent, source_identity)?;
        file.sync_all()
            .map_err(|error| connection(format!("flush staged content {}: {error}", self.id)))?;
        self.area.fail_if(StagingFaultPoint::ContentFlushed)?;
        drop(file);
        let sealed_path = self
            .area
            .inner
            .generations
            .join(sealed_generation_name(sequence, self.id));
        let source_name = path.file_name().ok_or_else(|| {
            connection(format!(
                "staged generation {} has no file name",
                path.display()
            ))
        })?;
        let destination_name = sealed_path.file_name().ok_or_else(|| {
            connection(format!(
                "sealed generation {} has no file name",
                sealed_path.display()
            ))
        })?;
        self.area.inner.generations_directory.rename_with_identity(
            Path::new(source_name),
            Path::new(destination_name),
            source_identity,
        )?;
        self.area.fail_if(StagingFaultPoint::GenerationRenamed)?;
        self.path = None;
        self.area.submit_seal(intent, sealed_path, source_identity)
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
        self.area
            .inner
            .seal_order
            .lock()
            .reserved_identifiers
            .remove(&self.id);
    }
}

fn closed_writer() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::BrokenPipe,
        "staged content writer is closed",
    )
}
