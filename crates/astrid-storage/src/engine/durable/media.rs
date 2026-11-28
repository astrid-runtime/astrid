//! Native-file and Astrid-volume byte streams used by the durable engine.
//!
//! Framing stays generic over this interface so the frozen store format is
//! independent of whichever media provider owns the bytes.

use std::fs::File as NativeFile;
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::sync::Arc;

use crate::volume::{AstridVolume, VolumeFile, VolumeMetadata, VolumeRegion};

use super::DurableError;

// I/O coalescing only; neither frame sizes nor retained history depend on it.
pub(in crate::engine::durable) const STREAM_WRITE_BUFFER_BYTES: usize = 64 * 1024;

fn write_from_buffered(
    destination: &mut (impl Write + ?Sized),
    payload_len: u64,
    payload: &mut dyn Read,
) -> io::Result<()> {
    let mut writer = BufWriter::with_capacity(STREAM_WRITE_BUFFER_BYTES, destination);
    let copied = io::copy(&mut payload.take(payload_len), &mut writer)?;
    if copied != payload_len {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "short durable stream",
        ));
    }
    // Drain only the coalescing buffer. The caller still owns the final flush
    // and its media-specific durability boundary.
    writer
        .into_inner()
        .map(|_| ())
        .map_err(io::IntoInnerError::into_error)
}

#[derive(Debug)]
pub(in crate::engine::durable) enum StoreLock {
    Native(NativeFile),
    Volume,
}

/// Byte-stream handle used by the durable engine.
///
/// Native files remain available for legacy import and format tests. Runtime
/// layout two opens the same engine over [`VolumeFile`], so object and root
/// authority no longer depends on a host directory namespace.
pub(in crate::engine::durable) type File = super::frontier::Backing<NativeFile, VolumeFile>;

/// Common random-access durable byte stream used by both legacy host files and
/// Astrid volume regions.
///
/// Keeping framing generic over this interface is important: the frozen store
/// format is independent of whichever media provider owns the bytes.
pub(in crate::engine::durable) trait DurableIo:
    Read + Write + Seek
{
    fn durable_metadata(&self) -> io::Result<StoreMetadata>;
    fn durable_set_len(&self, length: u64) -> io::Result<()>;
    fn durable_sync_data(&self) -> io::Result<()>;
    /// Persist a repaired tail on its owning file or volume container.
    fn durable_sync_repaired_tail(&self) -> io::Result<()>;
    fn durable_read_at(&self, buffer: &mut [u8], offset: u64) -> io::Result<usize>;

    /// Emit exactly the known-length stream, without performing the final flush.
    fn durable_write_from(&mut self, payload_len: u64, payload: &mut dyn Read) -> io::Result<()> {
        write_from_buffered(self, payload_len, payload)
    }

    /// Whether positional reads leave the sequential cursor unchanged.
    /// Unknown providers conservatively require cursor preservation.
    fn durable_read_at_preserves_cursor(&self) -> bool {
        false
    }
}

impl File {
    pub(in crate::engine::durable) fn native(file: NativeFile) -> Self {
        Self::Native(file)
    }

    pub(in crate::engine::durable) fn volume(
        volume: Arc<dyn AstridVolume>,
        name: &str,
        create: bool,
    ) -> Result<Self, DurableError> {
        let region = VolumeRegion::new(name).map_err(|source| DurableError::Io {
            operation: "validate volume region",
            source,
        })?;
        VolumeFile::open(volume, region, create)
            .map(Self::Volume)
            .map_err(|source| DurableError::Io {
                operation: "open volume region",
                source,
            })
    }

    pub(in crate::engine::durable) fn try_clone(&self) -> io::Result<Self> {
        match self {
            Self::Native(file) => file.try_clone().map(Self::Native),
            Self::Volume(file) => file.try_clone().map(Self::Volume),
        }
    }

    pub(in crate::engine::durable) fn sync_data(&self) -> io::Result<()> {
        match self {
            Self::Native(file) => file.sync_data(),
            Self::Volume(_) => Ok(()),
        }
    }

    pub(super) fn flush_region(&self) -> io::Result<super::frontier::JournalFlush<VolumeFile>> {
        self.flush_with(NativeFile::sync_data, Clone::clone)
    }

    pub(in crate::engine::durable) fn set_len(&self, length: u64) -> io::Result<()> {
        match self {
            Self::Native(file) => file.set_len(length),
            Self::Volume(file) => file.set_len(length),
        }
    }

    pub(in crate::engine::durable) fn metadata(&self) -> io::Result<StoreMetadata> {
        match self {
            Self::Native(file) => file.metadata().map(StoreMetadata::Native),
            Self::Volume(file) => file.metadata().map(StoreMetadata::Volume),
        }
    }

    pub(in crate::engine::durable) fn read_at(
        &self,
        buffer: &mut [u8],
        offset: u64,
    ) -> io::Result<usize> {
        match self {
            #[cfg(unix)]
            Self::Native(file) => std::os::unix::fs::FileExt::read_at(file, buffer, offset),
            #[cfg(windows)]
            Self::Native(file) => std::os::windows::fs::FileExt::seek_read(file, buffer, offset),
            #[cfg(not(any(unix, windows)))]
            Self::Native(file) => {
                let mut reader = file.try_clone()?;
                reader.seek(SeekFrom::Start(offset))?;
                reader.read(buffer)
            },
            Self::Volume(file) => file.read_at(buffer, offset),
        }
    }
}

impl std::io::Read for File {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Native(file) => file.read(buffer),
            Self::Volume(file) => file.read(buffer),
        }
    }
}

impl std::io::Write for File {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self {
            Self::Native(file) => file.write(bytes),
            Self::Volume(file) => file.write(bytes),
        }
    }

    fn write_vectored(&mut self, slices: &[io::IoSlice<'_>]) -> io::Result<usize> {
        match self {
            Self::Native(file) => file.write_vectored(slices),
            Self::Volume(file) => file.write_vectored(slices),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Native(file) => file.flush(),
            Self::Volume(file) => file.flush(),
        }
    }
}

impl std::io::Seek for File {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        match self {
            Self::Native(file) => file.seek(position),
            Self::Volume(file) => file.seek(position),
        }
    }
}

impl DurableIo for File {
    fn durable_write_from(&mut self, payload_len: u64, payload: &mut dyn Read) -> io::Result<()> {
        match self {
            Self::Native(file) => write_from_buffered(file, payload_len, payload),
            Self::Volume(file) => file.write_from(payload_len, payload),
        }
    }

    fn durable_read_at_preserves_cursor(&self) -> bool {
        match self {
            Self::Native(_) => cfg!(unix),
            Self::Volume(_) => true,
        }
    }

    fn durable_metadata(&self) -> io::Result<StoreMetadata> {
        self.metadata()
    }

    fn durable_set_len(&self, length: u64) -> io::Result<()> {
        self.set_len(length)
    }

    fn durable_sync_data(&self) -> io::Result<()> {
        self.sync_data()
    }

    fn durable_sync_repaired_tail(&self) -> io::Result<()> {
        self.persist_repair(NativeFile::sync_data, |region| region)
            .map(drop)
    }

    fn durable_read_at(&self, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
        self.read_at(buffer, offset)
    }
}

impl DurableIo for NativeFile {
    fn durable_read_at_preserves_cursor(&self) -> bool {
        cfg!(unix)
    }

    fn durable_metadata(&self) -> io::Result<StoreMetadata> {
        self.metadata().map(StoreMetadata::Native)
    }

    fn durable_set_len(&self, length: u64) -> io::Result<()> {
        self.set_len(length)
    }

    fn durable_sync_data(&self) -> io::Result<()> {
        self.sync_data()
    }

    fn durable_sync_repaired_tail(&self) -> io::Result<()> {
        self.sync_data()
    }

    fn durable_read_at(&self, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
        #[cfg(unix)]
        {
            std::os::unix::fs::FileExt::read_at(self, buffer, offset)
        }
        #[cfg(windows)]
        {
            std::os::windows::fs::FileExt::seek_read(self, buffer, offset)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let mut reader = self.try_clone()?;
            reader.seek(SeekFrom::Start(offset))?;
            reader.read(buffer)
        }
    }
}

pub(in crate::engine::durable) enum StoreMetadata {
    Native(std::fs::Metadata),
    Volume(VolumeMetadata),
}

impl StoreMetadata {
    pub(in crate::engine::durable) fn len(&self) -> u64 {
        match self {
            Self::Native(metadata) => metadata.len(),
            Self::Volume(metadata) => metadata.len(),
        }
    }
}

// Tail repair borrows the selected region and propagates the original I/O error.
impl super::frontier::JournalContainer for &VolumeFile {
    type Error = io::Error;

    fn sync_container(&mut self) -> io::Result<()> {
        self.sync_data()
    }
}

impl super::frontier::JournalContainer for VolumeFile {
    type Error = DurableError;

    fn sync_container(&mut self) -> Result<(), DurableError> {
        self.sync_data()
            .map_err(|source| super::io_error("flush volume container", source))
    }
}
