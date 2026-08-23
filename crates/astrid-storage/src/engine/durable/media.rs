//! Native-file and Astrid-volume byte streams used by the durable engine.
//!
//! Framing stays generic over this interface so the frozen store format is
//! independent of whichever media provider owns the bytes.

use std::fs::File as NativeFile;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::Arc;

use crate::volume::{AstridVolume, VolumeFile, VolumeMetadata, VolumeRegion};

use super::DurableError;

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
#[derive(Debug)]
pub(in crate::engine::durable) enum File {
    Native(NativeFile),
    Volume(VolumeFile),
}

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
    fn durable_read_at(&self, buffer: &mut [u8], offset: u64) -> io::Result<usize>;
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
            // ASTVOL1 durability is one container fsync via AstridVolume::sync.
            Self::Volume(_) => Ok(()),
        }
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
    fn durable_metadata(&self) -> io::Result<StoreMetadata> {
        self.metadata()
    }

    fn durable_set_len(&self, length: u64) -> io::Result<()> {
        self.set_len(length)
    }

    fn durable_sync_data(&self) -> io::Result<()> {
        self.sync_data()
    }

    fn durable_read_at(&self, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
        self.read_at(buffer, offset)
    }
}

impl DurableIo for NativeFile {
    fn durable_metadata(&self) -> io::Result<StoreMetadata> {
        self.metadata().map(StoreMetadata::Native)
    }

    fn durable_set_len(&self, length: u64) -> io::Result<()> {
        self.set_len(length)
    }

    fn durable_sync_data(&self) -> io::Result<()> {
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
