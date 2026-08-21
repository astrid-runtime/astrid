//! Astrid-owned durable volume boundary.
//!
//! The storage engine addresses validated regions inside one volume. Hosted
//! systems may realize that volume as one container file; bare-metal systems
//! can implement the same contract directly over a block device. Neither the
//! logical store nor callers derive authority from host paths.

use std::fmt;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::Arc;

#[cfg(not(target_family = "wasm"))]
mod hosted;

#[cfg(not(target_family = "wasm"))]
pub use hosted::HostedFileVolume;

#[cfg(all(test, not(target_family = "wasm")))]
pub(crate) use hosted::write_record_payloads;

const MAX_REGION_NAME_BYTES: usize = 512;

/// Validated, portable name of one byte-addressable volume region.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VolumeRegion(String);

impl VolumeRegion {
    /// Construct a portable region name.
    ///
    /// # Errors
    ///
    /// Rejects empty names, absolute names, traversal, empty components,
    /// backslashes, control characters, and names beyond the format limit.
    pub fn new(name: impl Into<String>) -> io::Result<Self> {
        let name = name.into();
        if name.is_empty()
            || name.len() > MAX_REGION_NAME_BYTES
            || name.starts_with('/')
            || name.ends_with('/')
            || name.contains('\\')
            || name.chars().any(char::is_control)
            || name
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid Astrid volume region name {name:?}"),
            ));
        }
        Ok(Self(name))
    }

    /// Borrow the canonical UTF-8 region name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One path-free namespace mutation committed as part of a volume transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VolumeMetadataMutation {
    /// Move `source` to an absent `destination`.
    Rename {
        /// Existing region to move.
        source: VolumeRegion,
        /// Absent name that becomes current.
        destination: VolumeRegion,
    },
    /// Move `source` over an existing `destination`.
    Replace {
        /// Existing prepared region to move.
        source: VolumeRegion,
        /// Existing current name to replace.
        destination: VolumeRegion,
    },
}

/// Minimal durable media contract required by the Astrid store.
///
/// Implementations must serialize mutations, preserve exact byte offsets, and
/// make all preceding mutations durable when [`Self::sync`] succeeds.
pub trait AstridVolume: fmt::Debug + Send + Sync {
    /// Ensure a region exists, optionally rejecting an existing region.
    ///
    /// # Errors
    ///
    /// Returns an I/O or namespace-transition error.
    fn create_region(&self, region: &VolumeRegion, create_new: bool) -> io::Result<()>;

    /// Return whether a region exists.
    ///
    /// # Errors
    ///
    /// Returns an underlying media error.
    fn region_exists(&self, region: &VolumeRegion) -> io::Result<bool>;

    /// Return the current logical region length.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` or an underlying media error.
    fn region_len(&self, region: &VolumeRegion) -> io::Result<u64>;

    /// Read bytes at an exact logical offset.
    ///
    /// # Errors
    ///
    /// Returns `NotFound`, an overflow error, or an underlying media error.
    fn read_region_at(
        &self,
        region: &VolumeRegion,
        offset: u64,
        buffer: &mut [u8],
    ) -> io::Result<usize>;

    /// Write `payload_len` bytes from `payload` at an exact logical offset.
    ///
    /// This is the payload write. Hosted ASTVOL2 persists it as one `Write`
    /// record of that length. Stream; do not assemble `payload_len` in RAM
    /// solely to call this.
    ///
    /// # Errors
    ///
    /// Returns `NotFound`, `UnexpectedEof` when the source ends early, an
    /// overflow error, or an underlying media error.
    fn write_region_from(
        &self,
        region: &VolumeRegion,
        offset: u64,
        payload_len: u64,
        payload: &mut dyn Read,
    ) -> io::Result<()>;

    /// Write all bytes at an exact logical offset.
    ///
    /// Slice form of [`Self::write_region_from`]. Not a second installer.
    ///
    /// # Errors
    ///
    /// Returns `NotFound`, an overflow error, or an underlying media error.
    fn write_region_at(&self, region: &VolumeRegion, offset: u64, bytes: &[u8]) -> io::Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        self.write_region_from(
            region,
            offset,
            u64::try_from(bytes.len())
                .map_err(|_| io::Error::other("volume write length overflow"))?,
            &mut &bytes[..],
        )
    }

    /// Set a region's logical length.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` or an underlying media error.
    fn set_region_len(&self, region: &VolumeRegion, length: u64) -> io::Result<()>;

    /// Remove one region.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` or an underlying media error.
    fn remove_region(&self, region: &VolumeRegion) -> io::Result<()>;

    /// Atomically rename a region without replacing an existing destination.
    ///
    /// # Errors
    ///
    /// Returns a namespace-transition or underlying media error.
    fn rename_region(&self, source: &VolumeRegion, destination: &VolumeRegion) -> io::Result<()>;

    /// Atomically replace an existing destination with a prepared source.
    ///
    /// Bare-metal providers implement this as one journaled metadata commit;
    /// hosted volumes encode it as one checksummed container record.
    ///
    /// # Errors
    ///
    /// Returns a namespace-transition or underlying media error.
    fn replace_region(&self, source: &VolumeRegion, destination: &VolumeRegion) -> io::Result<()>;

    /// Atomically commit a non-empty sequence of namespace mutations.
    ///
    /// No mutation may be externally observable unless the complete sequence
    /// is recoverable. This is the bare-metal transaction boundary used when
    /// a physical store generation and its audit receipt must become current
    /// together.
    ///
    /// # Errors
    ///
    /// Returns an invalid transaction, namespace-transition, or media error.
    fn commit_metadata(&self, mutations: &[VolumeMetadataMutation]) -> io::Result<()>;

    /// Enumerate regions beneath a canonical prefix.
    ///
    /// # Errors
    ///
    /// Returns an underlying media error.
    fn list_regions(&self, prefix: &str) -> io::Result<Vec<VolumeRegion>>;

    /// Return currently available physical bytes for a replacement rewrite.
    ///
    /// Hosted adapters derive this from the containing filesystem. Bare-metal
    /// adapters should report the media allocator's native free-byte value;
    /// returning `None` means capacity is not observable and callers must fail
    /// closed before a destructive rewrite rather than guessing from a host
    /// path.
    ///
    /// # Errors
    ///
    /// Returns an underlying media-capacity error.
    fn available_space(&self) -> io::Result<Option<u64>> {
        Ok(None)
    }

    /// Physically reclaim obsolete container extents after a logical rewrite.
    ///
    /// The operation is invoked only after the replacement namespace and its
    /// evidence are durable. Implementations must use their own crash-safe
    /// media transaction; the default rejects backends that cannot provide a
    /// reclaim boundary, so callers never mistake logical reachability for
    /// physical reclamation.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::Unsupported`] when the backend has no safe
    /// reclaim primitive, or an underlying media error.
    fn reclaim(&self) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "volume backend does not provide physical reclamation",
        ))
    }

    /// Flush all preceding volume mutations to durable media.
    ///
    /// # Errors
    ///
    /// Returns an underlying durability-barrier error.
    fn sync(&self) -> io::Result<()>;
}

/// Seekable handle to one region in an [`AstridVolume`].
#[derive(Clone)]
pub struct VolumeFile {
    volume: Arc<dyn AstridVolume>,
    region: VolumeRegion,
    cursor: u64,
}

impl fmt::Debug for VolumeFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VolumeFile")
            .field("region", &self.region)
            .field("cursor", &self.cursor)
            .finish_non_exhaustive()
    }
}

impl VolumeFile {
    /// Open or create a volume region.
    ///
    /// # Errors
    ///
    /// Returns a namespace or underlying volume error.
    pub fn open(
        volume: Arc<dyn AstridVolume>,
        region: VolumeRegion,
        create: bool,
    ) -> io::Result<Self> {
        if create {
            volume.create_region(&region, false)?;
        } else if !volume.region_exists(&region)? {
            return Err(io::Error::new(io::ErrorKind::NotFound, region.as_str()));
        }
        Ok(Self {
            volume,
            region,
            cursor: 0,
        })
    }

    /// Exclusively create a new region.
    ///
    /// # Errors
    ///
    /// Returns `AlreadyExists` or an underlying volume error.
    pub fn create_new(volume: Arc<dyn AstridVolume>, region: VolumeRegion) -> io::Result<Self> {
        volume.create_region(&region, true)?;
        Ok(Self {
            volume,
            region,
            cursor: 0,
        })
    }

    /// Clone this handle with an independent cursor.
    ///
    /// # Errors
    ///
    /// Reserved for volume implementations that cannot clone a handle.
    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(self.clone())
    }

    /// Flush the complete containing volume.
    ///
    /// # Errors
    ///
    /// Returns an underlying durability-barrier error.
    pub fn sync_all(&self) -> io::Result<()> {
        self.volume.sync()
    }

    /// Flush the complete containing volume.
    ///
    /// # Errors
    ///
    /// Returns an underlying durability-barrier error.
    pub fn sync_data(&self) -> io::Result<()> {
        self.volume.sync()
    }

    /// Set the logical region length.
    ///
    /// # Errors
    ///
    /// Returns an underlying volume error.
    pub fn set_len(&self, length: u64) -> io::Result<()> {
        self.volume.set_region_len(&self.region, length)
    }

    /// Return lightweight region metadata.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` or an underlying volume error.
    pub fn metadata(&self) -> io::Result<VolumeMetadata> {
        Ok(VolumeMetadata {
            length: self.volume.region_len(&self.region)?,
        })
    }

    /// Read from an exact offset without changing the cursor.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` or an underlying volume error.
    pub fn read_at(&self, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
        self.volume.read_region_at(&self.region, offset, buffer)
    }

    /// Borrow this handle's region name.
    #[must_use]
    pub fn region(&self) -> &VolumeRegion {
        &self.region
    }
}

impl Read for VolumeFile {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self
            .volume
            .read_region_at(&self.region, self.cursor, buffer)?;
        self.cursor = self
            .cursor
            .checked_add(read as u64)
            .ok_or_else(|| io::Error::other("volume cursor overflow"))?;
        Ok(read)
    }
}

impl Write for VolumeFile {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.volume
            .write_region_at(&self.region, self.cursor, bytes)?;
        self.cursor = self
            .cursor
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| io::Error::other("volume cursor overflow"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.volume.sync()
    }
}

impl Seek for VolumeFile {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let next = match position {
            SeekFrom::Start(offset) => i128::from(offset),
            SeekFrom::Current(delta) => i128::from(self.cursor)
                .checked_add(i128::from(delta))
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "volume seek overflow")
                })?,
            SeekFrom::End(delta) => i128::from(self.volume.region_len(&self.region)?)
                .checked_add(i128::from(delta))
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "volume seek overflow")
                })?,
        };
        self.cursor = u64::try_from(next)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "negative volume seek"))?;
        Ok(self.cursor)
    }
}

/// Minimal metadata returned for a volume region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VolumeMetadata {
    length: u64,
}

impl VolumeMetadata {
    /// Return the logical byte length.
    #[must_use]
    pub const fn len(self) -> u64 {
        self.length
    }

    /// A volume region is always a regular byte stream.
    #[must_use]
    pub const fn is_file(self) -> bool {
        true
    }

    /// Return whether the region is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.length == 0
    }
}
