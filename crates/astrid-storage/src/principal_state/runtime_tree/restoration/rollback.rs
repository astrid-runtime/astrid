//! One private anonymous scratch file for prior host generations.
//!
//! Bytes are needed only for rollback in this process. Crash recovery already
//! uses the durable RETIRING volume inventory, so scratch needs neither a named
//! sidecar nor its own durability journal. Scratch allocation uses OS temporary
//! capacity; an I/O or space error fails restoration and rolls back prior writes.

use std::fs::File;
use std::io::{self, Read as _, Seek as _, SeekFrom, Write};
use std::path::Path;

use astrid_core::platform_fs::{
    PrivateFileProjection, PrivateFilePublication, PrivateFileReplacement,
};

/// Opaque byte-offset range in this attempt's sole scratch file.
/// An empty range represents an existing empty generation; None is absence.
#[derive(Debug)]
pub(super) struct PreviousGeneration(Option<std::ops::Range<u64>>);

#[derive(Default)]
pub(super) struct RollbackSpool {
    file: Option<File>,
}

impl RollbackSpool {
    pub(super) fn capture<'a>(
        &mut self,
        projection: &'a PrivateFileProjection,
        relative: &Path,
    ) -> io::Result<(PrivateFileReplacement<'a>, PreviousGeneration)> {
        let start = match self.file.as_mut() {
            Some(file) => file.seek(SeekFrom::End(0))?,
            None => 0,
        };
        let (replacement, length) = projection.capture_replacement(relative, self)?;
        let Some(length) = length else {
            return Ok((replacement, PreviousGeneration(None)));
        };
        let end = start
            .checked_add(length)
            .ok_or_else(|| io::Error::other("rollback scratch offset overflow"))?;
        Ok((replacement, PreviousGeneration(Some(start..end))))
    }

    pub(super) fn restore(
        &mut self,
        projection: &PrivateFileProjection,
        publication: PrivateFilePublication,
        previous: PreviousGeneration,
    ) -> io::Result<()> {
        let Some(span) = previous.0 else {
            return projection.rollback_publication(publication, None);
        };
        if span.is_empty() {
            return projection.rollback_publication(publication, Some((&mut io::empty(), 0)));
        }
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| io::Error::other("rollback scratch bytes are unavailable"))?;
        file.seek(SeekFrom::Start(span.start))?;
        let length = span
            .end
            .checked_sub(span.start)
            .ok_or_else(|| io::Error::other("rollback scratch range is reversed"))?;
        projection.rollback_publication(publication, Some((&mut file.take(length), length)))
    }

    #[cfg(test)]
    pub(super) fn has_scratch_file(&self) -> bool {
        self.file.is_some()
    }
}

impl Write for RollbackSpool {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        if self.file.is_none() {
            // Lazy: allocate only when prior generation bytes actually exist.
            self.file = Some(astrid_core::platform_fs::create_private_scratch_file()?);
        }
        self.file
            .as_mut()
            .ok_or_else(|| io::Error::other("rollback scratch file was not created"))?
            .write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.file.as_mut() {
            Some(file) => file.flush(),
            None => Ok(()),
        }
    }
}
