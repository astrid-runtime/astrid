//! Page I/O uses the container's existing append and checksum authority.

use std::fs::File;
use std::io;

use super::super::{ContainerState, HostedFileVolume, Operation, VolumeRegion, recover};
use super::INDEX_PAGE_REGION;
use super::codec::Page;
use super::reference::{PageRef, RecordOffset, RecordSequence};
use super::traversal::PageReader;

pub(in crate::volume::hosted) struct RecordReader<'a> {
    pub(in crate::volume::hosted) file: &'a File,
    pub(in crate::volume::hosted) published_before: RecordOffset,
    pub(in crate::volume::hosted) commit_sequence: RecordSequence,
}

impl PageReader for RecordReader<'_> {
    fn read_page(&self, reference: PageRef) -> io::Result<Page> {
        recover::read_index_page(
            self.file,
            reference,
            self.published_before,
            self.commit_sequence,
        )
    }
}

impl<'a> RecordReader<'a> {
    /// The root was already bound to its publishing commit during recovery.
    /// Narrow subsequent reads to that immutable record and its predecessors.
    pub(in crate::volume::hosted) fn for_root(file: &'a File, root: PageRef) -> io::Result<Self> {
        let end = root
            .offset()
            .get()
            .checked_add(super::INDEX_PAGE_RECORD_BYTES)
            .ok_or_else(|| io::Error::other("extent-index root record end overflow"))?;
        let sequence = root
            .sequence()
            .get()
            .checked_add(1)
            .ok_or_else(|| io::Error::other("extent-index root sequence exhausted"))?;
        Ok(Self {
            file,
            published_before: RecordOffset::new(end)?,
            commit_sequence: RecordSequence::new(sequence)?,
        })
    }
}

pub(in crate::volume::hosted) fn append_page(
    state: &mut ContainerState,
    page: &Page,
) -> io::Result<PageRef> {
    let offset = RecordOffset::new(state.valid_len)?;
    let sequence = state
        .sequence
        .checked_add(1)
        .ok_or_else(|| io::Error::other("Astrid volume sequence exhausted"))?;
    let sequence = RecordSequence::new(sequence)?;
    // Validate child/data bounds before mutating the file. Only the checksum
    // is unknown here; append_record returns the one actually written.
    page.reference(offset, sequence, [0; 32])?;
    let payload = page.encode()?;
    let region = VolumeRegion::new(INDEX_PAGE_REGION)?;
    let record =
        HostedFileVolume::append_record(state, Operation::IndexPage, &region, 0, &payload)?;
    page.reference(offset, sequence, record.checksum)
}

#[cfg(test)]
#[path = "records_tests.rs"]
mod tests;
