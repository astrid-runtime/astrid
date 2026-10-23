//! Stream canonical metadata through a private spool into one media write.
//!
//! A volume holds its mutation lock while consuming a source. Spooling first
//! avoids reading that same volume under its write lock, bounds resident frame
//! workspace, and prevents one journal extent per frame header and payload.

use std::io::{Read, Seek, SeekFrom};

use super::cold::ColdNodes;
use super::format::{METADATA_FILE, METADATA_MAGIC, MetadataFrame, MetadataKind};
use super::{DurableError, DurableFile, RecoveryLimits, append_frame, io_error};
use crate::storage_model::PhysicalMapNodeId;

pub(super) struct MetadataBatch {
    spool: DurableFile,
    limits: RecoveryLimits,
}

impl MetadataBatch {
    pub(super) fn new(limits: RecoveryLimits) -> Result<Self, DurableError> {
        Ok(Self {
            limits,
            spool: DurableFile::native(
                tempfile::tempfile()
                    .map_err(|error| io_error("create metadata batch spool", error))?,
            ),
        })
    }

    pub(super) fn push(&mut self, frame: &MetadataFrame) -> Result<(), DurableError> {
        let payload = frame.encode()?;
        super::super::ensure_payload_limit(METADATA_FILE, 0, payload.len(), self.limits)?;
        append_frame(&mut self.spool, METADATA_MAGIC, &payload)?;
        Ok(())
    }

    pub(super) fn append_to(&mut self, destination: &mut DurableFile) -> Result<u64, DurableError> {
        let length = self
            .spool
            .metadata()
            .map_err(|error| io_error("measure metadata batch spool", error))?
            .len();
        self.spool
            .seek(SeekFrom::Start(0))
            .map_err(|error| io_error("rewind metadata batch spool", error))?;
        let base = destination
            .seek(SeekFrom::End(0))
            .map_err(|error| io_error("seek metadata batch append", error))?;
        match destination {
            DurableFile::Native(file) => {
                let copied = std::io::copy(&mut Read::take(&mut self.spool, length), file)
                    .map_err(|error| io_error("append native metadata batch", error))?;
                if copied != length {
                    return Err(DurableError::InvalidRepresentationState(
                        "metadata spool ended before its declared length",
                    ));
                }
            },
            DurableFile::Volume(file) => file
                .write_from(length, &mut self.spool)
                .map_err(|error| io_error("append streamed volume metadata batch", error))?,
        }
        Ok(base)
    }

    pub(super) fn promote_nodes(
        &mut self,
        nodes: &ColdNodes,
        base: u64,
        limits: RecoveryLimits,
    ) -> Result<(), DurableError> {
        super::super::scan_frames(
            &mut self.spool,
            METADATA_FILE,
            METADATA_MAGIC,
            limits,
            |offset, payload| {
                let frame = MetadataFrame::decode(payload)?;
                if frame.kind == MetadataKind::MapNode {
                    let payload_len =
                        u64::try_from(payload.len()).map_err(|_| DurableError::EncodingOverflow)?;
                    nodes.promote(
                        PhysicalMapNodeId::new(frame.identity),
                        super::ArenaLocation {
                            offset: base
                                .checked_add(offset)
                                .ok_or(DurableError::EncodingOverflow)?,
                            payload_len,
                            checksum: super::super::format::frame_checksum(
                                METADATA_MAGIC,
                                payload_len,
                                payload,
                            ),
                        },
                    )?;
                }
                Ok(())
            },
        )
    }
}

#[cfg(test)]
mod tests;
