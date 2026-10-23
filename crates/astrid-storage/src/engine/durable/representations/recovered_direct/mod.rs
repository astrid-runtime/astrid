//! Mount-only authenticated replica stream; released before the engine opens.
use super::{
    ArenaLocation, BTreeMap, DurableError, FRAME_HEADER_LEN, ObjectId, PlacementEntry,
    ReplicaLocator, io_error,
};
use std::fs::File;
use std::io::{BufWriter, Seek, SeekFrom, Write};

mod reader;

#[derive(Debug)]
pub(super) struct RecoveredDirect {
    file: File,
    digest: blake3::Hash,
    bytes: u64,
    groups: u64,
    protected: u64,
}

pub(super) struct Builder {
    file: BufWriter<File>,
    digest: blake3::Hasher,
    bytes: u64,
    groups: u64,
    protected: u64,
}

impl Builder {
    pub(super) fn new() -> Result<Self, DurableError> {
        Ok(Self {
            file: BufWriter::new(
                tempfile::tempfile().map_err(|e| io_error("create recovery replica stream", e))?,
            ),
            digest: blake3::Hasher::new(),
            bytes: 0,
            groups: 0,
            protected: 0,
        })
    }

    pub(super) fn push(
        &mut self,
        object: ObjectId,
        placement: &PlacementEntry,
    ) -> Result<(), DurableError> {
        let count = arena_locations(placement).count();
        if count == 0 {
            return Err(DurableError::InvalidRepresentationState(
                "direct representation has no generation-zero arena placement",
            ));
        }
        self.group(
            object,
            u64::try_from(count).map_err(|_| DurableError::EncodingOverflow)?,
        )?;
        for location in arena_locations(placement) {
            self.location(location)?;
        }
        Ok(())
    }

    fn group(&mut self, object: ObjectId, count: u64) -> Result<(), DurableError> {
        self.write(object.as_bytes())?;
        self.write(&count.to_le_bytes())?;
        self.groups = self
            .groups
            .checked_add(1)
            .ok_or(DurableError::EncodingOverflow)?;
        Ok(())
    }

    fn location(&mut self, location: ArenaLocation) -> Result<(), DurableError> {
        self.write(&location.offset.to_le_bytes())?;
        self.write(&location.payload_len.to_le_bytes())?;
        self.write(&location.checksum)?;
        let end = location
            .offset
            .checked_add(FRAME_HEADER_LEN)
            .and_then(|end| end.checked_add(location.payload_len))
            .ok_or(DurableError::EncodingOverflow)?;
        self.protected = self.protected.max(end);
        Ok(())
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), DurableError> {
        self.file
            .write_all(bytes)
            .map_err(|e| io_error("write recovery replica stream", e))?;
        self.digest.update(bytes);
        self.bytes = self
            .bytes
            .checked_add(u64::try_from(bytes.len()).map_err(|_| DurableError::EncodingOverflow)?)
            .ok_or(DurableError::EncodingOverflow)?;
        Ok(())
    }

    pub(super) fn finish(mut self) -> Result<RecoveredDirect, DurableError> {
        self.file
            .flush()
            .map_err(|e| io_error("flush recovery replica stream", e))?;
        let mut file = self
            .file
            .into_inner()
            .map_err(|e| io_error("finish recovery replica stream", e.into_error()))?;
        file.seek(SeekFrom::Start(0))
            .map_err(|e| io_error("rewind recovery replica stream", e))?;
        Ok(RecoveredDirect {
            file,
            digest: self.digest.finalize(),
            bytes: self.bytes,
            groups: self.groups,
            protected: self.protected,
        })
    }
}

impl RecoveredDirect {
    pub(super) fn protected_len(&self) -> u64 {
        self.protected
    }

    pub(super) fn validate(
        self,
        index: &BTreeMap<ObjectId, ArenaLocation>,
    ) -> Result<(), DurableError> {
        reader::validate(self, index)
    }
}

#[cfg(test)]
mod tests;

pub(super) fn arena_locations(
    placement: &PlacementEntry,
) -> impl Iterator<Item = ArenaLocation> + '_ {
    placement.replicas().iter().filter_map(|replica| {
        if let ReplicaLocator::ArenaFrame {
            arena_generation: 0,
            offset,
            payload_length,
            frame_checksum,
        } = replica.locator()
        {
            Some(ArenaLocation {
                offset,
                payload_len: payload_length,
                checksum: frame_checksum,
            })
        } else {
            None
        }
    })
}
