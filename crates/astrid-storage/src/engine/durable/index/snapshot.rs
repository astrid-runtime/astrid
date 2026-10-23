//! Constant-workspace encoding of the existing sorted index snapshot.

use super::super::locations::LocationLookup;
use std::io::{BufWriter, SeekFrom, Write};

use super::super::format::{frame_checksum_hasher, frame_header};
use super::super::{DurableIo, io_error};
use super::{
    DurableError, INDEX_MAGIC, IdentityScheme, IndexState, LOCATION_BYTES, SNAPSHOT_RECORD,
    encode_identity, encode_len, encode_optional_location, encode_scheme,
};

// An I/O coalescing target, not a retention or admission limit. Neither the
// frame format nor the number of historical objects depends on this buffer.
const WRITE_BUFFER_BYTES: usize = 64 * 1024;

pub(super) struct Snapshot<'a> {
    prefix: Vec<u8>,
    objects: &'a dyn LocationLookup,
    scheme: IdentityScheme,
    payload_len: u64,
}

impl<'a> Snapshot<'a> {
    pub(super) fn new<M: LocationLookup>(
        state: &'a IndexState<M>,
        scheme: IdentityScheme,
    ) -> Result<Self, DurableError> {
        let objects = &state.objects;
        let mut prefix = Vec::new();
        prefix.push(SNAPSHOT_RECORD);
        encode_scheme(&mut prefix, scheme);
        prefix.extend_from_slice(&state.arena_len.to_le_bytes());
        encode_optional_location(&mut prefix, state.arena_tail);
        encode_len(&mut prefix, objects.location_count())?;
        let payload_len = objects
            .location_count()
            .checked_mul(LOCATION_BYTES)
            .and_then(|bytes| bytes.checked_add(prefix.len()))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(DurableError::EncodingOverflow)?;
        Ok(Self {
            prefix,
            objects,
            scheme,
            payload_len,
        })
    }

    pub(super) fn append<F: DurableIo>(&self, file: &mut F) -> Result<(), DurableError> {
        // The immutable borrowed map is visited twice: first for the frozen
        // frame checksum, then for emission. No full-map or full-payload copy
        // survives alongside the authoritative in-memory index.
        let mut hasher = frame_checksum_hasher(INDEX_MAGIC, self.payload_len);
        self.visit_payload(|bytes| {
            hasher.update(bytes);
            Ok(())
        })?;
        let header = frame_header(INDEX_MAGIC, self.payload_len, *hasher.finalize().as_bytes());
        file.seek(SeekFrom::End(0))
            .map_err(|source| io_error("seek streamed object-index snapshot", source))?;
        let mut writer = BufWriter::with_capacity(WRITE_BUFFER_BYTES, file);
        writer
            .write_all(&header)
            .map_err(|source| io_error("append streamed object-index header", source))?;
        self.visit_payload(|bytes| {
            writer
                .write_all(bytes)
                .map_err(|source| io_error("append streamed object-index payload", source))
        })?;
        writer
            .flush()
            .map_err(|source| io_error("flush streamed object-index buffer", source))
    }

    fn visit_payload(
        &self,
        mut visit: impl FnMut(&[u8]) -> Result<(), DurableError>,
    ) -> Result<(), DurableError> {
        visit(&self.prefix)?;
        let mut entry = Vec::with_capacity(LOCATION_BYTES);
        for record in self.objects.locations() {
            let (id, location) = record?;
            entry.clear();
            encode_identity(&mut entry, self.scheme, id);
            entry.extend_from_slice(&location.offset.to_le_bytes());
            entry.extend_from_slice(&location.payload_len.to_le_bytes());
            entry.extend_from_slice(&location.checksum);
            visit(&entry)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
