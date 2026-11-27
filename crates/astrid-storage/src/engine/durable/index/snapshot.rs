//! Constant-workspace encoding of the existing sorted index snapshot.

use std::borrow::Borrow;
use std::collections::{BTreeMap, btree_map};
use std::io::{self, Cursor, Read, SeekFrom};

use super::super::format::{frame_checksum_hasher, frame_header};
use super::super::{DurableIo, io_error};
use super::{
    ArenaLocation, DurableError, INDEX_MAGIC, IdentityScheme, IndexState, LOCATION_BYTES, ObjectId,
    SNAPSHOT_RECORD, encode_identity, encode_len, encode_optional_location, encode_scheme,
};

pub(super) struct Snapshot<'a> {
    prefix: Vec<u8>,
    objects: &'a BTreeMap<ObjectId, ArenaLocation>,
    scheme: IdentityScheme,
    payload_len: u64,
}

impl<'a> Snapshot<'a> {
    pub(super) fn new<M: Borrow<BTreeMap<ObjectId, ArenaLocation>>>(
        state: &'a IndexState<M>,
        scheme: IdentityScheme,
    ) -> Result<Self, DurableError> {
        let objects = state.objects.borrow();
        let mut prefix = Vec::new();
        prefix.push(SNAPSHOT_RECORD);
        encode_scheme(&mut prefix, scheme);
        prefix.extend_from_slice(&state.arena_len.to_le_bytes());
        encode_optional_location(&mut prefix, state.arena_tail);
        encode_len(&mut prefix, objects.len())?;
        let payload_len = objects
            .len()
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
        let payload_bytes = io::copy(&mut self.payload_reader(), &mut hasher)
            .map_err(|source| io_error("hash streamed object-index snapshot", source))?;
        if payload_bytes != self.payload_len {
            return Err(DurableError::InvalidRepresentationState(
                "streamed object-index length differs from its immutable snapshot",
            ));
        }
        let header = frame_header(INDEX_MAGIC, self.payload_len, *hasher.finalize().as_bytes());
        let frame_len = self
            .payload_len
            .checked_add(u64::try_from(header.len()).map_err(|_| DurableError::EncodingOverflow)?)
            .ok_or(DurableError::EncodingOverflow)?;
        let mut reader = Cursor::new(header).chain(self.payload_reader());
        file.seek(SeekFrom::End(0))
            .map_err(|source| io_error("seek streamed object-index snapshot", source))?;
        file.durable_write_from(frame_len, &mut reader)
            .map_err(|source| io_error("append streamed object-index snapshot", source))?;
        // VolumeFile::flush commits the container; its sync_data adapter is a
        // no-op. Keep this explicit barrier after the complete streamed frame.
        file.flush()
            .map_err(|source| io_error("flush streamed object-index buffer", source))
    }

    fn payload_reader(&self) -> PayloadReader<'_> {
        PayloadReader {
            prefix: Cursor::new(&self.prefix),
            objects: self.objects.iter(),
            scheme: self.scheme,
            entry: Cursor::new(Vec::with_capacity(LOCATION_BYTES)),
        }
    }
}

struct PayloadReader<'a> {
    prefix: Cursor<&'a [u8]>,
    objects: btree_map::Iter<'a, ObjectId, ArenaLocation>,
    scheme: IdentityScheme,
    entry: Cursor<Vec<u8>>,
}

impl PayloadReader<'_> {
    fn next_entry(&mut self) -> bool {
        let Some((id, location)) = self.objects.next() else {
            return false;
        };
        let entry = self.entry.get_mut();
        entry.clear();
        encode_identity(entry, self.scheme, *id);
        location.encode(entry);
        self.entry.set_position(0);
        true
    }
}

impl Read for PayloadReader<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let mut written = self.prefix.read(bytes)?;
        while written < bytes.len() {
            written = written.strict_add(self.entry.read(&mut bytes[written..])?);
            if written == bytes.len() || !self.next_entry() {
                break;
            }
        }
        Ok(written)
    }
}

#[cfg(test)]
mod tests;
