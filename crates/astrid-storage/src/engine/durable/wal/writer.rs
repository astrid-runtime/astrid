use std::fs::File;
use std::io::{self, BufWriter, Seek, SeekFrom, Write};
use std::marker::PhantomData;

use super::super::format::object_frame_declares_identity;
use super::super::{IdentityScheme, PersistentObjectIdentity, PrincipalCodec};
use crate::storage_model::{ObjectId, ObjectRecord, RootState};

use super::codec::{
    digest_record, digest_record_with_flags, encode_begin_body, encode_commit_body,
    encode_object_body, encode_object_storage_body, encode_physical_record,
    encode_physical_record_with_flags, encode_root_body, finish_digest, logical_record_length,
    new_digest,
};
use super::scan::ScannedWal;
use super::types::{
    WalBeginHints, WalCommitDescriptor, WalCount, WalError, WalLength, WalLimits,
    WalObjectDescriptor, WalOffset, WalOrdinal, WalRecordKind, WalResumeState, WalSequence,
};

/// A stream capable of one explicit durability publication.
pub(crate) trait WalSink: Write + Seek {
    /// Flush all appended WAL bytes to stable storage.
    fn sync_data(&mut self) -> io::Result<()>;

    /// Truncate or extend the sink to an exact validated resume boundary.
    fn set_len(&mut self, len: u64) -> io::Result<()>;
}

impl WalSink for File {
    fn sync_data(&mut self) -> io::Result<()> {
        File::sync_data(self)
    }

    fn set_len(&mut self, len: u64) -> io::Result<()> {
        File::set_len(self, len)
    }
}

impl WalSink for BufWriter<File> {
    fn sync_data(&mut self) -> io::Result<()> {
        self.flush()?;
        self.get_ref().sync_data()
    }

    fn set_len(&mut self, len: u64) -> io::Result<()> {
        self.flush()?;
        self.get_mut().set_len(len)
    }
}

impl WalSink for super::super::File {
    fn sync_data(&mut self) -> io::Result<()> {
        super::super::File::sync_data(self)
    }

    fn set_len(&mut self, len: u64) -> io::Result<()> {
        super::super::File::set_len(self, len)
    }
}

impl WalSink for BufWriter<super::super::File> {
    fn sync_data(&mut self) -> io::Result<()> {
        self.flush()?;
        self.get_ref().sync_data()
    }

    fn set_len(&mut self, len: u64) -> io::Result<()> {
        self.flush()?;
        self.get_mut().set_len(len)
    }
}

/// A streaming ASTWAL2 writer. It retains only the active transaction's
/// counters, order keys, and digest state—not its record payloads.
pub(crate) struct WalWriter<S, I, C, P> {
    sink: S,
    identity: I,
    codec: C,
    limits: WalLimits,
    active: Option<ActiveWrite>,
    last_sequence: Option<WalSequence>,
    append_offset: WalOffset,
    pending_publications: u64,
    poisoned: bool,
    _principal: PhantomData<P>,
}

struct ActiveWrite {
    sequence: WalSequence,
    scheme: IdentityScheme,
    next_ordinal: WalOrdinal,
    object_count: WalCount,
    root_count: WalCount,
    logical_count: WalCount,
    logical_bytes: WalLength,
    digest: blake3::Hasher,
    previous_object: Option<ObjectId>,
    previous_principal: Option<Vec<u8>>,
    saw_root: bool,
}

impl<S, I, C, P> WalWriter<S, I, C, P>
where
    S: WalSink,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    /// Return the next valid transaction sequence for this exact stream.
    pub(in crate::engine::durable) fn next_sequence(&self) -> Result<WalSequence, WalError> {
        match self.last_sequence {
            Some(sequence) => sequence
                .get()
                .checked_add(1)
                .and_then(WalSequence::new)
                .ok_or(WalError::CountOverflow {
                    field: "transaction sequence",
                }),
            None => WalSequence::new(1).ok_or(WalError::CountOverflow {
                field: "transaction sequence",
            }),
        }
    }

    /// Return the current physical WAL length at the append cursor.
    pub(in crate::engine::durable) fn current_len(&mut self) -> Result<u64, WalError> {
        self.ensure_usable()?;
        Ok(self.append_offset.get())
    }

    /// Construct a writer with a per-record recovery bound.
    #[cfg(test)]
    pub(super) fn new(
        mut sink: S,
        identity: I,
        codec: C,
        limits: WalLimits,
    ) -> Result<Self, WalError> {
        let offset = sink.seek(SeekFrom::End(0)).map_err(|source| WalError::Io {
            operation: "seek ASTWAL2 append",
            source,
        })?;
        if offset != 0 {
            return Err(WalError::InvalidTransaction(
                "WAL writer requires an empty sink; use resume",
            ));
        }
        Ok(Self {
            sink,
            identity,
            codec,
            limits,
            active: None,
            last_sequence: None,
            append_offset: WalOffset::new(offset),
            pending_publications: 0,
            poisoned: false,
            _principal: PhantomData,
        })
    }

    fn resume_parts(
        mut sink: S,
        identity: I,
        codec: C,
        limits: WalLimits,
        state: WalResumeState,
    ) -> Result<Self, WalError> {
        let file_len = sink.seek(SeekFrom::End(0)).map_err(|source| WalError::Io {
            operation: "seek ASTWAL2 resume",
            source,
        })?;
        let (append_offset, last_sequence) = state.into_parts();
        let append_offset = append_offset.get();
        if file_len < append_offset {
            return Err(WalError::InvalidTransaction(
                "WAL resume offset is past the sink end",
            ));
        }
        sink.set_len(append_offset).map_err(|source| WalError::Io {
            operation: "truncate ASTWAL2 stale tail",
            source,
        })?;
        sink.seek(SeekFrom::Start(append_offset))
            .map_err(|source| WalError::Io {
                operation: "seek ASTWAL2 resume append",
                source,
            })?;
        Ok(Self {
            sink,
            identity,
            codec,
            limits,
            active: None,
            last_sequence,
            append_offset: WalOffset::new(append_offset),
            pending_publications: 0,
            poisoned: false,
            _principal: PhantomData,
        })
    }

    /// Begin one transaction without syncing.
    pub(in crate::engine::durable) fn begin(
        &mut self,
        sequence: WalSequence,
        hints: Option<WalBeginHints>,
    ) -> Result<(), WalError> {
        self.ensure_usable()?;
        if self.active.is_some() {
            return Err(WalError::InvalidTransaction(
                "WAL transaction is already active",
            ));
        }
        if self.last_sequence.is_some_and(|last| sequence <= last) {
            let previous = match self.last_sequence {
                Some(previous) => previous,
                None => sequence,
            };
            return Err(WalError::SequenceRegression {
                previous,
                current: sequence,
            });
        }
        let scheme = self.identity.scheme();
        let body = encode_begin_body(scheme, hints)?;
        let logical_bytes = logical_record_length(&body)?;
        let mut digest = new_digest();
        digest_record(
            &mut digest,
            WalRecordKind::Begin,
            sequence,
            WalOrdinal::new(0),
            &body,
        )?;
        let encoded = encode_physical_record(
            WalRecordKind::Begin,
            sequence,
            WalOrdinal::new(0),
            &body,
            self.limits,
        )?;
        self.append_encoded(&encoded)?;
        self.active = Some(ActiveWrite {
            sequence,
            scheme,
            next_ordinal: WalOrdinal::new(1),
            object_count: WalCount::new(0),
            root_count: WalCount::new(0),
            logical_count: WalCount::new(1),
            logical_bytes,
            digest,
            previous_object: None,
            previous_principal: None,
            saw_root: false,
        });
        Ok(())
    }

    /// Append one identity-validated canonical object record without syncing.
    pub(in crate::engine::durable) fn append_object(
        &mut self,
        id: ObjectId,
        record: &ObjectRecord,
    ) -> Result<WalObjectDescriptor, WalError> {
        self.ensure_usable()?;
        let scheme = self
            .active
            .as_ref()
            .ok_or(WalError::InvalidTransaction(
                "WAL object requires an active transaction",
            ))?
            .scheme;
        let body = encode_object_body(scheme, id, record, &self.identity)?;
        self.append_object_body(id, &body)
    }

    /// Append an engine-prepared canonical object frame without decoding and
    /// re-encoding its record body. The fixed identity prefix is still checked
    /// at this boundary; the private `Prepared` producer owns full canonical
    /// validation before this method is reachable.
    pub(in crate::engine::durable) fn append_prepared_object(
        &mut self,
        id: ObjectId,
        body: &[u8],
    ) -> Result<WalObjectDescriptor, WalError> {
        self.ensure_usable()?;
        let scheme = self
            .active
            .as_ref()
            .ok_or(WalError::InvalidTransaction(
                "WAL object requires an active transaction",
            ))?
            .scheme;
        if !object_frame_declares_identity(body, scheme, id) {
            return Err(WalError::ObjectIdentityMismatch { object: id });
        }
        self.append_object_body(id, body)
    }

    fn append_object_body(
        &mut self,
        id: ObjectId,
        body: &[u8],
    ) -> Result<WalObjectDescriptor, WalError> {
        super::codec::validate_logical_body(body, self.limits, WalOffset::new(0))?;
        let (sequence, ordinal, previous, saw_root, count, logical) = {
            let active = self.active.as_ref().ok_or(WalError::InvalidTransaction(
                "WAL object requires an active transaction",
            ))?;
            (
                active.sequence,
                active.next_ordinal,
                active.previous_object,
                active.saw_root,
                active.object_count,
                active.logical_bytes,
            )
        };
        if saw_root || previous.is_some_and(|previous| previous >= id) {
            return Err(WalError::OrderingViolation);
        }
        let body_length = WalLength::new(
            u64::try_from(body.len())
                .map_err(|_| WalError::Encoding("WAL object length overflow"))?,
        );
        let (flags, stored_body) = encode_object_storage_body(body)?;
        let next_count = count
            .checked_inc()
            .ok_or(WalError::CountOverflow { field: "objects" })?;
        let logical_record = logical_record_length(&stored_body)?;
        let next_logical = logical
            .checked_add(logical_record)
            .ok_or(WalError::CountOverflow {
                field: "logical bytes",
            })?;
        let next_logical_count = {
            let active = self.active.as_ref().ok_or(WalError::InvalidTransaction(
                "WAL object transaction disappeared",
            ))?;
            active
                .logical_count
                .checked_inc()
                .ok_or(WalError::CountOverflow {
                    field: "logical records",
                })?
        };
        let next_ordinal = ordinal
            .checked_next()
            .ok_or(WalError::CountOverflow { field: "ordinals" })?;
        let encoded = encode_physical_record_with_flags(
            WalRecordKind::Object,
            flags,
            sequence,
            ordinal,
            &stored_body,
            self.limits,
        )?;
        let encoded_length = encoded_length(&encoded)?;
        let mut next_digest = self
            .active
            .as_ref()
            .ok_or(WalError::InvalidTransaction(
                "WAL object transaction disappeared",
            ))?
            .digest
            .clone();
        digest_record_with_flags(
            &mut next_digest,
            WalRecordKind::Object,
            flags,
            sequence,
            ordinal,
            &stored_body,
        )?;
        let offset = self.append_encoded(&encoded)?;
        let active = self.active.as_mut().ok_or(WalError::InvalidTransaction(
            "WAL transaction disappeared while appending object",
        ))?;
        active.object_count = next_count;
        active.logical_bytes = next_logical;
        active.next_ordinal = next_ordinal;
        active.previous_object = Some(id);
        active.digest = next_digest;
        active.logical_count = next_logical_count;
        Ok(WalObjectDescriptor {
            offset,
            length: encoded_length,
            id,
            logical_bytes: body_length,
        })
    }

    /// Append one codec-validated canonical root transition without syncing.
    pub(in crate::engine::durable) fn append_root(
        &mut self,
        principal: &P,
        expected: Option<RootState>,
        replacement: RootState,
    ) -> Result<(), WalError> {
        self.ensure_usable()?;
        let (sequence, ordinal, scheme, previous, count, logical) = {
            let active = self.active.as_ref().ok_or(WalError::InvalidTransaction(
                "WAL root requires an active transaction",
            ))?;
            (
                active.sequence,
                active.next_ordinal,
                active.scheme,
                active.previous_principal.clone(),
                active.root_count,
                active.logical_bytes,
            )
        };
        let (principal_bytes, body) =
            encode_root_body(scheme, principal, expected, replacement, &self.codec)?;
        if previous
            .as_deref()
            .is_some_and(|previous| previous >= principal_bytes.as_slice())
        {
            return Err(WalError::OrderingViolation);
        }
        let next_count = count
            .checked_inc()
            .ok_or(WalError::CountOverflow { field: "roots" })?;
        let logical_record = logical_record_length(&body)?;
        let next_logical = logical
            .checked_add(logical_record)
            .ok_or(WalError::CountOverflow {
                field: "logical bytes",
            })?;
        let next_logical_count = {
            let active = self.active.as_ref().ok_or(WalError::InvalidTransaction(
                "WAL root transaction disappeared",
            ))?;
            active
                .logical_count
                .checked_inc()
                .ok_or(WalError::CountOverflow {
                    field: "logical records",
                })?
        };
        let next_ordinal = ordinal
            .checked_next()
            .ok_or(WalError::CountOverflow { field: "ordinals" })?;
        let encoded =
            encode_physical_record(WalRecordKind::Root, sequence, ordinal, &body, self.limits)?;
        let mut next_digest = self
            .active
            .as_ref()
            .ok_or(WalError::InvalidTransaction(
                "WAL root transaction disappeared",
            ))?
            .digest
            .clone();
        digest_record(
            &mut next_digest,
            WalRecordKind::Root,
            sequence,
            ordinal,
            &body,
        )?;
        self.append_encoded(&encoded)?;
        let active = self.active.as_mut().ok_or(WalError::InvalidTransaction(
            "WAL transaction disappeared while appending root",
        ))?;
        active.root_count = next_count;
        active.logical_bytes = next_logical;
        active.next_ordinal = next_ordinal;
        active.previous_principal = Some(principal_bytes);
        active.saw_root = true;
        active.digest = next_digest;
        active.logical_count = next_logical_count;
        Ok(())
    }

    /// Append Commit and return its descriptor; this never calls `sync_data`.
    pub(in crate::engine::durable) fn finish_commit(
        &mut self,
    ) -> Result<WalCommitDescriptor, WalError> {
        self.ensure_usable()?;
        let (
            sequence,
            logical_count,
            object_count,
            root_count,
            logical_bytes,
            digest_state,
            ordinal,
        ) = {
            let active = self.active.as_ref().ok_or(WalError::InvalidTransaction(
                "WAL Commit requires an active transaction",
            ))?;
            if !active.saw_root {
                return Err(WalError::ZeroRoots);
            }
            (
                active.sequence,
                active.logical_count,
                active.object_count,
                active.root_count,
                active.logical_bytes,
                active.digest.clone(),
                active.next_ordinal,
            )
        };
        let next_pending =
            self.pending_publications
                .checked_add(1)
                .ok_or(WalError::CountOverflow {
                    field: "pending publications",
                })?;
        let digest = finish_digest(&digest_state);
        let body = encode_commit_body(
            sequence,
            logical_count,
            object_count,
            root_count,
            logical_bytes,
            digest,
        );
        let encoded =
            encode_physical_record(WalRecordKind::Commit, sequence, ordinal, &body, self.limits)?;
        let encoded_length = encoded_length(&encoded)?;
        let offset = self.append_encoded(&encoded)?;
        let descriptor = WalCommitDescriptor {
            offset,
            length: encoded_length,
            sequence,
            logical_count,
            object_count,
            root_count,
            logical_bytes,
            digest,
        };
        self.last_sequence = Some(sequence);
        self.pending_publications = next_pending;
        self.active = None;
        Ok(descriptor)
    }

    /// Sync all complete transactions appended since the previous publication.
    pub(in crate::engine::durable) fn publish(&mut self) -> Result<u64, WalError> {
        self.ensure_usable()?;
        if self.active.is_some() {
            return Err(WalError::InvalidTransaction(
                "cannot publish an active transaction",
            ));
        }
        if self.pending_publications == 0 {
            return Err(WalError::InvalidTransaction(
                "no complete transaction is pending publication",
            ));
        }
        if let Err(source) = self.sink.sync_data() {
            self.poisoned = true;
            return Err(WalError::Io {
                operation: "sync ASTWAL2 publication",
                source,
            });
        }
        let published = self.pending_publications;
        self.pending_publications = 0;
        Ok(published)
    }

    /// Retire every committed WAL record after the canonical arena, root
    /// journal, and representation files are durable.
    pub(in crate::engine::durable) fn checkpoint(&mut self) -> Result<(), WalError> {
        self.ensure_usable()?;
        if self.active.is_some() || self.pending_publications != 0 {
            return Err(WalError::InvalidTransaction(
                "cannot checkpoint an active or unpublished WAL transaction",
            ));
        }
        if let Err(source) = self.sink.set_len(0) {
            self.poisoned = true;
            return Err(WalError::Io {
                operation: "truncate ASTWAL2 checkpoint",
                source,
            });
        }
        if let Err(source) = self.sink.seek(SeekFrom::Start(0)) {
            self.poisoned = true;
            return Err(WalError::Io {
                operation: "seek ASTWAL2 checkpoint",
                source,
            });
        }
        if let Err(source) = self.sink.sync_data() {
            self.poisoned = true;
            return Err(WalError::Io {
                operation: "sync ASTWAL2 checkpoint",
                source,
            });
        }
        self.last_sequence = None;
        self.append_offset = WalOffset::new(0);
        Ok(())
    }

    /// Return the number of complete transactions awaiting publication.
    #[cfg(test)]
    pub(super) const fn pending_publications(&self) -> u64 {
        self.pending_publications
    }

    /// Return the sink after the caller has finished writing.
    #[cfg(test)]
    pub(super) fn into_inner(self) -> S {
        self.sink
    }

    fn append_encoded(&mut self, encoded: &[u8]) -> Result<WalOffset, WalError> {
        let offset = self.append_offset;
        let encoded_length = encoded_length(encoded)?;
        let next_offset = offset
            .checked_add(encoded_length)
            .ok_or(WalError::CountOverflow {
                field: "WAL append offset",
            })?;
        if let Err(source) = self.sink.write_all(encoded) {
            self.poisoned = true;
            return Err(WalError::Io {
                operation: "append ASTWAL2 record",
                source,
            });
        }
        self.append_offset = next_offset;
        Ok(offset)
    }

    fn ensure_usable(&self) -> Result<(), WalError> {
        if self.poisoned {
            Err(WalError::InvalidTransaction("WAL writer is poisoned"))
        } else {
            Ok(())
        }
    }
}

impl<S, I, C, P> ScannedWal<S, I, C, P>
where
    S: WalSink,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    /// Resume on the exact reader that produced this scanner state.
    pub(super) fn into_writer(self, limits: WalLimits) -> Result<WalWriter<S, I, C, P>, WalError> {
        let (sink, identity, codec, state) = self.into_parts();
        WalWriter::resume_parts(sink, identity, codec, limits, state)
    }
}

fn encoded_length(encoded: &[u8]) -> Result<WalLength, WalError> {
    u64::try_from(encoded.len())
        .map(WalLength::new)
        .map_err(|_| WalError::Encoding("WAL physical length overflow"))
}
