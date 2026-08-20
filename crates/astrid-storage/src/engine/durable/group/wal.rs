//! Single-sync transaction-WAL publication for a durable commit group.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use crate::engine::ProjectionPhase;
use crate::storage_model::{ModelError, ObjectId, ObjectIdentity};

use super::super::wal::durable_error as wal_durable_error;
use super::super::{
    ARENA_FILE, DurableEngine, DurableError, DurableInner, FaultPoint, Persisted,
    PersistentObjectIdentity, Prepared, PrincipalCodec, WAL_FILE, decode_object_frame,
    encode_object_frame, io_error, live_files_mut, read_indexed_object,
};
use super::{AcceptedCommit, record_group};

impl<P, I, C> DurableEngine<P, I, C>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    pub(super) fn seed_pending_wal_frames(
        wal_enabled: bool,
        inner: &DurableInner<P>,
        pending: &mut BTreeMap<ObjectId, Arc<[u8]>>,
    ) {
        if wal_enabled {
            pending.extend(
                inner
                    .pending_wal
                    .objects()
                    .map(|(id, object)| (*id, object.payload_arc())),
            );
        }
    }

    pub(super) fn advance_wal_arena_frontier(
        inner: &mut DurableInner<P>,
        arena_len: u64,
    ) -> Result<(), DurableError> {
        let arena_tail = inner
            .pending_index_locations
            .last()
            .map(|(_, location)| *location);
        let files = live_files_mut(&mut inner.files)?;
        if arena_len < files.arena_len {
            return Err(DurableError::Corrupt {
                file: ARENA_FILE,
                offset: arena_len,
                detail: "object arena moved behind the cached WAL frontier",
            });
        }
        if arena_len > files.arena_len {
            files.arena_len = arena_len;
            if arena_tail.is_some() {
                files.arena_tail = arena_tail;
            }
        }
        Ok(())
    }

    pub(super) fn maybe_checkpoint_transaction_wal(
        &self,
        inner: &mut DurableInner<P>,
    ) -> Result<(), DurableError> {
        let Some(limit) = self.transaction_wal.checkpoint_bytes() else {
            return Ok(());
        };
        let current_len = {
            let mut wal = self.wal.lock();
            let writer = wal.as_mut().ok_or(DurableError::Closed)?;
            writer.current_len().map_err(wal_durable_error)?
        };
        if current_len >= limit.get() {
            self.checkpoint_transaction_wal(inner)?;
        }
        Ok(())
    }

    pub(super) fn persist_group_wal(
        &self,
        inner: &mut DurableInner<P>,
        accepted: &[AcceptedCommit<P>],
    ) -> Result<Persisted, DurableError> {
        let durable_frontier = live_files_mut(&mut inner.files)?.arena_len;
        let staged = self.collect_unsynced_staged(inner, durable_frontier)?;
        let prepared = accepted
            .iter()
            .map(|accepted| Self::collect_prepared_wal_objects(&accepted.prepared))
            .collect::<Result<Vec<_>, _>>()?;
        self.append_wal_transactions(accepted, &staged, &prepared)?;
        self.fail_if(FaultPoint::AfterWalPublication)?;
        self.install_wal_overlay(inner, accepted, &staged, &prepared)?;
        let arena_len = live_files_mut(&mut inner.files)?
            .arena
            .metadata()
            .map_err(|source| io_error("read WAL staged arena metadata", source))?
            .len();
        Ok(Persisted {
            locations: Vec::new(),
            arena_len,
        })
    }

    fn install_wal_overlay(
        &self,
        inner: &mut DurableInner<P>,
        accepted: &[AcceptedCommit<P>],
        staged: &BTreeMap<ObjectId, crate::storage_model::ObjectRecord>,
        prepared: &[BTreeMap<ObjectId, Arc<[u8]>>],
    ) -> Result<(), DurableError> {
        for (id, record) in staged {
            let location = inner.index.get(id).copied().ok_or(DurableError::Corrupt {
                file: ARENA_FILE,
                offset: 0,
                detail: "WAL staged object is missing its arena location",
            })?;
            let payload: Arc<[u8]> =
                encode_object_frame(self.identity.scheme(), *id, record)?.into();
            inner.pending_wal.insert_staged(
                *id,
                payload,
                Arc::new(record.clone()),
                location,
                inner.pending_direct_objects.get(id).cloned(),
            )?;
        }
        for objects in prepared {
            for (id, payload) in objects {
                let (decoded_id, record) = decode_object_frame(payload, self.identity.scheme())
                    .map_err(|detail| DurableError::Corrupt {
                        file: WAL_FILE,
                        offset: 0,
                        detail,
                    })?;
                if decoded_id != *id || self.identity.identify(&record) != *id {
                    return Err(DurableError::Corrupt {
                        file: WAL_FILE,
                        offset: 0,
                        detail: "WAL overlay object identity mismatch",
                    });
                }
                inner
                    .pending_wal
                    .insert_prepared(*id, Arc::clone(payload), Arc::new(record))?;
            }
        }
        for accepted in accepted {
            inner.pending_wal.push_root(
                accepted.prepared.principal.clone(),
                accepted.prepared.expected,
                accepted.prepared.root,
                accepted.prepared.journal.clone(),
            );
        }
        Ok(())
    }

    fn append_wal_transactions(
        &self,
        accepted: &[AcceptedCommit<P>],
        staged: &BTreeMap<ObjectId, crate::storage_model::ObjectRecord>,
        prepared: &[BTreeMap<ObjectId, Arc<[u8]>>],
    ) -> Result<(), DurableError> {
        let mut wal = self.wal.lock();
        let writer = wal.as_mut().ok_or(DurableError::Closed)?;
        for (position, accepted) in accepted.iter().enumerate() {
            let sequence = writer.next_sequence().map_err(wal_durable_error)?;
            writer.begin(sequence, None).map_err(wal_durable_error)?;
            if position == 0 {
                let mut staged = staged.iter().peekable();
                let mut prepared = prepared[position].iter().peekable();
                loop {
                    match (staged.peek(), prepared.peek()) {
                        (Some((staged_id, staged_record)), Some((prepared_id, frame))) => {
                            match staged_id.cmp(prepared_id) {
                                std::cmp::Ordering::Less => {
                                    writer
                                        .append_object(**staged_id, staged_record)
                                        .map_err(wal_durable_error)?;
                                    staged.next();
                                },
                                std::cmp::Ordering::Greater => {
                                    writer
                                        .append_prepared_object(**prepared_id, frame)
                                        .map_err(wal_durable_error)?;
                                    prepared.next();
                                },
                                std::cmp::Ordering::Equal => {
                                    let (_, decoded) =
                                        decode_object_frame(frame, self.identity.scheme())
                                            .map_err(|detail| DurableError::Corrupt {
                                                file: ARENA_FILE,
                                                offset: 0,
                                                detail,
                                            })?;
                                    if decoded != **staged_record {
                                        return Err(ModelError::ObjectCollision(**staged_id).into());
                                    }
                                    writer
                                        .append_prepared_object(**prepared_id, frame)
                                        .map_err(wal_durable_error)?;
                                    staged.next();
                                    prepared.next();
                                },
                            }
                        },
                        (Some((id, record)), None) => {
                            writer
                                .append_object(**id, record)
                                .map_err(wal_durable_error)?;
                            staged.next();
                        },
                        (None, Some((id, frame))) => {
                            writer
                                .append_prepared_object(**id, frame)
                                .map_err(wal_durable_error)?;
                            prepared.next();
                        },
                        (None, None) => break,
                    }
                }
            } else {
                for (id, frame) in &prepared[position] {
                    writer
                        .append_prepared_object(*id, frame)
                        .map_err(wal_durable_error)?;
                }
            }
            writer
                .append_root(
                    &accepted.prepared.principal,
                    accepted.prepared.expected,
                    accepted.prepared.root,
                )
                .map_err(wal_durable_error)?;
            writer.finish_commit().map_err(wal_durable_error)?;
        }
        let flush_started = Instant::now();
        writer.publish().map_err(wal_durable_error)?;
        record_group(accepted, ProjectionPhase::Flush, flush_started);
        Ok(())
    }

    fn collect_unsynced_staged(
        &self,
        inner: &mut DurableInner<P>,
        durable_frontier: u64,
    ) -> Result<BTreeMap<ObjectId, crate::storage_model::ObjectRecord>, DurableError> {
        let pending = inner
            .pending_index_locations
            .iter()
            .copied()
            .filter(|(id, location)| {
                location.offset >= durable_frontier && !inner.pending_wal.contains_object(id)
            })
            .collect::<Vec<_>>();
        let files = live_files_mut(&mut inner.files)?;
        let mut records = BTreeMap::new();
        for (id, location) in pending {
            let record =
                read_indexed_object(&files.arena, id, location, &self.identity, self.limits)?;
            insert_wal_object(&mut records, id, record)?;
        }
        Ok(records)
    }

    fn collect_prepared_wal_objects(
        prepared: &Prepared<P>,
    ) -> Result<BTreeMap<ObjectId, Arc<[u8]>>, DurableError> {
        let mut records = BTreeMap::new();
        for (id, payload) in prepared.objects.iter().chain(prepared.commit.iter()) {
            match records.entry(*id) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(Arc::clone(payload));
                },
                std::collections::btree_map::Entry::Occupied(entry)
                    if entry.get().as_ref() == payload.as_ref() => {},
                std::collections::btree_map::Entry::Occupied(_) => {
                    return Err(ModelError::ObjectCollision(*id).into());
                },
            }
        }
        Ok(records)
    }
}

fn insert_wal_object(
    records: &mut BTreeMap<ObjectId, crate::storage_model::ObjectRecord>,
    id: ObjectId,
    record: crate::storage_model::ObjectRecord,
) -> Result<(), DurableError> {
    match records.entry(id) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(record);
            Ok(())
        },
        std::collections::btree_map::Entry::Occupied(entry) if entry.get() == &record => Ok(()),
        std::collections::btree_map::Entry::Occupied(_) => {
            Err(ModelError::ObjectCollision(id).into())
        },
    }
}
