//! Single-sync transaction-WAL publication for a durable commit group.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use crate::engine::ProjectionPhase;
use crate::storage_model::{ModelError, ObjectId};

use super::super::group_publication::{self, Action, Entry};
use super::super::wal::durable_error as wal_durable_error;
use super::super::{
    ARENA_FILE, DurableEngine, DurableError, DurableInner, FaultPoint, Persisted,
    PersistentObjectIdentity, Prepared, PrincipalCodec, decode_object_frame, encode_object_frame,
    io_error, live_files_mut, read_indexed_object,
};
use super::{AcceptedCommit, record_group};

type WalEntry<'a, P> = Entry<'a, AcceptedCommit<P>, BTreeMap<ObjectId, Arc<[u8]>>>;

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
        let Some((length, tail)) = super::super::frontier::wal_position(
            files.arena_len,
            files.arena_tail,
            arena_len,
            arena_tail,
        ) else {
            return Err(DurableError::Corrupt {
                file: ARENA_FILE,
                offset: arena_len,
                detail: "object arena moved behind the cached WAL frontier",
            });
        };
        files.arena_len = length;
        files.arena_tail = tail;
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
        let prepared = group_publication::prepare(accepted, |entry| {
            Self::collect_prepared_wal_objects(&entry.prepared)
        })?;
        group_publication::install_after_flush(
            &prepared,
            &staged,
            |group, staged| self.append_wal_transactions(accepted, staged, group),
            |group, staged, _published_count| {
                self.fail_if(FaultPoint::AfterWalPublication)?;
                self.install_wal_overlay(inner, staged, group)
            },
        )?;
        let arena_len = live_files_mut(&mut inner.files)?
            .arena
            .metadata()
            .map_err(|source| io_error("read WAL staged arena metadata", source))?
            .len();
        Ok(Persisted {
            frontier: super::super::CommitFrontier::Wal,
            locations: Vec::new(),
            arena_len,
        })
    }

    fn install_wal_overlay(
        &self,
        inner: &mut DurableInner<P>,
        staged: &BTreeMap<ObjectId, crate::storage_model::ObjectRecord>,
        prepared: &[WalEntry<'_, P>],
    ) -> Result<(), DurableError> {
        for (id, record) in staged {
            let (location, direct) = super::super::arena_index::placement(
                *id,
                &inner.index,
                &inner.pending_direct_objects,
            )
            .ok_or(DurableError::Corrupt {
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
                direct.cloned(),
            )?;
        }
        for entry in prepared {
            for (id, payload) in &entry.frames {
                let (name, retained, record) =
                    super::super::format::pending_object_frame(payload, *id, &self.identity)?;
                inner.pending_wal.insert_prepared(name, retained, record)?;
            }
        }
        for entry in prepared {
            inner
                .pending_wal
                .retain_root(&entry.transaction.prepared.root);
        }
        Ok(())
    }

    fn append_wal_transactions(
        &self,
        accepted: &[AcceptedCommit<P>],
        staged: &BTreeMap<ObjectId, crate::storage_model::ObjectRecord>,
        prepared: &[WalEntry<'_, P>],
    ) -> Result<u64, DurableError> {
        let mut wal = self.wal.lock();
        let writer = wal.as_mut().ok_or(DurableError::Closed)?;
        let empty = BTreeMap::new();
        group_publication::publish(
            prepared,
            writer,
            |writer, action| -> Result<_, DurableError> {
                match action {
                    Action::Begin => {
                        let sequence = writer.next_sequence().map_err(wal_durable_error)?;
                        writer.begin(sequence, None).map_err(wal_durable_error)?;
                    },
                    Action::Objects { first, frames } => {
                        let staged_rows = if first { staged } else { &empty };
                        self.append_wal_rows(writer, staged_rows, frames)?;
                    },
                    Action::Root(entry) => {
                        entry
                            .prepared
                            .root
                            .write_wal(|owner, expected, replacement, journal| {
                                writer.append_prepared_root(owner, expected, replacement, journal)
                            })
                            .map_err(wal_durable_error)?;
                    },
                    Action::Commit => {
                        writer.finish_commit().map_err(wal_durable_error)?;
                    },
                }
                Ok(writer)
            },
            |writer| {
                let started = Instant::now();
                let published = writer.publish().map_err(wal_durable_error)?;
                record_group(accepted, ProjectionPhase::Flush, started);
                Ok(published)
            },
        )
    }

    fn append_wal_rows(
        &self,
        writer: &mut super::super::DurableWal<P, I, C>,
        staged_rows: &BTreeMap<ObjectId, crate::storage_model::ObjectRecord>,
        frames: &BTreeMap<ObjectId, Arc<[u8]>>,
    ) -> Result<(), DurableError> {
        super::super::merge_rows::merge(
            staged_rows,
            frames,
            &mut *writer,
            |writer, row| -> Result<_, DurableError> {
                use super::super::merge_rows::Input;
                let input = row.resolve(
                    |frame| {
                        decode_object_frame(frame, self.identity.scheme())
                            .map(|(_, record)| record)
                            .map_err(|detail| DurableError::Corrupt {
                                file: ARENA_FILE,
                                offset: 0,
                                detail,
                            })
                    },
                    |id| DurableError::from(ModelError::ObjectCollision(id)),
                )?;
                match input {
                    Input::Staged(id, record) => writer.append_object(id, record),
                    Input::Prepared(id, frame) => writer.append_prepared_object(id, frame),
                }
                .map_err(wal_durable_error)?;
                Ok(writer)
            },
        )?;
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
