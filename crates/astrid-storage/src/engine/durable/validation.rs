//! Owning-closure loading, graph validation, and usage accounting.

use crate::storage_model::{ModelError, ObjectId, ObjectKind, ObjectRecord, PrincipalUsage, World};

use super::closure_walk::{self, Failure, Source, Work};
use super::format::{read_indexed_object, visit_indexed_objects};
use super::wal::PendingWalOverlay;
use super::{
    ArenaLocation, BTreeMap, BTreeSet, DurableError, File, PersistentObjectIdentity, ROOT_FILE,
    RecoveryLimits,
};

// This is an I/O coalescing target, not an authenticity or allocation limit.
// Each indexed frame is still checksum- and identity-verified independently.
const RECOVERY_CLOSURE_READ_TARGET_BYTES: u64 = 8 * 1024 * 1024;

pub(super) struct ClosureObjects<'a, I, P: Ord> {
    pub(super) arena: &'a mut File,
    pub(super) index: &'a BTreeMap<ObjectId, ArenaLocation>,
    pub(super) incoming: &'a BTreeMap<ObjectId, ObjectRecord>,
    pub(super) pending: Option<&'a PendingWalOverlay<P>>,
    pub(super) identity: &'a I,
    pub(super) limits: RecoveryLimits,
}

impl<I: PersistentObjectIdentity, P: Ord> ClosureObjects<'_, I, P> {
    fn load(&mut self, id: ObjectId) -> Result<ObjectRecord, DurableError> {
        super::closure_load::load(
            id,
            &super::closure_load::Layers {
                incoming: self.incoming,
                pending: self.pending.map(PendingWalOverlay::object_index),
                index: self.index,
            },
            ObjectRecord::clone,
            |pending| pending.record().clone(),
            |requested, location| {
                read_indexed_object(self.arena, requested, *location, self.identity, self.limits)
            },
            |missing| ModelError::MissingObject(missing).into(),
        )
    }
}

impl<I: PersistentObjectIdentity, P: Ord> Source<ObjectId> for ClosureObjects<'_, I, P> {
    type Error = DurableError;

    fn check_root(&mut self, root: ObjectId) -> Result<(), DurableError> {
        let root_record = self.load(root)?;
        if root_record.kind() != ObjectKind::Commit {
            return Err(ModelError::RootNotCommit {
                object: root,
                actual: root_record.kind(),
            }
            .into());
        }
        Ok(())
    }

    fn expand(
        &mut self,
        id: ObjectId,
        stack: &mut Vec<Work<ObjectId>>,
    ) -> Result<(), DurableError> {
        let record = self.load(id)?;
        closure_walk::schedule(record.references(), stack);
        Ok(())
    }
}

pub(super) fn materialize_closure<I: PersistentObjectIdentity, P: Ord>(
    source: &mut ClosureObjects<'_, I, P>,
    root: ObjectId,
) -> Result<Vec<(ObjectId, ObjectRecord)>, DurableError> {
    let mut records = BTreeMap::new();
    let mut marks = BTreeMap::<ObjectId, u8>::new();
    let mut stack = vec![(root, false)];

    while let Some((id, expanded)) = stack.pop() {
        if expanded {
            marks.insert(id, 2);
            continue;
        }
        match marks.get(&id).copied() {
            Some(2) => continue,
            Some(1) => return Err(ModelError::ObjectCycle(id).into()),
            Some(_) | None => {},
        }
        let record = source.load(id)?;
        marks.insert(id, 1);
        stack.push((id, true));
        for child in record.owning_references().rev() {
            stack.push((child, false));
        }
        records.insert(id, record);
    }
    Ok(records.into_iter().collect())
}

/// Load the indexed objects reachable from a set of roots in coalesced spans.
///
/// The frontier is expanded one owning-reference level at a time so the
/// reader can sort adjacent locations into a single positional read without
/// scanning unrelated arena bytes. `visit_indexed_objects` retains the same
/// frame checksum, canonical decoding, and identity checks as a one-object
/// load.
pub(super) fn preload_indexed_closures<I: PersistentObjectIdentity>(
    arena: &File,
    index: &BTreeMap<ObjectId, ArenaLocation>,
    roots: impl IntoIterator<Item = ObjectId>,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<BTreeMap<ObjectId, ObjectRecord>, DurableError> {
    use super::journal_preload::{Error, accept, preload};
    preload(
        index,
        roots.into_iter().collect(),
        |mut loaded, requested| {
            let mut next = BTreeSet::new();
            visit_indexed_objects(
                arena,
                requested,
                RECOVERY_CLOSURE_READ_TARGET_BYTES,
                identity,
                limits,
                |id, _location, record, _payload| {
                    accept(&mut loaded, &mut next, id, record);
                    Ok(())
                },
            )?;
            Ok((loaded, next))
        },
    )
    .map_err(|error| match error {
        Error::Missing(id) => ModelError::MissingObject(id).into(),
        Error::Read(error) => error,
    })
}

pub(super) fn validate_incremental_closure<I: PersistentObjectIdentity, P: Ord>(
    source: &mut ClosureObjects<'_, I, P>,
    validated: &BTreeSet<ObjectId>,
    root: ObjectId,
) -> Result<BTreeSet<ObjectId>, DurableError> {
    closure_walk::walk(source, validated, root).map_err(|error| match error {
        Failure::Cycle(id) => ModelError::ObjectCycle(id).into(),
        Failure::Root(e) | Failure::Source(_, e) => e,
    })
}

pub(super) fn usage_from_closure(
    records: &[(ObjectId, ObjectRecord)],
    commit: ObjectId,
) -> Result<PrincipalUsage, ModelError> {
    let mut world = World::<()>::new();
    world.import_closure(records, commit)?;
    world.compare_and_swap_root((), None, commit)?;
    world.principal_usage(&())
}

pub(super) fn recovery_closure_error(error: DurableError, root_offset: u64) -> DurableError {
    match error {
        DurableError::Model(source) => DurableError::RecoveryModel {
            file: ROOT_FILE,
            offset: root_offset,
            source,
        },
        other => other,
    }
}
