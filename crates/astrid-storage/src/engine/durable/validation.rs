//! Owning-closure loading, graph validation, and usage accounting.

use crate::storage_model::{ModelError, ObjectId, ObjectKind, ObjectRecord, PrincipalUsage, World};

use super::format::read_indexed_object;
use super::representations::{RepresentationStore, read_contiguous_object};
use super::{
    ArenaLocation, BTreeMap, BTreeSet, DurableError, File, PersistentObjectIdentity, ROOT_FILE,
    RecoveryLimits,
};

pub(super) struct ClosureObjects<'a, I> {
    pub(super) arena: &'a mut File,
    pub(super) index: &'a BTreeMap<ObjectId, ArenaLocation>,
    pub(super) incoming: &'a BTreeMap<ObjectId, ObjectRecord>,
    pub(super) representations: Option<&'a RepresentationStore>,
    pub(super) identity: &'a I,
    pub(super) limits: RecoveryLimits,
}

impl<I: PersistentObjectIdentity> ClosureObjects<'_, I> {
    fn load(&mut self, id: ObjectId) -> Result<ObjectRecord, DurableError> {
        if let Some(record) = self.incoming.get(&id) {
            return Ok(record.clone());
        }
        if let Some(location) = self.index.get(&id).copied() {
            return read_indexed_object(self.arena, id, location, self.identity, self.limits);
        }
        if let Some((file, location)) = self
            .representations
            .map(|store| store.open_contiguous_read(id))
            .transpose()?
            .flatten()
        {
            return read_contiguous_object(file, location, id, self.identity);
        }
        Err(ModelError::MissingObject(id).into())
    }
}

pub(super) fn materialize_closure<I: PersistentObjectIdentity>(
    source: &mut ClosureObjects<'_, I>,
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

pub(super) fn validate_commit_closure(
    records: &[(ObjectId, ObjectRecord)],
    commit: ObjectId,
) -> Result<(), ModelError> {
    let mut world = World::<()>::new();
    world.import_closure(records, commit)?;
    world.compare_and_swap_root((), None, commit)?;
    Ok(())
}

pub(super) fn validate_incremental_closure<I: PersistentObjectIdentity>(
    source: &mut ClosureObjects<'_, I>,
    validated: &BTreeSet<ObjectId>,
    root: ObjectId,
) -> Result<BTreeSet<ObjectId>, DurableError> {
    let root_record = source.load(root)?;
    if root_record.kind() != ObjectKind::Commit {
        return Err(ModelError::RootNotCommit {
            object: root,
            actual: root_record.kind(),
        }
        .into());
    }
    let mut reachable = BTreeSet::new();
    let mut marks = BTreeMap::<ObjectId, u8>::new();
    let mut stack = vec![(root, false)];

    while let Some((id, expanded)) = stack.pop() {
        if validated.contains(&id) {
            reachable.insert(id);
            continue;
        }
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
        reachable.insert(id);
        marks.insert(id, 1);
        stack.push((id, true));
        for child in record.owning_references().rev() {
            stack.push((child, false));
        }
    }
    Ok(reachable)
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
