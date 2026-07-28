//! Owning-closure loading, graph validation, and usage accounting.

use astrid_storage_model::{ModelError, ObjectId, ObjectKind, ObjectRecord, PrincipalUsage, World};

use super::format::read_indexed_object;
use super::{
    ArenaLocation, BTreeMap, BTreeSet, DurableError, File, PersistentObjectIdentity, ROOT_FILE,
    RecoveryLimits,
};

pub(super) fn materialize_closure<I: PersistentObjectIdentity>(
    arena: &mut File,
    index: &BTreeMap<ObjectId, ArenaLocation>,
    incoming: &BTreeMap<ObjectId, ObjectRecord>,
    root: ObjectId,
    identity: &I,
    limits: RecoveryLimits,
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
        let record = if let Some(record) = incoming.get(&id) {
            record.clone()
        } else {
            let location = index
                .get(&id)
                .copied()
                .ok_or(ModelError::MissingObject(id))?;
            read_indexed_object(arena, id, location, identity, limits)?
        };
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
    arena: &mut File,
    index: &BTreeMap<ObjectId, ArenaLocation>,
    incoming: &BTreeMap<ObjectId, ObjectRecord>,
    validated: &BTreeSet<ObjectId>,
    root: ObjectId,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<BTreeSet<ObjectId>, DurableError> {
    let root_record = if let Some(record) = incoming.get(&root) {
        record.clone()
    } else {
        let location = index
            .get(&root)
            .copied()
            .ok_or(ModelError::MissingObject(root))?;
        read_indexed_object(arena, root, location, identity, limits)?
    };
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
        let record = if let Some(record) = incoming.get(&id) {
            record.clone()
        } else {
            let location = index
                .get(&id)
                .copied()
                .ok_or(ModelError::MissingObject(id))?;
            read_indexed_object(arena, id, location, identity, limits)?
        };
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
