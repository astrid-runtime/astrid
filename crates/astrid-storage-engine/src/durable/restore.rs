//! Destination-only root restoration and principal-codec migration.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::path::Path;

use astrid_storage_model::{ModelError, ObjectId, ObjectRecord, RootState};

use super::{
    ARENA_FILE, ARENA_MAGIC, DurableEngine, DurableError, DurableInner, PersistentObjectIdentity,
    PrincipalCodec, ROOT_FILE, ROOT_MAGIC, append_frame, encode_object_frame, encode_root_snapshot,
    ensure_payload_limit, ensure_usable, io_error, live_files_mut, read_indexed_object,
    recover_roots,
};
use crate::RootSnapshot;

impl<P, I, C> DurableEngine<P, I, C>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    /// Install complete principal snapshots into a destination with no roots.
    ///
    /// This is a destination-only primitive for format migration and bundle
    /// restore. It preserves each supplied [`RootState`] exactly, including
    /// its generation, while admitting immutable objects by verified identity.
    /// Standalone bootstrap objects may already exist in the destination
    /// arena, but the root journal must be empty and no principal root may
    /// already be visible.
    ///
    /// Objects are flushed before one canonical root-snapshot frame makes the
    /// restored roots authoritative. Any I/O failure poisons this engine
    /// instance and requires reopen.
    ///
    /// # Errors
    ///
    /// Returns a model, identity, collision, principal-codec, encoding, I/O,
    /// or destination-state error.
    pub fn restore_snapshots(&self, snapshots: Vec<(P, RootSnapshot)>) -> Result<(), DurableError> {
        restore_snapshots(self, snapshots)
    }

    /// Write and fully validate a root snapshot under a successor principal
    /// codec without mutating the active journal.
    ///
    /// The caller owns the crash protocol that later promotes `destination`.
    /// This engine remains on its original codec and must be closed before a
    /// platform that forbids renaming open files can promote the replacement.
    ///
    /// # Errors
    ///
    /// Returns a mapping, codec, encoding, closure, or I/O error. The active
    /// arena and root journal are never modified.
    pub fn write_mapped_root_snapshot<Q, D, F>(
        &self,
        destination: impl AsRef<Path>,
        destination_codec: &D,
        map: F,
    ) -> Result<(), DurableError>
    where
        Q: Clone + Ord,
        D: PrincipalCodec<Q>,
        F: FnMut(&P) -> Result<Q, DurableError>,
    {
        write_mapped_root_snapshot(self, destination.as_ref(), destination_codec, map)
    }
}

pub(super) fn restore_snapshots<P, I, C>(
    engine: &DurableEngine<P, I, C>,
    snapshots: Vec<(P, RootSnapshot)>,
) -> Result<(), DurableError>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    let mut inner = engine.inner.lock();
    ensure_usable(&inner)?;
    ensure_empty_destination(&mut inner)?;

    let restore = collect_restore(engine, snapshots)?;
    let validated = validate_restore_closures(engine, &mut inner, &restore)?;
    let objects = prepare_restore_objects(engine, &mut inner, &restore.records)?;
    let journal = encode_restored_roots(engine, &restore.roots)?;

    let persisted = persist_restore(&mut inner, &objects, &journal);
    match persisted {
        Ok((locations, arena_len)) => {
            for location in locations {
                inner.index.insert(location.0, location.1);
                inner.pending_index_locations.push(location);
            }
            inner.validated.extend(validated);
            inner.roots_by_principal = restore.roots;
            if let Err(error) = engine.advance_index_frontier(&mut inner, arena_len) {
                inner.poisoned = true;
                return Err(error);
            }
            Ok(())
        },
        Err(error) => {
            inner.poisoned = true;
            Err(error)
        },
    }
}

struct RestoreSet<P> {
    roots: BTreeMap<P, RootState>,
    records: BTreeMap<ObjectId, ObjectRecord>,
    records_by_root: Vec<(ObjectId, BTreeSet<ObjectId>)>,
}

fn ensure_empty_destination<P: Ord>(inner: &mut DurableInner<P>) -> Result<(), DurableError> {
    if !inner.roots_by_principal.is_empty() {
        return Err(DurableError::InvalidRestore(
            "destination already has principal roots",
        ));
    }
    if live_files_mut(&mut inner.files)?
        .roots
        .metadata()
        .map_err(|source| io_error("read restore root-journal metadata", source))?
        .len()
        != 0
    {
        return Err(DurableError::InvalidRestore(
            "destination root journal is not empty",
        ));
    }
    Ok(())
}

fn collect_restore<P, I, C>(
    engine: &DurableEngine<P, I, C>,
    snapshots: Vec<(P, RootSnapshot)>,
) -> Result<RestoreSet<P>, DurableError>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    let mut roots = BTreeMap::new();
    let mut records = BTreeMap::<ObjectId, ObjectRecord>::new();
    let mut records_by_root = Vec::new();
    for (principal, snapshot) in snapshots {
        let principal_bytes = engine.principal_codec.encode(&principal);
        if engine.principal_codec.decode(&principal_bytes).as_ref() != Some(&principal) {
            return Err(DurableError::InvalidRestore(
                "principal codec does not round-trip a restored principal",
            ));
        }
        if roots.insert(principal, snapshot.root()).is_some() {
            return Err(DurableError::InvalidRestore(
                "restore contains a duplicate principal",
            ));
        }
        let mut declared = BTreeSet::new();
        for (id, record) in snapshot.records() {
            let computed = engine.identify(record);
            if computed != *id {
                return Err(ModelError::ObjectIdentityMismatch {
                    declared: *id,
                    computed,
                }
                .into());
            }
            if !declared.insert(*id) {
                return Err(DurableError::InvalidRestore(
                    "one snapshot declares a duplicate object",
                ));
            }
            match records.get(id) {
                Some(existing) if existing == record => {},
                Some(_) => return Err(ModelError::ObjectCollision(*id).into()),
                None => {
                    records.insert(*id, record.clone());
                },
            }
        }
        records_by_root.push((snapshot.root().commit, declared));
    }
    Ok(RestoreSet {
        roots,
        records,
        records_by_root,
    })
}

fn validate_restore_closures<P, I, C>(
    engine: &DurableEngine<P, I, C>,
    inner: &mut DurableInner<P>,
    restore: &RestoreSet<P>,
) -> Result<BTreeSet<ObjectId>, DurableError>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    let mut validated = BTreeSet::new();
    for (commit, declared) in &restore.records_by_root {
        let reachable = engine.validate_pending_closure(inner, &restore.records, *commit)?;
        if &reachable != declared {
            return Err(DurableError::InvalidRestore(
                "snapshot records are not exactly its owning closure",
            ));
        }
        validated.extend(reachable);
    }
    Ok(validated)
}

fn prepare_restore_objects<P, I, C>(
    engine: &DurableEngine<P, I, C>,
    inner: &mut DurableInner<P>,
    records: &BTreeMap<ObjectId, ObjectRecord>,
) -> Result<Vec<(ObjectId, Vec<u8>)>, DurableError>
where
    P: Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    let mut objects = Vec::new();
    for (id, record) in records {
        if let Some(location) = inner.index.get(id).copied() {
            let files = live_files_mut(&mut inner.files)?;
            let existing =
                read_indexed_object(&files.arena, *id, location, &engine.identity, engine.limits)?;
            if existing != *record {
                return Err(ModelError::ObjectCollision(*id).into());
            }
            continue;
        }
        let payload = encode_object_frame(engine.identity.scheme(), *id, record)?;
        ensure_payload_limit(ARENA_FILE, 0, payload.len(), engine.limits)?;
        objects.push((*id, payload));
    }
    Ok(objects)
}

fn encode_restored_roots<P, I, C>(
    engine: &DurableEngine<P, I, C>,
    roots: &BTreeMap<P, RootState>,
) -> Result<Vec<u8>, DurableError>
where
    P: Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    let mut encoded_roots = roots
        .iter()
        .map(|(principal, root)| (engine.principal_codec.encode(principal), *root))
        .collect::<Vec<_>>();
    encoded_roots.sort_by(|left, right| left.0.cmp(&right.0));
    if encoded_roots.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(DurableError::InvalidRestore(
            "principal codec collides in restored root snapshot",
        ));
    }
    let journal = encode_root_snapshot(engine.identity.scheme(), &encoded_roots)?;
    ensure_payload_limit(ROOT_FILE, 0, journal.len(), engine.limits)?;
    Ok(journal)
}

fn persist_restore<P: Ord>(
    inner: &mut DurableInner<P>,
    objects: &[(ObjectId, Vec<u8>)],
    journal: &[u8],
) -> Result<(Vec<(ObjectId, super::ArenaLocation)>, u64), DurableError> {
    let files = live_files_mut(&mut inner.files)?;
    let mut locations = Vec::new();
    for (id, payload) in objects {
        let location = append_frame(&mut files.arena, ARENA_MAGIC, payload)?;
        locations.push((*id, location));
    }
    files
        .arena
        .sync_data()
        .map_err(|source| io_error("flush restored object frames", source))?;
    append_frame(&mut files.roots, ROOT_MAGIC, journal)?;
    files
        .roots
        .sync_data()
        .map_err(|source| io_error("flush restored root snapshot", source))?;
    let arena_len = files
        .arena
        .metadata()
        .map_err(|source| io_error("read restored arena metadata", source))?
        .len();
    Ok((locations, arena_len))
}

pub(super) fn write_mapped_root_snapshot<P, I, C, Q, D, F>(
    engine: &DurableEngine<P, I, C>,
    destination: &Path,
    destination_codec: &D,
    mut map: F,
) -> Result<(), DurableError>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
    Q: Clone + Ord,
    D: PrincipalCodec<Q>,
    F: FnMut(&P) -> Result<Q, DurableError>,
{
    let mut inner = engine.inner.lock();
    ensure_usable(&inner)?;
    let mut mapped = BTreeMap::new();
    for (principal, root) in &inner.roots_by_principal {
        if mapped.insert(map(principal)?, *root).is_some() {
            return Err(DurableError::InvalidRestore(
                "principal mapping collapses two durable roots",
            ));
        }
    }
    let mut encoded = mapped
        .iter()
        .map(|(principal, root)| (destination_codec.encode(principal), *root))
        .collect::<Vec<_>>();
    for ((principal, _), (bytes, _)) in mapped.iter().zip(encoded.iter()) {
        if destination_codec.decode(bytes).as_ref() != Some(principal) {
            return Err(DurableError::InvalidRestore(
                "successor principal codec does not round-trip",
            ));
        }
    }
    encoded.sort_by(|left, right| left.0.cmp(&right.0));
    if encoded.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(DurableError::InvalidRestore(
            "successor principal codec collides",
        ));
    }
    let payload = encode_root_snapshot(engine.identity.scheme(), &encoded)?;
    ensure_payload_limit(ROOT_FILE, 0, payload.len(), engine.limits)?;

    let mut options = OpenOptions::new();
    options.create(true).truncate(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut replacement = options
        .open(destination)
        .map_err(|source| io_error("create mapped root snapshot", source))?;
    append_frame(&mut replacement, ROOT_MAGIC, &payload)?;
    replacement
        .sync_data()
        .map_err(|source| io_error("flush mapped root snapshot", source))?;

    let DurableInner { files, index, .. } = &mut *inner;
    let files = live_files_mut(files)?;
    let (recovered, _) = recover_roots(
        &mut replacement,
        &mut files.arena,
        index,
        destination_codec,
        &engine.identity,
        engine.limits,
    )?;
    if recovered != mapped {
        return Err(DurableError::InvalidRestore(
            "validated mapped roots differ from requested roots",
        ));
    }
    Ok(())
}
