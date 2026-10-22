//! Object-to-representation lookup without a heap vector for singleton records.

use std::collections::{BTreeMap, btree_map::Entry};

use crate::storage_model::{ObjectId, RepresentationRecordId};

pub(super) type ReverseIndex = BTreeMap<ObjectId, RepresentationIds>;

/// The common direct-canonical case owns one ID inline. Multiple retained
/// representations keep their original admission order and are never pruned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum RepresentationIds {
    Single(RepresentationRecordId),
    Multiple(Vec<RepresentationRecordId>),
}

impl RepresentationIds {
    pub(super) const fn single(id: RepresentationRecordId) -> Self {
        Self::Single(id)
    }

    pub(super) fn iter(&self) -> std::slice::Iter<'_, RepresentationRecordId> {
        match self {
            Self::Single(id) => std::slice::from_ref(id).iter(),
            Self::Multiple(ids) => ids.iter(),
        }
    }

    fn push(&mut self, id: RepresentationRecordId) {
        match self {
            Self::Single(first) => *self = Self::Multiple(vec![*first, id]),
            Self::Multiple(ids) => ids.push(id),
        }
    }

    #[cfg(test)]
    pub(super) fn heap_capacity_bytes(&self) -> usize {
        match self {
            Self::Single(_) => 0,
            Self::Multiple(ids) => ids
                .capacity()
                .strict_mul(std::mem::size_of::<RepresentationRecordId>()),
        }
    }
}

pub(super) fn insert(index: &mut ReverseIndex, object: ObjectId, id: RepresentationRecordId) {
    match index.entry(object) {
        Entry::Vacant(entry) => {
            entry.insert(RepresentationIds::single(id));
        },
        Entry::Occupied(mut entry) => entry.get_mut().push(id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn singleton_has_no_heap_capacity_and_multiple_preserves_every_id_in_order() {
        let mut index = ReverseIndex::new();
        let object = ObjectId::new([1; 32]);
        let first = RepresentationRecordId::new([2; 32]);
        insert(&mut index, object, first);
        assert_eq!(index[&object].heap_capacity_bytes(), 0);
        let mut expected = vec![first];
        for byte in 3..12 {
            let id = RepresentationRecordId::new([byte; 32]);
            insert(&mut index, object, id);
            expected.push(id);
            assert_eq!(index[&object].iter().copied().collect::<Vec<_>>(), expected);
        }
        // Equal IDs are retained too: this storage change adds no dedup policy.
        insert(&mut index, object, first);
        expected.push(first);
        assert_eq!(index[&object].iter().copied().collect::<Vec<_>>(), expected);
        assert_eq!(index.clone(), index);
    }
}

#[cfg(test)]
mod persistence_tests {
    use super::super::{ArenaLocation, RepresentationStore};
    use super::*;
    use crate::engine::RecoveryLimits;
    use crate::volume::{AstridVolume, HostedFileVolume};
    use std::sync::Arc;

    fn assert_inline(store: &RepresentationStore, count: usize) {
        assert_eq!(store.reverse.len(), count);
        assert_eq!(
            store
                .reverse
                .values()
                .map(RepresentationIds::heap_capacity_bytes)
                .sum::<usize>(),
            0
        );
        assert_eq!(store.direct_arena_locations().unwrap().len(), count);
    }

    #[test]
    fn direct_publication_rebase_and_recovery_keep_singletons_inline() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("inline.volume");
        let volume: Arc<dyn AstridVolume> = HostedFileVolume::open(&path).unwrap();
        let limits = RecoveryLimits::process_addressable();
        let mut store =
            RepresentationStore::activate_volume(&volume, limits, ObjectId::new([1; 32]), [])
                .unwrap();
        let objects = (0..128_u64)
            .map(|index| {
                let mut bytes = [0; 32];
                bytes[..8].copy_from_slice(&index.to_le_bytes());
                store
                    .describe_direct(
                        ObjectId::new(bytes),
                        &index.to_le_bytes(),
                        ArenaLocation {
                            offset: index.strict_mul(8),
                            payload_len: 8,
                            checksum: [3; 32],
                        },
                    )
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let update = store.append_direct_update(&objects).unwrap().unwrap();
        store.publish_direct_update(update).unwrap();
        assert_inline(&store, objects.len());
        store.rebase_all_direct(&objects).unwrap();
        assert_inline(&store, objects.len());
        let active = store.active;
        let expected = store.reverse.clone();
        store.checkpoint_volume(&volume, limits).unwrap();
        drop(store);
        std::fs::copy(&path, directory.path().join("reopened.volume")).unwrap();
        let reopened: Arc<dyn AstridVolume> =
            HostedFileVolume::open(directory.path().join("reopened.volume")).unwrap();
        let recovered = RepresentationStore::open_volume(&reopened, limits)
            .unwrap()
            .unwrap();
        assert_inline(&recovered, objects.len());
        assert_eq!(recovered.active, active);
        assert_eq!(recovered.reverse, expected);
        for object in &objects {
            assert!(recovered.contains_direct(object.object));
        }
    }
}
