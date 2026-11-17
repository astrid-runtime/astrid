//! Mount-time correspondence between direct replicas and the recovered index.

use super::{ArenaLocation, BTreeMap, DurableError, FRAME_HEADER_LEN, ObjectId};

#[cfg(test)]
std::thread_local! {
    pub(super) static PLACEMENT_COLLECTIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    pub(super) static DIRECT_EXTRACTIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(in crate::engine::durable) fn count_extractions_during<T>(
    operation: impl FnOnce() -> T,
) -> (T, usize) {
    DIRECT_EXTRACTIONS.with(|count| count.set(0));
    let value = operation();
    (value, DIRECT_EXTRACTIONS.with(std::cell::Cell::get))
}

/// Selected placements moved out of metadata validation, never retained by the
/// store. Selection follows canonical record order, before filtering replicas.
#[derive(Default)]
pub(in crate::engine::durable) struct GenerationZeroPlacements {
    // Ranges are formed only from this owned buffer before it is consumed.
    selected: BTreeMap<ObjectId, Option<std::ops::Range<usize>>>,
    locations: Vec<ArenaLocation>,
}

impl GenerationZeroPlacements {
    pub(super) fn observe(
        &mut self,
        object: ObjectId,
        is_direct_profile: bool,
        placement: &super::PlacementEntry,
    ) {
        #[cfg(test)]
        PLACEMENT_COLLECTIONS.with(|count| count.set(count.get().strict_add(1)));
        let selected = self.selected.entry(object).or_default();
        if !is_direct_profile || selected.is_some() {
            return;
        }
        let start = self.locations.len();
        self.locations
            .extend(
                placement
                    .replicas()
                    .iter()
                    .filter_map(|replica| match replica.locator() {
                        super::ReplicaLocator::ArenaFrame {
                            arena_generation: 0,
                            offset,
                            payload_length,
                            frame_checksum,
                        } => Some(ArenaLocation {
                            offset,
                            payload_len: payload_length,
                            checksum: frame_checksum,
                        }),
                        _ => None,
                    }),
            );
        *selected = Some(start..self.locations.len());
    }

    pub(in crate::engine::durable) fn into_index(
        self,
    ) -> Result<GenerationZeroIndex, DurableError> {
        let mut direct = Vec::new();
        for (object, selected) in self.selected {
            let range = selected.ok_or(DurableError::InvalidRepresentationState(
                "reverse index has no direct representation",
            ))?;
            let replicas =
                self.locations
                    .get(range)
                    .ok_or(DurableError::InvalidRepresentationState(
                        "generation-zero placement range is invalid",
                    ))?;
            if replicas.is_empty() {
                return Err(DurableError::InvalidRepresentationState(
                    "direct representation has no generation-zero arena placement",
                ));
            }
            direct.extend(replicas.iter().copied().map(|location| (object, location)));
        }
        GenerationZeroIndex::from_locations(direct)
    }
}

/// One recovery-local placement snapshot, consumed before WAL replay can
/// advance representation authority. Arena repair and index validation must
/// consult the same checked placements. A malformed frame below the protected
/// prefix is corruption, never a repairable uncommitted arena tail.
///
/// Index correspondence is mount-time topology validation. Authoritative reads
/// still verify frame checksums, canonical encoding, and logical identity;
/// proactive full-corpus re-attestation belongs to the refinery.
#[derive(Default)]
pub(in crate::engine::durable) struct GenerationZeroIndex {
    direct: Vec<(ObjectId, ArenaLocation)>,
    protected_len: u64,
}

impl GenerationZeroIndex {
    fn from_locations(direct: Vec<(ObjectId, ArenaLocation)>) -> Result<Self, DurableError> {
        let protected_len = direct.iter().try_fold(0_u64, |protected, (_, location)| {
            let end = location
                .offset
                .checked_add(FRAME_HEADER_LEN)
                .and_then(|value| value.checked_add(location.payload_len))
                .ok_or(DurableError::EncodingOverflow)?;
            Ok::<_, DurableError>(protected.max(end))
        })?;
        Ok(Self {
            direct,
            protected_len,
        })
    }

    pub(in crate::engine::durable) fn protected_len(&self) -> u64 {
        self.protected_len
    }

    pub(in crate::engine::durable) fn validate(
        self,
        index: &BTreeMap<ObjectId, ArenaLocation>,
    ) -> Result<(), DurableError> {
        validate(&self.direct, index)
    }
}

pub(super) fn validate(
    direct: &[(ObjectId, ArenaLocation)],
    index: &BTreeMap<ObjectId, ArenaLocation>,
) -> Result<(), DurableError> {
    // Recovery evidence emits every object's selected replicas contiguously,
    // rejecting objects without a replica before constructing this index.
    // Visit each group once rather than rescanning the whole corpus per object.
    for replicas in direct.chunk_by(|left, right| left.0 == right.0) {
        let object = replicas[0].0;
        let location =
            index
                .get(&object)
                .copied()
                .ok_or(DurableError::InvalidRepresentationState(
                    "direct representation names a missing logical object",
                ))?;
        if !replicas.iter().any(|(_, candidate)| *candidate == location) {
            return Err(DurableError::InvalidRepresentationState(
                "generation-zero placement disagrees with the arena index",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn location(offset: u64) -> ArenaLocation {
        ArenaLocation {
            offset,
            payload_len: 8,
            checksum: [0; 32],
        }
    }

    #[test]
    fn snapshot_checks_every_replica_end_before_recovery() {
        let object = ObjectId::new([1; 32]);
        let snapshot = GenerationZeroIndex::from_locations(vec![
            (object, location(1)),
            (object, location(100)),
        ])
        .unwrap();
        assert_eq!(snapshot.protected_len(), 100 + FRAME_HEADER_LEN + 8);
        snapshot
            .validate(&BTreeMap::from([(object, location(1))]))
            .unwrap();
        assert!(matches!(
            GenerationZeroIndex::from_locations(vec![(object, location(u64::MAX))]),
            Err(DurableError::EncodingOverflow)
        ));
        let absent = GenerationZeroIndex::default();
        assert_eq!(absent.protected_len(), 0);
        absent.validate(&BTreeMap::new()).unwrap();
    }

    #[test]
    fn accepts_any_matching_replica_without_borrowing_another_objects_location() {
        let first = ObjectId::new([1; 32]);
        let second = ObjectId::new([2; 32]);
        let direct = [
            (first, location(1)),
            (first, location(2)),
            (second, location(3)),
        ];
        let mut index = BTreeMap::from([(first, location(2)), (second, location(3))]);
        validate(&direct, &index).unwrap();
        index.insert(first, location(3));
        assert!(matches!(
            validate(&direct, &index),
            Err(DurableError::InvalidRepresentationState(
                "generation-zero placement disagrees with the arena index"
            ))
        ));
    }

    #[test]
    fn missing_objects_still_fail_closed() {
        let object = ObjectId::new([1; 32]);
        assert!(matches!(
            validate(&[(object, location(1))], &BTreeMap::new()),
            Err(DurableError::InvalidRepresentationState(
                "direct representation names a missing logical object"
            ))
        ));
        validate(&[], &BTreeMap::new()).unwrap();
    }

    #[test]
    #[ignore = "manual lookup-cost comparison, not a timing-sensitive CI gate"]
    fn compare_grouped_validation_with_previous_full_corpus_scan() {
        let direct: Vec<_> = (0_u64..10_000)
            .map(|ordinal| {
                let mut id = [0; 32];
                id[..8].copy_from_slice(&ordinal.to_be_bytes());
                (ObjectId::new(id), location(ordinal))
            })
            .collect();
        let index: BTreeMap<_, _> = direct.iter().copied().collect();
        let started = std::time::Instant::now();
        for (object, location) in &index {
            assert!(
                direct
                    .iter()
                    .any(|(covered, candidate)| { covered == object && candidate == location })
            );
        }
        let previous = started.elapsed();
        let started = std::time::Instant::now();
        validate(&direct, &index).unwrap();
        eprintln!(
            "10000 objects: previous={previous:?}, grouped={:?}",
            started.elapsed()
        );
    }
}
