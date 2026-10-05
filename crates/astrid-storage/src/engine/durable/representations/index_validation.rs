//! Mount-time correspondence between direct replicas and the recovered index.

use super::{ArenaLocation, BTreeMap, DurableError, ObjectId};

pub(super) fn validate(
    direct: &[(ObjectId, ArenaLocation)],
    index: &BTreeMap<ObjectId, ArenaLocation>,
) -> Result<(), DurableError> {
    // direct_arena_locations walks the ordered reverse map and emits every
    // object's replicas contiguously, rejecting objects without a replica.
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
