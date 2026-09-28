use super::{ChainMetadata, OMITTED_TOTAL_UNKNOWN, PruneGeneration};

fn receipt(generation: u64, omitted_count: u64) -> PruneGeneration {
    PruneGeneration {
        generation,
        omitted_count,
    }
}

fn counted(total: u64, generation: Option<u64>) -> ChainMetadata {
    ChainMetadata {
        omitted_total: Some(total),
        omitted_generation: generation,
        ..ChainMetadata::default()
    }
}

#[test]
fn count_prune_accumulates_each_generation_once() {
    let mut metadata = ChainMetadata::default();
    metadata.count_prune(receipt(0, 5), None);
    assert_eq!(
        (metadata.omitted_total, metadata.omitted_generation),
        (Some(5), Some(0))
    );
    // A resumed finalization of generation 0 sees its own receipt installed.
    metadata.count_prune(receipt(0, 5), Some(receipt(0, 5)));
    assert_eq!(metadata.omitted_total, Some(5));
    metadata.count_prune(receipt(1, 3), Some(receipt(0, 5)));
    metadata.count_prune(receipt(2, 4), Some(receipt(1, 3)));
    assert_eq!(
        (metadata.omitted_total, metadata.omitted_generation),
        (Some(12), Some(2))
    );
}

#[test]
fn count_prune_derives_the_base_of_uncounted_metadata_from_the_receipt() {
    // Never pruned: generation 0 starts from zero.
    let mut first = ChainMetadata::default();
    first.count_prune(receipt(0, 7), None);
    assert_eq!(first.omitted_total, Some(7));

    // Pruned once before the counter: the installed generation-0 receipt
    // holds the whole prior total.
    let mut second = ChainMetadata::default();
    second.count_prune(receipt(1, 2), Some(receipt(0, 7)));
    assert_eq!(second.omitted_total, Some(9));

    // Pruned twice before the counter: generation 0's count is gone.
    let mut third = ChainMetadata::default();
    third.count_prune(receipt(2, 2), Some(receipt(1, 3)));
    assert_eq!(third.omitted_total, Some(OMITTED_TOTAL_UNKNOWN));
    third.count_prune(receipt(3, 1), Some(receipt(2, 2)));
    assert_eq!(third.omitted_total, Some(OMITTED_TOTAL_UNKNOWN));
    assert_eq!(third.omitted_generation, Some(3));

    // Generation 1 finalized again after an older binary had already
    // installed its receipt: generation 0's count is gone.
    let mut resumed = ChainMetadata::default();
    resumed.count_prune(receipt(1, 2), Some(receipt(1, 2)));
    assert_eq!(resumed.omitted_total, Some(OMITTED_TOTAL_UNKNOWN));
}

#[test]
fn count_prune_marks_a_skipped_generation_unknown() {
    let mut skipped = counted(5, Some(0));
    skipped.count_prune(receipt(2, 1), Some(receipt(1, 3)));
    assert_eq!(skipped.omitted_total, Some(OMITTED_TOTAL_UNKNOWN));

    let mut uncounted_first = counted(0, None);
    uncounted_first.count_prune(receipt(1, 1), Some(receipt(0, 3)));
    assert_eq!(uncounted_first.omitted_total, Some(OMITTED_TOTAL_UNKNOWN));
}

#[test]
fn uncounted_metadata_reencodes_to_its_stored_bytes() {
    let stored = br#"{"schema":1,"segment":0,"sealed":false,"count":2,"bytes":10,"head":null,"head_hash":"0000000000000000000000000000000000000000000000000000000000000000","segment_count":2,"segment_bytes":10,"segment_first":null,"seal_ordinal":null}"#;
    let metadata: ChainMetadata = serde_json::from_slice(stored).unwrap();
    assert_eq!(metadata.omitted_total, None);
    assert_eq!(serde_json::to_vec(&metadata).unwrap(), stored.to_vec());

    let encoded = serde_json::to_value(counted(3, Some(0))).unwrap();
    assert_eq!(encoded["omitted_total"], 3);
    assert_eq!(encoded["omitted_generation"], 0);
}

#[test]
fn prune_generation_requires_both_fields() {
    assert_eq!(
        PruneGeneration::parse(br#"{"generation":2,"omitted_count":9}"#).unwrap(),
        receipt(2, 9)
    );
    assert!(PruneGeneration::parse(br#"{"omitted_count":9}"#).is_err());
    assert!(PruneGeneration::parse(br#"{"generation":2}"#).is_err());
}
