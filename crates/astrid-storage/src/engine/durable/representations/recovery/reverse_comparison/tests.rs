use super::*;

const A: ObjectId = ObjectId::new([1; 32]);
const B: ObjectId = ObjectId::new([2; 32]);
const C: ObjectId = ObjectId::new([3; 32]);
const ONE: RepresentationRecordId = RepresentationRecordId::new([1; 32]);
const TWO: RepresentationRecordId = RepresentationRecordId::new([2; 32]);
const THREE: RepresentationRecordId = RepresentationRecordId::new([3; 32]);
const FOUR: RepresentationRecordId = RepresentationRecordId::new([4; 32]);

fn expected() -> BTreeMap<ObjectId, Vec<RepresentationRecordId>> {
    BTreeMap::from([(A, vec![ONE, THREE]), (B, vec![TWO])])
}

fn matches(
    expected: &BTreeMap<ObjectId, Vec<RepresentationRecordId>>,
    stream: &[(ObjectId, RepresentationRecordId)],
) -> bool {
    let mut comparison = ReverseComparison::new(expected).unwrap();
    for (object, record) in stream {
        comparison.observe(*object, *record);
    }
    comparison.matches()
}

#[test]
fn canonical_interleaved_objects_match_without_collecting() {
    assert!(matches(&expected(), &[(A, ONE), (B, TWO), (A, THREE)]));
    assert!(matches(&BTreeMap::new(), &[]));
}

#[test]
fn index_mutations_preserve_exact_ordered_equality_rejection() {
    let stream = [(A, ONE), (B, TWO), (A, THREE)];
    let cases = [
        BTreeMap::from([(A, vec![ONE, THREE])]),
        BTreeMap::from([(A, vec![ONE]), (B, vec![TWO])]),
        BTreeMap::from([(A, vec![ONE, THREE, FOUR]), (B, vec![TWO])]),
        BTreeMap::from([(A, vec![ONE, ONE, THREE]), (B, vec![TWO])]),
        BTreeMap::from([(A, vec![THREE, ONE]), (B, vec![TWO])]),
        BTreeMap::from([(A, vec![ONE, FOUR]), (B, vec![TWO])]),
        BTreeMap::from([(A, vec![ONE, THREE]), (C, vec![TWO])]),
        BTreeMap::from([(A, vec![ONE, THREE]), (B, vec![TWO]), (C, vec![])]),
    ];
    for expected in cases {
        assert!(
            !matches(&expected, &stream),
            "accepted unequal index {expected:?}"
        );
    }
}

#[test]
fn malformed_stream_cannot_pass_membership_and_count_alone() {
    let expected = expected();
    let cases: &[&[(ObjectId, RepresentationRecordId)]] = &[
        &[(A, ONE), (B, TWO)],
        &[(A, ONE), (B, TWO), (A, THREE), (A, FOUR)],
        &[(A, ONE), (A, ONE), (A, THREE)],
        &[(A, THREE), (B, TWO), (A, ONE)],
        &[(A, ONE), (C, TWO), (A, THREE)],
    ];
    for stream in cases {
        assert!(
            !matches(&expected, stream),
            "accepted unequal stream {stream:?}"
        );
    }
}
