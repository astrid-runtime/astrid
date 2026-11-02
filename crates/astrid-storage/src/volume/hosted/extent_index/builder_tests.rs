use super::super::reference::{ExtentCount, ExtentRange, PageLevel, RecordOffset, RecordSequence};
use super::*;

fn leaf(index: u64) -> PageRef {
    PageRef::new(
        RecordOffset::new(index.strict_add(8)).unwrap(),
        RecordSequence::new(index.strict_add(1)).unwrap(),
        [7; 32],
        ExtentRange::new(index.strict_mul(2), index.strict_mul(2).strict_add(1)).unwrap(),
        ExtentCount::new(1).unwrap(),
        PageLevel::new(0).unwrap(),
    )
    .unwrap()
}

fn branch(children: &[PageRef], ordinal: &mut u64) -> io::Result<PageRef> {
    *ordinal = ordinal.strict_add(1);
    PageRef::new(
        RecordOffset::new(1_000_000_u64.strict_add(ordinal.strict_mul(8192)))?,
        RecordSequence::new(1_000_000_u64.strict_add(*ordinal))?,
        [8; 32],
        ExtentRange::new(
            children.first().unwrap().range().start(),
            children.last().unwrap().range().end(),
        )?,
        ExtentCount::new(
            children
                .iter()
                .map(|child| child.extent_count().get())
                .sum(),
        )?,
        PageLevel::new(children[0].level().get().strict_add(1))?,
    )
}

#[test]
fn empty_and_single_leaf_need_no_branch_records() {
    for count in [0, 1] {
        let mut builder = BranchBuilder::default();
        let mut append = |_: &[PageRef]| -> io::Result<PageRef> {
            panic!("empty or single-leaf trees must not emit a branch")
        };
        if count == 1 {
            builder.push_leaf(leaf(0), &mut append).unwrap();
        }
        assert_eq!(
            builder.finish(&mut append).unwrap(),
            (count == 1).then(|| leaf(0))
        );
    }
}

#[test]
fn promotion_boundaries_never_emit_singleton_or_overfull_branches() {
    for capacity in [BRANCH_CAPACITY] {
        let mut counts = vec![2, capacity, capacity + 1, capacity + 2];
        for power in [2, 3] {
            let boundary = capacity.pow(power);
            counts.extend([boundary - 1, boundary, boundary + 1, boundary + 2]);
        }
        for count in counts {
            let mut ordinal = 0;
            let mut append = |children: &[PageRef]| {
                assert!((2..=capacity).contains(&children.len()));
                branch(children, &mut ordinal)
            };
            let mut builder = BranchBuilder::default();
            for index in 0..count {
                builder.push_leaf(leaf(index as u64), &mut append).unwrap();
                assert!(
                    builder
                        .levels
                        .iter()
                        .all(|pages| pages.len() <= capacity + 1)
                );
                assert!(builder.levels.len() <= u64::BITS as usize);
            }
            let root = builder.finish(&mut append).unwrap().unwrap();
            assert_eq!(
                root.extent_count().get(),
                count as u64,
                "capacity={capacity}, count={count}"
            );
            assert_eq!(root.range().start(), 0);
            assert_eq!(root.range().end(), (count as u64 - 1) * 2 + 1);
        }
    }
}

#[test]
fn rejects_overlapping_reversed_or_nonleaf_input() {
    let mut ordinal = 0;
    let mut append = |children: &[PageRef]| branch(children, &mut ordinal);
    let mut builder = BranchBuilder::default();
    builder.push_leaf(leaf(1), &mut append).unwrap();
    assert!(builder.push_leaf(leaf(1), &mut append).is_err());
    assert!(builder.push_leaf(leaf(0), &mut append).is_err());
    let parent = branch(&[leaf(2), leaf(3)], &mut 0).unwrap();
    assert!(builder.push_leaf(parent, &mut append).is_err());
}

#[test]
fn propagates_writer_failure_and_rejects_unbound_parent() {
    for corrupt in [false, true] {
        let mut builder = BranchBuilder::default();
        let mut append = |_: &[PageRef]| {
            if corrupt {
                Ok(leaf(100))
            } else {
                Err(io::Error::other("injected page write failure"))
            }
        };
        builder.push_leaf(leaf(0), &mut append).unwrap();
        builder.push_leaf(leaf(1), &mut append).unwrap();
        let error = builder.finish(&mut append).unwrap_err();
        assert_eq!(
            error.kind(),
            if corrupt {
                io::ErrorKind::InvalidData
            } else {
                io::ErrorKind::Other
            }
        );
    }
}
