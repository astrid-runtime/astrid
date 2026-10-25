use super::*;

fn row(ordinal: u64) -> Row {
    Row {
        object: ObjectId::new([1; 32]),
        ordinal,
        representation: RepresentationRecordId::new(
            *blake3::hash(&ordinal.to_le_bytes()).as_bytes(),
        ),
    }
}
fn run() -> Run {
    let mut writer = Writer::new().unwrap();
    for ordinal in 0..8 {
        writer.push(row(ordinal)).unwrap();
    }
    writer.finish().unwrap()
}
fn consume(run: Run) -> Result<Vec<Row>, DurableError> {
    let mut reader = run.reader();
    let mut rows = Vec::new();
    while let Some(row) = reader.next()? {
        rows.push(row);
    }
    Ok(rows)
}
#[test]
fn sorted_runs_reject_body_changes_truncation_and_extra_bytes() {
    for damage in 0..3 {
        let mut run = run();
        match damage {
            0 => {
                run.file.seek(SeekFrom::Start(40)).unwrap();
                run.file.write_all(&[0x99]).unwrap();
            },
            1 => run.file.set_len(ROW_BYTES as u64).unwrap(),
            _ => {
                run.file.seek(SeekFrom::End(0)).unwrap();
                run.file.write_all(&[1]).unwrap();
            },
        }
        run.file.seek(SeekFrom::Start(0)).unwrap();
        assert!(consume(run).is_err());
    }
}
#[test]
fn sorted_run_order_and_merge_preserve_every_ordinal() {
    let mut left = Writer::new().unwrap();
    let mut right = Writer::new().unwrap();
    for n in 0..16 {
        if n % 2 == 0 {
            left.push(row(n)).unwrap();
        } else {
            right.push(row(n)).unwrap();
        }
    }
    let merged = left
        .finish()
        .unwrap()
        .merge(right.finish().unwrap())
        .unwrap();
    assert_eq!(
        consume(merged).unwrap(),
        (0..16).map(row).collect::<Vec<_>>()
    );
    let mut duplicate = Writer::new().unwrap();
    duplicate.push(row(0)).unwrap();
    let mut changed = row(0);
    changed.representation = RepresentationRecordId::new([7; 32]);
    assert!(duplicate.push(changed).is_err());
}
#[test]
fn merge_cannot_publish_a_damaged_input() {
    let damaged = run();
    damaged.file.set_len(0).unwrap();
    let mut other = Writer::new().unwrap();
    other.push(row(9)).unwrap();
    assert!(damaged.merge(other.finish().unwrap()).is_err());
}
