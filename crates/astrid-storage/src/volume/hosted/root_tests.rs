use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom};
use std::sync::Arc;

use super::reclaim::{ReclaimStage, set_stage_hook};
use super::tests::append_valid_record;
use super::{
    COMMIT_REGION, Extent, HostedFileVolume, Operation, RECORD_FIXED_BYTES, ROOT_BYTES,
    ROOT_SLOT_BYTES, RegionState, VOLUME_MAGIC, VolumeRegion, recover,
};
use crate::volume::AstridVolume;

fn seeded_volume(path: &std::path::Path) -> Arc<HostedFileVolume> {
    let volume = HostedFileVolume::open(path).unwrap();
    let region = VolumeRegion::new("objects").unwrap();
    volume.create_region(&region, true).unwrap();
    volume
        .write_region_at(&region, 0, &vec![0xAA; 256 * 1024])
        .unwrap();
    volume.write_region_at(&region, 0, b"small").unwrap();
    volume.set_region_len(&region, 5).unwrap();
    volume.sync().unwrap();
    volume
}

fn snapshot_reclaim_at(stage: ReclaimStage) -> (tempfile::TempDir, std::path::PathBuf) {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("astrid.volume");
    let snapshot = temporary.path().join(format!(
        "snapshot-{}",
        match stage {
            ReclaimStage::BoundImagePublished => "bound-root",
            ReclaimStage::ReplacementDurable => "unflipped",
            ReclaimStage::RootPublished => "replacement-root",
            ReclaimStage::FinalImageDurable => "final-image",
            ReclaimStage::FinalRootPublished => "final-root",
            ReclaimStage::Truncated => "truncated",
        }
    ));
    let volume = seeded_volume(&path);
    let source = path.clone();
    let target = snapshot.clone();
    set_stage_hook(
        path.clone(),
        Box::new(move |seen| {
            if seen == stage {
                std::fs::copy(&source, &target)?;
            }
            Ok(())
        }),
    );
    let reclaiming = Arc::clone(&volume);
    let result = std::thread::spawn(move || reclaiming.reclaim_same_inode())
        .join()
        .unwrap();
    result.unwrap();
    assert!(snapshot.exists(), "reclaim did not reach {stage:?}");
    (temporary, snapshot)
}

fn read_objects(volume: &HostedFileVolume) -> [u8; 5] {
    let region = VolumeRegion::new("objects").unwrap();
    let mut bytes = [0_u8; 5];
    volume.read_region_at(&region, 0, &mut bytes).unwrap();
    bytes
}

#[test]
fn inode_stable_reclaim_shrinks_the_selected_generation() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("astrid.volume");
    let volume = seeded_volume(&path);
    let before = std::fs::metadata(&path).unwrap().len();
    volume.reclaim_same_inode().unwrap();
    let after = std::fs::metadata(&path).unwrap().len();
    assert!(after < before, "{before} did not shrink to {after}");
    assert_eq!(read_objects(&volume), *b"small");
    drop(volume);
    let reopened = HostedFileVolume::open(&path).unwrap();
    assert_eq!(read_objects(&reopened), *b"small");
}

#[test]
fn same_inode_reclaim_preserves_an_empty_volume() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("astrid.volume");
    let volume = HostedFileVolume::open(&path).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 8);
    volume.reclaim_same_inode().unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 8);
    assert_eq!(volume.list_regions("").unwrap(), Vec::new());
    drop(volume);
    let reopened = HostedFileVolume::open(&path).unwrap();
    assert_eq!(reopened.list_regions("").unwrap(), Vec::new());
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 8);
}

#[test]
fn released_reclaim_after_same_inode_stays_generation_zero() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("astrid.volume");
    let region = VolumeRegion::new("objects").unwrap();
    let volume = seeded_volume(&path);
    volume.reclaim_same_inode().unwrap();
    volume.reclaim().unwrap();
    drop(volume);

    let mut file = OpenOptions::new().read(true).open(&path).unwrap();
    let recovered = recover::recover_container(&mut file).unwrap();
    assert_eq!(recovered.generation, 0);
    for slot_offset in [
        VOLUME_MAGIC.len(),
        ROOT_BYTES.checked_sub(ROOT_SLOT_BYTES).unwrap(),
    ] {
        file.seek(SeekFrom::Start(slot_offset as u64)).unwrap();
        let mut magic = [0; ROOT_SLOT_BYTES - 32];
        file.read_exact(&mut magic).unwrap();
        assert_ne!(&magic[..super::ROOT_MAGIC.len()], &super::ROOT_MAGIC);
    }
    drop(file);

    let volume = HostedFileVolume::open(&path).unwrap();
    volume.write_region_at(&region, 0, b"after").unwrap();
    volume.sync().unwrap();
    drop(volume);
    let reopened = HostedFileVolume::open(&path).unwrap();
    let mut bytes = [0; 5];
    reopened.read_region_at(&region, 0, &mut bytes).unwrap();
    assert_eq!(&bytes, b"after");
    drop(reopened);

    let mut file = OpenOptions::new().read(true).open(&path).unwrap();
    assert_eq!(recover::recover_container(&mut file).unwrap().generation, 0);
}

#[test]
fn generation_root_recovers_after_uncommitted_tail() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("astrid.volume");
    let region = VolumeRegion::new("objects").unwrap();
    let volume = seeded_volume(&path);
    volume.reclaim_same_inode().unwrap();
    let mut file = OpenOptions::new().read(true).open(&path).unwrap();
    let selected = recover::recover_container(&mut file).unwrap();
    drop(file);
    assert!(selected.generation > 0);
    let authority_len = selected.authority_len;

    volume
        .detach_after_uncommitted_write_for_test(&region, b"pending")
        .unwrap();
    drop(volume);
    assert!(std::fs::metadata(&path).unwrap().len() > authority_len);

    let reopened = HostedFileVolume::open(&path).unwrap();
    assert_eq!(read_objects(&reopened), *b"small");
    assert_eq!(std::fs::metadata(&path).unwrap().len(), authority_len);
}

#[test]
fn generation_root_stream_append_preserves_named_footer() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("astrid.volume");
    let region = VolumeRegion::new("objects").unwrap();
    let volume = seeded_volume(&path);
    volume.reclaim_same_inode().unwrap();
    let mut file = OpenOptions::new().read(true).open(&path).unwrap();
    let selected = recover::recover_container(&mut file).unwrap();
    let authority_len = selected.authority_len;
    let footer_offset = authority_len - u64::try_from(recover::FOOTER_BYTES).unwrap();
    file.seek(SeekFrom::Start(footer_offset)).unwrap();
    let mut footer_before = [0; recover::FOOTER_BYTES];
    file.read_exact(&mut footer_before).unwrap();
    drop(file);

    let payload = b"streamed";
    volume
        .write_region_from(
            &region,
            0,
            u64::try_from(payload.len()).unwrap(),
            &mut payload.as_slice(),
        )
        .unwrap();
    volume.detach_for_test().unwrap();
    drop(volume);

    assert!(std::fs::metadata(&path).unwrap().len() > authority_len);
    let mut file = OpenOptions::new().read(true).open(&path).unwrap();
    file.seek(SeekFrom::Start(footer_offset)).unwrap();
    let mut footer_after = [0; recover::FOOTER_BYTES];
    file.read_exact(&mut footer_after).unwrap();
    assert_eq!(footer_after, footer_before);
    drop(file);

    let reopened = HostedFileVolume::open(&path).unwrap();
    let mut bytes = [0; 5];
    reopened.read_region_at(&region, 0, &mut bytes).unwrap();
    assert_eq!(&bytes, b"small");
    assert_eq!(std::fs::metadata(&path).unwrap().len(), authority_len);
}

#[test]
fn same_generation_stale_pointer_does_not_block_new_root() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("astrid.volume");
    let region = VolumeRegion::new("objects").unwrap();
    let volume = seeded_volume(&path);
    volume.reclaim_same_inode().unwrap();
    let mut file = OpenOptions::new().read(true).open(&path).unwrap();
    let selected = recover::recover_container(&mut file).unwrap();
    let stale_footer = selected.durable_len;
    let stale_root_base = selected.root_base;
    drop(file);

    volume.write_region_at(&region, 0, b"new").unwrap();
    volume.sync().unwrap();
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let selected = recover::recover_container(&mut file).unwrap();
    let generation = selected.generation;
    let root_base = selected.root_base;
    assert!(selected.durable_len > stale_footer);

    // Reproduce the crash point at which the first (slot-zero) copy names the
    // new footer while its same-generation sibling still names the old one.
    recover::write_root_pointer(&mut file, generation, stale_root_base, stale_footer, true)
        .unwrap();
    file.sync_all().unwrap();
    drop(file);
    volume.detach_for_test().unwrap();
    drop(volume);

    let reopened = HostedFileVolume::open(&path).unwrap();
    let mut bytes = [0_u8; 3];
    reopened.read_region_at(&region, 0, &mut bytes).unwrap();
    assert_eq!(&bytes, b"new");
    assert!(
        !recover::recover_container(&mut OpenOptions::new().read(true).open(&path).unwrap())
            .unwrap()
            .pointer_slot
    );
    assert_eq!(root_base, stale_root_base);
}

#[test]
fn unrecoverable_higher_generation_pointer_does_not_block_older_root() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("astrid.volume");
    let volume = seeded_volume(&path);
    volume.reclaim_same_inode().unwrap();
    drop(volume);

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let lower = recover::recover_container(&mut file).unwrap();
    let lower_generation = lower.generation;
    let lower_footer = lower.durable_len;
    let root_base = lower.root_base;
    let fake_footer = file.metadata().unwrap().len();
    recover::write_footer(
        &mut file,
        lower.last_commit_offset,
        fake_footer,
        lower.sequence,
    )
    .unwrap();
    recover::write_root_pointer(
        &mut file,
        lower_generation
            .checked_add(1)
            .expect("test generation fits u64"),
        root_base,
        fake_footer,
        false,
    )
    .unwrap();
    file.sync_all().unwrap();
    drop(file);

    let reopened = HostedFileVolume::open(&path).unwrap();
    assert_eq!(read_objects(&reopened), *b"small");
    let mut file = OpenOptions::new().read(true).open(&path).unwrap();
    let selected = recover::recover_container(&mut file).unwrap();
    assert_eq!(selected.generation, lower_generation);
    assert!(selected.pointer_slot);
    assert_eq!(selected.durable_len, lower_footer);
}

#[test]
fn unflipped_replacement_image_leaves_the_old_generation_current() {
    let (temporary, snapshot) = snapshot_reclaim_at(ReclaimStage::ReplacementDurable);
    let physical_len = std::fs::metadata(&snapshot).unwrap().len();
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&snapshot)
        .unwrap();
    let recovery = recover::recover_container(&mut file).unwrap();
    // Generation one is the durable copy of the pre-reclaim image. The
    // replacement's footer is beyond that selected authority, so an EOF scan
    // cannot silently promote it before its own root flip.
    assert_eq!(recovery.generation, 1);
    assert!(recovery.root_base < recovery.last_commit_offset);
    assert!(physical_len > recovery.authority_len);
    let volume = HostedFileVolume::open(&snapshot).unwrap();
    assert_eq!(read_objects(&volume), *b"small");
    assert_eq!(
        std::fs::metadata(&snapshot).unwrap().len(),
        recovery.authority_len
    );
    drop(volume);
    assert_eq!(temporary.path().read_dir().unwrap().count(), 2);
}

#[test]
fn replacement_root_is_selected_before_the_final_image_exists() {
    let (temporary, snapshot) = snapshot_reclaim_at(ReclaimStage::RootPublished);
    let volume = HostedFileVolume::open(snapshot).unwrap();
    assert_eq!(read_objects(&volume), *b"small");
    drop(volume);
    assert_eq!(temporary.path().read_dir().unwrap().count(), 2);
}

#[test]
fn durable_final_image_is_ignored_until_its_root_is_selected() {
    let (temporary, snapshot) = snapshot_reclaim_at(ReclaimStage::FinalImageDurable);
    let volume = HostedFileVolume::open(snapshot).unwrap();
    assert_eq!(read_objects(&volume), *b"small");
    drop(volume);
    assert_eq!(temporary.path().read_dir().unwrap().count(), 2);
}

#[test]
fn selected_final_root_survives_until_truncate_completes() {
    let (temporary, flipped) = snapshot_reclaim_at(ReclaimStage::FinalRootPublished);
    let untruncated = std::fs::metadata(&flipped).unwrap().len();
    let volume = HostedFileVolume::open(flipped).unwrap();
    assert_eq!(read_objects(&volume), *b"small");
    drop(volume);
    let (complete_temporary, complete) = snapshot_reclaim_at(ReclaimStage::Truncated);
    let truncated = std::fs::metadata(&complete).unwrap().len();
    assert!(truncated < untruncated, "{untruncated} -> {truncated}");
    assert_eq!(temporary.path().read_dir().unwrap().count(), 2);
    assert_eq!(complete_temporary.path().read_dir().unwrap().count(), 2);
}

#[test]
fn torn_root_candidates_are_not_admitted_as_authority() {
    let (_temporary, snapshot) = snapshot_reclaim_at(ReclaimStage::Truncated);
    let mut bytes = std::fs::read(&snapshot).unwrap();
    // Damage the checksum in each fixed root copy. Neither byte sequence can
    // masquerade as generation zero, and the EOF footer alone is no longer a
    // root authority once a generation pointer has existed.
    bytes[VOLUME_MAGIC.len() + ROOT_SLOT_BYTES - 1] ^= 0x80;
    bytes[ROOT_BYTES - 1] ^= 0x80;
    std::fs::write(&snapshot, bytes).unwrap();
    let error = HostedFileVolume::open(snapshot).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert!(
        error
            .to_string()
            .contains("invalid Astrid volume root pointer"),
        "{error}"
    );
}

#[test]
fn higher_valid_root_generation_wins() {
    let (_temporary, snapshot) = snapshot_reclaim_at(ReclaimStage::Truncated);
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&snapshot)
        .unwrap();
    let footer_offset = file.metadata().unwrap().len() - recover::FOOTER_BYTES as u64;
    recover::write_root_pointer(&mut file, 9, ROOT_BYTES as u64, footer_offset, false).unwrap();
    recover::write_root_pointer(&mut file, 7, ROOT_BYTES as u64, footer_offset, true).unwrap();
    file.sync_all().unwrap();
    let volume = HostedFileVolume::open(snapshot).unwrap();
    assert_eq!(read_objects(&volume), *b"small");
}

#[test]
fn generation_zero_eof_footer_remains_recoverable_and_reclaimable() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("astrid.volume");
    std::fs::write(&path, VOLUME_MAGIC).unwrap();
    append_valid_record(&path, 1, Operation::Create, b"objects", 0, &[]);
    append_valid_record(&path, 2, Operation::Write, b"objects", 0, b"small");
    append_valid_record(
        &path,
        3,
        Operation::Commit,
        COMMIT_REGION.as_bytes(),
        0,
        &encode_region_snapshot_for_test(
            VOLUME_MAGIC.len() as u64
                + 2 * u64::try_from(RECORD_FIXED_BYTES + b"objects".len()).unwrap(),
        ),
    );
    let durable_len = std::fs::metadata(&path).unwrap().len();
    let snapshot = encode_region_snapshot_for_test(
        VOLUME_MAGIC.len() as u64
            + 2 * u64::try_from(RECORD_FIXED_BYTES + b"objects".len()).unwrap(),
    );
    let commit_length = RECORD_FIXED_BYTES + b"system/volume-commit".len() + snapshot.len();
    let commit_offset = durable_len - u64::try_from(commit_length).unwrap();
    {
        let mut file = OpenOptions::new().write(true).open(&path).unwrap();
        recover::write_footer(&mut file, commit_offset, durable_len, 3).unwrap();
        file.sync_all().unwrap();
    }
    let volume = HostedFileVolume::open(&path).unwrap();
    assert_eq!(read_objects(&volume), *b"small");
    drop(volume);
    let reopened = HostedFileVolume::open(&path).unwrap();
    assert_eq!(read_objects(&reopened), *b"small");
}

#[test]
fn receipt_region_survives_all_same_inode_reclaim_stages() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("astrid.volume");
    let volume = seeded_volume(&path);
    let receipt = VolumeRegion::new("system/gc-outbox/receipt.ready").unwrap();
    volume.create_region(&receipt, true).unwrap();
    volume.write_region_at(&receipt, 0, b"proof").unwrap();
    volume.sync().unwrap();
    volume.reclaim_same_inode().unwrap();
    let mut proof = [0_u8; 5];
    volume.read_region_at(&receipt, 0, &mut proof).unwrap();
    assert_eq!(&proof, b"proof");
    drop(volume);
    let reopened = HostedFileVolume::open(&path).unwrap();
    reopened.read_region_at(&receipt, 0, &mut proof).unwrap();
    assert_eq!(&proof, b"proof");
}

#[test]
fn physical_credit_waits_until_the_final_root_and_truncate() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("astrid.volume");
    let volume = seeded_volume(&path);
    let before = std::fs::metadata(&path).unwrap().len();
    let source = path.clone();
    set_stage_hook(
        path.clone(),
        Box::new(move |stage| {
            let current = std::fs::metadata(&source).unwrap().len();
            match stage {
                ReclaimStage::ReplacementDurable
                | ReclaimStage::BoundImagePublished
                | ReclaimStage::RootPublished
                | ReclaimStage::FinalImageDurable
                | ReclaimStage::FinalRootPublished => assert!(current >= before),
                ReclaimStage::Truncated => assert!(current < before),
            }
            Ok(())
        }),
    );
    volume.reclaim_same_inode().unwrap();
    let available = volume.available_space().unwrap().expect("host capacity");
    assert!(available > 0);
}

fn encode_region_snapshot_for_test(physical_offset: u64) -> Vec<u8> {
    let mut regions = BTreeMap::new();
    regions.insert(
        VolumeRegion::new("objects").unwrap(),
        RegionState {
            length: 5,
            extents: BTreeMap::from([(
                0,
                Extent {
                    logical_end: 5,
                    physical_offset,
                },
            )]),
        },
    );
    recover::encode_region_snapshot(&regions).unwrap()
}
