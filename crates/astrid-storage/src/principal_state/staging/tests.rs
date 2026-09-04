use std::io::{Read as _, Seek as _, Write as _};
use std::sync::Barrier;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::time::{Duration, Instant};

use astrid_core::identity::PrincipalUid;
use astrid_core::principal::PrincipalId;
use uuid::Uuid;

use super::format::{
    LegacyStagingIntent, LegacyStagingOwner, StagingIntent, decode_intent, decode_legacy_intent,
    encode_intent, encode_legacy_intent, load_intent,
};
use super::journal::{
    JournalRecord, StageKey, append_records, encoded_frame, flush_journal, refresh_frame_checksum,
};
use super::recovery::{read_directory, retired_generation_name};
use super::*;
use crate::principal_state::native_io::{atomic_write, create_private_file, sync_directory};

fn write_private_file(path: &Path, bytes: &[u8]) {
    let mut file = create_private_file(path).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

fn uid() -> PrincipalUid {
    let digest = blake3::Hasher::new_derive_key("astrid staging owner test fixture v1")
        .update(b"alice")
        .finalize();
    PrincipalUid::from_bytes(*digest.as_bytes())
}

fn owner() -> StateOwner {
    StateOwner::Principal(uid())
}

#[cfg(test)]
mod publication_tests;

#[test]
fn public_staging_handles_remain_unwind_safe() {
    fn assert_unwind_safe<T: std::panic::RefUnwindSafe + std::panic::UnwindSafe>() {}

    assert_unwind_safe::<NativeContentStagingArea>();
    assert_unwind_safe::<StagedContentWriter>();
}

fn open_area(path: &Path) -> NativeContentStagingArea {
    open_area_result(path).unwrap()
}

fn open_area_result(path: &Path) -> StorageResult<NativeContentStagingArea> {
    NativeContentStagingArea::open_with_group_commit_policy(path, GroupCommitPolicy::immediate())
}

fn writer(area: &NativeContentStagingArea, name: &str) -> StagedContentWriter {
    area.begin(
        owner(),
        ContentName::new(name).unwrap(),
        ChunkingProfile::ASTRID_V1,
    )
    .unwrap()
}

#[test]
fn begin_collision_preserves_the_existing_generation() {
    let directory = tempfile::tempdir().unwrap();
    let area = open_area(directory.path());
    let id = StagedContentId(Uuid::from_u128(42));
    let path = area.inner.generations.join(open_generation_name(id));
    std::fs::write(&path, b"other writer's bytes").unwrap();

    let error = area
        .begin_with_id(
            owner(),
            ContentName::new("collision.bin").unwrap(),
            ChunkingProfile::ASTRID_V1,
            id,
        )
        .unwrap_err();

    assert!(error.to_string().contains("create private file"));
    assert_eq!(std::fs::read(path).unwrap(), b"other writer's bytes");
}

#[test]
fn begin_rejects_identifier_reserved_by_a_sealed_generation() {
    let directory = tempfile::tempdir().unwrap();
    let area = open_area(directory.path());
    let id = StagedContentId(Uuid::from_u128(43));
    let mut first = area
        .begin_with_id(
            owner(),
            ContentName::new("first.bin").unwrap(),
            ChunkingProfile::ASTRID_V1,
            id,
        )
        .unwrap();
    first.write_all(b"sealed bytes").unwrap();
    let sealed = first.seal().unwrap();

    let error = area
        .begin_with_id(
            owner(),
            ContentName::new("second.bin").unwrap(),
            ChunkingProfile::ASTRID_V1,
            id,
        )
        .unwrap_err();

    assert!(error.to_string().contains("already reserved"), "{error}");
    assert_eq!(read_logical(&sealed), b"sealed bytes");
    assert_eq!(area.ready().unwrap(), vec![sealed]);
}

#[test]
fn sealed_generation_rejects_a_replaced_directory_entry() {
    let directory = tempfile::tempdir().unwrap();
    let area = open_area(directory.path());
    let mut staged = writer(&area, "identity-bound.bin");
    staged.write_all(b"identity-bound bytes").unwrap();
    let sealed = staged.seal().unwrap();
    let path = sealed.content_path();
    let displaced = path.with_extension("displaced");
    std::fs::rename(&path, &displaced).unwrap();
    std::fs::copy(&displaced, &path).unwrap();

    let error = area.ready().unwrap_err();
    assert!(
        error.to_string().contains("source identity changed"),
        "{error}"
    );
    assert_eq!(
        std::fs::read(displaced).unwrap(),
        std::fs::read(path).unwrap()
    );
}

#[test]
fn sealed_generation_rejects_a_rewritten_source_identity() {
    let directory = tempfile::tempdir().unwrap();
    let area = open_area(directory.path());
    let mut staged = writer(&area, "identity-checksum.bin");
    staged.write_all(b"identity-checksum bytes").unwrap();
    let sealed = staged.seal().unwrap();
    let path = sealed.content_path();
    let mut bytes = std::fs::read(&path).unwrap();
    let identity_offset = bytes.len() - 32 - 32 - 16;
    bytes[identity_offset] ^= 0x80;
    std::fs::write(&path, bytes).unwrap();

    let error = area.ready().unwrap_err();
    assert!(
        error
            .to_string()
            .contains("source binding checksum mismatch"),
        "{error}"
    );
}

#[cfg(unix)]
#[test]
fn seal_stays_bound_to_the_opened_generation_directory() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("staging");
    let displaced_root = directory.path().join("original-staging");
    let area = open_area(&root);
    let mut staged = writer(&area, "directory-bound.bin");
    staged.write_all(b"directory-bound bytes").unwrap();
    let id = staged.id();
    let open_name = open_generation_name(id);

    std::fs::rename(&root, &displaced_root).unwrap();
    let replacement_generations = root.join(GENERATIONS_DIRECTORY);
    std::fs::create_dir_all(&replacement_generations).unwrap();
    let original_open = displaced_root.join(GENERATIONS_DIRECTORY).join(&open_name);
    let replacement_open = replacement_generations.join(&open_name);
    std::fs::hard_link(&original_open, &replacement_open).unwrap();

    let sealed = staged.seal().unwrap();
    let sealed_name = sealed_generation_name(sealed.sequence, id);
    let original_sealed = displaced_root
        .join(GENERATIONS_DIRECTORY)
        .join(&sealed_name);
    assert!(original_sealed.is_file());
    assert!(!original_open.exists());
    assert!(replacement_open.is_file());
    assert!(!replacement_generations.join(&sealed_name).exists());

    let replacement_sealed = replacement_generations.join(&sealed_name);
    std::fs::hard_link(&original_sealed, &replacement_sealed).unwrap();
    let key = StageKey {
        sequence: sealed.sequence,
        id,
    };
    retirement::establish_in(&area.inner.generations_directory, key).unwrap();
    let retired_name = retired_generation_name(key.sequence, key.id);
    let original_retired = displaced_root
        .join(GENERATIONS_DIRECTORY)
        .join(&retired_name);
    assert!(original_retired.is_file());
    assert!(!original_sealed.exists());
    assert!(replacement_sealed.is_file());
    assert!(!replacement_generations.join(&retired_name).exists());

    retirement::remove_in(&area.inner.generations_directory, key).unwrap();
    assert!(!original_retired.exists());
    assert!(replacement_sealed.is_file());
}

#[test]
fn dropping_an_unsealed_writer_releases_its_identifier() {
    let directory = tempfile::tempdir().unwrap();
    let area = open_area(directory.path());
    let id = StagedContentId(Uuid::from_u128(44));
    drop(
        area.begin_with_id(
            owner(),
            ContentName::new("abandoned.bin").unwrap(),
            ChunkingProfile::ASTRID_V1,
            id,
        )
        .unwrap(),
    );

    assert!(
        area.begin_with_id(
            owner(),
            ContentName::new("replacement.bin").unwrap(),
            ChunkingProfile::ASTRID_V1,
            id,
        )
        .is_ok()
    );
}

#[test]
fn reaped_identifier_stays_reserved_until_the_journal_is_drained() {
    let directory = tempfile::tempdir().unwrap();
    let area = open_area(directory.path());
    let first_id = StagedContentId(Uuid::from_u128(45));
    let second_id = StagedContentId(Uuid::from_u128(46));
    let mut first = area
        .begin_with_id(
            owner(),
            ContentName::new("first.bin").unwrap(),
            ChunkingProfile::ASTRID_V1,
            first_id,
        )
        .unwrap();
    first.write_all(b"first").unwrap();
    let first = first.seal().unwrap();
    let mut second = area
        .begin_with_id(
            owner(),
            ContentName::new("second.bin").unwrap(),
            ChunkingProfile::ASTRID_V1,
            second_id,
        )
        .unwrap();
    second.write_all(b"second").unwrap();
    let second = second.seal().unwrap();

    area.mark_published(&first).unwrap();
    let error = area
        .begin_with_id(
            owner(),
            ContentName::new("still-reserved.bin").unwrap(),
            ChunkingProfile::ASTRID_V1,
            first_id,
        )
        .unwrap_err();
    assert!(error.to_string().contains("already reserved"), "{error}");

    area.mark_published(&second).unwrap();
    assert!(
        area.begin_with_id(
            owner(),
            ContentName::new("reusable.bin").unwrap(),
            ChunkingProfile::ASTRID_V1,
            first_id,
        )
        .is_ok()
    );
}

fn wait_for_queued_seals(area: &NativeContentStagingArea, expected: usize) {
    let started = Instant::now();
    while area.queued_seal_count() < expected {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "timed out waiting for {expected} queued seals"
        );
        std::thread::yield_now();
    }
}

fn read_logical(staged: &ReadyStagedContent) -> Vec<u8> {
    let mut bytes = Vec::new();
    open_private_file(&staged.content_path())
        .unwrap()
        .take(staged.logical_bytes())
        .read_to_end(&mut bytes)
        .unwrap();
    bytes
}

#[derive(Debug)]
struct FailOnce {
    point: StagingFaultPoint,
    fired: AtomicBool,
}

#[cfg(unix)]
#[derive(Debug)]
struct ReplaceRootAt {
    point: StagingFaultPoint,
    root: PathBuf,
    displaced: PathBuf,
    fired: AtomicBool,
}

#[derive(Debug)]
struct BarrierAt {
    point: StagingFaultPoint,
    barrier: Arc<Barrier>,
}

#[derive(Debug)]
struct PauseAt {
    point: StagingFaultPoint,
    reached: Arc<Barrier>,
    release: Arc<Barrier>,
}

#[derive(Debug)]
struct PauseFirstAt {
    point: StagingFaultPoint,
    fired: AtomicBool,
    reached: Arc<Barrier>,
    release: Arc<Barrier>,
}

impl StagingFaultInjector for BarrierAt {
    fn fail(&self, point: StagingFaultPoint) -> StorageResult<()> {
        if point == self.point {
            self.barrier.wait();
        }
        Ok(())
    }
}

impl StagingFaultInjector for PauseAt {
    fn fail(&self, point: StagingFaultPoint) -> StorageResult<()> {
        if point == self.point {
            self.reached.wait();
            self.release.wait();
        }
        Ok(())
    }
}

impl StagingFaultInjector for PauseFirstAt {
    fn fail(&self, point: StagingFaultPoint) -> StorageResult<()> {
        if point == self.point && !self.fired.swap(true, AtomicOrdering::SeqCst) {
            self.reached.wait();
            self.release.wait();
        }
        Ok(())
    }
}

impl StagingFaultInjector for FailOnce {
    fn fail(&self, point: StagingFaultPoint) -> StorageResult<()> {
        if point == self.point && !self.fired.swap(true, AtomicOrdering::SeqCst) {
            Err(connection(format!("injected staging fault at {point:?}")))
        } else {
            Ok(())
        }
    }
}

#[cfg(unix)]
impl StagingFaultInjector for ReplaceRootAt {
    fn fail(&self, point: StagingFaultPoint) -> StorageResult<()> {
        if point == self.point && !self.fired.swap(true, AtomicOrdering::SeqCst) {
            std::fs::rename(&self.root, &self.displaced).unwrap();
            std::fs::create_dir(&self.root).unwrap();
            std::fs::create_dir(self.root.join(GENERATIONS_DIRECTORY)).unwrap();
            std::fs::create_dir(self.root.join(QUARANTINE_DIRECTORY)).unwrap();
        }
        Ok(())
    }
}

fn open_with_fault(path: &Path, point: StagingFaultPoint) -> NativeContentStagingArea {
    NativeContentStagingArea::open_configured(
        path.to_path_buf(),
        GroupCommitPolicy::immediate(),
        Arc::new(FailOnce {
            point,
            fired: AtomicBool::new(false),
        }),
    )
    .unwrap()
}

#[test]
fn intent_round_trips_and_rejects_corruption() {
    let intent = StagingIntent {
        sequence: 7,
        id: StagedContentId(Uuid::parse_str("86c54e54-a944-41d2-8bf1-28be44985973").unwrap()),
        owner: owner(),
        name: ContentName::new("projects/game/assets.bin").unwrap(),
        profile: ChunkingProfile::ASTRID_V1,
        logical_bytes: 98_765,
    };
    let bytes = encode_intent(&intent).unwrap();
    assert_eq!(
        hex::encode(&bytes),
        "4153545249442d53544147452d5632000200070000000000000086c54e54a94441d28bf128be44985973210000000000000001003243b2489c6f911b35f55a12ad27bdfc996669c927d65548321c51bf48b6c5180000000000000070726f6a656374732f67616d652f6173736574732e62696e010100010040000000000100000004000000000000000000cd81010000000000b5cd550559ff256d340253488186ad0c240c07eb2e244205e2445356353706e2"
    );
    assert_eq!(decode_intent(&bytes).unwrap(), intent);

    let mut corrupt = bytes;
    corrupt[24] ^= 0x80;
    assert_eq!(
        decode_intent(&corrupt),
        Err("staged intent checksum mismatch")
    );
}

#[test]
fn alias_intent_migration_is_crash_idempotent_and_reaches_the_flat_journal() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let writing = root.join(legacy::WRITING_DIRECTORY);
    let ready = root.join(legacy::READY_DIRECTORY);
    let quarantine = root.join(QUARANTINE_DIRECTORY);
    for path in [&writing, &ready, &quarantine] {
        std::fs::create_dir_all(path).unwrap();
    }
    let malformed_id = StagedContentId(Uuid::new_v4());
    let malformed = writing.join(malformed_id.to_string());
    std::fs::write(&malformed, b"not a legacy staging directory").unwrap();

    let id = StagedContentId(Uuid::new_v4());
    let staging_directory = writing.join(id.to_string());
    std::fs::create_dir(&staging_directory).unwrap();
    write_private_file(
        &staging_directory.join(legacy::CONTENT_FILE),
        b"durable staged bytes",
    );
    let legacy_intent = LegacyStagingIntent {
        sequence: 4,
        id,
        owner: LegacyStagingOwner::Principal(PrincipalId::new("alice").unwrap()),
        name: ContentName::new("projects/game/save.bin").unwrap(),
        profile: ChunkingProfile::ASTRID_V1,
        logical_bytes: 20,
    };
    atomic_write(
        &staging_directory.join(migration::LEGACY_INTENT_FILE),
        &encode_legacy_intent(&legacy_intent).unwrap(),
    )
    .unwrap();
    let migrated = StagingIntent {
        sequence: legacy_intent.sequence,
        id,
        owner: owner(),
        name: legacy_intent.name,
        profile: legacy_intent.profile,
        logical_bytes: legacy_intent.logical_bytes,
    };
    atomic_write(
        &staging_directory.join(legacy::INTENT_FILE),
        &encode_intent(&migrated).unwrap(),
    )
    .unwrap();

    migrate_alias_owner_intents(root, |alias| {
        assert_eq!(alias.as_str(), "alice");
        Ok(uid())
    })
    .unwrap();
    migrate_alias_owner_intents(root, |_| {
        panic!("an already-migrated intent must not be resolved twice")
    })
    .unwrap();

    assert!(
        !staging_directory
            .join(migration::LEGACY_INTENT_FILE)
            .exists()
    );
    assert_eq!(
        decode_intent(&std::fs::read(staging_directory.join(legacy::INTENT_FILE)).unwrap())
            .unwrap(),
        migrated
    );
    let reopened = open_area(root);
    let entries = reopened.ready().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].owner(), &owner());
    assert_eq!(read_logical(&entries[0]), b"durable staged bytes");
    assert!(!malformed.exists());
    assert!(
        quarantine
            .join(format!("{malformed_id}.legacy-unsealed.0"))
            .exists()
    );
}

#[test]
fn conflicting_alias_intents_fail_before_any_entry_is_migrated() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let writing = root.join(legacy::WRITING_DIRECTORY);
    let ready = root.join(legacy::READY_DIRECTORY);
    std::fs::create_dir_all(&writing).unwrap();
    std::fs::create_dir_all(&ready).unwrap();
    let id = StagedContentId(Uuid::new_v4());
    let sequence = 17;
    let alias = PrincipalId::new("alice").unwrap();
    let entries = [
        (writing.join(id.to_string()), "writing"),
        (ready.join(format!("{sequence:020}-{id}")), "ready"),
    ];
    for (path, name) in &entries {
        std::fs::create_dir(path).unwrap();
        let intent = LegacyStagingIntent {
            sequence,
            id,
            owner: LegacyStagingOwner::Principal(alias.clone()),
            name: ContentName::new(*name).unwrap(),
            profile: ChunkingProfile::ASTRID_V1,
            logical_bytes: 0,
        };
        atomic_write(
            &path.join(migration::LEGACY_INTENT_FILE),
            &encode_legacy_intent(&intent).unwrap(),
        )
        .unwrap();
    }

    let error = migrate_alias_owner_intents(root, |_| Ok(uid())).unwrap_err();
    assert!(error.to_string().contains("disagrees"), "{error}");
    for (path, _) in entries {
        assert!(path.join(migration::LEGACY_INTENT_FILE).exists());
        assert!(!path.join(legacy::INTENT_FILE).exists());
    }
}

#[test]
fn alias_migration_preflights_current_legacy_intents_before_mutation() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let writing = root.join(legacy::WRITING_DIRECTORY);
    let ready = root.join(legacy::READY_DIRECTORY);
    std::fs::create_dir_all(&writing).unwrap();
    std::fs::create_dir_all(&ready).unwrap();

    let id = StagedContentId(Uuid::new_v4());
    let alias_directory = writing.join(id.to_string());
    std::fs::create_dir(&alias_directory).unwrap();
    let alias = LegacyStagingIntent {
        sequence: 31,
        id,
        owner: LegacyStagingOwner::Principal(PrincipalId::new("alice").unwrap()),
        name: ContentName::new("alias.bin").unwrap(),
        profile: ChunkingProfile::ASTRID_V1,
        logical_bytes: 0,
    };
    atomic_write(
        &alias_directory.join(migration::LEGACY_INTENT_FILE),
        &encode_legacy_intent(&alias).unwrap(),
    )
    .unwrap();

    let current_directory = ready.join(format!("{:020}-{}", 32, id));
    std::fs::create_dir(&current_directory).unwrap();
    let current = StagingIntent {
        sequence: 32,
        id,
        owner: owner(),
        name: ContentName::new("current.bin").unwrap(),
        profile: ChunkingProfile::ASTRID_V1,
        logical_bytes: 0,
    };
    atomic_write(
        &current_directory.join(legacy::INTENT_FILE),
        &encode_intent(&current).unwrap(),
    )
    .unwrap();

    let error = migrate_alias_owner_intents(root, |_| Ok(uid())).unwrap_err();
    assert!(error.to_string().contains("identifier"), "{error}");
    assert!(alias_directory.join(migration::LEGACY_INTENT_FILE).exists());
    assert!(!alias_directory.join(legacy::INTENT_FILE).exists());
    assert_eq!(
        load_intent(&current_directory.join(legacy::INTENT_FILE)).unwrap(),
        current
    );
}

#[test]
fn legacy_intent_decoder_does_not_accept_uid_intents() {
    let intent = StagingIntent {
        sequence: 7,
        id: StagedContentId(Uuid::parse_str("86c54e54-a944-41d2-8bf1-28be44985973").unwrap()),
        owner: owner(),
        name: ContentName::new("projects/game/assets.bin").unwrap(),
        profile: ChunkingProfile::ASTRID_V1,
        logical_bytes: 98_765,
    };
    assert_eq!(
        decode_legacy_intent(&encode_intent(&intent).unwrap()),
        Err("staged intent checksum mismatch")
    );
}

#[test]
fn sealing_orders_by_close_and_survives_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let area = open_area(directory.path());
    let mut older = writer(&area, "same-name");
    let mut newer = writer(&area, "same-name");
    older.write_all(b"began first").unwrap();
    newer.write_all(b"closed first").unwrap();
    let closed_first = newer.seal().unwrap();
    older.seek(SeekFrom::Start(0)).unwrap();
    older.write_all(b"closed last!").unwrap();
    let closed_last = older.seal().unwrap();

    assert!(closed_first.sequence() < closed_last.sequence());
    drop(area);
    let reopened = open_area(directory.path());
    let ready = reopened.ready().unwrap();
    assert_eq!(ready.len(), 2);
    assert_eq!(ready[0].id(), closed_first.id());
    assert_eq!(ready[1].id(), closed_last.id());
    assert_eq!(ready[1].logical_bytes(), 12);
}

#[test]
fn a_later_close_cannot_publish_while_an_earlier_close_is_still_syncing() {
    let directory = tempfile::tempdir().unwrap();
    let reached = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let area = Arc::new(
        NativeContentStagingArea::open_configured(
            directory.path().to_path_buf(),
            GroupCommitPolicy::immediate(),
            Arc::new(PauseFirstAt {
                point: StagingFaultPoint::ContentFlushed,
                fired: AtomicBool::new(false),
                reached: Arc::clone(&reached),
                release: Arc::clone(&release),
            }),
        )
        .unwrap(),
    );
    let mut earlier = writer(&area, "same-name");
    earlier.write_all(b"earlier").unwrap();
    let earlier_worker = std::thread::spawn(move || earlier.seal().unwrap());

    reached.wait();
    let mut later = writer(&area, "same-name");
    later.write_all(b"later").unwrap();
    let later = later.seal().unwrap();
    let error = area.ensure_publication_order(&later).unwrap_err();
    assert!(error.to_string().contains("earlier close"));

    release.wait();
    let earlier = earlier_worker.join().unwrap();
    assert!(earlier.sequence() < later.sequence());
    let ready = area.ready().unwrap();
    assert_eq!(ready, vec![earlier, later]);
}

#[test]
fn publication_order_does_not_validate_unrelated_generation_files() {
    let directory = tempfile::tempdir().unwrap();
    let area = open_area(directory.path());
    let mut unrelated = writer(&area, "unrelated");
    unrelated.write_all(b"unrelated").unwrap();
    let unrelated = unrelated.seal().unwrap();
    let mut candidate = writer(&area, "candidate");
    candidate.write_all(b"candidate").unwrap();
    let candidate = candidate.seal().unwrap();

    std::fs::remove_file(unrelated.content_path()).unwrap();
    area.ensure_publication_order(&candidate).unwrap();
}

#[test]
fn unacknowledged_open_and_orphan_sealed_generations_are_quarantined() {
    let directory = tempfile::tempdir().unwrap();
    let area = open_area(directory.path());
    let mut open = writer(&area, "open");
    open.write_all(b"not acknowledged").unwrap();
    open.preserve_on_drop = true;
    let open_name = open.path.as_ref().unwrap().file_name().unwrap().to_owned();
    drop(open);

    let mut orphan = writer(&area, "orphan");
    orphan.write_all(b"renamed but not journalled").unwrap();
    let open_path = orphan.path.take().unwrap();
    let orphan_path = area
        .inner
        .generations
        .join(sealed_generation_name(9, orphan.id));
    std::fs::rename(&open_path, &orphan_path).unwrap();
    orphan.preserve_on_drop = true;
    drop(orphan);
    drop(area);

    let reopened = open_area(directory.path());
    assert!(reopened.ready().unwrap().is_empty());
    let quarantine = directory.path().join(QUARANTINE_DIRECTORY);
    assert!(
        quarantine
            .join(format!("{}.unsealed.0", open_name.to_string_lossy()))
            .exists()
    );
    assert!(
        quarantine
            .join(format!(
                "{}.orphan.0",
                orphan_path.file_name().unwrap().to_string_lossy()
            ))
            .exists()
    );
}

#[cfg(unix)]
#[test]
fn ready_scan_rejects_a_symlinked_content_source() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let area = open_area(directory.path());
    let mut staged_writer = writer(&area, "redirect");
    staged_writer.write_all(b"safe").unwrap();
    let staged = staged_writer.seal().unwrap();
    std::fs::remove_file(staged.content_path()).unwrap();
    symlink("/etc/passwd", staged.content_path()).unwrap();

    let error = area.ready().unwrap_err();
    assert!(
        error
            .to_string()
            .contains("redirected or not a regular file"),
        "{error}"
    );
}

#[test]
fn self_consistent_future_header_fails_without_truncating_the_journal() {
    for field in ["version", "reserved"] {
        let directory = tempfile::tempdir().unwrap();
        let area = open_area(directory.path());
        let mut staged_writer = writer(&area, "current");
        staged_writer.write_all(b"current").unwrap();
        staged_writer.seal().unwrap();
        let future_intent = StagingIntent {
            sequence: 99,
            id: StagedContentId(Uuid::new_v4()),
            owner: owner(),
            name: ContentName::new("future-header").unwrap(),
            profile: ChunkingProfile::ASTRID_V1,
            logical_bytes: 0,
        };
        let mut frame = encoded_frame(&JournalRecord::Sealed(future_intent)).unwrap();
        if field == "version" {
            frame[8..10].copy_from_slice(&2_u16.to_le_bytes());
        } else {
            frame[10] = 1;
        }
        refresh_frame_checksum(&mut frame).unwrap();
        let journal_path = directory.path().join(JOURNAL_FILE);
        {
            let mut journal = area.inner.journal.lock();
            journal.file.seek(SeekFrom::End(0)).unwrap();
            journal.file.write_all(&frame).unwrap();
            journal.file.sync_all().unwrap();
        }
        drop(area);
        let bytes_before = std::fs::read(&journal_path).unwrap();

        let error = open_area_result(directory.path()).unwrap_err();
        assert!(error.to_string().contains(field), "{field}: {error}");
        assert_eq!(
            std::fs::read(journal_path).unwrap(),
            bytes_before,
            "{field}"
        );
    }
}

#[test]
fn future_envelope_after_a_corrupt_frame_prevents_tail_truncation() {
    let directory = tempfile::tempdir().unwrap();
    let area = open_area(directory.path());
    let mut staged_writer = writer(&area, "current");
    staged_writer.write_all(b"current").unwrap();
    let current = staged_writer.seal().unwrap();
    let next_sequence = current.sequence().checked_add(1).unwrap();
    let corrupt_intent = StagingIntent {
        sequence: next_sequence,
        id: StagedContentId(Uuid::new_v4()),
        owner: owner(),
        name: ContentName::new("corrupt").unwrap(),
        profile: ChunkingProfile::ASTRID_V1,
        logical_bytes: 0,
    };
    let future_intent = StagingIntent {
        sequence: next_sequence.checked_add(1).unwrap(),
        id: StagedContentId(Uuid::new_v4()),
        owner: owner(),
        name: ContentName::new("future").unwrap(),
        profile: ChunkingProfile::ASTRID_V1,
        logical_bytes: 0,
    };
    let mut corrupt = encoded_frame(&JournalRecord::Sealed(corrupt_intent)).unwrap();
    corrupt[20] ^= 0x80;
    let mut future = encoded_frame(&JournalRecord::Sealed(future_intent)).unwrap();
    future[8..10].copy_from_slice(&2_u16.to_le_bytes());
    refresh_frame_checksum(&mut future).unwrap();
    let journal_path = directory.path().join(JOURNAL_FILE);
    {
        let mut journal = area.inner.journal.lock();
        journal.file.seek(SeekFrom::End(0)).unwrap();
        journal.file.write_all(&corrupt).unwrap();
        journal.file.write_all(&future).unwrap();
        journal.file.sync_all().unwrap();
    }
    drop(area);
    let bytes_before = std::fs::read(&journal_path).unwrap();

    let error = open_area_result(directory.path()).unwrap_err();
    assert!(error.to_string().contains("corrupt interior"), "{error}");
    assert_eq!(std::fs::read(journal_path).unwrap(), bytes_before);
}

#[test]
fn every_seal_crash_prefix_recovers_only_acknowledgeable_state() {
    let cases = [
        (StagingFaultPoint::ContentFlushed, 0),
        (StagingFaultPoint::GenerationRenamed, 1),
        (StagingFaultPoint::GenerationDirectoryFlushed, 1),
        // An append that reached the page cache may survive even though the
        // caller did not receive acknowledgement. Recovery accepting that
        // complete record is safe because the generation directory was
        // synchronized first.
        (StagingFaultPoint::SealJournalAppended, 1),
        (StagingFaultPoint::SealJournalFlushed, 1),
    ];
    for (point, recovered_count) in cases {
        let directory = tempfile::tempdir().unwrap();
        let area = open_with_fault(directory.path(), point);
        let mut staged_writer = writer(&area, "faulted");
        staged_writer.write_all(b"preserve me").unwrap();
        assert!(staged_writer.seal().is_err(), "{point:?}");
        drop(area);

        let reopened = open_area(directory.path());
        assert_eq!(
            reopened.ready().unwrap().len(),
            recovered_count,
            "{point:?}"
        );
    }
}

#[test]
fn orphan_recovery_flushes_the_generation_name_before_journalling_it() {
    let directory = tempfile::tempdir().unwrap();
    let area = open_with_fault(directory.path(), StagingFaultPoint::GenerationRenamed);
    let mut staged_writer = writer(&area, "recovered");
    staged_writer.write_all(b"recover after rename").unwrap();
    assert!(staged_writer.seal().is_err());
    drop(area);

    let error = NativeContentStagingArea::open_configured(
        directory.path().to_path_buf(),
        GroupCommitPolicy::immediate(),
        Arc::new(FailOnce {
            point: StagingFaultPoint::RecoveryGenerationDirectoryFlushed,
            fired: AtomicBool::new(false),
        }),
    )
    .unwrap_err();
    assert!(error.to_string().contains("injected staging fault"));
    assert_eq!(
        std::fs::metadata(directory.path().join(JOURNAL_FILE))
            .unwrap()
            .len(),
        0
    );

    let reopened = open_area(directory.path());
    let ready = reopened.ready().unwrap();
    assert_eq!(ready.len(), 1);
    assert_eq!(read_logical(&ready[0]), b"recover after rename");
}
