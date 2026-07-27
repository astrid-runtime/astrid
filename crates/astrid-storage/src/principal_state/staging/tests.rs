use std::io::{Seek as _, Write as _};

use astrid_core::principal::PrincipalId;
use uuid::Uuid;

use super::format::{StagingIntent, decode_intent, encode_intent};
use super::*;

fn owner() -> StateOwner {
    StateOwner::Principal(PrincipalId::new("alice").unwrap())
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
    assert_eq!(decode_intent(&bytes).unwrap(), intent);

    let mut corrupt = bytes;
    corrupt[24] ^= 0x80;
    assert_eq!(
        decode_intent(&corrupt),
        Err("staged intent checksum mismatch")
    );
}

#[test]
fn sealing_orders_by_close_and_survives_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let area = NativeContentStagingArea::open(directory.path()).unwrap();
    let mut older = area
        .begin(
            owner(),
            ContentName::new("same-name").unwrap(),
            ChunkingProfile::ASTRID_V1,
        )
        .unwrap();
    let mut newer = area
        .begin(
            owner(),
            ContentName::new("same-name").unwrap(),
            ChunkingProfile::ASTRID_V1,
        )
        .unwrap();
    older.write_all(b"began first").unwrap();
    newer.write_all(b"closed first").unwrap();
    let closed_first = newer.seal().unwrap();
    older.seek(SeekFrom::Start(0)).unwrap();
    older.write_all(b"closed last!").unwrap();
    let closed_last = older.seal().unwrap();

    assert!(closed_first.sequence() < closed_last.sequence());
    drop(area);
    let reopened = NativeContentStagingArea::open(directory.path()).unwrap();
    let ready = reopened.ready().unwrap();
    assert_eq!(ready.len(), 2);
    assert_eq!(ready[0].id(), closed_first.id());
    assert_eq!(ready[1].id(), closed_last.id());
    assert_eq!(ready[1].logical_bytes(), 12);
}

#[test]
fn interrupted_seal_is_promoted_but_unsealed_bytes_are_quarantined() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let area = NativeContentStagingArea::open(root).unwrap();
    let mut sealed = area
        .begin(
            owner(),
            ContentName::new("sealed").unwrap(),
            ChunkingProfile::ASTRID_V1,
        )
        .unwrap();
    sealed.write_all(b"recover me").unwrap();
    let sealed_directory = sealed.directory.clone().unwrap();
    let file = sealed.file.take().unwrap();
    file.sync_all().unwrap();
    let intent = StagingIntent {
        sequence: area.allocate_sequence().unwrap(),
        id: sealed.id,
        owner: sealed.owner.clone(),
        name: sealed.name.clone(),
        profile: sealed.profile,
        logical_bytes: 10,
    };
    atomic_write(
        &sealed_directory.join(INTENT_FILE),
        &encode_intent(&intent).unwrap(),
    )
    .unwrap();
    sealed.preserve_on_drop = true;
    drop(sealed);

    let mut unsealed = area
        .begin(
            owner(),
            ContentName::new("unsealed").unwrap(),
            ChunkingProfile::ASTRID_V1,
        )
        .unwrap();
    unsealed.write_all(b"not acknowledged").unwrap();
    unsealed.preserve_on_drop = true;
    let unsealed_id = unsealed.id;
    drop(unsealed);
    drop(area);

    let recovered = NativeContentStagingArea::open(root).unwrap();
    let ready = recovered.ready().unwrap();
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].id(), intent.id);
    assert!(
        recovered
            .inner
            .root
            .join(QUARANTINE_DIRECTORY)
            .join(format!("{unsealed_id}.unsealed.0"))
            .exists()
    );
}

#[cfg(unix)]
#[test]
fn ready_scan_rejects_a_symlinked_content_source() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let area = NativeContentStagingArea::open(directory.path()).unwrap();
    let mut writer = area
        .begin(
            owner(),
            ContentName::new("redirect").unwrap(),
            ChunkingProfile::ASTRID_V1,
        )
        .unwrap();
    writer.write_all(b"safe").unwrap();
    let staged = writer.seal().unwrap();
    std::fs::remove_file(staged.content_path()).unwrap();
    symlink("/etc/passwd", staged.content_path()).unwrap();

    let error = area.ready().unwrap_err();
    assert!(
        error
            .to_string()
            .contains("redirected or not a regular file")
    );
}

#[test]
fn corrupt_ready_intent_fails_closed_without_deleting_staged_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let area = NativeContentStagingArea::open(directory.path()).unwrap();
    let mut writer = area
        .begin(
            owner(),
            ContentName::new("keep-on-corruption").unwrap(),
            ChunkingProfile::ASTRID_V1,
        )
        .unwrap();
    writer.write_all(b"still here").unwrap();
    let staged = writer.seal().unwrap();
    let intent_path = staged.directory.join(INTENT_FILE);
    let mut bytes = std::fs::read(&intent_path).unwrap();
    bytes[8] ^= 0x40;
    std::fs::write(&intent_path, bytes).unwrap();

    assert!(area.ready().is_err());
    assert_eq!(std::fs::read(staged.content_path()).unwrap(), b"still here");
}

#[test]
fn durable_publication_marker_reaps_an_interrupted_cleanup() {
    let directory = tempfile::tempdir().unwrap();
    let area = NativeContentStagingArea::open(directory.path()).unwrap();
    let mut writer = area
        .begin(
            owner(),
            ContentName::new("published").unwrap(),
            ChunkingProfile::ASTRID_V1,
        )
        .unwrap();
    writer.write_all(b"published bytes").unwrap();
    let staged = writer.seal().unwrap();
    atomic_write(&staged.directory.join(PUBLISHED_FILE), PUBLISHED_MARKER).unwrap();

    assert!(area.ready().unwrap().is_empty());
    assert!(!staged.directory.exists());
}

#[cfg(unix)]
#[test]
fn staging_root_cannot_be_a_symlink() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("target");
    std::fs::create_dir(&target).unwrap();
    let redirected = directory.path().join("redirected");
    symlink(&target, &redirected).unwrap();

    let error = NativeContentStagingArea::open(&redirected).unwrap_err();
    assert!(error.to_string().contains("redirected or not a directory"));
}
