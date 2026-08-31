//! Canonical-user rejection order for recovered and migrated staging state.

use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

use astrid_core::identity::PrincipalUid;
use uuid::Uuid;

use super::format::{
    INTENT_MAGIC, INTENT_VERSION, USER_OWNER_NOT_ADMITTED, append_runtime_forbidden_user_footer,
    encode_fields, load_generation_footer_from_file,
};
use super::journal::{JOURNAL_HEADER_BYTES, JOURNAL_MAGIC, SEALED_RECORD, refresh_frame_checksum};
use super::{
    JOURNAL_FILE, NativeContentStagingArea, QUARANTINE_DIRECTORY, StagedContentId,
    migrate_alias_owner_intents, sealed_generation_name,
};
use crate::content::{ChunkingProfile, ContentName};
use crate::engine::{GroupCommitPolicy, PrincipalCodec};
use crate::principal_state::native_io::{atomic_write, private_file_identity};
use crate::principal_state::{StateOwner, StateOwnerCodecV2};

fn principal_owner() -> StateOwner {
    let digest = blake3::Hasher::new_derive_key("astrid staging owner preservation test")
        .update(b"principal")
        .finalize();
    StateOwner::Principal(PrincipalUid::from_bytes(*digest.as_bytes()))
}

#[test]
fn journal_user_after_malformed_frame_fails_before_recovery_mutation() {
    let directory = tempfile::tempdir().unwrap();
    let area = open_area(directory.path()).unwrap();
    let mut staged = area
        .begin(
            principal_owner(),
            ContentName::new("order.bin").unwrap(),
            ChunkingProfile::ASTRID_V1,
        )
        .unwrap();
    staged.write_all(b"malformed first").unwrap();
    let sealed = staged.seal().unwrap();
    drop(area);

    let journal = directory.path().join(JOURNAL_FILE);
    let owner = StateOwnerCodecV2.encode(&user_owner());
    let encoded_intent = encode_fields(
        INTENT_MAGIC,
        INTENT_VERSION,
        91,
        StagedContentId(Uuid::from_u128(91)),
        &owner,
        &ContentName::new("later-user.bin").unwrap(),
        ChunkingProfile::ASTRID_V1,
        0,
        "astrid native content staging intent v2",
        true,
    )
    .unwrap();
    let mut frame = vec![0_u8; JOURNAL_HEADER_BYTES];
    frame[..JOURNAL_MAGIC.len()].copy_from_slice(&JOURNAL_MAGIC);
    frame[8..10].copy_from_slice(&1_u16.to_le_bytes());
    let payload_len = u64::try_from(encoded_intent.len() + 1).unwrap();
    frame[12..20].copy_from_slice(&payload_len.to_le_bytes());
    frame.push(SEALED_RECORD);
    frame.extend_from_slice(&encoded_intent);
    refresh_frame_checksum(&mut frame).unwrap();

    let original = std::fs::read(&journal).unwrap();
    let mut malformed = original.clone();
    let last = malformed.len() - 1;
    malformed[last] ^= 0x80;
    std::fs::write(&journal, &malformed).unwrap();
    {
        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&journal)
            .unwrap();
        file.write_all(&frame).unwrap();
        file.sync_all().unwrap();
    }
    let mixed = std::fs::read(&journal).unwrap();
    assert_eq!(frame[..JOURNAL_MAGIC.len()], JOURNAL_MAGIC);
    assert_eq!(mixed.len(), original.len() + frame.len());
    assert_eq!(
        &mixed[original.len()..original.len() + JOURNAL_MAGIC.len()],
        &JOURNAL_MAGIC
    );
    let magic_offsets = (0..=mixed.len().saturating_sub(JOURNAL_MAGIC.len()))
        .filter(|offset| mixed[*offset..*offset + JOURNAL_MAGIC.len()] == JOURNAL_MAGIC)
        .collect::<Vec<_>>();
    assert_eq!(magic_offsets, vec![0, original.len()]);

    let error = open_area(directory.path()).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("explicit user owner in staging journal"),
        "{error}"
    );
    assert_eq!(std::fs::read(&journal).unwrap(), mixed);
    assert!(
        directory
            .path()
            .join(QUARANTINE_DIRECTORY)
            .read_dir()
            .unwrap()
            .next()
            .is_none()
    );
    let expected_name = sealed_generation_name(sealed.sequence(), sealed.id());
    assert_eq!(
        sealed
            .content_path()
            .file_name()
            .and_then(|name| name.to_str()),
        Some(expected_name.as_str())
    );
}

fn user_owner() -> StateOwner {
    StateOwner::User(astrid_core::UserUid::from_bytes([11; 32]))
}

fn open_area(path: &Path) -> crate::error::StorageResult<NativeContentStagingArea> {
    NativeContentStagingArea::open_with_group_commit_policy(path, GroupCommitPolicy::immediate())
}

#[test]
fn orphan_user_footer_fails_before_quarantine_or_journal_mutation() {
    let directory = tempfile::tempdir().unwrap();
    let area = open_area(directory.path()).unwrap();
    let mut staged = area
        .begin(
            principal_owner(),
            ContentName::new("user-footer.bin").unwrap(),
            ChunkingProfile::ASTRID_V1,
        )
        .unwrap();
    staged.write_all(b"canonical user rejection").unwrap();
    let sealed = staged.seal().unwrap();
    let path = sealed.content_path();

    let identity_reader = std::fs::File::open(&path).unwrap();
    let source_identity = private_file_identity(&identity_reader).unwrap();
    let mut reader = std::fs::File::open(&path).unwrap();
    let intent = load_generation_footer_from_file(&path, &mut reader)
        .unwrap()
        .intent;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .truncate(false)
        .open(&path)
        .unwrap();
    let mut user_intent = intent.clone();
    user_intent.owner = user_owner();
    file.set_len(user_intent.logical_bytes).unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    append_runtime_forbidden_user_footer(&mut file, &user_intent, source_identity).unwrap();
    file.sync_all().unwrap();
    let user_bytes = std::fs::read(&path).unwrap();

    let journal = directory.path().join(JOURNAL_FILE);
    let journal_before = std::fs::read(&journal).unwrap();
    drop(area);

    let error = open_area(directory.path()).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("explicit user owner in staged generation"),
        "{error}"
    );
    assert_eq!(std::fs::read(&path).unwrap(), user_bytes);
    assert_eq!(std::fs::read(&journal).unwrap(), journal_before);
    assert!(
        directory
            .path()
            .join(QUARANTINE_DIRECTORY)
            .read_dir()
            .unwrap()
            .next()
            .is_none()
    );
    let expected_name = sealed_generation_name(sealed.sequence(), sealed.id());
    assert_eq!(
        path.file_name().and_then(|name| name.to_str()),
        Some(expected_name.as_str())
    );
}

#[test]
fn current_user_intent_migration_fails_before_write_or_removal() {
    let directory = tempfile::tempdir().unwrap();
    let ready = directory.path().join(super::legacy::READY_DIRECTORY);
    let id = StagedContentId(Uuid::from_u128(77));
    let entry = ready.join(id.to_string());
    std::fs::create_dir_all(&entry).unwrap();
    let intent_path = entry.join(super::legacy::INTENT_FILE);
    let owner = StateOwnerCodecV2.encode(&user_owner());
    let bytes = encode_fields(
        INTENT_MAGIC,
        INTENT_VERSION,
        41,
        id,
        &owner,
        &ContentName::new("user-migration.bin").unwrap(),
        ChunkingProfile::ASTRID_V1,
        0,
        "astrid native content staging intent v2",
        true,
    )
    .unwrap();
    atomic_write(&intent_path, &bytes).unwrap();

    let error =
        migrate_alias_owner_intents(directory.path(), |_| Ok(PrincipalUid::from_bytes([22; 32])))
            .unwrap_err();
    assert!(
        error.to_string().contains(USER_OWNER_NOT_ADMITTED),
        "{error}"
    );
    assert_eq!(std::fs::read(&intent_path).unwrap(), bytes);
    assert!(entry.join(super::legacy::INTENT_FILE).exists());
}
