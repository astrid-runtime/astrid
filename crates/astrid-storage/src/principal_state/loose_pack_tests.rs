//! Conversion of recovered `LooseBlob` homes into packed arena frames.

use std::io::Cursor;
use std::sync::Arc;

use crate::content::{ChunkingProfile, ContentName};
use crate::volume::{AstridVolume, HostedFileVolume, VolumeFile, VolumeRegion};
use crate::{KvQuotaResolver, open_runtime_principal_store};
use astrid_core::PrincipalUid;
use astrid_core::dirs::AstridHome;

use super::{RuntimePrincipalStore, StateOwner};

fn unlimited_quota() -> Arc<dyn KvQuotaResolver<StateOwner>> {
    Arc::new(|owner: &StateOwner| {
        Ok(match owner {
            StateOwner::System => None,
            StateOwner::Principal(_) | StateOwner::Fleet(_) => Some(u64::MAX),
        })
    })
}

fn loose_blob_payload_bytes(home: &AstridHome) -> u64 {
    crate::volume::write_record_payloads(&home.storage_volume_path())
        .unwrap()
        .into_iter()
        .filter(|(name, _)| {
            name.contains("representations/blobs/loose")
                && std::path::Path::new(name)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("blob"))
        })
        .map(|(_, len)| len)
        .sum()
}

fn seed_identical_loose_names(store: &RuntimePrincipalStore, owner: StateOwner, bytes: &[u8]) {
    let prepared = store
        .engine
        .prepare_contiguous_file(
            ChunkingProfile::ASTRID_V1,
            u64::try_from(bytes.len()).unwrap(),
            Cursor::new(bytes),
        )
        .unwrap();
    let published = store
        .engine
        .publish_contiguous_copy(prepared, Cursor::new(bytes))
        .unwrap();
    store
        .content
        .publish_verified_batch(
            &owner,
            [
                (
                    ContentName::new("one.bin").unwrap(),
                    published.verified_content(),
                ),
                (
                    ContentName::new("two.bin").unwrap(),
                    published.verified_content(),
                ),
            ],
            published.objects_inserted(),
        )
        .unwrap();
}

#[tokio::test]
async fn convert_loose_home_is_packed_byte_identical_and_durable() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    home.ensure().unwrap();
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let owner = StateOwner::Principal(PrincipalUid::from_bytes([0x61; 32]));
    let bytes = vec![0x5A_u8; 256 * 1024];
    seed_identical_loose_names(&store, owner, &bytes);
    assert!(
        loose_blob_payload_bytes(&home) > 0,
        "fixture must start as LooseBlob"
    );

    store.pack_contiguous_home_payloads().unwrap();
    let volume_path = home.storage_volume_path();
    let packed_len = std::fs::metadata(&volume_path).unwrap().len();
    let logical = u64::try_from(bytes.len()).unwrap();
    assert!(
        packed_len < logical.saturating_mul(2).saturating_add(4 * 1024 * 1024),
        "packed volume {packed_len} still ~1:1 with two logical copies"
    );

    let copy_directory = tempfile::tempdir().unwrap();
    let copy_home = AstridHome::from_path(copy_directory.path());
    copy_home.ensure().unwrap();
    std::fs::copy(&volume_path, copy_home.storage_volume_path()).unwrap();

    store.engine.close().unwrap();
    drop(store);

    let reopened = open_runtime_principal_store(&copy_home, unlimited_quota())
        .await
        .expect("reopen packed conversion copied before source close");
    let filesystem = crate::AstridFilesystem::new(reopened.content(), owner);
    assert_eq!(
        filesystem
            .read(&crate::FilesystemPath::new("one.bin").unwrap(), 0, logical,)
            .unwrap(),
        bytes
    );
    assert_eq!(
        filesystem
            .read(&crate::FilesystemPath::new("two.bin").unwrap(), 0, logical,)
            .unwrap(),
        bytes
    );
    assert_eq!(
        loose_blob_payload_bytes(&copy_home),
        0,
        "converted volume still has loose blob regions"
    );
}

#[tokio::test]
async fn convert_refuses_unnamed_loose_payload_and_does_not_delete_it() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    home.ensure().unwrap();
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let bytes = vec![0x5A_u8; 256 * 1024];
    let prepared = store
        .engine
        .prepare_contiguous_file(
            ChunkingProfile::ASTRID_V1,
            u64::try_from(bytes.len()).unwrap(),
            Cursor::new(bytes.clone()),
        )
        .unwrap();
    store
        .engine
        .publish_contiguous_copy(prepared, Cursor::new(bytes))
        .unwrap();
    assert!(
        loose_blob_payload_bytes(&home) > 0,
        "fixture must start as LooseBlob"
    );

    let error = store
        .pack_contiguous_home_payloads()
        .expect_err("unnamed loose payload must fail closed");
    assert!(
        error
            .to_string()
            .contains("unnamed loose payload not in catalog"),
        "{error}"
    );
    assert!(
        loose_blob_payload_bytes(&home) > 0,
        "fail-closed conversion deleted unnamed loose payload"
    );
}

#[tokio::test]
async fn empty_contiguous_index_still_retires_leftover_loose_regions() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    home.ensure().unwrap();
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let owner = StateOwner::Principal(PrincipalUid::from_bytes([0x62; 32]));
    let bytes = vec![0x5A_u8; 256 * 1024];
    seed_identical_loose_names(&store, owner, &bytes);
    store.pack_contiguous_home_payloads().unwrap();
    store.engine.close().unwrap();
    drop(store);
    assert_eq!(loose_blob_payload_bytes(&home), 0);

    let volume: Arc<dyn AstridVolume> = HostedFileVolume::open(home.storage_volume_path()).unwrap();
    let region = VolumeRegion::new("representations/blobs/loose/orphan.blob").unwrap();
    let mut file = VolumeFile::create_new(Arc::clone(&volume), region).unwrap();
    let orphan = vec![0xA5_u8; 4096];
    file.write_from(
        u64::try_from(orphan.len()).unwrap(),
        &mut Cursor::new(orphan),
    )
    .unwrap();
    drop(file);
    volume.sync().unwrap();
    drop(volume);
    assert!(
        loose_blob_payload_bytes(&home) > 0,
        "orphan loose region must exist before reopen convert"
    );

    let reopened = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .expect("empty-index leftover loose regions must not fail open");
    assert_eq!(
        loose_blob_payload_bytes(&home),
        0,
        "empty contiguous index left orphan loose regions on volume"
    );
    reopened.engine.close().unwrap();
}
