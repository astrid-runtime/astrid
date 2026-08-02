//! Cross-reader checks for selected durable crash images.

#![cfg(not(target_os = "windows"))]

use std::path::{Path, PathBuf};

use astrid_core::identity::PrincipalUid;
use astrid_storage_engine::{DurableError, RecoveryLimits};
use astrid_storage_model::RootState;

use super::*;
use crate::ContentName;

const FRAME_HEADER_BYTES: usize = 52;

#[derive(Clone, Debug, PartialEq, Eq)]
struct AuthorityImage {
    arena: Vec<u8>,
    roots: Vec<u8>,
    metadata: Vec<u8>,
}

impl AuthorityImage {
    fn capture(path: &Path) -> Self {
        Self {
            arena: std::fs::read(path.join("objects.arena")).unwrap(),
            roots: std::fs::read(path.join("roots.journal")).unwrap(),
            metadata: std::fs::read(path.join("store.meta")).unwrap(),
        }
    }

    fn install(&self, path: &Path) {
        std::fs::create_dir_all(path).unwrap();
        std::fs::write(path.join("objects.arena"), &self.arena).unwrap();
        std::fs::write(path.join("roots.journal"), &self.roots).unwrap();
        std::fs::write(path.join("store.meta"), &self.metadata).unwrap();
    }
}

#[derive(Clone, Copy, Debug)]
enum ExpectedImage {
    Root(RootState),
    InteriorCorruption,
}

fn independent_reader() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/runatal_v1_reader.py")
}

fn frame_spans(bytes: &[u8], magic: [u8; 8]) -> Vec<std::ops::Range<usize>> {
    let mut spans = Vec::new();
    let mut offset = 0_usize;
    while offset < bytes.len() {
        let header_end = offset.checked_add(FRAME_HEADER_BYTES).unwrap();
        let header = bytes.get(offset..header_end).unwrap();
        assert_eq!(&header[..8], magic.as_slice());
        let payload_len =
            usize::try_from(u64::from_le_bytes(header[12..20].try_into().unwrap())).unwrap();
        let end = header_end.checked_add(payload_len).unwrap();
        assert!(end <= bytes.len());
        spans.push(offset..end);
        offset = end;
    }
    spans
}

fn cross_check(image: &AuthorityImage, owner: StateOwner, expected: ExpectedImage) {
    let directory = tempfile::tempdir().unwrap();
    image.install(directory.path());
    let reader = std::process::Command::new("python3")
        .arg(independent_reader())
        .arg(directory.path())
        .output()
        .unwrap();

    match expected {
        ExpectedImage::Root(root) => {
            assert!(
                reader.status.success(),
                "independent reader rejected recoverable crash image: {}",
                String::from_utf8_lossy(&reader.stderr)
            );
            let decoded: serde_json::Value = serde_json::from_slice(&reader.stdout).unwrap();
            let StateOwner::Principal(uid) = owner else {
                panic!("fixture owner must be a principal");
            };
            assert_eq!(
                decoded["roots"][uid.to_string()]["generation"],
                root.generation.get()
            );

            let engine = RuntimeEngine::open(
                directory.path(),
                Blake3ObjectIdentityV1,
                StateOwnerCodecV1,
                RecoveryLimits::process_addressable(),
            )
            .unwrap();
            assert_eq!(engine.root(&owner).unwrap(), Some(root));
            assert_eq!(engine.snapshot(&owner).unwrap().unwrap().root(), root);
        },
        ExpectedImage::InteriorCorruption => {
            assert!(
                !reader.status.success(),
                "independent reader accepted an interior-corrupt crash image"
            );
            let before = AuthorityImage::capture(directory.path());
            assert!(matches!(
                RuntimeEngine::open(
                    directory.path(),
                    Blake3ObjectIdentityV1,
                    StateOwnerCodecV1,
                    RecoveryLimits::process_addressable(),
                ),
                Err(DurableError::Corrupt { .. })
            ));
            assert_eq!(AuthorityImage::capture(directory.path()), before);
        },
    }
}

fn test_uid(alias: &str) -> PrincipalUid {
    let mut hasher = blake3::Hasher::new_derive_key("astrid crash reader fixture uid v1");
    hasher.update(alias.as_bytes());
    PrincipalUid::from_bytes(*hasher.finalize().as_bytes())
}

fn unlimited_quota() -> Arc<dyn KvQuotaResolver<StateOwner>> {
    Arc::new(|_: &StateOwner| Ok(Some(u64::MAX)))
}

#[tokio::test]
async fn independent_reader_agrees_on_selected_crash_prefixes() {
    let source = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(source.path());
    let uid = test_uid("alice");
    let owner = StateOwner::Principal(uid);
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let name = ContentName::new("workspace/crash-prefix.txt").unwrap();
    store
        .content()
        .put(&owner, &name, b"first durable content")
        .unwrap();
    let before_root = store.engine.root(&owner).unwrap().unwrap();
    let before = AuthorityImage::capture(&home.principal_store_path());
    store
        .content()
        .put(&owner, &name, b"second durable content")
        .unwrap();
    let after_root = store.engine.root(&owner).unwrap().unwrap();
    let after = AuthorityImage::capture(&home.principal_store_path());
    drop(store);

    let arena_delta = after.arena.strip_prefix(before.arena.as_slice()).unwrap();
    let root_delta = after.roots.strip_prefix(before.roots.as_slice()).unwrap();
    assert!(!arena_delta.is_empty());
    assert!(!root_delta.is_empty());

    let mut torn_arena = before.clone();
    torn_arena
        .arena
        .extend_from_slice(&arena_delta[..arena_delta.len() / 2]);
    cross_check(&torn_arena, owner, ExpectedImage::Root(before_root));

    let mut torn_roots = after.clone();
    torn_roots.roots = before.roots.clone();
    torn_roots
        .roots
        .extend_from_slice(&root_delta[..root_delta.len() / 2]);
    cross_check(&torn_roots, owner, ExpectedImage::Root(before_root));

    cross_check(&after, owner, ExpectedImage::Root(after_root));

    let arena_spans = frame_spans(arena_delta, *b"ASTOBJ1\0");
    assert!(arena_spans.len() >= 2);
    let mut invalid_tail = before.clone();
    invalid_tail.arena.extend_from_slice(arena_delta);
    *invalid_tail.arena.last_mut().unwrap() ^= 0x80;
    cross_check(&invalid_tail, owner, ExpectedImage::Root(before_root));

    let mut interior = before;
    interior.arena.extend_from_slice(arena_delta);
    let first_payload = interior
        .arena
        .len()
        .checked_sub(arena_delta.len())
        .and_then(|base| base.checked_add(arena_spans[0].start))
        .and_then(|offset| offset.checked_add(FRAME_HEADER_BYTES))
        .unwrap();
    interior.arena[first_payload] ^= 0x80;
    cross_check(&interior, owner, ExpectedImage::InteriorCorruption);
}
