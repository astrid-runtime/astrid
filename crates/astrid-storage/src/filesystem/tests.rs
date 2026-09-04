use std::sync::Arc;

use astrid_core::PrincipalUid;

use super::*;
use crate::{KvQuotaResolver, StateOwner, open_runtime_principal_store};

async fn filesystem() -> (
    tempfile::TempDir,
    AstridFilesystem<
        StateOwner,
        crate::engine::DurableEngine<
            StateOwner,
            crate::Blake3ObjectIdentityV1,
            crate::StateOwnerCodecV2,
        >,
    >,
) {
    let directory = tempfile::tempdir().unwrap();
    let home = astrid_core::dirs::AstridHome::from_path(directory.path());
    home.ensure().unwrap();
    let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|owner: &StateOwner| {
        Ok(match owner {
            StateOwner::System => None,
            StateOwner::Principal(_) | StateOwner::Fleet(_) => Some(u64::MAX),
        })
    });
    let store = open_runtime_principal_store(&home, quota).await.unwrap();
    let owner = StateOwner::Principal(PrincipalUid::from_bytes([7; 32]));
    (directory, AstridFilesystem::new(store.content(), owner))
}

#[tokio::test]
async fn directories_are_namespace_entries_not_host_directories() {
    let (directory, filesystem) = filesystem().await;
    let projects = FilesystemPath::new("projects").unwrap();
    let note = FilesystemPath::new("projects/note.txt").unwrap();

    filesystem.create_dir(&projects).unwrap();
    filesystem.write(&note, b"astrid").unwrap();

    assert_eq!(
        filesystem.read_dir(&FilesystemPath::root()).unwrap(),
        vec![FilesystemEntry {
            name: "projects".to_owned(),
            kind: FilesystemEntryKind::Directory,
            logical_bytes: 0,
        }]
    );
    assert_eq!(filesystem.read(&note, 1, 4).unwrap(), b"stri");
    assert!(!directory.path().join("projects").exists());
}

#[tokio::test]
async fn owner_views_are_isolated_over_one_physical_store() {
    let (directory, first) = filesystem().await;
    let home = astrid_core::dirs::AstridHome::from_path(directory.path());
    let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|owner: &StateOwner| {
        Ok(match owner {
            StateOwner::System => None,
            StateOwner::Principal(_) | StateOwner::Fleet(_) => Some(u64::MAX),
        })
    });
    drop(first);
    let store = open_runtime_principal_store(&home, quota).await.unwrap();
    let first = AstridFilesystem::new(
        store.content(),
        StateOwner::Principal(PrincipalUid::from_bytes([7; 32])),
    );
    let second = AstridFilesystem::new(
        store.content(),
        StateOwner::Principal(PrincipalUid::from_bytes([8; 32])),
    );
    let path = FilesystemPath::new("shared-name.txt").unwrap();

    first.write(&path, b"first").unwrap();
    second.write(&path, b"second").unwrap();

    assert_eq!(first.read(&path, 0, 5).unwrap(), b"first");
    assert_eq!(second.read(&path, 0, 6).unwrap(), b"second");
}

#[tokio::test]
async fn fleet_shared_view_cannot_escape_fixed_prefix() {
    let (_directory, filesystem) = filesystem().await;
    let shared = FilesystemPath::new("shared").unwrap();
    let inside = FilesystemPath::new("shared/inside.txt").unwrap();
    let outside = FilesystemPath::new("private.txt").unwrap();
    filesystem.create_dir(&shared).unwrap();
    filesystem.write(&inside, b"shared bytes").unwrap();
    filesystem.write(&outside, b"private bytes").unwrap();

    let scoped =
        AstridFilesystem::new_fleet_shared(Arc::clone(&filesystem.content), filesystem.owner);
    assert_eq!(
        scoped.read_dir(&FilesystemPath::root()).unwrap()[0].name(),
        "inside.txt"
    );
    assert_eq!(
        scoped
            .read(&FilesystemPath::new("inside.txt").unwrap(), 0, 12)
            .unwrap(),
        b"shared bytes"
    );
    assert!(matches!(
        scoped.stat(&FilesystemPath::new("private.txt").unwrap()),
        Err(FilesystemError::NotFound(_))
    ));
    assert!(matches!(
        scoped.remove(&FilesystemPath::root()),
        Err(FilesystemError::AlreadyExists(_))
    ));
}

#[tokio::test]
async fn empty_directory_removal_is_explicit_and_non_recursive() {
    let (_directory, filesystem) = filesystem().await;
    let directory = FilesystemPath::new("dir").unwrap();
    let child = FilesystemPath::new("dir/child").unwrap();
    filesystem.create_dir(&directory).unwrap();
    filesystem.write(&child, b"x").unwrap();

    assert!(matches!(
        filesystem.remove(&directory),
        Err(FilesystemError::DirectoryNotEmpty(_))
    ));
    filesystem.remove(&child).unwrap();
    filesystem.remove(&directory).unwrap();
    assert!(matches!(
        filesystem.stat(&directory),
        Err(FilesystemError::NotFound(_))
    ));
}

#[tokio::test]
async fn directory_rename_publishes_the_subtree_as_one_owner_transition() {
    let (_directory, filesystem) = filesystem().await;
    let from = FilesystemPath::new("from").unwrap();
    let nested = FilesystemPath::new("from/nested").unwrap();
    let file = FilesystemPath::new("from/nested/file").unwrap();
    let to = FilesystemPath::new("to").unwrap();
    filesystem.create_dir(&from).unwrap();
    filesystem.create_dir(&nested).unwrap();
    filesystem.write(&file, b"value").unwrap();

    filesystem.rename(&from, &to).unwrap();

    assert!(matches!(
        filesystem.stat(&from),
        Err(FilesystemError::NotFound(_))
    ));
    assert_eq!(
        filesystem
            .read(&FilesystemPath::new("to/nested/file").unwrap(), 0, 5)
            .unwrap(),
        b"value"
    );
}

#[tokio::test]
async fn replace_rename_supports_atomic_editor_saves() {
    let (_directory, filesystem) = filesystem().await;
    let temporary = FilesystemPath::new("note.txt.tmp").unwrap();
    let target = FilesystemPath::new("note.txt").unwrap();
    filesystem.write(&target, b"old").unwrap();
    filesystem.write(&temporary, b"new contents").unwrap();

    filesystem.rename_replacing(&temporary, &target).unwrap();

    assert_eq!(filesystem.read(&target, 0, 12).unwrap(), b"new contents");
    assert!(matches!(
        filesystem.stat(&temporary),
        Err(FilesystemError::NotFound(_))
    ));
}

#[tokio::test]
async fn directory_replace_requires_an_empty_compatible_destination() {
    let (_directory, filesystem) = filesystem().await;
    let source = FilesystemPath::new("source").unwrap();
    let destination = FilesystemPath::new("destination").unwrap();
    filesystem.create_dir(&source).unwrap();
    filesystem.create_dir(&destination).unwrap();
    filesystem
        .write(&FilesystemPath::new("destination/occupied").unwrap(), b"x")
        .unwrap();

    assert!(matches!(
        filesystem.rename_replacing(&source, &destination),
        Err(FilesystemError::DirectoryNotEmpty(_))
    ));
}

#[tokio::test]
async fn parent_exists_does_not_list_the_owner_catalog() {
    let (_directory, filesystem) = filesystem().await;
    let startup_list = filesystem.content.list_invocations();
    let startup_list_prefix = filesystem.content.list_prefix_invocations();
    let startup_header_decodes = filesystem.content.decode_header_invocations();
    let directory = FilesystemPath::new("blobs").unwrap();
    filesystem.create_dir(&directory).unwrap();
    filesystem
        .write(&FilesystemPath::new("blobs/0000").unwrap(), b"x")
        .unwrap();
    filesystem
        .write(&FilesystemPath::new("blobs/0001").unwrap(), b"x")
        .unwrap();
    for index in 2..64_u32 {
        let path = FilesystemPath::new(format!("blobs/{index:04}")).unwrap();
        filesystem.write(&path, b"x").unwrap();
    }
    assert_eq!(filesystem.content.list_invocations(), startup_list);
    assert_eq!(
        filesystem.content.list_prefix_invocations(),
        startup_list_prefix
    );
    assert!(filesystem.content.decode_header_invocations() >= startup_header_decodes);

    let extra = FilesystemPath::new("blobs/extra").unwrap();
    let prefix_exists = filesystem.content.prefix_exists_invocations();
    filesystem.write(&extra, b"y").unwrap();
    assert_eq!(filesystem.content.list_invocations(), startup_list);
    assert_eq!(
        filesystem.content.list_prefix_invocations(),
        startup_list_prefix
    );
    assert!(
        filesystem.content.prefix_exists_invocations() <= prefix_exists.saturating_add(1),
        "extra write listed children instead of one prefix_exists"
    );
    assert_eq!(filesystem.read(&extra, 0, 1).unwrap(), b"y");
    assert_eq!(filesystem.content.list_invocations(), startup_list);
    assert_eq!(
        filesystem.content.list_prefix_invocations(),
        startup_list_prefix
    );
}

#[tokio::test]
async fn write_still_rejects_a_directory_name_in_a_confirmed_parent() {
    let (_directory, filesystem) = filesystem().await;
    let parent = FilesystemPath::new("blobs").unwrap();
    let nested = FilesystemPath::new("blobs/foo").unwrap();
    let nested_file = FilesystemPath::new("blobs/foo/child").unwrap();
    filesystem.create_dir(&parent).unwrap();
    filesystem.create_dir(&nested).unwrap();
    filesystem.write(&nested_file, b"x").unwrap();
    filesystem
        .write(&FilesystemPath::new("blobs/other").unwrap(), b"y")
        .unwrap();
    assert!(matches!(
        filesystem.write(&nested, b"nope"),
        Err(FilesystemError::IsDirectory(_))
    ));
}

#[tokio::test]
async fn removed_directory_is_not_cached_as_still_present() {
    let (_directory, filesystem) = filesystem().await;
    let directory = FilesystemPath::new("gone").unwrap();
    let child = FilesystemPath::new("gone/child").unwrap();
    filesystem.create_dir(&directory).unwrap();
    filesystem.write(&child, b"x").unwrap();
    filesystem.remove(&child).unwrap();
    filesystem.remove(&directory).unwrap();
    assert!(matches!(
        filesystem.write(&child, b"y"),
        Err(FilesystemError::NotFound(_))
    ));
}

#[tokio::test]
async fn renamed_directory_is_not_cached_under_the_old_name() {
    let (_directory, filesystem) = filesystem().await;
    let from = FilesystemPath::new("from").unwrap();
    let to = FilesystemPath::new("to").unwrap();
    let old_child = FilesystemPath::new("from/file").unwrap();
    let new_child = FilesystemPath::new("to/file").unwrap();
    filesystem.create_dir(&from).unwrap();
    filesystem.write(&old_child, b"x").unwrap();
    filesystem.rename(&from, &to).unwrap();
    assert_eq!(filesystem.read(&new_child, 0, 1).unwrap(), b"x");
    assert!(matches!(
        filesystem.write(&old_child, b"y"),
        Err(FilesystemError::NotFound(_))
    ));
}

#[tokio::test]
async fn implied_directory_lookup_does_not_list_the_owner_catalog() {
    let (_directory, filesystem) = filesystem().await;
    let startup_list = filesystem.content.list_invocations();
    filesystem
        .content
        .put(
            &filesystem.owner,
            &ContentName::new("models/0000").unwrap(),
            b"blob",
        )
        .unwrap();
    filesystem
        .content
        .put(
            &filesystem.owner,
            &ContentName::new("models/0001").unwrap(),
            b"blob",
        )
        .unwrap();
    for index in 2..32_u32 {
        let name = ContentName::new(format!("models/{index:04}")).unwrap();
        filesystem
            .content
            .put(&filesystem.owner, &name, b"blob")
            .unwrap();
    }
    assert_eq!(filesystem.content.list_invocations(), startup_list);
    let models = FilesystemPath::new("models").unwrap();
    assert_eq!(
        filesystem.stat(&models).unwrap().kind(),
        FilesystemEntryKind::Directory
    );
    assert_eq!(filesystem.content.list_invocations(), startup_list);

    let extra = FilesystemPath::new("models/extra").unwrap();
    filesystem.write(&extra, b"more").unwrap();
    assert_eq!(filesystem.content.list_invocations(), startup_list);
    assert_eq!(filesystem.read(&extra, 0, 4).unwrap(), b"more");
}
