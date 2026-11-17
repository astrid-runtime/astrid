use super::test_support::fixture;
use super::{FilesystemError, FilesystemPath};
use crate::content::ContentName;

#[test]
fn public_rename_batch_keeps_its_existing_signature_and_result() {
    let (_engine, branches, owner, id) = fixture();
    let source = ContentName::new("source").unwrap();
    let destination = ContentName::new("destination").unwrap();
    branches.write(&owner, id, &source, b"value").unwrap();
    assert!(
        branches
            .rename_batch(&owner, id, &[(source.clone(), destination.clone())], &[])
            .unwrap()
    );
    assert_eq!(
        branches.read(&owner, id, &destination).unwrap(),
        Some(b"value".to_vec())
    );
    assert!(
        !branches
            .rename_batch(&owner, id, &[(source, destination)], &[])
            .unwrap()
    );
}

#[test]
fn directory_rename_replans_source_after_root_conflict() {
    let (engine, branches, owner, id) = fixture();
    let fs = branches.filesystem(owner, id);
    let old = FilesystemPath::new("old").unwrap();
    let new = FilesystemPath::new("new").unwrap();
    let late = FilesystemPath::new("old/late").unwrap();
    fs.create_dir(&old).unwrap();
    fs.write(&FilesystemPath::new("old/file").unwrap(), b"file")
        .unwrap();
    let interleaving_fs = branches.filesystem(owner, id);
    *engine.before_commit.lock() = Some(Box::new(move || {
        interleaving_fs.write(&late, b"late").unwrap();
    }));
    fs.rename(&old, &new).unwrap();
    assert!(matches!(
        fs.stat(&old),
        Err(super::WorkspaceBranchError::Filesystem(
            FilesystemError::NotFound(_)
        ))
    ));
    assert_eq!(
        fs.read(&FilesystemPath::new("new/late").unwrap(), 0, 4)
            .unwrap(),
        b"late"
    );
    assert_eq!(
        fs.read(&FilesystemPath::new("new/file").unwrap(), 0, 4)
            .unwrap(),
        b"file"
    );
}

#[test]
fn replacing_directory_rechecks_empty_destination_after_root_conflict() {
    let (engine, branches, owner, id) = fixture();
    let fs = branches.filesystem(owner, id);
    let old = FilesystemPath::new("old").unwrap();
    let new = FilesystemPath::new("new").unwrap();
    fs.create_dir(&old).unwrap();
    fs.create_dir(&new).unwrap();
    let interleaving_fs = branches.filesystem(owner, id);
    *engine.before_commit.lock() = Some(Box::new(move || {
        interleaving_fs
            .write(&FilesystemPath::new("new/late").unwrap(), b"late")
            .unwrap();
    }));
    assert!(matches!(
        fs.rename_replacing(&old, &new),
        Err(super::WorkspaceBranchError::Filesystem(
            FilesystemError::DirectoryNotEmpty(_)
        ))
    ));
    assert!(fs.stat(&old).is_ok());
    assert_eq!(
        fs.read(&FilesystemPath::new("new/late").unwrap(), 0, 4)
            .unwrap(),
        b"late"
    );
}

#[test]
fn rename_rechecks_destination_parent_after_root_conflict() {
    let (engine, branches, owner, id) = fixture();
    let fs = branches.filesystem(owner, id);
    let parent = FilesystemPath::new("parent").unwrap();
    let source = FilesystemPath::new("source").unwrap();
    let destination = FilesystemPath::new("parent/file").unwrap();
    fs.create_dir(&parent).unwrap();
    fs.write(&source, b"file").unwrap();
    let interleaving_fs = branches.filesystem(owner, id);
    *engine.before_commit.lock() = Some(Box::new(move || {
        interleaving_fs.remove(&parent).unwrap();
    }));
    assert!(matches!(
        fs.rename(&source, &destination),
        Err(super::WorkspaceBranchError::Filesystem(
            FilesystemError::NotFound(_)
        ))
    ));
    assert_eq!(fs.read(&source, 0, 4).unwrap(), b"file");
    assert!(matches!(
        fs.stat(&destination),
        Err(super::WorkspaceBranchError::Filesystem(
            FilesystemError::NotFound(_)
        ))
    ));
}

#[test]
fn file_rename_rejects_new_source_directory_alias() {
    let (engine, branches, owner, id) = fixture();
    let fs = branches.filesystem(owner, id);
    let old = FilesystemPath::new("old").unwrap();
    let new = FilesystemPath::new("new").unwrap();
    fs.write(&old, b"file").unwrap();
    let interleaving_branches = branches.clone();
    let interleaving_owner = owner;
    *engine.before_commit.lock() = Some(Box::new(move || {
        interleaving_branches
            .write(
                &interleaving_owner,
                id,
                &ContentName::new("old/child").unwrap(),
                b"child",
            )
            .unwrap();
    }));
    assert!(matches!(
        fs.rename(&old, &new),
        Err(super::WorkspaceBranchError::Filesystem(
            FilesystemError::NamespaceConflict(_)
        ))
    ));
    assert!(
        branches
            .describe_name(&owner, id, &ContentName::new("old").unwrap())
            .unwrap()
            .is_some()
    );
    assert!(
        branches
            .describe_name(&owner, id, &ContentName::new("old/child").unwrap())
            .unwrap()
            .is_some()
    );
    assert!(
        branches
            .describe_name(&owner, id, &ContentName::new("new").unwrap())
            .unwrap()
            .is_none()
    );
}

#[test]
fn directory_rename_rejects_new_source_file_alias() {
    let (engine, branches, owner, id) = fixture();
    let fs = branches.filesystem(owner, id);
    let old = FilesystemPath::new("old").unwrap();
    let new = FilesystemPath::new("new").unwrap();
    fs.create_dir(&old).unwrap();
    let interleaving_branches = branches.clone();
    let interleaving_owner = owner;
    *engine.before_commit.lock() = Some(Box::new(move || {
        interleaving_branches
            .write(
                &interleaving_owner,
                id,
                &ContentName::new("old").unwrap(),
                b"file",
            )
            .unwrap();
    }));
    assert!(matches!(
        fs.rename(&old, &new),
        Err(super::WorkspaceBranchError::Filesystem(
            FilesystemError::NamespaceConflict(_)
        ))
    ));
    assert!(
        branches
            .describe_name(&owner, id, &ContentName::new("old/").unwrap())
            .unwrap()
            .is_some()
    );
    assert!(
        branches
            .describe_name(&owner, id, &ContentName::new("old").unwrap())
            .unwrap()
            .is_some()
    );
    assert!(
        branches
            .describe_name(&owner, id, &ContentName::new("new/").unwrap())
            .unwrap()
            .is_none()
    );
}

#[test]
fn rename_replans_when_source_disappears() {
    let (engine, branches, owner, id) = fixture();
    let fs = branches.filesystem(owner, id);
    let old = FilesystemPath::new("old").unwrap();
    let new = FilesystemPath::new("new").unwrap();
    fs.write(&old, b"file").unwrap();
    let interleaving_fs = branches.filesystem(owner, id);
    let removed = old.clone();
    *engine.before_commit.lock() = Some(Box::new(move || {
        interleaving_fs.remove(&removed).unwrap();
    }));
    assert!(matches!(
        fs.rename(&old, &new),
        Err(super::WorkspaceBranchError::Filesystem(
            FilesystemError::NotFound(_)
        ))
    ));
    assert!(matches!(
        fs.stat(&new),
        Err(super::WorkspaceBranchError::Filesystem(
            FilesystemError::NotFound(_)
        ))
    ));
}

#[test]
fn rename_replans_when_replacement_disappears() {
    let (engine, branches, owner, id) = fixture();
    let fs = branches.filesystem(owner, id);
    let old = FilesystemPath::new("old").unwrap();
    let new = FilesystemPath::new("new").unwrap();
    fs.write(&old, b"old!").unwrap();
    fs.write(&new, b"new!").unwrap();
    let interleaving_fs = branches.filesystem(owner, id);
    let removed = new.clone();
    *engine.before_commit.lock() = Some(Box::new(move || {
        interleaving_fs.remove(&removed).unwrap();
    }));
    fs.rename_replacing(&old, &new).unwrap();
    assert!(matches!(
        fs.stat(&old),
        Err(super::WorkspaceBranchError::Filesystem(
            FilesystemError::NotFound(_)
        ))
    ));
    assert_eq!(fs.read(&new, 0, 4).unwrap(), b"old!");
}

#[test]
fn rename_rejects_new_destination_ancestor_alias() {
    let (engine, branches, owner, id) = fixture();
    let fs = branches.filesystem(owner, id);
    let source = FilesystemPath::new("source").unwrap();
    let destination = FilesystemPath::new("a/b/destination").unwrap();
    fs.create_dir(&FilesystemPath::new("a").unwrap()).unwrap();
    fs.create_dir(&FilesystemPath::new("a/b").unwrap()).unwrap();
    fs.write(&source, b"file").unwrap();
    let interleaving_branches = branches.clone();
    let interleaving_owner = owner;
    *engine.before_commit.lock() = Some(Box::new(move || {
        interleaving_branches
            .write(
                &interleaving_owner,
                id,
                &ContentName::new("a").unwrap(),
                b"alias",
            )
            .unwrap();
    }));
    assert!(matches!(
        fs.rename(&source, &destination),
        Err(super::WorkspaceBranchError::Filesystem(
            FilesystemError::NamespaceConflict(_)
        ))
    ));
    assert!(
        branches
            .describe_name(&owner, id, &ContentName::new("source").unwrap())
            .unwrap()
            .is_some()
    );
    assert!(
        branches
            .describe_name(&owner, id, &ContentName::new("a/b/destination").unwrap())
            .unwrap()
            .is_none()
    );
}

#[test]
fn rename_rejects_new_source_ancestor_alias() {
    let (engine, branches, owner, id) = fixture();
    let fs = branches.filesystem(owner, id);
    let source = FilesystemPath::new("a/b/source").unwrap();
    let destination = FilesystemPath::new("destination").unwrap();
    fs.create_dir(&FilesystemPath::new("a").unwrap()).unwrap();
    fs.create_dir(&FilesystemPath::new("a/b").unwrap()).unwrap();
    fs.write(&source, b"file").unwrap();
    let interleaving_branches = branches.clone();
    let interleaving_owner = owner;
    *engine.before_commit.lock() = Some(Box::new(move || {
        interleaving_branches
            .write(
                &interleaving_owner,
                id,
                &ContentName::new("a").unwrap(),
                b"alias",
            )
            .unwrap();
    }));
    assert!(matches!(
        fs.rename(&source, &destination),
        Err(super::WorkspaceBranchError::Filesystem(
            FilesystemError::NamespaceConflict(_)
        ))
    ));
    assert!(
        branches
            .describe_name(&owner, id, &ContentName::new("a/b/source").unwrap())
            .unwrap()
            .is_some()
    );
    assert!(
        branches
            .describe_name(&owner, id, &ContentName::new("destination").unwrap())
            .unwrap()
            .is_none()
    );
}
