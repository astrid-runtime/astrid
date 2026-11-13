//! Existing-only open must never turn missing/empty media into a new volume.

use super::*;

fn open(path: &std::path::Path) -> io::Result<Arc<HostedFileVolume>> {
    #[cfg(windows)]
    let root = Arc::new(
        astrid_core::platform_fs::directory_capability::RetainedPrivateRoot::admit(
            path.parent().unwrap(),
        )?,
    );
    HostedFileVolume::open_existing_canonical(
        path,
        #[cfg(windows)]
        root,
    )
}

fn create(path: &std::path::Path) -> Arc<HostedFileVolume> {
    #[cfg(windows)]
    {
        let root = Arc::new(
            astrid_core::platform_fs::directory_capability::RetainedPrivateRoot::admit(
                path.parent().unwrap(),
            )
            .unwrap(),
        );
        HostedFileVolume::open_runtime(root, path).unwrap()
    }
    #[cfg(not(windows))]
    HostedFileVolume::open(path).unwrap()
}

#[test]
fn canonical_open_never_creates_missing_media() {
    let directory = crate::test_directory::temporary().unwrap();
    let path = directory.path().join("astrid.volume");
    assert!(open(&path).is_err());
    assert!(!path.exists());
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[test]
fn canonical_open_never_initializes_empty_media() {
    let directory = crate::test_directory::temporary().unwrap();
    let path = directory.path().join("astrid.volume");
    #[cfg(windows)]
    drop(astrid_core::platform_fs::create_new_private_file_shared(&path).unwrap());
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        drop(
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .unwrap(),
        );
    }
    assert!(open(&path).is_err());
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
}

#[test]
fn canonical_open_never_promotes_a_previous_inode() {
    let directory = crate::test_directory::temporary().unwrap();
    let path = directory.path().join("astrid.volume");
    drop(create(&path));
    let previous = reclaim::previous_path(&path);
    std::fs::rename(&path, &previous).unwrap();
    let bytes = std::fs::read(&previous).unwrap();
    assert!(open(&path).is_err());
    assert!(!path.exists());
    assert_eq!(std::fs::read(&previous).unwrap(), bytes);
}

#[test]
fn canonical_open_keeps_swap_artifacts_until_authority_is_accepted() {
    let directory = crate::test_directory::temporary().unwrap();
    let path = directory.path().join("astrid.volume");
    drop(create(&path));
    let temporary = reclaim::temp_path(&path);
    std::fs::write(&temporary, b"unaccepted artifact").unwrap();
    let volume = open(&path).unwrap();
    assert_eq!(std::fs::read(&temporary).unwrap(), b"unaccepted artifact");
    volume.finish_canonical_recovery().unwrap();
    assert!(!temporary.exists());
}

#[cfg(unix)]
#[test]
fn canonical_open_never_follows_a_redirect() {
    let directory = crate::test_directory::temporary().unwrap();
    let outside = directory.path().join("outside");
    drop(create(&outside));
    let path = directory.path().join("astrid.volume");
    std::os::unix::fs::symlink(&outside, &path).unwrap();
    let bytes = std::fs::read(&outside).unwrap();
    assert!(open(&path).is_err());
    assert!(
        std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(std::fs::read(&outside).unwrap(), bytes);
}
