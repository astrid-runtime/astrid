//! Open the singleton fence without following appended temporary-path aliases.
use std::fs::File;
use std::path::Path;

use anyhow::{Context, Result, ensure};

#[cfg(unix)]
pub(super) fn open(path: &Path) -> Result<File> {
    use nix::errno::Errno;
    use nix::fcntl::{OFlag, open, openat};
    use nix::sys::stat::{Mode, mkdirat};
    use std::os::unix::fs::MetadataExt;

    let parent = path.parent().context("start fence has no directory")?;
    let root = parent
        .parent()
        .context("start fence has no temporary root")?;
    let root = open(
        root,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .context("open temporary root")?;
    let directory_name = parent.file_name().context("start fence directory name")?;
    match mkdirat(&root, directory_name, Mode::S_IRWXU) {
        Ok(()) | Err(Errno::EEXIST) => {},
        Err(error) => return Err(error).context("create start fence directory"),
    }
    // All later operations are relative to the captured directory descriptor.
    // Never chmod a pathname that may redirect into an unadmitted runtime.
    let directory = File::from(
        openat(
            &root,
            directory_name,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .context("open non-aliased start fence directory")?,
    );
    let metadata = directory.metadata()?;
    ensure!(
        metadata.uid() == nix::unistd::getuid().as_raw() && metadata.mode() & 0o777 == 0o700,
        "start fence directory must be owned by this user and mode 0700"
    );
    let name = path.file_name().context("start fence file name")?;
    let file = File::from(
        openat(
            &directory,
            name,
            OFlag::O_RDWR
                | OFlag::O_CREAT
                | OFlag::O_NOFOLLOW
                | OFlag::O_NONBLOCK
                | OFlag::O_CLOEXEC,
            Mode::S_IRUSR | Mode::S_IWUSR,
        )
        .context("open non-aliased start fence file")?,
    );
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.nlink() == 1
            && metadata.uid() == nix::unistd::getuid().as_raw()
            && metadata.mode() & 0o777 == 0o600,
        "start fence must be a private regular single-link file owned by this user"
    );
    file.lock().context("lock daemon start fence")?;
    Ok(file)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn lock_leaf_alias_is_refused_without_mutating_target() {
        let root = tempfile::tempdir().expect("owned root");
        let target = root.path().join("target");
        std::fs::write(&target, b"retained").expect("target contents");
        let directory = root.path().join("astrid-start-fences");
        std::fs::create_dir(&directory).expect("directory");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("private directory");
        let path = directory.join("fixture.lock");
        std::os::unix::fs::symlink(&target, &path).expect("leaf alias");
        assert!(open(&path).is_err());
        assert_eq!(
            std::fs::read(&target).expect("retained target"),
            b"retained"
        );
        assert!(
            path.symlink_metadata()
                .expect("retained alias")
                .is_symlink()
        );
    }

    #[test]
    fn private_fence_can_be_reused_after_unlock() {
        let root = tempfile::tempdir().expect("owned root");
        let path = root.path().join("astrid-start-fences/fixture.lock");
        drop(open(&path).expect("first fence"));
        drop(open(&path).expect("reused fence"));
        assert!(path.is_file());
    }
}

#[cfg(not(unix))]
pub(super) fn open(path: &Path) -> Result<File> {
    let parent = path.parent().context("start fence has no directory")?;
    match std::fs::create_dir(parent) {
        Ok(()) => {},
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {},
        Err(error) => return Err(error).context("create start fence directory"),
    }
    let metadata = std::fs::symlink_metadata(parent)?;
    ensure!(
        metadata.is_dir() && !metadata.is_symlink(),
        "aliased start fence directory"
    );
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        ensure!(
            metadata.is_file() && !metadata.is_symlink(),
            "aliased start fence file"
        );
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    file.lock()?;
    Ok(file)
}
