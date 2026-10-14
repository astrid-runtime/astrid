//! Open the singleton fence without following appended temporary-path aliases.
use std::fs::File;
use std::path::Path;

use anyhow::{Context, Result, ensure};

#[cfg(unix)]
pub(super) fn open(path: &Path) -> Result<File> {
    use nix::fcntl::{OFlag, open, openat};
    use nix::sys::stat::Mode;
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
    let directory_name = directory_for_user(&root, directory_name)?;
    // All later operations are relative to the captured directory descriptor.
    // Never chmod a pathname that may redirect into an unadmitted runtime.
    let directory = File::from(
        openat(
            &root,
            directory_name.as_os_str(),
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

/// Keep the legacy lock for its owner so old and new CLIs still serialize.
/// Other users cannot use that private directory; give each a private sibling.
#[cfg(unix)]
fn directory_for_user(
    root: &std::os::fd::OwnedFd,
    legacy_name: &std::ffi::OsStr,
) -> Result<std::ffi::OsString> {
    use nix::fcntl::AtFlags;
    use nix::sys::stat::{SFlag, fstatat};

    create_directory(root, legacy_name)?;
    let metadata = fstatat(root, legacy_name, AtFlags::AT_SYMLINK_NOFOLLOW)
        .context("inspect non-aliased start fence directory")?;
    ensure!(
        metadata.st_mode & SFlag::S_IFMT.bits() == SFlag::S_IFDIR.bits(),
        "start fence directory must be a real directory"
    );
    if metadata.st_uid == nix::unistd::getuid().as_raw() {
        return Ok(legacy_name.to_owned());
    }
    let mut name = legacy_name.to_owned();
    name.push(format!("-{}", nix::unistd::getuid()));
    create_directory(root, &name)?;
    Ok(name)
}

#[cfg(unix)]
fn create_directory(root: &std::os::fd::OwnedFd, name: &std::ffi::OsStr) -> Result<()> {
    use nix::errno::Errno;
    use nix::sys::stat::{Mode, mkdirat};

    match mkdirat(root, name, Mode::S_IRWXU) {
        Ok(()) | Err(Errno::EEXIST) => Ok(()),
        Err(error) => Err(error).context("create start fence directory"),
    }
}

#[cfg(all(test, unix))]
mod tests;

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
