//! Root binding and bounded relative directory ownership.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::path::{Component, Path, PathBuf};

use nix::fcntl::openat;
use nix::sys::stat::{FileStat, Mode, SFlag, fchmod, mkdirat};
use nix::unistd::{fsync, getuid};

use super::{
    Identity, MountBoundary, directory_flags, entry_stat, fstat, invalid, nix_io_error,
    verify_identity,
};

/// Typed directory-walk authority for one rooted projection session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WalkPolicy {
    /// Open existing private directories only; never create or repair.
    Inspect,
    /// Open existing directories and repair privacy; never create.
    Repair,
    /// Create missing private directories and repair privacy as needed.
    Create,
}

pub(super) struct Root {
    parent: File,
    name: OsString,
    pub(super) file: File,
    pub(super) identity: Identity,
    absolute: PathBuf,
}

impl Root {
    pub(super) fn open(path: &Path) -> io::Result<Self> {
        if path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::Prefix(_)))
        {
            return Err(invalid("projection root contains traversal"));
        }
        let absolute = crate::platform_fs::normalize_unix_system_alias(if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()?.join(path)
        });
        let parent_path = absolute
            .parent()
            .ok_or_else(|| invalid("projection root has no parent"))?;
        let name = absolute
            .file_name()
            .ok_or_else(|| invalid("projection root has no name"))?
            .to_os_string();
        let parent = crate::platform_fs::open_existing_directory_no_follow(parent_path)?;
        let file = File::from(
            openat(&parent, name.as_os_str(), directory_flags(), Mode::empty())
                .map_err(nix_io_error)?,
        );
        let identity = Identity::of(&file)?;
        verify_identity(&parent, &name, &file, identity)?;
        Ok(Self {
            parent,
            name,
            file,
            identity,
            absolute,
        })
    }

    pub(super) fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            parent: self.parent.try_clone()?,
            name: self.name.clone(),
            file: self.file.try_clone()?,
            identity: self.identity,
            absolute: self.absolute.clone(),
        })
    }

    pub(super) fn validate(&self, boundary: &MountBoundary) -> io::Result<()> {
        validate_binding(&self.parent, &self.name, self.identity, boundary)
    }

    pub(super) fn validate_absolute(&self, boundary: &MountBoundary) -> io::Result<()> {
        self.validate(boundary)?;
        let current = crate::platform_fs::open_existing_directory_no_follow(&self.absolute)?;
        if Identity::of(&current)? != self.identity {
            return Err(invalid("projection absolute root binding changed"));
        }
        boundary.validate(&current)
    }
}

struct DirectoryBinding {
    name: OsString,
    file: File,
    identity: Identity,
}

pub(super) struct DirectoryChain<'a> {
    root: &'a Root,
    bindings: Vec<DirectoryBinding>,
}

impl<'a> DirectoryChain<'a> {
    pub(super) fn walk(
        root: &'a Root,
        boundary: &MountBoundary,
        names: &[OsString],
        policy: WalkPolicy,
    ) -> io::Result<Option<Self>> {
        #[cfg(test)]
        RELATIVE_WALKS.with(|count| count.set(count.get().strict_add(1)));
        root.validate(boundary)?;
        let mut chain = Self {
            root,
            bindings: Vec::with_capacity(names.len()),
        };
        for name in names {
            let parent = chain.directory();
            let mut created = false;
            let initial = match entry_stat(parent, name)? {
                Some(stat) => stat,
                None if matches!(policy, WalkPolicy::Inspect | WalkPolicy::Repair) => {
                    chain.validate(boundary)?;
                    return Ok(None);
                },
                None => {
                    match mkdirat(parent, name.as_os_str(), Mode::from_bits_truncate(0o700)) {
                        Ok(()) => created = true,
                        Err(nix::errno::Errno::EEXIST) => {},
                        Err(error) => return Err(nix_io_error(error)),
                    }
                    entry_stat(parent, name)?
                        .ok_or_else(|| invalid("new projection directory disappeared"))?
                },
            };
            if initial.st_mode & SFlag::S_IFMT.bits() != SFlag::S_IFDIR.bits() {
                return Err(invalid("projection parent is not a real directory"));
            }
            let file = File::from(
                openat(parent, name.as_os_str(), directory_flags(), Mode::empty())
                    .map_err(nix_io_error)?,
            );
            let identity = Identity::read(&initial);
            verify_identity(parent, name, &file, identity)?;
            boundary.validate(&file)?;
            match policy {
                WalkPolicy::Inspect => {
                    validate_private_directory(&file)?;
                },
                WalkPolicy::Repair | WalkPolicy::Create => {
                    if make_private_directory(&file)? || created {
                        fsync(&file).map_err(nix_io_error)?;
                        fsync(parent).map_err(nix_io_error)?;
                    }
                },
            }
            chain.bindings.push(DirectoryBinding {
                name: name.clone(),
                file,
                identity,
            });
        }
        chain.validate(boundary)?;
        Ok(Some(chain))
    }

    pub(super) fn directory(&self) -> &File {
        self.bindings
            .last()
            .map_or(&self.root.file, |binding| &binding.file)
    }

    pub(super) fn validate(&self, boundary: &MountBoundary) -> io::Result<()> {
        self.root.validate(boundary)?;
        let mut parent = &self.root.file;
        for binding in &self.bindings {
            validate_binding(parent, &binding.name, binding.identity, boundary)?;
            parent = &binding.file;
        }
        Ok(())
    }
}

fn validate_binding(
    parent: &File,
    name: &OsStr,
    expected: Identity,
    boundary: &MountBoundary,
) -> io::Result<()> {
    let current =
        File::from(openat(parent, name, directory_flags(), Mode::empty()).map_err(nix_io_error)?);
    // The retained descriptor pins the captured inode. Matching the fresh
    // no-follow handle lets privacy, identity and mount checks use one object.
    let stat = validate_private_directory(&current)?;
    if Identity::read(&stat) != expected {
        return Err(invalid("projection directory binding changed"));
    }
    boundary.validate(&current)
}

pub(super) fn make_private_directory(file: &File) -> io::Result<bool> {
    let stat = fstat(file).map_err(nix_io_error)?;
    if stat.st_mode & SFlag::S_IFMT.bits() != SFlag::S_IFDIR.bits()
        || stat.st_uid != getuid().as_raw()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "projection directory is not owned by the current user",
        ));
    }
    let mut changed = false;
    if stat.st_mode & 0o777 != 0o700 {
        fchmod(file, Mode::from_bits_truncate(0o700)).map_err(nix_io_error)?;
        changed = true;
    }
    #[cfg(target_os = "macos")]
    if crate::platform_fs::macos_acl::validate(file).is_err() {
        crate::platform_fs::macos_acl::restrict(file)?;
        changed = true;
    }
    Ok(changed)
}

fn validate_private_directory(file: &File) -> io::Result<FileStat> {
    let stat = fstat(file).map_err(nix_io_error)?;
    if stat.st_mode & SFlag::S_IFMT.bits() != SFlag::S_IFDIR.bits()
        || stat.st_uid != getuid().as_raw()
        || stat.st_mode & 0o777 != 0o700
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "projection directory is not private",
        ));
    }
    #[cfg(target_os = "macos")]
    crate::platform_fs::macos_acl::validate(file)?;
    Ok(stat)
}

#[cfg(test)]
thread_local! { static RELATIVE_WALKS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }
#[cfg(test)]
pub(super) fn take_relative_walks() -> usize {
    RELATIVE_WALKS.with(|count| count.replace(0))
}

#[cfg(test)]
mod validation_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn directory_validation_reads_each_current_identity_once() {
        let home = tempfile::tempdir().expect("temporary directory");
        let root_path = home.path().join("root");
        std::fs::create_dir(&root_path).expect("create root");
        std::fs::set_permissions(&root_path, std::fs::Permissions::from_mode(0o700))
            .expect("private root");
        let names = [OsString::from("first"), OsString::from("second")];
        let mut path = root_path.clone();
        for name in &names {
            path.push(name);
            std::fs::create_dir(&path).expect("create ancestor");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                .expect("private ancestor");
        }
        let root = Root::open(&root_path).expect("capture root");
        let boundary = MountBoundary::new(&root.file).expect("capture mount boundary");
        let chain = DirectoryChain::walk(&root, &boundary, &names, WalkPolicy::Inspect)
            .expect("capture chain")
            .expect("existing chain");
        super::super::hooks::take_file_stat_queries();
        chain.validate(&boundary).expect("validate captured chain");
        assert_eq!(
            super::super::hooks::take_file_stat_queries(),
            names.len() + 1
        );
        root.validate(&boundary).expect("validate captured root");
        assert_eq!(super::super::hooks::take_file_stat_queries(), 1);
    }
}
