//! Root binding and bounded relative directory ownership.

use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::path::{Component, Path, PathBuf};

use nix::fcntl::openat;
use nix::sys::stat::{Mode, SFlag, fchmod, mkdirat};
use nix::unistd::{fsync, getuid};

use super::{
    DescriptorObservation, Identity, MountBoundary, directory_flags, entry_stat, fstat, invalid,
    nix_io_error, verify_identity, verify_observed_identity,
};

pub(super) struct Root {
    parent: File,
    name: OsString,
    pub(super) file: File,
    identity: Identity,
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

    pub(super) fn validate(&self, boundary: &MountBoundary) -> io::Result<()> {
        let held = DescriptorObservation::read(&self.file)?;
        validate_private_directory(&held)?;
        verify_observed_identity(&self.parent, &self.name, &held, self.identity)?;
        let current = File::from(
            openat(
                &self.parent,
                self.name.as_os_str(),
                directory_flags(),
                Mode::empty(),
            )
            .map_err(nix_io_error)?,
        );
        let current = DescriptorObservation::read(&current)?;
        if Identity::read(current.stat()) != self.identity {
            return Err(invalid("projection root binding changed"));
        }
        boundary.validate_observation(&current)
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
        create: bool,
    ) -> io::Result<Option<Self>> {
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
                None if !create => {
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
            if make_private_directory(&file)? || created {
                fsync(&file).map_err(nix_io_error)?;
                fsync(parent).map_err(nix_io_error)?;
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
            let held = DescriptorObservation::read(&binding.file)?;
            validate_private_directory(&held)?;
            verify_observed_identity(parent, &binding.name, &held, binding.identity)?;
            let current = File::from(
                openat(
                    parent,
                    binding.name.as_os_str(),
                    directory_flags(),
                    Mode::empty(),
                )
                .map_err(nix_io_error)?,
            );
            let current = DescriptorObservation::read(&current)?;
            if Identity::read(current.stat()) != binding.identity {
                return Err(invalid("projection directory binding changed"));
            }
            boundary.validate_observation(&current)?;
            parent = &binding.file;
        }
        Ok(())
    }
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

fn validate_private_directory(observed: &DescriptorObservation<'_>) -> io::Result<()> {
    let stat = observed.stat();
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
    crate::platform_fs::macos_acl::validate(observed.file())?;
    Ok(())
}
