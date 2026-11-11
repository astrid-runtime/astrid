//! Rooted Windows private projection session over `TrustedPathGuard`.
//!
//! Leaf mutations stay handle-relative under one captured root. This is not a
//! MOVE/empty-delete owner; [`super::CapturedDirectory`] remains that API.

mod publish;
mod scratch;

use std::cell::RefCell;

#[cfg(test)]
use super::io::rename_guarded_handle;

pub(in crate::platform_fs) use scratch::create_private_scratch_file;

#[cfg(test)]
pub(in crate::platform_fs::windows) use publish::set_temporary_cleanup_failures;

use super::io::{
    FileContract, open_guarded_regular_file, remove_guarded_file_with_contract,
    validate_file_contract,
};
use super::path::{
    BoundaryContract, FileIdentity, TrustedPathGuard, open_directory_identity,
    validate_local_absolute_path,
};
use super::prelude::*;
use super::private_file::{PRIVATE_FILE_TRANSACTION_JOURNAL, PRIVATE_FILE_TRANSACTION_LOCK};
use crate::platform_fs::StagingScope;

/// Writer session bound to one captured private projection root.
pub(in crate::platform_fs) struct ProjectionRoot {
    guard: TrustedPathGuard,
    absolute: PathBuf,
    identity: FileIdentity,
    staging_scope: Option<StagingScope>,
    pending_temporary: RefCell<Option<publish::PendingTemporary>>,
}

impl ProjectionRoot {
    /// Open a writer on an existing `ExactPrivate` projection root.
    ///
    /// Existing roots must already satisfy the private-directory contract;
    /// Windows does not repair privacy here (unlike Unix `make_private_directory`).
    /// Missing roots are created private via [`ensure_private_directory`].
    pub(in crate::platform_fs) fn open_writer(
        root: &Path,
        staging_scope: Option<StagingScope>,
    ) -> io::Result<Self> {
        validate_local_absolute_path(root)?;
        super::path::ensure_private_directory(root)?;
        let guard = TrustedPathGuard::capture(root)?;
        guard.verify_contract(BoundaryContract::ExactPrivateDirectory)?;
        Ok(Self {
            identity: guard.authority_identity(),
            absolute: root.to_path_buf(),
            guard,
            staging_scope,
            pending_temporary: RefCell::new(None),
        })
    }

    /// Snapshot a regular leaf into `output` without retaining a `Vec`.
    ///
    /// Uses [`FileContract::Trusted`] so ordinary prior generations remain
    /// capturable for rollback. Published `ExactPrivate` leaves still validate.
    pub(in crate::platform_fs) fn snapshot_to(
        &self,
        relative: &[OsString],
        output: &mut dyn Write,
    ) -> io::Result<Option<u64>> {
        let (dirs, name) = split_relative(relative)?;
        let result = self.with_parent(dirs, false, |parent| {
            let path = parent.authority_boundary().join(name);
            // Prior generations may be ordinary/trusted host files (portable
            // profiles, externally edited state). ExactPrivate stays on publish,
            // matches, and authorized-private delete.
            match open_guarded_regular_file(parent, &path, FileContract::Trusted) {
                Ok(mut file) => {
                    let written = io::copy(&mut file, output)?;
                    validate_file_contract(
                        file.as_raw_handle().cast(),
                        &path,
                        FileContract::Trusted,
                    )?;
                    parent.verify_contract(BoundaryContract::ExactPrivateDirectory)?;
                    Ok(Some(written))
                },
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    parent.verify_contract(BoundaryContract::ExactPrivateDirectory)?;
                    Ok(None)
                },
                Err(error) => Err(error),
            }
        });
        match result {
            Ok(value) => {
                self.guard
                    .verify_contract(BoundaryContract::ExactPrivateDirectory)?;
                Ok(value)
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                // Missing intermediate directories are absence, not hard failure,
                // once the captured root still validates.
                self.guard
                    .verify_contract(BoundaryContract::ExactPrivateDirectory)?;
                Ok(None)
            },
            Err(error) => Err(error),
        }
    }

    /// Publish private bytes from a reader of exactly `exact_len`.
    ///
    /// Stages under a scoped (or legacy unscoped) temporary basename, then
    /// renames with the same held parent guard. Does not create private-file
    /// journal or lock sidecars; batch crash recovery remains RETIRING-owned.
    pub(in crate::platform_fs) fn write_from(
        &self,
        relative: &[OsString],
        reader: &mut dyn Read,
        exact_len: u64,
    ) -> io::Result<()> {
        self.cleanup_temporary()?;
        let (dirs, name) = split_relative(relative)?;
        reject_reserved_name(name)?;
        self.guard
            .verify_contract(BoundaryContract::ExactPrivateDirectory)?;
        let published = if dirs.is_empty() {
            let path = self.guard.authority_boundary().join(name);
            publish::publish_from_reader(&self.guard, &path, reader, exact_len, self.staging_scope)
        } else {
            let parent = self.guard.capture_descendant_directory(dirs, true)?;
            let path = parent.authority_boundary().join(name);
            publish::publish_from_reader(&parent, &path, reader, exact_len, self.staging_scope)
        };
        match published {
            Ok(()) => self
                .guard
                .verify_contract(BoundaryContract::ExactPrivateDirectory),
            Err(failure) => Err(self.retain_publish_failure(failure)),
        }
    }

    /// Convenience wrapper around [`Self::write_from`].
    pub(in crate::platform_fs) fn write(
        &self,
        relative: &[OsString],
        bytes: &[u8],
    ) -> io::Result<()> {
        let len = u64::try_from(bytes.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "projection payload is too large",
            )
        })?;
        self.write_from(relative, &mut io::Cursor::new(bytes), len)
    }

    pub(in crate::platform_fs) fn remove(&self, relative: &[OsString]) -> io::Result<()> {
        self.remove_leaf(relative, FileContract::Trusted)
    }

    pub(in crate::platform_fs) fn remove_authorized_private_leaf(
        &self,
        relative: &[OsString],
    ) -> io::Result<()> {
        self.remove_leaf(relative, FileContract::ExactPrivate)
    }

    pub(in crate::platform_fs) fn remove_staging(
        &self,
        relative: &[OsString],
        scope: StagingScope,
    ) -> io::Result<()> {
        let name = relative.last().ok_or_else(invalid_relative)?;
        if !scope.matches_temporary_basename(name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "staging removal name is outside the durable restoration scope",
            ));
        }
        let Some(bound) = self.staging_scope else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "staging removal requires a bound restoration scope",
            ));
        };
        if bound != scope {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "staging removal scope does not match the bound projection session",
            ));
        }
        self.remove_authorized_private_leaf(relative)
    }

    pub(in crate::platform_fs) fn ensure_directory(&self, relative: &[OsString]) -> io::Result<()> {
        self.cleanup_temporary()?;
        if relative.is_empty() {
            return Err(invalid_relative());
        }
        self.guard
            .verify_contract(BoundaryContract::TrustedForCreate)?;
        let _ = self.guard.capture_descendant_directory(relative, true)?;
        self.guard
            .verify_contract(BoundaryContract::ExactPrivateDirectory)
    }

    pub(in crate::platform_fs) fn sync(&self) -> io::Result<()> {
        let cleanup = self.cleanup_temporary();
        let fence = self.confirm_absolute_binding();
        match cleanup {
            Ok(()) => fence,
            Err(error) => Err(combine_cleanup_and_fence(error, fence)),
        }
    }

    fn cleanup_temporary(&self) -> io::Result<()> {
        let mut pending = self.pending_temporary.borrow_mut();
        if let Some(temporary) = pending.as_ref() {
            temporary.cleanup()?;
        }
        pending.take();
        Ok(())
    }

    fn retain_publish_failure(&self, failure: publish::PublishFailure) -> io::Error {
        if let Some(pending) = failure.pending {
            *self.pending_temporary.borrow_mut() = Some(pending);
        }
        failure.error
    }

    #[cfg(test)]
    pub(in crate::platform_fs::windows) fn test_has_pending_temporary(&self) -> bool {
        self.pending_temporary.borrow().is_some()
    }

    /// Rename the retained pending temporary by its held handle only.
    ///
    /// Used to place an unrelated same-basename decoy and prove cleanup never
    /// deletes by path reopen.
    #[cfg(test)]
    pub(in crate::platform_fs::windows) fn test_park_pending_temporary(
        &self,
        aside_name: &OsStr,
    ) -> io::Result<()> {
        let pending = self.pending_temporary.borrow();
        let Some(temporary) = pending.as_ref() else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "projection has no pending temporary to park",
            ));
        };
        let destination = self.guard.authority_boundary().join(aside_name);
        rename_guarded_handle(temporary.file(), &self.guard, &destination, false)
    }

    fn remove_leaf(&self, relative: &[OsString], contract: FileContract) -> io::Result<()> {
        self.cleanup_temporary()?;
        let (dirs, name) = split_relative(relative)?;
        let result = self.with_parent(dirs, false, |parent| {
            let path = parent.authority_boundary().join(name);
            match remove_guarded_file_with_contract(parent, &path, contract) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error),
            }
        });
        match result {
            Ok(()) => self
                .guard
                .verify_contract(BoundaryContract::ExactPrivateDirectory),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn with_parent<T>(
        &self,
        dirs: &[OsString],
        create: bool,
        action: impl FnOnce(&TrustedPathGuard) -> io::Result<T>,
    ) -> io::Result<T> {
        self.guard
            .verify_contract(BoundaryContract::ExactPrivateDirectory)?;
        if dirs.is_empty() {
            return action(&self.guard);
        }
        let parent = self.guard.capture_descendant_directory(dirs, create)?;
        action(&parent)
    }

    fn confirm_absolute_binding(&self) -> io::Result<()> {
        self.guard
            .verify_contract(BoundaryContract::ExactPrivateDirectory)?;
        let (handle, identity) = open_directory_identity(&self.absolute, true)?;
        drop(handle);
        if identity != self.identity {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "projection absolute root binding changed: {}",
                    self.absolute.display()
                ),
            ));
        }
        self.guard
            .verify_contract(BoundaryContract::ExactPrivateDirectory)
    }
}

/// Read-only matching session; opening never repairs privacy.
pub(in crate::platform_fs) struct ProjectionInspection {
    guard: TrustedPathGuard,
    absolute: PathBuf,
    identity: FileIdentity,
}

impl ProjectionInspection {
    pub(in crate::platform_fs) fn try_open(root: &Path) -> io::Result<Self> {
        validate_local_absolute_path(root)?;
        // Retain the validated identity for the whole inspection; never repair.
        let guard = TrustedPathGuard::capture(root)?;
        guard.verify_contract(BoundaryContract::ExactPrivateDirectory)?;
        Ok(Self {
            identity: guard.authority_identity(),
            absolute: root.to_path_buf(),
            guard,
        })
    }

    pub(in crate::platform_fs) fn matches_private_directory(
        &self,
        relative: &[OsString],
    ) -> io::Result<bool> {
        if relative.is_empty() {
            return Ok(false);
        }
        match self.guard.capture_descendant_directory(relative, false) {
            Ok(dir) => {
                dir.verify_contract(BoundaryContract::ExactPrivateDirectory)?;
                self.guard
                    .verify_contract(BoundaryContract::ExactPrivateDirectory)?;
                Ok(true)
            },
            Err(error) if is_non_match(&error) => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub(in crate::platform_fs) fn matches_private_file(
        &self,
        relative: &[OsString],
        expected: &[u8],
    ) -> io::Result<bool> {
        let (dirs, name) = split_relative(relative)?;
        let run = |parent: &TrustedPathGuard| {
            let path = parent.authority_boundary().join(name);
            parent.verify_contract(BoundaryContract::ExactPrivateDirectory)?;
            let mut file = open_guarded_regular_file(parent, &path, FileContract::ExactPrivate)?;
            let matched =
                crate::platform_fs::private_projection::compare::matches_file(&mut file, expected)?;
            validate_file_contract(
                file.as_raw_handle().cast(),
                &path,
                FileContract::ExactPrivate,
            )?;
            parent.verify_contract(BoundaryContract::ExactPrivateDirectory)?;
            Ok(matched)
        };
        let matched = if dirs.is_empty() {
            match run(&self.guard) {
                Ok(value) => value,
                Err(error) if is_non_match(&error) => false,
                Err(error) => return Err(error),
            }
        } else {
            match self.guard.capture_descendant_directory(dirs, false) {
                Ok(parent) => match run(&parent) {
                    Ok(value) => value,
                    Err(error) if is_non_match(&error) => false,
                    Err(error) => return Err(error),
                },
                Err(error) if is_non_match(&error) => false,
                Err(error) => return Err(error),
            }
        };
        self.guard
            .verify_contract(BoundaryContract::ExactPrivateDirectory)?;
        Ok(matched)
    }

    pub(in crate::platform_fs) fn confirm_absolute_root(&self) -> io::Result<()> {
        self.guard
            .verify_contract(BoundaryContract::ExactPrivateDirectory)?;
        let (handle, identity) = open_directory_identity(&self.absolute, true)?;
        drop(handle);
        if identity != self.identity {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "projection absolute root binding changed: {}",
                    self.absolute.display()
                ),
            ));
        }
        self.guard
            .verify_contract(BoundaryContract::ExactPrivateDirectory)
    }
}

fn split_relative(relative: &[OsString]) -> io::Result<(&[OsString], &OsStr)> {
    let (name, dirs) = relative.split_last().ok_or_else(invalid_relative)?;
    if name.is_empty() || dirs.iter().any(|part| part.is_empty()) {
        return Err(invalid_relative());
    }
    Ok((dirs, name.as_os_str()))
}

fn reject_reserved_name(name: &OsStr) -> io::Result<()> {
    let lower = name.to_string_lossy().to_ascii_lowercase();
    if lower.starts_with(".astrid-private.")
        || lower == PRIVATE_FILE_TRANSACTION_JOURNAL
        || lower == PRIVATE_FILE_TRANSACTION_LOCK
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private file name conflicts with Astrid recovery metadata",
        ));
    }
    Ok(())
}

fn invalid_relative() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "projection path contains a non-normal component",
    )
}

fn is_non_match(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound
            | io::ErrorKind::PermissionDenied
            | io::ErrorKind::InvalidData
            | io::ErrorKind::InvalidInput
    )
}

fn combine_cleanup_and_fence(cleanup: io::Error, fence: io::Result<()>) -> io::Error {
    match fence {
        Ok(()) => cleanup,
        Err(fence_error) => io::Error::new(
            cleanup.kind(),
            format!("{cleanup}; absolute root fence failed: {fence_error}"),
        ),
    }
}
