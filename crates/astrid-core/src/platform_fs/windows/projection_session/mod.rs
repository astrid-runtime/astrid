//! Rooted Windows private projection session over `TrustedPathGuard`.
//!
//! Leaf mutations stay handle-relative under one captured root. This is not a
//! MOVE/empty-delete owner; [`super::CapturedDirectory`] remains that API.

mod publish;
mod scratch;

use std::cell::RefCell;

#[cfg(test)]
use std::cell::Cell;

#[cfg(test)]
use super::io::rename_guarded_handle;

pub(in crate::platform_fs) use scratch::create_private_scratch_file;

#[cfg(test)]
pub(in crate::platform_fs::windows) use publish::set_temporary_cleanup_failures;

use super::io::{
    FileContract, open_guarded_regular_file, remove_guarded_file_with_contract,
    validate_file_contract,
};
use super::ntfs_directory_flush::open_flush_bound_to_guard;
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
    /// Open a writer on an `ExactPrivate` projection root.
    ///
    /// Existing roots must already satisfy the private-directory contract;
    /// Windows does not repair privacy here (unlike Unix `make_private_directory`).
    /// Missing roots remain supported: [`ensure_private_directory`] creates them
    /// with the same paired child+parent NTFS namespace fences used for nested
    /// [`Self::ensure_directory`] births (not an unfenced create path).
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
        Replacement::for_write(self, relative)?
            .write_from(reader, exact_len)
            .1
    }

    pub(in crate::platform_fs) fn capture_replacement<'a>(
        &'a self,
        relative: &[OsString],
        sink: &mut dyn Write,
    ) -> io::Result<(Replacement<'a>, Option<u64>)> {
        let replacement = Replacement::for_write(self, relative)?;
        let length = replacement.snapshot_to(sink)?;
        Ok((replacement, length))
    }

    pub(in crate::platform_fs) fn rollback_publication(
        &self,
        relative: &[OsString],
        installed: Publication,
        prior: Option<(&mut dyn Read, u64)>,
    ) -> io::Result<()> {
        if installed.root != self.identity {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "publication belongs to a different projection root",
            ));
        }
        let replacement = Replacement::open(self, relative, ParentMode::Existing)?;
        if replacement.previous != Some(installed.file) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "published projection file was replaced before rollback",
            ));
        }
        if let Some((reader, length)) = prior {
            replacement.write_from(reader, length).1
        } else {
            publish::require_destination(
                replacement.parent(),
                &replacement.path,
                Some(installed.file),
            )?;
            remove_guarded_file_with_contract(
                replacement.parent(),
                &replacement.path,
                FileContract::Trusted,
            )?;
            flush_captured_namespace(replacement.parent())?;
            self.guard
                .verify_contract(BoundaryContract::ExactPrivateDirectory)
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
        let fence = (|| {
            flush_captured_namespace(&self.guard)?;
            self.confirm_absolute_binding()
        })();
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
                Ok(()) => {
                    flush_captured_namespace(parent)?;
                    Ok(())
                },
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

    #[cfg(test)]
    pub(in crate::platform_fs) fn matches_private_file(
        &self,
        relative: &[OsString],
        expected: &[u8],
    ) -> io::Result<bool> {
        self.matches_private_file_from(
            relative,
            u64::try_from(expected.len()).map_err(io::Error::other)?,
            &mut io::Cursor::new(expected),
        )
    }

    pub(in crate::platform_fs) fn matches_private_file_from(
        &self,
        relative: &[OsString],
        length: u64,
        expected: &mut dyn Read,
    ) -> io::Result<bool> {
        let (dirs, name) = split_relative(relative)?;
        let mut run = |parent: &TrustedPathGuard| {
            let path = parent.authority_boundary().join(name);
            parent.verify_contract(BoundaryContract::ExactPrivateDirectory)?;
            let mut file = open_guarded_regular_file(parent, &path, FileContract::ExactPrivate)?;
            let matched = crate::platform_fs::private_projection::compare::matches_file_from(
                &mut file, length, expected,
            )?;
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

/// FileId-bound NTFS parent/root directory-structure flush for projection fences.
pub(super) fn flush_captured_namespace(guard: &TrustedPathGuard) -> io::Result<()> {
    #[cfg(test)]
    test_maybe_fail_namespace_flush()?;
    open_flush_bound_to_guard(guard)?.flush()
}

#[cfg(test)]
thread_local! {
    static NAMESPACE_FLUSH_FAILURES: Cell<usize> = const { Cell::new(0) };
}

#[cfg(test)]
/// Arm the next `count` projection namespace flush failures on this thread only.
///
/// Drop the returned guard (or let it fall out of scope) to clear the arm so
/// parallel tests cannot steal faults.
pub(in crate::platform_fs) fn install_namespace_flush_failures(
    count: usize,
) -> NamespaceFlushFaultReset {
    NAMESPACE_FLUSH_FAILURES.with(|slot| slot.set(count));
    NamespaceFlushFaultReset
}

#[cfg(test)]
#[must_use]
pub(in crate::platform_fs) struct NamespaceFlushFaultReset;

#[cfg(test)]
impl Drop for NamespaceFlushFaultReset {
    fn drop(&mut self) {
        NAMESPACE_FLUSH_FAILURES.with(|slot| slot.set(0));
    }
}

#[cfg(test)]
fn test_maybe_fail_namespace_flush() -> io::Result<()> {
    NAMESPACE_FLUSH_FAILURES.with(|slot| {
        let remaining = slot.get();
        if remaining == 0 {
            return Ok(());
        }
        slot.set(remaining.strict_sub(1));
        Err(io::Error::other(
            "injected projection namespace flush failure",
        ))
    })
}

/// Private publication receipt binds the exact installed identity to its root.
#[derive(Clone, Copy)]
pub(in crate::platform_fs) struct Publication {
    root: FileIdentity,
    file: FileIdentity,
}

#[derive(Clone, Copy)]
enum ParentMode {
    Create,
    Existing,
}

pub(in crate::platform_fs) struct Replacement<'a> {
    owner: &'a ProjectionRoot,
    parent: Option<TrustedPathGuard>,
    path: PathBuf,
    previous: Option<FileIdentity>,
}
impl<'a> Replacement<'a> {
    fn for_write(owner: &'a ProjectionRoot, relative: &[OsString]) -> io::Result<Self> {
        Self::open(owner, relative, ParentMode::Create)
    }

    fn open(
        owner: &'a ProjectionRoot,
        relative: &[OsString],
        mode: ParentMode,
    ) -> io::Result<Self> {
        owner.cleanup_temporary()?;
        let (dirs, name) = split_relative(relative)?;
        reject_reserved_name(name)?;
        owner
            .guard
            .verify_contract(BoundaryContract::ExactPrivateDirectory)?;
        let parent = if dirs.is_empty() {
            None
        } else {
            Some(
                owner
                    .guard
                    .capture_descendant_directory(dirs, matches!(mode, ParentMode::Create))?,
            )
        };
        let guard = parent.as_ref().unwrap_or(&owner.guard);
        let path = guard.authority_boundary().join(name);
        let previous = publish::destination_identity(guard, &path)?;
        Ok(Self {
            owner,
            parent,
            path,
            previous,
        })
    }
    fn parent(&self) -> &TrustedPathGuard {
        self.parent.as_ref().unwrap_or(&self.owner.guard)
    }
    fn snapshot_to(&self, sink: &mut dyn Write) -> io::Result<Option<u64>> {
        publish::require_destination(self.parent(), &self.path, self.previous)?;
        let Some(identity) = self.previous else {
            self.parent()
                .verify_contract(BoundaryContract::ExactPrivateDirectory)?;
            return Ok(None);
        };
        let mut file = open_guarded_regular_file(self.parent(), &self.path, FileContract::Trusted)?;
        if super::path::file_identity(&file)? != identity {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "projection changed before backup",
            ));
        }
        let length = io::copy(&mut file, sink)?;
        validate_file_contract(
            file.as_raw_handle().cast(),
            &self.path,
            FileContract::Trusted,
        )?;
        drop(file);
        publish::require_destination(self.parent(), &self.path, self.previous)?;
        self.parent()
            .verify_contract(BoundaryContract::ExactPrivateDirectory)?;
        self.owner
            .guard
            .verify_contract(BoundaryContract::ExactPrivateDirectory)?;
        Ok(Some(length))
    }
    pub(in crate::platform_fs) fn write_from(
        self,
        reader: &mut dyn Read,
        length: u64,
    ) -> (Option<Publication>, io::Result<()>) {
        if let Err(error) = publish::require_destination(self.parent(), &self.path, self.previous) {
            return (None, Err(error));
        }
        match publish::publish_from_reader(
            self.parent(),
            &self.path,
            reader,
            length,
            self.owner.staging_scope,
            self.previous,
        ) {
            Ok(file) => (
                Some(Publication {
                    root: self.owner.identity,
                    file,
                }),
                self.owner
                    .guard
                    .verify_contract(BoundaryContract::ExactPrivateDirectory),
            ),
            Err(mut failure) => {
                let installed = failure.published.take().map(|file| Publication {
                    root: self.owner.identity,
                    file,
                });
                (installed, Err(self.owner.retain_publish_failure(failure)))
            },
        }
    }
}
