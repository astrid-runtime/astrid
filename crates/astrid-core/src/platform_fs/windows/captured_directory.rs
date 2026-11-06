//! Captured Windows directory handle used as rename and empty-delete authority.
//!
//! The source parent [`TrustedPathGuard`] is dropped after the directory file is
//! captured. The retained [`File`] is `Send` and remains the owner across await
//! points. This is not a durable MOVE receipt or resume journal.

use super::error::with_context;
use super::io::rename_guarded_handle;
use super::path::{OwnedHandle, TrustedPathGuard, open_directory_identity_relative_with_access};
use super::prelude::*;
use crate::platform_fs::DirectoryIdentity;
use std::os::windows::io::BorrowedHandle;
use windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND;

/// Windows directory opened with delete access and without delete sharing.
///
/// `open` captures an existing child of a trusted parent. `rename_to` moves that
/// same object into a trusted destination parent without replacing an occupant.
/// `remove_empty` deletes only an empty captured directory through the retained
/// handle. Cloning the directory file duplicates the native object; it does not
/// reopen a path and does not restore pathname authority if ancestors move.
pub struct CapturedDirectory {
    file: File,
    identity: DirectoryIdentity,
    parent: File,
    name: OsString,
}

impl CapturedDirectory {
    /// Capture an existing directory as rename and empty-delete authority.
    ///
    /// The path must have a parent and a file name. The parent is captured as a
    /// [`TrustedPathGuard`] only long enough to open the child with `DELETE` and
    /// `FILE_LIST_DIRECTORY` while denying `FILE_SHARE_DELETE`. Identity is the
    /// 128-bit `FileIdInfo` of that handle. Failure leaves the source tree
    /// uncaptured.
    ///
    /// # Errors
    ///
    /// Returns an error if the path is missing a parent or name, the parent
    /// cannot be captured, the child cannot be opened as a directory, or
    /// `FileIdInfo` cannot be queried.
    pub fn open(path: &Path) -> io::Result<Self> {
        let parent = path.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "captured Windows directory has no parent: {}",
                    path.display()
                ),
            )
        })?;
        let name = path.file_name().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("captured Windows directory has no name: {}", path.display()),
            )
        })?;
        let source_parent = TrustedPathGuard::capture(parent).map_err(|error| {
            with_context(error, format!("capture parent of {}", path.display()))
        })?;
        let (handle, _) = open_directory_identity_relative_with_access(
            source_parent.authority_handle(),
            name,
            true,
            DELETE | FILE_LIST_DIRECTORY,
        )
        .map_err(|error| {
            with_context(error, format!("open captured directory {}", path.display()))
        })?;
        let parent = duplicate_directory_handle(source_parent.authority_handle())?;
        let file = into_std_file(handle);
        let identity = query_directory_identity(&file)?;
        Ok(Self {
            file,
            identity,
            parent,
            name: name.to_os_string(),
        })
    }

    /// Duplicate the captured native directory object.
    ///
    /// The returned file is `DuplicateHandle` of the same object, retaining
    /// `FILE_LIST_DIRECTORY`. It is not a second pathname open and has no
    /// pathname authority if ancestors later move.
    ///
    /// # Errors
    ///
    /// Returns an error if the handle cannot be duplicated.
    pub fn try_clone_directory_file(&self) -> io::Result<File> {
        self.file.try_clone()
    }

    /// Return the captured 128-bit directory identity.
    #[must_use]
    pub fn identity(&self) -> DirectoryIdentity {
        self.identity
    }

    /// Move the captured directory into `destination` without replacement.
    ///
    /// The destination parent is captured for the native call and retained
    /// for the eventual handle-relative removal check. The destination must be a direct child of that parent. The source
    /// file remains open through return. This does not establish a durable MOVE
    /// receipt.
    ///
    /// # Errors
    ///
    /// Returns an error if the destination has no parent, the parent cannot be
    /// captured, the destination is not a direct child, or the no-replace rename
    /// fails. Failure leaves the captured source unmoved.
    pub fn rename_to(&mut self, destination: &Path) -> io::Result<()> {
        let parent = destination.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "captured rename destination has no parent: {}",
                    destination.display()
                ),
            )
        })?;
        let destination_parent = TrustedPathGuard::capture(parent).map_err(|error| {
            with_context(
                error,
                format!("capture destination parent of {}", destination.display()),
            )
        })?;
        let parent = duplicate_directory_handle(destination_parent.authority_handle())?;
        let name = destination
            .file_name()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "captured destination has no name",
                )
            })?
            .to_os_string();
        rename_guarded_handle(&self.file, &destination_parent, destination, false)?;
        self.parent = parent;
        self.name = name;
        Ok(())
    }

    /// Delete the captured directory if it is empty, consuming the handle.
    ///
    /// Uses classic `FileDispositionInformation` so a nonempty directory is
    /// refused and POSIX unlink-while-open is not applied. Callers must empty
    /// contents through a cloned directory file and drop that clone first. This
    /// does not recurse. Success also requires proving the child name absent
    /// through the retained parent. An outstanding duplicate may delay actual
    /// deletion: that returns an error, never completed retirement. Because
    /// `self` is consumed, errors still close the captured handle.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory is not empty or the delete disposition
    /// is refused.
    pub fn remove_empty(self) -> io::Result<()> {
        let Self {
            file, parent, name, ..
        } = self;
        delete_empty_directory(&file)?;
        drop(file);
        // A duplicate may keep the same native file object delete-pending.
        // Only a missing child is proof of namespace removal; an existing
        // child, DELETE_PENDING, or any other error is not success.
        match open_directory_identity_relative_with_access(
            parent.as_raw_handle().cast(),
            &name,
            false,
            0,
        ) {
            Err(error) if child_name_absent(&error) => Ok(()),
            Err(error) => Err(with_context(error, "captured directory removal not proven")),
            Ok(_) => Err(io::Error::other(
                "captured directory name still exists after removal",
            )),
        }
    }
}

pub(super) fn child_name_absent(error: &io::Error) -> bool {
    // A retained parent and one relative child need an actual missing name.
    // Rust also classifies invalid drives/network paths as NotFound; those
    // failures cannot prove that the captured entry has been removed.
    error.raw_os_error() == Some(ERROR_FILE_NOT_FOUND.cast_signed())
}

fn duplicate_directory_handle(handle: HANDLE) -> io::Result<File> {
    // SAFETY: the caller retains its TrustedPathGuard through this duplication.
    // The borrowed view does not take ownership; try_clone_to_owned duplicates
    // the same native file object and File owns that duplicate exactly once.
    let borrowed = unsafe { BorrowedHandle::borrow_raw(handle.cast()) };
    borrowed.try_clone_to_owned().map(File::from)
}

pub(super) fn query_directory_identity(file: &File) -> io::Result<DirectoryIdentity> {
    let mut info = FILE_ID_INFO::default();
    // SAFETY: `file` owns a live handle and `info` is a valid output buffer.
    let succeeded = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle().cast(),
            FileIdInfo,
            (&raw mut info).cast(),
            u32::try_from(size_of::<FILE_ID_INFO>()).expect("FILE_ID_INFO fits in u32"),
        )
    };
    if succeeded == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(DirectoryIdentity::from_windows_file_id(
        info.VolumeSerialNumber,
        info.FileId.Identifier,
    ))
}

fn into_std_file(handle: OwnedHandle) -> File {
    let raw = handle.0;
    std::mem::forget(handle);
    // SAFETY: ownership transfers from OwnedHandle exactly once.
    unsafe { File::from_raw_handle(raw.cast()) }
}

fn delete_empty_directory(file: &File) -> io::Result<()> {
    let disposition = FILE_DISPOSITION_INFORMATION { DeleteFile: true };
    let mut status = IO_STATUS_BLOCK::default();
    // SAFETY: the captured directory file holds DELETE access, and the
    // disposition and status buffers remain live for the native call.
    let result = unsafe {
        NtSetInformationFile(
            file.as_raw_handle().cast(),
            &raw mut status,
            (&raw const disposition).cast(),
            u32::try_from(size_of::<FILE_DISPOSITION_INFORMATION>())
                .expect("FILE_DISPOSITION_INFORMATION fits in u32"),
            FileDispositionInformation,
        )
    };
    if result < 0 {
        // SAFETY: conversion is defined for the NTSTATUS returned by the call.
        let code = unsafe { RtlNtStatusToDosError(result) };
        return Err(io::Error::from_raw_os_error(code.cast_signed()));
    }
    Ok(())
}
