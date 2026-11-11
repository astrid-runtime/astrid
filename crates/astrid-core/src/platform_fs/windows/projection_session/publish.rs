//! Projection-only scoped stage and guarded publish.
//!
//! Crash authority for restoration remains durable RETIRING + `RollbackSpool`.
//! This path must not create private-file journal/lock sidecars in the home.
//! Failed staging cleanup retains at most one held [`File`] for retry.

#[cfg(test)]
use std::sync::Mutex;
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};

use super::super::acl::validate_private_acl_handle;
use super::super::io::{
    FileContract, create_guarded_private_file, rename_guarded_handle, validate_file_contract,
};
use super::super::path::{BoundaryContract, TrustedPathGuard, mark_handle_for_deletion};
use super::super::prelude::*;
use crate::platform_fs::StagingScope;

const STAGE_NAME_ATTEMPTS: u32 = 16;

/// One abandoned staging object that still needs handle-relative deletion.
pub(super) struct PendingTemporary {
    file: File,
}

impl PendingTemporary {
    #[cfg(test)]
    pub(super) fn file(&self) -> &File {
        &self.file
    }

    /// Delete this exact held object. Never re-opens a path by name.
    pub(super) fn cleanup(&self) -> io::Result<()> {
        #[cfg(test)]
        test_maybe_fail_temporary_cleanup()?;
        mark_handle_for_deletion(self.file.as_raw_handle().cast()).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("projection temporary cleanup failed: {error}"),
            )
        })?;
        Ok(())
    }
}

impl Drop for PendingTemporary {
    fn drop(&mut self) {
        // Abandonment only. Normal failure paths call [`Self::cleanup`] and
        // surface errors before dropping the slot.
        let _ = mark_handle_for_deletion(self.file.as_raw_handle().cast());
    }
}

/// Stream exactly `exact_len` bytes into a scoped/unscoped temp, then rename.
///
/// On pre-rename failure, attempts handle deletion of the staged object. If that
/// deletion fails, returns the staged [`PendingTemporary`] for the caller to
/// retain (at most one). After a successful rename, never deletes the published
/// destination; post-rename validation errors leave rollback to the batch.
pub(super) fn publish_from_reader(
    parent: &TrustedPathGuard,
    destination: &Path,
    reader: &mut dyn Read,
    exact_len: u64,
    staging_scope: Option<StagingScope>,
) -> Result<(), PublishFailure> {
    parent
        .verify_contract(BoundaryContract::ExactPrivateDirectory)
        .map_err(PublishFailure::without_pending)?;
    let mut exhausted = None;
    for _ in 0..STAGE_NAME_ATTEMPTS {
        let temporary_name = temporary_basename(staging_scope);
        let temporary = parent.authority_boundary().join(&temporary_name);
        let file = match create_guarded_private_file(parent, &temporary) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                exhausted = Some(error);
                continue;
            },
            Err(error) => return Err(PublishFailure::without_pending(error)),
        };
        return finish_publish(parent, destination, reader, exact_len, &temporary, file);
    }
    Err(PublishFailure::without_pending(exhausted.unwrap_or_else(
        || {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "could not allocate a unique projection staging name",
            )
        },
    )))
}

pub(super) struct PublishFailure {
    pub error: io::Error,
    pub pending: Option<PendingTemporary>,
}

impl PublishFailure {
    fn without_pending(error: io::Error) -> Self {
        Self {
            error,
            pending: None,
        }
    }
}

fn finish_publish(
    parent: &TrustedPathGuard,
    destination: &Path,
    reader: &mut dyn Read,
    exact_len: u64,
    temporary: &Path,
    mut file: File,
) -> Result<(), PublishFailure> {
    let staged = (|| -> io::Result<()> {
        copy_exact(reader, &mut file, exact_len)?;
        file.flush()?;
        file.sync_all()?;
        validate_private_acl_handle(
            file.as_raw_handle().cast(),
            false,
            &temporary.display().to_string(),
        )?;
        parent.verify_contract(BoundaryContract::ExactPrivateDirectory)?;
        Ok(())
    })();
    if let Err(error) = staged {
        return Err(abandon_staged(file, error));
    }

    if let Err(error) = rename_guarded_handle(&file, parent, destination, true) {
        return Err(abandon_staged(file, error));
    }

    // Rename committed: this handle now names the destination. Never delete it
    // here; batch rollback restores prior generations on validation failure.
    let published = (|| {
        validate_file_contract(
            file.as_raw_handle().cast(),
            destination,
            FileContract::ExactPrivate,
        )?;
        // Parent directory-structure fence (Unix parent fsync parity).
        super::flush_captured_namespace(parent)?;
        parent.verify_contract(BoundaryContract::ExactPrivateDirectory)?;
        Ok(())
    })();
    drop(file);
    published.map_err(PublishFailure::without_pending)
}

fn abandon_staged(file: File, error: io::Error) -> PublishFailure {
    let pending = PendingTemporary { file };
    match pending.cleanup() {
        Ok(()) => {
            // Successful mark: drop closes and removes the staged object.
            drop(pending);
            PublishFailure::without_pending(error)
        },
        Err(cleanup) => PublishFailure {
            error: io::Error::new(
                error.kind(),
                format!("{error}; temporary cleanup failed: {cleanup}"),
            ),
            pending: Some(pending),
        },
    }
}

fn temporary_basename(staging_scope: Option<StagingScope>) -> String {
    match staging_scope {
        Some(scope) => scope.temporary_basename(),
        None => format!(".astrid-private-{}", uuid::Uuid::new_v4().simple()),
    }
}

fn copy_exact(source: &mut dyn Read, destination: &mut File, exact_len: u64) -> io::Result<()> {
    let written = io::copy(&mut Read::take(&mut *source, exact_len), destination)?;
    if written != exact_len {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("projection staging payload ended after {written} bytes; expected {exact_len}"),
        ));
    }
    let mut extra = [0_u8; 1];
    loop {
        match source.read(&mut extra) {
            Ok(0) => return Ok(()),
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "projection staging payload exceeded exact length",
                ));
            },
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {},
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
static TEST_TEMPORARY_CLEANUP_FAILURES_REMAINING: AtomicUsize = AtomicUsize::new(0);

#[cfg(test)]
/// Fail the next `count` temporary cleanup attempts (handle mark only).
pub(in crate::platform_fs::windows) fn set_temporary_cleanup_failures(count: usize) {
    TEST_TEMPORARY_CLEANUP_FAILURES_REMAINING.store(count, Ordering::SeqCst);
}

#[cfg(test)]
fn test_maybe_fail_temporary_cleanup() -> io::Result<()> {
    let _guard = CLEANUP_FAULT_SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let remaining = TEST_TEMPORARY_CLEANUP_FAILURES_REMAINING.load(Ordering::SeqCst);
    if remaining == 0 {
        return Ok(());
    }
    TEST_TEMPORARY_CLEANUP_FAILURES_REMAINING.fetch_sub(1, Ordering::SeqCst);
    Err(io::Error::other(
        "injected projection temporary cleanup failure",
    ))
}

#[cfg(test)]
static CLEANUP_FAULT_SERIAL: Mutex<()> = Mutex::new(());
