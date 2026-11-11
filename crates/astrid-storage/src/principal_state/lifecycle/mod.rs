//! One finalization path, shared by graceful daemon exit and CLI recovery.

mod handoff;

use std::fs::File;
use std::io;
use std::sync::Arc;

use astrid_core::dirs::AstridHome;

use super::{StateOwner, native_io, open_runtime_principal_store_for_pack};
use crate::{KvQuotaResolver, StorageError, StorageResult};

/// Fence a runtime from before boot until its host projection is retired.
///
/// The fence is outside the runtime root: deleting `run/` cannot let a new
/// daemon bypass it by opening a replacement lock inode. Drop never deletes
/// the lock file. Callers must drain and drop their task runtime before finish.
pub struct RuntimeLifecycleGuard {
    home: AstridHome,
    _lock: File,
}

impl RuntimeLifecycleGuard {
    /// Acquire exclusive lifecycle ownership without creating the runtime root.
    ///
    /// # Errors
    /// Refuses a competing daemon/finalizer or an unsafe control directory.
    pub fn acquire(home: &AstridHome) -> io::Result<Self> {
        home.validate_run_dir()?;
        let path = home.lifecycle_lock_path()?;
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::other("lifecycle lock has no parent"))?;
        native_io::ensure_private_directory(parent).map_err(io::Error::other)?;
        let directory = cap_std::fs::Dir::open_ambient_dir(parent, cap_std::ambient_authority())?;
        let name = path
            .file_name()
            .ok_or_else(|| io::Error::other("lifecycle lock has no name"))?;
        if directory
            .symlink_metadata(name)
            .is_ok_and(|metadata| !metadata.is_file() || metadata.is_symlink())
        {
            return Err(io::Error::other("lifecycle lock is not a regular file"));
        }
        let mut options = cap_std::fs::OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt as _;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let lock = directory.open_with(name, &options)?.into_std();
        lock.try_lock().map_err(|error| {
            io::Error::other(format!("runtime is running or finalizing: {error}"))
        })?;
        Ok(Self {
            home: home.clone(),
            _lock: lock,
        })
    }

    /// Pack final host writes and leave exactly the durable volume.
    ///
    /// The kernel and every task using its projection must already be stopped.
    /// A failure preserves recoverable host files and never reports completion.
    /// Repeating this after a successful graceful exit is harmless.
    ///
    /// # Errors
    /// Returns a storage error if opening, publishing, or retirement fails.
    pub async fn finish(self) -> StorageResult<()> {
        if !self
            .home
            .storage_volume_path()
            .try_exists()
            .map_err(|error| StorageError::Internal(error.to_string()))?
        {
            return Ok(());
        }
        let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|_: &StateOwner| Ok(None));
        let store = open_runtime_principal_store_for_pack(&self.home, quota).await?;
        store.pack_and_retire_runtime_projection(&self.home)?;
        Ok(())
    }
}

/// Exclusive finalization custody after former runtime handles are closed.
///
/// This token deliberately cannot be cloned. Dropping it closes the engine,
/// including when runtime teardown or final publication fails.
#[must_use = "finish the durable home after stopping the task runtime"]
pub struct RuntimeFinalization {
    store: super::RuntimePrincipalStore,
    shutdown_error: Option<StorageError>,
}

impl super::RuntimePrincipalStore {
    pub(super) fn require_volume_binding(&self, home: &AstridHome) -> StorageResult<()> {
        let volume = self.volume_binding.upgrade().ok_or_else(|| {
            StorageError::Connection("retained runtime volume is already closed".into())
        })?;
        volume
            .require_current_binding(&home.storage_volume_path())
            .map_err(|error| {
                StorageError::Connection(format!("validate retained runtime volume: {error}"))
            })
    }

    #[cfg(unix)]
    pub(super) fn retirement_volume_file(&self, home: &AstridHome) -> StorageResult<File> {
        let volume = self.volume_binding.upgrade().ok_or_else(|| {
            StorageError::Connection("retained runtime volume is already closed".into())
        })?;
        volume
            .retirement_file(&home.storage_volume_path())
            .map_err(|error| {
                StorageError::Connection(format!("capture retained runtime volume: {error}"))
            })
    }
}

impl RuntimeFinalization {
    /// Retain an ancillary shutdown failure until packing and close complete.
    ///
    /// Custody must survive an old projection's close error. Finalization still
    /// packs late host writes, then reports the earlier failure to its caller.
    pub fn record_shutdown_error(&mut self, error: StorageError) {
        self.shutdown_error = Some(match self.shutdown_error.take() {
            Some(previous) => StorageError::Internal(format!("{previous}; additionally: {error}")),
            None => error,
        });
    }
}

impl Drop for RuntimeFinalization {
    fn drop(&mut self) {
        // Close invalidates every surviving projection, even on error. Never
        // trace here: finalization may already have retired the log directory.
        let _ = self.store.engine.close();
    }
}

/// Open-store custody retained across task-runtime teardown before handoff.
///
/// Clone the live [`super::RuntimePrincipalStore`] without closing it. Dropping
/// this token without [`Self::handoff_for_finalization`] closes the original
/// engine. A successful handoff transfers into [`RuntimeFinalization`] and must
/// not close the fresh owner.
#[must_use = "hand off after the task runtime stops, or drop to close the engine"]
pub struct PendingRuntimeFinalization {
    store: Option<super::RuntimePrincipalStore>,
    home: AstridHome,
    shutdown_error: Option<StorageError>,
}

impl PendingRuntimeFinalization {
    /// Retain an ancillary shutdown failure until handoff and packing complete.
    pub fn record_shutdown_error(&mut self, error: StorageError) {
        self.shutdown_error = Some(match self.shutdown_error.take() {
            Some(previous) => StorageError::Internal(format!("{previous}; additionally: {error}")),
            None => error,
        });
    }

    /// Transfer authority after producers have joined, typically after runtime drop.
    ///
    /// The live store stays in this token until transfer succeeds. A failed
    /// handoff therefore still drops custody and closes the original engine.
    /// Ancillary shutdown errors are preserved on both success and failure.
    ///
    /// # Errors
    /// Fails on a wrong home, active commits, or a durable flush failure.
    pub fn handoff_for_finalization(mut self) -> StorageResult<RuntimeFinalization> {
        let Some(store) = self.store.as_ref() else {
            return Err(StorageError::Connection(
                "pending runtime custody is already released".into(),
            ));
        };
        match store.handoff_for_finalization(&self.home) {
            Ok(mut finalization) => {
                // Successful transfer already closed the old engine. Drop the
                // retained clone without running abandonment close again.
                let _ = self.store.take();
                if let Some(error) = self.shutdown_error.take() {
                    finalization.record_shutdown_error(error);
                }
                Ok(finalization)
            },
            Err(error) => {
                // Keep store installed so Drop closes the original engine.
                Err(match self.shutdown_error.take() {
                    Some(earlier) => StorageError::Connection(format!(
                        "{error}; earlier shutdown failed: {earlier}"
                    )),
                    None => error,
                })
            },
        }
    }
}

impl Drop for PendingRuntimeFinalization {
    fn drop(&mut self) {
        // Abandonment must close the still-authoritative engine. Successful
        // handoff takes the store out first so the fresh owner stays open.
        if let Some(store) = self.store.take() {
            let _ = store.engine.close();
        }
    }
}

impl RuntimeLifecycleGuard {
    /// Finalize the retained store after its task runtime has stopped.
    ///
    /// # Errors
    /// Rejects a different home, replaced volume, or unsafe host projection.
    /// Failures before retirement preserve host files. Later errors retain
    /// the durable volume and any surviving projection for recovery.
    pub fn finish_retained(self, mut finalization: RuntimeFinalization) -> StorageResult<()> {
        let packed = finalization
            .store
            .require_volume_binding(&self.home)
            .and_then(|()| {
                finalization
                    .store
                    .pack_and_retire_runtime_projection(&self.home)
            });
        let closed = finalization.store.engine.close().map_err(|error| {
            StorageError::Connection(format!("close finalized runtime volume: {error}"))
        });
        let shutdown_error = finalization.shutdown_error.take();
        drop(finalization);
        let finalized = match (packed, closed) {
            (Err(pack), Err(close)) => Err(StorageError::Connection(format!(
                "{pack}; additionally failed to close retained storage: {close}"
            ))),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Ok(()), Ok(())) => Ok(()),
        };
        match (finalized, shutdown_error) {
            (Err(error), Some(earlier)) => Err(StorageError::Connection(format!(
                "{error}; earlier shutdown failed: {earlier}"
            ))),
            (Ok(()), Some(error)) => Err(StorageError::Internal(format!(
                "durable home packed and closed; earlier shutdown failed: {error}"
            ))),
            (result, None) => result,
        }
    }
}

#[cfg(test)]
mod tests;
