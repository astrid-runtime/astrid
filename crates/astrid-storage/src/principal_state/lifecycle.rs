//! One finalization path, shared by graceful daemon exit and CLI recovery.

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ContentName, open_runtime_principal_store};

    #[tokio::test]
    async fn finalizer_fences_replacement_and_is_idempotent() {
        let parent = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(parent.path().join("runtime"));
        let lifecycle = RuntimeLifecycleGuard::acquire(&home).unwrap();
        assert!(
            !home.root().exists(),
            "fencing must not preempt fresh-home admission"
        );
        let original_path = home.lifecycle_lock_path().unwrap();
        let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|_: &StateOwner| Ok(None));
        let store = open_runtime_principal_store(&home, quota.clone())
            .await
            .unwrap();
        let name = ContentName::new("bin/test.wasm").unwrap();
        store
            .content()
            .put(&StateOwner::System, &name, b"capsule")
            .unwrap();
        store.publish_runtime_projection(&home).unwrap();
        drop(store);
        assert_eq!(original_path, home.lifecycle_lock_path().unwrap());
        assert!(RuntimeLifecycleGuard::acquire(&home).is_err());
        lifecycle.finish().await.unwrap();
        let entries = std::fs::read_dir(home.root())
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].file_name(), "astrid.volume");
        RuntimeLifecycleGuard::acquire(&home)
            .unwrap()
            .finish()
            .await
            .unwrap();
        let store = open_runtime_principal_store(&home, quota).await.unwrap();
        assert_eq!(
            store.content().read(&StateOwner::System, &name).unwrap(),
            Some(b"capsule".to_vec())
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn failed_finalization_preserves_recovery_evidence() {
        let parent = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(parent.path().join("runtime"));
        let lifecycle = RuntimeLifecycleGuard::acquire(&home).unwrap();
        let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|_: &StateOwner| Ok(None));
        let store = open_runtime_principal_store(&home, quota).await.unwrap();
        std::fs::write(home.root().join("config.toml"), b"keep").unwrap();
        drop(store);
        std::os::unix::fs::symlink(parent.path(), home.root().join("redirect")).unwrap();
        assert!(lifecycle.finish().await.is_err());
        assert_eq!(
            std::fs::read(home.root().join("config.toml")).unwrap(),
            b"keep"
        );
        assert!(home.root().join("redirect").symlink_metadata().is_ok());
        assert!(RuntimeLifecycleGuard::acquire(&home).is_ok());
    }
}
