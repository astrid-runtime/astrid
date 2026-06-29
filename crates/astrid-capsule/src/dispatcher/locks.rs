use std::collections::HashMap;
use std::sync::Arc;

use astrid_events::PrincipalKey;

use crate::capsule::CapsuleId;

/// Shared map of per-(capsule, principal) chain mutexes. One
/// `Arc<tokio::sync::Mutex<()>>` per `(CapsuleId, PrincipalKey)` so
/// chain dispatches for the same key serialize FIFO while distinct
/// keys run concurrently.
pub(super) type ChainLocks =
    Arc<parking_lot::RwLock<HashMap<(CapsuleId, PrincipalKey), Arc<tokio::sync::Mutex<()>>>>>;

/// RAII chain-lock lease that prunes its `ChainLocks` map entry on drop
/// when it was the last referrer.
pub(super) struct ChainLockGuard {
    guard: Option<tokio::sync::OwnedMutexGuard<()>>,
    mutex: Arc<tokio::sync::Mutex<()>>,
    chain_locks: ChainLocks,
    key: (CapsuleId, PrincipalKey),
}

impl Drop for ChainLockGuard {
    fn drop(&mut self) {
        self.guard.take();
        let mut write = self.chain_locks.write();
        if let Some(entry) = write.get(&self.key)
            && Arc::ptr_eq(entry, &self.mutex)
            && Arc::strong_count(entry) == 2
        {
            write.remove(&self.key);
        }
    }
}

/// Acquire the per-(capsule, principal) chain lock, returning a guard that
/// prunes the map entry on drop. Read-fast / write-on-miss: the common case
/// is a hit on an existing lock.
pub(super) async fn acquire_chain_lock(
    chain_locks: &ChainLocks,
    key: (CapsuleId, PrincipalKey),
) -> ChainLockGuard {
    let mutex = {
        let read = chain_locks.read();
        if let Some(m) = read.get(&key) {
            Arc::clone(m)
        } else {
            drop(read);
            let mut write = chain_locks.write();
            Arc::clone(
                write
                    .entry(key.clone())
                    .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
            )
        }
    };
    let guard = Arc::clone(&mutex).lock_owned().await;
    ChainLockGuard {
        guard: Some(guard),
        mutex,
        chain_locks: Arc::clone(chain_locks),
        key,
    }
}
