//! Close staging host capabilities before native tree retirement.
//!
//! Idle facade clones do not pin open host state. Live writer and publish
//! leases do. An empty finalization `OnceLock` is a successful no-op close so
//! handoff owners can pack without reviving staging.

use crate::StorageResult;
use crate::principal_state::RuntimePrincipalStore;
use crate::principal_state::staging::StagingCloseToken;

/// Reserve exclusive close of installed staging, if any.
///
/// Returns `Ok(None)` when the finalization owner has an empty staging slot.
/// Does not hold the phase mutex across engine or filesystem IO.
pub(in crate::principal_state) fn reserve_for_retirement(
    store: &RuntimePrincipalStore,
) -> StorageResult<Option<StagingCloseToken>> {
    let Some(area) = store.staging.get() else {
        return Ok(None);
    };
    Ok(Some(area.reserve_for_close()?))
}

/// Test helper: reserve and commit staging close without packing.
///
/// Production retirement uses [`reserve_for_retirement`] inside public pack so
/// failure before RETIRING can restore Open. Empty staging is a successful no-op.
#[cfg(test)]
pub(in crate::principal_state) fn close_for_retirement(
    store: &RuntimePrincipalStore,
) -> StorageResult<()> {
    if let Some(token) = reserve_for_retirement(store)? {
        token.commit();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::ChunkingProfile;
    use crate::principal_state::{StateOwner, open_runtime_principal_store};
    use crate::{ContentName, KvQuotaResolver, StorageError};
    use astrid_core::dirs::AstridHome;
    use std::io::Write;
    use std::sync::{Arc, Barrier};
    use std::time::{Duration, Instant};

    async fn fixture() -> (tempfile::TempDir, AstridHome, RuntimePrincipalStore) {
        let parent = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(parent.path().join("runtime"));
        let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|_: &StateOwner| Ok(None));
        let store = open_runtime_principal_store(&home, quota).await.unwrap();
        (parent, home, store)
    }

    fn seed_host(home: &AstridHome, name: &ContentName, bytes: &[u8]) {
        let path = home.root().join(name.as_str());
        astrid_core::platform_fs::ensure_private_directory_tree(path.parent().unwrap()).unwrap();
        astrid_core::platform_fs::atomic_write_private_file(&path, bytes).unwrap();
    }

    fn busy(error: &StorageError) -> bool {
        error
            .to_string()
            .contains("runtime staging is still in use; stop all staging users before retirement")
    }

    fn closed(error: &StorageError) -> bool {
        error
            .to_string()
            .contains("runtime staging is closed after projection retirement")
    }

    #[tokio::test]
    async fn closes_host_handles_but_preserves_volume_and_staging_slot() {
        let (_parent, home, store) = fixture().await;
        let name = ContentName::new("bin/retained.wasm").unwrap();
        store
            .content()
            .put(&StateOwner::System, &name, b"retained")
            .unwrap();
        store.publish_runtime_projection(&home).unwrap();
        close_for_retirement(&store).unwrap();
        assert!(
            store.staging.get().is_some(),
            "OnceLock must stay occupied after close"
        );
        {
            let area = store.staging();
            let err = area
                .begin(
                    StateOwner::System,
                    ContentName::new("var/tmp/after-close.bin").unwrap(),
                    ChunkingProfile::ASTRID_V1,
                )
                .expect_err("closed staging must reject begin");
            assert!(closed(&err), "{err}");
            assert!(
                closed(&area.ready().unwrap_err()),
                "ready must error closed"
            );
        }

        store.pack_and_retire_runtime_projection(&home).unwrap();
        assert_eq!(
            store.content().read(&StateOwner::System, &name).unwrap(),
            Some(b"retained".to_vec())
        );
        assert_eq!(std::fs::read_dir(home.root()).unwrap().count(), 1);
        store.pack_and_retire_runtime_projection(&home).unwrap();
    }

    #[tokio::test]
    async fn idle_store_and_staging_facade_clones_do_not_block_close() {
        let (_parent, _home, store) = fixture().await;
        let alias = store.clone();
        let area = (*store.staging()).clone();
        close_for_retirement(&store).unwrap();
        assert!(closed(
            &alias
                .staging()
                .begin(
                    StateOwner::System,
                    ContentName::new("var/tmp/after-idle-close.bin").unwrap(),
                    ChunkingProfile::ASTRID_V1,
                )
                .unwrap_err()
        ));
        assert!(closed(&area.ready().unwrap_err()));
        drop(alias);
        drop(area);
    }

    #[tokio::test]
    async fn empty_finalization_staging_slot_is_noop_close() {
        let (_parent, home, store) = fixture().await;
        let finalization = store.handoff_for_finalization(&home).unwrap();
        assert!(finalization.store.staging.get().is_none());
        close_for_retirement(&finalization.store).unwrap();
        // Avoid Drop closing over a moved field: finish path packs separately.
        drop(finalization);
    }

    #[tokio::test]
    async fn public_pack_refuses_active_writer_then_retries_after_drop() {
        let (_parent, home, store) = fixture().await;
        let name = ContentName::new("etc/writer-held.toml").unwrap();
        seed_host(&home, &name, b"writer-held");
        store.publish_runtime_projection(&home).unwrap();

        let writer = store
            .staging()
            .begin(
                StateOwner::System,
                ContentName::new("var/tmp/held.bin").unwrap(),
                ChunkingProfile::ASTRID_V1,
            )
            .unwrap();
        let error = store
            .pack_and_retire_runtime_projection(&home)
            .expect_err("active writer must refuse close");
        assert!(busy(&error), "{error}");
        assert!(home.root().join("etc/writer-held.toml").is_file());
        // Busy reserve must leave staging open.
        store
            .staging()
            .begin(
                StateOwner::System,
                ContentName::new("var/tmp/busy-still-open.bin").unwrap(),
                ChunkingProfile::ASTRID_V1,
            )
            .unwrap();
        drop(writer);

        store.pack_and_retire_runtime_projection(&home).unwrap();
        {
            let area = store.staging();
            assert!(closed(
                &area
                    .begin(
                        StateOwner::System,
                        ContentName::new("var/tmp/after-pack.bin").unwrap(),
                        ChunkingProfile::ASTRID_V1,
                    )
                    .unwrap_err()
            ));
            assert!(closed(&area.ready().unwrap_err()));
        }
        assert_eq!(
            store.content().read(&StateOwner::System, &name).unwrap(),
            Some(b"writer-held".to_vec())
        );
        assert_eq!(std::fs::read_dir(home.root()).unwrap().count(), 1);
        store.pack_and_retire_runtime_projection(&home).unwrap();
    }

    #[tokio::test]
    async fn canceled_publish_awaiter_keeps_busy_until_worker_finishes() {
        let (_parent, home, store) = fixture().await;
        let name = ContentName::new("var/tmp/publish-held.bin").unwrap();
        let mut writer = store
            .staging()
            .begin(StateOwner::System, name.clone(), ChunkingProfile::ASTRID_V1)
            .unwrap();
        writer.write_all(b"publish-lease").unwrap();
        let ready = writer.seal().unwrap();
        let reached = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        store
            .staging()
            .gate_next_publish(Arc::clone(&reached), Arc::clone(&release));
        let area = store.staging();
        let content = store.content();
        let publish = tokio::spawn(async move { area.publish(ready, content).await });
        // Await a blocking barrier wait so the current-thread runtime can poll
        // publish → spawn_blocking before we cancel the awaiter.
        tokio::task::spawn_blocking({
            let reached = Arc::clone(&reached);
            move || {
                reached.wait();
            }
        })
        .await
        .unwrap();
        publish.abort();
        let join = publish.await;
        assert!(join.unwrap_err().is_cancelled());
        assert!(
            busy(&close_for_retirement(&store).unwrap_err()),
            "canceled awaiter must not drop the in-flight publish lease"
        );
        tokio::task::spawn_blocking({
            let release = Arc::clone(&release);
            move || {
                release.wait();
            }
        })
        .await
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match close_for_retirement(&store) {
                Ok(()) => break,
                Err(error) if busy(&error) && Instant::now() < deadline => {
                    tokio::task::yield_now().await;
                },
                Err(error) => panic!("expected close after publish worker drain: {error}"),
            }
        }
        assert_eq!(
            store.content().read(&StateOwner::System, &name).unwrap(),
            Some(b"publish-lease".to_vec()),
            "drained publish worker must retain acknowledged content"
        );
        let _ = home;
    }

    #[tokio::test]
    async fn cloned_store_after_close_sees_closed_staging_without_panic() {
        let (_parent, home, store) = fixture().await;
        store.publish_runtime_projection(&home).unwrap();
        close_for_retirement(&store).unwrap();
        let clone = store.clone();
        let err = clone
            .staging()
            .ready()
            .expect_err("cloned closed store must error, not panic");
        assert!(closed(&err), "{err}");
        drop(clone);
        store.pack_and_retire_runtime_projection(&home).unwrap();
    }
}
