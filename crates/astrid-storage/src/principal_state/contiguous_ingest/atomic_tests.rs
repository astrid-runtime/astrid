//! Exercise the public atomic batch with more files than available handles.
use super::*;
use crate::{ContentName, KvQuotaResolver, open_runtime_principal_store};
use astrid_core::dirs::AstridHome;
#[cfg(unix)]
use nix::sys::resource::{Resource, getrlimit, setrlimit};
use std::sync::Arc;

fn quota() -> Arc<dyn KvQuotaResolver<StateOwner>> {
    Arc::new(|_: &StateOwner| Ok(None))
}

#[tokio::test]
async fn late_source_failure_does_not_publish_any_catalog_change() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path().join("runtime"));
    let store = open_runtime_principal_store(&home, quota()).await.unwrap();
    let name = ContentName::new("keep").unwrap();
    store
        .content()
        .put(&StateOwner::System, &name, b"old")
        .unwrap();
    let good = directory.path().join("good");
    let bad = directory.path().join("bad");
    std::fs::write(&good, b"new").unwrap();
    std::fs::write(&bad, b"wrong length").unwrap();
    let absent = ContentName::new("absent").unwrap();
    let result = store.put_contiguous_files(
        StateOwner::System,
        [
            ContiguousFileIngest::new(name.clone(), &good, 3),
            ContiguousFileIngest::new(absent.clone(), &good, 3),
            ContiguousFileIngest::new(ContentName::new("bad").unwrap(), &bad, 1),
        ],
    );
    assert!(result.is_err());
    assert_eq!(
        store.content().read(&StateOwner::System, &name).unwrap(),
        Some(b"old".to_vec())
    );
    assert!(
        store
            .content()
            .describe(&StateOwner::System, &absent)
            .unwrap()
            .is_none()
    );
}

#[cfg(unix)]
#[test]
fn atomic_batch_succeeds_beyond_process_file_descriptor_limit() {
    if std::env::var_os("ASTRID_TEST_PACK_LOW_FD").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "principal_state::contiguous_ingest::atomic_tests::atomic_batch_succeeds_beyond_process_file_descriptor_limit", "--nocapture"])
            .env("ASTRID_TEST_PACK_LOW_FD", "1")
            .output().unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let directory = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(directory.path().join("runtime"));
        let store = open_runtime_principal_store(&home, quota()).await.unwrap();
        let mut files = Vec::new();
        for index in 0..512 {
            let path = directory.path().join(format!("input-{index}"));
            std::fs::write(&path, b"payload").unwrap();
            files.push(ContiguousFileIngest::new(
                ContentName::new(format!("file-{index}")).unwrap(),
                path,
                7,
            ));
        }
        // This child owns its process-wide limit; no parallel tests or user's
        // daemons are affected. rlim_max remains unchanged.
        let (soft, hard) = getrlimit(Resource::RLIMIT_NOFILE).unwrap();
        setrlimit(Resource::RLIMIT_NOFILE, soft.min(64), hard).unwrap();
        store
            .put_contiguous_files(StateOwner::System, files)
            .unwrap();
        for index in 0..512 {
            assert_eq!(
                store
                    .content()
                    .read(
                        &StateOwner::System,
                        &ContentName::new(format!("file-{index}")).unwrap()
                    )
                    .unwrap(),
                Some(b"payload".to_vec())
            );
        }
    });
}
