use super::*;
use crate::context::ProcessStorageMountBroker;
use crate::engine::wasm::{host_state::PrincipalMountLocation, test_fixtures::minimal_host_state};
use astrid_core::{PrincipalId, PrincipalUid};

#[derive(Default)]
struct RecordingBroker(std::sync::Mutex<Vec<PrincipalUid>>);

#[async_trait::async_trait]
impl ProcessStorageMountBroker for RecordingBroker {
    async fn mount(&self, _: &PrincipalId) -> Result<ProcessStorageMount, String> {
        panic!("guest projection expected a UID-bound mount")
    }

    async fn mount_for(
        &self,
        _: &PrincipalId,
        uid: PrincipalUid,
    ) -> Result<ProcessStorageMount, String> {
        self.0.lock().unwrap().push(uid);
        Err("test broker declines launch".into())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn process_projection_requires_an_admitted_uid_and_passes_it_to_the_broker() {
    let mut state = minimal_host_state(tokio::runtime::Handle::current());
    let root = tempfile::tempdir().unwrap();
    let mut mount = crate::engine::wasm::mount_dir_sync(root.path()).unwrap();
    mount.location = PrincipalMountLocation::AstridFilesystem;
    state.home = Some(mount);
    let broker = std::sync::Arc::new(RecordingBroker::default());
    state.process_storage_mount_broker = Some(broker.clone());
    assert!(prepare_process_storage_mount(&state, "spawn", "test").is_err());
    assert!(broker.0.lock().unwrap().is_empty());

    let owner = PrincipalUid::from_bytes([7; 32]);
    state.invocation_storage_uid = Some(owner);
    assert!(prepare_process_storage_mount(&state, "spawn", "test").is_err());
    assert_eq!(broker.0.lock().unwrap().as_slice(), &[owner]);
}
