use super::*;
use crate::context::ProcessStorageMountBroker;
use crate::engine::wasm::{host_state::PrincipalMountLocation, test_fixtures::minimal_host_state};
use astrid_core::{PrincipalId, PrincipalUid};

#[derive(Default)]
struct RecordingBroker(std::sync::Mutex<Vec<(PrincipalId, PrincipalUid)>>);

#[async_trait::async_trait]
impl ProcessStorageMountBroker for RecordingBroker {
    async fn mount(&self, _: &PrincipalId) -> Result<ProcessStorageMount, String> {
        panic!("guest projection expected a UID-bound mount")
    }

    async fn mount_for(
        &self,
        owner: &PrincipalId,
        uid: PrincipalUid,
    ) -> Result<ProcessStorageMount, String> {
        self.0.lock().unwrap().push((owner.clone(), uid));
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
    assert_eq!(
        broker.0.lock().unwrap().as_slice(),
        &[(state.effective_principal(), owner)]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn persistent_preparation_requires_a_subgrant_and_projects_the_authenticated_caller() {
    use astrid_events::ipc::{IpcMessage, IpcPayload, Topic};
    let mut state = minimal_host_state(tokio::runtime::Handle::current());
    state.security = Some(Arc::new(crate::security::AllowAllGate));
    let root = tempfile::tempdir().unwrap();
    let mut mount = crate::engine::wasm::mount_dir_sync(root.path()).unwrap();
    mount.location = PrincipalMountLocation::AstridFilesystem;
    state.home = Some(mount);
    let uid = PrincipalUid::from_bytes([8; 32]);
    state.invocation_storage_uid = Some(uid);
    let broker = Arc::new(RecordingBroker::default());
    state.process_storage_mount_broker = Some(broker.clone());

    assert!(matches!(
        persistent::admit_and_prepare(&state, "tool", None),
        Err(ErrorCode::CapabilityDenied)
    ));
    state.capability_names.push("allow_persistent".to_owned());
    assert!(matches!(
        persistent::admit_and_prepare(&state, "tool", None),
        Err(ErrorCode::PersistUnsupported)
    ));
    let caller = PrincipalId::new("test-caller").unwrap();
    assert_ne!(caller, state.principal);
    state.caller_context = Some(
        IpcMessage::new(
            Topic::from_raw("test.v1.spawn"),
            IpcPayload::RawJson(serde_json::Value::Null),
            uuid::Uuid::new_v4(),
        )
        .with_principal(caller.as_str().to_owned()),
    );
    assert!(matches!(
        persistent::admit_and_prepare(&state, "tool", Some(0)),
        Err(ErrorCode::InvalidInput)
    ));
    assert!(broker.0.lock().unwrap().is_empty());
    assert!(matches!(
        persistent::admit_and_prepare(&state, "tool", None),
        Err(ErrorCode::CapabilityDenied)
    ));
    assert_eq!(broker.0.lock().unwrap().as_slice(), &[(caller, uid)]);
}
