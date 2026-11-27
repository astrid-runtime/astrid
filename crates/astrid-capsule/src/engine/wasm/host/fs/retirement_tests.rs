//! Principal retirement between write-ahead admission and a real native file write.
use super::{ErrorCode, HostAuditEvent, HostAuditOutcome, fs::Host};
use crate::audit_sink::{HostAuditRefusal, HostAuditSink};
use crate::engine::wasm::{
    PrincipalInvocationTracker,
    host_state::{PrincipalMount, PrincipalMountLocation},
    test_fixtures::minimal_host_state,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

struct RetireBeforeWrite {
    tracker: Arc<PrincipalInvocationTracker>,
    path: std::path::PathBuf,
    completed: AtomicBool,
}

impl HostAuditSink for RetireBeforeWrite {
    fn admit(
        &self,
        principal: &astrid_core::PrincipalId,
        event: HostAuditEvent<'_>,
    ) -> Result<(), HostAuditRefusal> {
        assert!(
            matches!(event, HostAuditEvent::FileWrite {path,..} if std::path::Path::new(path) == self.path)
        );
        assert_eq!(std::fs::read(&self.path).unwrap(), b"before");
        self.tracker.retire(principal);
        assert_eq!(self.tracker.active(principal), 1);
        assert!(self.tracker.begin(principal).is_none());
        Ok(())
    }
    fn record(
        &self,
        principal: &astrid_core::PrincipalId,
        event: HostAuditEvent<'_>,
        outcome: HostAuditOutcome<'_>,
    ) {
        assert!(
            matches!(event, HostAuditEvent::FileWrite {path,..} if std::path::Path::new(path) == self.path)
        );
        assert!(matches!(outcome, HostAuditOutcome::Allowed));
        assert_eq!(std::fs::read(&self.path).unwrap(), b"admitted");
        assert_eq!(self.tracker.active(principal), 1);
        self.completed.store(true, Ordering::Release);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admitted_write_retains_its_principal_through_native_completion() {
    let root = tempfile::tempdir().unwrap();
    let root_path = root.path().canonicalize().unwrap();
    let path = root_path.join("item");
    std::fs::write(&path, b"before").unwrap();
    let handle = astrid_capabilities::DirHandle::new();
    let mut state = minimal_host_state(tokio::runtime::Handle::current());
    state.workspace_root = root_path.clone();
    state.workspace = Some(PrincipalMount {
        location: PrincipalMountLocation::Native(root_path.clone()),
        vfs: Arc::new(
            astrid_vfs::HostVfs::with_registered_dir(handle.clone(), &root_path).unwrap(),
        ),
        handle,
    });
    let tracker = Arc::new(PrincipalInvocationTracker::default());
    let observer = Arc::new(RetireBeforeWrite {
        tracker: Arc::clone(&tracker),
        path,
        completed: AtomicBool::new(false),
    });
    state.principal_invocations = Some(Arc::clone(&tracker));
    state.audit_sink = Some(observer.clone());
    state
        .write_file("item".to_owned(), b"admitted".to_vec())
        .unwrap();
    assert!(observer.completed.load(Ordering::Acquire));
    assert_eq!(tracker.active(&state.effective_principal()), 0);
    assert!(matches!(
        state.write_file("item".to_owned(), b"late".to_vec()),
        Err(ErrorCode::CapabilityDenied)
    ));
    assert_eq!(std::fs::read(&observer.path).unwrap(), b"admitted");
}
