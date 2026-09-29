//! An install/upgrade hook's host calls are attributed to the hook's code:
//! the lifecycle host state binds the audit sink to the capsule id and the
//! BLAKE3 of the hook component bytes.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use astrid_core::PrincipalId;
use astrid_crypto::ContentHash;

use super::{LifecycleConfig, LifecyclePrincipalContext, build_lifecycle_host_state, limits};
use crate::audit_sink::{HostAuditActor, HostAuditEvent, HostAuditOutcome, HostAuditSink};
use crate::engine::wasm::host_state::LifecyclePhase;

/// Records the actor each record was attributed to.
#[derive(Default)]
struct ActorLog(Mutex<Vec<(Option<HostAuditActor>, String)>>);

struct Bound {
    log: Arc<ActorLog>,
    actor: Option<HostAuditActor>,
}

impl HostAuditSink for Bound {
    fn record(
        &self,
        _principal: &PrincipalId,
        event: HostAuditEvent<'_>,
        _outcome: HostAuditOutcome<'_>,
    ) {
        self.log
            .0
            .lock()
            .unwrap()
            .push((self.actor.clone(), format!("{event:?}")));
    }

    fn attributed(&self, actor: HostAuditActor) -> Option<Arc<dyn HostAuditSink>> {
        Some(Arc::new(Bound {
            log: Arc::clone(&self.log),
            actor: Some(actor),
        }))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lifecycle_hook_host_calls_carry_the_hook_identity() {
    let workspace = tempfile::tempdir().unwrap();
    let log = Arc::new(ActorLog::default());
    let wasm_bytes = b"hook component bytes".to_vec();
    let backend = Arc::new(astrid_storage::MemoryKvStore::new());
    let kv = astrid_storage::ScopedKvStore::new(backend.clone(), "default:capsule:hooked").unwrap();
    let secret_scope = astrid_storage::ScopedKvStore::new(backend, "secrets").unwrap();
    let cfg = LifecycleConfig {
        wasm_bytes: wasm_bytes.clone(),
        capsule_id: crate::capsule::CapsuleId::new("hooked").unwrap(),
        workspace_root: workspace.path().to_path_buf(),
        home_root: None,
        kv,
        event_bus: astrid_events::EventBus::with_capacity(16),
        config: HashMap::new(),
        secret_store: astrid_storage::build_secret_store(
            "hooked",
            secret_scope,
            tokio::runtime::Handle::current(),
        ),
        http_limits: limits::HttpLimits::default(),
        audit_sink: Some(Arc::new(Bound {
            log: Arc::clone(&log),
            actor: None,
        })),
    };
    let state = build_lifecycle_host_state(
        &cfg,
        LifecyclePhase::Install,
        LifecyclePrincipalContext::new(PrincipalId::default()),
        crate::MemoryLedger::default(),
    )
    .await
    .unwrap();

    crate::engine::wasm::host::fs::audit_fs(
        &state,
        "astrid:fs/host.write-file",
        "home://settings.json",
        &Ok::<(), ()>(()),
    );

    let records = log.0.lock().unwrap().clone();
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].0,
        Some(HostAuditActor {
            capsule_id: "hooked".to_owned(),
            wasm_hash: Some(ContentHash::hash(&wasm_bytes)),
        })
    );
}
