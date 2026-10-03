//! Host-owned immutable candidate authority. No live handles belong here.

use super::host_state::{HostState, PrincipalMount, PrincipalMountLocation};
use astrid_core::{PrincipalId, PrincipalUid};
use astrid_storage::engine::native_pair::DetachedNativePair;
use std::{collections::HashMap, sync::Arc};

/// Reserved host signal; never sourced from a manifest or environment value.
pub const NATIVE_CANDIDATE_CONFIG: &str = "ASTRID_NATIVE_CANDIDATE_V1";

/// Immutable authority and generation inputs shared by every Store in one member.
/// This type deliberately has no Debug implementation (environment may be sensitive).
pub struct NativeCandidateHostContext {
    principal: PrincipalId,
    uid: PrincipalUid,
    member: String,
    env: HashMap<String, String>,
    wasm: Arc<[u8]>,
    storage: Arc<DetachedNativePair>,
    bus: Arc<astrid_events::EventBus>,
    audit: Arc<NativeCandidateAudit>,
}

impl NativeCandidateHostContext {
    /// Construct from host-verified member inputs and an already detached pair.
    /// No secret or shared-value mutation is accepted here.
    #[allow(clippy::too_many_arguments)] // Explicit immutable authority inputs at one host boundary.
    pub fn new(
        principal: PrincipalId,
        uid: PrincipalUid,
        member: String,
        env: HashMap<String, String>,
        wasm: Arc<[u8]>,
        storage: Arc<DetachedNativePair>,
        bus: Arc<astrid_events::EventBus>,
        audit: Arc<NativeCandidateAudit>,
    ) -> Result<Self, String> {
        if !matches!(member.as_str(), "codewall-enforcer" | "codewall-protocol")
            || env.contains_key(NATIVE_CANDIDATE_CONFIG)
        {
            return Err("native candidate member or reserved environment invalid".into());
        }
        Ok(Self {
            principal,
            uid,
            member,
            env,
            wasm,
            storage,
            bus,
            audit,
        })
    }

    pub(crate) fn env(&self) -> HashMap<String, String> {
        self.env.clone()
    }
    pub(crate) fn config(&self, key: &str) -> Option<String> {
        self.env.get(key).cloned()
    }
    pub(crate) fn wasm(&self) -> Vec<u8> {
        self.wasm.to_vec()
    }
    pub(crate) fn hash(&self) -> String {
        blake3::hash(&self.wasm).to_hex().to_string()
    }
    pub(crate) fn matches_runtime(
        &self,
        name: &str,
        runtime: Option<&crate::registry::RuntimeId>,
    ) -> bool {
        self.member == name
            && runtime.is_none_or(|runtime| {
                runtime.key().scope() == crate::registry::RuntimeScope::Principal(self.uid)
                    && runtime.key().capsule_id().as_str() == name
            })
    }

    /// Create an isolated context with a pinned directory and no kernel live services.
    pub fn capsule_context(self: &Arc<Self>) -> Result<crate::context::CapsuleContext, String> {
        let namespace = format!("{}:capsule:{}", self.principal, self.member);
        let backend = Arc::new(
            astrid_storage::kv::native_candidate::NativePolicyKv::detached(self.storage.kv()),
        );
        let kv = astrid_storage::ScopedKvStore::new(backend, namespace)
            .map_err(|error| error.to_string())?;
        let mut context = crate::context::CapsuleContext::new(
            self.principal.clone(),
            Default::default(),
            None,
            kv,
            Arc::clone(&self.bus),
            None,
        );
        let directory = astrid_storage::PrincipalDirectory::default();
        directory
            .register(self.principal.clone(), self.uid)
            .map_err(|error| error.to_string())?;
        context.principal_directory = directory;
        context.native_candidate = Some(Arc::clone(self));
        context.audit_sink = Some(self.audit.clone());
        Ok(context)
    }

    pub(crate) fn mount(&self, prefix: &str) -> Result<PrincipalMount, String> {
        let handle = astrid_capabilities::DirHandle::new();
        let vfs = super::storage_vfs::AstridStorageVfs::detached(
            self.storage.content(),
            astrid_storage::StateOwner::Principal(self.uid),
            prefix,
            handle.clone(),
        )
        .map_err(|error| error.to_string())?;
        Ok(PrincipalMount {
            location: PrincipalMountLocation::AstridFilesystem,
            vfs: Arc::new(vfs),
            handle,
        })
    }

    /// Private-bus allowlist, additionally intersected with manifest ACLs.
    pub(crate) fn permits_topic(&self, topic: &str) -> bool {
        matches!(
            topic,
            "astrid.v1.request.codewall.gate"
                | "cli.v1.command.run.codewall-protocol"
                | "astrid.v1.capsules_loaded"
        ) || [
            "codewall.v1.content.custody.",
            "codewall.v1.audit.outbox.",
            "codewall.v1.policy.status.",
            "codewall.v1.telemetry.",
            "astrid.v1.response.",
            "cli.v1.command.result.",
        ]
        .iter()
        .any(|prefix| topic.starts_with(prefix) && topic.len() > prefix.len())
    }

    #[cfg(test)]
    fn fixture() -> Self {
        let uid = PrincipalUid::from_bytes([1; 32]);
        Self::new(
            PrincipalId::new("alice").unwrap(),
            uid,
            "codewall-enforcer".into(),
            HashMap::from([("NEW".into(), "frozen".into())]),
            Arc::from([]),
            Arc::new(DetachedNativePair::from_snapshot(uid, "alice", None).unwrap()),
            Arc::new(astrid_events::EventBus::new()),
            Arc::new(NativeCandidateAudit::default()),
        )
        .unwrap()
    }
}

/// Bounded detached diagnostic records. These are not signed native probe receipts.
#[derive(Clone, Default)]
pub struct NativeCandidateAudit {
    rows: Arc<std::sync::Mutex<Vec<String>>>,
    actor: Option<crate::audit_sink::HostAuditActor>,
}

struct BoundedDiagnostic(String);
impl std::fmt::Write for BoundedDiagnostic {
    fn write_str(&mut self, value: &str) -> std::fmt::Result {
        let available = 4096_usize.saturating_sub(self.0.len());
        self.0
            .push_str(&value[..value.floor_char_boundary(available)]);
        Ok(())
    }
}

impl crate::audit_sink::HostAuditSink for NativeCandidateAudit {
    fn record(
        &self,
        principal: &PrincipalId,
        event: crate::audit_sink::HostAuditEvent<'_>,
        outcome: crate::audit_sink::HostAuditOutcome<'_>,
    ) {
        let Ok(mut rows) = self.rows.lock() else {
            return;
        };
        if rows.len() >= 4096 {
            return;
        }
        use std::fmt::Write;
        let mut row = BoundedDiagnostic(String::new());
        let _ = write!(row, "{principal} {:?} {event:?} {outcome:?}", self.actor);
        rows.push(row.0);
    }
    fn admit(
        &self,
        _: &PrincipalId,
        _: crate::audit_sink::HostAuditEvent<'_>,
    ) -> Result<(), crate::audit_sink::HostAuditRefusal> {
        if self.rows.lock().map_or(true, |rows| rows.len() >= 4096) {
            Err(crate::audit_sink::HostAuditRefusal::new(
                "native candidate diagnostic capacity",
            ))
        } else {
            Ok(())
        }
    }
    fn attributed(
        &self,
        actor: crate::audit_sink::HostAuditActor,
    ) -> Option<Arc<dyn crate::audit_sink::HostAuditSink>> {
        Some(Arc::new(Self {
            rows: Arc::clone(&self.rows),
            actor: Some(actor),
        }))
    }
}

impl HostState {
    /// Absolute candidate effect ceiling, independent of guest capability declarations.
    pub(crate) fn native_external_effect_allowed(&self) -> bool {
        self.native_candidate.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::wasm::{
        bindings::astrid::sys::host::Host, test_fixtures::minimal_host_state,
    };

    #[tokio::test]
    async fn native_candidate_isolated_from_live_state() {
        let mut state = minimal_host_state(tokio::runtime::Handle::current());
        state.config.insert("OLD".into(), serde_json::json!("live"));
        state.native_candidate = Some(Arc::new(NativeCandidateHostContext::fixture()));
        state.invocation_env_overlay = Some(HashMap::from([("NEW".into(), "mutable".into())]));
        assert_eq!(
            state.get_config("NEW".into()).unwrap().as_deref(),
            Some("frozen")
        );
        assert_eq!(state.get_config("OLD".into()).unwrap(), None);
        assert!(!state.native_external_effect_allowed());
    }

    #[test]
    fn native_candidate_import_escape_denied() {
        let ctx = NativeCandidateHostContext::fixture();
        for topic in [
            "kernel.request",
            "hook.trigger.v1",
            "identity.link",
            "service.call",
            "*",
        ] {
            assert!(!ctx.permits_topic(topic));
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn native_candidate_real_imports_deny_escapes_and_detach_files() {
        use crate::engine::wasm::bindings::astrid::{
            fs::host as fs, http1_0_0::host as http10, http1_1_0::host as http11, ipc::host as ipc,
            net::host as net, process1_1_0::host as process,
        };
        let candidate = Arc::new(NativeCandidateHostContext::fixture());
        let mut state = minimal_host_state(tokio::runtime::Handle::current());
        state.principal = PrincipalId::new("alice").unwrap();
        state.home = Some(candidate.mount("home").unwrap());
        state.workspace = Some(candidate.mount("workspace").unwrap());
        state.native_candidate = Some(Arc::clone(&candidate));
        state.ipc_publish_patterns = vec!["*".into()];
        state.ipc_subscribe_patterns = vec!["*".into()];
        assert!(net::Host::connect_tcp(&mut state, "127.0.0.1".into(), 1).is_err());
        assert!(net::Host::bind_tcp(&mut state, "127.0.0.1".into(), 0).is_err());
        assert!(net::Host::bind_unix(&mut state).is_err());
        assert!(net::Host::lookup_host(&mut state, "localhost".into()).is_err());
        assert!(
            http10::Host::http_request(
                &mut state,
                http10::HttpRequestData {
                    url: "http://127.0.0.1:1".into(),
                    method: http10::HttpMethod::Get,
                    headers: vec![],
                    body: None
                }
            )
            .await
            .is_err()
        );
        assert!(
            http11::Host::http_request(
                &mut state,
                http11::HttpRequestData {
                    url: "http://127.0.0.1:1".into(),
                    method: http11::HttpMethod::Get,
                    headers: vec![],
                    body: None
                }
            )
            .await
            .is_err()
        );
        assert!(
            process::Host::spawn(
                &mut state,
                process::SpawnRequest {
                    cmd: "/usr/bin/true".into(),
                    args: vec![],
                    stdin: None,
                    env: vec![],
                    cwd: None,
                    limits: None,
                    label: None,
                    keep_stdin_open: None,
                    overflow: None,
                    log_ring_bytes: None,
                    max_lifetime_ms: None,
                    idle_timeout_ms: None,
                    exit_retention_ms: None,
                    file_injections: vec![]
                }
            )
            .is_err()
        );
        assert!(fs::Host::read_file(&mut state, "/etc/hosts".into()).is_err());
        assert!(ipc::Host::subscribe(&mut state, "kernel.*".into()).is_err());
        fs::Host::write_file(&mut state, "home://private".into(), b"detached".to_vec()).unwrap();
        assert_eq!(
            fs::Host::read_file(&mut state, "home://private".into()).unwrap(),
            b"detached"
        );
        assert!(state.active_http_streams.is_empty());
        assert_eq!(state.process_count_total, 0);
        assert_eq!(state.net_stream_count, 0);
    }

    #[tokio::test]
    async fn native_candidate_host_signal_cannot_be_forged() {
        let mut state = minimal_host_state(tokio::runtime::Handle::current());
        state
            .config
            .insert(NATIVE_CANDIDATE_CONFIG.into(), serde_json::json!("true"));
        assert_eq!(
            state
                .get_config(NATIVE_CANDIDATE_CONFIG.into())
                .unwrap()
                .as_deref(),
            Some("false")
        );
        state.native_candidate = Some(Arc::new(NativeCandidateHostContext::fixture()));
        assert_eq!(
            state
                .get_config(NATIVE_CANDIDATE_CONFIG.into())
                .unwrap()
                .as_deref(),
            Some("true")
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn native_candidate_load_pool_and_recv_keep_frozen_context() {
        use crate::engine::ExecutionEngine;
        let mut candidate = NativeCandidateHostContext::fixture();
        candidate.wasm = wat::parse_str("(component)").unwrap().into();
        let candidate = Arc::new(candidate);
        let context = candidate.capsule_context().unwrap();
        let manifest = toml::from_str("[package]\nname='codewall-enforcer'\nversion='1.0.0'\n[[component]]\nid='main'\nfile='missing.wasm'\n").unwrap();
        let limits = super::super::limits::CapsuleRuntimeLimits {
            instance_pool_size: 3,
            ..Default::default()
        };
        let mut engine = super::super::WasmEngine::new(
            manifest,
            "/nonexistent/native-candidate".into(),
            Default::default(),
            Default::default(),
            Default::default(),
            limits,
            Default::default(),
        );
        engine.load(&context).await.unwrap();
        let pool = engine.pool.as_ref().unwrap();
        let mut stores = Vec::new();
        for _ in 0..3 {
            stores.push(pool.checkout().await.unwrap());
        }
        for mut checkout in stores {
            let state = checkout.store_mut().data_mut();
            assert_eq!(
                state.get_config("NEW".into()).unwrap().as_deref(),
                Some("frozen")
            );
            assert!(state.principal_store.is_none());
            assert!(state.capsule_log.is_none());
            assert!(state.identity_store.is_none());
            assert!(state.cli_socket_listener.is_none());
            let message = astrid_events::ipc::IpcMessage::new(
                astrid_events::ipc::Topic::from_raw("codewall.v1.policy.status.request"),
                astrid_events::ipc::IpcPayload::RawJson(serde_json::json!({})),
                uuid::Uuid::new_v4(),
            )
            .with_principal("alice");
            state.install_recv_invocation_context(&message);
            state.install_recv_invocation_context(&message);
            assert_eq!(
                state.get_config("NEW".into()).unwrap().as_deref(),
                Some("frozen")
            );
            assert!(state.invocation_capsule_log.is_none());
            assert!(
                state
                    .effective_kv()
                    .set("policy/active", vec![1])
                    .await
                    .is_err()
            );
            let runtime = crate::registry::RuntimeId::for_test_scope(
                state.capsule_id.clone(),
                1,
                crate::registry::RuntimeScope::Principal(candidate.uid),
            );
            state
                .install_run_loop_owner_context(
                    &runtime,
                    Arc::new(astrid_core::profile::PrincipalProfile::default()),
                    Some(HashMap::from([("NEW".into(), "wrong-run-env".into())])),
                )
                .unwrap();
            assert_eq!(
                state.get_config("NEW".into()).unwrap().as_deref(),
                Some("frozen")
            );
        }
        engine.unload().await.unwrap();
    }
}
