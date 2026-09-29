//! The grant-on-use prompt is committed to the audit log before it is
//! published.

use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use astrid_capabilities::AuditEntryId;
use astrid_core::GroupConfig;
use astrid_core::dirs::AstridHome;
use astrid_core::principal::PrincipalId;
use astrid_events::AstridEvent;
use astrid_events::ipc::{IpcPayload, RequestOwnerId, Topic};

use super::{CapsuleAccessResolver, GRANT_APPROVAL_ACTION, emit_grant_required};
use crate::audit_sink::{HostAuditEvent, HostAuditOutcome, HostAuditReceipt, HostAuditSink};
use crate::profile_cache::PrincipalProfileCache;

/// Records committed prompts and whether the prompt was already on the bus
/// when the commit ran (it watches the approval topic itself).
struct PromptSink {
    bus_watch: Mutex<astrid_events::EventReceiver>,
    committed: Mutex<Vec<(String, String, String, bool)>>,
}

impl HostAuditSink for PromptSink {
    fn record(&self, _: &PrincipalId, _: HostAuditEvent<'_>, _: HostAuditOutcome<'_>) {}

    fn commit<'a>(
        &'a self,
        principal: &'a PrincipalId,
        event: HostAuditEvent<'a>,
        _outcome: HostAuditOutcome<'a>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HostAuditReceipt> + Send + 'a>> {
        if let HostAuditEvent::ApprovalRequested {
            request_id,
            action,
            resource,
        } = event
        {
            assert_eq!(action, GRANT_APPROVAL_ACTION);
            self.committed.lock().unwrap().push((
                principal.to_string(),
                request_id.to_owned(),
                resource.to_owned(),
                self.bus_watch.lock().unwrap().try_recv().is_some(),
            ));
        }
        Box::pin(std::future::ready(HostAuditReceipt {
            sequence: None,
            entry_id: Some(AuditEntryId::new()),
        }))
    }
}

#[tokio::test]
async fn grant_prompt_is_committed_before_it_is_published() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cache = Arc::new(PrincipalProfileCache::with_home(AstridHome::from_path(
        dir.path(),
    )));
    let groups = Arc::new(ArcSwap::from_pointee(GroupConfig::builtin_only()));
    let bus = astrid_events::EventBus::with_capacity(16);
    let sink = Arc::new(PromptSink {
        bus_watch: Mutex::new(bus.subscribe_topic(Topic::approval_request().as_str())),
        committed: Mutex::new(Vec::new()),
    });
    let resolver = CapsuleAccessResolver::new(cache, groups)
        .with_audit_sink(Arc::clone(&sink) as Arc<dyn HostAuditSink>);
    let mut prompts = bus.subscribe_topic(Topic::approval_request().as_str());

    emit_grant_required(
        &bus,
        Some(&resolver),
        "alice",
        "search-tool".to_owned(),
        Some(RequestOwnerId::generate()),
    )
    .await;
    let event = prompts.recv().await.expect("prompt published");
    let AstridEvent::Ipc { message, .. } = &*event else {
        panic!("unexpected event");
    };
    let IpcPayload::GrantRequired { request_id, .. } = &message.payload else {
        panic!("unexpected payload");
    };

    assert_eq!(
        sink.committed.lock().unwrap().clone(),
        vec![(
            "alice".to_owned(),
            request_id.clone(),
            "search-tool".to_owned(),
            false
        )]
    );
}
