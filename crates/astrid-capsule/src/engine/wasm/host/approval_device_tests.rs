//! Exercise command approval across an actual device-registry retirement.
use super::tests::{
    approval_request, approval_response_event, await_approval_request, install_request_owner,
    persistent_test_state,
};
use super::*;
use astrid_core::profile::{AuthMethod, DeviceKey, DeviceKeyId, DeviceScope, PrincipalProfile};

#[tokio::test]
async fn replacement_registration_cannot_authorize_queued_command_grant() {
    for (caller_stale, responder_stale) in [(false, false), (true, false), (false, true)] {
        let dir = tempfile::tempdir().unwrap();
        let home = astrid_core::dirs::AstridHome::from_path(dir.path());
        let mut state = persistent_test_state(dir.path());
        let principal = state.effective_principal();
        let owner = install_request_owner(&mut state);
        let original = DeviceKey::new("a".repeat(64), DeviceScope::Full, None, 0);
        let current = DeviceKey::new("b".repeat(64), DeviceScope::Full, None, 0);
        let mut profile = PrincipalProfile::default();
        profile.auth.methods.push(AuthMethod::Keypair);
        profile.add_device(original.clone());
        profile.add_device(current.clone());
        profile.save(&home, &principal).unwrap();

        let caller = if caller_stale { &original } else { &current };
        let context = state.caller_context.as_mut().unwrap();
        context.device_key_id = Some(caller.key_id.clone());
        context.device_registration_id = caller.registration_id.map(Into::into);
        let bus = state.event_bus.clone();
        let requests = bus.subscribe_topic(Topic::approval_request().as_str());
        let sessions = state.device_sessions.clone();
        let cache = state.profile_cache.clone().unwrap();
        let task = tokio::task::spawn_blocking(move || {
            approval::Host::request_approval(
                &mut state,
                approval_request("git push", "git push origin main"),
            )
        });
        let (id, _, published_owner) = await_approval_request(requests).await;
        assert_eq!(owner, published_owner);
        let replacement = DeviceKey::new("a".repeat(64), DeviceScope::Full, None, 0);
        assert_ne!(replacement.registration_id, original.registration_id);
        profile.auth.public_keys.clear();
        profile.add_device(replacement);
        profile.add_device(current.clone());
        profile.save(&home, &principal).unwrap();
        cache.invalidate(&principal);
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            sessions.retire(
                &principal,
                &DeviceKeyId::new(original.key_id.clone()).unwrap(),
            ),
        )
        .await
        .expect("device retirement finishes while the prompt waits")
        .unwrap();

        let responder = if responder_stale { &original } else { &current };
        let mut reply =
            approval_response_event(&id, Some(principal.as_str()), Some(owner), "approve_always");
        let AstridEvent::Ipc { message, .. } = &mut reply else {
            unreachable!()
        };
        message.device_key_id = Some(responder.key_id.clone());
        message.device_registration_id = responder.registration_id.map(Into::into);
        bus.publish(reply);
        let result = task.await.unwrap();
        let saved = PrincipalProfile::load_required(&home, &principal).unwrap();
        if caller_stale || responder_stale {
            assert!(matches!(result, Err(ErrorCode::StoreUnavailable)));
            assert!(saved.approvals.command_always.is_empty());
        } else {
            assert_eq!(result.unwrap().decision, ApprovalDecision::ApprovedAlways);
            assert_eq!(saved.approvals.command_always.len(), 1);
            assert_eq!(saved.approvals.command_always[0].command, "git push");
        }
    }
}

#[tokio::test]
async fn retirement_during_reply_lookup_rejects_an_unchanged_profile_record() {
    use astrid_core::profile::device_sessions::{DeviceSessionError, DeviceSessions};
    let key = DeviceKey::new("c".repeat(64), DeviceScope::Full, None, 0);
    let mut profile = PrincipalProfile::default();
    profile.auth.methods.push(AuthMethod::Keypair);
    profile.add_device(key.clone());
    let principal = PrincipalId::default();
    let registry = DeviceSessions::default();
    let runtime = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        for retire in [false, true] {
            let bound = registry.bind_current(
                &principal,
                DeviceKeyId::new(key.key_id.clone()).unwrap(),
                |owner, fingerprint| {
                    let live = profile
                        .active_registration(fingerprint, key.registration_id.map(Into::into))
                        .unwrap();
                    if retire {
                        runtime
                            .block_on(registry.retire(owner, fingerprint))
                            .unwrap();
                    }
                    Ok(live.registration_id)
                },
            );
            assert_eq!(matches!(bound, Err(DeviceSessionError::Retired)), retire);
            assert_eq!(
                consent_reply::admit(Ok(()), || Ok(()), || bound.map_err(|_| ())).is_some(),
                !retire
            );
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn principal_retirement_during_approval_prevents_persistent_grant() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = persistent_test_state(dir.path());
    let owner = install_request_owner(&mut state);
    let principal = state.effective_principal();
    let tracker = std::sync::Arc::new(crate::engine::wasm::PrincipalInvocationTracker::default());
    state.principal_invocations = Some(tracker.clone());
    let bus = state.event_bus.clone();
    let requests = bus.subscribe_topic(Topic::approval_request().as_str());
    let task = tokio::task::spawn_blocking(move || {
        approval::Host::request_approval(
            &mut state,
            approval_request("git push", "git push origin main"),
        )
    });
    let (id, _, _) = await_approval_request(requests).await;
    tracker.retire(&principal);
    bus.publish(approval_response_event(
        &id,
        Some(principal.as_str()),
        Some(owner),
        "approve_always",
    ));
    assert!(matches!(
        task.await.unwrap(),
        Err(ErrorCode::StoreUnavailable)
    ));
    let fresh = persistent_test_state(dir.path());
    assert!(!check_persisted_allowance(&fresh, &principal, "git push origin main").unwrap());
}
