//! Recv-path stamp regressions kept out of `host_state_tests.rs` so that
//! file stays under the 1000-line cap.

use super::super::test_fixtures::minimal_host_state;
use astrid_events::ipc::Topic;
use astrid_storage::PrincipalDirectory;

fn event_message(principal: Option<&str>) -> astrid_events::ipc::IpcMessage {
    let message = astrid_events::ipc::IpcMessage::new(
        Topic::from_raw("some.v1.event"),
        astrid_events::ipc::IpcPayload::RawJson(serde_json::json!({})),
        uuid::Uuid::new_v4(),
    );
    match principal {
        Some(name) => message.with_principal(name.to_string()),
        None => message,
    }
}

fn owner_state(handle: tokio::runtime::Handle) -> super::HostState {
    let mut state = minimal_host_state(handle);
    let owner = astrid_core::PrincipalId::new("alice").expect("alice");
    state.principal = owner.clone();
    let owner_uid = state
        .principal_directory
        .uid_for(&owner)
        .expect("fixture alice binding");
    state.stamped_invocation = Some(crate::stamp::StampedInvocation::from_trusted_uid(owner_uid));
    state
}

fn owner_uid(state: &super::HostState) -> astrid_core::PrincipalUid {
    state
        .principal_directory
        .uid_for(&state.principal)
        .expect("owner binding")
}

#[test]
fn host_state_stamp_field_is_crate_private() {
    let source = include_str!("host_state.rs");
    assert!(
        source.contains("    pub(crate) stamped_invocation:"),
        "HostState must not expose a public stamp slot"
    );
    assert!(
        !source.contains("    pub stamped_invocation:"),
        "a public stamp field would let downstream crates replay attribution"
    );
}

#[test]
fn recv_unspecified_does_not_inherit_owner_stamp() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mut state = owner_state(rt.handle().clone());

    state.install_recv_invocation_context(&event_message(None));
    assert!(
        state.stamped_invocation.is_none(),
        "principalless recv must be Unspecified, not inherited owner attribution"
    );
}

#[test]
fn recv_same_owner_keeps_stamp_when_binding_is_current() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mut state = owner_state(rt.handle().clone());
    let uid = owner_uid(&state);

    state.install_recv_invocation_context(&event_message(Some("alice")));
    assert_eq!(
        state
            .stamped_invocation
            .as_ref()
            .map(crate::stamp::StampedInvocation::principal),
        Some(uid)
    );
}

#[test]
fn recv_drops_cached_stamp_after_directory_rename() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mut state = owner_state(rt.handle().clone());
    let owner = state.principal.clone();
    let renamed = astrid_core::PrincipalId::new("alice-renamed").expect("renamed");
    let uid = owner_uid(&state);

    state
        .principal_directory
        .rename(uid, &owner, renamed)
        .expect("rebind captured uid away from the owner alias");

    state.install_recv_invocation_context(&event_message(None));
    assert!(
        state.stamped_invocation.is_none(),
        "unspecified recv must not retain a UID after the owner alias was rebound"
    );

    state.stamped_invocation = Some(crate::stamp::StampedInvocation::from_trusted_uid(uid));
    state.install_recv_invocation_context(&event_message(Some("alice")));
    assert!(
        state.stamped_invocation.is_none(),
        "same-owner recv must not retain a UID after the owner alias was rebound"
    );
}

#[test]
fn recv_drops_cached_stamp_after_directory_unregister() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mut state = owner_state(rt.handle().clone());
    let uid = owner_uid(&state);
    state.principal_directory = PrincipalDirectory::default();

    state.install_recv_invocation_context(&event_message(None));
    assert!(
        state.stamped_invocation.is_none(),
        "unspecified recv must not retain a UID after the owner binding was removed"
    );

    state.stamped_invocation = Some(crate::stamp::StampedInvocation::from_trusted_uid(uid));
    state.install_recv_invocation_context(&event_message(Some("alice")));
    assert!(
        state.stamped_invocation.is_none(),
        "same-owner recv must not retain a UID after the owner binding was removed"
    );
}

#[test]
fn recv_cross_publisher_does_not_reuse_owner_stamp() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mut state = owner_state(rt.handle().clone());
    let owner_uid = owner_uid(&state);
    let bob = astrid_core::PrincipalId::new("bob").expect("bob");
    let bob_uid = state
        .principal_directory
        .uid_for(&bob)
        .expect("fixture bob binding");

    state.install_recv_invocation_context(&event_message(Some("bob")));
    assert_eq!(
        state
            .stamped_invocation
            .as_ref()
            .map(crate::stamp::StampedInvocation::principal),
        Some(bob_uid)
    );
    assert_ne!(
        state
            .stamped_invocation
            .as_ref()
            .map(crate::stamp::StampedInvocation::principal),
        Some(owner_uid),
        "peer recv must not keep the owner UID"
    );

    state.stamped_invocation = Some(crate::stamp::StampedInvocation::from_trusted_uid(owner_uid));
    state.install_recv_invocation_context(&event_message(Some("carol")));
    assert!(
        state.stamped_invocation.is_none(),
        "unbound peer recv must drop the owner stamp rather than reuse it"
    );
}
