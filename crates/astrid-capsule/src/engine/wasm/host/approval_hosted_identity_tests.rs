use super::tests::{
    answer_action_request, approval_request, native_workspace_test_state, persistent_test_state,
};
use super::*;

#[tokio::test]
async fn hosted_always_reuses_stable_portal_across_distinct_cow_merged_paths() {
    let home = tempfile::tempdir().unwrap();
    let portal = home.path().join("portal");
    let other_portal = home.path().join("other-portal");

    let mut persist = persistent_test_state(home.path());
    persist.hosted_workspace_root = portal.clone();
    persist.workspace_root = home.path().join("cow-a");
    let result = answer_action_request(persist, "approve_always")
        .await
        .unwrap();
    assert_eq!(result.decision, ApprovalDecision::ApprovedAlways);

    let mut reuse = persistent_test_state(home.path());
    reuse.hosted_workspace_root = portal.clone();
    reuse.workspace_root = home.path().join("cow-b");
    assert!(
        check_persisted_allowance(&reuse, &PrincipalId::default(), "git push origin other")
            .unwrap()
    );
    let response = tokio::task::spawn_blocking(move || {
        approval::Host::request_approval(
            &mut reuse,
            approval_request("git push", "git push origin main"),
        )
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response.decision, ApprovalDecision::Allowance);

    let mut other_workspace = persistent_test_state(home.path());
    other_workspace.hosted_workspace_root = other_portal;
    other_workspace.workspace_root = home.path().join("cow-b");
    assert!(
        !check_persisted_allowance(
            &other_workspace,
            &PrincipalId::default(),
            "git push origin main"
        )
        .unwrap()
    );

    let other = PrincipalId::new("other").unwrap();
    astrid_core::profile::PrincipalProfile::default()
        .save_to_path(&astrid_core::dirs::AstridHome::from_path(home.path()).profile_path(&other))
        .unwrap();
    let mut same_identity = persistent_test_state(home.path());
    same_identity.hosted_workspace_root = portal;
    same_identity.workspace_root = home.path().join("cow-c");
    assert!(!check_persisted_allowance(&same_identity, &other, "git push origin main").unwrap());
    assert!(
        !check_persisted_allowance(
            &same_identity,
            &PrincipalId::default(),
            "git pull origin main"
        )
        .unwrap()
    );
    assert!(
        !check_persisted_allowance(
            &native_workspace_test_state(home.path()),
            &PrincipalId::default(),
            "git push origin main"
        )
        .unwrap()
    );
}

#[tokio::test]
async fn hosted_always_rejects_empty_portal_identity() {
    let home = tempfile::tempdir().unwrap();
    let mut empty = persistent_test_state(home.path());
    empty.hosted_workspace_root.clear();
    assert!(matches!(
        answer_action_request(empty, "approve_always").await,
        Err(ErrorCode::InvalidInput)
    ));
}

#[tokio::test]
async fn durable_always_survives_without_request_owner() {
    let home = tempfile::tempdir().unwrap();
    let persist = answer_action_request(persistent_test_state(home.path()), "approve_always")
        .await
        .unwrap();
    assert_eq!(persist.decision, ApprovalDecision::ApprovedAlways);

    // Fast paths return without blocking, so keep the host alive while
    // proving neither durable reuse nor unmatched deny publishes a prompt.
    let mut reuse = persistent_test_state(home.path());
    assert!(reuse.caller_context.is_none());
    let mut request_rx = reuse
        .event_bus
        .subscribe_topic(Topic::approval_request().as_str());
    let response = approval::Host::request_approval(
        &mut reuse,
        approval_request("git push", "git push origin main"),
    )
    .unwrap();
    assert_eq!(response.decision, ApprovalDecision::Allowance);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), request_rx.recv())
            .await
            .is_err(),
        "durable grant must not publish ApprovalRequired"
    );

    let mut other = persistent_test_state(home.path());
    assert!(other.caller_context.is_none());
    let mut other_rx = other
        .event_bus
        .subscribe_topic(Topic::approval_request().as_str());
    let denied = approval::Host::request_approval(
        &mut other,
        approval_request("git pull", "git pull origin main"),
    )
    .unwrap();
    assert_eq!(denied.decision, ApprovalDecision::Denied);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), other_rx.recv())
            .await
            .is_err(),
        "unattributed unmatched command must not be broadcast"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn hosted_always_rejects_non_utf8_portal_identity() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let home = tempfile::tempdir().unwrap();
    let mut persist = persistent_test_state(home.path());
    persist.hosted_workspace_root =
        std::path::PathBuf::from(OsString::from_vec(b"portal\x80".to_vec()));
    assert!(matches!(
        answer_action_request(persist, "approve_always").await,
        Err(ErrorCode::InvalidInput)
    ));

    let mut check = persistent_test_state(home.path());
    check.hosted_workspace_root =
        std::path::PathBuf::from(OsString::from_vec(b"portal\x80".to_vec()));
    assert!(
        !check_persisted_allowance(&check, &PrincipalId::default(), "git push origin main")
            .unwrap()
    );
}
