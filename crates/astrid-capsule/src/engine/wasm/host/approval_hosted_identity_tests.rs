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
