//! Invite admission must respect durable interrupted-retirement reservations.

use super::*;

#[tokio::test]
async fn invite_alias_retirement_fence_preserves_bearer_until_cleanup() {
    let (_dir, kernel) = fixture().await;
    let token = issue_token(&kernel).await;
    let alias = PrincipalId::new("pending-enrollee").unwrap();
    let old_user = kernel
        .identity_store
        .create_principal(alias.clone(), [9; 32])
        .await
        .unwrap();
    let old_uid = kernel.principal_directory.uid_for(&alias).unwrap();
    let guard = kernel
        .ownership_store
        .guard_principal_deletion_for_alias(old_uid, alias.clone())
        .await
        .unwrap();
    assert!(
        kernel
            .identity_store
            .delete_user(old_user.id)
            .await
            .unwrap()
    );
    drop(guard); // Interruption after identity removal leaves durable authority.
    assert!(kernel.principal_directory.uid_for(&alias).is_err());
    assert!(!kernel.astrid_home.profile_path(&alias).exists());
    let before = kernel.ownership_store.load().await.unwrap();
    let store = invite_store(&kernel).unwrap();
    let token_hash = invite::hash_token(&token);
    let invitation = store.redeemable(&token_hash).await.unwrap().unwrap();

    let response = invite_redeem(
        &kernel,
        token.clone(),
        "cd".repeat(32),
        Some("Pending Enrollee".into()),
    )
    .await;
    let AdminResponseBody::Error(message) = response else {
        panic!("reserved alias was admitted: {response:?}");
    };
    assert!(message.contains("unavailable"), "{message}");
    assert!(kernel.principal_directory.uid_for(&alias).is_err());
    assert!(!kernel.astrid_home.profile_path(&alias).exists());
    assert_eq!(kernel.ownership_store.load().await.unwrap(), before);
    assert_eq!(
        store.redeemable(&token_hash).await.unwrap(),
        Some(invitation)
    );

    let resumed = kernel
        .ownership_store
        .resume_principal_deletion_by_alias(&alias)
        .await
        .unwrap()
        .expect("interrupted retirement remains resumable");
    assert_eq!(resumed.principal_uid(), old_uid);
    resumed.finish().await.unwrap();
    let retried = invite_redeem(
        &kernel,
        token,
        "cd".repeat(32),
        Some("Pending Enrollee".into()),
    )
    .await;
    let AdminResponseBody::InviteRedeemed(redeemed) = retried else {
        panic!("same bearer must succeed after retirement finishes: {retried:?}");
    };
    assert_eq!(redeemed.principal, alias);
    assert_ne!(kernel.principal_directory.uid_for(&alias).unwrap(), old_uid);
    assert!(store.redeemable(&token_hash).await.unwrap().is_none());
}
