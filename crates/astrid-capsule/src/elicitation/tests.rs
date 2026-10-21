use super::*;
use std::time::Duration;

fn registry() -> Arc<PendingSecretElicits> {
    Arc::new(PendingSecretElicits::new(NonZeroUsize::new(1).unwrap()))
}

fn identity(principal: &str, capsule: &str, key: &str) -> SecretElicitIdentity {
    SecretElicitIdentity::new(
        PrincipalId::new(principal).unwrap(),
        CapsuleId::new(capsule).unwrap(),
        SecretElicitKey::new(key).unwrap(),
    )
}

fn owner() -> SecretElicitIdentity {
    identity("alice", "example", "token")
}

#[tokio::test]
async fn complete_is_single_use_and_keeps_value_private() {
    let registry = registry();
    let owner = owner();
    let waiter = registry.register(owner.clone()).unwrap();
    let id = waiter.id();
    registry.complete(id, &owner, "synthetic".into()).unwrap();
    let reply = waiter.recv().await;
    assert!(!format!("{reply:?}").contains("synthetic"));
    let SecretElicitReply::Provided(value) = reply else {
        panic!("missing response")
    };
    assert_eq!(value.expose_as_str(), "synthetic");
    assert_eq!(
        registry.complete(id, &owner, "late".into()),
        Err(SecretElicitError::UnknownRequest)
    );
    assert_eq!(registry.in_flight(), 0);
}

#[tokio::test]
async fn mismatched_identity_or_empty_value_does_not_consume_request() {
    let registry = registry();
    let owner = owner();
    let waiter = registry.register(owner.clone()).unwrap();
    let id = waiter.id();
    for wrong in [
        identity("bob", "example", "token"),
        identity("alice", "other", "token"),
        identity("alice", "example", "other"),
    ] {
        assert_eq!(
            registry.complete(id, &wrong, "synthetic".into()),
            Err(SecretElicitError::IdentityMismatch)
        );
        assert_eq!(
            registry.cancel(id, &wrong),
            Err(SecretElicitError::IdentityMismatch)
        );
    }
    assert_eq!(
        registry.complete(id, &owner, String::new()),
        Err(SecretElicitError::EmptySecret)
    );
    registry.cancel(id, &owner).unwrap();
    assert!(matches!(waiter.recv().await, SecretElicitReply::Cancelled));
}

#[test]
fn dropping_waiter_recovers_capacity() {
    let registry = registry();
    let first = registry.register(owner()).unwrap();
    assert_eq!(
        registry.register(owner()).unwrap_err(),
        SecretElicitError::AtCapacity
    );
    drop(first);
    assert_eq!(registry.in_flight(), 0);
    assert!(registry.register(owner()).is_ok());
}

#[tokio::test]
async fn timeout_drops_owned_waiter_and_rejects_late_response() {
    let registry = registry();
    let waiter = registry.register(owner()).unwrap();
    let id = waiter.id();
    assert!(
        tokio::time::timeout(Duration::from_millis(5), waiter.recv())
            .await
            .is_err()
    );
    assert_eq!(registry.in_flight(), 0);
    assert_eq!(
        registry.complete(id, &owner(), "late".into()),
        Err(SecretElicitError::UnknownRequest)
    );
    assert!(registry.register(owner()).is_ok());
}

#[tokio::test]
async fn aborted_receiver_task_releases_slot() {
    let registry = registry();
    let waiter = registry.register(owner()).unwrap();
    let task = tokio::spawn(waiter.recv());
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(registry.in_flight(), 0);
}

#[tokio::test]
async fn cancel_all_notifies_waiters() {
    let registry = registry();
    let waiter = registry.register(owner()).unwrap();
    registry.cancel_all();
    assert!(matches!(waiter.recv().await, SecretElicitReply::Cancelled));
    assert_eq!(registry.in_flight(), 0);
}

#[test]
fn failed_delivery_is_not_reported_as_success() {
    let registry = registry();
    let mut waiter = registry.register(owner()).unwrap();
    waiter.rx.as_mut().unwrap().close();
    assert_eq!(
        registry.complete(waiter.id(), &owner(), "synthetic".into()),
        Err(SecretElicitError::UnknownRequest)
    );
    assert_eq!(registry.in_flight(), 0);
}

#[test]
fn constructor_does_not_allocate_capacity_or_panic_at_large_limit() {
    let registry = Arc::new(PendingSecretElicits::new(
        NonZeroUsize::new(usize::MAX).unwrap(),
    ));
    assert!(registry.register(owner()).is_ok());
}

#[test]
fn empty_secret_and_key_are_rejected_and_debug_is_redacted() {
    assert_eq!(
        SecretValue::try_new("").unwrap_err(),
        SecretElicitError::EmptySecret
    );
    assert_eq!(
        SecretElicitKey::new("").unwrap_err(),
        SecretElicitError::EmptyKey
    );
    let value = SecretValue::try_new("synthetic").unwrap();
    assert!(!format!("{value:?}").contains("synthetic"));
}

#[tokio::test]
async fn empty_text_is_distinct_from_cancel() {
    let registry = registry();
    let owner = owner();
    let waiter = registry
        .register_kind(owner.clone(), ElicitAnswerKind::Text)
        .unwrap();
    let id = waiter.id();
    assert_eq!(
        registry.reply_for_principal(id, owner.principal(), None, Some(vec!["x".into()])),
        Err(SecretElicitError::InvalidAnswer)
    );
    assert_eq!(registry.in_flight(), 1);
    registry
        .reply_for_principal(id, owner.principal(), Some(String::new()), None)
        .unwrap();
    assert!(matches!(waiter.recv().await, SecretElicitReply::Value(value) if value.is_empty()));
    assert_eq!(registry.in_flight(), 0);
}

#[tokio::test]
async fn empty_array_is_distinct_from_cancel() {
    let registry = registry();
    let owner = owner();
    let waiter = registry
        .register_kind(owner.clone(), ElicitAnswerKind::Array)
        .unwrap();
    let id = waiter.id();
    assert_eq!(
        registry.reply_for_principal(id, owner.principal(), Some("x".into()), None),
        Err(SecretElicitError::InvalidAnswer)
    );
    registry
        .reply_for_principal(id, owner.principal(), None, Some(Vec::new()))
        .unwrap();
    assert!(matches!(
        waiter.recv().await,
        SecretElicitReply::Values(values) if values.is_empty()
    ));
}

#[tokio::test]
async fn both_present_or_wrong_type_does_not_consume_and_cancel_still_works() {
    let registry = registry();
    let owner = owner();
    let waiter = registry
        .register_kind(owner.clone(), ElicitAnswerKind::Text)
        .unwrap();
    let id = waiter.id();
    assert_eq!(
        registry.reply_for_principal(
            id,
            owner.principal(),
            Some("x".into()),
            Some(vec!["y".into()])
        ),
        Err(SecretElicitError::InvalidAnswer)
    );
    assert_eq!(
        registry.reply_for_principal(id, owner.principal(), None, Some(vec!["y".into()])),
        Err(SecretElicitError::InvalidAnswer)
    );
    assert_eq!(registry.in_flight(), 1);
    registry
        .reply_for_principal(id, owner.principal(), None, None)
        .unwrap();
    assert!(matches!(waiter.recv().await, SecretElicitReply::Cancelled));
}

#[tokio::test]
async fn select_requires_exact_member_and_rejects_non_member() {
    let registry = registry();
    let owner = owner();
    let waiter = registry
        .register_kind(
            owner.clone(),
            ElicitAnswerKind::Select(vec!["mainnet".into(), "testnet".into()]),
        )
        .unwrap();
    let id = waiter.id();
    assert_eq!(
        registry.reply_for_principal(id, owner.principal(), Some("devnet".into()), None),
        Err(SecretElicitError::InvalidAnswer)
    );
    assert_eq!(registry.in_flight(), 1);
    registry
        .reply_for_principal(id, owner.principal(), Some("mainnet".into()), None)
        .unwrap();
    assert!(matches!(
        waiter.recv().await,
        SecretElicitReply::Value(value) if value == "mainnet"
    ));
}

#[tokio::test]
async fn secret_empty_and_cross_principal_do_not_consume_existing_secret() {
    let registry = registry();
    let owner = owner();
    let waiter = registry.register(owner.clone()).unwrap();
    let id = waiter.id();
    assert_eq!(
        registry.reply_for_principal(id, owner.principal(), Some(String::new()), None),
        Err(SecretElicitError::EmptySecret)
    );
    assert_eq!(
        registry.reply_for_principal(
            id,
            identity("bob", "example", "token").principal(),
            Some("synthetic".into()),
            None
        ),
        Err(SecretElicitError::IdentityMismatch)
    );
    registry
        .reply_for_principal(id, owner.principal(), Some("synthetic".into()), None)
        .unwrap();
    let SecretElicitReply::Provided(value) = waiter.recv().await else {
        panic!("missing secret")
    };
    assert_eq!(value.expose_as_str(), "synthetic");
}
