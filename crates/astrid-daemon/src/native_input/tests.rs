#![allow(clippy::unwrap_used)]

#[cfg(unix)]
mod socket;

use std::num::NonZeroUsize;

use super::*;
use astrid_capsule::capsule::CapsuleId;
use astrid_capsule::elicitation::{
    ElicitAnswerKind, SecretElicitIdentity, SecretElicitKey, SecretElicitReply,
};

fn owner(name: &str) -> SecretElicitIdentity {
    SecretElicitIdentity::new(
        PrincipalId::new(name).unwrap(),
        CapsuleId::from_static("demo"),
        SecretElicitKey::new("token").unwrap(),
    )
}

#[tokio::test]
async fn bound_device_delivers_to_original_waiter_and_late_reply_fails() {
    let registry = Arc::new(PendingSecretElicits::new(NonZeroUsize::new(1).unwrap()));
    let identity = owner("alice");
    let waiter = registry.register(identity.clone()).unwrap();
    let id = waiter.id().as_uuid();
    let responder = NativeSecretResponder::new(
        registry,
        identity.principal().clone(),
        "0123456789abcdef".into(),
        |_, _| true,
    )
    .unwrap();
    for (principal, device) in [
        (owner("bob"), "0123456789abcdef"),
        (identity.clone(), "other-device"),
    ] {
        assert_eq!(
            responder.reply(
                principal.principal(),
                device,
                id,
                Some("rejected".into()),
                None
            ),
            Err(PrivateElicitRejection::Forbidden)
        );
    }
    responder
        .reply(
            identity.principal(),
            "0123456789abcdef",
            id,
            Some("synthetic".into()),
            None,
        )
        .unwrap();
    let SecretElicitReply::Provided(value) = waiter.recv().await else {
        panic!("missing secret")
    };
    assert_eq!(value.expose_as_str(), "synthetic");
    assert_eq!(
        responder.reply(
            identity.principal(),
            "0123456789abcdef",
            id,
            Some("late".into()),
            None,
        ),
        Err(PrivateElicitRejection::Unavailable)
    );
}

#[tokio::test]
async fn authorized_device_cannot_answer_another_principals_request() {
    let registry = Arc::new(PendingSecretElicits::new(NonZeroUsize::new(1).unwrap()));
    let alice = owner("alice");
    let waiter = registry.register(alice.clone()).unwrap();
    let id = waiter.id().as_uuid();
    let bob = owner("bob");
    let responder = NativeSecretResponder::new(
        registry.clone(),
        bob.principal().clone(),
        "0123456789abcdef".into(),
        |_, _| true,
    )
    .unwrap();
    assert_eq!(
        responder.reply(bob.principal(), "0123456789abcdef", id, None, None),
        Err(PrivateElicitRejection::Forbidden)
    );
    registry.cancel(waiter.id(), &alice).unwrap();
    assert!(matches!(waiter.recv().await, SecretElicitReply::Cancelled));
}

#[tokio::test]
async fn empty_answer_does_not_consume_request_and_cancel_is_explicit() {
    let registry = Arc::new(PendingSecretElicits::new(NonZeroUsize::new(1).unwrap()));
    let identity = owner("alice");
    let waiter = registry.register(identity.clone()).unwrap();
    let id = waiter.id().as_uuid();
    let responder = NativeSecretResponder::new(
        registry,
        identity.principal().clone(),
        "0123456789abcdef".into(),
        |_, _| true,
    )
    .unwrap();
    assert_eq!(
        responder.reply(
            identity.principal(),
            "0123456789abcdef",
            id,
            Some(String::new()),
            None,
        ),
        Err(PrivateElicitRejection::Invalid)
    );
    responder
        .reply(identity.principal(), "0123456789abcdef", id, None, None)
        .unwrap();
    assert!(matches!(waiter.recv().await, SecretElicitReply::Cancelled));
}

fn bound_responder(
    registry: Arc<PendingSecretElicits>,
    identity: &SecretElicitIdentity,
) -> NativeSecretResponder {
    NativeSecretResponder::new(
        registry,
        identity.principal().clone(),
        "0123456789abcdef".into(),
        |_, _| true,
    )
    .unwrap()
}

#[tokio::test]
async fn empty_text_is_valid_and_distinct_from_cancel() {
    let registry = Arc::new(PendingSecretElicits::new(NonZeroUsize::new(1).unwrap()));
    let identity = owner("alice");
    let waiter = registry
        .register_kind(identity.clone(), ElicitAnswerKind::Text)
        .unwrap();
    let id = waiter.id().as_uuid();
    let responder = bound_responder(registry, &identity);
    responder
        .reply(
            identity.principal(),
            "0123456789abcdef",
            id,
            Some(String::new()),
            None,
        )
        .unwrap();
    assert!(matches!(waiter.recv().await, SecretElicitReply::Value(value) if value.is_empty()));
}

#[tokio::test]
async fn array_values_are_delivered_and_wrong_shape_does_not_consume() {
    let registry = Arc::new(PendingSecretElicits::new(NonZeroUsize::new(1).unwrap()));
    let identity = owner("alice");
    let waiter = registry
        .register_kind(identity.clone(), ElicitAnswerKind::Array)
        .unwrap();
    let id = waiter.id().as_uuid();
    let responder = bound_responder(registry, &identity);
    assert_eq!(
        responder.reply(
            identity.principal(),
            "0123456789abcdef",
            id,
            Some("not-a-list".into()),
            None,
        ),
        Err(PrivateElicitRejection::Invalid)
    );
    responder
        .reply(
            identity.principal(),
            "0123456789abcdef",
            id,
            None,
            Some(vec!["alpha".into(), "beta".into()]),
        )
        .unwrap();
    let SecretElicitReply::Values(values) = waiter.recv().await else {
        panic!("missing values")
    };
    assert_eq!(values, vec!["alpha".to_string(), "beta".to_string()]);
}

#[tokio::test]
async fn secret_slot_rejects_values_without_consuming() {
    let registry = Arc::new(PendingSecretElicits::new(NonZeroUsize::new(1).unwrap()));
    let identity = owner("alice");
    let waiter = registry.register(identity.clone()).unwrap();
    let id = waiter.id().as_uuid();
    let responder = bound_responder(registry, &identity);
    assert_eq!(
        responder.reply(
            identity.principal(),
            "0123456789abcdef",
            id,
            None,
            Some(vec!["synthetic".into()]),
        ),
        Err(PrivateElicitRejection::Invalid)
    );
    responder
        .reply(
            identity.principal(),
            "0123456789abcdef",
            id,
            Some("synthetic".into()),
            None,
        )
        .unwrap();
    let SecretElicitReply::Provided(value) = waiter.recv().await else {
        panic!("missing secret")
    };
    assert_eq!(value.expose_as_str(), "synthetic");
}

#[tokio::test]
async fn live_check_failure_does_not_consume_pending_secret() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let registry = Arc::new(PendingSecretElicits::new(NonZeroUsize::new(1).unwrap()));
    let identity = owner("alice");
    let waiter = registry.register(identity.clone()).unwrap();
    let id = waiter.id().as_uuid();
    let live = Arc::new(AtomicBool::new(false));
    let responder = NativeSecretResponder::new(
        registry,
        identity.principal().clone(),
        "0123456789abcdef".into(),
        {
            let live = Arc::clone(&live);
            move |_, _| live.load(Ordering::SeqCst)
        },
    )
    .unwrap();
    assert_eq!(
        responder.reply(
            identity.principal(),
            "0123456789abcdef",
            id,
            Some("synthetic".into()),
            None,
        ),
        Err(PrivateElicitRejection::Forbidden)
    );
    live.store(true, Ordering::SeqCst);
    responder
        .reply(
            identity.principal(),
            "0123456789abcdef",
            id,
            Some("synthetic".into()),
            None,
        )
        .unwrap();
    let SecretElicitReply::Provided(value) = waiter.recv().await else {
        panic!("missing secret")
    };
    assert_eq!(value.expose_as_str(), "synthetic");
}
