use super::*;

const ID: &str = "1234567890abcdef1234567890abcdef";

#[test]
fn correlations_and_subscription_aliases_are_canonical_and_self_scoped() {
    let publisher = Uuid::new_v4();
    for invalid in [
        "",
        "../other",
        "00000000000000000000000000000000",
        "12345678-90ab-cdef-1234-567890abcdef",
    ] {
        assert!(DeliveryId::parse(invalid).is_none());
    }
    assert_eq!(
        subscription_topic(&format!("{FAILURE_NAMESPACE}.{ID}"), publisher),
        Some(format!("{FAILURE_NAMESPACE}.{}.{ID}", publisher.simple()))
    );
    assert!(subscription_topic(FAILURE_NAMESPACE, publisher).is_none());
    assert!(
        subscription_topic(
            &format!("{FAILURE_NAMESPACE}.{}.{ID}", Uuid::new_v4().simple()),
            publisher
        )
        .is_none()
    );
}

#[cfg(feature = "clock")]
#[test]
fn guest_receipt_preserves_routing_but_not_arguments_or_native_reply_authority() {
    let publisher = Uuid::new_v4();
    let mut request = IpcMessage::new(
        Topic::from_raw("any.request"),
        IpcPayload::RawJson(serde_json::json!({"secret": "never copied"})),
        publisher,
    )
    .with_principal("alice")
    .with_request_owner(super::super::RequestOwnerId::generate());
    assert!(DeliveryFailureBinding::capture(&request).is_none());
    request.delivery_id = DeliveryId::parse(ID);
    let reply = DeliveryFailureBinding::capture(&request)
        .expect("opt-in guest request")
        .message("interceptor execution failed");
    assert!(visible_to(&reply, publisher));
    assert!(!visible_to(&reply, Uuid::new_v4()));
    assert_eq!(reply.principal, request.principal);
    assert_eq!(reply.request_owner, request.request_owner);
    assert!(
        !serde_json::to_string(&reply)
            .expect("serialize")
            .contains("never copied")
    );
    assert!(
        super::super::request_failure::RequestFailure::from_message(&reply, ID, "alice").is_none()
    );
    let mut forged = reply.clone();
    forged.source_id = publisher;
    assert!(!visible_to(&forged, publisher));
    request.source_id = Uuid::nil();
    assert!(DeliveryFailureBinding::capture(&request).is_none());
}

#[cfg(feature = "clock")]
#[test]
fn external_deserialization_cannot_mint_publication_metadata() {
    let mut request = IpcMessage::new(
        Topic::from_raw("any.request"),
        IpcPayload::RawJson(serde_json::json!({})),
        Uuid::new_v4(),
    )
    .with_principal("alice");
    request.delivery_id = DeliveryId::parse(ID);
    let mut value = serde_json::to_value(&request).expect("serialize");
    value["delivery_id"] = serde_json::json!(ID);
    let decoded: IpcMessage = serde_json::from_value(value).expect("deserialize");
    assert!(decoded.delivery_id.is_none());
}
