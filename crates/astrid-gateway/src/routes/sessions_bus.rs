use super::{
    AstridEvent, CAPSULE_ID_NAMESPACE, Duration, EventBus, EventMetadata, GatewayError,
    GatewayResult, IpcMessage, IpcPayload, MessageOrigin, PrincipalId, SESSION_CAPSULE_ID, Topic,
    Uuid, Value,
};

pub(super) fn session_capsule_source_id() -> Uuid {
    Uuid::new_v5(&CAPSULE_ID_NAMESPACE, SESSION_CAPSULE_ID.as_bytes())
}

/// Reusable capsule request/reply-over-bus primitive.
///
/// Subscribes to `response_topic` FIRST (a per-correlation scoped topic,
/// so no request-id filtering at the subscription layer is needed),
/// publishes the principal-stamped request on `request_topic`, and
/// awaits exactly one reply from the session capsule. It defensively verifies
/// the kernel-stamped `source_id` and body `correlation_id` before returning.
///
/// `device_key_id` is stamped when present, exactly as `bus_admin.rs`
/// does, so a device-scoped bearer carries its attenuation floor to the
/// kernel cap-gate on the way to the capsule.
#[allow(clippy::too_many_arguments)]
pub(super) async fn request_capsule(
    bus: &EventBus,
    request_topic: &str,
    response_topic: &str,
    payload: Value,
    correlation_id: &str,
    principal: &PrincipalId,
    device_key_id: Option<&str>,
    expected_source_ids: &[Uuid],
    timeout: Duration,
) -> GatewayResult<Value> {
    // Subscribe before publish so a fast capsule cannot race the waiter.
    let principal = principal.to_string();
    let mut receiver = bus.subscribe_topic_routed_scoped(
        Uuid::new_v4(),
        response_topic,
        "gateway",
        "gateway::sessions",
        Some(Some(principal.clone())),
    );

    let mut msg = IpcMessage::new(
        Topic::from_raw(request_topic),
        IpcPayload::RawJson(payload),
        Uuid::new_v4(),
    )
    .with_principal(principal.clone())
    .with_origin(MessageOrigin::RemoteGateway);
    if let Some(key_id) = device_key_id {
        msg = msg.with_device_key_id(key_id.to_string());
    }
    bus.publish(AstridEvent::Ipc {
        metadata: EventMetadata::new("astrid-gateway::sessions"),
        message: msg,
    });

    let deadline = tokio::time::Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(tokio::time::Instant::now);
    let expected_source_ids = if expected_source_ids.is_empty() {
        vec![session_capsule_source_id()]
    } else {
        expected_source_ids.to_vec()
    };

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(capsule_timeout(response_topic, timeout));
        }
        let event = receiver
            .recv(Some(remaining))
            .await
            .ok_or_else(|| capsule_timeout(response_topic, timeout))?;

        let AstridEvent::Ipc { message, .. } = &*event else {
            continue;
        };
        if !expected_source_ids.contains(&message.source_id) {
            continue;
        }
        let Ok(value) = session_reply_payload_json(&message.payload) else {
            continue;
        };
        if value.get("correlation_id").and_then(Value::as_str) == Some(correlation_id) {
            return Ok(value);
        }
    }
}

fn session_reply_payload_json(payload: &IpcPayload) -> GatewayResult<Value> {
    let bytes = payload
        .to_guest_bytes()
        .map_err(|e| GatewayError::Kernel(format!("session capsule returned invalid JSON: {e}")))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| GatewayError::Kernel(format!("session capsule returned invalid JSON: {e}")))
}

fn capsule_timeout(response_topic: &str, timeout: Duration) -> GatewayError {
    GatewayError::Kernel(format!(
        "session capsule did not reply within {}s on {response_topic}",
        timeout.as_secs()
    ))
}
