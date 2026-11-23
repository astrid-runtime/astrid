#![no_main]

use astrid_core::kernel_api::{
    AdminKernelRequest, AdminKernelResponse, KernelRequest, KernelResponse,
};
use libfuzzer_sys::fuzz_target;
use serde_json::Value;

fuzz_target!(|data: &[u8]| {
    let Ok(value) = serde_json::from_slice::<Value>(data) else {
        return;
    };

    assert_unknown_admin_methods_fail_closed(&value);

    try_roundtrip::<AdminKernelRequest>(&value, assert_admin_request_invariants);
    try_roundtrip::<AdminKernelResponse>(&value, assert_admin_response_invariants);
    try_roundtrip::<KernelRequest>(&value, |_| {});
    try_roundtrip::<KernelResponse>(&value, |_| {});
});

fn try_roundtrip<T>(value: &Value, check: impl Fn(&T))
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    let Ok(parsed) = serde_json::from_value::<T>(value.clone()) else {
        return;
    };
    check(&parsed);

    let encoded = serde_json::to_value(&parsed).expect("parsed wire type must serialize");
    let reparsed: T =
        serde_json::from_value(encoded.clone()).expect("serialized wire type must reparse");
    check(&reparsed);
    assert_eq!(
        encoded,
        serde_json::to_value(&reparsed).expect("reparsed wire type must serialize"),
        "canonical wire serialization must be stable across reparsing"
    );
}

fn assert_admin_request_invariants(req: &AdminKernelRequest) {
    let encoded = serde_json::to_value(req).expect("admin request must serialize");
    assert!(
        encoded.get("method").and_then(Value::as_str).is_some(),
        "serialized admin requests must carry an explicit method tag"
    );

    if let Some(request_id) = &req.request_id {
        assert_eq!(
            encoded.get("request_id").and_then(Value::as_str),
            Some(request_id.as_str())
        );
    }
}

fn assert_admin_response_invariants(resp: &AdminKernelResponse) {
    let encoded = serde_json::to_value(resp).expect("admin response must serialize");
    assert!(
        encoded.get("status").and_then(Value::as_str).is_some(),
        "serialized admin responses must carry an explicit status tag"
    );

    if let Some(request_id) = &resp.request_id {
        assert_eq!(
            encoded.get("request_id").and_then(Value::as_str),
            Some(request_id.as_str())
        );
    }
}

fn assert_unknown_admin_methods_fail_closed(value: &Value) {
    let Some(mut object) = value.as_object().cloned() else {
        return;
    };
    // Inject a deliberately unknown tag rather than duplicating the production
    // variant list: new legitimate methods must not become fuzz false positives.
    object.insert(
        "method".into(),
        Value::String("\0astrid_fuzz_unknown".into()),
    );
    assert!(
        serde_json::from_value::<AdminKernelRequest>(Value::Object(object)).is_err(),
        "unknown admin methods must fail closed"
    );
}
