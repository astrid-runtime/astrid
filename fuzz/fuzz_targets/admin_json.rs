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
    let reparsed: T = serde_json::from_value(encoded).expect("serialized wire type must reparse");
    check(&reparsed);
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
    let Some(method) = value
        .as_object()
        .and_then(|obj| obj.get("method"))
        .and_then(Value::as_str)
    else {
        return;
    };

    if !KNOWN_ADMIN_METHODS.contains(&method) {
        assert!(
            serde_json::from_value::<AdminKernelRequest>(value.clone()).is_err(),
            "unknown admin method {method:?} must not deserialize as an allowed request"
        );
    }
}

const KNOWN_ADMIN_METHODS: &[&str] = &[
    "AgentCreate",
    "AgentDelete",
    "AgentDisable",
    "AgentEnable",
    "AgentList",
    "AgentModify",
    "CapsGrant",
    "CapsRevoke",
    "CapsTokenList",
    "CapsTokenMint",
    "CapsTokenRevoke",
    "GroupCreate",
    "GroupDelete",
    "GroupList",
    "GroupModify",
    "InviteIssue",
    "InviteList",
    "InviteRedeem",
    "InviteRevoke",
    "PairDeviceIssue",
    "PairDeviceList",
    "PairDeviceRedeem",
    "PairDeviceRevoke",
    "QuotaGet",
    "QuotaSet",
    "UsageGet",
];
