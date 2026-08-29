//! Closure identity and independent-floor assertions.

use serde_json::Value;

use super::{ExpectedClosures, SUCCESS_BOUND_EVENTS, check, count_named, ev_name};

pub(super) fn closure_holds(events: &[Value], closures: &ExpectedClosures<'_>) -> bool {
    let mut ok = true;
    ok &= check(
        "one event for each success-bound milestone",
        SUCCESS_BOUND_EVENTS
            .iter()
            .all(|name| count_named(events, name) == 1),
    );
    ok &= check(
        "no closure.reject",
        count_named(events, "closure.reject") == 0,
    );
    let kernel_ev = events.iter().find(|e| ev_name(e) == "closure.kernel");
    let sysgen_ev = events.iter().find(|e| ev_name(e) == "closure.sysgen");
    let bound_ev = events.iter().find(|e| ev_name(e) == "closure.bound");
    let handoff_ev = events.iter().find(|e| ev_name(e) == "handoff.bound");
    ok &= check(
        "handoff.bound generation and measurements match loader",
        handoff_ev.is_some_and(|e| {
            e.get("policy_generation").and_then(Value::as_u64) == Some(closures.policy_generation)
                && e.get("kernel_image").and_then(Value::as_str) == Some(closures.kernel_image_hex)
                && e.get("closure_table").and_then(Value::as_str)
                    == Some(closures.closure_table_hex)
        }),
    );
    ok &= check(
        "closure.kernel kind, floor, and id match loader",
        kernel_ev.is_some_and(|e| {
            e.get("kind").and_then(Value::as_str) == Some("kernel-bootstrap")
                && e.get("floor").and_then(Value::as_u64) == Some(closures.kernel_floor)
                && e.get("id").and_then(Value::as_str) == Some(closures.kernel_id_hex)
        }),
    );
    ok &= check(
        "closure.sysgen non-empty descriptor, floor, and id match loader",
        sysgen_ev.is_some_and(|e| {
            e.get("kind").and_then(Value::as_str) == Some("system-generation")
                && e.get("empty") == Some(&Value::Bool(false))
                && e.get("floor").and_then(Value::as_u64) == Some(closures.sysgen_floor)
                && e.get("id").and_then(Value::as_str) == Some(closures.sysgen_id_hex)
        }),
    );
    ok &= check(
        "closure.bound keeps independent floors and distinct identities",
        bound_ev.is_some_and(|e| {
            e.get("kernel_floor").and_then(Value::as_u64) == Some(closures.kernel_floor)
                && e.get("sysgen_floor").and_then(Value::as_u64) == Some(closures.sysgen_floor)
                && e.get("kernel_id").and_then(Value::as_str) == Some(closures.kernel_id_hex)
                && e.get("sysgen_id").and_then(Value::as_str) == Some(closures.sysgen_id_hex)
                && closures.kernel_id_hex != closures.sysgen_id_hex
                && e.get("floor").is_none()
        }),
    );
    ok
}
