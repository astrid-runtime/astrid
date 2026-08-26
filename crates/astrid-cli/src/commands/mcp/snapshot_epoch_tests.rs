//! Focused consumer-side tests for the private MCP snapshot contract.

use std::collections::BTreeSet;

use serde_json::json;

use super::server::snapshot_tool_names;

fn snapshot(epoch: u64, names: &[&str]) -> serde_json::Value {
    json!({
        "epoch": epoch,
        "tools": names.iter().map(|name| json!({
            "name": name,
            "description": "",
            "inputSchema": {},
        })).collect::<Vec<_>>(),
    })
}

#[test]
fn empty_snapshot_is_valid_only_with_a_positive_epoch() {
    let (epoch, names) = snapshot_tool_names(&snapshot(1, &[])).expect("valid empty snapshot");
    assert_eq!(epoch, 1);
    assert!(names.is_empty());
    assert!(snapshot_tool_names(&json!({ "epoch": 0, "tools": [] })).is_err());
    assert!(snapshot_tool_names(&json!({ "tools": [] })).is_err());
}

#[test]
fn malformed_snapshot_is_resnapshot_trigger() {
    for value in [
        json!({}),
        json!({ "epoch": 2, "tools": null }),
        json!({ "epoch": 2, "tools": [{ "description": "missing name", "inputSchema": {} }] }),
        json!({ "epoch": 2, "tools": [{ "name": "bad-schema", "inputSchema": [] }] }),
    ] {
        assert!(snapshot_tool_names(&value).is_err());
    }
}

#[test]
fn disjoint_principal_snapshots_remain_disjoint() {
    let (_, alice) = snapshot_tool_names(&snapshot(3, &["alpha", "alice_only"])).expect("alice");
    let (_, bob) = snapshot_tool_names(&snapshot(2, &["beta"])).expect("bob");
    assert_eq!(alice, BTreeSet::from(["alpha".into(), "alice_only".into()]));
    assert_eq!(bob, BTreeSet::from(["beta".into()]));
    assert!(alice.is_disjoint(&bob));
}
