//! Helpers for the `astrid.v1.capsules_loaded` broadcast payload.
//!
//! The kernel surfaces, per loaded capsule, its installed `meta.json` plus its
//! live tool surface. The reserved `tools` field is removed from installed
//! metadata before the kernel probes the capsule's `tool_describe`; a successful
//! probe injects the current result ([`inject_tools`]), while an unavailable or
//! failed probe leaves the field absent so consumers can fall back to describe
//! fan-out. This also prevents tool surfaces baked by older Astrid releases from
//! suppressing that fallback. The kernel invokes-and-forwards — it does not
//! interpret the descriptors, the way a Linux uevent carries a device's
//! attributes and leaves all interpretation to userspace. A sandboxed consumer
//! (e.g. the sage-mcp broker) derives a deterministic tool surface from this
//! signal without itself gaining filesystem access.
//!
//! These helpers are the pure payload-assembly pieces ([`read_capsule_meta_opaque`],
//! [`without_tools`], [`inject_tools`], [`build_capsules_loaded_payload`]), kept
//! off [`crate::Kernel`] so they are unit-testable without a running kernel; the
//! live `tool_describe` probe itself lives in `Kernel::publish_capsules_loaded`.

use std::path::Path;

use serde_json::{Value, json};

/// Read a capsule's installed `meta.json` as an opaque JSON value.
///
/// Returns `None` if the file is absent, unreadable, or not valid JSON — a
/// degraded capsule contributes a `null` `meta` and never blocks the signal.
/// The kernel does not deserialize into a typed shape on purpose: it forwards
/// the metadata verbatim and attaches no meaning to it.
pub(crate) fn read_capsule_meta_opaque(source_dir: &Path) -> Option<Value> {
    let bytes = std::fs::read(source_dir.join("meta.json")).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Remove the reserved live `tools` field from opaque installed metadata.
///
/// Older Astrid releases persisted build-time tool descriptors in `meta.json`.
/// They must not be treated as current: a run-loop capsule needs an absent field
/// to trigger consumer describe fan-out, and a failed live probe must not expose
/// stale descriptors. Other metadata, including non-object values, remains
/// untouched.
pub(crate) fn without_tools(meta: Option<Value>) -> Option<Value> {
    meta.map(|value| match value {
        Value::Object(mut map) => {
            map.remove("tools");
            Value::Object(map)
        },
        other => other,
    })
}

/// Inject a freshly-described `tools` array into a capsule's opaque `meta`.
///
/// `meta` is the capsule's `meta.json` value (or `None` if it had none); the
/// result is the same object with its `tools` key set to `tools` (a JSON array
/// of descriptors). A `None` or non-object `meta` becomes a fresh
/// `{ "tools": [...] }` object so the consumer sees the surface either way. The
/// kernel does not interpret the descriptors — it forwards what the capsule
/// reported.
pub(crate) fn inject_tools(meta: Option<Value>, tools: Value) -> Value {
    let mut obj = match meta {
        Some(Value::Object(map)) => map,
        _ => serde_json::Map::new(),
    };
    obj.insert("tools".to_string(), tools);
    Value::Object(obj)
}

/// Build the `astrid.v1.capsules_loaded` payload from per-capsule
/// `(principal, name, opaque meta)` tuples.
///
/// Retains the legacy `status: "ready"` field so subscribers that treat the
/// event as a bare signal (the `astrid mcp serve` shim, the TUI) keep working;
/// `capsules` is additive. Each `meta` value is forwarded verbatim. The
/// per-entry `principal` field lets newer clients verify the payload belongs
/// to their principal view while preserving the old `name`/`meta` shape for
/// compatibility.
pub(crate) fn build_capsules_loaded_payload(
    entries: Vec<(String, String, Option<Value>)>,
) -> Value {
    build_capsules_loaded_payload_with_optional_epoch(entries, None)
}

/// Build a principal-scoped inventory hint carrying a successfully allocated
/// MCP namespace epoch.  The epoch is omitted when snapshot production failed;
/// consumers must treat that hint as malformed and perform a full resnapshot.
pub(crate) fn build_capsules_loaded_payload_with_epoch(
    entries: Vec<(String, String, Option<Value>)>,
    epoch: u64,
) -> Value {
    build_capsules_loaded_payload_with_optional_epoch(entries, Some(epoch))
}

fn build_capsules_loaded_payload_with_optional_epoch(
    entries: Vec<(String, String, Option<Value>)>,
    epoch: Option<u64>,
) -> Value {
    let capsules: Vec<Value> = entries
        .into_iter()
        .map(
            |(principal, name, meta)| json!({ "principal": principal, "name": name, "meta": meta }),
        )
        .collect();
    match epoch {
        Some(epoch) => json!({ "status": "ready", "epoch": epoch, "capsules": capsules }),
        None => json!({ "status": "ready", "capsules": capsules }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inject_tools_sets_tools_preserving_other_meta() {
        let meta = json!({ "version": "1.0.0", "wasm_hash": "abc" });
        let tools = json!([{ "name": "read_file", "description": "", "input_schema": {} }]);
        let out = inject_tools(Some(meta), tools.clone());
        assert_eq!(out["tools"], tools);
        assert_eq!(out["version"], "1.0.0");
        assert_eq!(out["wasm_hash"], "abc");
    }

    #[test]
    fn inject_tools_builds_object_when_meta_absent_or_nonobject() {
        let tools = json!([{ "name": "t" }]);
        // None meta -> fresh object.
        let out = inject_tools(None, tools.clone());
        assert_eq!(out["tools"], tools);
        // Non-object meta -> fresh object (don't lose the tools).
        let out2 = inject_tools(Some(json!("oops")), tools.clone());
        assert_eq!(out2["tools"], tools);
    }

    #[test]
    fn without_tools_removes_legacy_surface_and_preserves_other_meta() {
        let meta = json!({
            "version": "1.0.0",
            "tools": [{ "name": "stale_tool" }],
            "wasm_hash": "abc"
        });

        let out = without_tools(Some(meta)).expect("object metadata");

        assert!(out.get("tools").is_none());
        assert_eq!(out["version"], "1.0.0");
        assert_eq!(out["wasm_hash"], "abc");
    }

    #[test]
    fn without_tools_preserves_absent_and_nonobject_meta() {
        assert_eq!(without_tools(None), None);
        assert_eq!(without_tools(Some(json!("opaque"))), Some(json!("opaque")));
    }

    #[test]
    fn payload_retains_status_and_lists_capsules() {
        let meta = json!({ "version": "1.0.0", "tools": [{ "name": "read_file" }] });
        let payload = build_capsules_loaded_payload(vec![
            (
                "alice".to_string(),
                "astrid-capsule-fs".to_string(),
                Some(meta.clone()),
            ),
            ("bob".to_string(), "no-meta".to_string(), None),
        ]);
        // Legacy bare-signal field is preserved for existing subscribers.
        assert_eq!(payload["status"], "ready");
        let caps = payload["capsules"].as_array().expect("capsules array");
        assert_eq!(caps.len(), 2);
        assert_eq!(caps[0]["principal"], "alice");
        assert_eq!(caps[0]["name"], "astrid-capsule-fs");
        // Meta is forwarded verbatim (the consumer extracts `tools`).
        assert_eq!(caps[0]["meta"], meta);
        // A capsule with no readable meta carries an explicit null.
        assert_eq!(caps[1]["principal"], "bob");
        assert_eq!(caps[1]["name"], "no-meta");
        assert!(caps[1]["meta"].is_null());
    }

    #[test]
    fn empty_entries_still_well_formed() {
        let payload = build_capsules_loaded_payload(vec![]);
        assert_eq!(payload["status"], "ready");
        assert!(payload["capsules"].as_array().expect("array").is_empty());
    }

    #[test]
    fn read_meta_missing_is_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(read_capsule_meta_opaque(dir.path()).is_none());
    }

    #[test]
    fn read_meta_malformed_is_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("meta.json"), b"{not valid json").expect("write");
        assert!(read_capsule_meta_opaque(dir.path()).is_none());
    }

    #[test]
    fn read_meta_valid_round_trips_opaque() {
        let dir = tempfile::tempdir().expect("tempdir");
        let meta = json!({ "version": "2.0.0", "tools": [], "wasm_hash": "abc" });
        std::fs::write(
            dir.path().join("meta.json"),
            serde_json::to_vec(&meta).expect("serialize"),
        )
        .expect("write");
        assert_eq!(read_capsule_meta_opaque(dir.path()), Some(meta));
    }
}
