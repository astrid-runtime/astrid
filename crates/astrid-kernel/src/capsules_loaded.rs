//! Helpers for the `astrid.v1.capsules_loaded` broadcast payload.
//!
//! The kernel surfaces, per loaded capsule, its installed `meta.json` plus its
//! tool surface. A surface baked into `meta.json` at build time is forwarded
//! verbatim; one that was not baked is filled in by the kernel probing the live
//! capsule's `tool_describe` and injecting the result ([`inject_tools`]), so an
//! un-rebuilt (or third-party) capsule still contributes a complete surface.
//! Either way the kernel invokes-and-forwards — it does not interpret the
//! descriptors, the way a Linux uevent carries a device's attributes and leaves
//! all interpretation to userspace. A sandboxed consumer (e.g. the sage-mcp
//! broker) derives a deterministic tool surface from this signal, instead of a
//! racy describe fan-out, without itself gaining filesystem access.
//!
//! These helpers are the pure payload-assembly pieces ([`read_capsule_meta_opaque`],
//! [`meta_has_tools`], [`inject_tools`], [`build_capsules_loaded_payload`]), kept
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
/// `(name, opaque meta)` pairs.
///
/// Retains the legacy `status: "ready"` field so subscribers that treat the
/// event as a bare signal (the `astrid mcp serve` shim, the TUI) keep working;
/// `capsules` is additive. Each `meta` value is forwarded verbatim.
pub(crate) fn build_capsules_loaded_payload(entries: Vec<(String, Option<Value>)>) -> Value {
    let capsules: Vec<Value> = entries
        .into_iter()
        .map(|(name, meta)| json!({ "name": name, "meta": meta }))
        .collect();
    json!({ "status": "ready", "capsules": capsules })
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
    fn payload_retains_status_and_lists_capsules() {
        let meta = json!({ "version": "1.0.0", "tools": [{ "name": "read_file" }] });
        let payload = build_capsules_loaded_payload(vec![
            ("astrid-capsule-fs".to_string(), Some(meta.clone())),
            ("no-meta".to_string(), None),
        ]);
        // Legacy bare-signal field is preserved for existing subscribers.
        assert_eq!(payload["status"], "ready");
        let caps = payload["capsules"].as_array().expect("capsules array");
        assert_eq!(caps.len(), 2);
        assert_eq!(caps[0]["name"], "astrid-capsule-fs");
        // Meta is forwarded verbatim (the consumer extracts `tools`).
        assert_eq!(caps[0]["meta"], meta);
        // A capsule with no readable meta carries an explicit null.
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
