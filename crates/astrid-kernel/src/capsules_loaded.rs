//! Helpers for the `astrid.v1.capsules_loaded` broadcast payload.
//!
//! The kernel surfaces, per loaded capsule, its installed `meta.json` as an
//! **opaque** JSON value — it never parses or interprets that metadata (no tool
//! awareness), the way a Linux uevent carries a device's attributes and leaves
//! all interpretation to userspace. A sandboxed consumer (e.g. the sage-mcp
//! broker) derives a deterministic tool surface from this signal it already
//! receives, instead of a racy describe fan-out — without the kernel gaining
//! any tool knowledge and without widening the consumer's own capabilities.
//!
//! Kept off [`crate::Kernel`] so the pure payload assembly is unit-testable
//! without standing up a running kernel.

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
