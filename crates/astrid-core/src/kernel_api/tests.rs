//! Tests for `kernel_api/mod.rs`. Split into a sibling file to keep `mod.rs`
//! under the 1000-line CI threshold. Included as a `tests` submodule of
//! `kernel_api`.

use super::{CommandInfo, CommandKind, KernelResponse};

#[test]
fn kernel_response_working_serializes_as_status_working() {
    // The keepalive variant is a unit variant on a `tag = "status",
    // content = "data"` enum with no `rename_all`, so it serializes as the
    // bare `{"status":"Working"}` shape (PascalCase, like `Success` /
    // `Error`) the uplink recognises — no `data` key on a unit variant.
    let json = serde_json::to_value(KernelResponse::Working).unwrap();
    assert_eq!(json, serde_json::json!({ "status": "Working" }));
    assert!(
        json.get("data").is_none(),
        "a unit keepalive variant carries no data payload"
    );
    // And round-trips back to the same variant so an uplink can match on it.
    let back: KernelResponse = serde_json::from_value(json).unwrap();
    assert!(matches!(back, KernelResponse::Working));
}

#[test]
fn command_info_kind_defaults_to_slash_on_wire() {
    // A frame from a daemon that predates the `kind` field has no
    // `kind` key; it must deserialize to the Slash default so an older
    // daemon's commands keep listing as slash commands.
    let json = serde_json::json!({
        "name": "git",
        "description": "git ops",
        "provider_capsule": "git-capsule",
    });
    let info: CommandInfo = serde_json::from_value(json).unwrap();
    assert_eq!(info.kind, CommandKind::Slash);
}

#[test]
fn command_info_kind_roundtrips_cli() {
    let info = CommandInfo {
        name: "deploy".into(),
        description: "deploy it".into(),
        provider_capsule: "ops".into(),
        kind: CommandKind::Cli,
    };
    let json = serde_json::to_value(&info).unwrap();
    // `cli` is not the default, so it is serialized.
    assert_eq!(json.get("kind").and_then(|k| k.as_str()), Some("cli"));
    let back: CommandInfo = serde_json::from_value(json).unwrap();
    assert_eq!(back.kind, CommandKind::Cli);
}

#[test]
fn command_info_default_kind_omitted_from_wire() {
    let info = CommandInfo {
        name: "git".into(),
        description: "git ops".into(),
        provider_capsule: "git-capsule".into(),
        kind: CommandKind::Slash,
    };
    let json = serde_json::to_value(&info).unwrap();
    // Default kind is skipped so the wire shape is byte-compatible with
    // pre-field consumers.
    assert!(json.get("kind").is_none());
}
