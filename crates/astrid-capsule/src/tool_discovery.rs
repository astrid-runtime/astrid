//! Build-time tool-descriptor capture.
//!
//! [`describe_capsule_tools`] instantiates a built capsule component
//! exactly as the kernel would at load time, drives its
//! `tool_describe` interceptor, and returns the static tool surface
//! the `#[astrid::tool]` macro generated. The CLI build command runs
//! this against a freshly-compiled component so the descriptors can be
//! baked into the installed `meta.json` — a static, offline-inspectable
//! artifact instead of a runtime describe fan-out.
//!
//! The capture path is deliberately daemon-free: an in-memory KV store,
//! a fresh [`EventBus`], and a no-op secure MCP client. No socket, no
//! identity store, no profile cache. A pure-WASM tool capsule never
//! touches the MCP client (that is only wired for `[[mcp_servers]]`
//! stdio breakouts), so the no-op client is never exercised.

use std::path::Path;
use std::sync::Arc;

use astrid_audit::AuditLog;
use astrid_capabilities::CapabilityStore;
use astrid_core::PrincipalId;
use astrid_core::types::SessionId;
use astrid_crypto::KeyPair;
use astrid_events::EventBus;
use astrid_mcp::{McpClient, SecureMcpClient, ServerManager, ServersConfig};
use astrid_storage::{KvStore, MemoryKvStore, ScopedKvStore};
use serde::{Deserialize, Serialize};

use crate::capsule::InterceptResult;
use crate::context::CapsuleContext;
use crate::discovery::load_manifest;
use crate::loader::CapsuleLoader;

/// A single tool's static descriptor, as emitted by the
/// `#[astrid::tool]`-generated `tool_describe` interceptor.
///
/// Field shape matches the JSON the macro builds
/// (`{ name, description, input_schema }`) and what the MCP bridge /
/// prompt-builder consume, so a captured descriptor round-trips
/// without translation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolDescriptor {
    /// Tool name (the `#[astrid::tool("name")]` argument).
    pub name: String,
    /// Human-readable description (the tool method's doc comment).
    pub description: String,
    /// JSON Schema for the tool's input arguments.
    #[serde(rename = "input_schema")]
    pub input_schema: serde_json::Value,
}

/// Capture the static tool descriptors a capsule exports.
///
/// `dir` must contain `Capsule.toml` and the built component WASM at the
/// manifest's `[[component]] file` path (i.e. the same co-located layout
/// `astrid capsule install` stages from an unpacked `.capsule` archive).
/// This loads the manifest, instantiates the component through the same
/// loader the kernel uses, runs its `tool_describe` interceptor, and
/// parses the resulting `tools` array.
///
/// A capsule that declares no tools has no `tool_describe` interceptor;
/// the WASM engine returns `NotSupported`, which is treated as "no
/// tools" — `Ok(vec![])`, never an error (mirroring how a missing
/// `handle_lifecycle_restart` interceptor is optional on restart).
///
/// The WASM engine fail-closes unless a `meta.json` records the
/// component's BLAKE3 hash (it refuses to load an unverified binary).
/// At build time there is no installed `meta.json` yet, so this stages a
/// transient one carrying the freshly-computed hash of the very bytes
/// being loaded — the integrity check is satisfied honestly (the wasm
/// matches what its meta claims), not bypassed. The transient file is
/// removed before returning unless `dir` already had a `meta.json`.
///
/// # Errors
///
/// Returns an error if the manifest cannot be loaded, the component file
/// is missing or unreadable, the component cannot be created or loaded,
/// the interceptor denies, or the descriptor payload is present but not
/// the expected JSON shape.
pub async fn describe_capsule_tools(dir: &Path) -> anyhow::Result<Vec<ToolDescriptor>> {
    let manifest_path = dir.join("Capsule.toml");
    let manifest = load_manifest(&manifest_path)
        .map_err(|e| anyhow::anyhow!("failed to load manifest: {e}"))?;

    // Stage the integrity `meta.json` the WASM engine requires. RAII so
    // it is removed on every exit path (including errors) when we created
    // it. A capsule with no WASM component (e.g. a pure MCP/static
    // capsule) has no tool_describe to capture — return empty early.
    let _meta_guard = match manifest.components.first() {
        Some(component) => Some(stage_integrity_meta(dir, &component.path)?),
        None => return Ok(Vec::new()),
    };

    // Build the capsule via the same loader path the kernel uses
    // (`Kernel::load_capsule`). The MCP client is a no-op wired to
    // in-memory stores — a pure-WASM tool capsule never touches it.
    let loader = CapsuleLoader::new(
        no_op_mcp_client(),
        crate::FuelLedger::default(),
        crate::FuelRateLimiter::default(),
        crate::MemoryLedger::default(),
        crate::CapsuleRuntimeLimits::default(),
    );
    let mut capsule = loader
        .create_capsule(manifest, dir.to_path_buf())
        .map_err(|e| anyhow::anyhow!("failed to create capsule: {e}"))?;

    // Minimal, daemon-free context: in-memory KV scoped to this
    // capsule, a fresh bus, no socket / identity / profile wiring.
    let principal = PrincipalId::default();
    let kv_store: Arc<dyn KvStore> = Arc::new(MemoryKvStore::new());
    let kv = ScopedKvStore::new(kv_store, format!("{principal}:capsule:{}", capsule.id()))
        .map_err(|e| anyhow::anyhow!("failed to scope KV store: {e}"))?;
    let event_bus = Arc::new(EventBus::new());
    let ctx = CapsuleContext::new(principal, dir.to_path_buf(), None, kv, event_bus, None);

    capsule
        .load(&ctx)
        .await
        .map_err(|e| anyhow::anyhow!("failed to load capsule: {e}"))?;

    // Primary capture: the `tool_describe` interceptor returns the
    // descriptor JSON in its `CapsuleResult { action: "continue",
    // data: Some(...) }`, which the engine surfaces as
    // `InterceptResult::Continue(bytes)`.
    //
    // A capsule with no `#[astrid::tool]` has no `tool_describe` arm, and the
    // engine signals that two different ways depending on whether the capsule
    // has *any* interceptors: a capsule with none yields a `NotSupported`
    // error, while a capsule with other interceptors (e.g. the sage-mcp broker)
    // has its generated dispatch *deny* the unknown action with "unknown hook
    // action: tool_describe". Both mean "no tools", not a failure — otherwise a
    // pure-interceptor capsule (which includes the broker itself) would be left
    // unmarked and a consumer could never trust the static surface.
    let result = match capsule.invoke_interceptor("tool_describe", &[], None).await {
        Ok(r) => r,
        Err(e) if is_unsupported(&e) => return Ok(Vec::new()),
        Err(e) => return Err(anyhow::anyhow!("tool_describe interceptor failed: {e}")),
    };

    let payload = match result {
        InterceptResult::Continue(bytes) | InterceptResult::Final(bytes) => bytes,
        // No `tool_describe` arm => "no tools", treated like NotSupported above.
        InterceptResult::Deny { reason } if is_unknown_action(&reason) => {
            return Ok(Vec::new());
        },
        // Any other deny is a genuine refusal — surface it.
        InterceptResult::Deny { reason } => {
            anyhow::bail!("tool_describe interceptor denied: {reason}");
        },
    };

    if payload.is_empty() {
        return Ok(Vec::new());
    }

    parse_tool_descriptors(&payload)
}

/// Parse the `tools` array out of a `tool_describe` descriptor payload
/// (`{ "tools": [ {name, description, input_schema}, ... ], "description": "..." }`).
///
/// Deserializes straight into a typed wrapper rather than walking a generic
/// `serde_json::Value` — no intermediate allocation or clone. A missing
/// `tools` key defaults to empty (a non-tool payload), while a present-but-
/// malformed `tools` array is a hard error.
fn parse_tool_descriptors(payload: &[u8]) -> anyhow::Result<Vec<ToolDescriptor>> {
    #[derive(Deserialize)]
    struct ToolDescribePayload {
        #[serde(default)]
        tools: Vec<ToolDescriptor>,
    }
    let parsed: ToolDescribePayload = serde_json::from_slice(payload).map_err(|e| {
        anyhow::anyhow!("tool_describe payload is not valid JSON or has an unexpected shape: {e}")
    })?;
    Ok(parsed.tools)
}

/// Whether a capsule error signals "this interceptor action is not
/// implemented" (a capsule with no tools), as opposed to a real
/// failure. The WASM engine returns `NotSupported` for an unknown
/// action and the trait default does the same.
fn is_unsupported(err: &crate::error::CapsuleError) -> bool {
    matches!(err, crate::error::CapsuleError::NotSupported(_))
}

/// Whether a `tool_describe` deny reason means the capsule simply has no
/// `tool_describe` arm (a capsule with other interceptors but no
/// `#[astrid::tool]`), as opposed to a genuine refusal. The SDK's generated
/// interceptor dispatch denies an unhandled action with the exact reason
/// "unknown hook action: <action>" — match it precisely (this is only ever
/// called for the `tool_describe` action) rather than by substring, so a
/// genuine deny whose message happens to contain the phrase is never silently
/// swallowed as "no tools".
fn is_unknown_action(reason: &str) -> bool {
    reason == "unknown hook action: tool_describe"
}

/// RAII handle for a transient build-time `meta.json` staged so the WASM
/// engine's integrity check passes. Removes the file on drop only when we
/// created it (an already-present, real `meta.json` is left untouched).
struct StagedMeta {
    path: std::path::PathBuf,
    created: bool,
}

impl Drop for StagedMeta {
    fn drop(&mut self) {
        if self.created {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Stage a `meta.json` recording the BLAKE3 hash of the component WASM at
/// `<dir>/<component_path>`, so the WASM engine's fail-secure integrity
/// check (no hash ⇒ refuse to load) is satisfied with the hash of the
/// exact bytes being loaded. If a `meta.json` already exists it is left
/// as-is (an installed capsule already carries the real one).
fn stage_integrity_meta(dir: &Path, component_path: &Path) -> anyhow::Result<StagedMeta> {
    let meta_path = dir.join("meta.json");
    if meta_path.exists() {
        return Ok(StagedMeta {
            path: meta_path,
            created: false,
        });
    }

    let wasm_path = if component_path.is_absolute() {
        component_path.to_path_buf()
    } else {
        dir.join(component_path)
    };
    let wasm_bytes = std::fs::read(&wasm_path).map_err(|e| {
        anyhow::anyhow!(
            "failed to read component WASM at {}: {e}",
            wasm_path.display()
        )
    })?;
    let hash = blake3::hash(&wasm_bytes).to_hex().to_string();
    let meta = serde_json::json!({ "wasm_hash": hash });
    std::fs::write(&meta_path, serde_json::to_vec(&meta)?)
        .map_err(|e| anyhow::anyhow!("failed to stage transient meta.json: {e}"))?;

    Ok(StagedMeta {
        path: meta_path,
        created: true,
    })
}

/// A `SecureMcpClient` wired to in-memory stores with an empty server
/// manager. Never exercised for pure-WASM tool capsules; present only
/// because `CapsuleLoader::new` requires one.
fn no_op_mcp_client() -> SecureMcpClient {
    let mcp_manager = ServerManager::new(ServersConfig::default());
    let mcp_client = McpClient::new(mcp_manager);
    let capabilities = Arc::new(CapabilityStore::in_memory());
    let audit = Arc::new(AuditLog::in_memory(KeyPair::generate()));
    SecureMcpClient::new(mcp_client, capabilities, audit, SessionId::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_action_deny_matches_only_tool_describe() {
        // A capsule with interceptors but no `#[astrid::tool]` (e.g. the broker)
        // denies the unknown `tool_describe` action — that is "no tools".
        assert!(is_unknown_action("unknown hook action: tool_describe"));
        // An unknown action for a DIFFERENT endpoint is not our signal — don't
        // swallow it (this fn is only ever called for `tool_describe`, but the
        // exact match keeps it honest).
        assert!(!is_unknown_action("unknown hook action: other_action"));
        // A genuine refusal must NOT be swallowed as "no tools", even if its
        // message happens to contain the phrase.
        assert!(!is_unknown_action("capability denied: caps:token:mint"));
        assert!(!is_unknown_action(
            "policy blocked: unknown hook action is not allowed here"
        ));
    }

    #[test]
    fn parses_tool_describe_payload() {
        // The exact shape the `#[astrid::tool]` macro emits.
        let payload = serde_json::json!({
            "tools": [
                {
                    "name": "read_file",
                    "description": "Read a file",
                    "input_schema": { "type": "object", "properties": {} }
                },
                {
                    "name": "write_file",
                    "description": "Write a file",
                    "input_schema": { "type": "object" }
                }
            ],
            "description": "fs capsule"
        });
        let bytes = serde_json::to_vec(&payload).expect("serialize");
        let tools = parse_tool_descriptors(&bytes).expect("parse");
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0].name, "read_file");
        assert_eq!(tools[0].description, "Read a file");
        assert_eq!(tools[0].input_schema["type"], "object");
        assert_eq!(tools[1].name, "write_file");
    }

    #[test]
    fn empty_tools_array_yields_empty_vec() {
        let payload = serde_json::json!({ "tools": [], "description": "" });
        let bytes = serde_json::to_vec(&payload).expect("serialize");
        assert!(parse_tool_descriptors(&bytes).expect("parse").is_empty());
    }

    #[test]
    fn missing_tools_key_yields_empty_vec() {
        let payload = serde_json::json!({ "description": "no tools key" });
        let bytes = serde_json::to_vec(&payload).expect("serialize");
        assert!(parse_tool_descriptors(&bytes).expect("parse").is_empty());
    }

    #[test]
    fn malformed_tools_array_errors() {
        let payload = serde_json::json!({ "tools": [ { "name": 42 } ] });
        let bytes = serde_json::to_vec(&payload).expect("serialize");
        assert!(parse_tool_descriptors(&bytes).is_err());
    }

    #[test]
    fn tool_descriptor_round_trips_with_input_schema_rename() {
        let d = ToolDescriptor {
            name: "do_thing".into(),
            description: "does it".into(),
            input_schema: serde_json::json!({ "type": "object" }),
        };
        let json = serde_json::to_value(&d).expect("serialize");
        // Field is `input_schema` on the wire, matching the macro output.
        assert!(json.get("input_schema").is_some());
        let back: ToolDescriptor = serde_json::from_value(json).expect("deserialize");
        assert_eq!(back, d);
    }

    #[tokio::test]
    async fn capsule_with_no_component_returns_empty() {
        // A manifest with no `[[component]]` (e.g. a pure static/MCP
        // capsule) has no WASM tool surface — empty, never an error.
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("Capsule.toml"),
            "[package]\nname = \"no-component\"\nversion = \"0.1.0\"\n",
        )
        .expect("write manifest");
        let tools = describe_capsule_tools(dir.path()).await.expect("describe");
        assert!(tools.is_empty());
    }

    #[test]
    fn stage_integrity_meta_leaves_existing_untouched() {
        let dir = tempfile::tempdir().expect("tempdir");
        let meta_path = dir.path().join("meta.json");
        std::fs::write(&meta_path, r#"{"wasm_hash":"real"}"#).expect("write meta");
        {
            let guard = stage_integrity_meta(dir.path(), Path::new("missing.wasm")).expect("stage");
            assert!(!guard.created, "must not claim ownership of existing meta");
        }
        // Existing meta survives the guard drop.
        let content = std::fs::read_to_string(&meta_path).expect("read");
        assert!(content.contains("real"));
    }

    #[test]
    fn stage_integrity_meta_creates_and_cleans_up() {
        let dir = tempfile::tempdir().expect("tempdir");
        let wasm_path = dir.path().join("c.wasm");
        std::fs::write(&wasm_path, b"\0asm\x0d\0\x01\0fake-component").expect("write wasm");
        let meta_path = dir.path().join("meta.json");
        {
            let guard = stage_integrity_meta(dir.path(), Path::new("c.wasm")).expect("stage");
            assert!(guard.created);
            let meta: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&meta_path).expect("read")).expect("json");
            let expected = blake3::hash(b"\0asm\x0d\0\x01\0fake-component")
                .to_hex()
                .to_string();
            assert_eq!(meta["wasm_hash"], expected);
        }
        // Transient meta removed on guard drop.
        assert!(!meta_path.exists());
    }
}
