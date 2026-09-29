//! Audit entries binding capsule code identity at install and load.
//!
//! A `CapsuleInstalled` entry is appended when the daemon has installed and
//! activated a capsule; a `CapsuleLoaded` entry when a runtime generation is
//! published (`load`) or replaces a running one (`replace`). Both bind the
//! BLAKE3 of the verified wasm component (from the install metadata the
//! engine checks the bytes against before loading), the BLAKE3 of the exact
//! `Capsule.toml` bytes, and — for loads — the engine profile the code was
//! compiled for. Host-call entries made by the runtime carry the same wasm
//! hash as their actor.

use std::path::Path;

use astrid_audit::{AuditAction, AuditOutcome, AuthorizationProof};
use astrid_capsule_types::manifest::CapsuleManifest;
use astrid_core::principal::PrincipalId;
use astrid_crypto::ContentHash;
use tracing::warn;

/// Authorization reason on capsule install and load entries.
const CAPSULE_LIFECYCLE_REASON: &str = "kernel capsule lifecycle";

/// Code identity of one capsule runtime, captured before it is published.
pub(crate) struct CapsuleIdentity {
    capsule_id: String,
    version: String,
    wasm_hash: Option<ContentHash>,
    manifest_hash: Option<ContentHash>,
    engine_profile: String,
}

impl CapsuleIdentity {
    /// Identity of `capsule` as built from its runtime directory.
    pub(crate) fn of(capsule: &dyn astrid_capsule::capsule::Capsule) -> Self {
        let manifest = capsule.manifest();
        let dir = capsule.source_dir();
        Self {
            capsule_id: manifest.package.name.clone(),
            version: manifest.package.version.clone(),
            wasm_hash: dir
                .filter(|_| !manifest.components.is_empty())
                .and_then(installed_wasm_hash),
            manifest_hash: dir.and_then(manifest_hash),
            engine_profile: engine_profile(manifest),
        }
    }
}

/// BLAKE3 of the exact `Capsule.toml` bytes in `dir`.
fn manifest_hash(dir: &Path) -> Option<ContentHash> {
    std::fs::read(dir.join("Capsule.toml"))
        .ok()
        .map(|bytes| ContentHash::hash(&bytes))
}

/// The wasm hash recorded at install in `dir`'s metadata; the engine refuses
/// to load a component whose bytes do not match it.
fn installed_wasm_hash(dir: &Path) -> Option<ContentHash> {
    astrid_capsule_install::read_meta(dir)?
        .wasm_hash
        .and_then(|hex| ContentHash::from_hex(&hex).ok())
}

/// The engines a manifest runs on: `wasm:<compiled engine ABI>` for wasm
/// components, `mcp-host` for host-process MCP servers, `static` otherwise.
pub(crate) fn engine_profile(manifest: &CapsuleManifest) -> String {
    let mut engines = Vec::new();
    if !manifest.components.is_empty() {
        engines.push(format!(
            "wasm:{}",
            astrid_capsule::engine::wasm::COMPILED_ENGINE_ABI
        ));
    }
    if manifest
        .mcp_servers
        .iter()
        .any(|server| server.server_type.as_deref() == Some("stdio"))
    {
        engines.push("mcp-host".to_owned());
    }
    if engines.is_empty() {
        engines.push("static".to_owned());
    }
    engines.join("+")
}

/// Record a published runtime generation for `principal`'s view.
pub(crate) async fn record_capsule_loaded(
    kernel: &crate::Kernel,
    principal: &PrincipalId,
    identity: CapsuleIdentity,
    trigger: &str,
) {
    let action = AuditAction::CapsuleLoaded {
        capsule_id: identity.capsule_id,
        version: identity.version,
        wasm_hash: identity.wasm_hash,
        manifest_hash: identity.manifest_hash,
        engine_profile: identity.engine_profile,
        trigger: trigger.to_owned(),
    };
    append(kernel, principal, action).await;
}

/// Record a completed daemon install of `output` for `principal`.
pub(crate) async fn record_capsule_installed(
    kernel: &crate::Kernel,
    principal: &PrincipalId,
    output: &astrid_capsule_install::InstallOutput,
) {
    let manifest_path = output.target_dir.join("Capsule.toml");
    let capsule_id = match astrid_capsule::discovery::load_manifest(&manifest_path) {
        Ok(manifest) => manifest.package.name,
        Err(error) => {
            warn!(%error, "Cannot read installed manifest for the install audit entry");
            return;
        },
    };
    let action = AuditAction::CapsuleInstalled {
        capsule_id,
        version: output.installed_version.clone(),
        target_principal: Some(principal.clone()),
        wasm_hash: output
            .wasm_hash
            .as_deref()
            .and_then(|hex| ContentHash::from_hex(hex).ok()),
        manifest_hash: manifest_hash(&output.target_dir),
    };
    append(kernel, principal, action).await;
}

async fn append(kernel: &crate::Kernel, principal: &PrincipalId, action: AuditAction) {
    // Boxed so the load and install paths that await this do not carry the
    // append's state machine inline.
    let append = Box::pin(kernel.audit_log.append_with_principal(
        kernel.session_id.clone(),
        principal.clone(),
        action,
        AuthorizationProof::System {
            reason: CAPSULE_LIFECYCLE_REASON.to_owned(),
        },
        AuditOutcome::success(),
    ));
    if let Err(error) = append.await {
        warn!(
            security_event = true,
            %principal,
            %error,
            "Failed to persist capsule lifecycle audit entry; continuing"
        );
    }
}
