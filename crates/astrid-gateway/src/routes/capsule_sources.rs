use std::collections::HashSet;
use std::path::{Path, PathBuf};

use astrid_core::PrincipalId;
use astrid_core::dirs::AstridHome;
use serde::Deserialize;
use uuid::Uuid;

const CAPSULE_ID_NAMESPACE: Uuid = Uuid::from_u128(0x310714d5_9c6d_4c94_8187_75258f393bb6);

pub(super) fn capsule_source_id_v0(capsule_id: &str) -> Uuid {
    Uuid::new_v5(&CAPSULE_ID_NAMESPACE, capsule_id.as_bytes())
}

/// Derive the trusted `source_id` a shared capsule runtime stamps on its IPC
/// replies.
///
/// MUST stay byte-identical to the WASM engine's `capsule_uuid` seed in
/// `astrid-capsule/src/engine/wasm/mod.rs` (`{capsule_id}\0{content_hash}`, same
/// namespace). One runtime is shared by every principal that views the same
/// content hash (issue #1069), so the seed carries NO principal segment. Reply
/// routing to the requesting principal is handled by the principal-scoped routed
/// subscription plus the body correlation id; this id is only an authenticity
/// gate, so it needs only to match the runtime's stamped id.
pub(super) fn capsule_source_id_v1(capsule_id: &str, content_hash: &str) -> Uuid {
    let seed = format!("{capsule_id}\0{content_hash}");
    Uuid::new_v5(&CAPSULE_ID_NAMESPACE, seed.as_bytes())
}

pub(super) fn trusted_capsule_source_ids(capsule_id: &str, caller: &PrincipalId) -> Vec<Uuid> {
    let Ok(home) = AstridHome::resolve() else {
        return Vec::new();
    };

    // The `caller` selects WHICH install set to read the content hash from (a
    // principal may have its own installed version); it no longer contributes to
    // the derived source id, which is content-addressed and shared across
    // principals (issue #1069).
    let mut dirs = Vec::new();
    dirs.push(home.principal_home(caller).capsules_dir().join(capsule_id));
    if let Ok(cwd) = std::env::current_dir() {
        dirs.push(cwd.join(".astrid").join("capsules").join(capsule_id));
    }

    trusted_capsule_source_ids_from_dirs(capsule_id, dirs)
}

fn trusted_capsule_source_ids_from_dirs(
    capsule_id: &str,
    dirs: impl IntoIterator<Item = PathBuf>,
) -> Vec<Uuid> {
    let mut seen_hashes = HashSet::new();
    let mut seen_ids = HashSet::new();
    let mut ids = Vec::new();

    for dir in dirs {
        let Some(content_hash) = installed_content_hash(capsule_id, &dir) else {
            continue;
        };
        if !seen_hashes.insert(content_hash.clone()) {
            continue;
        }
        let source_id = capsule_source_id_v1(capsule_id, &content_hash);
        if seen_ids.insert(source_id) {
            ids.push(source_id);
        }
    }

    ids
}

fn installed_content_hash(capsule_id: &str, dir: &Path) -> Option<String> {
    if let Some(hash) = read_meta_wasm_hash(dir) {
        return Some(hash);
    }
    read_manifest_package(dir)
        .filter(|package| package.name == capsule_id && !package.version.is_empty())
        .map(|package| synthetic_content_hash(&package.name, &package.version))
}

fn read_meta_wasm_hash(dir: &Path) -> Option<String> {
    let meta_path = dir.join("meta.json");
    let data = match std::fs::read_to_string(&meta_path) {
        Ok(data) => data,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            tracing::warn!(
                path = %meta_path.display(),
                error = %e,
                "failed to read meta.json for capsule source-id derivation"
            );
            return None;
        },
    };
    match serde_json::from_str::<serde_json::Value>(&data) {
        Ok(meta) => meta
            .get("wasm_hash")
            .and_then(serde_json::Value::as_str)
            .filter(|hash| !hash.is_empty())
            .map(str::to_owned),
        Err(e) => {
            tracing::warn!(
                path = %meta_path.display(),
                error = %e,
                "failed to parse meta.json for capsule source-id derivation"
            );
            None
        },
    }
}

fn synthetic_content_hash(name: &str, version: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"synthetic-capsule-instance:");
    hasher.update(name.as_bytes());
    hasher.update(&[0]);
    hasher.update(version.as_bytes());
    hasher.finalize().to_hex().to_string()
}

#[derive(Deserialize)]
struct CapsuleManifestPackageOnly {
    package: CapsuleManifestPackage,
}

#[derive(Deserialize)]
struct CapsuleManifestPackage {
    name: String,
    version: String,
}

fn read_manifest_package(dir: &Path) -> Option<CapsuleManifestPackage> {
    let manifest_path = dir.join("Capsule.toml");
    let data = match std::fs::read_to_string(&manifest_path) {
        Ok(data) => data,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            tracing::warn!(
                path = %manifest_path.display(),
                error = %e,
                "failed to read Capsule.toml for capsule source-id derivation"
            );
            return None;
        },
    };
    match toml::from_str::<CapsuleManifestPackageOnly>(&data) {
        Ok(manifest) => Some(manifest.package),
        Err(e) => {
            tracing::warn!(
                path = %manifest_path.display(),
                error = %e,
                "failed to parse Capsule.toml for capsule source-id derivation"
            );
            None
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{
        capsule_source_id_v1, synthetic_content_hash, trusted_capsule_source_ids_from_dirs,
    };
    use serde_json::json;
    use uuid::Uuid;

    #[test]
    fn derives_content_addressed_source_id_from_installed_wasm_hash() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let capsule_dir = tmp.path().join("astrid-capsule-session");
        std::fs::create_dir_all(&capsule_dir).expect("capsule dir");
        std::fs::write(
            capsule_dir.join("meta.json"),
            serde_json::to_vec(&json!({
                "version": "1.0.0",
                "installed_at": "now",
                "updated_at": "now",
                "wasm_hash": "abc123"
            }))
            .expect("json"),
        )
        .expect("meta");

        let ids = trusted_capsule_source_ids_from_dirs("astrid-capsule-session", [capsule_dir]);

        // Content-addressed: one id per hash, principal-independent (#1069).
        assert_eq!(
            ids,
            vec![capsule_source_id_v1("astrid-capsule-session", "abc123")]
        );
    }

    #[test]
    fn source_id_lockstep_with_wasm_engine_seed() {
        // The gateway's trusted source-id derivation MUST stay byte-identical to
        // the WASM engine's `capsule_uuid` seed in
        // `astrid-capsule/src/engine/wasm/mod.rs`, else the gateway would reject
        // every genuine reply from a shared capsule runtime. This reproduces the
        // engine's exact derivation (same fixed namespace, same
        // `{capsule_id}\0{content_hash}` seed, NO principal segment) and asserts
        // equality. If this fails, the two seeds have drifted — fix BOTH.
        const ENGINE_NAMESPACE: Uuid = Uuid::from_u128(0x310714d5_9c6d_4c94_8187_75258f393bb6);
        let capsule_id = "astrid-capsule-session";
        let content_hash = "abc123";
        let engine_seed = format!("{capsule_id}\0{content_hash}");
        let engine_uuid = Uuid::new_v5(&ENGINE_NAMESPACE, engine_seed.as_bytes());

        assert_eq!(
            capsule_source_id_v1(capsule_id, content_hash),
            engine_uuid,
            "gateway source-id derivation drifted from the WASM engine capsule_uuid seed"
        );
    }

    #[test]
    fn source_id_is_principal_independent() {
        // The shared-runtime seed must not depend on any principal: the same
        // content hash yields the same source id regardless of which caller's
        // install set it was read from.
        let hash = "deadbeef";
        let id = capsule_source_id_v1("astrid-capsule-session", hash);
        assert_ne!(id, Uuid::nil());
        // Re-deriving from the same inputs is stable.
        assert_eq!(id, capsule_source_id_v1("astrid-capsule-session", hash));
        // A different hash yields a different id.
        assert_ne!(id, capsule_source_id_v1("astrid-capsule-session", "cafe"));
    }

    #[test]
    fn derives_source_ids_from_manifest_when_meta_has_no_wasm_hash() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let capsule_dir = tmp.path().join("astrid-capsule-session");
        std::fs::create_dir_all(&capsule_dir).expect("capsule dir");
        std::fs::write(
            capsule_dir.join("meta.json"),
            serde_json::to_vec(&json!({
                "version": "1.0.0",
                "installed_at": "now",
                "updated_at": "now"
            }))
            .expect("json"),
        )
        .expect("meta");
        std::fs::write(
            capsule_dir.join("Capsule.toml"),
            "[package]\nname = \"astrid-capsule-session\"\nversion = \"1.0.0\"\n",
        )
        .expect("manifest");

        let ids = trusted_capsule_source_ids_from_dirs("astrid-capsule-session", [capsule_dir]);
        let content_hash = synthetic_content_hash("astrid-capsule-session", "1.0.0");

        assert_eq!(
            ids,
            vec![capsule_source_id_v1(
                "astrid-capsule-session",
                &content_hash
            )]
        );
    }

    #[test]
    fn derives_source_ids_from_partial_meta_with_wasm_hash() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let capsule_dir = tmp.path().join("astrid-capsule-session");
        std::fs::create_dir_all(&capsule_dir).expect("capsule dir");
        std::fs::write(
            capsule_dir.join("meta.json"),
            r#"{"wasm_hash":"real-hash"}"#,
        )
        .expect("meta");
        std::fs::write(
            capsule_dir.join("Capsule.toml"),
            "[package]\nname = \"astrid-capsule-session\"\nversion = \"1.0.0\"\n",
        )
        .expect("manifest");

        let ids = trusted_capsule_source_ids_from_dirs("astrid-capsule-session", [capsule_dir]);

        assert_eq!(
            ids,
            vec![capsule_source_id_v1("astrid-capsule-session", "real-hash")]
        );
    }

    #[test]
    fn ignores_manifest_with_mismatched_package_name() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let capsule_dir = tmp.path().join("astrid-capsule-session");
        std::fs::create_dir_all(&capsule_dir).expect("capsule dir");
        std::fs::write(
            capsule_dir.join("Capsule.toml"),
            "[package]\nname = \"astrid-capsule-other\"\nversion = \"1.0.0\"\n",
        )
        .expect("manifest");

        let ids = trusted_capsule_source_ids_from_dirs("astrid-capsule-session", [capsule_dir]);

        assert!(ids.is_empty());
    }
}
