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

pub(super) fn capsule_source_id_v1(
    principal: &PrincipalId,
    capsule_id: &str,
    content_hash: &str,
) -> Uuid {
    let seed = format!("{principal}\0{capsule_id}\0{content_hash}");
    Uuid::new_v5(&CAPSULE_ID_NAMESPACE, seed.as_bytes())
}

pub(super) fn trusted_capsule_source_ids(capsule_id: &str, caller: &PrincipalId) -> Vec<Uuid> {
    let Ok(home) = AstridHome::resolve() else {
        return Vec::new();
    };

    let principals = principal_candidates(caller);
    let mut dirs = Vec::new();
    for principal in &principals {
        dirs.push(
            home.principal_home(principal)
                .capsules_dir()
                .join(capsule_id),
        );
    }
    if let Ok(cwd) = std::env::current_dir() {
        dirs.push(cwd.join(".astrid").join("capsules").join(capsule_id));
    }

    trusted_capsule_source_ids_from_dirs(capsule_id, &principals, dirs)
}

fn principal_candidates(caller: &PrincipalId) -> Vec<PrincipalId> {
    let default = PrincipalId::default();
    if caller == &default {
        vec![default]
    } else {
        vec![default, caller.clone()]
    }
}

fn trusted_capsule_source_ids_from_dirs(
    capsule_id: &str,
    principals: &[PrincipalId],
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
        for principal in principals {
            let source_id = capsule_source_id_v1(principal, capsule_id, &content_hash);
            if seen_ids.insert(source_id) {
                ids.push(source_id);
            }
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
    use astrid_core::PrincipalId;
    use serde_json::json;

    #[test]
    fn derives_source_ids_from_installed_wasm_hash_for_principal_candidates() {
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

        let default = PrincipalId::default();
        let alice = PrincipalId::new("alice").expect("valid principal");
        let ids = trusted_capsule_source_ids_from_dirs(
            "astrid-capsule-session",
            &[default.clone(), alice.clone()],
            [capsule_dir],
        );

        assert_eq!(
            ids,
            vec![
                capsule_source_id_v1(&default, "astrid-capsule-session", "abc123"),
                capsule_source_id_v1(&alice, "astrid-capsule-session", "abc123"),
            ]
        );
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

        let alice = PrincipalId::new("alice").expect("valid principal");
        let ids = trusted_capsule_source_ids_from_dirs(
            "astrid-capsule-session",
            std::slice::from_ref(&alice),
            [capsule_dir],
        );
        let content_hash = synthetic_content_hash("astrid-capsule-session", "1.0.0");

        assert_eq!(
            ids,
            vec![capsule_source_id_v1(
                &alice,
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

        let alice = PrincipalId::new("alice").expect("valid principal");
        let ids = trusted_capsule_source_ids_from_dirs(
            "astrid-capsule-session",
            std::slice::from_ref(&alice),
            [capsule_dir],
        );

        assert_eq!(
            ids,
            vec![capsule_source_id_v1(
                &alice,
                "astrid-capsule-session",
                "real-hash"
            )]
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

        let alice = PrincipalId::new("alice").expect("valid principal");
        let ids = trusted_capsule_source_ids_from_dirs(
            "astrid-capsule-session",
            std::slice::from_ref(&alice),
            [capsule_dir],
        );

        assert!(ids.is_empty());
    }
}
