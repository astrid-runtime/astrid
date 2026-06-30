use std::collections::HashSet;
use std::path::PathBuf;

use astrid_core::PrincipalId;
use astrid_core::dirs::AstridHome;
use uuid::Uuid;

const CAPSULE_ID_NAMESPACE: Uuid = Uuid::from_u128(0x310714d5_9c6d_4c94_8187_75258f393bb6);

pub(super) fn legacy_capsule_source_id(capsule_id: &str) -> Uuid {
    Uuid::new_v5(&CAPSULE_ID_NAMESPACE, capsule_id.as_bytes())
}

pub(super) fn content_addressed_capsule_source_id(
    principal: &PrincipalId,
    capsule_id: &str,
    wasm_hash: &str,
) -> Uuid {
    let seed = format!("{principal}\0{capsule_id}\0{wasm_hash}");
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
        let Some(wasm_hash) = astrid_capsule_install::meta::read_meta(&dir)
            .and_then(|meta| meta.wasm_hash)
            .filter(|hash| !hash.is_empty())
        else {
            continue;
        };
        if !seen_hashes.insert(wasm_hash.clone()) {
            continue;
        }
        for principal in principals {
            let source_id = content_addressed_capsule_source_id(principal, capsule_id, &wasm_hash);
            if seen_ids.insert(source_id) {
                ids.push(source_id);
            }
        }
    }

    ids
}

#[cfg(test)]
mod tests {
    use super::{content_addressed_capsule_source_id, trusted_capsule_source_ids_from_dirs};
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
                content_addressed_capsule_source_id(&default, "astrid-capsule-session", "abc123"),
                content_addressed_capsule_source_id(&alice, "astrid-capsule-session", "abc123"),
            ]
        );
    }
}
