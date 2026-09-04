use super::*;
use std::collections::HashMap;

use crate::authority::AuthoritySource;
use tempfile::tempdir;

#[test]
fn durable_metadata_cross_binding_rejects_manifest_and_archive_mismatches() {
    let source = tempdir().unwrap();
    let manifest_bytes = br#"[package]
name = "cross-bound"
version = "1.0.0"

[[component]]
id = "main"
file = "main.wasm"

[imports.astrid]
session = "^1.0"

[exports.astrid]
capability = "1.0.0"
"#;
    fs::write(source.path().join("Capsule.toml"), manifest_bytes).unwrap();
    let wasm_bytes = b"trusted component bytes";
    fs::write(source.path().join("main.wasm"), wasm_bytes).unwrap();

    let archive = canonical_capsule_archive(source.path()).unwrap();
    let verification = artifact::verify_archive_bytes(&archive).unwrap();
    let ArchiveInventory { files, .. } = read_archive_files(&archive).unwrap();
    let manifest: CapsuleManifest =
        toml::from_str(std::str::from_utf8(manifest_bytes).unwrap()).unwrap();
    let wasm_hash = blake3::hash(wasm_bytes).to_hex().to_string();

    let mut imports = HashMap::new();
    imports.insert(
        "astrid".to_owned(),
        HashMap::from([("session".to_owned(), "^1.0".to_owned())]),
    );
    let mut exports = HashMap::new();
    exports.insert(
        "astrid".to_owned(),
        HashMap::from([("capability".to_owned(), "1.0.0".to_owned())]),
    );
    let metadata = CapsuleMeta {
        version: "1.0.0".to_owned(),
        imports,
        exports,
        wasm_hash: Some(wasm_hash.clone()),
        ..Default::default()
    };
    let authority = InstalledAuthority {
        schema_version: 1,
        source: AuthoritySource::ExplicitApproval,
        capsule_id: "cross-bound".to_owned(),
        version: "1.0.0".to_owned(),
        content_digest: verification.content_digest().to_owned(),
        manifest_digest: crate::authority::digest_manifest(manifest_bytes),
        signer: None,
        signature: None,
        approved_capabilities: manifest.capabilities.clone(),
        wasm_hash_pinned: true,
        approved_wasm_hash: Some(wasm_hash),
    };

    verify_package_identity(
        "cross-bound",
        &manifest,
        &metadata,
        &authority,
        manifest_bytes,
        &verification,
        &files,
    )
    .expect("matching durable metadata should verify");

    let rejects = |candidate: &CapsuleMeta| {
        verify_package_identity(
            "cross-bound",
            &manifest,
            candidate,
            &authority,
            manifest_bytes,
            &verification,
            &files,
        )
        .is_err()
    };

    let mut imports_tampered = metadata.clone();
    imports_tampered.imports.clear();
    let imports_rejected = rejects(&imports_tampered);

    let mut exports_tampered = metadata.clone();
    exports_tampered
        .exports
        .get_mut("astrid")
        .unwrap()
        .insert("capability".to_owned(), "9.9.9".to_owned());
    let exports_rejected = rejects(&exports_tampered);

    let mut wasm_tampered = metadata;
    wasm_tampered.wasm_hash = Some("00".repeat(32));
    let wasm_rejected = rejects(&wasm_tampered);
    assert!(
        imports_rejected && exports_rejected && wasm_rejected,
        "durable metadata must bind imports, exports, and wasm_hash to the archive"
    );
}

#[test]
fn archive_entries_enumerate_every_verified_member_with_exact_bytes() {
    let source = tempdir().unwrap();
    fs::write(
        source.path().join("Capsule.toml"),
        b"[package]\nname='demo'\nversion='1.0.0'\n",
    )
    .unwrap();
    fs::create_dir(source.path().join("nested")).unwrap();
    fs::write(source.path().join("nested/file"), b"exact bytes").unwrap();
    fs::create_dir(source.path().join("empty")).unwrap();
    fs::create_dir(source.path().join("nested/deep")).unwrap();
    let home_dir = tempdir().unwrap();
    let home = astrid_core::dirs::AstridHome::from_path(home_dir.path());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let store = runtime
        .block_on(async {
            astrid_storage::open_runtime_principal_store(
                &home,
                std::sync::Arc::new(|_: &StateOwner| Ok(None)),
            )
            .await
        })
        .unwrap();
    let archive = canonical_capsule_archive(source.path()).unwrap();
    let verification = artifact::verify_archive_bytes(&archive).unwrap();
    let manifest_bytes = fs::read(source.path().join("Capsule.toml")).unwrap();
    let manifest: CapsuleManifest =
        toml::from_str(std::str::from_utf8(&manifest_bytes).unwrap()).unwrap();
    let authority = InstalledAuthority {
        schema_version: 1,
        source: AuthoritySource::ExplicitApproval,
        capsule_id: "demo".to_owned(),
        version: "1.0.0".to_owned(),
        content_digest: verification.content_digest().to_owned(),
        manifest_digest: crate::authority::digest_manifest(&manifest_bytes),
        signer: None,
        signature: None,
        approved_capabilities: manifest.capabilities,
        wasm_hash_pinned: false,
        approved_wasm_hash: None,
    };
    let package = CapsulePackage::new(
        archive,
        br#"{"version":"1.0.0","installed_at":"","updated_at":""}"#.to_vec(),
        serde_json::to_vec(&authority).unwrap(),
    );
    let store = std::sync::Arc::new(store);
    publish_package(
        &store,
        astrid_core::identity::PrincipalUid::from_bytes([7_u8; 32]),
        "demo",
        &package,
    )
    .unwrap();
    let verified = read_verified_durable_package_for_owner(
        &store,
        &StateOwner::Principal(astrid_core::identity::PrincipalUid::from_bytes([7_u8; 32])),
        "demo",
    )
    .unwrap()
    .unwrap();

    let entries: std::collections::BTreeMap<&str, &[u8]> = verified.archive_entries().collect();
    assert_eq!(
        entries.get("Capsule.toml"),
        Some(&&b"[package]\nname='demo'\nversion='1.0.0'\n"[..])
    );
    assert_eq!(entries.get("nested/file"), Some(&&b"exact bytes"[..]));
    assert_eq!(entries.len(), 2);
    let directories: std::collections::BTreeSet<&str> = verified.archive_directories().collect();
    assert_eq!(
        directories,
        std::iter::once("empty")
            .chain(["nested", "nested/deep"])
            .collect()
    );
}
