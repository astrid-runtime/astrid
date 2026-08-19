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
    let files = read_archive_files(&archive).unwrap();
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
