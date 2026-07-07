//! End-to-end install tests against a temp `AstridHome`.
//!
//! These exercise the path the kernel-side install handler and the
//! CLI's `install_from_local_path` both reach into. The behaviours
//! verified here used to live as `#[cfg(test)] mod tests` blocks
//! inside `astrid-cli/src/commands/capsule/install.rs`; they followed
//! the install machinery into this crate when it was extracted.

use astrid_capsule_install::{
    InstallOptions, copy_capsule_dir, install_from_local_path, read_meta,
};
use astrid_core::dirs::AstridHome;

/// Resolve the `home://wit/` mirror directory for the install principal.
///
/// Uses [`astrid_capsule_install::paths::install_principal`] — the same
/// single source of truth the mirror writer resolves against — so the test
/// stays aligned if the install principal ever changes.
fn wit_mirror_dir(home: &AstridHome) -> std::path::PathBuf {
    home.principal_home(&astrid_capsule_install::paths::install_principal())
        .root()
        .join("wit")
}

fn write_minimal_capsule(base: &std::path::Path, name: &str, version: &str) {
    std::fs::write(
        base.join("Capsule.toml"),
        format!("[package]\nname = \"{name}\"\nversion = \"{version}\"\n"),
    )
    .unwrap();
}

#[test]
fn install_preserves_node_modules() {
    let capsule_dir = tempfile::tempdir().unwrap();
    let base = capsule_dir.path();

    std::fs::write(
        base.join("Capsule.toml"),
        "[package]\nname = \"install-test\"\nversion = \"1.0.0\"\n\n\
         [[mcp_server]]\nid = \"install-test\"\ncommand = \"node\"\nargs = [\"bridge.mjs\"]\n",
    )
    .unwrap();
    std::fs::write(base.join("bridge.mjs"), "// bridge").unwrap();
    std::fs::create_dir_all(base.join("src")).unwrap();
    std::fs::write(base.join("src/index.js"), "module.exports = {};").unwrap();
    std::fs::write(
        base.join("package.json"),
        r#"{"name": "install-test", "dependencies": {"got": "^1.0"}}"#,
    )
    .unwrap();
    std::fs::create_dir_all(base.join("node_modules/got")).unwrap();
    std::fs::write(
        base.join("node_modules/got/index.js"),
        "module.exports = {};",
    )
    .unwrap();

    let home_dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(home_dir.path());
    install_from_local_path(base, &home, InstallOptions::default())
        .expect("install should succeed");

    let installed = home
        .principal_home(&astrid_core::PrincipalId::default())
        .capsules_dir()
        .join("install-test");
    assert!(installed.join("Capsule.toml").exists());
    assert!(installed.join("node_modules/got/index.js").exists());
    assert!(installed.join("package.json").exists());
    assert!(installed.join("src/index.js").exists());
}

#[test]
fn copy_capsule_dir_skips_git_and_build_artifacts() {
    let src_dir = tempfile::tempdir().unwrap();
    let base = src_dir.path();

    std::fs::write(base.join("index.js"), "// code").unwrap();
    std::fs::create_dir_all(base.join(".git/objects")).unwrap();
    std::fs::write(base.join(".git/objects/abc"), "blob").unwrap();
    std::fs::create_dir_all(base.join("dist")).unwrap();
    std::fs::write(base.join("dist/out.js"), "// built").unwrap();
    std::fs::create_dir_all(base.join("target")).unwrap();
    std::fs::write(base.join("target/debug"), "// rust").unwrap();
    std::fs::create_dir_all(base.join("node_modules/pkg")).unwrap();
    std::fs::write(base.join("node_modules/pkg/index.js"), "// dep").unwrap();

    let dst_dir = tempfile::tempdir().unwrap();
    copy_capsule_dir(base, dst_dir.path()).unwrap();

    assert!(dst_dir.path().join("index.js").exists());
    assert!(dst_dir.path().join("node_modules/pkg/index.js").exists());
    assert!(!dst_dir.path().join(".git").exists());
    assert!(!dst_dir.path().join("dist").exists());
    assert!(!dst_dir.path().join("target").exists());
}

#[test]
fn copy_capsule_dir_excludes_wasm_and_wit() {
    // The runtime contract says: WASM lives in bin/<hash>.wasm,
    // WIT lives in wit/<hash>.wit, the per-capsule directory holds
    // the manifest + meta + resources. The copy must reflect that.
    let src_dir = tempfile::tempdir().unwrap();
    let base = src_dir.path();

    std::fs::write(
        base.join("Capsule.toml"),
        "[package]\nname = \"x\"\nversion = \"1.0.0\"\n",
    )
    .unwrap();
    std::fs::write(base.join("plugin.wasm"), b"\0asm").unwrap();
    std::fs::create_dir_all(base.join("wit")).unwrap();
    std::fs::write(base.join("wit/contract.wit"), "package foo:bar;").unwrap();

    let dst_dir = tempfile::tempdir().unwrap();
    copy_capsule_dir(base, dst_dir.path()).unwrap();

    assert!(dst_dir.path().join("Capsule.toml").exists());
    assert!(
        !dst_dir.path().join("plugin.wasm").exists(),
        "*.wasm must be excluded from per-capsule dir copy"
    );
    assert!(
        !dst_dir.path().join("wit").exists(),
        "top-level wit/ must be excluded from per-capsule dir copy"
    );
}

#[test]
#[cfg_attr(windows, ignore = "symlinks require elevated privileges on Windows")]
fn copy_capsule_dir_refuses_file_symlink_pointing_outside_root() {
    // Sandbox-escape vector: a malicious capsule tree ships a file
    // symlink pointing at a host secret. The installer must refuse
    // rather than copying the bytes into the per-capsule directory
    // (which the capsule's WASM sandbox could then read via the
    // `home://` VFS or a Tier-2 local-command script).
    let outside = tempfile::tempdir().unwrap();
    let host_secret = outside.path().join("host-secret");
    std::fs::write(&host_secret, b"super secret host data").unwrap();

    let src = tempfile::tempdir().unwrap();
    std::fs::write(src.path().join("legit.txt"), "ok").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&host_secret, src.path().join("evil")).unwrap();

    let dst = tempfile::tempdir().unwrap();
    let err = copy_capsule_dir(src.path(), dst.path())
        .expect_err("must refuse a symlink resolving outside the source root");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("outside the capsule source root"),
        "expected sandbox-escape error, got: {msg}"
    );
    assert!(
        !dst.path().join("evil").exists(),
        "host secret must not be copied into the capsule dir"
    );
}

#[test]
#[cfg_attr(windows, ignore = "symlinks require elevated privileges on Windows")]
fn copy_capsule_dir_refuses_directory_symlink() {
    // Directory symlinks open two problems: (a) infinite recursion
    // when the link points to an ancestor, and (b) ballooning copies
    // of legitimately-shared trees (e.g. a symlink to a sibling's
    // node_modules). npm only produces FILE symlinks under
    // `node_modules/.bin/`, so refusing directory symlinks loses no
    // real use case and shuts both threats down.
    let src = tempfile::tempdir().unwrap();
    let real_dir = src.path().join("real-dir");
    std::fs::create_dir_all(&real_dir).unwrap();
    std::fs::write(real_dir.join("inner.txt"), "x").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&real_dir, src.path().join("link-to-dir")).unwrap();

    let dst = tempfile::tempdir().unwrap();
    let err = copy_capsule_dir(src.path(), dst.path()).expect_err("must refuse directory symlinks");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("directory symlink"),
        "expected directory-symlink error, got: {msg}"
    );
}

#[test]
#[cfg_attr(windows, ignore = "symlinks require elevated privileges on Windows")]
fn install_dereferences_node_modules_bin_symlinks() {
    let capsule_dir = tempfile::tempdir().unwrap();
    let base = capsule_dir.path();

    std::fs::write(
        base.join("Capsule.toml"),
        "[package]\nname = \"symlink-test\"\nversion = \"1.0.0\"\n\n\
         [[mcp_server]]\nid = \"symlink-test\"\ncommand = \"node\"\nargs = [\"bridge.mjs\"]\n",
    )
    .unwrap();
    std::fs::write(base.join("bridge.mjs"), "// bridge").unwrap();

    std::fs::create_dir_all(base.join("node_modules/somepkg")).unwrap();
    std::fs::write(
        base.join("node_modules/somepkg/cli.js"),
        "#!/usr/bin/env node\nconsole.log('works');",
    )
    .unwrap();
    std::fs::create_dir_all(base.join("node_modules/.bin")).unwrap();

    #[cfg(unix)]
    std::os::unix::fs::symlink(
        std::path::Path::new("../somepkg/cli.js"),
        base.join("node_modules/.bin/somepkg"),
    )
    .unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(
        std::path::Path::new("../somepkg/cli.js"),
        base.join("node_modules/.bin/somepkg"),
    )
    .unwrap();

    let home_dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(home_dir.path());
    install_from_local_path(base, &home, InstallOptions::default())
        .expect("install must not bail on symlinks");

    let installed = home
        .principal_home(&astrid_core::PrincipalId::default())
        .capsules_dir()
        .join("symlink-test");
    let bin_file = installed.join("node_modules/.bin/somepkg");
    assert!(bin_file.exists());
    assert!(!bin_file.is_symlink());
    let content = std::fs::read_to_string(&bin_file).unwrap();
    assert!(content.contains("works"));
}

#[test]
fn install_writes_meta_json() {
    let capsule_dir = tempfile::tempdir().unwrap();
    let base = capsule_dir.path();
    write_minimal_capsule(base, "meta-test", "2.0.0");

    let home_dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(home_dir.path());
    install_from_local_path(base, &home, InstallOptions::default())
        .expect("install should succeed");

    let installed = home
        .principal_home(&astrid_core::PrincipalId::default())
        .capsules_dir()
        .join("meta-test");
    let meta = read_meta(&installed).expect("meta.json should exist after install");
    assert_eq!(meta.version, "2.0.0");
}

#[test]
fn install_materializes_home_wit_mirror() {
    // The system capsule's list_interfaces / read_interface tools read
    // `home://wit/<basename>`, which resolves to <principal_home>/wit/.
    // Install must mirror the content-addressed WIT blobs there, keyed
    // by basename (read_interface rejects names containing '/').
    let capsule_dir = tempfile::tempdir().unwrap();
    let base = capsule_dir.path();
    write_minimal_capsule(base, "wit-mirror-test", "1.0.0");

    std::fs::create_dir_all(base.join("wit/deps/astrid-contracts")).unwrap();
    let broker_src = "package astrid:broker;\ninterface broker {}\n";
    let contracts_src = "package astrid:contracts;\ninterface contracts {}\n";
    std::fs::write(base.join("wit/broker.wit"), broker_src).unwrap();
    // Nested path — must be flattened to basename in the mirror.
    std::fs::write(
        base.join("wit/deps/astrid-contracts/astrid-contracts.wit"),
        contracts_src,
    )
    .unwrap();

    let home_dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(home_dir.path());
    install_from_local_path(base, &home, InstallOptions::default())
        .expect("install should succeed");

    let mirror = wit_mirror_dir(&home);
    let broker = mirror.join("broker.wit");
    let contracts = mirror.join("astrid-contracts.wit");

    assert!(
        broker.exists(),
        "broker.wit must be mirrored to home://wit/"
    );
    assert!(
        contracts.exists(),
        "nested astrid-contracts.wit must be flattened to its basename in home://wit/"
    );
    assert_eq!(std::fs::read_to_string(&broker).unwrap(), broker_src);
    assert_eq!(std::fs::read_to_string(&contracts).unwrap(), contracts_src);
    // No nested directory should be created in the mirror — basename only.
    assert!(
        !mirror.join("deps").exists(),
        "mirror must be flat (basename), not a nested tree"
    );
}

#[test]
fn install_wit_mirror_is_idempotent() {
    // Re-installing the same capsule must not error and must converge
    // to the same mirror state (idempotency requirement).
    let capsule_dir = tempfile::tempdir().unwrap();
    let base = capsule_dir.path();
    write_minimal_capsule(base, "wit-idem-test", "1.0.0");

    std::fs::create_dir_all(base.join("wit")).unwrap();
    let src = "package astrid:idem;\ninterface idem {}\n";
    std::fs::write(base.join("wit/idem.wit"), src).unwrap();

    let home_dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(home_dir.path());

    install_from_local_path(base, &home, InstallOptions::default()).expect("first install");
    let mirrored = wit_mirror_dir(&home).join("idem.wit");
    assert_eq!(std::fs::read_to_string(&mirrored).unwrap(), src);

    // Second install (same bytes) must not error and must leave the same
    // content. Also confirm no stray temp files leak into the mirror.
    install_from_local_path(base, &home, InstallOptions::default()).expect("re-install");
    assert_eq!(std::fs::read_to_string(&mirrored).unwrap(), src);

    let entries: Vec<String> = std::fs::read_dir(wit_mirror_dir(&home))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        entries,
        vec!["idem.wit".to_string()],
        "mirror must contain exactly the one file, no temp leftovers"
    );
}

#[test]
fn install_retains_wit_blobs_in_content_store() {
    // Every WIT file a capsule vendors must be retained content-addressed
    // at wit/store/<hash>.wit so its meta.json pin can always be
    // dereferenced from local disk — the WIT analogue of bin/<hash>.wasm.
    let capsule_dir = tempfile::tempdir().unwrap();
    let base = capsule_dir.path();
    write_minimal_capsule(base, "wit-store-test", "1.0.0");

    std::fs::create_dir_all(base.join("wit/deps/astrid-contracts")).unwrap();
    let broker_src = "package astrid:broker;\ninterface broker {}\n";
    let contracts_src = "package astrid:contracts;\ninterface contracts {}\n";
    std::fs::write(base.join("wit/broker.wit"), broker_src).unwrap();
    std::fs::write(
        base.join("wit/deps/astrid-contracts/astrid-contracts.wit"),
        contracts_src,
    )
    .unwrap();

    let home_dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(home_dir.path());
    install_from_local_path(base, &home, InstallOptions::default())
        .expect("install should succeed");

    let installed = home
        .principal_home(&astrid_core::PrincipalId::default())
        .capsules_dir()
        .join("wit-store-test");
    let meta = read_meta(&installed).expect("meta.json exists after install");
    assert!(
        !meta.wit_files.is_empty(),
        "install must record wit_files pins"
    );

    // Each pinned file's bytes are retained in the store and re-hash to
    // the recorded pin.
    for (rel, hash) in &meta.wit_files {
        let blob = home.wit_store_dir().join(format!("{hash}.wit"));
        assert!(
            blob.exists(),
            "wit blob for {rel} must be retained at wit/store/{hash}.wit"
        );
        let bytes = std::fs::read(&blob).unwrap();
        assert_eq!(
            blake3::hash(&bytes).to_hex().to_string(),
            *hash,
            "retained blob for {rel} must re-hash to its recorded pin"
        );
    }

    // The store is a dedicated subdirectory — hash-named blobs live under
    // wit/store/, never at the top of wit/ (which is reserved for the
    // daemon's canonical named copies like astrid-contracts.wit).
    for hash in meta.wit_files.values() {
        assert!(
            !home.wit_dir().join(format!("{hash}.wit")).exists(),
            "content-addressed blob {hash}.wit must not leak to the top of wit/"
        );
    }
}

#[test]
fn install_succeeds_when_wit_store_unwritable() {
    // Retention is best-effort: an unwritable wit/store must NOT fail the
    // install. Pins are still recorded in meta.json; the bytes just aren't
    // retained this pass.
    let capsule_dir = tempfile::tempdir().unwrap();
    let base = capsule_dir.path();
    write_minimal_capsule(base, "store-ro-test", "1.0.0");
    std::fs::create_dir_all(base.join("wit")).unwrap();
    std::fs::write(
        base.join("wit/thing.wit"),
        "package astrid:thing;\ninterface thing {}\n",
    )
    .unwrap();

    let home_dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(home_dir.path());
    // Make wit/ a regular file so wit/store/ can never be created — a
    // portable stand-in for "the store is unwritable".
    std::fs::write(home.wit_dir(), b"not a directory").unwrap();

    install_from_local_path(base, &home, InstallOptions::default())
        .expect("install must succeed even when the WIT store is unwritable");

    let installed = home
        .principal_home(&astrid_core::PrincipalId::default())
        .capsules_dir()
        .join("store-ro-test");
    let meta = read_meta(&installed).expect("meta.json exists after install");
    assert!(
        !meta.wit_files.is_empty(),
        "pins must be recorded even when blob retention fails"
    );
}

#[test]
fn install_seeds_canonical_contracts_first_writer_wins() {
    use astrid_capsule_install::{ContractsSkew, canonical_contracts_path, contracts_skew};

    let home_dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(home_dir.path());

    // First capsule vendoring contracts seeds the daemon canonical.
    let cap_a = tempfile::tempdir().unwrap();
    write_minimal_capsule(cap_a.path(), "contracts-a", "1.0.0");
    std::fs::create_dir_all(cap_a.path().join("wit/deps/astrid-contracts")).unwrap();
    let contracts_a = "package astrid:contracts;\ninterface v1 {}\n";
    std::fs::write(
        cap_a
            .path()
            .join("wit/deps/astrid-contracts/astrid-contracts.wit"),
        contracts_a,
    )
    .unwrap();
    install_from_local_path(cap_a.path(), &home, InstallOptions::default())
        .expect("first install should succeed");

    let canonical = canonical_contracts_path(&home);
    assert_eq!(
        std::fs::read_to_string(&canonical).unwrap(),
        contracts_a,
        "first install must seed the daemon canonical astrid-contracts.wit"
    );

    // A second capsule pinning DIFFERENT contracts must not overwrite the
    // canonical (first-writer-wins) and must read as skewed against it.
    let cap_b = tempfile::tempdir().unwrap();
    write_minimal_capsule(cap_b.path(), "contracts-b", "1.0.0");
    std::fs::create_dir_all(cap_b.path().join("wit/deps/astrid-contracts")).unwrap();
    let contracts_b = "package astrid:contracts;\ninterface v2 {}\n";
    std::fs::write(
        cap_b
            .path()
            .join("wit/deps/astrid-contracts/astrid-contracts.wit"),
        contracts_b,
    )
    .unwrap();
    install_from_local_path(cap_b.path(), &home, InstallOptions::default())
        .expect("second install should still succeed despite skew");

    assert_eq!(
        std::fs::read_to_string(&canonical).unwrap(),
        contracts_a,
        "canonical must stay first-writer-wins across later installs"
    );
    // The ahead-of-canonical capsule reads as skewed against the baseline.
    let meta_b = read_meta(
        &home
            .principal_home(&astrid_core::PrincipalId::default())
            .capsules_dir()
            .join("contracts-b"),
    )
    .unwrap();
    assert!(
        contracts_skew(&home, &meta_b.wit_files).is_mismatch(),
        "the ahead-of-canonical capsule must read as skewed against the baseline"
    );

    // And the first capsule still reads as aligned.
    let meta_a = read_meta(
        &home
            .principal_home(&astrid_core::PrincipalId::default())
            .capsules_dir()
            .join("contracts-a"),
    )
    .unwrap();
    assert!(matches!(
        contracts_skew(&home, &meta_a.wit_files),
        ContractsSkew::Match { .. }
    ));
}

#[test]
fn install_detects_upgrade_preserves_installed_at() {
    let capsule_dir = tempfile::tempdir().unwrap();
    let base = capsule_dir.path();
    write_minimal_capsule(base, "upgrade-test", "1.0.0");

    let home_dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(home_dir.path());

    install_from_local_path(base, &home, InstallOptions::default()).expect("first install");
    let meta1 = read_meta(
        &home
            .principal_home(&astrid_core::PrincipalId::default())
            .capsules_dir()
            .join("upgrade-test"),
    )
    .unwrap();
    assert_eq!(meta1.version, "1.0.0");
    let original_installed_at = meta1.installed_at.clone();

    write_minimal_capsule(base, "upgrade-test", "2.0.0");
    install_from_local_path(base, &home, InstallOptions::default()).expect("upgrade");

    let meta2 = read_meta(
        &home
            .principal_home(&astrid_core::PrincipalId::default())
            .capsules_dir()
            .join("upgrade-test"),
    )
    .unwrap();
    assert_eq!(meta2.version, "2.0.0");
    assert_eq!(
        meta2.installed_at, original_installed_at,
        "installed_at must be preserved across upgrades"
    );
}
