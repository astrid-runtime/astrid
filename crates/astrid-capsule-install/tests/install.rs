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

#[test]
fn install_bakes_topic_schema_into_meta() {
    let capsule_dir = tempfile::tempdir().unwrap();
    let base = capsule_dir.path();
    std::fs::create_dir_all(base.join("schemas")).unwrap();
    std::fs::write(
        base.join("schemas/chunk.json"),
        r#"{"type":"object","properties":{"content":{"type":"string"}}}"#,
    )
    .unwrap();
    std::fs::write(
        base.join("Capsule.toml"),
        "[package]\nname = \"topic-test\"\nversion = \"1.0.0\"\n\n\
         [[topic]]\nname = \"llm.v1.chunk\"\ndirection = \"publish\"\n\
         description = \"Streaming chunk\"\nschema = \"schemas/chunk.json\"\n\n\
         [[topic]]\nname = \"llm.v1.request\"\ndirection = \"subscribe\"\n",
    )
    .unwrap();

    let home_dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(home_dir.path());
    install_from_local_path(base, &home, InstallOptions::default())
        .expect("install should succeed");

    let installed = home
        .principal_home(&astrid_core::PrincipalId::default())
        .capsules_dir()
        .join("topic-test");
    let meta = read_meta(&installed).expect("meta.json should exist");
    assert_eq!(meta.topics.len(), 2);
    assert_eq!(meta.topics[0].name, "llm.v1.chunk");
    assert_eq!(
        meta.topics[0].direction,
        astrid_capsule::manifest::TopicDirection::Publish
    );
    assert!(meta.topics[0].schema.is_some());
    assert_eq!(meta.topics[1].name, "llm.v1.request");
    assert!(meta.topics[1].schema.is_none());
}

#[test]
fn install_fails_on_missing_schema_file() {
    let capsule_dir = tempfile::tempdir().unwrap();
    let base = capsule_dir.path();
    std::fs::write(
        base.join("Capsule.toml"),
        "[package]\nname = \"missing-schema\"\nversion = \"1.0.0\"\n\n\
         [[topic]]\nname = \"foo.bar\"\ndirection = \"publish\"\n\
         schema = \"schemas/nonexistent.json\"\n",
    )
    .unwrap();

    let home_dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(home_dir.path());
    let err = install_from_local_path(base, &home, InstallOptions::default())
        .expect_err("install should fail with missing schema");
    let msg = format!("{err:#}");
    assert!(msg.contains("schema file not found") || msg.contains("No such file"));
}

#[test]
fn install_fails_on_invalid_json_schema() {
    let capsule_dir = tempfile::tempdir().unwrap();
    let base = capsule_dir.path();
    std::fs::write(base.join("bad.json"), "not valid json {{{").unwrap();
    std::fs::write(
        base.join("Capsule.toml"),
        "[package]\nname = \"bad-json\"\nversion = \"1.0.0\"\n\n\
         [[topic]]\nname = \"foo.bar\"\ndirection = \"publish\"\n\
         schema = \"bad.json\"\n",
    )
    .unwrap();

    let home_dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(home_dir.path());
    let err = install_from_local_path(base, &home, InstallOptions::default())
        .expect_err("install should fail with invalid JSON");
    let msg = format!("{err:#}");
    assert!(msg.contains("invalid JSON"));
}

#[test]
fn install_no_topics_backwards_compat() {
    let capsule_dir = tempfile::tempdir().unwrap();
    let base = capsule_dir.path();
    write_minimal_capsule(base, "no-topics", "1.0.0");

    let home_dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(home_dir.path());
    install_from_local_path(base, &home, InstallOptions::default())
        .expect("install should succeed");

    let installed = home
        .principal_home(&astrid_core::PrincipalId::default())
        .capsules_dir()
        .join("no-topics");
    let meta = read_meta(&installed).expect("meta.json should exist");
    assert!(meta.topics.is_empty());
}
