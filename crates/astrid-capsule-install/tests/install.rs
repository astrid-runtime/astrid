//! End-to-end install tests against a temp `AstridHome`.
//!
//! These exercise the path the kernel-side install handler and the
//! CLI's `install_from_local_path` both reach into. The behaviours
//! verified here used to live as `#[cfg(test)] mod tests` blocks
//! inside `astrid-cli/src/commands/capsule/install.rs`; they followed
//! the install machinery into this crate when it was extracted.

use std::sync::Arc;

#[cfg(windows)]
use astrid_capsule_install::{
    AuthorityDecision, inspect_directory_for_principal_in_workspace,
    install_from_local_path_authorized_for_principal_in_workspace,
};
use astrid_capsule_install::{
    InstallOptions, VerifiedDurableCapsulePackage, copy_capsule_dir, install_from_local_path,
    read_durable_meta, read_verified_durable_package,
};
#[cfg(windows)]
use astrid_core::PrincipalId;
use astrid_core::dirs::AstridHome;
#[cfg(windows)]
use astrid_core::dirs::WorkspaceLayout;
use astrid_core::identity::PrincipalUid;
use astrid_storage::{
    KvQuotaResolver, PrincipalDirectory, RuntimePrincipalStore, StateOwner,
    open_runtime_principal_store_with_directory,
};

fn install_store(home: &AstridHome) -> Arc<RuntimePrincipalStore> {
    let principal = astrid_capsule_install::paths::install_principal();
    let directory = PrincipalDirectory::default();
    let uid = PrincipalUid::from_bytes([0x44; 32]);
    directory.register(principal.clone(), uid).unwrap();
    let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|owner: &StateOwner| {
        Ok(match owner {
            StateOwner::System => None,
            StateOwner::Principal(_) | StateOwner::Fleet(_) => Some(u64::MAX),
        })
    });
    let store = Arc::new(
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(open_runtime_principal_store_with_directory(
                home, quota, directory,
            ))
            .unwrap(),
    );
    store
        .principal_directory()
        .register(principal, uid)
        .unwrap();
    store
}

fn install_options(storage: &Arc<RuntimePrincipalStore>) -> InstallOptions {
    InstallOptions {
        storage: Some(Arc::clone(storage)),
        ..Default::default()
    }
}

fn durable_package(
    storage: &RuntimePrincipalStore,
    capsule_id: &str,
) -> VerifiedDurableCapsulePackage {
    let uid = storage
        .principal_directory()
        .uid_for(&astrid_capsule_install::paths::install_principal())
        .unwrap();
    read_verified_durable_package(storage, uid, capsule_id)
        .unwrap()
        .unwrap_or_else(|| panic!("durable package {capsule_id} is missing"))
}

fn write_minimal_capsule(base: &std::path::Path, name: &str, version: &str) {
    std::fs::write(
        base.join("Capsule.toml"),
        format!("[package]\nname = \"{name}\"\nversion = \"{version}\"\n"),
    )
    .unwrap();
}

#[test]
fn storage_install_publishes_wasm_to_system_catalog() {
    let capsule_dir = tempfile::tempdir().unwrap();
    let bytes = wat::parse_str("(component)").unwrap();
    std::fs::write(
        capsule_dir.path().join("Capsule.toml"),
        "[package]\nname = \"install-catalog\"\nversion = \"1.0.0\"\n\n[[component]]\nid = \"main\"\nfile = \"main.wasm\"\n",
    )
    .unwrap();
    std::fs::write(capsule_dir.path().join("main.wasm"), &bytes).unwrap();

    let home_dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(home_dir.path());
    let storage = install_store(&home);
    install_from_local_path(capsule_dir.path(), &home, install_options(&storage))
        .expect("storage-backed install should publish WASM");

    let hash = blake3::hash(&bytes).to_hex().to_string();
    let name = astrid_storage::ContentName::new(format!("bin/{hash}.wasm")).unwrap();
    let descriptor = storage
        .content()
        .describe(&StateOwner::System, &name)
        .unwrap()
        .expect("system catalog WASM entry");
    let catalog_bytes = storage
        .content()
        .read_range(&StateOwner::System, &name, 0, descriptor.logical_bytes())
        .unwrap()
        .expect("system catalog WASM bytes");

    assert_eq!(catalog_bytes, bytes);
    assert!(
        !home.bin_dir().join(format!("{hash}.wasm")).exists(),
        "storage-backed install must not create a second durable POSIX WASM store"
    );
}

#[cfg(windows)]
struct FreshWindowsHome {
    path: std::path::PathBuf,
}

#[cfg(windows)]
impl FreshWindowsHome {
    fn new() -> Self {
        let runtime_root = astrid_core::platform_fs::default_astrid_home_root()
            .expect("resolve Windows LocalAppData");
        let local_app_data = runtime_root
            .parent()
            .and_then(std::path::Path::parent)
            .expect("Astrid runtime root is below Windows LocalAppData");
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let path = local_app_data.join(format!("AstTest-{}", &suffix[..16]));
        assert!(!path.exists(), "fresh test home must not exist");
        Self { path }
    }
}

#[cfg(windows)]
impl Drop for FreshWindowsHome {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[cfg(windows)]
#[test]
fn user_install_uses_initialized_fresh_private_windows_home() {
    let capsule_dir = tempfile::tempdir().unwrap();
    write_minimal_capsule(capsule_dir.path(), "fresh-windows-home-test", "1.0.0");
    let fresh = FreshWindowsHome::new();
    let home = AstridHome::from_path(&fresh.path);
    home.ensure()
        .expect("fresh Windows install home should be initialized before storage opens");
    let storage = install_store(&home);

    let output = install_from_local_path(capsule_dir.path(), &home, install_options(&storage))
        .expect("fresh Windows user install should use its private home");

    assert!(output.target_dir.join("Capsule.toml").is_file());
    assert!(
        durable_package(&storage, "fresh-windows-home-test")
            .manifest()
            .package
            .name
            == "fresh-windows-home-test"
    );
}

#[cfg(windows)]
#[test]
fn inspected_user_install_uses_initialized_fresh_private_windows_home() {
    let capsule_dir = tempfile::tempdir().unwrap();
    std::fs::write(
        capsule_dir.path().join("Capsule.toml"),
        "[package]\nname = \"fresh-inspected-home-test\"\nversion = \"1.0.0\"\n\
         [exports.astrid]\nidentity = \"1.0.0\"\n",
    )
    .unwrap();
    let fresh = FreshWindowsHome::new();
    let home = AstridHome::from_path(&fresh.path);
    home.ensure()
        .expect("fresh Windows inspection home should be initialized before storage opens");
    let storage = install_store(&home);
    let principal = PrincipalId::default();
    let layout = WorkspaceLayout::default();
    // This regression targets fresh user-home provisioning. Workspace-root
    // validation is covered separately and must keep failing closed.
    let workspace_root = None;

    let inspection = inspect_directory_for_principal_in_workspace(
        capsule_dir.path(),
        &home,
        &principal,
        false,
        workspace_root,
        &layout,
    )
    .expect("inspection should use the private runtime identity");
    let decision = AuthorityDecision::ExplicitApproval {
        content_digest: inspection.content_digest,
    };
    let output = install_from_local_path_authorized_for_principal_in_workspace(
        capsule_dir.path(),
        &home,
        install_options(&storage),
        &principal,
        workspace_root,
        &decision,
        &layout,
    )
    .expect("authorized install should scan and provision the private principal home");

    assert!(output.target_dir.join("Capsule.toml").is_file());
    assert_eq!(
        durable_package(&storage, "fresh-inspected-home-test")
            .manifest()
            .package
            .name,
        "fresh-inspected-home-test"
    );
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
    let storage = install_store(&home);
    let output = install_from_local_path(base, &home, install_options(&storage))
        .expect("install should succeed");

    let installed = output.target_dir;
    assert!(installed.join("Capsule.toml").exists());
    assert!(installed.join("node_modules/got/index.js").exists());
    assert!(installed.join("package.json").exists());
    assert!(installed.join("src/index.js").exists());
    assert!(
        !home.etc_dir().join("capsule-authority").exists(),
        "storage-backed installs keep authority only in the durable package"
    );
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
    let storage = install_store(&home);
    let output = install_from_local_path(base, &home, install_options(&storage))
        .expect("install must not bail on symlinks");

    let installed = output.target_dir;
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
    let storage = install_store(&home);
    let output = install_from_local_path(base, &home, install_options(&storage))
        .expect("install should succeed");

    let package = durable_package(&storage, "meta-test");
    let meta = package.metadata();
    assert_eq!(meta.version, "2.0.0");
    assert!(output.target_dir.join("meta.json").is_file());
}

#[test]
fn install_materializes_home_wit_mirror() {
    // WIT is authoritative in the UID-owned durable package. The native
    // cache is only a disposable materialization and must not be consulted.
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
    let storage = install_store(&home);
    install_from_local_path(base, &home, install_options(&storage))
        .expect("install should succeed");

    let package = durable_package(&storage, "wit-mirror-test");
    assert_eq!(package.wit_file("broker.wit"), Some(broker_src.as_bytes()));
    assert_eq!(
        package.wit_file("deps/astrid-contracts/astrid-contracts.wit"),
        Some(contracts_src.as_bytes())
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
    let storage = install_store(&home);

    install_from_local_path(base, &home, install_options(&storage)).expect("first install");
    let first = durable_package(&storage, "wit-idem-test");
    assert_eq!(first.wit_file("idem.wit"), Some(src.as_bytes()));

    // Second install (same bytes) must not error and must leave the same
    // durable package content.
    install_from_local_path(base, &home, install_options(&storage)).expect("re-install");
    let second = durable_package(&storage, "wit-idem-test");
    assert_eq!(second.wit_file("idem.wit"), Some(src.as_bytes()));
    assert_eq!(first.archive(), second.archive());
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
    let storage = install_store(&home);
    install_from_local_path(base, &home, install_options(&storage))
        .expect("install should succeed");

    let package = durable_package(&storage, "wit-store-test");
    let meta = package.metadata();
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
    let storage = install_store(&home);
    // Make wit/ a regular file so wit/store/ can never be created — a
    // portable stand-in for "the store is unwritable".
    std::fs::write(home.wit_dir(), b"not a directory").unwrap();

    install_from_local_path(base, &home, install_options(&storage))
        .expect("install must succeed even when the WIT store is unwritable");

    let package = durable_package(&storage, "store-ro-test");
    let meta = package.metadata();
    assert!(
        !meta.wit_files.is_empty(),
        "pins must be recorded even when blob retention fails"
    );
}

#[test]
fn install_persists_contracts_in_the_durable_registry() {
    let home_dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(home_dir.path());
    let storage = install_store(&home);

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
    install_from_local_path(cap_a.path(), &home, install_options(&storage))
        .expect("first install should succeed");

    let package_a = durable_package(&storage, "contracts-a");
    assert_eq!(
        package_a.wit_file("deps/astrid-contracts/astrid-contracts.wit"),
        Some(contracts_a.as_bytes()),
        "the first package must retain its exact contracts bytes"
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
    install_from_local_path(cap_b.path(), &home, install_options(&storage))
        .expect("second install should still succeed despite skew");

    let package_b = durable_package(&storage, "contracts-b");
    assert!(
        package_b
            .wit_file("deps/astrid-contracts/astrid-contracts.wit")
            .is_some_and(|bytes| bytes == contracts_b.as_bytes()),
        "the second package must retain its own contracts bytes"
    );
    assert_ne!(
        package_a.snapshot().package().archive,
        package_b.snapshot().package().archive
    );
    assert!(
        !home
            .principal_home(&astrid_capsule_install::paths::install_principal())
            .root()
            .exists()
    );
}

#[test]
fn install_detects_upgrade_preserves_installed_at() {
    let capsule_dir = tempfile::tempdir().unwrap();
    let base = capsule_dir.path();
    write_minimal_capsule(base, "upgrade-test", "1.0.0");

    let home_dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(home_dir.path());
    let storage = install_store(&home);

    install_from_local_path(base, &home, install_options(&storage)).expect("first install");
    let meta1 = read_durable_meta(
        &storage,
        &astrid_capsule_install::paths::install_principal(),
        "upgrade-test",
    )
    .unwrap()
    .unwrap();
    assert_eq!(meta1.version, "1.0.0");
    let original_installed_at = meta1.installed_at.clone();

    write_minimal_capsule(base, "upgrade-test", "2.0.0");
    install_from_local_path(base, &home, install_options(&storage)).expect("upgrade");

    let meta2 = read_durable_meta(
        &storage,
        &astrid_capsule_install::paths::install_principal(),
        "upgrade-test",
    )
    .unwrap()
    .unwrap();
    assert_eq!(meta2.version, "2.0.0");
    assert_eq!(
        meta2.installed_at, original_installed_at,
        "installed_at must be preserved across upgrades"
    );
}
