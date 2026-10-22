use astrid_core::PrincipalId;
use astrid_core::dirs::AstridHome;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn load_capsule_uses_catalog_when_native_wasm_projection_is_absent() {
    let directory = tempfile::tempdir().expect("test home");
    let home = AstridHome::from_path(directory.path());
    let kernel = crate::test_kernel_with_home(home.clone()).await;
    let principal = PrincipalId::default();
    let capsule_dir = kernel
        .workspace_selection
        .state_dir()
        .join("capsules/catalog-authority");
    std::fs::create_dir_all(&capsule_dir).expect("capsule directory");
    std::fs::write(
        capsule_dir.join("Capsule.toml"),
        "[package]\nname = \"catalog-authority\"\nversion = \"1.0.0\"\n\n[[component]]\nid = \"main\"\nfile = \"component.wasm\"\n",
    )
    .expect("manifest");
    let wasm = wat::parse_str("(component)").expect("valid component");
    let hash = blake3::hash(&wasm).to_hex().to_string();
    std::fs::write(capsule_dir.join("component.wasm"), &wasm).expect("component");
    astrid_capsule_install::write_meta(
        &capsule_dir,
        &astrid_capsule_install::CapsuleMeta {
            version: "1.0.0".to_owned(),
            wasm_hash: Some(hash.clone()),
            ..Default::default()
        },
    )
    .expect("metadata");

    let manifest = astrid_capsule::discovery::load_manifest(&capsule_dir.join("Capsule.toml"))
        .expect("manifest loads");
    let store = kernel
        .principal_store
        .as_ref()
        .expect("test kernel principal store")
        .clone();
    let name = astrid_storage::ContentName::new(format!("bin/{hash}.wasm")).expect("catalog name");
    store
        .content()
        .put(&astrid_storage::StateOwner::System, &name, &wasm)
        .expect("catalog bytes");
    astrid_capsule_install::verify_installed_authority_with_store(
        &home,
        &capsule_dir,
        &manifest,
        &store,
    )
    .expect("catalog-backed authority receipt");

    // The materialized component and the legacy host projection are both
    // disposable. A bound kernel load must still succeed from System/bin.
    std::fs::remove_file(capsule_dir.join("component.wasm")).expect("remove projection");
    assert!(!home.bin_dir().join(format!("{hash}.wasm")).exists());

    crate::Kernel::load_capsule(&kernel, capsule_dir, &principal)
        .await
        .expect("catalog-backed capsule load");
}
