use crate::capsule_adversarial_tests::{
    durable_target, publish_component_source, scratch_home, seed_isolated_principal,
    write_component_source,
};
use astrid_core::PrincipalId;
use std::os::unix::fs::MetadataExt as _;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn copied_owner_projection_preserves_exact_authority_and_independent_writes() {
    let (_temporary, home) = scratch_home();
    let kernel = crate::test_kernel_with_home(home.clone()).await;
    let default = PrincipalId::default();
    let peer = seed_isolated_principal(&kernel, &home, "clone-peer", [71; 32]).await;
    let source = tempfile::tempdir().unwrap();
    let wasm = write_component_source(source.path(), "copied-projection", None);
    let parent_package = publish_component_source(&kernel, &default, source.path(), None).unwrap();
    let parent = durable_target(&kernel, &default, &parent_package, "copied-projection");
    astrid_capsule_install::materialize_capsule_package(&parent_package, &parent).unwrap();
    let package = publish_component_source(&kernel, &peer, source.path(), None).unwrap();
    let target = durable_target(&kernel, &peer, &package, "copied-projection");
    let owner =
        astrid_storage::StateOwner::Principal(kernel.principal_directory.uid_for(&peer).unwrap());
    let snapshot = kernel
        .principal_store
        .as_ref()
        .unwrap()
        .capsules()
        .get_snapshot(&owner, "copied-projection")
        .unwrap()
        .unwrap();
    let manifest = astrid_capsule::discovery::load_manifest(&parent.join("Capsule.toml")).unwrap();
    assert!(
        kernel
            .copy_published_projection(&target, &peer, &manifest, &snapshot)
            .unwrap()
            .is_some()
    );
    kernel
        .verify_published_materialization(&target, &peer, &manifest, &snapshot)
        .unwrap();
    assert!(
        kernel
            .copy_published_projection(&parent, &default, &manifest, &snapshot)
            .unwrap()
            .is_none()
    );
    assert!(
        kernel
            .copy_published_projection(&target, &peer, &manifest, &snapshot)
            .is_err()
    );
    kernel
        .verify_published_materialization(&target, &peer, &manifest, &snapshot)
        .unwrap();

    assert_eq!(
        std::fs::read(target.join("meta.json")).unwrap(),
        package.metadata
    );
    assert_eq!(
        std::fs::read(target.join("authority.json")).unwrap(),
        package.authority
    );
    assert_ne!(
        std::fs::metadata(parent.join("main.wasm")).unwrap().ino(),
        std::fs::metadata(target.join("main.wasm")).unwrap().ino()
    );
    std::fs::write(target.join("main.wasm"), b"target mutation").unwrap();
    assert_eq!(std::fs::read(parent.join("main.wasm")).unwrap(), wasm);
    std::fs::write(parent.join("main.wasm"), b"source mutation").unwrap();
    assert_eq!(
        std::fs::read(target.join("main.wasm")).unwrap(),
        b"target mutation"
    );
    assert!(
        kernel
            .verify_published_materialization(&target, &peer, &manifest, &snapshot)
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn damaged_copy_sources_never_publish_and_canonical_repair_still_succeeds() {
    for symlink in [false, true] {
        let (_temporary, home) = scratch_home();
        let kernel = crate::test_kernel_with_home(home.clone()).await;
        let default = PrincipalId::default();
        let peer = seed_isolated_principal(&kernel, &home, "damaged-clone-peer", [72; 32]).await;
        let source = tempfile::tempdir().unwrap();
        let wasm = write_component_source(source.path(), "damaged-copy-projection", None);
        let package = publish_component_source(&kernel, &default, source.path(), None).unwrap();
        let parent = durable_target(&kernel, &default, &package, "damaged-copy-projection");
        astrid_capsule_install::materialize_capsule_package(&package, &parent).unwrap();
        let package = publish_component_source(&kernel, &peer, source.path(), None).unwrap();
        let target = durable_target(&kernel, &peer, &package, "damaged-copy-projection");
        let owner = astrid_storage::StateOwner::Principal(
            kernel.principal_directory.uid_for(&peer).unwrap(),
        );
        let snapshot = kernel
            .principal_store
            .as_ref()
            .unwrap()
            .capsules()
            .get_snapshot(&owner, "damaged-copy-projection")
            .unwrap()
            .unwrap();
        let manifest =
            astrid_capsule::discovery::load_manifest(&parent.join("Capsule.toml")).unwrap();
        if symlink {
            std::fs::remove_file(parent.join("main.wasm")).unwrap();
            std::os::unix::fs::symlink(source.path().join("main.wasm"), parent.join("main.wasm"))
                .unwrap();
        } else {
            let mut forged = wasm.clone();
            forged[0] ^= 1;
            std::fs::write(parent.join("main.wasm"), forged).unwrap();
        }
        // APFS must reject mismatched cloned bytes. A non-cloning filesystem
        // may safely construct canonical bytes instead; neither trusts source.
        match kernel.copy_published_projection(&target, &peer, &manifest, &snapshot) {
            Err(_) => assert!(!target.exists()),
            Ok(Some(_)) => kernel
                .verify_published_materialization(&target, &peer, &manifest, &snapshot)
                .unwrap(),
            Ok(None) => panic!("existing source must be considered"),
        }
        kernel
            .repair_published_materialization(&target, &peer, &manifest, &snapshot)
            .unwrap();
        assert_eq!(std::fs::read(target.join("main.wasm")).unwrap(), wasm);
        assert_eq!(
            std::fs::read(target.join("authority.json")).unwrap(),
            package.authority
        );
        kernel
            .verify_published_materialization(&target, &peer, &manifest, &snapshot)
            .unwrap();
    }
}
