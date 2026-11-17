//! Full-clone package inventory is independent of the tool grant list.

use super::*;
use astrid_capsule::capsule::CapsuleId;
use astrid_storage::StateOwner;
use std::future::Future as _;
use std::sync::OnceLock;
use std::task::{Context, Waker};
use tokio::sync::{Notify, Semaphore};

const ALIASES: [&str; 3] = [
    "clone-inventory-visible",
    "clone-copy-rollback",
    "clone-cleanup-failed",
];
static BARRIERS: [OnceLock<PublicationBarrier>; 3] = [const { OnceLock::new() }; 3];

struct PublicationBarrier {
    published: Notify,
    release: Semaphore,
}

pub(crate) async fn pause_after_profile_publication(principal: &PrincipalId) {
    if let Some(index) = ALIASES
        .iter()
        .position(|alias| *alias == principal.as_str())
        && let Some(barrier) = BARRIERS[index].get()
    {
        barrier.published.notify_one();
        barrier.release.acquire().await.unwrap().forget();
    }
}

fn seed_driver(kernel: &Kernel, source: &PrincipalId, name: &str) {
    let directory = kernel
        .astrid_home
        .run_dir()
        .join("clone-install-inputs")
        .join(name);
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(directory.join("Capsule.toml"), format!(
        "[package]\nname = \"{name}\"\nversion = \"1.0.0\"\n\n[[component]]\nid = \"main\"\nfile = \"main.wasm\"\n"
    )).unwrap();
    let wasm = wat::parse_str("(component)").unwrap();
    std::fs::write(directory.join("main.wasm"), &wasm).unwrap();
    let name =
        astrid_storage::ContentName::new(format!("bin/{}.wasm", blake3::hash(&wasm).to_hex()))
            .unwrap();
    kernel
        .principal_store
        .as_ref()
        .unwrap()
        .content()
        .put(&StateOwner::System, &name, &wasm)
        .unwrap();
    crate::capsule_adversarial_tests::publish_without_running_lifecycle(kernel, source, &directory)
        .unwrap();
}

async fn create_clone(kernel: &Arc<Kernel>, source: &PrincipalId, name: &str) -> AdminResponseBody {
    super::super::test_support::dispatch_as_operator(
        kernel,
        &PrincipalId::default(),
        AdminRequestKind::AgentCreate {
            name: name.into(),
            groups: Vec::new(),
            grants: Vec::new(),
            inherit_from: None,
            clone_from: Some(source.clone()),
            allow_admin_clone: true,
        },
    )
    .await
}

fn owner(kernel: &Kernel, principal: &PrincipalId) -> StateOwner {
    StateOwner::Principal(kernel.principal_directory.uid_for(principal).unwrap())
}

fn assert_package_copy(kernel: &Kernel, source: &PrincipalId, target: &PrincipalId, name: &str) {
    let registry = kernel.principal_store.as_ref().unwrap().capsules();
    let original = registry
        .get_snapshot(&owner(kernel, source), name)
        .unwrap()
        .unwrap();
    let copied = registry
        .get_snapshot(&owner(kernel, target), name)
        .unwrap()
        .unwrap();
    assert_eq!(original.package(), copied.package());
}

#[tokio::test(flavor = "multi_thread")]
async fn unrestricted_admin_clone_copies_installs_with_empty_acl_and_loads_after_reopen() {
    let (_directory, kernel) = fixture().await;
    let source = PrincipalId::default();
    let target = pid("clone-empty-admin-acl");
    let driver = "clone-admin-driver";
    let profile_path = PrincipalProfile::path_for(&kernel.astrid_home, &source);
    let source_bytes = std::fs::read(&profile_path).unwrap();
    let source_profile = PrincipalProfile::load_from_path(&profile_path).unwrap();
    assert!(source_profile.capsules.is_empty());
    seed_driver(&kernel, &source, driver);
    assert!(
        kernel
            .capsules
            .read()
            .await
            .get_for(&source, &CapsuleId::new(driver).unwrap())
            .is_none()
    );
    assert_success(&create_clone(&kernel, &source, target.as_str()).await);
    let copied =
        PrincipalProfile::load_from_path(&PrincipalProfile::path_for(&kernel.astrid_home, &target))
            .unwrap();
    assert!(copied.capsules.is_empty());
    assert_eq!(copied.groups, source_profile.groups);
    assert_ne!(copied.auth, source_profile.auth);
    assert_eq!(std::fs::read(profile_path).unwrap(), source_bytes);
    assert_package_copy(&kernel, &source, &target, driver);
    let resolver = astrid_capsule::CapsuleAccessResolver::new(
        Arc::clone(&kernel.profile_cache),
        Arc::clone(&kernel.groups),
    );
    assert!(resolver.is_capsule_allowed(Some(target.as_str()), &CapsuleId::new(driver).unwrap()));
    drop(resolver);
    let home = kernel.astrid_home.clone();
    let source_uid = kernel.principal_directory.uid_for(&source).unwrap();
    let target_uid = kernel.principal_directory.uid_for(&target).unwrap();
    let migration_path = home.migrations_dir().join("layout-v2-components.complete");
    let migration_history = std::fs::read(&migration_path).unwrap();
    kernel
        .shutdown(Some("clone package reopen regression".into()))
        .await;
    drop(kernel);
    let reopened = crate::test_kernel_with_home(home).await;
    assert_eq!(
        reopened.principal_directory.uid_for(&source).unwrap(),
        source_uid
    );
    assert_eq!(
        reopened.principal_directory.uid_for(&target).unwrap(),
        target_uid
    );
    assert_eq!(std::fs::read(migration_path).unwrap(), migration_history);
    let id = CapsuleId::new(driver).unwrap();
    assert_package_copy(&reopened, &source, &target, driver);
    assert!(
        reopened
            .capsules
            .read()
            .await
            .get_for(&target, &id)
            .is_none()
    );
    // This is the first checked demand after reopening, without warming or a
    // retry. It must discover the durable package despite the empty tool ACL.
    reopened
        .ensure_principal_capsules_ready(&target, &[driver.into()])
        .await
        .unwrap();
    assert!(
        reopened
            .capsules
            .read()
            .await
            .get_for(&target, &id)
            .is_some()
    );
    reopened
        .shutdown(Some("clone package regression complete".into()))
        .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn restricted_clone_copies_ungranted_installs_without_widening_dispatch_access() {
    let (_directory, kernel) = fixture().await;
    let source = pid("clone-restricted-source");
    let target = pid("clone-restricted-target");
    let mut profile = PrincipalProfile {
        groups: vec![BUILTIN_RESTRICTED.into()],
        capsules: vec!["allowed-driver".into()],
        ..Default::default()
    };
    profile.grants = vec!["self:capsule:list".into()];
    profile.revokes = vec!["self:quota:set".into()];
    profile.quotas.max_background_processes = 7;
    let path = PrincipalProfile::path_for(&kernel.astrid_home, &source);
    profile.save_to_path(&path).unwrap();
    let source_bytes = std::fs::read(&path).unwrap();
    kernel
        .identity_store
        .create_principal(source.clone(), [8; 32])
        .await
        .unwrap();
    seed_driver(&kernel, &source, "allowed-driver");
    seed_driver(&kernel, &source, "internal-driver");
    assert_success(&create_clone(&kernel, &source, target.as_str()).await);
    let copied =
        PrincipalProfile::load_from_path(&PrincipalProfile::path_for(&kernel.astrid_home, &target))
            .unwrap();
    let mut expected = serde_json::to_value(&profile).unwrap();
    let mut actual = serde_json::to_value(&copied).unwrap();
    // Identity is minted separately; all policy fields retain their exact values.
    expected.as_object_mut().unwrap().remove("auth");
    actual.as_object_mut().unwrap().remove("auth");
    assert_eq!(actual, expected);
    assert_eq!(std::fs::read(&path).unwrap(), source_bytes);
    for driver in ["allowed-driver", "internal-driver"] {
        assert_package_copy(&kernel, &source, &target, driver);
    }
    let resolver = astrid_capsule::CapsuleAccessResolver::new(
        Arc::clone(&kernel.profile_cache),
        Arc::clone(&kernel.groups),
    );
    assert!(resolver.is_capsule_allowed(
        Some(target.as_str()),
        &CapsuleId::new("allowed-driver").unwrap()
    ));
    assert!(!resolver.is_capsule_allowed(
        Some(target.as_str()),
        &CapsuleId::new("internal-driver").unwrap()
    ));
    assert!(!resolver.is_capsule_allowed(
        Some("unrelated"),
        &CapsuleId::new("internal-driver").unwrap()
    ));
    drop(resolver);
    kernel
        .shutdown(Some("restricted clone regression complete".into()))
        .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn clone_rejects_active_install_before_identity_or_profile_publication() {
    let (_directory, kernel) = fixture().await;
    let fence = Arc::clone(&kernel.env_install_fence).write_owned().await;
    let target = pid("clone-busy-installer");
    let response = create_clone(&kernel, &PrincipalId::default(), target.as_str()).await;
    drop(fence);
    assert_error_contains(&response, "capsule install in progress");
    assert!(!PrincipalProfile::path_for(&kernel.astrid_home, &target).exists());
    assert!(kernel.principal_directory.uid_for(&target).is_err());
}

async fn paused_clone(
    kernel: &Arc<Kernel>,
    index: usize,
) -> tokio::task::JoinHandle<AdminResponseBody> {
    assert!(
        BARRIERS[index]
            .set(PublicationBarrier {
                published: Notify::new(),
                release: Semaphore::new(0)
            })
            .is_ok()
    );
    let cloned = Arc::clone(kernel);
    let mut task = tokio::spawn(async move {
        create_clone(&cloned, &PrincipalId::default(), ALIASES[index]).await
    });
    tokio::select! {
        () = BARRIERS[index].get().unwrap().published.notified() => {},
        response = &mut task => panic!("clone ended before publication barrier: {response:?}"),
    }
    task
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn clone_locks_actual_empty_acl_inventory_before_profile_visibility() {
    let (_directory, kernel) = fixture().await;
    seed_driver(&kernel, &PrincipalId::default(), "inventory-locked-driver");
    let task = paused_clone(&kernel, 0).await;
    let target = pid(ALIASES[0]);
    let id = CapsuleId::new("inventory-locked-driver").unwrap();
    let mut view = Box::pin(kernel.lock_capsule_view(&target, &id));
    let blocked = view
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending();
    drop(view);
    let install_blocked = kernel.env_install_fence.try_write().is_err();
    BARRIERS[0].get().unwrap().release.add_permits(1);
    let response = task.await.unwrap();
    assert_success(&response);
    assert!(
        blocked,
        "actual copied package was not fenced before profile publication"
    );
    assert!(
        install_blocked,
        "source inventory was not pinned against concurrent install"
    );
    assert_package_copy(&kernel, &PrincipalId::default(), &target, id.as_str());
    kernel
        .shutdown(Some("clone initialization regression complete".into()))
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn clone_partial_copy_error_reclaims_packages_identity_profile_and_assignment() {
    let (_directory, kernel) = fixture().await;
    let source = PrincipalId::default();
    seed_driver(&kernel, &source, "a-copied-driver");
    seed_driver(&kernel, &source, "z-missing-driver");
    let task = paused_clone(&kernel, 1).await;
    let target = pid(ALIASES[1]);
    let target_owner = owner(&kernel, &target);
    // Inject a storage-level failure after inventory capture, outside the
    // supported install/remove routes whose locks the previous test checks.
    kernel
        .principal_store
        .as_ref()
        .unwrap()
        .capsules()
        .remove(&owner(&kernel, &source), "z-missing-driver")
        .unwrap();
    BARRIERS[1].get().unwrap().release.add_permits(1);
    let response = task.await.unwrap();
    assert_error_contains(
        &response,
        "source capsule 'z-missing-driver' is not installed",
    );
    assert!(!PrincipalProfile::path_for(&kernel.astrid_home, &target).exists());
    assert!(kernel.principal_directory.uid_for(&target).is_err());
    assert!(
        kernel
            .principal_store
            .as_ref()
            .unwrap()
            .capsules()
            .list(&target_owner)
            .unwrap()
            .is_empty()
    );
    let StateOwner::Principal(uid) = target_owner else {
        panic!("principal owner expected")
    };
    assert!(
        kernel
            .ownership_store
            .load()
            .await
            .unwrap()
            .principal_owner(uid)
            .is_none()
    );
    assert!(
        kernel
            .capsules
            .read()
            .await
            .cloned_values_for(&target)
            .is_empty()
    );
    kernel
        .shutdown(Some("clone rollback regression complete".into()))
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_clone_cleanup_keeps_alias_reserved_and_reports_both_failures() {
    let (_directory, kernel) = fixture().await;
    let source = PrincipalId::default();
    seed_driver(&kernel, &source, "broken-driver");
    let task = paused_clone(&kernel, 2).await;
    let target = pid(ALIASES[2]);
    let target_uid = kernel.principal_directory.uid_for(&target).unwrap();
    let name = astrid_storage::ContentName::new("capsules/broken-driver/meta.json").unwrap();
    // Malformed package state makes both publication and rollback enumeration
    // fail. Retaining the exact UID reservation is safer than reusing the alias
    // while its old package catalog cannot be proved reclaimed.
    kernel
        .principal_store
        .as_ref()
        .unwrap()
        .content()
        .put(&StateOwner::Principal(target_uid), &name, b"incomplete")
        .unwrap();
    BARRIERS[2].get().unwrap().release.add_permits(1);
    let response = task.await.unwrap();
    assert_error_contains(&response, "read target capsule 'broken-driver'");
    assert_error_contains(&response, "list durable capsule packages");
    assert_error_contains(&response, "rollback could not complete");
    assert_eq!(
        kernel.principal_directory.uid_for(&target).unwrap(),
        target_uid
    );
    assert!(PrincipalProfile::path_for(&kernel.astrid_home, &target).exists());
    assert!(
        kernel
            .ownership_store
            .ensure_alias_available(&target)
            .await
            .is_err()
    );
    assert!(kernel.capabilities.is_principal_retiring(&target).await);
    assert!(
        kernel
            .capsules
            .read()
            .await
            .cloned_values_for(&target)
            .is_empty()
    );
    kernel
        .shutdown(Some("failed clone cleanup regression complete".into()))
        .await;
}
