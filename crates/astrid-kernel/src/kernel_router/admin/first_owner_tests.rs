//! A native fresh boot authenticates devices without inventing user authority.

use std::{
    collections::HashMap,
    process::Stdio,
    sync::Arc,
    time::{Duration, Instant},
};

use astrid_core::{PrincipalId, PrincipalProfile};
use astrid_events::kernel_api::{AdminRequestKind, AdminResponseBody};

use super::handlers;
use crate::Kernel;

fn create(name: &str) -> AdminRequestKind {
    AdminRequestKind::AgentCreate {
        name: name.into(),
        groups: Vec::new(),
        grants: Vec::new(),
        inherit_from: None,
        clone_from: None,
        allow_admin_clone: false,
    }
}

async fn assert_fresh_mutations_denied(kernel: &Arc<Kernel>) {
    let caller = PrincipalId::default();
    let target = PrincipalId::new("unenrolled-existing").unwrap();
    // Admitted identity/profile models a preinstalled principal. It confers
    // neither a human owner nor a fleet, even when the CLI has admin caps.
    let key = astrid_crypto::KeyPair::generate();
    let user = kernel
        .identity_store
        .create_principal(target.clone(), *key.public_key_bytes())
        .await
        .unwrap();
    let profile_path = PrincipalProfile::path_for(&kernel.astrid_home, &target);
    PrincipalProfile::default()
        .save_to_path(&profile_path)
        .unwrap();
    let profile_before = std::fs::read(&profile_path).unwrap();
    let graph_before = kernel.ownership_store.load().await.unwrap();
    let uid_before = kernel.principal_directory.uid_for(&target).unwrap();
    let bindings_before = kernel.principal_directory.bindings();
    let identity_before = kernel
        .identity_store
        .get_principal_identity(user.id)
        .await
        .unwrap();
    let mut users_before = kernel.identity_store.list_users().await.unwrap();
    users_before.sort_by_key(|user| user.id);
    let caller_profile = PrincipalProfile::load(&kernel.astrid_home, &caller).unwrap();
    let device = &caller_profile.auth.public_keys[0];

    for (request, expected) in [
        (create("unenrolled-new"), "current user delegation"),
        (
            AdminRequestKind::UserPrincipalClaim {
                principal: target.clone(),
            },
            "current user delegation",
        ),
        (
            AdminRequestKind::AgentDelete {
                principal: target.clone(),
            },
            "ownership mutation requires an enrolled authority",
        ),
    ] {
        let response =
            handlers::dispatch_with_device(kernel, &caller, Some(&device.key_id), request).await;
        assert!(
            matches!(response, AdminResponseBody::Error(ref error) if error.contains(expected)),
            "registered admin device must fail without enrollment: {response:?}"
        );
        assert_eq!(kernel.ownership_store.load().await.unwrap(), graph_before);
        assert_eq!(kernel.principal_directory.bindings(), bindings_before);
        assert_eq!(
            kernel.principal_directory.uid_for(&target).unwrap(),
            uid_before
        );
        assert_eq!(std::fs::read(&profile_path).unwrap(), profile_before);
        assert_eq!(
            kernel
                .identity_store
                .get_principal_identity(user.id)
                .await
                .unwrap(),
            identity_before
        );
        let mut users_after = kernel.identity_store.list_users().await.unwrap();
        users_after.sort_by_key(|user| user.id);
        assert_eq!(users_after, users_before);
        assert!(
            kernel
                .identity_store
                .resolve("cli", "unenrolled-new")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            !kernel
                .astrid_home
                .keys_dir()
                .join("unenrolled-new.key")
                .exists()
        );
        assert!(
            !PrincipalProfile::path_for(
                &kernel.astrid_home,
                &PrincipalId::new("unenrolled-new").unwrap(),
            )
            .exists()
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_fresh_admin_device_cannot_create_claim_or_delete() {
    const CHILD: &str = "ASTRID_FIRST_OWNER_ADMIN_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let kernel = Kernel::new(
            astrid_core::SessionId::SYSTEM,
            std::env::current_dir().unwrap(),
            astrid_capsule_types::CapsuleRuntimeLimits::default(),
            HashMap::new(),
            astrid_capsule_types::HttpLimits::default(),
        )
        .await
        .unwrap();
        assert_eq!(
            kernel.ownership_store.first_owner_state().await.unwrap(),
            astrid_storage::FirstOwnerEnrollment::Unenrolled,
        );
        assert_fresh_mutations_denied(&kernel).await;
        return;
    }

    // Isolate only the application home in a child process; changing HOME or
    // the parent process environment would race other native kernel tests.
    let home = tempfile::tempdir().unwrap();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "kernel_router::admin::first_owner_tests::native_fresh_admin_device_cannot_create_claim_or_delete", "--nocapture"])
        .env("ASTRID_HOME", home.path())
        .env(CHILD, "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Test-only watchdog: a boot or deletion deadlock must fail this bounded
    // native scenario instead of blocking the entire workspace test suite.
    let deadline = Instant::now()
        .checked_add(Duration::from_mins(2))
        .expect("native admin watchdog deadline");
    let mut expired = false;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            expired = true;
            child.kill().expect("stop stalled native admin child");
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    assert!(!expired, "native admin child exceeded its test watchdog");
    assert!(
        output.status.success(),
        "native admin child failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
