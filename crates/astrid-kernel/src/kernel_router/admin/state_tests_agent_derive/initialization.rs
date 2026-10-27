//! Real capsule loaders must not enter before cloned state is initialized.
use super::*;
use std::future::Future;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Waker};
use tokio::sync::{Notify, Semaphore};

const ALIASES: [&str; 3] = ["init-created", "init-derived", "init-failed"];
static BARRIERS: [OnceLock<InitializationBarrier>; 3] = [const { OnceLock::new() }; 3];

struct InitializationBarrier {
    installed: Notify,
    release: Semaphore,
    admitted: AtomicBool,
    loader_release: Semaphore,
}

fn barrier(principal: &PrincipalId) -> Option<&'static InitializationBarrier> {
    ALIASES
        .iter()
        .position(|alias| *alias == principal.as_str())
        .and_then(|index| BARRIERS[index].get())
}

pub(crate) async fn pause_after_install(principal: &PrincipalId) {
    if let Some(barrier) = barrier(principal) {
        barrier.installed.notify_one();
        barrier.release.acquire().await.unwrap().forget();
    }
}

pub(crate) async fn pause_admitted_loader(principal: &PrincipalId) {
    if let Some(barrier) = barrier(principal)
        && !barrier.admitted.swap(true, Ordering::SeqCst)
    {
        barrier.loader_release.acquire().await.unwrap().forget();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn created_capsule_waits_for_cloned_state() {
    exercise_initialization(0, false, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn derived_capsule_waits_for_selected_state() {
    exercise_initialization(1, true, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_inheritance_fences_a_queued_real_loader() {
    exercise_initialization(2, true, true).await;
}

async fn exercise_initialization(index: usize, derived: bool, fail: bool) {
    let (_dir, kernel) = fixture().await;
    prepare_source(&kernel).await;
    let principal = PrincipalId::new(ALIASES[index]).unwrap();
    assert!(
        BARRIERS[index]
            .set(InitializationBarrier {
                installed: Notify::new(),
                release: Semaphore::new(0),
                admitted: AtomicBool::new(false),
                loader_release: Semaphore::new(0),
            })
            .is_ok()
    );
    let gate = BARRIERS[index].get().unwrap();
    let provision = spawn_provision(Arc::clone(&kernel), index, derived);
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        gate.installed.notified(),
    )
    .await
    .unwrap();

    // An unrelated principal still passes the actual loader's global lock
    // while target initialization is paused. Only its target view may block.
    let source = PrincipalId::default();
    let source_dir = kernel.sorted_principal_capsules(&source).pop().unwrap().1;
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        kernel.load_capsule(source_dir, &source),
    )
    .await
    .unwrap()
    .unwrap();
    let target_uid = kernel.principal_directory.uid_for(&principal).unwrap();
    let target_dir = kernel
        .sorted_principal_capsules(&principal)
        .pop()
        .unwrap()
        .1;
    let mut load = Box::pin(kernel.load_capsule(target_dir, &principal));
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(load.as_mut().poll(&mut context), Poll::Pending));
    let ran_before_inheritance = gate.admitted.load(Ordering::SeqCst);
    if fail {
        kernel
            .kv
            .set(
                &format!("{principal}:capsule:provider"),
                "model",
                b"conflict".to_vec(),
            )
            .await
            .unwrap();
    }
    gate.loader_release.add_permits(1);
    gate.release.add_permits(1);
    let (loaded, response) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        tokio::join!(load, provision)
    })
    .await
    .unwrap();
    let response = response.unwrap();
    assert!(
        !ran_before_inheritance,
        "real capsule constructor admitted before inheritance"
    );
    if fail {
        assert!(
            loaded.is_err(),
            "failed initialization must reject its queued loader"
        );
        assert!(
            !matches!(response, AdminResponseBody::Success(_)),
            "{response:?}"
        );
        assert!(
            !gate.admitted.load(Ordering::SeqCst),
            "failed target ran before reclamation"
        );
        assert_failed_target_reclaimed(&kernel, &principal, target_uid).await;
    } else {
        loaded.unwrap();
        assert!(
            matches!(response, AdminResponseBody::Success(_)),
            "{response:?}"
        );
        assert_inherited_state(&kernel, &principal).await;
    }
}

async fn assert_failed_target_reclaimed(
    kernel: &Kernel,
    principal: &PrincipalId,
    target_uid: astrid_core::PrincipalUid,
) {
    assert!(
        kernel
            .capsules
            .read()
            .await
            .get_for(principal, &CapsuleId::new("provider").unwrap())
            .is_none()
    );
    assert!(kernel.principal_directory.uid_for(principal).is_err());
    assert!(
        !kernel
            .principal_store
            .as_ref()
            .unwrap()
            .purge_principal_kv(target_uid)
            .unwrap(),
        "rollback left authoritative KV state behind for its immutable UID"
    );
}

async fn assert_inherited_state(kernel: &Kernel, principal: &PrincipalId) {
    assert_eq!(
        kernel
            .kv
            .get(&format!("{principal}:capsule:provider"), "model")
            .await
            .unwrap(),
        Some(b"selected".to_vec())
    );
    assert!(
        kernel
            .capsules
            .read()
            .await
            .get_for(principal, &CapsuleId::new("provider").unwrap())
            .is_some()
    );
    let uid = kernel.principal_directory.uid_for(principal).unwrap();
    let secrets = ScopedKvStore::new(
        Arc::clone(&kernel.kv),
        principal_secret_namespace(uid, "provider"),
    )
    .unwrap();
    assert_eq!(
        secrets
            .get(&format!("{SECRET_KEY_PREFIX}API_KEY"))
            .await
            .unwrap(),
        Some(b"selected-secret".to_vec())
    );
}

async fn prepare_source(kernel: &Arc<Kernel>) {
    let source = PrincipalId::default();
    seed_capsule(kernel, &source, "provider");
    seed_source_state(kernel, &source).await;
    let path = PrincipalProfile::path_for(&kernel.astrid_home, &source);
    let mut profile = PrincipalProfile::load_from_path(&path).unwrap();
    profile.capsules = vec!["provider".into()];
    profile.save_to_path(&path).unwrap();
    kernel.profile_cache.invalidate(&source);
    // Use the real source manifest as well: ordinary create snapshots its
    // declared secrets, including API_KEY. No target runtime is pre-registered.
    let source_dir = kernel.sorted_principal_capsules(&source).pop().unwrap().1;
    kernel.load_capsule(source_dir, &source).await.unwrap();
}

fn spawn_provision(
    kernel: Arc<Kernel>,
    index: usize,
    derived: bool,
) -> tokio::task::JoinHandle<AdminResponseBody> {
    tokio::spawn(async move {
        let caller = PrincipalId::default();
        if derived {
            super::super::agent_derive::agent_derive_from_req(
                &kernel,
                &caller,
                AgentDeriveRequest {
                    name: ALIASES[index].into(),
                    source: caller.clone(),
                    load_capsules: vec!["provider".into()],
                    allow_capsules: vec!["provider".into()],
                    inherit_capsule_state: vec!["provider".into()],
                    network_egress: Vec::new(),
                },
            )
            .await
        } else {
            super::super::test_support::dispatch_as_operator(
                &kernel,
                &caller,
                astrid_events::kernel_api::AdminRequestKind::AgentCreate {
                    name: ALIASES[index].into(),
                    groups: Vec::new(),
                    grants: Vec::new(),
                    inherit_from: None,
                    clone_from: Some(caller.clone()),
                    allow_admin_clone: true,
                },
            )
            .await
        }
    })
}
