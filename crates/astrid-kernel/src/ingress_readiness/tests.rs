use super::*;
use std::sync::OnceLock;
use tokio::sync::{Notify, Semaphore};

struct LoadBarrier {
    loaded: Notify,
    cleaned: Notify,
    release: Semaphore,
}
static BARRIER: OnceLock<LoadBarrier> = OnceLock::new();
const NAME: &str = "native-cancel-owned-load";

pub(crate) async fn pause_after_load(name: &str) {
    if name != NAME {
        return;
    }
    if let Some(barrier) = BARRIER.get() {
        barrier.loaded.notify_one();
        barrier.release.acquire().await.unwrap().forget();
    }
}

pub(crate) fn record_cleanup(name: &str) {
    if name == NAME
        && let Some(barrier) = BARRIER.get()
    {
        barrier.cleaned.notify_one();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disconnected_native_waiter_cannot_cancel_a_loaded_runtime_before_cleanup() {
    let root = tempfile::tempdir().unwrap();
    let home = astrid_core::dirs::AstridHome::from_path(root.path());
    let kernel = crate::test_kernel_with_home(home.clone()).await;
    let principal = astrid_core::PrincipalId::default();
    let source = root.path().join("source");
    std::fs::create_dir(&source).unwrap();
    std::fs::write(
        source.join("Capsule.toml"),
        format!(
            r#"[package]
name = "{NAME}"
version = "1.0.0"
[[component]]
id = "main"
file = "main.wasm"
[subscribe]
"cli.v1.command.run.fixture" = {{ wit = "TODO" }}
"#
        ),
    )
    .unwrap();
    // load() spawns a deferred run worker. It cannot subscribe, so activation
    // must fail readiness and execute the real cancel/unload cleanup path.
    let wasm = wat::parse_str(
        r#"(component
        (core module $m (func (export "run") (loop $forever (br $forever))))
        (core instance $i (instantiate $m))
        (func (export "run") (canon lift (core func $i "run"))))"#,
    )
    .unwrap();
    let hash = blake3::hash(&wasm).to_hex().to_string();
    let name = astrid_storage::ContentName::new(format!("bin/{hash}.wasm")).unwrap();
    kernel
        .principal_store
        .as_ref()
        .unwrap()
        .content()
        .put(&astrid_storage::StateOwner::System, &name, &wasm)
        .unwrap();
    std::fs::write(source.join("main.wasm"), wasm).unwrap();
    crate::capsule_adversarial_tests::publish_without_running_lifecycle(
        &kernel, &principal, &source,
    )
    .unwrap();
    assert!(
        BARRIER
            .set(LoadBarrier {
                loaded: Notify::new(),
                cleaned: Notify::new(),
                release: Semaphore::new(0)
            })
            .is_ok()
    );
    let barrier = BARRIER.get().unwrap();
    assert_eq!(kernel.sorted_principal_capsules(&principal).len(), 1);
    let probe = kernel.capsule_ingress_readiness();
    let waiter = tokio::spawn(async move {
        probe
            .ensure_subscribed("\0astrid.scoped-topic\0default\0cli.v1.command.run.fixture")
            .await
    });
    tokio::time::timeout(Duration::from_secs(10), barrier.loaded.notified())
        .await
        .unwrap();
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    let mut close = Box::pin(kernel.runtime_work.close());
    assert!(
        std::future::Future::poll(
            close.as_mut(),
            &mut std::task::Context::from_waker(std::task::Waker::noop())
        )
        .is_pending(),
        "owned load must retain admission after socket wait is dropped"
    );
    barrier.release.add_permits(1);
    tokio::time::timeout(Duration::from_secs(10), close)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), barrier.cleaned.notified())
        .await
        .unwrap();
    let id = astrid_capsule_types::CapsuleId::new(NAME).unwrap();
    assert!(
        kernel
            .capsules
            .read()
            .await
            .get_for(&principal, &id)
            .is_none()
    );
    kernel.shutdown(Some("cancelled socket wait".into())).await;
}
