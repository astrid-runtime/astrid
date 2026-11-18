//! Exercise the production boot ordering through real signed local clients.

use super::super::{Args, run_to_completion_with_args};
use anyhow::{Context, Result, ensure};
use astrid_core::PrincipalId;
use astrid_core::dirs::AstridHome;
use astrid_core::kernel_api::{KernelRequest, KernelResponse};
use astrid_uplink::kernel_client::KernelClient;
use clap::Parser;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{Notify, oneshot};
use tracing::field::{Field, Visit};
use tracing_subscriber::layer::{Context as TraceContext, SubscriberExt};
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{Layer, Registry};

const CHILD: &str = "ASTRID_TEST_PRE_READY_SOCKET_CHILD";
const TEST: &str = "tests::startup::pre_ready_status_disconnect_preserves_host_handoff";

#[derive(Default)]
struct BootObservation {
    entered: Notify,
    disconnected: Notify,
    ready: Notify,
    shutdown_requested: AtomicBool,
    released: Mutex<bool>,
    release: Condvar,
}

impl BootObservation {
    fn pause(&self) {
        self.entered.notify_one();
        let (released, _) = self
            .release
            .wait_timeout_while(
                self.released.lock().expect("boot gate lock"),
                Duration::from_secs(20),
                |released| !*released,
            )
            .expect("boot gate wait");
        assert!(*released, "test did not release the pre-Ready boot gate");
    }

    fn resume(&self) {
        *self
            .released
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        self.release.notify_all();
    }
}

// Release even when a client assertion fails, so runtime drop cannot wait on
// the test's synchronous tracing observer. The parent also owns a child deadline.
struct ReleaseBoot(Arc<BootObservation>);

impl Drop for ReleaseBoot {
    fn drop(&mut self) {
        self.0.resume();
    }
}

#[derive(Clone)]
struct BootObserver(Arc<BootObservation>);

#[derive(Default)]
struct Message(String);

impl Visit for Message {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            value.clone_into(&mut self.0);
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{value:?}");
        }
    }
}

impl<S: tracing::Subscriber> Layer<S> for BootObserver {
    fn on_event(&self, event: &tracing::Event<'_>, _: TraceContext<'_, S>) {
        let mut message = Message::default();
        event.record(&mut message);
        match event.metadata().target() {
            "astrid_kernel" if message.0.starts_with("Agent chat is not configured") => {
                // This existing diagnostic runs after native accept is spawned,
                // before Ready. The boot thread holds a shared registry read;
                // GetStatus can take another read, and the fresh empty fixture
                // has no capsule writers. The runtime still serves clients.
                self.0.pause();
            },
            "astrid_uplink::native" if message.0 == "local client disconnected" => {
                // Emitted after the real lifecycle publication has closed its
                // counted lease. No test-side connection bookkeeping is used.
                self.0.disconnected.notify_one();
            },
            "astrid_daemon" if message.0 == "Kernel booted successfully" => {
                self.0.ready.notify_one();
            },
            "astrid_kernel"
                if message.0 == "Last client disconnected, shutting down ephemeral kernel" =>
            {
                self.0.shutdown_requested.store(true, Ordering::Release);
            },
            _ => {},
        }
    }
}

async fn status_client() -> Result<KernelClient> {
    let mut client = KernelClient::connect(PrincipalId::default()).await?;
    let response = client.request(KernelRequest::GetStatus).await?;
    let KernelResponse::Status(status) = response else {
        anyhow::bail!("expected a status response, got {response:?}");
    };
    ensure!(
        status.pid == std::process::id(),
        "connected to another process"
    );
    ensure!(
        status.connected_clients == 1,
        "expected exactly one real client"
    );
    Ok(client)
}

async fn socket_handoff(observation: Arc<BootObservation>) -> Result<()> {
    let _release_on_error = ReleaseBoot(Arc::clone(&observation));
    let home = AstridHome::resolve()?;
    ensure!(
        home.root() == std::env::current_dir()?.join("home") && !home.root().exists(),
        "socket child requires its own absent fixture home"
    );
    let args = Args::parse_from(["astrid-daemon", "--ephemeral"]);
    let (finished, completion) = oneshot::channel();
    // Use the binary's complete lifecycle, including runtime drop and durable
    // finalization. The separate client runtime never owns kernel custody.
    let daemon = std::thread::spawn(move || {
        let _ = finished.send(run_to_completion_with_args(args));
    });
    tokio::time::timeout(Duration::from_secs(20), observation.entered.notified())
        .await
        .context("boot never reached its pre-Ready diagnostic")?;
    ensure!(
        !home.ready_path().exists(),
        "Ready preceded the boot barrier"
    );

    let preflight = status_client().await?;
    ensure!(
        !home.ready_path().exists(),
        "status query bypassed the boot barrier"
    );
    drop(preflight);
    tokio::time::timeout(Duration::from_secs(5), observation.disconnected.notified())
        .await
        .context("early socket disconnect was not processed")?;
    ensure!(
        !home.ready_path().exists(),
        "early disconnect happened after Ready"
    );
    ensure!(
        !observation.shutdown_requested.load(Ordering::Acquire),
        "pre-Ready status disconnect requested shutdown"
    );
    observation.resume();
    tokio::time::timeout(Duration::from_secs(10), observation.ready.notified())
        .await
        .context("daemon did not publish Ready after the early disconnect")?;
    ensure!(
        home.ready_path().is_file(),
        "daemon did not write readiness"
    );

    let mut host = status_client()
        .await
        .context("lasting host could not attach")?;
    // Keep a real host beyond the existing five-second startup grace. This is
    // a lifecycle assertion, not a startup-performance benchmark or a new limit.
    tokio::time::sleep(Duration::from_millis(5100)).await;
    ensure!(
        !daemon.is_finished(),
        "daemon exited with its host connected"
    );
    ensure!(
        matches!(
            host.request(KernelRequest::GetStatus).await?,
            KernelResponse::Status(_)
        ),
        "lasting host lost its status route"
    );
    drop(host);
    tokio::time::timeout(Duration::from_secs(8), completion)
        .await
        .context("last disconnect exceeded the product shutdown limit")???;
    daemon
        .join()
        .map_err(|_| anyhow::anyhow!("daemon boot thread panicked"))?;
    Ok(())
}

struct OwnedChild(Option<Child>);

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0
            && matches!(child.try_wait(), Ok(None))
        {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn isolated_child() -> Result<()> {
    let root = tempfile::tempdir()?;
    let fixture = root.path().canonicalize()?;
    let child = Command::new(std::env::current_exe()?)
        .args(["--exact", TEST, "--nocapture"])
        .current_dir(root.path())
        .env(CHILD, "1")
        .env("ASTRID_HOME", fixture.join("home"))
        .env("XDG_CONFIG_HOME", fixture.join("config"))
        .env("ASTRID_DAEMON_LOG_TARGET", "stderr")
        .env_remove("ASTRID_RUN_DIR")
        .env_remove("ASTRID_CONFIG")
        .env_remove("ASTRID_WORKSPACE_STATE_DIR")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut owned = OwnedChild(Some(child));
    let deadline = Instant::now()
        .checked_add(Duration::from_mins(1))
        .context("child deadline overflow")?;
    while owned
        .0
        .as_mut()
        .context("owned test child")?
        .try_wait()?
        .is_none()
    {
        ensure!(Instant::now() < deadline, "isolated socket test timed out");
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = owned
        .0
        .take()
        .context("completed test child")?
        .wait_with_output()?;
    ensure!(
        output.status.success(),
        "isolated socket test failed: {}\n{}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[test]
fn pre_ready_status_disconnect_preserves_host_handoff() -> Result<()> {
    if std::env::var_os(CHILD).is_none() {
        return isolated_child();
    }
    let observation = Arc::new(BootObservation::default());
    Registry::default()
        .with(BootObserver(Arc::clone(&observation)))
        .with(tracing_subscriber::filter::LevelFilter::INFO)
        .try_init()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?;
    let result = runtime.block_on(socket_handoff(observation));
    drop(runtime);
    result?;
    ensure!(
        !AstridHome::resolve()?.run_dir().exists(),
        "daemon retained its runtime projections"
    );
    Ok(())
}
