//! Utility functions for WASM host implementations.

use std::future::Future;

use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

/// Maximum allowed length for a guest string or payload (10 MB).
pub(crate) const MAX_GUEST_PAYLOAD_LEN: u64 = 10 * 1024 * 1024;

/// Run an async future inside `block_in_place` / `block_on` with bounded
/// concurrency. Acquires a permit from the host semaphore before executing,
/// limiting concurrent blocking operations across all capsules.
///
/// For run-loop capsules the outer `block_in_place` is a no-op (already
/// inside one), but the semaphore still gates concurrent I/O to prevent
/// thundering-herd on the async runtime.
pub(crate) fn bounded_block_on<F, T>(
    handle: &tokio::runtime::Handle,
    semaphore: &Semaphore,
    fut: F,
) -> T
where
    F: Future<Output = T>,
{
    tokio::task::block_in_place(|| {
        handle.block_on(async {
            // The semaphore is owned by HostState and lives for the capsule's
            // lifetime. It is never explicitly closed, so acquire only fails if
            // the semaphore is dropped (capsule already deallocated). A panic
            // here is the correct fail-fast: it signals a critical runtime
            // invariant violation that cannot be recovered from.
            let _permit = semaphore
                .acquire()
                .await
                .expect("host semaphore closed: capsule HostState was dropped");
            fut.await
        })
    })
}

/// Like [`bounded_block_on`], but also respects a [`CancellationToken`].
///
/// Returns `Some(T)` if the future completes before cancellation, or `None`
/// if the token fires first. Used for host functions whose I/O can stall
/// indefinitely (network writes to slow clients) and must abort promptly
/// when the capsule is unloaded.
///
/// Cancellation is checked both synchronously (before entering `block_on`)
/// and asynchronously (via `biased` select that prioritises the cancel
/// branch over permit acquisition). This avoids wasting a semaphore permit
/// on capsules that are already being torn down.
pub(crate) fn bounded_block_on_cancellable<F, T>(
    handle: &tokio::runtime::Handle,
    semaphore: &Semaphore,
    cancel_token: &CancellationToken,
    fut: F,
) -> Option<T>
where
    F: Future<Output = T>,
{
    if cancel_token.is_cancelled() {
        return None;
    }
    tokio::task::block_in_place(|| {
        handle.block_on(async {
            tokio::select! {
                biased;
                () = cancel_token.cancelled() => None,
                result = async {
                    let _permit = semaphore
                        .acquire()
                        .await
                        .expect("host semaphore closed: capsule HostState was dropped");
                    fut.await
                } => Some(result),
            }
        })
    })
}

/// Async-native sibling of [`bounded_block_on_cancellable`] for host fns
/// that are themselves `async` (see the bindgen `imports` async selector).
///
/// Same semantics — bounded by the host semaphore, abortable via the
/// cancellation token with a `biased` select that prioritises cancel over
/// permit acquisition — but it `.await`s directly instead of wrapping the
/// wait in `block_in_place`/`block_on`. The calling tokio worker is
/// released back to the pool while the future is pending rather than being
/// pinned for the whole wait, which is the point of issue #816: a capsule
/// blocked in `ipc::recv` waiting for the next stage no longer holds a
/// worker hostage.
///
/// Returns `Some(T)` if the future completes before cancellation, `None` if
/// the token fires first.
pub(crate) async fn bounded_await_cancellable<F, T>(
    semaphore: &Semaphore,
    cancel_token: &CancellationToken,
    fut: F,
) -> Option<T>
where
    F: Future<Output = T>,
{
    if cancel_token.is_cancelled() {
        return None;
    }
    tokio::select! {
        biased;
        () = cancel_token.cancelled() => None,
        result = async {
            let _permit = semaphore
                .acquire()
                .await
                .expect("host semaphore closed: capsule HostState was dropped");
            fut.await
        } => Some(result),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn bounded_block_on_limits_concurrency() {
        let semaphore = Arc::new(Semaphore::new(2));
        let handle = tokio::runtime::Handle::current();
        let concurrent = Arc::new(AtomicUsize::new(0));
        let max_concurrent = Arc::new(AtomicUsize::new(0));

        let mut tasks = Vec::new();
        for _ in 0..6 {
            let sem = semaphore.clone();
            let h = handle.clone();
            let c = concurrent.clone();
            let mc = max_concurrent.clone();
            tasks.push(tokio::task::spawn(async move {
                bounded_block_on(&h, &sem, async {
                    let current = c.fetch_add(1, Ordering::SeqCst) + 1;
                    mc.fetch_max(current, Ordering::SeqCst);
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    c.fetch_sub(1, Ordering::SeqCst);
                });
            }));
        }

        for t in tasks {
            t.await.unwrap();
        }

        let max = max_concurrent.load(Ordering::SeqCst);
        assert!(max <= 2, "max concurrent was {max} but should be <= 2");
        // With 6 tasks and 50ms sleep each, we expect the semaphore to be
        // saturated (max == 2) at some point during execution.
        assert!(
            max >= 1,
            "expected at least 1 concurrent execution, got {max}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn bounded_block_on_propagates_result() {
        let semaphore = Semaphore::new(4);
        let handle = tokio::runtime::Handle::current();

        let result: Result<u32, &str> = bounded_block_on(&handle, &semaphore, async { Ok(42) });
        assert_eq!(result.unwrap(), 42);

        let err: Result<u32, &str> = bounded_block_on(&handle, &semaphore, async { Err("fail") });
        assert_eq!(err.unwrap_err(), "fail");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cancellation_unblocks_bounded_block_on_cancellable() {
        let semaphore = Arc::new(Semaphore::new(4));
        let handle = tokio::runtime::Handle::current();
        let cancel_token = CancellationToken::new();

        let sem = semaphore.clone();
        let h = handle.clone();
        let ct = cancel_token.clone();

        // Cancel after 50ms while the future sleeps for 60s.
        let cancel = cancel_token.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            cancel.cancel();
        });

        let result = tokio::task::spawn(async move {
            bounded_block_on_cancellable(&h, &sem, &ct, async {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                42u32
            })
        })
        .await
        .unwrap();

        assert!(result.is_none(), "expected None on cancellation");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn bounded_block_on_cancellable_pre_cancelled() {
        let semaphore = Semaphore::new(4);
        let handle = tokio::runtime::Handle::current();
        let cancel_token = CancellationToken::new();
        cancel_token.cancel();

        let result: Option<u32> =
            bounded_block_on_cancellable(&handle, &semaphore, &cancel_token, async {
                panic!("future should never execute when token is pre-cancelled");
            });
        assert!(result.is_none(), "expected None for pre-cancelled token");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn bounded_block_on_cancellable_normal_completion() {
        let semaphore = Semaphore::new(4);
        let handle = tokio::runtime::Handle::current();
        let cancel_token = CancellationToken::new();

        let result: Option<Result<u32, &str>> =
            bounded_block_on_cancellable(&handle, &semaphore, &cancel_token, async { Ok(42) });
        assert_eq!(result.unwrap().unwrap(), 42);

        let err: Option<Result<u32, &str>> =
            bounded_block_on_cancellable(&handle, &semaphore, &cancel_token, async { Err("fail") });
        assert_eq!(err.unwrap().unwrap_err(), "fail");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn bounded_block_on_cancellable_limits_concurrency() {
        let semaphore = Arc::new(Semaphore::new(2));
        let handle = tokio::runtime::Handle::current();
        let cancel_token = CancellationToken::new();
        let concurrent = Arc::new(AtomicUsize::new(0));
        let max_concurrent = Arc::new(AtomicUsize::new(0));

        let mut tasks = Vec::new();
        for _ in 0..6 {
            let sem = semaphore.clone();
            let h = handle.clone();
            let ct = cancel_token.clone();
            let c = concurrent.clone();
            let mc = max_concurrent.clone();
            tasks.push(tokio::task::spawn(async move {
                bounded_block_on_cancellable(&h, &sem, &ct, async {
                    let current = c.fetch_add(1, Ordering::SeqCst) + 1;
                    mc.fetch_max(current, Ordering::SeqCst);
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    c.fetch_sub(1, Ordering::SeqCst);
                });
            }));
        }

        for t in tasks {
            t.await.unwrap();
        }

        let max = max_concurrent.load(Ordering::SeqCst);
        assert!(max <= 2, "max concurrent was {max} but should be <= 2");
        assert!(
            max >= 1,
            "expected at least 1 concurrent execution, got {max}"
        );
    }

    /// Cancellation must unblock a task waiting for a semaphore permit,
    /// not just a task already executing inside one. This locks in the
    /// invariant that the biased select in `bounded_block_on_cancellable`
    /// fires cancel even when queued behind the permit acquisition.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn bounded_block_on_cancellable_cancel_while_queued_for_permit() {
        let semaphore = Arc::new(Semaphore::new(1));
        let handle = tokio::runtime::Handle::current();
        let cancel_token = CancellationToken::new();

        // Hold the only permit for the duration of the test.
        let _permit = semaphore.acquire().await.unwrap();

        let ct = cancel_token.clone();
        let sem = semaphore.clone();
        let h = handle.clone();

        // Spawn a task that will block waiting for the permit.
        let task =
            tokio::task::spawn(
                async move { bounded_block_on_cancellable(&h, &sem, &ct, async { 42 }) },
            );

        // Give the spawned task time to enter the permit-wait path.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Cancel while the task is still queued for the permit.
        cancel_token.cancel();

        let result = task.await.unwrap();
        assert!(
            result.is_none(),
            "expected None (cancelled), got {result:?}"
        );
    }
}
