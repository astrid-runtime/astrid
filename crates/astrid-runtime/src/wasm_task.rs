//! Minimal `spawn` / `JoinHandle` / `JoinError` for the wasm target.
//!
//! `wasm32-unknown-unknown` has no tokio runtime and no OS threads, so a task
//! is a future driven on the JS microtask queue via
//! [`wasm_bindgen_futures::spawn_local`]. This module rebuilds the slice of
//! tokio's task API the kernel actually uses — spawning, a join handle that is
//! awaitable and abortable, and a join error that reports cancellation — on top
//! of that primitive, keeping the same call shape as the native arm.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::channel::oneshot;
use futures::future::{AbortHandle, Abortable};

/// Error returned by an awaited [`JoinHandle`] whose task did not produce an
/// output.
///
/// On this target the only such cause is cooperative cancellation via
/// [`JoinHandle::abort`]. Wasm has no `catch_unwind`, so a task that panics
/// aborts the whole runtime rather than surfacing here — an accepted semantic
/// difference from native tokio (where a panicking task yields a non-cancelled
/// `JoinError`), not a bug. Every error this arm can produce is therefore a
/// cancellation, so [`is_cancelled`](Self::is_cancelled) always returns `true`.
#[derive(Debug)]
pub struct JoinError {
    _private: (),
}

impl JoinError {
    /// Whether the task was cancelled. Always `true` on wasm (see the type
    /// docs: cancellation is the only error this arm produces).
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        true
    }
}

impl std::fmt::Display for JoinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("task was cancelled")
    }
}

impl std::error::Error for JoinError {}

/// Handle to a task spawned with [`spawn`].
///
/// Awaiting it yields `Ok(output)` once the task completes, or
/// `Err(JoinError)` if it was [aborted](Self::abort) first. Dropping the handle
/// does *not* cancel the task (matching tokio) — the task keeps running on the
/// microtask queue; only [`abort`](Self::abort) stops it.
#[must_use = "dropping a JoinHandle detaches the task; call .abort() to cancel it"]
pub struct JoinHandle<T> {
    rx: oneshot::Receiver<T>,
    abort: AbortHandle,
}

impl<T> std::fmt::Debug for JoinHandle<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JoinHandle").finish_non_exhaustive()
    }
}

impl<T> JoinHandle<T> {
    /// Cooperatively cancel the task at its next `.await` point. After this the
    /// handle resolves to `Err(JoinError)` (unless the output was already sent).
    pub fn abort(&self) {
        self.abort.abort();
    }

    /// Build a handle over an already-produced value, so awaiting it resolves
    /// to `Ok(value)` immediately. Used by [`spawn_blocking`], which runs its
    /// closure inline on this target and has nothing to spawn.
    fn ready(value: T) -> Self {
        let (tx, rx) = oneshot::channel();
        // The receiver is live and holds `value`, so the send always succeeds.
        let _ = tx.send(value);
        // No task backs this handle; the abort half is inert.
        let (abort, _registration) = AbortHandle::new_pair();
        JoinHandle { rx, abort }
    }
}

impl<T> Future for JoinHandle<T> {
    type Output = Result<T, JoinError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Every field is `Unpin` (`oneshot::Receiver`, `AbortHandle`), so the
        // handle is `Unpin` and we can project a `&mut` to the receiver.
        let this = self.get_mut();
        match Pin::new(&mut this.rx).poll(cx) {
            Poll::Ready(Ok(output)) => Poll::Ready(Ok(output)),
            // Sender dropped without sending: the task was aborted (its
            // `Abortable` future resolved to `Aborted` and skipped the send).
            Poll::Ready(Err(oneshot::Canceled)) => Poll::Ready(Err(JoinError { _private: () })),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Spawn `future` onto the JS microtask queue.
///
/// Bounds mirror [`tokio::spawn`] (`Send + 'static`); a `Send` future is
/// trivially acceptable to the non-`Send` [`spawn_local`], so callers written
/// against the native arm compile unchanged.
///
/// [`spawn_local`]: wasm_bindgen_futures::spawn_local
pub fn spawn<F>(future: F) -> JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    let (tx, rx) = oneshot::channel();
    let (abort, registration) = AbortHandle::new_pair();
    let task = Abortable::new(future, registration);
    wasm_bindgen_futures::spawn_local(async move {
        // `Ok` = ran to completion; `Err(Aborted)` = cancelled, in which case
        // we drop `tx` so the awaiting handle observes `JoinError`.
        if let Ok(output) = task.await {
            let _ = tx.send(output);
        }
    });
    JoinHandle { rx, abort }
}

/// Run a blocking closure, mirroring [`tokio::task::spawn_blocking`]'s shape.
///
/// This target has no dedicated blocking thread pool (no OS threads), so the
/// closure runs **inline on the current task** and the returned handle is
/// already complete. That means `f` blocks the single wasm thread for its whole
/// duration — acceptable because the kernel's genuinely heavy blocking paths
/// (capsule install, disk discovery) are native-gated and never reach this arm;
/// the sites that do compile here wrap only short, non-blocking work.
pub fn spawn_blocking<F, R>(f: F) -> JoinHandle<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    JoinHandle::ready(f())
}
