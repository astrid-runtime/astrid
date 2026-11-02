//! Epoch CPU-policy tests plus the cancelled-component Interrupt regression.

use std::time::Duration;

use wasmtime::Store;
use wasmtime::component::{Component, Linker};

use super::super::host_state::HostState;
use super::super::test_fixtures::minimal_host_state;
use super::super::{
    RunLoopBudget, WASM_MAX_MEMORY_BYTES, cancel_principal_token, spawn_epoch_ticker,
};
use super::{
    DEFAULT_RUN_LOOP_WINDOW_TICKS, EpochAction, MAX_NO_YIELD_WINDOWS, configure_run_store,
    epoch_decision, exempt_epoch_action, run_epoch_action,
};

// ── epoch_decision (the FIX 2 callback logic, directly) ──────────────

#[test]
fn epoch_recv_loop_never_traps_and_resets() {
    // recv_yielded=true → Yield, flag cleared, counter reset to 0 — no
    // matter how high the counter had climbed.
    let (action, recv, windows) = epoch_decision(true, 99, 50, MAX_NO_YIELD_WINDOWS);
    assert_eq!(action, EpochAction::Yield(50));
    assert!(!recv, "flag must be cleared after reading");
    assert_eq!(windows, 0, "a recv resets the no-yield counter");
}

#[test]
fn epoch_no_recv_yields_during_grace_then_interrupts() {
    // A no-recv spinner: Yields (cooperatively, never starving) while the
    // counter is below max, then Interrupts exactly when it reaches max.
    let max = 3u32;
    // window 0 -> 1: yield
    let (a0, _, w0) = epoch_decision(false, 0, 50, max);
    assert_eq!(a0, EpochAction::Yield(50));
    assert_eq!(w0, 1);
    // window 1 -> 2: yield
    let (a1, _, w1) = epoch_decision(false, w0, 50, max);
    assert_eq!(a1, EpochAction::Yield(50));
    assert_eq!(w1, 2);
    // window 2 -> 3 == max: interrupt
    let (a2, _, w2) = epoch_decision(false, w1, 50, max);
    assert_eq!(a2, EpochAction::Interrupt);
    assert_eq!(w2, 3);
}

#[test]
fn epoch_recv_every_window_never_interrupts_driven() {
    // The task's named guarantee, modelled as a DRIVEN feedback loop (not a
    // single shot): a legit recv/accept loop sets `recv_yielded` every
    // window, so feeding `epoch_decision`'s output back into its next call —
    // exactly as the production callback does via HostState — yields forever
    // and NEVER interrupts, even far past MAX_NO_YIELD_WINDOWS windows.
    let max = MAX_NO_YIELD_WINDOWS;
    let mut no_yield = 0u32;
    for window in 0..(max as u64 * 100 + 7) {
        // A recv occurred since the last window (the host fn set the flag).
        let recv_yielded = true;
        let (action, new_recv, new_windows) = epoch_decision(recv_yielded, no_yield, 50, max);
        assert_eq!(
            action,
            EpochAction::Yield(50),
            "a recv-yielding loop must Yield on window {window}, never Interrupt"
        );
        assert!(!new_recv, "the flag is always cleared after reading");
        assert_eq!(new_windows, 0, "every recv resets the no-yield counter");
        no_yield = new_windows;
    }
}

#[test]
fn epoch_single_late_recv_restores_full_grace_driven() {
    // Adversarial boundary: a spinner accrues to max-1 (one window short of
    // the trap), then a SINGLE recv arrives. That recv must reset the
    // counter to 0 so the spinner gets the FULL grace again before any
    // trap — there must be no "primed" early interrupt carried across the
    // reset. Drive `epoch_decision`'s output back into itself.
    let max = MAX_NO_YIELD_WINDOWS;
    assert!(max >= 2, "test assumes a multi-window grace");
    let mut no_yield = 0u32;
    // Spin up to max-1 (still yielding, not yet trapped).
    for _ in 0..(max - 1) {
        let (action, _, w) = epoch_decision(false, no_yield, 50, max);
        assert_eq!(action, EpochAction::Yield(50));
        no_yield = w;
    }
    assert_eq!(no_yield, max - 1, "primed one window short of the trap");
    // A single recv resets the counter.
    let (action, _, w) = epoch_decision(true, no_yield, 50, max);
    assert_eq!(action, EpochAction::Yield(50));
    assert_eq!(w, 0, "one recv at the brink restores the full grace");
    no_yield = w;
    // Now the spinner must get the FULL grace again: max-1 yields, then trap
    // exactly on the max-th — not one window early.
    for window in 0..(max - 1) {
        let (action, _, w) = epoch_decision(false, no_yield, 50, max);
        assert_eq!(
            action,
            EpochAction::Yield(50),
            "post-reset grace window {window} must Yield, not trap early"
        );
        no_yield = w;
    }
    let (action, _, _) = epoch_decision(false, no_yield, 50, max);
    assert_eq!(
        action,
        EpochAction::Interrupt,
        "trap lands on the full max-th post-reset window, not earlier"
    );
}

#[test]
fn epoch_interrupt_is_immediate_when_max_is_one() {
    // With max=1 the very first no-recv window traps.
    let (action, _, windows) = epoch_decision(false, 0, 10, 1);
    assert_eq!(action, EpochAction::Interrupt);
    assert_eq!(windows, 1);
}

#[test]
fn epoch_counter_does_not_overflow() {
    // saturating_add guards a pathological counter near u32::MAX.
    let (action, _, windows) = epoch_decision(false, u32::MAX, 10, MAX_NO_YIELD_WINDOWS);
    assert_eq!(action, EpochAction::Interrupt);
    assert_eq!(windows, u32::MAX);
}

#[test]
fn exempt_epoch_action_always_yields_never_interrupts() {
    // The exempt run-loop policy is unbounded: it must ALWAYS cooperatively
    // yield the worker (re-arming by `window_ticks`) and NEVER trap, for any
    // window value — the guarantee that keeps an exempt capsule from
    // starving the daemon without ever bounding its CPU.
    for ticks in [1_u64, 10, 50, DEFAULT_RUN_LOOP_WINDOW_TICKS, u64::MAX] {
        assert_eq!(
            exempt_epoch_action(ticks),
            EpochAction::Yield(ticks),
            "exempt policy must yield (never interrupt) for window {ticks}"
        );
    }
}

#[tokio::test]
async fn cancelled_exempt_and_bound_epoch_action_interrupt_before_policy() {
    // Old run_epoch_action ignored instance cancel: exempt always Yielded and
    // bound still ran CPU policy. Instance cancel must Interrupt first; a
    // principal overlay cancel must not. Live admin and a healthy recv loop
    // must keep their existing Yield/reset behaviour.
    assert_eq!(DEFAULT_RUN_LOOP_WINDOW_TICKS, 50);
    assert_eq!(MAX_NO_YIELD_WINDOWS, 3);

    let mut live = minimal_host_state(tokio::runtime::Handle::current());
    assert_eq!(
        run_epoch_action(&mut live, None),
        EpochAction::Yield(DEFAULT_RUN_LOOP_WINDOW_TICKS),
        "live admin (not cancelled, window=None) must still Yield"
    );
    live.recv_yielded = true;
    live.no_yield_windows = 2;
    assert_eq!(
        run_epoch_action(&mut live, Some(DEFAULT_RUN_LOOP_WINDOW_TICKS)),
        EpochAction::Yield(DEFAULT_RUN_LOOP_WINDOW_TICKS)
    );
    assert!(
        !live.recv_yielded,
        "healthy bound recv must still clear the yield flag"
    );
    assert_eq!(
        live.no_yield_windows, 0,
        "healthy bound recv must still reset the no-yield counter"
    );

    let mut cancelled = minimal_host_state(tokio::runtime::Handle::current());
    cancelled.cancel_token.cancel();
    cancelled.recv_yielded = true;
    cancelled.no_yield_windows = 0;
    assert_eq!(
        run_epoch_action(&mut cancelled, None),
        EpochAction::Interrupt,
        "cancelled exempt must Interrupt before exempt_epoch_action"
    );
    assert_eq!(
        run_epoch_action(&mut cancelled, Some(DEFAULT_RUN_LOOP_WINDOW_TICKS)),
        EpochAction::Interrupt,
        "cancelled bound must Interrupt before epoch_decision"
    );
    assert!(
        cancelled.recv_yielded && cancelled.no_yield_windows == 0,
        "cancel Interrupt must not mutate CPU-policy counters"
    );

    let mut overlay = minimal_host_state(tokio::runtime::Handle::current());
    overlay.system_runtime = true;
    let alice = astrid_core::PrincipalId::new("alice").expect("fixture principal");
    overlay.install_invocation_cancel_token(Some(&alice));
    cancel_principal_token(
        &overlay.principal_cancel_tokens,
        &overlay.cancel_token,
        &alice,
    );
    assert!(
        overlay
            .invocation_cancel_token
            .as_ref()
            .is_some_and(tokio_util::sync::CancellationToken::is_cancelled),
        "request_cancel_for helper must cancel the installed child overlay"
    );
    assert!(
        !overlay.cancel_token.is_cancelled(),
        "instance token stays live so overlay is the only cancelled signal"
    );
    assert_eq!(
        run_epoch_action(&mut overlay, None),
        EpochAction::Yield(DEFAULT_RUN_LOOP_WINDOW_TICKS),
        "principal overlay cancel must not trap a live shared exempt pump"
    );
    overlay.recv_yielded = true;
    overlay.no_yield_windows = 2;
    assert_eq!(
        run_epoch_action(&mut overlay, Some(DEFAULT_RUN_LOOP_WINDOW_TICKS)),
        EpochAction::Yield(DEFAULT_RUN_LOOP_WINDOW_TICKS),
        "principal overlay cancel must not skip bound CPU policy"
    );
    assert!(
        !overlay.recv_yielded && overlay.no_yield_windows == 0,
        "live bound recv policy still runs when only the overlay is cancelled"
    );
}

fn assert_interrupt(err: &wasmtime::Error) {
    let trap = err.root_cause().downcast_ref::<wasmtime::Trap>();
    assert_eq!(
        trap,
        Some(&wasmtime::Trap::Interrupt),
        "expected the epoch-interrupt trap, got: {err:?}"
    );
}

/// Join an OS helper on drop so a RED/timeout cannot detach it.
struct JoinOnDrop(Option<std::thread::JoinHandle<()>>);

impl Drop for JoinOnDrop {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            let _ = handle.join();
        }
    }
}

/// Component canon-lift spinner on the production Store callback.
///
/// Must await the actual `call_async` trap with no outer `select!`/`abort`
/// masking. Old exempt Yield-never-Interrupt would hang until the 10s
/// hang-guard — including cases where a local `select!` on the cancel token
/// would have returned `"cancelled"` after the first Yield (~5s).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_component_spinner_interrupt_traps_via_production_callback() {
    let engine = super::super::build_wasmtime_engine().expect("engine");
    let component = Component::new(
        &engine,
        r#"(component
  (core module $m (func (export "run") (loop $forever (br $forever))))
  (core instance $i (instantiate $m))
  (func (export "run") (canon lift (core func $i "run"))))"#,
    )
    .expect("component");

    let mut store = Store::new(
        &engine,
        minimal_host_state(tokio::runtime::Handle::current()),
    );
    store.set_fuel(u64::MAX).expect("fuel");
    // Kernel owned-load fixture is builtin admin: exempt window_ticks=None
    // still arms the production 50-tick (~5s) deadline.
    configure_run_store(
        &mut store,
        &RunLoopBudget {
            exempt: true,
            bound_run_loop: false,
            window_ticks: None,
            mem_bytes: WASM_MAX_MEMORY_BYTES,
        },
    );

    let linker = Linker::<HostState>::new(&engine);
    let instance = linker
        .instantiate_async(&mut store, &component)
        .await
        .expect("instantiate");
    let run = instance
        .get_typed_func::<(), ()>(&mut store, "run")
        .expect("run export");

    let ticker = spawn_epoch_ticker(&engine);
    let cancel = store.data().cancel_token.clone();
    let _cancel_soon = JoinOnDrop(Some(std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        cancel.cancel();
    })));

    let outcome =
        tokio::time::timeout(Duration::from_secs(10), run.call_async(&mut store, ())).await;
    drop(ticker);
    let err = outcome
        .expect("cancelled component spinner must not hang the worker")
        .expect_err("cancelled component spinner must TRAP, not run forever");
    assert_interrupt(&err);
}
