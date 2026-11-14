//! Real first-write routing, sealed opt-in, failure and identity fencing.

use std::cell::RefCell;
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};

use super::*;
use crate::engine::wasm::bindings::astrid::sys::host::{Host as SysHost, LogLevel};
use crate::engine::wasm::test_fixtures::{minimal_host_state, open_log};
use astrid_storage::identity::IdentityStore as _;

fn bind(
    root: Option<&Arc<NativeLogRoot>>,
    directory: &PrincipalDirectory,
    principal: &PrincipalId,
    capsule: &str,
    prune: bool,
    tracker: &Arc<PrincipalInvocationTracker>,
) -> Binding {
    super::bind(
        root,
        directory,
        principal,
        capsule,
        prune,
        tracker,
        directory.uid_for(principal).ok(),
    )
}

fn install_invocation(state: &mut HostState, principal: &PrincipalId) {
    let uid = state.principal_directory.uid_for(principal).unwrap();
    super::install_invocation(state, principal, uid);
}

fn fixture() -> (
    tempfile::TempDir,
    Arc<NativeLogRoot>,
    HostState,
    Arc<PrincipalInvocationTracker>,
) {
    let parent = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(parent.path().join("home"));
    home.ensure().unwrap();
    let root = Arc::new(NativeLogRoot::capture(&home).unwrap());
    let mut state = minimal_host_state(tokio::runtime::Handle::current());
    let tracker = Arc::new(PrincipalInvocationTracker::default());
    state.principal_invocations = Some(Arc::clone(&tracker));
    let owner = bind(
        Some(&root),
        &state.principal_directory,
        &state.principal,
        state.capsule_id.as_str(),
        true,
        &tracker,
    );
    state.capsule_log = owner.file;
    state.deferred_logs = DeferredBindings::for_factory(Some(Arc::clone(&root)), owner.pending);
    (parent, root, state, tracker)
}

fn caller(state: &mut HostState, principal: &PrincipalId) {
    state.caller_context = Some(
        astrid_events::ipc::IpcMessage::new(
            astrid_events::ipc::Topic::from_raw("test.log"),
            astrid_events::ipc::IpcPayload::Custom {
                data: serde_json::json!({}),
            },
            uuid::Uuid::nil(),
        )
        .with_principal(principal.to_string()),
    );
}

fn contents(root: &NativeLogRoot, pending: &PendingLog) -> String {
    std::fs::read_to_string(root.home.root().join(&pending.target)).unwrap()
}

#[tokio::test]
async fn silent_ten_thousand_bindings_share_one_root_without_native_log_trees() {
    fn send_sync<T: Send + Sync>() {}
    send_sync::<NativeLogRoot>();
    let (_parent, root, state, tracker) = fixture();
    let bindings = (0..10_000)
        .map(|index| {
            bind(
                Some(&root),
                &state.principal_directory,
                &state.principal,
                &format!("silent-{index}"),
                true,
                &tracker,
            )
        })
        .collect::<Vec<_>>();
    for binding in &bindings {
        assert!(binding.file.is_none());
        let pending = binding.pending.as_ref().unwrap();
        assert!(Arc::ptr_eq(&pending.root, &root));
        assert!(pending.opened.get().is_none());
    }
    assert!(state.effective_capsule_log().is_none());
    assert!(!root.home.log_dir().join("principals").exists());
}

#[tokio::test]
async fn first_and_subsequent_lines_keep_one_file_and_existing_line_format() {
    let (_parent, root, mut state, _tracker) = fixture();
    let pending = Arc::clone(state.deferred_logs.owner.as_ref().unwrap());
    assert!(state.effective_capsule_log().is_none());
    state.log(LogLevel::Info, "first line".into());
    let opened = Arc::clone(state.effective_capsule_log().unwrap());
    state.log(LogLevel::Error, "second line".into());
    assert!(Arc::ptr_eq(state.effective_capsule_log().unwrap(), &opened));
    let text = contents(&root, &pending);
    let lines = text.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 2);
    assert!(lines[0].contains(" INFO [test] first line"), "{text}");
    assert!(lines[1].contains(" ERROR [test] second line"), "{text}");
}

#[tokio::test]
async fn invocation_file_then_pending_then_owner_precedence_is_preserved() {
    let (parent, root, mut state, _tracker) = fixture();
    let owner = Arc::clone(state.deferred_logs.owner.as_ref().unwrap());
    let alice = PrincipalId::new("alice").unwrap();
    caller(&mut state, &alice);
    install_invocation(&mut state, &alice);
    let invocation = Arc::clone(state.deferred_logs.invocation.as_ref().unwrap());
    let explicit_path = parent.path().join("explicit.log");
    state.invocation_capsule_log = Some(open_log(&explicit_path));
    state.log(LogLevel::Info, "explicit wins".into());
    assert!(
        std::fs::read_to_string(&explicit_path)
            .unwrap()
            .contains("explicit wins")
    );
    assert!(!root.home.root().join(&invocation.target).exists());
    assert!(!root.home.root().join(&owner.target).exists());
    state.invocation_capsule_log = None;
    state.log(LogLevel::Info, "caller pending wins".into());
    assert!(contents(&root, &invocation).contains("caller pending wins"));
    assert!(!root.home.root().join(&owner.target).exists());
    state.invocation_capsule_log = None;
    state.deferred_logs.clear_invocation();
    state.log(LogLevel::Warn, "owner fallback".into());
    assert!(contents(&root, &owner).contains("owner fallback"));
}

#[tokio::test]
async fn first_open_failure_is_cached_until_binding_reinstallation() {
    let (_parent, root, mut state, tracker) = fixture();
    let old = Arc::clone(state.deferred_logs.owner.as_ref().unwrap());
    let blocker = root.home.log_dir().join("principals");
    astrid_core::platform_fs::ensure_private_directory(&root.home.log_dir()).unwrap();
    std::fs::write(&blocker, b"not a directory").unwrap();
    state.log(LogLevel::Info, "falls back".into());
    assert!(old.opened.get().is_some_and(Option::is_none));
    std::fs::remove_file(&blocker).unwrap();
    state.log(LogLevel::Info, "does not retry failed open".into());
    assert!(!blocker.exists());
    let replacement = bind(
        Some(&root),
        &state.principal_directory,
        &state.principal,
        state.capsule_id.as_str(),
        true,
        &tracker,
    );
    state.deferred_logs.owner = replacement.pending;
    state.capsule_log = replacement.file;
    state.log(LogLevel::Info, "new binding retries".into());
    assert!(
        contents(&root, state.deferred_logs.owner.as_ref().unwrap())
            .contains("new binding retries")
    );
}

#[tokio::test]
async fn existing_history_keeps_eager_today_and_nonempty_previous_logs() {
    let (_parent, root, state, tracker) = fixture();
    let uid = state.principal_directory.uid_for(&state.principal).unwrap();
    let relative = Path::new("log/principals")
        .join(uid.to_string())
        .join("history/2000-01-01.log");
    use std::io::Write as _;
    root.open(&relative)
        .unwrap()
        .write_all(b"retained history\n")
        .unwrap();
    let history_path = root.home.root().join(&relative);
    let old_modified = std::fs::metadata(&history_path)
        .unwrap()
        .modified()
        .unwrap();
    let binding = bind(
        Some(&root),
        &state.principal_directory,
        &state.principal,
        "history",
        true,
        &tracker,
    );
    assert!(binding.pending.is_none());
    assert!(binding.file.is_some());
    let today = history_path
        .parent()
        .unwrap()
        .join(format!("{}.log", super::super::today_date_string()));
    assert_eq!(std::fs::metadata(today).unwrap().len(), 0);
    assert_eq!(std::fs::read(&history_path).unwrap(), b"retained history\n");
    assert_eq!(
        std::fs::metadata(history_path).unwrap().modified().unwrap(),
        old_modified
    );
}

#[tokio::test]
async fn pending_target_date_is_not_recomputed_on_first_write() {
    let (_parent, root, mut state, _tracker) = fixture();
    let owner = Arc::get_mut(state.deferred_logs.owner.as_mut().unwrap()).unwrap();
    // A binding installed before UTC rollover retains that installation target.
    owner.target.set_file_name("2001-02-03.log");
    let expected = root.home.root().join(&owner.target);
    state.log(LogLevel::Info, "after midnight".into());
    assert!(
        std::fs::read_to_string(expected)
            .unwrap()
            .contains("after midnight")
    );
}

#[tokio::test]
async fn pool_return_drops_old_pending_identity_before_next_principal() {
    let (_parent, root, mut state, _tracker) = fixture();
    let alice = PrincipalId::new("alice").unwrap();
    let bob = PrincipalId::new("bob").unwrap();
    caller(&mut state, &alice);
    install_invocation(&mut state, &alice);
    let old = Arc::clone(state.deferred_logs.invocation.as_ref().unwrap());
    super::super::pool::clear_on_return(&mut state, false);
    assert!(state.deferred_logs.invocation.is_none());
    assert!(state.invocation_capsule_log.is_none());
    caller(&mut state, &bob);
    install_invocation(&mut state, &bob);
    let new = Arc::clone(state.deferred_logs.invocation.as_ref().unwrap());
    assert_ne!(old.uid, new.uid);
    state.log(LogLevel::Info, "bob only".into());
    assert!(!root.home.root().join(&old.target).exists());
    assert!(contents(&root, &new).contains("bob only"));
}

#[tokio::test]
async fn unregistered_caller_retains_owner_fallback() {
    let (_parent, root, mut state, _tracker) = fixture();
    let owner = Arc::clone(state.deferred_logs.owner.as_ref().unwrap());
    let unknown = PrincipalId::new("unregistered").unwrap();
    caller(&mut state, &unknown);
    assert!(!super::super::install_principal_overlays_sync(
        &mut state,
        Some(&unknown)
    ));
    assert!(state.deferred_logs.invocation.is_none());
    state.log(LogLevel::Warn, "owner fallback for unknown".into());
    assert!(contents(&root, &owner).contains("owner fallback for unknown"));
}

#[tokio::test]
async fn already_admitted_matching_guard_can_finish_first_open_after_retirement() {
    let (_parent, root, state, tracker) = fixture();
    let owner = Arc::clone(state.deferred_logs.owner.as_ref().unwrap());
    let guard = state.begin_host_operation().unwrap().unwrap();
    tracker.retire(&state.principal);
    assert!(tracker.begin(&state.principal).is_none());
    let resolved = owner
        .resolve(Some(&guard))
        .expect("admitted operation must not re-enter admission");
    assert!(resolved.file.is_some());
    assert!(root.home.root().join(&owner.target).exists());
    assert_eq!(
        tracker.state.lock().unwrap().active.get(&state.principal),
        Some(&1)
    );
    drop(resolved);
    drop(guard);
    tracker.wait_for_quiescence(&state.principal).await;
}

#[tokio::test]
async fn retired_pending_owner_cannot_borrow_a_different_callers_guard() {
    let (_parent, root, mut state, tracker) = fixture();
    let owner = Arc::clone(state.deferred_logs.owner.as_ref().unwrap());
    let alice = PrincipalId::new("alice").unwrap();
    caller(&mut state, &alice);
    let guard = state.begin_host_operation().unwrap().unwrap();
    tracker.retire(&state.principal);
    assert!(resolve(&mut state, Some(&guard)).file.is_none());
    assert!(!root.home.root().join(&owner.target).exists());
    tracker.resume(&state.principal);
    let resolved = resolve(&mut state, Some(&guard));
    assert!(resolved.file.is_some());
    assert_eq!(
        tracker.state.lock().unwrap().active.get(&state.principal),
        Some(&1)
    );
    drop(resolved);
    assert!(
        !tracker
            .state
            .lock()
            .unwrap()
            .active
            .contains_key(&state.principal)
    );
}

#[tokio::test]
async fn retired_principal_is_refused_before_first_log_namespace_creation() {
    let (_parent, root, mut state, tracker) = fixture();
    tracker.retire(&state.principal);
    state.log(LogLevel::Info, "not admitted".into());
    assert!(!root.home.log_dir().join("principals").exists());
}

#[tokio::test]
async fn pending_binding_never_retargets_a_reused_alias() {
    let (_parent, root, mut state, tracker) = fixture();
    let directory = PrincipalDirectory::default();
    let identity = astrid_storage::KvIdentityStore::with_principal_directory(
        astrid_storage::ScopedKvStore::new(
            Arc::new(astrid_storage::MemoryKvStore::new()),
            "system:identity",
        )
        .unwrap(),
        directory.clone(),
    );
    let principal = PrincipalId::new("reused").unwrap();
    let original = identity
        .create_principal(principal.clone(), [0x11; 32])
        .await
        .unwrap();
    state.principal = principal.clone();
    state.principal_directory = directory.clone();
    let binding = bind(Some(&root), &directory, &principal, "test", true, &tracker);
    state.deferred_logs = DeferredBindings::for_factory(Some(Arc::clone(&root)), binding.pending);
    let old = Arc::clone(state.deferred_logs.owner.as_ref().unwrap());
    identity.delete_user(original.id).await.unwrap();
    identity
        .create_principal(principal.clone(), [0x22; 32])
        .await
        .unwrap();
    let new_uid = directory.uid_for(&principal).unwrap();
    assert_ne!(old.uid, new_uid);
    state.log(LogLevel::Info, "cannot retarget".into());
    assert!(
        old.opened.get().is_none(),
        "deleted UID is refused before an open attempt"
    );
    assert!(!root.home.log_dir().join("principals").exists());
}

struct OpenPause {
    entered: SyncSender<()>,
    release: Receiver<()>,
}

thread_local! {
    static PAUSE_OPEN: RefCell<Option<OpenPause>> = const { RefCell::new(None) };
}

pub(super) fn before_open() -> io::Result<()> {
    if let Some(pause) = PAUSE_OPEN.with(|slot| slot.borrow_mut().take()) {
        pause.entered.send(()).map_err(io::Error::other)?;
        pause.release.recv().map_err(io::Error::other)?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn first_open_holds_directory_binding_against_direct_identity_unregister() {
    let (_parent, root, mut state, _tracker) = fixture();
    let directory = PrincipalDirectory::default();
    let identity = astrid_storage::KvIdentityStore::with_principal_directory(
        astrid_storage::ScopedKvStore::new(
            Arc::new(astrid_storage::MemoryKvStore::new()),
            "system:identity",
        )
        .unwrap(),
        directory.clone(),
    );
    let principal = PrincipalId::new("unregister-race").unwrap();
    let user = identity
        .create_principal(principal.clone(), [0x11; 32])
        .await
        .unwrap();
    state.principal = principal.clone();
    state.principal_directory = directory.clone();
    let binding = bind(
        Some(&root),
        &directory,
        &principal,
        "test",
        true,
        state.principal_invocations.as_ref().unwrap(),
    );
    state.deferred_logs = DeferredBindings::for_factory(Some(Arc::clone(&root)), binding.pending);
    let pending = Arc::clone(state.deferred_logs.owner.as_ref().unwrap());
    let (entered_tx, entered_rx) = sync_channel(0);
    let (release_tx, release_rx) = sync_channel(0);
    let writer = std::thread::spawn(move || {
        PAUSE_OPEN.with(|slot| {
            *slot.borrow_mut() = Some(OpenPause {
                entered: entered_tx,
                release: release_rx,
            })
        });
        state.log(LogLevel::Info, "admitted creation".into());
    });
    tokio::task::spawn_blocking(move || entered_rx.recv().unwrap())
        .await
        .unwrap();
    let (starting_tx, starting_rx) = tokio::sync::oneshot::channel();
    let removing = tokio::task::spawn_blocking(move || {
        let _ = starting_tx.send(());
        tokio::runtime::Handle::current()
            .block_on(identity.delete_user(user.id))
            .unwrap()
    });
    starting_rx.await.unwrap();
    let prematurely_finished = removing.is_finished();
    release_tx.send(()).unwrap();
    writer.join().unwrap();
    assert!(removing.await.unwrap());
    assert!(
        !prematurely_finished,
        "unregister must wait for the captured read binding"
    );
    assert!(directory.uid_for(&principal).is_err());
    assert!(contents(&root, &pending).contains("admitted creation"));
}

#[tokio::test]
async fn external_hook_file_fields_remain_eager_and_pure_across_common_clears() {
    use crate::engine::wasm::host_state::HookHostStateParams;

    let base = minimal_host_state(tokio::runtime::Handle::current());
    let mut state = HostState::for_hook(HookHostStateParams {
        store_meter: base.store_meter,
        capsule_id: base.capsule_id,
        workspace_root: base.workspace_root,
        vfs: base.vfs,
        vfs_root_handle: base.vfs_root_handle,
        kv: base.kv,
        kv_backend: base.kv_backend,
        secret_store: base.secret_store,
        http_limits: base.http_limits,
        event_bus: base.event_bus,
        runtime_handle: base.runtime_handle,
        process_tracker: base.process_tracker,
        persistent_processes: base.persistent_processes,
    });
    assert!(state.deferred_logs.root.is_none());
    assert!(state.effective_capsule_log().is_none());
    let parent = tempfile::tempdir().unwrap();
    let owner_path = parent.path().join("owner.log");
    let invocation_path = parent.path().join("invocation.log");
    let owner = open_log(&owner_path);
    let invocation = open_log(&invocation_path);
    state.capsule_log = Some(Arc::clone(&owner));
    state.invocation_capsule_log = Some(Arc::clone(&invocation));
    assert!(Arc::ptr_eq(
        state.effective_capsule_log().unwrap(),
        &invocation
    ));
    state.log(LogLevel::Info, "external invocation".into());
    assert!(!super::super::install_principal_overlays_sync(
        &mut state, None
    ));
    assert!(state.deferred_logs.root.is_none());
    assert!(state.deferred_logs.invocation.is_none());
    assert!(Arc::ptr_eq(state.effective_capsule_log().unwrap(), &owner));
    state.log(LogLevel::Info, "external owner".into());
    state.capsule_log = None;
    assert!(state.effective_capsule_log().is_none());
    state.log(LogLevel::Info, "no implicit lazy mode".into());
    assert_eq!(std::fs::read_dir(parent.path()).unwrap().count(), 2);
    assert!(
        std::fs::read_to_string(invocation_path)
            .unwrap()
            .contains("external invocation")
    );
    assert!(
        std::fs::read_to_string(owner_path)
            .unwrap()
            .contains("external owner")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn same_principal_recv_fast_path_keeps_one_pending_installation() {
    let (_parent, root, mut state, _tracker) = fixture();
    state.system_runtime = true;
    let alice = PrincipalId::new("alice").unwrap();
    caller(&mut state, &alice);
    let message = state.caller_context.take().unwrap();
    state.install_recv_invocation_context(&message);
    let first = Arc::clone(state.deferred_logs.invocation.as_ref().unwrap());
    state.install_recv_invocation_context(&message);
    assert!(Arc::ptr_eq(
        state.deferred_logs.invocation.as_ref().unwrap(),
        &first
    ));
    assert!(state.effective_capsule_log().is_none());
    assert!(!root.home.log_dir().join("principals").exists());
}

#[tokio::test]
async fn realized_file_poison_preserves_existing_tracing_fallback_behavior() {
    let (_parent, root, mut state, _tracker) = fixture();
    let owner = Arc::clone(state.deferred_logs.owner.as_ref().unwrap());
    state.log(LogLevel::Info, "before poison".into());
    let file = Arc::clone(state.effective_capsule_log().unwrap());
    let poisoner = Arc::clone(&file);
    let _ = std::thread::spawn(move || {
        let _held = poisoner.lock().unwrap();
        panic!("test poison");
    })
    .join();
    assert!(file.is_poisoned());
    state.log(LogLevel::Error, "fallback after poison".into());
    assert_eq!(contents(&root, &owner).lines().count(), 1);
    // ERROR duplication and failed-write/poison routing retain the unchanged
    // sys::log body and its existing should_emit_to_daemon_log regressions.
}

#[tokio::test]
async fn matching_alias_on_a_foreign_tracker_cannot_reuse_its_guard() {
    let (_parent, root, state, tracker) = fixture();
    let foreign = Arc::new(PrincipalInvocationTracker::default());
    let foreign_guard = foreign.begin(&state.principal).unwrap();
    tracker.retire(&state.principal);
    assert!(
        state
            .deferred_logs
            .owner
            .as_ref()
            .unwrap()
            .resolve(Some(&foreign_guard))
            .is_none()
    );
    assert!(!root.home.log_dir().join("principals").exists());
}

#[tokio::test]
async fn cached_owner_fallback_keeps_its_lifecycle_fence_without_directory_io() {
    let (_parent, root, mut state, tracker) = fixture();
    let owner = Arc::clone(state.deferred_logs.owner.as_ref().unwrap());
    state.log(LogLevel::Info, "owner admitted".into());
    assert!(state.capsule_log.is_some());
    caller(&mut state, &PrincipalId::new("alice").unwrap());
    tracker.retire(&state.principal);
    state.log(LogLevel::Info, "retired owner cannot borrow alice".into());
    assert_eq!(contents(&root, &owner).lines().count(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admitted_first_sys_log_open_and_write_drain_before_quiescence() {
    use crate::engine::wasm::QuiescenceObservationHook;

    let (_parent, root, mut state, tracker) = fixture();
    let owner = Arc::clone(state.deferred_logs.owner.as_ref().unwrap());
    let principal = state.principal.clone();
    let cancelled = state.cancel_token.clone();
    let (entered_tx, entered_rx) = sync_channel(0);
    let (release_tx, release_rx) = sync_channel(0);
    let writer = std::thread::spawn(move || {
        PAUSE_OPEN.with(|slot| {
            *slot.borrow_mut() = Some(OpenPause {
                entered: entered_tx,
                release: release_rx,
            })
        });
        state.log(LogLevel::Info, "admitted first write drains".into());
    });
    tokio::task::spawn_blocking(move || entered_rx.recv().unwrap())
        .await
        .unwrap();
    tracker.retire(&principal);
    cancelled.cancel();
    let (observed_tx, observed_rx) = tokio::sync::oneshot::channel();
    let (resume_tx, resume_rx) = tokio::sync::oneshot::channel();
    let waiting_tracker = Arc::clone(&tracker);
    let waiting_principal = principal.clone();
    let waiter = tokio::spawn(async move {
        waiting_tracker
            .wait_for_quiescence_with_observation_hook(
                &waiting_principal,
                QuiescenceObservationHook {
                    observed: observed_tx,
                    resume: resume_rx,
                },
            )
            .await;
    });
    observed_rx.await.unwrap();
    let active = tracker
        .state
        .lock()
        .unwrap()
        .active
        .get(&principal)
        .copied();
    release_tx.send(()).unwrap();
    writer.join().unwrap();
    resume_tx.send(()).unwrap();
    waiter.await.unwrap();
    assert_eq!(
        active,
        Some(1),
        "the existing operation must cover first open and write"
    );
    assert!(contents(&root, &owner).contains("admitted first write drains"));
    assert!(
        !tracker
            .state
            .lock()
            .unwrap()
            .active
            .contains_key(&principal)
    );
}

#[tokio::test]
async fn live_uid_rename_keeps_pinned_destination_and_admits_the_current_alias() {
    let (_parent, root, mut state, tracker) = fixture();
    let directory = PrincipalDirectory::default();
    let identity = astrid_storage::KvIdentityStore::with_principal_directory(
        astrid_storage::ScopedKvStore::new(
            Arc::new(astrid_storage::MemoryKvStore::new()),
            "system:identity",
        )
        .unwrap(),
        directory.clone(),
    );
    let original_alias = PrincipalId::new("before-rename").unwrap();
    let current_alias = PrincipalId::new("after-rename").unwrap();
    let user = identity
        .create_principal(original_alias.clone(), [0x11; 32])
        .await
        .unwrap();
    let uid = directory.uid_for(&original_alias).unwrap();
    state.principal = original_alias.clone();
    state.principal_directory = directory.clone();
    let binding = bind(
        Some(&root),
        &directory,
        &original_alias,
        "test",
        true,
        &tracker,
    );
    state.deferred_logs = DeferredBindings::for_factory(Some(Arc::clone(&root)), binding.pending);
    let pending = Arc::clone(state.deferred_logs.owner.as_ref().unwrap());
    let target = pending.target.clone();
    identity
        .bind_principal_identity(user.id, current_alias.clone(), [0x22; 32])
        .await
        .unwrap();
    assert!(directory.uid_for(&original_alias).is_err());
    assert_eq!(directory.uid_for(&current_alias).unwrap(), uid);
    tracker.retire(&current_alias);
    state.log(LogLevel::Info, "current alias is retired".into());
    assert!(
        pending.opened.get().is_none(),
        "admission rejection must allow a later resumed view to retry"
    );
    assert!(!root.home.log_dir().join("principals").exists());
    tracker.resume(&current_alias);
    state.log(LogLevel::Info, "renamed UID still logs".into());
    let opened = pending.opened.get().unwrap().as_ref().unwrap();
    assert_eq!(opened.principal_at_open, current_alias);
    assert_eq!(pending.target, target);
    assert!(contents(&root, &pending).contains("renamed UID still logs"));
    tracker.retire(&current_alias);
    state.log(
        LogLevel::Info,
        "warm fallback also respects actual admission alias".into(),
    );
    assert_eq!(contents(&root, &pending).lines().count(), 1);
    tracker.resume(&current_alias);
    state.log(LogLevel::Info, "resumed current view".into());
    assert_eq!(contents(&root, &pending).lines().count(), 2);
}

#[tokio::test]
async fn captured_runtime_uid_is_not_relooked_up_when_alias_is_reused_before_binding() {
    let (_parent, root, _state, tracker) = fixture();
    let directory = PrincipalDirectory::default();
    let identity = astrid_storage::KvIdentityStore::with_principal_directory(
        astrid_storage::ScopedKvStore::new(
            Arc::new(astrid_storage::MemoryKvStore::new()),
            "system:identity",
        )
        .unwrap(),
        directory.clone(),
    );
    let principal = PrincipalId::new("captured-alias").unwrap();
    let original = identity
        .create_principal(principal.clone(), [0x11; 32])
        .await
        .unwrap();
    let captured_uid = directory.uid_for(&principal).unwrap();
    identity.delete_user(original.id).await.unwrap();
    identity
        .create_principal(principal.clone(), [0x22; 32])
        .await
        .unwrap();
    assert_ne!(directory.uid_for(&principal).unwrap(), captured_uid);
    let binding = super::bind(
        Some(&root),
        &directory,
        &principal,
        "test",
        true,
        &tracker,
        Some(captured_uid),
    );
    let pending = binding.pending.unwrap();
    assert_eq!(pending.uid, captured_uid);
    assert!(pending.resolve(None).is_none());
    assert!(!root.home.log_dir().join("principals").exists());
}
