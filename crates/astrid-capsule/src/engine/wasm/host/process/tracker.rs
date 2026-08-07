//! Process cancellation tracker — maps PIDs to optional `call_id`s so
//! a `tool.v1.request.cancel` event with specific call IDs only kills
//! the matching child processes.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, Weak};
#[cfg(unix)]
use std::time::Duration;

#[cfg(not(unix))]
use tracing::warn;

/// Grace period between SIGINT and SIGKILL when cancelling processes.
#[cfg(unix)]
const SIGKILL_GRACE_PERIOD: Duration = Duration::from_secs(2);

#[derive(Debug)]
struct TrackedProcess {
    call_id: Option<String>,
    owner: TrackedOwner,
}

#[derive(Debug)]
enum TrackedOwner {
    /// Compatibility entry created through the original public PID API.
    Legacy,
    /// Internal process-tree owner used by the hardened host implementation.
    Tree {
        identity: u64,
        tree: Weak<super::platform::ProcessTree>,
    },
}

#[derive(Debug)]
struct CancellationTarget {
    pid: u32,
    #[cfg(unix)]
    identity: Option<u64>,
    tree: Option<Arc<super::platform::ProcessTree>>,
}

impl TrackedProcess {
    fn target(&self, pid: u32) -> Option<CancellationTarget> {
        match &self.owner {
            TrackedOwner::Legacy => Some(CancellationTarget {
                pid,
                #[cfg(unix)]
                identity: None,
                tree: None,
            }),
            TrackedOwner::Tree { identity, tree } => {
                #[cfg(not(unix))]
                let _ = identity;
                tree.upgrade().map(|tree| CancellationTarget {
                    pid,
                    #[cfg(unix)]
                    identity: Some(*identity),
                    tree: Some(tree),
                })
            },
        }
    }
}

/// Tracks active child process PIDs for cancellation, with optional
/// call_id association for multi-session scoping.
#[derive(Debug, Default)]
pub struct ProcessTracker {
    active_pids: Arc<Mutex<HashMap<u32, TrackedProcess>>>,
}

impl ProcessTracker {
    /// Construct a fresh tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a child process PID with an optional call_id.
    ///
    /// This preserves the original public API for external callers. The
    /// process host itself uses [`Self::register_tree`] so Windows cancellation
    /// owns the whole descendant tree and PID reuse is identity-checked.
    pub fn register(&self, pid: u32, call_id: Option<String>) {
        if pid == 0 {
            return;
        }
        self.active_pids
            .lock()
            .expect("process tracker lock poisoned")
            .insert(
                pid,
                TrackedProcess {
                    call_id,
                    owner: TrackedOwner::Legacy,
                },
            );
    }

    /// Register a stable process-tree owner with an optional call_id.
    pub(super) fn register_tree(
        &self,
        tree: &Arc<super::platform::ProcessTree>,
        call_id: Option<String>,
    ) {
        self.active_pids
            .lock()
            .expect("process tracker lock poisoned")
            .insert(
                tree.pid(),
                TrackedProcess {
                    call_id,
                    owner: TrackedOwner::Tree {
                        identity: tree.identity(),
                        tree: Arc::downgrade(tree),
                    },
                },
            );
    }

    /// Whether any child process is currently registered as running.
    ///
    /// The workspace copy-on-write promote/rollback interlock consults this to
    /// refuse mutating the merged tree while a spawned process (e.g. a `cargo`
    /// with `cwd == merged`) may still be running in it — swapping and deleting
    /// the tree under it would corrupt or destroy its work.
    #[must_use]
    pub fn has_active(&self) -> bool {
        let mut active = self
            .active_pids
            .lock()
            .expect("process tracker lock poisoned");
        active.retain(|_, tracked| match &tracked.owner {
            TrackedOwner::Legacy => true,
            TrackedOwner::Tree { tree, .. } => tree.strong_count() > 0,
        });
        !active.is_empty()
    }

    /// Unregister a child process PID (process has exited).
    pub fn unregister(&self, pid: u32) {
        self.active_pids
            .lock()
            .expect("process tracker lock poisoned")
            .remove(&pid);
    }

    /// Unregister only if the stable identity still matches this tree owner.
    pub(super) fn unregister_tree(&self, tree: &super::platform::ProcessTree) {
        self.unregister_identity(tree.pid(), tree.identity());
    }

    fn unregister_identity(&self, pid: u32, identity: u64) {
        let mut active = self
            .active_pids
            .lock()
            .expect("process tracker lock poisoned");
        if active.get(&pid).is_some_and(|tracked| {
            matches!(
                &tracked.owner,
                TrackedOwner::Tree {
                    identity: current,
                    ..
                } if *current == identity
            )
        }) {
            active.remove(&pid);
        }
    }

    /// Cancel processes matching the given call_ids.
    ///
    /// Kills processes whose call_id matches one of the provided IDs,
    /// plus any processes with no call_id (conservative fallback).
    pub fn cancel_by_call_ids(&self, call_ids: &[String], handle: &tokio::runtime::Handle) {
        if call_ids.is_empty() {
            return;
        }
        let call_id_set: HashSet<&String> = call_ids.iter().collect();
        let targets: Vec<CancellationTarget> = self
            .active_pids
            .lock()
            .expect("process tracker lock poisoned")
            .iter()
            .filter_map(|(&pid, tracked)| match &tracked.call_id {
                None => tracked.target(pid),
                Some(id) if call_id_set.contains(id) => tracked.target(pid),
                Some(_) => None,
            })
            .collect();

        self.signal_targets(&targets, handle);
    }

    /// Cancel all tracked processes. Unix receives SIGINT then SIGKILL after
    /// a grace period; Windows terminates each descendant tree immediately.
    pub fn cancel_all(&self, handle: &tokio::runtime::Handle) {
        let targets: Vec<CancellationTarget> = self
            .active_pids
            .lock()
            .expect("process tracker lock poisoned")
            .iter()
            .filter_map(|(&pid, tracked)| tracked.target(pid))
            .collect();
        self.signal_targets(&targets, handle);
    }

    fn signal_targets(&self, targets: &[CancellationTarget], handle: &tokio::runtime::Handle) {
        if targets.is_empty() {
            return;
        }

        #[cfg(unix)]
        {
            for target in targets {
                if let Some(tree) = &target.tree {
                    let _ = super::platform::signal_root_process(
                        tree,
                        crate::engine::wasm::bindings::astrid::process1_1_0::host::ProcessSignal::Int,
                    );
                } else if let Ok(raw) = i32::try_from(target.pid) {
                    let _ = nix::sys::signal::kill(
                        nix::unistd::Pid::from_raw(raw),
                        nix::sys::signal::Signal::SIGINT,
                    );
                }
            }

            let tracker = self.active_pids.clone();
            let targets: Vec<(u32, Option<u64>)> = targets
                .iter()
                .map(|target| (target.pid, target.identity))
                .collect();
            handle.spawn(async move {
                tokio::time::sleep(SIGKILL_GRACE_PERIOD).await;
                for (pid, identity) in targets {
                    let still_current = tracker
                        .lock()
                        .expect("process tracker lock poisoned")
                        .get(&pid)
                        .is_some_and(|tracked| match (&tracked.owner, identity) {
                            (TrackedOwner::Legacy, None) => true,
                            (
                                TrackedOwner::Tree {
                                    identity: current, ..
                                },
                                Some(expected),
                            ) => *current == expected,
                            _ => false,
                        });
                    if still_current && let Ok(raw) = i32::try_from(pid) {
                        let _ = nix::sys::signal::kill(
                            nix::unistd::Pid::from_raw(raw),
                            nix::sys::signal::Signal::SIGKILL,
                        );
                    }
                }
            });
        }

        #[cfg(windows)]
        {
            let _ = handle;
            for target in targets {
                let Some(tree) = &target.tree else {
                    warn!(
                        pid = target.pid,
                        "legacy PID-only process tracking cannot own a Windows descendant tree"
                    );
                    continue;
                };
                if let Err(error) = tree.terminate(super::platform::Termination::Force) {
                    warn!(
                        pid = tree.pid(),
                        ?error,
                        "failed to terminate Windows process tree"
                    );
                }
            }
        }

        #[cfg(not(any(unix, windows)))]
        {
            let _ = handle;
            for target in targets {
                warn!(
                    pid = target.pid,
                    "process cancellation unsupported on this platform; leaving tracker entry active"
                );
            }
        }
    }

    /// Test helper: snapshot the active PID set. Visible only under
    /// `cfg(test)` so production callers can't introspect the map.
    #[cfg(test)]
    pub(crate) fn active_pids_snapshot(&self) -> Vec<u32> {
        let mut v: Vec<u32> = self
            .active_pids
            .lock()
            .expect("process tracker lock poisoned")
            .keys()
            .copied()
            .collect();
        v.sort_unstable();
        v
    }
}

#[cfg(test)]
mod tests {
    //! Regression tests for the `spawn_background` registration fix.
    //!
    //! PR #752 review surfaced that backgrounded children were never
    //! registered in the tracker, so `cancel_by_call_ids` could not
    //! reach them on capsule unload. These tests pin the contract
    //! `spawn_background` relies on.
    use super::*;

    fn register_tree_sentinel(
        tracker: &ProcessTracker,
        pid: u32,
        identity: u64,
        call_id: Option<String>,
    ) {
        if pid == 0 {
            return;
        }
        tracker
            .active_pids
            .lock()
            .expect("process tracker lock poisoned")
            .insert(
                pid,
                TrackedProcess {
                    call_id,
                    owner: TrackedOwner::Tree {
                        identity,
                        tree: Weak::new(),
                    },
                },
            );
    }

    #[test]
    fn register_adds_pid() {
        let t = ProcessTracker::new();
        t.register(42, None);
        assert_eq!(t.active_pids_snapshot(), vec![42]);
        assert!(t.has_active());
    }

    #[test]
    fn unregister_removes_pid() {
        let t = ProcessTracker::new();
        t.register(42, None);
        t.register(99, Some("call-a".into()));
        t.unregister(42);
        assert_eq!(t.active_pids_snapshot(), vec![99]);
    }

    #[test]
    fn pid_zero_is_rejected() {
        let t = ProcessTracker::new();
        t.register(0, None);
        assert!(t.active_pids_snapshot().is_empty());
    }

    #[test]
    fn double_register_overwrites_call_id() {
        // Re-registering a PID with a different call_id must replace
        // the prior entry, otherwise stale call_id associations leak.
        let t = ProcessTracker::new();
        t.register(42, Some("call-a".into()));
        t.register(42, Some("call-b".into()));
        assert_eq!(t.active_pids_snapshot(), vec![42]);
    }

    #[test]
    fn unregister_after_register_clears_call_id_match() {
        // The contract relied on by `spawn_background`'s drop path:
        // register on spawn, unregister on child exit. After
        // unregister, `cancel_by_call_ids` must find no PIDs to
        // signal — verified here by observing the snapshot is empty.
        let t = ProcessTracker::new();
        t.register(42, Some("call-a".into()));
        t.unregister(42);
        assert!(t.active_pids_snapshot().is_empty());
    }

    #[test]
    fn stale_unregister_does_not_remove_reused_pid_owner() {
        let t = ProcessTracker::new();
        register_tree_sentinel(&t, 42, 100, Some("old".into()));
        register_tree_sentinel(&t, 42, 200, Some("new".into()));

        t.unregister_identity(42, 100);
        assert_eq!(t.active_pids_snapshot(), vec![42]);
        assert_eq!(
            t.active_pids
                .lock()
                .expect("process tracker lock poisoned")
                .get(&42)
                .and_then(|tracked| match &tracked.owner {
                    TrackedOwner::Tree { identity, .. } => Some(*identity),
                    TrackedOwner::Legacy => None,
                }),
            Some(200)
        );
    }
}
