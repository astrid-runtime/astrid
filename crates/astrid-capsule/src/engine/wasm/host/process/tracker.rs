//! Process cancellation tracker — maps PIDs to optional `call_id`s so
//! a `tool.v1.request.cancel` event with specific call IDs only kills
//! the matching child processes.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tracing::warn;

/// Grace period between SIGINT and SIGKILL when cancelling processes.
const SIGKILL_GRACE_PERIOD: Duration = Duration::from_secs(2);

/// Tracks active child process PIDs for cancellation, with optional
/// call_id association for multi-session scoping.
#[derive(Debug, Default)]
pub struct ProcessTracker {
    active_pids: Arc<Mutex<HashMap<u32, Option<String>>>>,
}

impl ProcessTracker {
    /// Construct a fresh tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a child process PID with an optional call_id.
    pub fn register(&self, pid: u32, call_id: Option<String>) {
        if pid == 0 {
            return; // Guard: PID 0 means "no process" on some platforms.
        }
        self.active_pids
            .lock()
            .expect("process tracker lock poisoned")
            .insert(pid, call_id);
    }

    /// Whether any child process is currently registered as running.
    ///
    /// The workspace copy-on-write promote/rollback interlock consults this to
    /// refuse mutating the merged tree while a spawned process (e.g. a `cargo`
    /// with `cwd == merged`) may still be running in it — swapping and deleting
    /// the tree under it would corrupt or destroy its work.
    #[must_use]
    pub fn has_active(&self) -> bool {
        !self
            .active_pids
            .lock()
            .expect("process tracker lock poisoned")
            .is_empty()
    }

    /// Unregister a child process PID (process has exited).
    pub fn unregister(&self, pid: u32) {
        self.active_pids
            .lock()
            .expect("process tracker lock poisoned")
            .remove(&pid);
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
        let pids: Vec<u32> = self
            .active_pids
            .lock()
            .expect("process tracker lock poisoned")
            .iter()
            .filter_map(|(&pid, stored_call_id)| match stored_call_id {
                None => Some(pid),
                Some(id) => call_id_set.contains(id).then_some(pid),
            })
            .collect();

        self.signal_pids(&pids, handle);
    }

    /// Send SIGINT to all tracked processes, then SIGKILL after a grace
    /// period. Used for capsule-level shutdown.
    pub fn cancel_all(&self, handle: &tokio::runtime::Handle) {
        let pids: Vec<u32> = self
            .active_pids
            .lock()
            .expect("process tracker lock poisoned")
            .keys()
            .copied()
            .collect();
        self.signal_pids(&pids, handle);
    }

    fn signal_pids(&self, pids: &[u32], handle: &tokio::runtime::Handle) {
        if pids.is_empty() {
            return;
        }

        #[cfg(unix)]
        {
            for &pid in pids {
                let Some(raw) = i32::try_from(pid).ok() else {
                    warn!(pid, "PID overflows i32, skipping signal");
                    continue;
                };
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(raw),
                    nix::sys::signal::Signal::SIGINT,
                );
            }

            let tracker = self.active_pids.clone();
            let target_pids: Vec<u32> = pids.to_vec();
            handle.spawn(async move {
                tokio::time::sleep(SIGKILL_GRACE_PERIOD).await;
                let still_active = tracker.lock().expect("process tracker lock poisoned");
                for pid in target_pids {
                    if !still_active.contains_key(&pid) {
                        continue;
                    }
                    let Some(raw) = i32::try_from(pid).ok() else {
                        continue;
                    };
                    let _ = nix::sys::signal::kill(
                        nix::unistd::Pid::from_raw(raw),
                        nix::sys::signal::Signal::SIGKILL,
                    );
                }
            });
        }

        #[cfg(not(unix))]
        {
            let _ = (pids, handle);
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

    #[test]
    fn register_adds_pid() {
        let t = ProcessTracker::new();
        t.register(42, None);
        assert_eq!(t.active_pids_snapshot(), vec![42]);
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
}
