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
}
