//! First-write operational logs for private engine-owned host states.
//!
//! Public HostState file fields and its pure effective getter remain the eager
//! embedding interface. Only the engine factory installs these private bindings.

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use astrid_core::dirs::AstridHome;
use astrid_core::{PrincipalId, PrincipalUid};
use astrid_storage::PrincipalDirectory;

use super::host_state::HostState;
use super::{PrincipalInvocationGuard, PrincipalInvocationTracker};

pub(super) mod eager;

type LogFile = Arc<Mutex<File>>;

/// One captured native home authority shared by this runtime's operational logs.
///
/// Creating this service opens no log file or log directory. Passing it to a
/// loader opts only its private engine-owned stores into first-write creation;
/// standalone host states retain their eager public-file behavior.
pub struct NativeLogRoot {
    home: AstridHome,
    #[cfg(any(unix, windows))]
    root: astrid_core::platform_fs::PrivateAppendRoot,
}

impl NativeLogRoot {
    /// Capture an already-admitted private native home without creating paths.
    ///
    /// # Errors
    /// Rejects a missing, redirected or nonprivate home, or unsupported backend.
    pub fn capture(home: &AstridHome) -> io::Result<Self> {
        #[cfg(any(unix, windows))]
        {
            let root =
                astrid_core::platform_fs::PrivateProjectionInspection::try_open(home.root())?
                    .capture_append_root()?;
            Ok(Self {
                home: home.clone(),
                root,
            })
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = home;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "native append authority unavailable",
            ))
        }
    }

    fn open(&self, relative: &Path) -> io::Result<File> {
        #[cfg(any(unix, windows))]
        {
            self.root.open_private_append(relative)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = relative;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "native append authority unavailable",
            ))
        }
    }
}

impl super::WasmEngine {
    #[must_use]
    pub(crate) fn with_native_log_root(mut self, root: Option<Arc<NativeLogRoot>>) -> Self {
        self.native_log_root = root;
        self
    }
}

#[derive(Default)]
pub(super) struct DeferredBindings {
    root: Option<Arc<NativeLogRoot>>,
    owner: Option<Arc<PendingLog>>,
    invocation: Option<Arc<PendingLog>>,
}

impl DeferredBindings {
    pub(super) fn for_factory(
        root: Option<Arc<NativeLogRoot>>,
        owner: Option<Arc<PendingLog>>,
    ) -> Self {
        Self {
            root,
            owner,
            invocation: None,
        }
    }

    pub(super) fn clear_invocation(&mut self) {
        self.invocation = None;
    }

    pub(super) fn inherit_owner(&mut self) {
        self.invocation = self.owner.clone();
    }
}

#[derive(Default)]
pub(super) struct Binding {
    pub(super) file: Option<LogFile>,
    pub(super) pending: Option<Arc<PendingLog>>,
}

pub(super) struct PendingLog {
    uid: PrincipalUid,
    // Immutable relative target pins the UTC date at binding installation.
    target: PathBuf,
    root: Arc<NativeLogRoot>,
    directory: PrincipalDirectory,
    tracker: Arc<PrincipalInvocationTracker>,
    opened: OnceLock<Option<LogFile>>,
}

pub(super) fn bind(
    root: Option<&Arc<NativeLogRoot>>,
    directory: &PrincipalDirectory,
    principal: &PrincipalId,
    capsule: &str,
    prune: bool,
    tracker: &Arc<PrincipalInvocationTracker>,
    captured_uid: Option<PrincipalUid>,
) -> Binding {
    let Some(root) = root else {
        return Binding {
            file: super::open_capsule_log(directory, principal, capsule, prune),
            pending: None,
        };
    };
    let Some(uid) = captured_uid else {
        return Binding::default();
    };
    if !valid_name(capsule) {
        return Binding::default();
    }
    let group = Path::new("log")
        .join("principals")
        .join(uid.to_string())
        .join(capsule);
    // This observation only chooses an optimization. Every actual open remains
    // relative to captured home authority and verifies the pinned live binding.
    // Existing history keeps eager rotation/pruning and today's empty-file rule.
    let absent = std::fs::symlink_metadata(root.home.root().join(&group))
        .is_err_and(|error| error.kind() == io::ErrorKind::NotFound);
    if !absent {
        let file = directory
            .with_live_uid_binding(uid, |current| {
                let Some(_operation) = tracker.begin(current) else {
                    return Ok(None);
                };
                Ok(eager::open_capsule_log_at_uid(
                    &root.home.log_dir(),
                    uid,
                    capsule,
                    prune,
                ))
            })
            .ok()
            .flatten()
            .flatten();
        return Binding {
            file,
            pending: None,
        };
    }
    Binding {
        file: None,
        pending: Some(Arc::new(PendingLog {
            uid,
            target: group.join(format!("{}.log", super::today_date_string())),
            root: Arc::clone(root),
            directory: directory.clone(),
            tracker: Arc::clone(tracker),
            opened: OnceLock::new(),
        })),
    }
}

pub(super) fn install_invocation(
    state: &mut HostState,
    principal: &PrincipalId,
    uid: PrincipalUid,
) {
    state.deferred_logs.clear_invocation();
    let Some(root) = state.deferred_logs.root.as_ref() else {
        state.invocation_capsule_log = super::open_capsule_log(
            &state.principal_directory,
            principal,
            state.capsule_id.as_str(),
            false,
        );
        return;
    };
    let Some(tracker) = state.principal_invocations.as_ref() else {
        state.invocation_capsule_log = None;
        return;
    };
    let binding = bind(
        Some(root),
        &state.principal_directory,
        principal,
        state.capsule_id.as_str(),
        false,
        tracker,
        Some(uid),
    );
    state.invocation_capsule_log = binding.file;
    state.deferred_logs.invocation = binding.pending;
}

pub(super) struct ResolvedLog {
    pub(super) file: Option<LogFile>,
    // A different owner's first-open/write must drain under that owner's fence,
    // not merely under the invoking principal's already-admitted operation.
    _owner_operation: Option<PrincipalInvocationGuard>,
}

impl PendingLog {
    fn admit(
        &self,
        principal: &PrincipalId,
        admitted: Option<&PrincipalInvocationGuard>,
    ) -> Option<Option<PrincipalInvocationGuard>> {
        let covered = admitted.is_some_and(|guard| {
            Arc::ptr_eq(&guard.tracker, &self.tracker) && &guard.principal == principal
        });
        if covered {
            Some(None)
        } else {
            self.tracker.begin(principal).map(Some)
        }
    }

    fn resolve(&self, admitted: Option<&PrincipalInvocationGuard>) -> Option<ResolvedLog> {
        // Resolve only the immutable UID's current live alias. A rename keeps
        // the UID/date destination; alias reuse can never select another UID.
        self.directory
            .with_live_uid_binding(self.uid, |current| {
                let Some(operation) = self.admit(current, admitted) else {
                    return Ok(None);
                };
                // Admission failure deliberately does not initialize the cache:
                // a resumed view can retry. Only an attempted filesystem open is
                // cached, and no lifecycle guard is retained beyond this write.
                let opened = self.opened.get_or_init(|| {
                    #[cfg(test)]
                    tests::before_open().ok()?;
                    let file = self.root.open(&self.target).ok()?;
                    Some(Arc::new(Mutex::new(file)))
                });
                Ok(opened.as_ref().map(|opened| ResolvedLog {
                    file: Some(Arc::clone(opened)),
                    _owner_operation: operation,
                }))
            })
            .ok()
            .flatten()
            .flatten()
    }
}

pub(super) fn resolve(
    state: &mut HostState,
    admitted: Option<&PrincipalInvocationGuard>,
) -> ResolvedLog {
    // Explicit file injection always wins. The public getter remains pure and
    // never realizes pending state, including for external hook/recv contexts.
    if let Some(file) = &state.invocation_capsule_log {
        return resolve_file(file, state.deferred_logs.invocation.as_ref(), admitted);
    }
    if let Some(pending) = &state.deferred_logs.invocation
        && let Some(resolved) = pending.resolve(admitted)
    {
        state.invocation_capsule_log = resolved.file.clone();
        return resolved;
    }
    if let Some(file) = &state.capsule_log {
        return resolve_file(file, state.deferred_logs.owner.as_ref(), admitted);
    }
    if let Some(pending) = &state.deferred_logs.owner
        && let Some(resolved) = pending.resolve(admitted)
    {
        state.capsule_log = resolved.file.clone();
        return resolved;
    }
    ResolvedLog {
        file: None,
        _owner_operation: None,
    }
}

fn resolve_file(
    file: &LogFile,
    pending: Option<&Arc<PendingLog>>,
    admitted: Option<&PrincipalInvocationGuard>,
) -> ResolvedLog {
    // Only files known to originate in our private cache carry its owner fence.
    // Arbitrary explicit File injections retain the existing eager interface.
    let cached = pending.filter(|pending| {
        pending
            .opened
            .get()
            .and_then(Option::as_ref)
            .is_some_and(|opened| Arc::ptr_eq(opened, file))
    });
    if let Some(pending) = cached {
        // The FD stays UID-bound, but aliases and their lifecycle views can
        // change. Reuse the same live-binding admission for warm writes;
        // the initialized OnceLock performs no filesystem open or lookup.
        return pending.resolve(admitted).unwrap_or(ResolvedLog {
            file: None,
            _owner_operation: None,
        });
    }
    ResolvedLog {
        file: Some(Arc::clone(file)),
        _owner_operation: None,
    }
}

pub(super) fn valid_name(capsule: &str) -> bool {
    let mut components = Path::new(capsule).components();
    !capsule.is_empty()
        && matches!(components.next(), Some(std::path::Component::Normal(_)))
        && components.next().is_none()
}

#[cfg(test)]
mod tests;
