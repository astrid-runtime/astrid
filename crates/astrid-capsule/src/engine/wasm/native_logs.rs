//! First-write operational logs for private engine-owned host states.
//!
//! Public HostState file fields and its pure effective getter remain the eager
//! embedding interface. Only the engine factory installs these private bindings.

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use astrid_core::PrincipalUid;
use astrid_core::dirs::AstridHome;
use astrid_storage::PrincipalDirectory;

use super::host_state::HostState;
use super::{PrincipalInvocationGuard, PrincipalInvocationTracker};

mod admission;
pub(super) mod dispatch;
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
    owner: Option<Arc<BoundLog>>,
    invocation: Option<Arc<BoundLog>>,
}

impl DeferredBindings {
    pub(super) fn for_factory(
        root: Option<Arc<NativeLogRoot>>,
        owner: Option<Arc<BoundLog>>,
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
    pub(super) bound: Option<Arc<BoundLog>>,
}

pub(super) struct BoundLog {
    uid: PrincipalUid,
    source: LogSource,
    directory: PrincipalDirectory,
    tracker: Arc<PrincipalInvocationTracker>,
}

enum LogSource {
    Eager(LogFile),
    Deferred(DeferredFile),
}

struct DeferredFile {
    // Immutable relative target pins the UTC date at binding installation.
    target: PathBuf,
    root: Arc<NativeLogRoot>,
    opened: OnceLock<Option<LogFile>>,
}

pub(super) fn bind(
    root: Option<&Arc<NativeLogRoot>>,
    directory: &PrincipalDirectory,
    capsule: &str,
    prune: bool,
    tracker: &Arc<PrincipalInvocationTracker>,
    captured_uid: Option<PrincipalUid>,
) -> Binding {
    let Some(uid) = captured_uid else {
        return Binding::default();
    };
    if !valid_name(capsule) {
        return Binding::default();
    }
    let eager_binding = || {
        let file = directory
            .with_live_uid_binding(uid, |current| {
                let Some(_operation) = tracker.begin(current) else {
                    return Ok(None);
                };
                let log_dir = match root {
                    Some(root) => root.home.log_dir(),
                    None => AstridHome::resolve()?.log_dir(),
                };
                Ok(eager::open_capsule_log_at_uid(
                    &log_dir, uid, capsule, prune,
                ))
            })
            .ok()
            .flatten()
            .flatten();
        let binding = file.as_ref().map(|file| {
            Arc::new(BoundLog {
                uid,
                directory: directory.clone(),
                tracker: Arc::clone(tracker),
                source: LogSource::Eager(Arc::clone(file)),
            })
        });
        Binding {
            file,
            bound: binding,
        }
    };
    let Some(root) = root else {
        return eager_binding();
    };
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
        return eager_binding();
    }
    Binding {
        file: None,
        bound: Some(Arc::new(BoundLog {
            uid,
            directory: directory.clone(),
            tracker: Arc::clone(tracker),
            source: LogSource::Deferred(DeferredFile {
                target: group.join(format!("{}.log", super::today_date_string())),
                root: Arc::clone(root),
                opened: OnceLock::new(),
            }),
        })),
    }
}

pub(super) fn install_invocation(state: &mut HostState, uid: PrincipalUid) {
    state.deferred_logs.clear_invocation();
    let Some(tracker) = state.principal_invocations.as_ref() else {
        state.invocation_capsule_log = None;
        return;
    };
    let binding = bind(
        state.deferred_logs.root.as_ref(),
        &state.principal_directory,
        state.capsule_id.as_str(),
        false,
        tracker,
        Some(uid),
    );
    state.invocation_capsule_log = binding.file;
    state.deferred_logs.invocation = binding.bound;
}

pub(super) type ResolvedLog<'a> =
    dispatch::Destination<LogFile, admission::Operation<'a, PrincipalInvocationGuard>>;

impl BoundLog {
    fn resolve<'a>(
        &self,
        admitted: Option<&'a PrincipalInvocationGuard>,
    ) -> Option<ResolvedLog<'a>> {
        // Resolve only the immutable UID's current live alias. A rename keeps
        // the UID/date destination; alias reuse can never select another UID.
        self.directory
            .with_live_uid_binding(self.uid, |current| {
                let Some(operation) = admission::admit(
                    &self.tracker,
                    current,
                    admitted,
                    PrincipalInvocationGuard::belongs_to,
                    PrincipalInvocationTracker::begin,
                ) else {
                    return Ok(None);
                };
                // Admission failure deliberately does not initialize the cache:
                // a resumed view can retry. Only an attempted filesystem open is
                // cached, and no lifecycle guard is retained beyond this write.
                let opened = match &self.source {
                    LogSource::Eager(file) => Some(file),
                    LogSource::Deferred(deferred) => deferred
                        .opened
                        .get_or_init(|| {
                            #[cfg(test)]
                            tests::before_open().ok()?;
                            let file = deferred.root.open(&deferred.target).ok()?;
                            Some(Arc::new(Mutex::new(file)))
                        })
                        .as_ref(),
                };
                Ok(opened.map(|opened| ResolvedLog::Managed(Arc::clone(opened), operation)))
            })
            .ok()
            .flatten()
            .flatten()
    }
}

pub(super) fn resolve<'a>(
    state: &mut HostState,
    admitted: Option<&'a PrincipalInvocationGuard>,
) -> ResolvedLog<'a> {
    // Explicit file injection always wins. The public getter remains pure and
    // never realizes pending state, including for external hook/recv contexts.
    if let Some(file) = &state.invocation_capsule_log {
        return resolve_file(file, state.deferred_logs.invocation.as_ref(), admitted);
    }
    if let Some(pending) = &state.deferred_logs.invocation
        && matches!(pending.source, LogSource::Deferred(_))
        && let Some(resolved) = pending.resolve(admitted)
    {
        state.invocation_capsule_log = resolved.file().cloned();
        return resolved;
    }
    if let Some(file) = &state.capsule_log {
        return resolve_file(file, state.deferred_logs.owner.as_ref(), admitted);
    }
    if let Some(pending) = &state.deferred_logs.owner
        && matches!(pending.source, LogSource::Deferred(_))
        && let Some(resolved) = pending.resolve(admitted)
    {
        state.capsule_log = resolved.file().cloned();
        return resolved;
    }
    ResolvedLog::Absent
}

fn resolve_file<'a>(
    file: &LogFile,
    pending: Option<&Arc<BoundLog>>,
    admitted: Option<&'a PrincipalInvocationGuard>,
) -> ResolvedLog<'a> {
    // All engine-bound handles carry their owner fence on every write.
    // Arbitrary explicit File injections retain the existing eager interface.
    let cached = pending.filter(|pending| {
        let managed = match &pending.source {
            LogSource::Eager(file) => Some(file),
            LogSource::Deferred(deferred) => deferred.opened.get().and_then(Option::as_ref),
        };
        managed.is_some_and(|opened| Arc::ptr_eq(opened, file))
    });
    if let Some(pending) = cached {
        // The FD stays UID-bound, but aliases and their lifecycle views can
        // change. Reuse the same live-binding admission for warm writes;
        // the initialized OnceLock performs no filesystem open or lookup.
        return pending.resolve(admitted).unwrap_or(ResolvedLog::Absent);
    }
    ResolvedLog::Explicit(Arc::clone(file))
}

pub(super) fn valid_name(capsule: &str) -> bool {
    let mut components = Path::new(capsule).components();
    !capsule.is_empty()
        && matches!(components.next(), Some(std::path::Component::Normal(_)))
        && components.next().is_none()
}

#[cfg(test)]
mod tests;
