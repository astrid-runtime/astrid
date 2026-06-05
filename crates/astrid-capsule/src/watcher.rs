//! Hot-reload file watcher for capsules.
//!
//! Tracked by #296 - wire into kernel lifecycle or remove.
#![allow(dead_code)]
//!
//! Watches capsule source directories for file changes, debounces events,
//! and emits [`WatchEvent`]s when capsule source content actually changes
//! (verified via blake3 hashing). Runs as a daemon background task,
//! enabled by default via `gateway.watch_plugins` in config.
//!
//! # Architecture
//!
//! ```text
//! filesystem events (notify)
//!   → filter ignored dirs (node_modules, target, dist, .git)
//!   → map to capsule directory
//!   → debounce 500ms per capsule
//!   → blake3 hash source tree
//!   → compare to cached hash
//!   → emit WatchEvent::CapsuleChanged
//! ```

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::discovery::MANIFEST_FILE_NAME;
use crate::error::CapsuleResult;

/// Default debounce interval for file change events.
pub(crate) const DEFAULT_DEBOUNCE: Duration = Duration::from_millis(500);

/// Directory names to ignore during file watching.
pub(crate) const IGNORED_DIRS: &[&str] = &["node_modules", "target", "dist", ".git"];

/// File extensions to exclude from source hashing (generated artifacts).
const IGNORED_EXTENSIONS: &[&str] = &["wasm"];

/// Events emitted by the capsule watcher.
#[derive(Debug, Clone)]
pub(crate) enum WatchEvent {
    /// A capsule's source files changed and may need recompilation.
    CapsuleChanged {
        /// The capsule's root directory (contains `Capsule.toml`).
        capsule_dir: PathBuf,
        /// blake3 hash of the capsule's source tree after the change.
        source_hash: String,
    },
    /// Watcher encountered a non-fatal error.
    Error(String),
}

/// Configuration for the capsule watcher.
#[derive(Debug, Clone)]
pub(crate) struct WatcherConfig {
    /// Root directories to watch. Each should contain capsule subdirectories.
    pub watch_paths: Vec<PathBuf>,
    /// Debounce interval. File changes within this window are coalesced.
    pub debounce: Duration,
}

impl Default for WatcherConfig {
    fn default() -> Self {
        Self {
            watch_paths: Vec::new(),
            debounce: DEFAULT_DEBOUNCE,
        }
    }
}

/// Watches capsule source directories for changes and emits [`WatchEvent`]s.
///
/// Uses the `notify` crate for cross-platform filesystem watching and blake3
/// hashing to prevent unnecessary recompilation when file contents haven't
/// actually changed.
pub(crate) struct CapsuleWatcher {
    config: WatcherConfig,
    /// blake3 hash cache per capsule directory.
    hash_cache: HashMap<PathBuf, String>,
    /// The `notify` filesystem watcher handle. Kept alive for the duration
    /// of the watcher's lifetime — dropping it stops filesystem monitoring.
    watcher: RecommendedWatcher,
    /// Receives raw filesystem events from the `notify` callback thread.
    raw_rx: mpsc::UnboundedReceiver<notify::Result<Event>>,
    /// Sends processed [`WatchEvent`]s to the consumer.
    event_tx: mpsc::Sender<WatchEvent>,
}

impl CapsuleWatcher {
    /// Create a new capsule watcher.
    ///
    /// Returns the watcher and a receiver for [`WatchEvent`]s. Call
    /// [`run()`](Self::run) to start the event loop.
    ///
    /// # Errors
    ///
    /// Returns an error if the filesystem watcher cannot be initialized.
    pub(crate) fn new(config: WatcherConfig) -> CapsuleResult<(Self, mpsc::Receiver<WatchEvent>)> {
        let (raw_tx, raw_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::channel(64);

        let watcher = RecommendedWatcher::new(
            move |res| {
                let _ = raw_tx.send(res);
            },
            notify::Config::default(),
        )
        .map_err(|e| {
            crate::error::CapsuleError::UnsupportedEntryPoint(format!("filesystem watcher: {e}"))
        })?;

        Ok((
            Self {
                config,
                hash_cache: HashMap::new(),
                watcher,
                raw_rx,
                event_tx,
            },
            event_rx,
        ))
    }

    /// Run the watcher event loop.
    ///
    /// Starts watching all configured paths and processes filesystem events
    /// until the raw event channel closes (i.e., the `notify` watcher is dropped
    /// or encounters a fatal error).
    pub(crate) async fn run(mut self) {
        // Start watching configured paths.
        for path in &self.config.watch_paths {
            if path.exists() {
                match self.watcher.watch(path, RecursiveMode::Recursive) {
                    Ok(()) => info!(path = %path.display(), "Watching capsule directory"),
                    Err(e) => warn!(
                        path = %path.display(),
                        error = %e,
                        "Failed to watch directory"
                    ),
                }
            } else {
                warn!(path = %path.display(), "Watch path does not exist, skipping");
            }
        }

        let debounce = self.config.debounce;
        let mut pending: HashMap<PathBuf, tokio::time::Instant> = HashMap::new();

        loop {
            let next_deadline = pending.values().copied().min();

            tokio::select! {
                biased;

                // Fire debounced events (check timeouts first).
                () = async {
                    match next_deadline {
                        Some(deadline) => tokio::time::sleep_until(deadline).await,
                        None => std::future::pending::<()>().await,
                    }
                } => {
                    let now = tokio::time::Instant::now();
                    let ready: Vec<PathBuf> = pending
                        .iter()
                        .filter(|(_, deadline)| **deadline <= now)
                        .map(|(path, _)| path.clone())
                        .collect();

                    for capsule_dir in ready {
                        pending.remove(&capsule_dir);
                        if !self.process_capsule_change(&capsule_dir).await {
                            return; // Receiver dropped, stop the watcher.
                        }
                    }
                }

                // Process incoming FS events.
                event = self.raw_rx.recv() => {
                    match event {
                        Some(Ok(ev)) => {
                            self.handle_raw_event(&ev, &mut pending, debounce);
                        }
                        Some(Err(e)) => {
                            warn!(error = %e, "Filesystem watcher error");
                            if self.event_tx.send(WatchEvent::Error(e.to_string())).await.is_err() {
                                debug!("Event receiver dropped, stopping watcher");
                                return;
                            }
                        }
                        None => {
                            debug!("Filesystem watcher channel closed, stopping");
                            break;
                        }
                    }
                }
            }
        }
    }

    /// Map a raw `notify` event to a capsule directory and reset its debounce timer.
    fn handle_raw_event(
        &self,
        event: &Event,
        pending: &mut HashMap<PathBuf, tokio::time::Instant>,
        debounce: Duration,
    ) {
        // Only process content-changing events.
        match event.kind {
            EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_) => {},
            _ => return,
        }

        for path in &event.paths {
            if is_in_ignored_dir(path) {
                continue;
            }

            if let Some(capsule_dir) = self.resolve_capsule_dir(path) {
                debug!(
                    path = %path.display(),
                    capsule_dir = %capsule_dir.display(),
                    kind = ?event.kind,
                    "File change detected in capsule"
                );
                #[expect(clippy::arithmetic_side_effects)]
                // Instant + Duration cannot overflow in practice
                let deadline = tokio::time::Instant::now() + debounce;
                pending.insert(capsule_dir, deadline);
            }
        }
    }

    /// Walk up from a changed file to find its parent capsule directory.
    ///
    /// A capsule directory is identified by containing `Capsule.toml`.
    /// Starts from the parent of the changed path to avoid an unnecessary
    /// `stat` syscall on the path itself.
    fn resolve_capsule_dir(&self, path: &Path) -> Option<PathBuf> {
        // Start from the parent directory — for files in the capsule root
        // (including manifests like Capsule.toml), parent() gives the capsule
        // directory directly.
        let mut current = path.parent()?.to_path_buf();

        loop {
            if current.join(MANIFEST_FILE_NAME).exists() {
                return Some(current);
            }

            // Stop at watch roots to avoid traversing the entire filesystem.
            // Compare via components() to handle trailing slashes and
            // redundant separators from notify event paths.
            if self
                .config
                .watch_paths
                .iter()
                .any(|root| current.components().eq(root.components()))
            {
                return None;
            }

            current = current.parent()?.to_path_buf();
        }
    }

    /// Hash the capsule's source tree and emit an event if the hash changed.
    ///
    /// Returns `false` if the event receiver has been dropped (caller should
    /// stop the watcher loop to avoid wasting resources).
    async fn process_capsule_change(&mut self, capsule_dir: &Path) -> bool {
        // Run the recursive file hashing on a blocking thread to avoid
        // starving the Tokio worker (capsule directories can be large).
        let dir = capsule_dir.to_path_buf();
        let hash_result = match tokio::task::spawn_blocking(move || compute_source_hash(&dir)).await
        {
            Ok(result) => result,
            Err(e) => {
                warn!(error = %e, "Hash task was cancelled");
                return true;
            },
        };

        match hash_result {
            Ok(new_hash) => {
                if self
                    .hash_cache
                    .get(capsule_dir)
                    .is_some_and(|h| h == &new_hash)
                {
                    debug!(
                        capsule_dir = %capsule_dir.display(),
                        "Source hash unchanged, skipping recompilation"
                    );
                    return true;
                }

                info!(
                    capsule_dir = %capsule_dir.display(),
                    hash = %new_hash,
                    "Capsule source changed, triggering reload"
                );
                self.hash_cache
                    .insert(capsule_dir.to_path_buf(), new_hash.clone());

                if self
                    .event_tx
                    .send(WatchEvent::CapsuleChanged {
                        capsule_dir: capsule_dir.to_path_buf(),
                        source_hash: new_hash,
                    })
                    .await
                    .is_err()
                {
                    debug!("Event receiver dropped, stopping watcher");
                    return false;
                }
            },
            Err(e) => {
                warn!(
                    capsule_dir = %capsule_dir.display(),
                    error = %e,
                    "Failed to hash capsule source tree"
                );
                if self
                    .event_tx
                    .send(WatchEvent::Error(format!(
                        "Hash failed for {}: {e}",
                        capsule_dir.display()
                    )))
                    .await
                    .is_err()
                {
                    debug!("Event receiver dropped, stopping watcher");
                    return false;
                }
            },
        }
        true
    }
}

/// Check if a path contains any ignored directory component.
fn is_in_ignored_dir(path: &Path) -> bool {
    path.components().any(|c| {
        c.as_os_str()
            .to_str()
            .is_some_and(|s| IGNORED_DIRS.contains(&s))
    })
}

/// Compute a deterministic blake3 hash over all source files in a directory.
///
/// Files are sorted by relative path for deterministic output. The hash covers
/// both file paths (to detect renames) and file contents.
///
/// Directories in [`IGNORED_DIRS`] are skipped. Generated artifacts (`.wasm`
/// files) are excluded to prevent recompilation feedback loops.
///
/// # Errors
///
/// Returns an error if the directory itself cannot be read. Individual
/// unreadable files (e.g. deleted between enumeration and read) are
/// skipped with a debug log rather than failing the entire hash.
pub(crate) fn compute_source_hash(dir: &Path) -> std::io::Result<String> {
    let mut hasher = blake3::Hasher::new();
    let mut paths = Vec::new();
    collect_source_paths(dir, &mut paths)?;
    paths.sort();

    for path in &paths {
        let Ok(rel) = path.strip_prefix(dir) else {
            continue;
        };
        match std::fs::read(path) {
            Ok(content) => {
                let rel_bytes = rel.to_string_lossy();
                let rel_bytes = rel_bytes.as_bytes();
                hasher.update(&(rel_bytes.len() as u64).to_le_bytes());
                hasher.update(rel_bytes);
                hasher.update(&(content.len() as u64).to_le_bytes());
                hasher.update(&content);
            },
            Err(e) => {
                debug!(path = %path.display(), error = %e, "Skipping unreadable file in hash");
            },
        }
    }

    Ok(hasher.finalize().to_hex().to_string())
}

/// Recursively collect source file paths, skipping [`IGNORED_DIRS`] and
/// generated artifacts.
fn collect_source_paths(dir: &Path, paths: &mut Vec<PathBuf>) -> std::io::Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }

    for entry in std::fs::read_dir(dir)? {
        let Ok(entry) = entry else { continue };
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        let path = entry.path();

        if file_type.is_symlink() {
            continue;
        }

        if file_type.is_dir() {
            let name = entry.file_name();
            if IGNORED_DIRS
                .iter()
                .any(|&d| d == name.to_string_lossy().as_ref())
            {
                continue;
            }
            collect_source_paths(&path, paths)?;
        } else if file_type.is_file() {
            if path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|ext| IGNORED_EXTENSIONS.contains(&ext))
            {
                continue;
            }

            paths.push(path);
        }
    }

    Ok(())
}
