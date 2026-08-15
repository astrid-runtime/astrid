//! Byte-level durable-operation traces for exhaustive crash recovery tests.
//!
//! This module is compiled only for this crate's tests or with the explicit
//! `crash-replay` feature. It records what production code wrote without
//! defining a second storage format, then delegates persistence-state
//! generation to an explicit filesystem model.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

mod replay;

pub use replay::{ConservativeDataSync, CrashImage, CrashImageSet, PersistenceModel, ReplayLimits};

/// Stable relative path of one file in a crash trace.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TraceFileId(String);

impl TraceFileId {
    /// Construct a safe relative trace path.
    ///
    /// # Errors
    ///
    /// Rejects empty, absolute, parent-relative, current-directory, Windows
    /// separator, and drive-prefixed paths.
    pub fn new(name: impl Into<String>) -> Result<Self, CrashReplayError> {
        let name = name.into();
        let safe = !name.is_empty()
            && !name.contains('\\')
            && !name.contains(':')
            && name
                .split('/')
                .all(|component| !component.is_empty() && component != "." && component != "..")
            && std::path::Path::new(&name)
                .components()
                .all(|component| matches!(component, std::path::Component::Normal(_)));
        if !safe {
            return Err(CrashReplayError::InvalidFileId(name));
        }
        Ok(Self(name))
    }

    /// Borrow the canonical file name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One byte-level effect or durability annotation in execution order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TraceEffect {
    /// Bytes were appended at the exact pre-operation length.
    Append {
        /// Target file.
        file: TraceFileId,
        /// File length before the append.
        pre_len: u64,
        /// Appended bytes.
        bytes: Vec<u8>,
    },
    /// Existing bytes were overwritten at an explicit offset.
    Write {
        /// Target file.
        file: TraceFileId,
        /// Write offset.
        offset: u64,
        /// Bytes observed before the write.
        previous: Vec<u8>,
        /// Replacement bytes.
        bytes: Vec<u8>,
    },
    /// The file was shortened to `len`.
    Truncate {
        /// Target file.
        file: TraceFileId,
        /// File length before truncation.
        pre_len: u64,
        /// New file length.
        len: u64,
    },
    /// Every earlier effect on this file completed its data-durability barrier.
    Barrier {
        /// Flushed file.
        file: TraceFileId,
    },
    /// A root publication occupied this already-written byte range.
    RootPublication {
        /// Root-journal file.
        file: TraceFileId,
        /// First byte of the publication.
        offset: u64,
        /// Publication length.
        len: u64,
    },
    /// The caller observed a successful durable commit.
    AcknowledgedCommit {
        /// Stable test label for the acknowledged logical result.
        label: String,
    },
}

/// Deterministic initial files and ordered effects from one workload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrashTrace {
    initial_files: BTreeMap<TraceFileId, Vec<u8>>,
    initial_acknowledgements: Vec<String>,
    effects: Vec<TraceEffect>,
}

impl CrashTrace {
    /// Borrow the initial durable file images.
    #[must_use]
    pub const fn initial_files(&self) -> &BTreeMap<TraceFileId, Vec<u8>> {
        &self.initial_files
    }

    /// Borrow commits acknowledged before tracing began.
    #[must_use]
    pub fn initial_acknowledgements(&self) -> &[String] {
        &self.initial_acknowledgements
    }

    /// Borrow the ordered trace effects.
    #[must_use]
    pub fn effects(&self) -> &[TraceEffect] {
        &self.effects
    }

    /// Generate every crash image admitted by one explicit persistence model.
    ///
    /// # Errors
    ///
    /// Returns a trace-consistency or configured replay-bound error.
    pub fn replay(
        &self,
        model: &impl PersistenceModel,
        limits: ReplayLimits,
    ) -> Result<CrashImageSet, CrashReplayError> {
        replay::generate(self, model, limits)
    }
}

#[derive(Debug)]
struct RecorderState {
    initial_files: BTreeMap<TraceFileId, Vec<u8>>,
    initial_acknowledgements: Vec<String>,
    current_files: BTreeMap<TraceFileId, Vec<u8>>,
    effects: Vec<TraceEffect>,
}

/// Thread-safe recorder attached to production fault-injection checkpoints.
#[derive(Clone, Debug)]
pub struct CrashTraceRecorder {
    state: Arc<Mutex<RecorderState>>,
}

impl CrashTraceRecorder {
    /// Capture initial durable files from a directory.
    ///
    /// `files` maps logical trace names to paths. Entries are sorted by their
    /// logical identifiers, so the resulting trace is deterministic.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when any initial file cannot be read.
    pub fn from_paths(
        files: impl IntoIterator<Item = (TraceFileId, PathBuf)>,
        initial_acknowledgements: impl IntoIterator<Item = String>,
    ) -> Result<Self, CrashReplayError> {
        let mut initial_files = BTreeMap::new();
        for (file, path) in files {
            let bytes = std::fs::read(&path).map_err(|source| CrashReplayError::Io {
                operation: "read initial trace file",
                path,
                source,
            })?;
            if initial_files.insert(file.clone(), bytes).is_some() {
                return Err(CrashReplayError::DuplicateFile(file));
            }
        }
        Self::new(initial_files, initial_acknowledgements)
    }

    /// Construct a recorder from already-captured initial bytes.
    ///
    /// # Errors
    ///
    /// Rejects duplicate acknowledgement labels.
    pub fn new(
        initial_files: BTreeMap<TraceFileId, Vec<u8>>,
        initial_acknowledgements: impl IntoIterator<Item = String>,
    ) -> Result<Self, CrashReplayError> {
        let initial_acknowledgements: Vec<_> = initial_acknowledgements.into_iter().collect();
        require_unique_labels(&initial_acknowledgements)?;
        Ok(Self {
            state: Arc::new(Mutex::new(RecorderState {
                current_files: initial_files.clone(),
                initial_files,
                initial_acknowledgements,
                effects: Vec::new(),
            })),
        })
    }

    /// Capture a file and record the exact mutation since its prior snapshot.
    ///
    /// # Errors
    ///
    /// Returns an I/O, unknown-file, length, or poisoned-lock error.
    pub fn capture(&self, file: &TraceFileId, path: &Path) -> Result<(), CrashReplayError> {
        let next = std::fs::read(path).map_err(|source| CrashReplayError::Io {
            operation: "capture trace file",
            path: path.to_path_buf(),
            source,
        })?;
        self.capture_bytes(file, next)
    }

    /// Record an already-read file snapshot.
    ///
    /// # Errors
    ///
    /// Returns an unknown-file, length, or poisoned-lock error.
    pub fn capture_bytes(&self, file: &TraceFileId, next: Vec<u8>) -> Result<(), CrashReplayError> {
        let mut state = self.lock()?;
        let previous = state
            .current_files
            .get(file)
            .cloned()
            .ok_or_else(|| CrashReplayError::UnknownFile(file.clone()))?;
        record_snapshot_delta(&mut state.effects, file, &previous, &next)?;
        state.current_files.insert(file.clone(), next);
        Ok(())
    }

    /// Record a completed durability barrier for one file.
    ///
    /// # Errors
    ///
    /// Returns an unknown-file or poisoned-lock error.
    pub fn barrier(&self, file: &TraceFileId) -> Result<(), CrashReplayError> {
        let mut state = self.lock()?;
        if !state.current_files.contains_key(file) {
            return Err(CrashReplayError::UnknownFile(file.clone()));
        }
        state
            .effects
            .push(TraceEffect::Barrier { file: file.clone() });
        Ok(())
    }

    /// Annotate a root-journal publication after its durability barrier.
    ///
    /// # Errors
    ///
    /// Rejects ranges outside the current file or poisoned recorder locks.
    pub fn root_publication(
        &self,
        file: &TraceFileId,
        offset: u64,
        len: u64,
    ) -> Result<(), CrashReplayError> {
        let mut state = self.lock()?;
        let file_len = state
            .current_files
            .get(file)
            .ok_or_else(|| CrashReplayError::UnknownFile(file.clone()))?
            .len();
        let end = offset
            .checked_add(len)
            .ok_or(CrashReplayError::LengthOverflow)?;
        if end > u64::try_from(file_len).map_err(|_| CrashReplayError::LengthOverflow)? {
            return Err(CrashReplayError::InvalidPublicationRange {
                file: file.clone(),
                offset,
                len,
            });
        }
        state.effects.push(TraceEffect::RootPublication {
            file: file.clone(),
            offset,
            len,
        });
        Ok(())
    }

    /// Record a successful caller-visible durable acknowledgement.
    ///
    /// # Errors
    ///
    /// Rejects duplicate labels or poisoned recorder locks.
    pub fn acknowledge(&self, label: impl Into<String>) -> Result<(), CrashReplayError> {
        let label = label.into();
        let mut state = self.lock()?;
        if state.initial_acknowledgements.contains(&label)
            || state.effects.iter().any(
                |effect| matches!(effect, TraceEffect::AcknowledgedCommit { label: existing } if existing == &label),
            )
        {
            return Err(CrashReplayError::DuplicateAcknowledgement(label));
        }
        state
            .effects
            .push(TraceEffect::AcknowledgedCommit { label });
        Ok(())
    }

    /// Snapshot the deterministic trace recorded so far.
    ///
    /// # Errors
    ///
    /// Returns a poisoned-lock error if a prior recorder panic occurred.
    pub fn trace(&self) -> Result<CrashTrace, CrashReplayError> {
        let state = self.lock()?;
        Ok(CrashTrace {
            initial_files: state.initial_files.clone(),
            initial_acknowledgements: state.initial_acknowledgements.clone(),
            effects: state.effects.clone(),
        })
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, RecorderState>, CrashReplayError> {
        self.state
            .lock()
            .map_err(|_| CrashReplayError::RecorderPoisoned)
    }
}

fn record_snapshot_delta(
    effects: &mut Vec<TraceEffect>,
    file: &TraceFileId,
    previous: &[u8],
    next: &[u8],
) -> Result<(), CrashReplayError> {
    let shared = previous.len().min(next.len());
    let first_difference = previous[..shared]
        .iter()
        .zip(&next[..shared])
        .position(|(left, right)| left != right);
    if let Some(first) = first_difference {
        let last = previous[..shared]
            .iter()
            .zip(&next[..shared])
            .rposition(|(left, right)| left != right)
            .ok_or(CrashReplayError::LengthOverflow)?
            .checked_add(1)
            .ok_or(CrashReplayError::LengthOverflow)?;
        effects.push(TraceEffect::Write {
            file: file.clone(),
            offset: u64::try_from(first).map_err(|_| CrashReplayError::LengthOverflow)?,
            previous: previous[first..last].to_vec(),
            bytes: next[first..last].to_vec(),
        });
    }
    if next.len() < previous.len() {
        effects.push(TraceEffect::Truncate {
            file: file.clone(),
            pre_len: u64::try_from(previous.len()).map_err(|_| CrashReplayError::LengthOverflow)?,
            len: u64::try_from(next.len()).map_err(|_| CrashReplayError::LengthOverflow)?,
        });
    } else if next.len() > previous.len() {
        effects.push(TraceEffect::Append {
            file: file.clone(),
            pre_len: u64::try_from(previous.len()).map_err(|_| CrashReplayError::LengthOverflow)?,
            bytes: next[previous.len()..].to_vec(),
        });
    }
    Ok(())
}

fn require_unique_labels(labels: &[String]) -> Result<(), CrashReplayError> {
    let mut sorted = labels.to_vec();
    sorted.sort();
    if let Some(duplicate) = sorted.windows(2).find(|pair| pair[0] == pair[1]) {
        return Err(CrashReplayError::DuplicateAcknowledgement(
            duplicate[0].clone(),
        ));
    }
    Ok(())
}

/// Trace construction or replay failure.
#[derive(Debug)]
pub enum CrashReplayError {
    /// A file identifier was not a safe single path component.
    InvalidFileId(String),
    /// The initial trace declared the same file twice.
    DuplicateFile(TraceFileId),
    /// An effect named a file absent from the initial trace.
    UnknownFile(TraceFileId),
    /// A commit acknowledgement label was reused.
    DuplicateAcknowledgement(String),
    /// A trace effect disagreed with the bytes produced by earlier effects.
    TraceMismatch(&'static str),
    /// A root-publication annotation exceeded the current file.
    InvalidPublicationRange {
        /// Root-journal file.
        file: TraceFileId,
        /// Publication offset.
        offset: u64,
        /// Publication length.
        len: u64,
    },
    /// An integer length or offset could not be represented safely.
    LengthOverflow,
    /// Exhaustive generation exceeded an explicit configured bound.
    ReplayBound {
        /// Name of the exceeded bound.
        bound: &'static str,
        /// Observed value.
        actual: usize,
        /// Configured ceiling.
        limit: usize,
    },
    /// The recorder lock was poisoned by a prior panic.
    RecorderPoisoned,
    /// A filesystem operation failed.
    Io {
        /// Stable operation description.
        operation: &'static str,
        /// Affected path.
        path: PathBuf,
        /// Operating-system error.
        source: std::io::Error,
    },
}

impl fmt::Display for CrashReplayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFileId(name) => write!(formatter, "invalid trace file id {name:?}"),
            Self::DuplicateFile(file) => {
                write!(formatter, "duplicate trace file {}", file.as_str())
            },
            Self::UnknownFile(file) => write!(formatter, "unknown trace file {}", file.as_str()),
            Self::DuplicateAcknowledgement(label) => {
                write!(formatter, "duplicate acknowledgement {label:?}")
            },
            Self::TraceMismatch(detail) => write!(formatter, "inconsistent crash trace: {detail}"),
            Self::InvalidPublicationRange { file, offset, len } => write!(
                formatter,
                "root publication {offset}+{len} exceeds {}",
                file.as_str()
            ),
            Self::LengthOverflow => formatter.write_str("crash-trace length overflow"),
            Self::ReplayBound {
                bound,
                actual,
                limit,
            } => {
                write!(
                    formatter,
                    "crash replay {bound} bound exceeded: {actual} > {limit}"
                )
            },
            Self::RecorderPoisoned => formatter.write_str("crash-trace recorder lock poisoned"),
            Self::Io {
                operation,
                path,
                source,
            } => {
                write!(formatter, "{operation} at {}: {source}", path.display())
            },
        }
    }
}

impl std::error::Error for CrashReplayError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_file_ids_are_safe_relative_paths_on_every_host() {
        for invalid in [
            "",
            ".",
            "..",
            "../a",
            "/a",
            "a//b",
            "a\\b",
            "C:outside",
            ":",
        ] {
            assert!(matches!(
                TraceFileId::new(invalid),
                Err(CrashReplayError::InvalidFileId(name)) if name == invalid
            ));
        }
        assert_eq!(
            TraceFileId::new("objects.arena").unwrap().as_str(),
            "objects.arena"
        );
        assert_eq!(
            TraceFileId::new("representations/generations/0000000000000001/state.journal")
                .unwrap()
                .as_str(),
            "representations/generations/0000000000000001/state.journal"
        );
    }
}
