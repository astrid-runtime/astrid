//! Durable lane marker: detects a lane run that stopped without draining.
//!
//! The in-memory queue is lost when the daemon dies, so the lane keeps one
//! small record in kernel-owned storage: the current lane run (`epoch`), the
//! chains it has written to, and whether it closed cleanly. A chain is added
//! before the lane writes its first entry of the run there. Graceful shutdown
//! marks the run closed after the queue is fully drained.
//!
//! On the next start, a run that is not closed becomes a gap duty: a signed
//! gap entry in every chain the run registered, and one in the session's
//! system chain, which covers chains that were touched but not yet
//! registered. Duties stay in the marker until their entries are durable, so
//! a second crash does not lose them. A marker that cannot be read or parsed
//! says nothing about the previous run, so it is treated as an unclean stop
//! of an unknown run and replaced. A run whose marker cannot be written
//! records that about itself, because a crash would then go unnoticed.

use astrid_core::{PrincipalId, Timestamp};
use astrid_storage::ScopedKvStore;
use serde::{Deserialize, Serialize};

const MARKER_KEY: &str = "lane";
const MARKER_VERSION: u32 = 1;
/// Gap reason for a lane run that stopped without draining.
pub(super) const UNCLEAN_SHUTDOWN: &str = "unclean_shutdown";
/// Gap reason when the previous run's marker could not be read or parsed.
pub(super) const MARKER_UNREADABLE: &str = "lane_marker_unreadable";
/// Gap reason, recorded by a run itself, when its marker cannot be written.
pub(super) const MARKER_UNAVAILABLE: &str = "lane_marker_unavailable";

fn unclean_shutdown() -> String {
    UNCLEAN_SHUTDOWN.to_owned()
}

/// A lane run that may have lost calls, and the chains it wrote to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct GapDuty {
    pub(super) epoch: String,
    pub(super) opened_at: Timestamp,
    pub(super) chains: Vec<String>,
    #[serde(default = "unclean_shutdown")]
    pub(super) reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct MarkerState {
    version: u32,
    epoch: String,
    opened_at: Timestamp,
    closed: bool,
    chains: Vec<String>,
    pending_gaps: Vec<GapDuty>,
}

/// The lane marker of the current lane run.
pub(super) struct LaneMarker {
    store: ScopedKvStore,
    state: MarkerState,
    /// Whether `state` is what the store holds.
    saved: bool,
}

/// What opening the lane marker found.
pub(super) struct Opened {
    pub(super) marker: LaneMarker,
    /// Gap entries the new run must record.
    pub(super) duties: Vec<GapDuty>,
    /// Marker errors met on the way; each is reported, none stops the lane.
    pub(super) errors: Vec<String>,
}

fn unknown_run(opened_at: Timestamp) -> GapDuty {
    GapDuty {
        epoch: "unknown".to_owned(),
        opened_at,
        chains: Vec::new(),
        reason: MARKER_UNREADABLE.to_owned(),
    }
}

impl LaneMarker {
    /// Load the previous marker, start a new lane run, and return the gap
    /// duties the new run must record.
    ///
    /// A previous marker that cannot be read or parsed says nothing about
    /// the previous run, which becomes a gap of an unknown run. When the new
    /// marker cannot be written, a crash of this run would go unnoticed, so
    /// this run gets a gap duty of its own (`lane_marker_unavailable`); the
    /// write is retried by [`sync`](Self::sync).
    pub(super) fn open(
        runtime: &tokio::runtime::Runtime,
        store: ScopedKvStore,
        epoch: String,
        opened_at: Timestamp,
    ) -> Opened {
        let mut duties = Vec::new();
        let mut errors = Vec::new();
        match runtime.block_on(store.get(MARKER_KEY)) {
            Ok(None) => {},
            Ok(Some(bytes)) => match serde_json::from_slice::<MarkerState>(&bytes) {
                Ok(previous) => {
                    duties.extend(previous.pending_gaps);
                    if !previous.closed {
                        duties.push(GapDuty {
                            epoch: previous.epoch,
                            opened_at: previous.opened_at,
                            chains: previous.chains,
                            reason: unclean_shutdown(),
                        });
                    }
                },
                Err(error) => {
                    errors.push(format!("parse host-audit lane marker: {error}"));
                    duties.push(unknown_run(opened_at));
                },
            },
            Err(error) => {
                errors.push(format!("read host-audit lane marker: {error}"));
                duties.push(unknown_run(opened_at));
            },
        }
        let mut marker = Self {
            store,
            state: MarkerState {
                version: MARKER_VERSION,
                epoch,
                opened_at,
                closed: false,
                chains: Vec::new(),
                pending_gaps: duties.clone(),
            },
            saved: false,
        };
        if let Err(error) = marker.sync(runtime) {
            errors.push(error);
            let unavailable = GapDuty {
                epoch: marker.state.epoch.clone(),
                opened_at,
                chains: Vec::new(),
                reason: MARKER_UNAVAILABLE.to_owned(),
            };
            // Kept in the marker too: once a later sync writes it, a crash
            // before this gap is recorded must still leave the duty behind.
            marker.state.pending_gaps.push(unavailable.clone());
            duties.push(unavailable);
        }
        Opened {
            marker,
            duties,
            errors,
        }
    }

    /// Write the marker if the store does not hold its current state.
    ///
    /// # Errors
    ///
    /// Returns an error when the marker cannot be written; it stays unsaved
    /// and the next call tries again.
    pub(super) fn sync(&mut self, runtime: &tokio::runtime::Runtime) -> Result<(), String> {
        if self.saved {
            return Ok(());
        }
        let bytes = serde_json::to_vec(&self.state)
            .map_err(|error| format!("encode host-audit lane marker: {error}"))?;
        runtime
            .block_on(self.store.set(MARKER_KEY, bytes))
            .map_err(|error| format!("write host-audit lane marker: {error}"))?;
        self.saved = true;
        Ok(())
    }

    /// Add chains before the lane writes to them in this run.
    ///
    /// # Errors
    ///
    /// Returns an error when the marker cannot be written; the chains stay
    /// in the unsaved state and the next [`sync`](Self::sync) writes them.
    pub(super) fn register(
        &mut self,
        runtime: &tokio::runtime::Runtime,
        principals: &[PrincipalId],
    ) -> Result<(), String> {
        for principal in principals {
            if !self
                .state
                .chains
                .iter()
                .any(|chain| chain == principal.as_str())
            {
                self.state.chains.push(principal.as_str().to_owned());
                self.saved = false;
            }
        }
        self.sync(runtime)
    }

    /// Drop the gap duties once all their entries are durable.
    ///
    /// # Errors
    ///
    /// Returns an error when the marker cannot be written.
    pub(super) fn gaps_recorded(
        &mut self,
        runtime: &tokio::runtime::Runtime,
    ) -> Result<(), String> {
        if !self.state.pending_gaps.is_empty() {
            self.state.pending_gaps.clear();
            self.saved = false;
        }
        self.sync(runtime)
    }

    /// Mark the lane run closed after a complete drain.
    ///
    /// # Errors
    ///
    /// Returns an error when the marker cannot be written.
    pub(super) fn close(&mut self, runtime: &tokio::runtime::Runtime) -> Result<(), String> {
        self.state.closed = true;
        self.saved = false;
        self.sync(runtime)
    }
}
