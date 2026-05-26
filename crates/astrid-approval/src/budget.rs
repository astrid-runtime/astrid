//! Budget tracking for session and per-action spending limits.
//!
//! The [`BudgetTracker`] enforces two layers of cost control:
//! - **Session budget**: Total spending cap for the entire session.
//! - **Per-action limit**: Maximum cost for any single action.
//!
//! When the session spend approaches the warning threshold, the tracker
//! returns [`BudgetResult::WarnAndAllow`] so the caller can elicit
//! user confirmation before continuing.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::RwLock;

/// Configuration for budget limits.
///
/// # Example
///
/// ```
/// use astrid_approval::budget::BudgetConfig;
///
/// let config = BudgetConfig::new(100.0, 10.0);
/// assert!((config.session_max_usd - 100.0).abs() < f64::EPSILON);
/// assert!((config.per_action_max_usd - 10.0).abs() < f64::EPSILON);
/// assert_eq!(config.warn_at_percent, 80);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetConfig {
    /// Maximum total spend for the session (USD).
    pub session_max_usd: f64,
    /// Maximum spend for any single action (USD).
    pub per_action_max_usd: f64,
    /// Warning threshold as a percentage of session budget (0-100).
    pub warn_at_percent: u8,
}

impl BudgetConfig {
    /// Create a new budget config with the given limits.
    ///
    /// Uses the default warning threshold of 80%.
    #[must_use]
    pub fn new(session_max_usd: f64, per_action_max_usd: f64) -> Self {
        Self {
            session_max_usd,
            per_action_max_usd,
            warn_at_percent: 80,
        }
    }

    /// Set the warning threshold percentage.
    #[must_use]
    pub fn with_warn_at_percent(mut self, percent: u8) -> Self {
        self.warn_at_percent = percent.min(100);
        self
    }

    /// Get the warning threshold as a dollar amount.
    #[must_use]
    pub fn warn_threshold_usd(&self) -> f64 {
        self.session_max_usd * f64::from(self.warn_at_percent) / 100.0
    }
}

impl Default for BudgetConfig {
    fn default() -> Self {
        Self::new(100.0, 10.0)
    }
}

/// Result of a budget check.
#[derive(Debug, Clone, PartialEq)]
pub enum BudgetResult {
    /// Within budget — proceed without warning.
    Allowed,
    /// At or above warning threshold — elicit user before continuing.
    WarnAndAllow {
        /// Current session spend (USD).
        current_spend: f64,
        /// Session budget (USD).
        session_max: f64,
        /// Percentage of budget used.
        percent_used: f64,
    },
    /// Over budget — deny or elicit for override.
    Exceeded {
        /// What was exceeded.
        reason: ExceededReason,
        /// How much was requested (USD).
        requested: f64,
        /// How much is available (USD).
        available: f64,
    },
}

impl BudgetResult {
    /// Check if this result allows the action to proceed (possibly with a warning).
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed | Self::WarnAndAllow { .. })
    }

    /// Check if this result blocks the action.
    #[must_use]
    pub fn is_exceeded(&self) -> bool {
        matches!(self, Self::Exceeded { .. })
    }
}

impl fmt::Display for BudgetResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allowed => write!(f, "within budget"),
            Self::WarnAndAllow { percent_used, .. } => {
                write!(f, "budget warning: {percent_used:.0}% used")
            },
            Self::Exceeded {
                reason,
                requested,
                available,
            } => write!(
                f,
                "budget exceeded ({reason}): requested ${requested:.2}, available ${available:.2}"
            ),
        }
    }
}

/// Why the budget was exceeded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExceededReason {
    /// The action's estimated cost exceeds the per-action limit.
    PerActionLimit,
    /// The session budget would be exceeded.
    SessionBudget,
    /// The workspace cumulative budget would be exceeded.
    WorkspaceBudget,
}

impl fmt::Display for ExceededReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PerActionLimit => write!(f, "per-action limit"),
            Self::SessionBudget => write!(f, "session budget"),
            Self::WorkspaceBudget => write!(f, "workspace budget"),
        }
    }
}

/// Tracks spending against session and per-action budgets.
///
/// Thread-safe via internal [`RwLock`].
///
/// # Example
///
/// ```
/// use astrid_approval::budget::{BudgetConfig, BudgetTracker, BudgetResult};
///
/// let config = BudgetConfig::new(10.0, 5.0);
/// let tracker = BudgetTracker::new(config);
///
/// // Check a small cost
/// assert!(tracker.check_budget(1.0).is_allowed());
///
/// // Record spending
/// tracker.record_cost(1.0);
/// assert_eq!(tracker.remaining(), 9.0);
/// ```
pub struct BudgetTracker {
    config: BudgetConfig,
    session_spent: RwLock<f64>,
}

impl BudgetTracker {
    /// Create a new budget tracker with the given configuration.
    #[must_use]
    pub fn new(config: BudgetConfig) -> Self {
        Self {
            config,
            session_spent: RwLock::new(0.0),
        }
    }

    /// Check if an estimated cost is within budget.
    ///
    /// This does NOT record the cost — call [`record_cost`](Self::record_cost)
    /// after the action completes.
    #[must_use]
    pub fn check_budget(&self, estimated_cost: f64) -> BudgetResult {
        // Check per-action limit first
        if estimated_cost > self.config.per_action_max_usd {
            return BudgetResult::Exceeded {
                reason: ExceededReason::PerActionLimit,
                requested: estimated_cost,
                available: self.config.per_action_max_usd,
            };
        }

        let spent = self.session_spent.read().map_or(0.0, |s| *s);
        let remaining = self.config.session_max_usd - spent;

        // Check session budget
        if estimated_cost > remaining {
            return BudgetResult::Exceeded {
                reason: ExceededReason::SessionBudget,
                requested: estimated_cost,
                available: remaining,
            };
        }

        // Check warning threshold
        let new_spend = spent + estimated_cost;
        let warn_threshold = self.config.warn_threshold_usd();

        if new_spend >= warn_threshold {
            let percent_used = (new_spend / self.config.session_max_usd) * 100.0;
            return BudgetResult::WarnAndAllow {
                current_spend: new_spend,
                session_max: self.config.session_max_usd,
                percent_used,
            };
        }

        BudgetResult::Allowed
    }

    /// Atomically check if an estimated cost is within budget and reserve it.
    ///
    /// This combines [`check_budget`](Self::check_budget) and
    /// [`record_cost`](Self::record_cost) under a single write lock to prevent
    /// race conditions where two concurrent callers both pass the budget check
    /// and then both record costs, exceeding the budget.
    #[must_use]
    pub fn check_and_reserve(&self, estimated_cost: f64) -> BudgetResult {
        // Per-action limit (no lock needed — config is immutable)
        if estimated_cost > self.config.per_action_max_usd {
            return BudgetResult::Exceeded {
                reason: ExceededReason::PerActionLimit,
                requested: estimated_cost,
                available: self.config.per_action_max_usd,
            };
        }

        // Atomic check + reserve under write lock
        let mut spent = self.session_spent.write().unwrap_or_else(|e| {
            tracing::warn!("BudgetTracker lock poisoned, recovering");
            e.into_inner()
        });
        let remaining = self.config.session_max_usd - *spent;

        if estimated_cost > remaining {
            return BudgetResult::Exceeded {
                reason: ExceededReason::SessionBudget,
                requested: estimated_cost,
                available: remaining,
            };
        }

        let new_spend = *spent + estimated_cost;
        // Reserve atomically
        if estimated_cost > 0.0 && estimated_cost.is_finite() {
            *spent = new_spend;
        }

        // Warning check
        let warn_threshold = self.config.warn_threshold_usd();
        if new_spend >= warn_threshold {
            let percent_used = (new_spend / self.config.session_max_usd) * 100.0;
            return BudgetResult::WarnAndAllow {
                current_spend: new_spend,
                session_max: self.config.session_max_usd,
                percent_used,
            };
        }

        BudgetResult::Allowed
    }

    /// Record an actual cost against the session budget.
    ///
    /// Only positive, finite values are accepted. Negative, `NaN`, or infinite
    /// costs are silently ignored to prevent budget manipulation.
    pub fn record_cost(&self, actual_cost: f64) {
        if actual_cost > 0.0
            && actual_cost.is_finite()
            && let Ok(mut spent) = self.session_spent.write()
        {
            *spent += actual_cost;
        }
    }

    /// Refund a previously recorded cost (e.g., if an action fails or a subsequent check fails).
    pub fn refund_cost(&self, actual_cost: f64) {
        if actual_cost > 0.0
            && actual_cost.is_finite()
            && let Ok(mut spent) = self.session_spent.write()
        {
            *spent = (*spent - actual_cost).max(0.0);
        }
    }

    /// Get the remaining session budget.
    #[must_use]
    pub fn remaining(&self) -> f64 {
        let spent = self.session_spent.read().map_or(0.0, |s| *s);
        (self.config.session_max_usd - spent).max(0.0)
    }

    /// Get the total amount spent this session.
    #[must_use]
    pub fn spent(&self) -> f64 {
        self.session_spent.read().map_or(0.0, |s| *s)
    }

    /// Get the budget configuration.
    #[must_use]
    pub fn config(&self) -> &BudgetConfig {
        &self.config
    }

    /// Reset the session spend to zero.
    pub fn reset(&self) {
        if let Ok(mut spent) = self.session_spent.write() {
            *spent = 0.0;
        }
    }
}

impl Default for BudgetTracker {
    fn default() -> Self {
        Self::new(BudgetConfig::default())
    }
}

/// Snapshot of budget state for persistence.
///
/// Captures the current spending and configuration so a `BudgetTracker` can
/// be reconstructed later (e.g., when resuming a session).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetSnapshot {
    /// Total spent so far (USD).
    pub session_spent_usd: f64,
    /// Budget configuration.
    pub config: BudgetConfig,
    /// When the snapshot was taken.
    pub last_updated: chrono::DateTime<chrono::Utc>,
}

impl BudgetTracker {
    /// Take a snapshot of the current budget state for persistence.
    #[must_use]
    pub fn snapshot(&self) -> BudgetSnapshot {
        BudgetSnapshot {
            session_spent_usd: self.spent(),
            config: self.config.clone(),
            last_updated: chrono::Utc::now(),
        }
    }

    /// Restore a `BudgetTracker` from a previously saved snapshot.
    ///
    /// The spent amount is clamped to a non-negative, finite value to prevent
    /// budget manipulation via tampered snapshots (e.g., negative spend granting
    /// unlimited budget, or NaN/Infinity corrupting calculations).
    #[must_use]
    pub fn restore(snapshot: BudgetSnapshot) -> Self {
        // Clamp to non-negative, finite value
        let spent = if snapshot.session_spent_usd.is_finite() {
            snapshot.session_spent_usd.max(0.0)
        } else {
            0.0
        };
        let tracker = Self::new(snapshot.config);
        // Use direct write since record_cost would reject 0.0
        if spent > 0.0
            && let Ok(mut s) = tracker.session_spent.write()
        {
            *s = spent;
        }
        tracker
    }
}

impl fmt::Debug for BudgetTracker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let spent = self.spent();
        let remaining = self.remaining();
        f.debug_struct("BudgetTracker")
            .field("config", &self.config)
            .field("spent", &spent)
            .field("remaining", &remaining)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Workspace cumulative budget
// ---------------------------------------------------------------------------

/// Snapshot of workspace budget state for persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceBudgetSnapshot {
    /// Total spent across all sessions in this workspace (USD).
    pub total_spent_usd: f64,
    /// When the snapshot was taken.
    pub last_updated: chrono::DateTime<chrono::Utc>,
}

/// Tracks cumulative spending across all sessions in a workspace.
///
/// Thread-safe via internal [`RwLock`]. The workspace budget is optional —
/// when `max_usd` is `None`, the tracker still records spend for reporting
/// but never blocks.
pub struct WorkspaceBudgetTracker {
    max_usd: Option<f64>,
    total_spent: RwLock<f64>,
    warn_at_percent: u8,
}

impl WorkspaceBudgetTracker {
    /// Create a new workspace budget tracker.
    ///
    /// `warn_at_percent` controls the warning threshold (0–100). Values above
    /// 100 are clamped.
    #[must_use]
    pub fn new(max_usd: Option<f64>, warn_at_percent: u8) -> Self {
        Self {
            max_usd,
            total_spent: RwLock::new(0.0),
            warn_at_percent: warn_at_percent.min(100),
        }
    }

    /// Record an actual cost against the workspace budget.
    ///
    /// Only positive, finite values are accepted.
    pub fn record_cost(&self, cost: f64) {
        if cost > 0.0
            && cost.is_finite()
            && let Ok(mut spent) = self.total_spent.write()
        {
            *spent += cost;
        }
    }

    /// Refund a previously recorded cost against the workspace budget.
    pub fn refund_cost(&self, cost: f64) {
        if cost > 0.0
            && cost.is_finite()
            && let Ok(mut spent) = self.total_spent.write()
        {
            *spent = (*spent - cost).max(0.0);
        }
    }

    /// Atomically check if an estimated cost is within the workspace budget and reserve it.
    ///
    /// This combines [`check_budget`](Self::check_budget) and
    /// [`record_cost`](Self::record_cost) under a single write lock to prevent
    /// race conditions.
    #[must_use]
    pub fn check_and_reserve(&self, estimated_cost: f64) -> BudgetResult {
        let Some(max) = self.max_usd else {
            // No budget cap — still record the cost for reporting
            if estimated_cost > 0.0
                && estimated_cost.is_finite()
                && let Ok(mut spent) = self.total_spent.write()
            {
                *spent += estimated_cost;
            }
            return BudgetResult::Allowed;
        };

        // Atomic check + reserve under write lock
        let mut spent = self.total_spent.write().unwrap_or_else(|e| {
            tracing::warn!("WorkspaceBudgetTracker lock poisoned, recovering");
            e.into_inner()
        });
        let remaining = max - *spent;

        if estimated_cost > remaining {
            return BudgetResult::Exceeded {
                reason: ExceededReason::WorkspaceBudget,
                requested: estimated_cost,
                available: remaining.max(0.0),
            };
        }

        let new_spend = *spent + estimated_cost;
        // Reserve atomically
        if estimated_cost > 0.0 && estimated_cost.is_finite() {
            *spent = new_spend;
        }

        let warn_threshold = max * f64::from(self.warn_at_percent) / 100.0;
        if new_spend >= warn_threshold {
            return BudgetResult::WarnAndAllow {
                current_spend: new_spend,
                session_max: max,
                percent_used: (new_spend / max) * 100.0,
            };
        }

        BudgetResult::Allowed
    }

    /// Check if an estimated cost is within the workspace budget.
    #[must_use]
    pub fn check_budget(&self, estimated_cost: f64) -> BudgetResult {
        let Some(max) = self.max_usd else {
            return BudgetResult::Allowed;
        };

        let spent = self.total_spent.read().map_or(0.0, |s| *s);
        let remaining = max - spent;

        if estimated_cost > remaining {
            return BudgetResult::Exceeded {
                reason: ExceededReason::WorkspaceBudget,
                requested: estimated_cost,
                available: remaining.max(0.0),
            };
        }

        let new_spend = spent + estimated_cost;
        let warn_threshold = max * f64::from(self.warn_at_percent) / 100.0;
        if new_spend >= warn_threshold {
            return BudgetResult::WarnAndAllow {
                current_spend: new_spend,
                session_max: max,
                percent_used: (new_spend / max) * 100.0,
            };
        }

        BudgetResult::Allowed
    }

    /// Get the total amount spent in this workspace.
    #[must_use]
    pub fn spent(&self) -> f64 {
        self.total_spent.read().map_or(0.0, |s| *s)
    }

    /// Get the remaining workspace budget, or `None` if unlimited.
    #[must_use]
    pub fn remaining(&self) -> Option<f64> {
        self.max_usd.map(|max| (max - self.spent()).max(0.0))
    }

    /// Take a snapshot for persistence.
    #[must_use]
    pub fn snapshot(&self) -> WorkspaceBudgetSnapshot {
        WorkspaceBudgetSnapshot {
            total_spent_usd: self.spent(),
            last_updated: chrono::Utc::now(),
        }
    }

    /// Restore from a previously saved snapshot.
    ///
    /// Clamps negative/NaN/infinity to 0 to prevent budget manipulation.
    #[must_use]
    pub fn restore(
        snapshot: &WorkspaceBudgetSnapshot,
        max_usd: Option<f64>,
        warn_at_percent: u8,
    ) -> Self {
        let spent = if snapshot.total_spent_usd.is_finite() {
            snapshot.total_spent_usd.max(0.0)
        } else {
            0.0
        };
        let tracker = Self::new(max_usd, warn_at_percent);
        if spent > 0.0
            && let Ok(mut s) = tracker.total_spent.write()
        {
            *s = spent;
        }
        tracker
    }
}

impl fmt::Debug for WorkspaceBudgetTracker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WorkspaceBudgetTracker")
            .field("max_usd", &self.max_usd)
            .field("warn_at_percent", &self.warn_at_percent)
            .field("spent", &self.spent())
            .field("remaining", &self.remaining())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tracker(max: f64, per_action: f64) -> BudgetTracker {
        BudgetTracker::new(BudgetConfig::new(max, per_action))
    }

    // -----------------------------------------------------------------------
    // BudgetConfig tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_config_defaults() {
        let config = BudgetConfig::default();
        assert!((config.session_max_usd - 100.0).abs() < f64::EPSILON);
        assert!((config.per_action_max_usd - 10.0).abs() < f64::EPSILON);
        assert_eq!(config.warn_at_percent, 80);
    }

    #[test]
    fn test_config_warn_threshold() {
        let config = BudgetConfig::new(100.0, 10.0);
        assert!((config.warn_threshold_usd() - 80.0).abs() < f64::EPSILON);

        let config = BudgetConfig::new(50.0, 5.0).with_warn_at_percent(90);
        assert!((config.warn_threshold_usd() - 45.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_config_warn_percent_clamped() {
        let config = BudgetConfig::new(100.0, 10.0).with_warn_at_percent(150);
        assert_eq!(config.warn_at_percent, 100);
    }

    #[test]
    fn test_config_serialization() {
        let config = BudgetConfig::new(100.0, 10.0).with_warn_at_percent(75);
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: BudgetConfig = serde_json::from_str(&json).unwrap();
        assert!((deserialized.session_max_usd - 100.0).abs() < f64::EPSILON);
        assert_eq!(deserialized.warn_at_percent, 75);
    }

    // -----------------------------------------------------------------------
    // BudgetResult tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_result_allowed() {
        let result = BudgetResult::Allowed;
        assert!(result.is_allowed());
        assert!(!result.is_exceeded());
    }

    #[test]
    fn test_result_warn() {
        let result = BudgetResult::WarnAndAllow {
            current_spend: 85.0,
            session_max: 100.0,
            percent_used: 85.0,
        };
        assert!(result.is_allowed());
        assert!(!result.is_exceeded());
    }

    #[test]
    fn test_result_exceeded() {
        let result = BudgetResult::Exceeded {
            reason: ExceededReason::SessionBudget,
            requested: 20.0,
            available: 5.0,
        };
        assert!(!result.is_allowed());
        assert!(result.is_exceeded());
    }

    #[test]
    fn test_result_display() {
        assert_eq!(BudgetResult::Allowed.to_string(), "within budget");

        let warn = BudgetResult::WarnAndAllow {
            current_spend: 85.0,
            session_max: 100.0,
            percent_used: 85.0,
        };
        assert!(warn.to_string().contains("85%"));

        let exceeded = BudgetResult::Exceeded {
            reason: ExceededReason::PerActionLimit,
            requested: 15.0,
            available: 10.0,
        };
        assert!(exceeded.to_string().contains("per-action limit"));
    }

    // -----------------------------------------------------------------------
    // BudgetTracker tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_tracker_within_budget() {
        let tracker = make_tracker(100.0, 10.0);
        let result = tracker.check_budget(5.0);
        assert_eq!(result, BudgetResult::Allowed);
    }

    #[test]
    fn test_tracker_per_action_exceeded() {
        let tracker = make_tracker(100.0, 10.0);
        let result = tracker.check_budget(15.0);
        assert!(result.is_exceeded());
        assert!(matches!(
            result,
            BudgetResult::Exceeded {
                reason: ExceededReason::PerActionLimit,
                ..
            }
        ));
    }

    #[test]
    fn test_tracker_session_exceeded() {
        let tracker = make_tracker(100.0, 50.0);
        tracker.record_cost(90.0);
        let result = tracker.check_budget(15.0);
        assert!(result.is_exceeded());
        assert!(matches!(
            result,
            BudgetResult::Exceeded {
                reason: ExceededReason::SessionBudget,
                ..
            }
        ));
    }

    #[test]
    fn test_tracker_warning_threshold() {
        let tracker = make_tracker(100.0, 50.0);
        tracker.record_cost(75.0);

        // 75 + 10 = 85, which is >= 80% threshold
        let result = tracker.check_budget(10.0);
        assert!(matches!(result, BudgetResult::WarnAndAllow { .. }));
        assert!(result.is_allowed());
    }

    #[test]
    fn test_tracker_just_below_warning() {
        let tracker = make_tracker(100.0, 50.0);
        tracker.record_cost(70.0);

        // 70 + 5 = 75, which is below 80% threshold
        let result = tracker.check_budget(5.0);
        assert_eq!(result, BudgetResult::Allowed);
    }

    #[test]
    fn test_tracker_record_and_remaining() {
        let tracker = make_tracker(100.0, 10.0);
        assert!((tracker.remaining() - 100.0).abs() < f64::EPSILON);
        assert!(tracker.spent().abs() < f64::EPSILON);

        tracker.record_cost(30.0);
        assert!((tracker.remaining() - 70.0).abs() < f64::EPSILON);
        assert!((tracker.spent() - 30.0).abs() < f64::EPSILON);

        tracker.record_cost(50.0);
        assert!((tracker.remaining() - 20.0).abs() < f64::EPSILON);
        assert!((tracker.spent() - 80.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_tracker_remaining_never_negative() {
        let tracker = make_tracker(10.0, 10.0);
        tracker.record_cost(15.0); // overspend
        assert!(tracker.remaining().abs() < f64::EPSILON);
    }

    #[test]
    fn test_tracker_reset() {
        let tracker = make_tracker(100.0, 10.0);
        tracker.record_cost(50.0);
        assert!((tracker.spent() - 50.0).abs() < f64::EPSILON);

        tracker.reset();
        assert!(tracker.spent().abs() < f64::EPSILON);
        assert!((tracker.remaining() - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_tracker_default() {
        let tracker = BudgetTracker::default();
        assert!((tracker.config().session_max_usd - 100.0).abs() < f64::EPSILON);
        assert!((tracker.remaining() - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_tracker_debug() {
        let tracker = make_tracker(100.0, 10.0);
        tracker.record_cost(25.0);
        let debug = format!("{tracker:?}");
        assert!(debug.contains("BudgetTracker"));
        assert!(debug.contains("spent"));
        assert!(debug.contains("remaining"));
    }

    #[test]
    fn test_tracker_zero_cost() {
        let tracker = make_tracker(100.0, 10.0);
        let result = tracker.check_budget(0.0);
        assert_eq!(result, BudgetResult::Allowed);
    }

    #[test]
    fn test_tracker_exact_budget() {
        let tracker = make_tracker(10.0, 10.0);
        // Exactly the budget — should warn (10/10 = 100% >= 80%)
        let result = tracker.check_budget(10.0);
        assert!(matches!(result, BudgetResult::WarnAndAllow { .. }));
    }

    #[test]
    fn test_exceeded_reason_display() {
        assert_eq!(
            ExceededReason::PerActionLimit.to_string(),
            "per-action limit"
        );
        assert_eq!(ExceededReason::SessionBudget.to_string(), "session budget");
    }

    // -----------------------------------------------------------------------
    // BudgetSnapshot tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_snapshot_captures_state() {
        let tracker = make_tracker(100.0, 10.0);
        tracker.record_cost(42.5);

        let snapshot = tracker.snapshot();
        assert!((snapshot.session_spent_usd - 42.5).abs() < f64::EPSILON);
        assert!((snapshot.config.session_max_usd - 100.0).abs() < f64::EPSILON);
        assert!((snapshot.config.per_action_max_usd - 10.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_snapshot_restore_roundtrip() {
        let tracker = make_tracker(50.0, 5.0);
        tracker.record_cost(17.5);

        let snapshot = tracker.snapshot();
        let restored = BudgetTracker::restore(snapshot);

        assert!((restored.spent() - 17.5).abs() < f64::EPSILON);
        assert!((restored.remaining() - 32.5).abs() < f64::EPSILON);
        assert!((restored.config().session_max_usd - 50.0).abs() < f64::EPSILON);
        assert!((restored.config().per_action_max_usd - 5.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_snapshot_serialization() {
        let tracker = make_tracker(100.0, 10.0);
        tracker.record_cost(25.0);

        let snapshot = tracker.snapshot();
        let json = serde_json::to_string(&snapshot).unwrap();
        let deserialized: BudgetSnapshot = serde_json::from_str(&json).unwrap();

        assert!((deserialized.session_spent_usd - 25.0).abs() < f64::EPSILON);
        assert!((deserialized.config.session_max_usd - 100.0).abs() < f64::EPSILON);
    }

    // -----------------------------------------------------------------------
    // Security: budget manipulation prevention
    // -----------------------------------------------------------------------

    #[test]
    fn test_restore_clamps_negative_spent() {
        let snapshot = BudgetSnapshot {
            session_spent_usd: -50.0,
            config: BudgetConfig::new(100.0, 10.0),
            last_updated: chrono::Utc::now(),
        };
        let tracker = BudgetTracker::restore(snapshot);
        // Negative spend should be clamped to 0, giving full budget
        assert!(tracker.spent().abs() < f64::EPSILON);
        assert!((tracker.remaining() - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_restore_clamps_nan_spent() {
        let snapshot = BudgetSnapshot {
            session_spent_usd: f64::NAN,
            config: BudgetConfig::new(100.0, 10.0),
            last_updated: chrono::Utc::now(),
        };
        let tracker = BudgetTracker::restore(snapshot);
        assert!(tracker.spent().abs() < f64::EPSILON);
        assert!((tracker.remaining() - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_restore_clamps_infinity_spent() {
        let snapshot = BudgetSnapshot {
            session_spent_usd: f64::NEG_INFINITY,
            config: BudgetConfig::new(100.0, 10.0),
            last_updated: chrono::Utc::now(),
        };
        let tracker = BudgetTracker::restore(snapshot);
        assert!(tracker.spent().abs() < f64::EPSILON);
        assert!((tracker.remaining() - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_record_cost_rejects_negative() {
        let tracker = make_tracker(100.0, 10.0);
        tracker.record_cost(-50.0);
        assert!(tracker.spent().abs() < f64::EPSILON);
    }

    #[test]
    fn test_record_cost_rejects_nan() {
        let tracker = make_tracker(100.0, 10.0);
        tracker.record_cost(f64::NAN);
        assert!(tracker.spent().abs() < f64::EPSILON);
    }

    #[test]
    fn test_record_cost_rejects_infinity() {
        let tracker = make_tracker(100.0, 10.0);
        tracker.record_cost(f64::INFINITY);
        assert!(tracker.spent().abs() < f64::EPSILON);
    }

    #[test]
    fn test_exceeded_reason_workspace_budget_display() {
        assert_eq!(
            ExceededReason::WorkspaceBudget.to_string(),
            "workspace budget"
        );
    }

    // -----------------------------------------------------------------------
    // WorkspaceBudgetTracker tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_workspace_tracker_unlimited() {
        let tracker = WorkspaceBudgetTracker::new(None, 80);
        assert_eq!(tracker.check_budget(1000.0), BudgetResult::Allowed);
        assert!(tracker.remaining().is_none());
    }

    #[test]
    fn test_workspace_tracker_within_budget() {
        let tracker = WorkspaceBudgetTracker::new(Some(100.0), 80);
        assert_eq!(tracker.check_budget(10.0), BudgetResult::Allowed);
    }

    #[test]
    fn test_workspace_tracker_exceeded() {
        let tracker = WorkspaceBudgetTracker::new(Some(50.0), 80);
        tracker.record_cost(45.0);
        let result = tracker.check_budget(10.0);
        assert!(result.is_exceeded());
        assert!(matches!(
            result,
            BudgetResult::Exceeded {
                reason: ExceededReason::WorkspaceBudget,
                ..
            }
        ));
    }

    #[test]
    fn test_workspace_tracker_warn() {
        let tracker = WorkspaceBudgetTracker::new(Some(100.0), 80);
        tracker.record_cost(75.0);
        // 75 + 10 = 85 >= 80% threshold
        let result = tracker.check_budget(10.0);
        assert!(matches!(result, BudgetResult::WarnAndAllow { .. }));
    }

    #[test]
    fn test_workspace_tracker_record_and_remaining() {
        let tracker = WorkspaceBudgetTracker::new(Some(100.0), 80);
        assert!(tracker.spent().abs() < f64::EPSILON);
        assert_eq!(tracker.remaining(), Some(100.0));

        tracker.record_cost(30.0);
        assert!((tracker.spent() - 30.0).abs() < f64::EPSILON);
        assert_eq!(tracker.remaining(), Some(70.0));
    }

    #[test]
    fn test_workspace_tracker_snapshot_roundtrip() {
        let tracker = WorkspaceBudgetTracker::new(Some(200.0), 80);
        tracker.record_cost(42.5);

        let snapshot = tracker.snapshot();
        assert!((snapshot.total_spent_usd - 42.5).abs() < f64::EPSILON);

        let restored = WorkspaceBudgetTracker::restore(&snapshot, Some(200.0), 80);
        assert!((restored.spent() - 42.5).abs() < f64::EPSILON);
        assert!((restored.remaining().unwrap() - 157.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_workspace_tracker_restore_clamps_negative() {
        let snapshot = WorkspaceBudgetSnapshot {
            total_spent_usd: -100.0,
            last_updated: chrono::Utc::now(),
        };
        let tracker = WorkspaceBudgetTracker::restore(&snapshot, Some(50.0), 80);
        assert!(tracker.spent().abs() < f64::EPSILON);
        assert_eq!(tracker.remaining(), Some(50.0));
    }

    #[test]
    fn test_workspace_tracker_restore_clamps_nan() {
        let snapshot = WorkspaceBudgetSnapshot {
            total_spent_usd: f64::NAN,
            last_updated: chrono::Utc::now(),
        };
        let tracker = WorkspaceBudgetTracker::restore(&snapshot, Some(50.0), 80);
        assert!(tracker.spent().abs() < f64::EPSILON);
    }

    #[test]
    fn test_workspace_tracker_restore_clamps_infinity() {
        let snapshot = WorkspaceBudgetSnapshot {
            total_spent_usd: f64::INFINITY,
            last_updated: chrono::Utc::now(),
        };
        let tracker = WorkspaceBudgetTracker::restore(&snapshot, Some(50.0), 80);
        assert!(tracker.spent().abs() < f64::EPSILON);
    }

    #[test]
    fn test_workspace_tracker_record_rejects_bad_values() {
        let tracker = WorkspaceBudgetTracker::new(Some(100.0), 80);
        tracker.record_cost(-10.0);
        tracker.record_cost(f64::NAN);
        tracker.record_cost(f64::INFINITY);
        assert!(tracker.spent().abs() < f64::EPSILON);
    }

    #[test]
    fn test_workspace_tracker_snapshot_serialization() {
        let tracker = WorkspaceBudgetTracker::new(Some(100.0), 80);
        tracker.record_cost(25.0);
        let snapshot = tracker.snapshot();
        let json = serde_json::to_string(&snapshot).unwrap();
        let deserialized: WorkspaceBudgetSnapshot = serde_json::from_str(&json).unwrap();
        assert!((deserialized.total_spent_usd - 25.0).abs() < f64::EPSILON);
    }
}
