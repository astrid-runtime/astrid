//! Deferred resolution queue for actions that cannot be resolved immediately.
//!
//! When a user is unavailable during an approval request, the action is queued
//! for later resolution. The agent continues working within its existing
//! capability bounds.
//!
//! The [`DeferredResolutionStore`] holds pending resolutions in memory and
//! supports queuing, retrieval, resolution, and age-based cleanup.

use crate::error::{ApprovalError, ApprovalResult};
use astrid_core::types::{Permission, Timestamp};
use astrid_storage::ScopedKvStore;
use chrono::Duration;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::sync::RwLock;
use uuid::Uuid;

use crate::request::ApprovalRequest;

/// Unique identifier for a deferred resolution.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ResolutionId(pub Uuid);

impl ResolutionId {
    /// Create a new random resolution ID.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for ResolutionId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ResolutionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "resolution:{}", self.0)
    }
}

/// Priority level for deferred resolutions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Priority {
    /// Low priority — can wait indefinitely.
    Low,
    /// Normal priority — should be resolved reasonably soon.
    Normal,
    /// High priority — user attention needed promptly.
    High,
    /// Critical — blocking important work.
    Critical,
}

impl fmt::Display for Priority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Normal => write!(f, "normal"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

/// Context about the action that triggered the deferred resolution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionContext {
    /// What the agent was trying to accomplish.
    pub goal: String,
    /// What task the agent was working on (if known).
    pub task: Option<String>,
}

impl ActionContext {
    /// Create a new action context.
    #[must_use]
    pub fn new(goal: impl Into<String>) -> Self {
        Self {
            goal: goal.into(),
            task: None,
        }
    }

    /// Set the task description.
    #[must_use]
    pub fn with_task(mut self, task: impl Into<String>) -> Self {
        self.task = Some(task.into());
        self
    }
}

/// What action is pending resolution.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PendingAction {
    /// Approval was needed but user was unavailable.
    ApprovalNeeded {
        /// The original approval request.
        request: ApprovalRequest,
    },
    /// Budget was exceeded for the action.
    BudgetExceeded {
        /// Amount requested (as string to avoid float issues).
        requested: String,
        /// Amount available (as string).
        available: String,
    },
    /// A required capability was missing.
    CapabilityMissing {
        /// Resource being accessed.
        resource: String,
        /// Permission that was needed.
        permission: Permission,
    },
    /// An error occurred that needs user resolution.
    ErrorResolution {
        /// Description of the error.
        error: String,
        /// What action was being attempted.
        attempted_action: String,
    },
}

impl PendingAction {
    /// Get a human-readable summary of the pending action.
    #[must_use]
    pub fn summary(&self) -> String {
        match self {
            Self::ApprovalNeeded { request } => {
                format!("Approval needed: {}", request.action)
            },
            Self::BudgetExceeded {
                requested,
                available,
            } => {
                format!("Budget exceeded: requested ${requested}, available ${available}")
            },
            Self::CapabilityMissing {
                resource,
                permission,
            } => {
                format!("Missing capability: {permission} on {resource}")
            },
            Self::ErrorResolution {
                error,
                attempted_action,
            } => {
                format!("Error during {attempted_action}: {error}")
            },
        }
    }
}

/// Configurable fallback behavior when an action cannot be immediately resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackBehavior {
    /// Wait for resolution (critical/irreversible actions).
    Block,
    /// Skip the action and continue with other work.
    Skip,
    /// Take a conservative default action.
    SafeDefault,
    /// Queue for retry after resolution.
    Queue,
}

impl fmt::Display for FallbackBehavior {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Block => write!(f, "block"),
            Self::Skip => write!(f, "skip"),
            Self::SafeDefault => write!(f, "safe_default"),
            Self::Queue => write!(f, "queue"),
        }
    }
}

/// A deferred resolution — an action queued for later user attention.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeferredResolution {
    /// Unique identifier.
    pub id: ResolutionId,
    /// The pending action needing resolution.
    pub action: PendingAction,
    /// Why this was deferred.
    pub reason: String,
    /// When it was queued.
    pub queued_at: Timestamp,
    /// Priority level.
    pub priority: Priority,
    /// Context about what the agent was doing.
    pub context: ActionContext,
    /// What fallback action was taken (if any).
    pub fallback_taken: Option<String>,
}

impl DeferredResolution {
    /// Create a new deferred resolution.
    #[must_use]
    pub fn new(
        action: PendingAction,
        reason: impl Into<String>,
        priority: Priority,
        context: ActionContext,
    ) -> Self {
        Self {
            id: ResolutionId::new(),
            action,
            reason: reason.into(),
            queued_at: Timestamp::now(),
            priority,
            context,
            fallback_taken: None,
        }
    }

    /// Record what fallback was taken.
    #[must_use]
    pub fn with_fallback(mut self, fallback: impl Into<String>) -> Self {
        self.fallback_taken = Some(fallback.into());
        self
    }

    /// Check if this resolution is older than the given duration.
    #[must_use]
    pub fn is_older_than(&self, max_age: Duration) -> bool {
        // Safety: chrono Duration subtraction from DateTime cannot overflow for reasonable durations
        #[expect(clippy::arithmetic_side_effects)]
        let cutoff = Timestamp::from_datetime(chrono::Utc::now() - max_age);
        self.queued_at < cutoff
    }
}

impl fmt::Display for DeferredResolution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} - {} (queued {})",
            self.priority,
            self.id,
            self.action.summary(),
            self.queued_at
        )
    }
}

// ---------------------------------------------------------------------------
// DeferredResolutionStore
// ---------------------------------------------------------------------------

/// In-memory store for deferred resolutions.
///
/// Thread-safe via internal [`RwLock`]. Supports queuing, retrieval,
/// resolution, and age-based cleanup.
///
/// # Example
///
/// ```
/// use astrid_approval::deferred::DeferredResolutionStore;
///
/// let store = DeferredResolutionStore::new();
/// assert_eq!(store.count(), 0);
/// ```
pub struct DeferredResolutionStore {
    resolutions: RwLock<HashMap<ResolutionId, DeferredResolution>>,
    /// Optional persistent store for surviving restarts.
    persistent_store: Option<ScopedKvStore>,
}

impl DeferredResolutionStore {
    /// Create a new empty store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            resolutions: RwLock::new(HashMap::new()),
            persistent_store: None,
        }
    }

    /// Create a store with persistence.
    ///
    /// Loads existing deferred resolutions from the store on creation.
    ///
    /// # Errors
    ///
    /// Returns a storage error if loading from the persistent store fails.
    pub async fn with_persistence(store: ScopedKvStore) -> ApprovalResult<Self> {
        let mut s = Self {
            resolutions: RwLock::new(HashMap::new()),
            persistent_store: Some(store),
        };
        s.load_from_store().await?;
        Ok(s)
    }

    /// Maximum age for loaded deferred resolutions (24 hours).
    ///
    /// Items older than this are considered stale and are removed from the
    /// persistent store on load to prevent replay of outdated requests.
    const MAX_LOAD_AGE: Duration = Duration::hours(24);

    /// Load all deferred resolutions from persistent storage into memory.
    ///
    /// Items older than [`MAX_LOAD_AGE`](Self::MAX_LOAD_AGE) are discarded
    /// and removed from the persistent store to prevent stale replay.
    async fn load_from_store(&mut self) -> ApprovalResult<()> {
        let Some(store) = &self.persistent_store else {
            return Ok(());
        };
        let keys = store
            .list_keys()
            .await
            .map_err(|e| ApprovalError::Storage(e.to_string()))?;

        // Collect loaded resolutions first (avoiding holding MutexGuard across await)
        let mut loaded = Vec::new();
        for key in &keys {
            match store.get_json::<DeferredResolution>(key).await {
                Ok(Some(resolution)) => {
                    if resolution.is_older_than(Self::MAX_LOAD_AGE) {
                        // Remove stale item from persistent store
                        tracing::info!(
                            key = %key,
                            queued_at = %resolution.queued_at,
                            "Discarding stale deferred resolution (older than 24h)"
                        );
                        let _ = store.delete(key).await;
                    } else {
                        loaded.push(resolution);
                    }
                },
                Ok(None) => {},
                Err(e) => {
                    tracing::warn!(key = %key, error = %e, "Failed to load deferred resolution");
                },
            }
        }

        let mut resolutions = self
            .resolutions
            .write()
            .map_err(|e| ApprovalError::Storage(e.to_string()))?;
        for resolution in loaded {
            resolutions.insert(resolution.id.clone(), resolution);
        }
        Ok(())
    }

    /// Queue a new deferred resolution.
    ///
    /// Returns the resolution ID.
    ///
    /// # Errors
    ///
    /// Returns a storage error if the internal lock is poisoned.
    pub fn queue(&self, resolution: DeferredResolution) -> ApprovalResult<ResolutionId> {
        let id = resolution.id.clone();
        let mut store = self
            .resolutions
            .write()
            .map_err(|e| ApprovalError::Storage(e.to_string()))?;
        store.insert(id.clone(), resolution);
        Ok(id)
    }

    /// Get all pending resolutions, sorted by priority (highest first).
    #[must_use]
    pub fn get_pending(&self) -> Vec<DeferredResolution> {
        let Ok(store) = self.resolutions.read() else {
            return Vec::new();
        };
        let mut pending: Vec<_> = store.values().cloned().collect();
        // Sort by priority descending (Critical > High > Normal > Low)
        pending.sort_by_key(|p| std::cmp::Reverse(p.priority));
        pending
    }

    /// Resolve (remove) a deferred resolution by ID.
    ///
    /// Returns the resolved item.
    ///
    /// # Errors
    ///
    /// Returns a storage error if the resolution is not found or the lock is poisoned.
    pub fn resolve(&self, id: &ResolutionId) -> ApprovalResult<DeferredResolution> {
        let mut store = self
            .resolutions
            .write()
            .map_err(|e| ApprovalError::Storage(e.to_string()))?;
        store
            .remove(id)
            .ok_or_else(|| ApprovalError::Storage(format!("resolution not found: {id}")))
    }

    /// Remove all resolutions older than the given duration.
    ///
    /// Returns the number of resolutions removed.
    pub fn cleanup_old(&self, max_age: Duration) -> usize {
        let Ok(mut store) = self.resolutions.write() else {
            return 0;
        };
        let before = store.len();
        store.retain(|_, r| !r.is_older_than(max_age));
        before.saturating_sub(store.len())
    }

    /// Queue a new deferred resolution with persistence.
    ///
    /// If a persistent store is configured, the resolution is written to disk.
    ///
    /// # Errors
    ///
    /// Returns a storage error if the internal lock is poisoned or persistence fails.
    pub async fn queue_persistent(
        &self,
        resolution: DeferredResolution,
    ) -> ApprovalResult<ResolutionId> {
        let id = resolution.id.clone();

        // Persist first (fail fast)
        if let Some(store) = &self.persistent_store {
            store
                .set_json(&id.0.to_string(), &resolution)
                .await
                .map_err(|e| ApprovalError::Storage(e.to_string()))?;
        }

        // Then add to memory
        let mut resolutions = self
            .resolutions
            .write()
            .map_err(|e| ApprovalError::Storage(e.to_string()))?;
        resolutions.insert(id.clone(), resolution);
        Ok(id)
    }

    /// Resolve (remove) a deferred resolution by ID, with persistence.
    ///
    /// If a persistent store is configured, the resolution is removed from disk.
    ///
    /// # Errors
    ///
    /// Returns a storage error if the resolution is not found, the lock is poisoned,
    /// or persistence fails.
    pub async fn resolve_persistent(
        &self,
        id: &ResolutionId,
    ) -> ApprovalResult<DeferredResolution> {
        // Remove from memory
        let resolution = {
            let mut store = self
                .resolutions
                .write()
                .map_err(|e| ApprovalError::Storage(e.to_string()))?;
            store
                .remove(id)
                .ok_or_else(|| ApprovalError::Storage(format!("resolution not found: {id}")))?
        };

        // Remove from persistent store
        if let Some(store) = &self.persistent_store {
            let _ = store
                .delete(&id.0.to_string())
                .await
                .map_err(|e| ApprovalError::Storage(e.to_string()));
        }

        Ok(resolution)
    }

    /// Get the number of pending resolutions.
    #[must_use]
    pub fn count(&self) -> usize {
        self.resolutions.read().map_or(0, |s| s.len())
    }
}

impl Default for DeferredResolutionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for DeferredResolutionStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let count = self.count();
        f.debug_struct("DeferredResolutionStore")
            .field("count", &count)
            .field("has_persistence", &self.persistent_store.is_some())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::SensitiveAction;

    fn make_approval_request() -> ApprovalRequest {
        ApprovalRequest::new(
            SensitiveAction::FileDelete {
                path: "/important.txt".to_string(),
            },
            "Cleaning up files",
        )
    }

    fn make_resolution(priority: Priority) -> DeferredResolution {
        DeferredResolution::new(
            PendingAction::ApprovalNeeded {
                request: make_approval_request(),
            },
            "user unavailable",
            priority,
            ActionContext::new("cleaning up workspace"),
        )
    }

    // -----------------------------------------------------------------------
    // ResolutionId tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_resolution_id() {
        let id1 = ResolutionId::new();
        let id2 = ResolutionId::new();
        assert_ne!(id1, id2);
        assert!(id1.to_string().starts_with("resolution:"));
    }

    // -----------------------------------------------------------------------
    // PendingAction tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_pending_action_summary() {
        let action = PendingAction::ApprovalNeeded {
            request: make_approval_request(),
        };
        assert!(action.summary().contains("Approval needed"));

        let action = PendingAction::BudgetExceeded {
            requested: "50.00".to_string(),
            available: "10.00".to_string(),
        };
        assert!(action.summary().contains("50.00"));
        assert!(action.summary().contains("10.00"));

        let action = PendingAction::CapabilityMissing {
            resource: "file:///etc/passwd".to_string(),
            permission: Permission::Read,
        };
        assert!(action.summary().contains("read"));

        let action = PendingAction::ErrorResolution {
            error: "connection refused".to_string(),
            attempted_action: "API call".to_string(),
        };
        assert!(action.summary().contains("connection refused"));
    }

    // -----------------------------------------------------------------------
    // DeferredResolution tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_deferred_resolution_creation() {
        let resolution = make_resolution(Priority::High);
        assert_eq!(resolution.priority, Priority::High);
        assert!(resolution.fallback_taken.is_none());
    }

    #[test]
    fn test_deferred_resolution_with_fallback() {
        let resolution =
            make_resolution(Priority::Normal).with_fallback("skipped action, continued with task");
        assert_eq!(
            resolution.fallback_taken.as_deref(),
            Some("skipped action, continued with task")
        );
    }

    #[test]
    fn test_deferred_resolution_age() {
        let resolution = make_resolution(Priority::Normal);
        // Just created, should not be older than 1 hour
        assert!(!resolution.is_older_than(Duration::hours(1)));
    }

    #[test]
    fn test_deferred_resolution_display() {
        let resolution = make_resolution(Priority::Critical);
        let display = resolution.to_string();
        assert!(display.contains("critical"));
        assert!(display.contains("Approval needed"));
    }

    // -----------------------------------------------------------------------
    // FallbackBehavior tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_fallback_behavior_display() {
        assert_eq!(FallbackBehavior::Block.to_string(), "block");
        assert_eq!(FallbackBehavior::Skip.to_string(), "skip");
        assert_eq!(FallbackBehavior::SafeDefault.to_string(), "safe_default");
        assert_eq!(FallbackBehavior::Queue.to_string(), "queue");
    }

    // -----------------------------------------------------------------------
    // Priority tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_priority_ordering() {
        assert!(Priority::Low < Priority::Normal);
        assert!(Priority::Normal < Priority::High);
        assert!(Priority::High < Priority::Critical);
    }

    // -----------------------------------------------------------------------
    // DeferredResolutionStore tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_store_queue_and_count() {
        let store = DeferredResolutionStore::new();
        assert_eq!(store.count(), 0);

        let resolution = make_resolution(Priority::Normal);
        store.queue(resolution).unwrap();
        assert_eq!(store.count(), 1);
    }

    #[test]
    fn test_store_get_pending_sorted() {
        let store = DeferredResolutionStore::new();

        store.queue(make_resolution(Priority::Low)).unwrap();
        store.queue(make_resolution(Priority::Critical)).unwrap();
        store.queue(make_resolution(Priority::Normal)).unwrap();

        let pending = store.get_pending();
        assert_eq!(pending.len(), 3);
        // Should be sorted: Critical, Normal, Low
        assert_eq!(pending[0].priority, Priority::Critical);
        assert_eq!(pending[1].priority, Priority::Normal);
        assert_eq!(pending[2].priority, Priority::Low);
    }

    #[test]
    fn test_store_resolve() {
        let store = DeferredResolutionStore::new();

        let resolution = make_resolution(Priority::High);
        let id = resolution.id.clone();
        store.queue(resolution).unwrap();
        assert_eq!(store.count(), 1);

        let resolved = store.resolve(&id).unwrap();
        assert_eq!(resolved.id, id);
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn test_store_resolve_not_found() {
        let store = DeferredResolutionStore::new();
        let result = store.resolve(&ResolutionId::new());
        assert!(result.is_err());
    }

    #[test]
    fn test_store_cleanup_old() {
        let store = DeferredResolutionStore::new();

        // Queue a resolution
        store.queue(make_resolution(Priority::Normal)).unwrap();
        assert_eq!(store.count(), 1);

        // Cleanup with 1 hour max age — nothing should be removed (just created)
        let removed = store.cleanup_old(Duration::hours(1));
        assert_eq!(removed, 0);
        assert_eq!(store.count(), 1);
    }

    #[test]
    fn test_store_default() {
        let store = DeferredResolutionStore::default();
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn test_store_debug() {
        let store = DeferredResolutionStore::new();
        let debug = format!("{store:?}");
        assert!(debug.contains("DeferredResolutionStore"));
        assert!(debug.contains("count"));
    }

    #[test]
    fn test_pending_action_serialization() {
        let action = PendingAction::ApprovalNeeded {
            request: make_approval_request(),
        };
        let json = serde_json::to_string(&action).unwrap();
        let deserialized: PendingAction = serde_json::from_str(&json).unwrap();
        assert!(deserialized.summary().contains("Approval needed"));
    }

    #[test]
    fn test_deferred_resolution_serialization() {
        let resolution = make_resolution(Priority::High).with_fallback("skipped");
        let json = serde_json::to_string(&resolution).unwrap();
        let deserialized: DeferredResolution = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.priority, Priority::High);
        assert_eq!(deserialized.fallback_taken.as_deref(), Some("skipped"));
    }

    // -----------------------------------------------------------------------
    // Persistence tests
    // -----------------------------------------------------------------------

    use std::sync::Arc;

    use astrid_storage::{MemoryKvStore, ScopedKvStore};

    #[tokio::test]
    async fn test_persistent_queue_and_resolve() {
        let backend = Arc::new(MemoryKvStore::new());
        let scoped = ScopedKvStore::new(backend.clone(), "test:deferred").unwrap();
        let store = DeferredResolutionStore::with_persistence(scoped)
            .await
            .unwrap();

        let resolution = make_resolution(Priority::High);
        let id = resolution.id.clone();
        store.queue_persistent(resolution).await.unwrap();
        assert_eq!(store.count(), 1);

        let resolved = store.resolve_persistent(&id).await.unwrap();
        assert_eq!(resolved.id, id);
        assert_eq!(store.count(), 0);
    }

    #[tokio::test]
    async fn test_persistent_survives_reload() {
        let backend = Arc::new(MemoryKvStore::new());

        // Queue something with persistence
        {
            let scoped = ScopedKvStore::new(backend.clone(), "test:deferred").unwrap();
            let store = DeferredResolutionStore::with_persistence(scoped)
                .await
                .unwrap();
            store
                .queue_persistent(make_resolution(Priority::Critical))
                .await
                .unwrap();
            assert_eq!(store.count(), 1);
        }

        // Create a new store with the same backend — should load the resolution
        {
            let scoped = ScopedKvStore::new(backend, "test:deferred").unwrap();
            let store = DeferredResolutionStore::with_persistence(scoped)
                .await
                .unwrap();
            assert_eq!(store.count(), 1);
            let pending = store.get_pending();
            assert_eq!(pending[0].priority, Priority::Critical);
        }
    }

    #[tokio::test]
    async fn test_persistent_resolve_removes_from_store() {
        let backend = Arc::new(MemoryKvStore::new());

        let id;
        {
            let scoped = ScopedKvStore::new(backend.clone(), "test:deferred").unwrap();
            let store = DeferredResolutionStore::with_persistence(scoped)
                .await
                .unwrap();
            let resolution = make_resolution(Priority::Normal);
            id = resolution.id.clone();
            store.queue_persistent(resolution).await.unwrap();
            store.resolve_persistent(&id).await.unwrap();
        }

        // Reload — should be empty since we resolved it
        {
            let scoped = ScopedKvStore::new(backend, "test:deferred").unwrap();
            let store = DeferredResolutionStore::with_persistence(scoped)
                .await
                .unwrap();
            assert_eq!(store.count(), 0);
        }
    }
}
