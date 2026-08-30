use crate::context::{Duration, Timestamp};
use crate::error::{PackageServiceError, PackageServiceResult};
use crate::journal::{JournalStatus, OperationJournalRecord};
use std::num::NonZeroU64;
use std::time::Duration as StdDuration;

const fn non_zero(value: u64) -> NonZeroU64 {
    match NonZeroU64::new(value) {
        Some(value) => value,
        None => panic!("bounded policy capacity is non-zero"),
    }
}

/// Retention bounds for a terminal record class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetentionWindow {
    minimum: StdDuration,
    maximum: StdDuration,
}

impl RetentionWindow {
    /// Constructs finite retention bounds with `maximum >= minimum`.
    ///
    /// # Errors
    /// Returns [`PackageServiceError::InvalidValue`] for zero or inverted bounds.
    pub fn new(minimum: StdDuration, maximum: StdDuration) -> Result<Self, PackageServiceError> {
        if minimum.is_zero() || maximum < minimum {
            return Err(PackageServiceError::InvalidValue("retention"));
        }
        Ok(Self { minimum, maximum })
    }

    /// Returns the guaranteed minimum retention.
    #[must_use]
    pub const fn minimum(&self) -> StdDuration {
        self.minimum
    }

    /// Returns the finite hard retention maximum.
    #[must_use]
    pub const fn maximum(&self) -> StdDuration {
        self.maximum
    }
}

/// Retention policy by terminal outcome class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalRetention {
    receipts: RetentionWindow,
    terminal_failures: RetentionWindow,
}

impl JournalRetention {
    /// Constructs finite retention classes.
    #[must_use]
    pub fn new(receipts: RetentionWindow, terminal_failures: RetentionWindow) -> Self {
        Self {
            receipts,
            terminal_failures,
        }
    }

    fn window(&self, record: &OperationJournalRecord) -> Option<RetentionWindow> {
        match record.status() {
            JournalStatus::Committed => Some(self.receipts),
            JournalStatus::Failed | JournalStatus::Expired | JournalStatus::Aborted => {
                Some(self.terminal_failures)
            },
            JournalStatus::Intent | JournalStatus::Executing | JournalStatus::Unknown => None,
        }
    }
}

/// Bounded occupancy and collection policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalPolicy {
    record_capacity: NonZeroU64,
    byte_capacity: NonZeroU64,
    tombstone_capacity: NonZeroU64,
    gc_batch_limit: NonZeroU64,
    retention: JournalRetention,
}

impl JournalPolicy {
    /// Constructs a finite, nonzero policy.
    #[must_use]
    pub const fn new(
        record_capacity: NonZeroU64,
        byte_capacity: NonZeroU64,
        tombstone_capacity: NonZeroU64,
        gc_batch_limit: NonZeroU64,
        retention: JournalRetention,
    ) -> Self {
        Self {
            record_capacity,
            byte_capacity,
            tombstone_capacity,
            gc_batch_limit,
            retention,
        }
    }

    /// Named finite defaults for a private embedded model.
    ///
    /// # Panics
    /// Panics only if named constants violate their constructor invariants.
    #[must_use]
    pub fn default_policy() -> Self {
        let receipts =
            match RetentionWindow::new(Duration::from_hours(7 * 24), Duration::from_hours(90 * 24))
            {
                Ok(value) => value,
                Err(error) => panic!("named receipt retention bounds are valid: {error:?}"),
            };
        let terminal_failures =
            match RetentionWindow::new(Duration::from_hours(24), Duration::from_hours(30 * 24)) {
                Ok(value) => value,
                Err(error) => panic!("named failure retention bounds are valid: {error:?}"),
            };
        Self::new(
            non_zero(1_024),
            non_zero(4 * 1_024 * 1_024),
            non_zero(4_096),
            non_zero(64),
            JournalRetention::new(receipts, terminal_failures),
        )
    }

    /// Returns whether collection is allowed and how many records may go.
    #[must_use]
    pub const fn collection_batch_limit(&self) -> u64 {
        self.gc_batch_limit.get()
    }

    /// Returns true only when a terminal record is eligible.
    #[must_use]
    pub fn retention_eligible(&self, record: &OperationJournalRecord, now: Timestamp) -> bool {
        let Some(window) = self.retention.window(record) else {
            return false;
        };
        let Some(age) = now.seconds_since(record.terminal_at()) else {
            return false;
        };
        age >= window.maximum.as_secs()
    }

    pub(crate) fn has_admission_room(
        &self,
        occupancy: &crate::policy::Occupancy,
        record_bytes: u64,
    ) -> bool {
        occupancy.records < self.record_capacity.get()
            && occupancy
                .bytes
                .checked_add(record_bytes)
                .is_some_and(|bytes| bytes <= self.byte_capacity.get())
    }

    pub(crate) const fn tombstone_capacity(&self) -> u64 {
        self.tombstone_capacity.get()
    }

    pub(crate) const fn admission_error() -> PackageServiceError {
        PackageServiceError::QuotaExhausted
    }
}

/// Occupancy measured over authoritative journal records and tombstones.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Occupancy {
    records: u64,
    bytes: u64,
    tombstones: u64,
}

impl Occupancy {
    pub(crate) fn add_record(&mut self, bytes: u64) -> PackageServiceResult<()> {
        let records = self
            .records
            .checked_add(1)
            .ok_or(PackageServiceError::OccupancyCorruption)?;
        let bytes_total = self
            .bytes
            .checked_add(bytes)
            .ok_or(PackageServiceError::OccupancyCorruption)?;
        self.records = records;
        self.bytes = bytes_total;
        Ok(())
    }

    pub(crate) fn remove_record(&mut self, bytes: u64) -> PackageServiceResult<()> {
        let records = self
            .records
            .checked_sub(1)
            .ok_or(PackageServiceError::OccupancyCorruption)?;
        let bytes_total = self
            .bytes
            .checked_sub(bytes)
            .ok_or(PackageServiceError::OccupancyCorruption)?;
        self.records = records;
        self.bytes = bytes_total;
        Ok(())
    }

    pub(crate) fn add_tombstone(&mut self) -> PackageServiceResult<()> {
        self.tombstones = self
            .tombstones
            .checked_add(1)
            .ok_or(PackageServiceError::OccupancyCorruption)?;
        Ok(())
    }

    /// Returns current record, byte, and tombstone occupancy.
    #[must_use]
    pub const fn values(&self) -> (u64, u64, u64) {
        (self.records, self.bytes, self.tombstones)
    }
}
