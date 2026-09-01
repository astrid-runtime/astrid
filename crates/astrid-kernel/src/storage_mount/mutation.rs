//! Admission-scoped mutation reference counting.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use super::StorageMountLeaseState;

pub(super) struct InFlightMutation {
    count: Arc<StorageMountLeaseState>,
}

impl InFlightMutation {
    pub(super) fn begin(state: &Arc<StorageMountLeaseState>) -> Self {
        state.in_flight_mutations.fetch_add(1, Ordering::AcqRel);
        Self {
            count: Arc::clone(state),
        }
    }
}

impl Drop for InFlightMutation {
    fn drop(&mut self) {
        self.count
            .in_flight_mutations
            .fetch_sub(1, Ordering::AcqRel);
    }
}
