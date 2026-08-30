use crate::context::Operation;
use crate::error::{PackageServiceError, PackageServiceResult};
use crate::journal::PackageSlotRecord;
use crate::state::CanonicalInstalledState;
use std::num::NonZeroU64;

pub(super) fn next_generation(state: &CanonicalInstalledState) -> PackageServiceResult<NonZeroU64> {
    next_generation_value(state.generation_value())
}

pub(super) fn next_generation_from_high_watermark(
    high_watermark: Option<NonZeroU64>,
    operation: Operation,
) -> PackageServiceResult<NonZeroU64> {
    if operation == Operation::Install {
        return match high_watermark {
            None => first_state_generation(),
            Some(high_watermark) => next_generation_value(high_watermark),
        };
    }
    let high_watermark = high_watermark.ok_or(PackageServiceError::OccupancyCorruption)?;
    next_generation_value(high_watermark)
}

pub(super) fn next_transition_generation(
    slot_record: Option<&PackageSlotRecord>,
    operation: Operation,
) -> PackageServiceResult<NonZeroU64> {
    next_generation_from_high_watermark(
        slot_record.and_then(PackageSlotRecord::generation_high_watermark),
        operation,
    )
}

pub(super) fn next_generation_value(generation: NonZeroU64) -> PackageServiceResult<NonZeroU64> {
    let value = generation
        .get()
        .checked_add(1)
        .ok_or(PackageServiceError::GenerationOverflow)?;
    NonZeroU64::try_from(value).map_err(PackageServiceError::from)
}

fn first_state_generation() -> PackageServiceResult<NonZeroU64> {
    NonZeroU64::new(1).ok_or(PackageServiceError::InvalidValue("package generation"))
}
