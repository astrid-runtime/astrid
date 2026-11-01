//! Immutable hosted extent-index pages and their publication checkpoint.

mod assembly;
mod builder;
pub(super) mod checkpoint;
pub(super) mod codec;
pub(super) mod publication;
pub(super) mod records;
pub(super) mod reference;
pub(super) mod traversal;
mod update;

pub(super) const INDEX_PAGE_REGION: &str = "system/volume-extent-index";
// Fixed wire framing, not an aggregate capacity or operator tuning knob.
pub(super) const INDEX_PAGE_RECORD_BYTES: u64 = (super::RECORD_FIXED_BYTES as u64)
    .strict_add(INDEX_PAGE_REGION.len() as u64)
    .strict_add(codec::PAGE_BYTES as u64);

#[cfg(test)]
mod integration_tests;

#[cfg(test)]
mod test_support;
