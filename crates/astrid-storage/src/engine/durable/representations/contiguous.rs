//! Capability-pinned filesystem helpers for physical representation metadata.

mod namespace;

pub(in crate::engine::durable::representations) use namespace::{
    configure_no_follow, open_component, sync_directory, validate_opened_regular,
};
pub(in crate::engine::durable) use namespace::{open_representation_root, open_store_root};
