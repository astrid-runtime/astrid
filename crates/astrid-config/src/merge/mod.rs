//! Deep merge of TOML values with restriction enforcement.
//!
//! The merge operates on raw [`toml::Value`] trees rather than deserialized
//! structs. This correctly handles "absent vs default" — a missing key in a
//! TOML table will not override the base layer.

mod deep;
mod enforce;
mod path;
mod restrict;
mod servers;
mod types;

pub use deep::{deep_merge, deep_merge_tracking};
pub use restrict::enforce_restrictions;
pub use types::{ConfigLayer, FieldSources};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod shutdown_budget_tests;
