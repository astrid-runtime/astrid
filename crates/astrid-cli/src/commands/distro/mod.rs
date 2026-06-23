//! Distro manifest parsing and lockfile management.
//!
//! A distro manifest (`Distro.toml`) declares a curated bundle of capsules.
//! The lockfile (`Distro.lock`) pins exact resolved versions and BLAKE3 hashes
//! for reproducible installs.

pub(crate) mod lock;
pub(crate) mod manifest;
pub(crate) mod seal;
pub(crate) mod shuttle;
pub(crate) mod sign;
pub(crate) mod validate;
