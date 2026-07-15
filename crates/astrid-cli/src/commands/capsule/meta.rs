//! Re-exports of the persisted capsule install metadata types.
//!
//! The actual definitions live in [`astrid_capsule_install::meta`] —
//! both the CLI and the kernel-side install handler share them. This
//! module exists so the existing `super::capsule::meta::*` imports
//! sprinkled across the CLI keep working after the extraction.

// `CapsuleLocation` is referenced only from `#[cfg(test)]` blocks in
// `deps.rs` / `remove.rs`; `write_meta` is exported for parity but
// not used by any current CLI consumer. Suppress the resulting
// unused-import warning on non-test builds.
#[allow(unused_imports)]
pub(crate) use astrid_capsule_install::meta::{
    CapsuleLocation, CapsuleMeta, InstalledCapsule, read_meta, scan_installed_capsules,
    scan_installed_capsules_in_home, scan_installed_capsules_in_home_for,
    scan_installed_capsules_in_home_for_with_layout, scan_installed_capsules_in_home_with_layout,
    scan_installed_capsules_with_layout, write_meta,
};
