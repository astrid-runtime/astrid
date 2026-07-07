//! Capsule install machinery shared between the CLI and the kernel.
//!
//! The CLI's `astrid capsule install` flow and the kernel's
//! `KernelRequest::InstallCapsule` admin handler both land here once
//! they've resolved a source down to "a directory on disk that
//! contains a Capsule.toml" or "a .capsule archive on disk".
//!
//! What this crate owns:
//!
//! * File layout — copying the capsule tree into its target dir under
//!   `~/.astrid/<principal>/capsules/<id>/`, with rollback on failure.
//! * Content-addressing — `wasm` binaries go to `~/.astrid/bin/`,
//!   `wit` blobs go to `~/.astrid/wit/store/`, both keyed by BLAKE3.
//! * Contracts retention/skew — seeding the daemon canonical
//!   `astrid-contracts.wit` and comparing capsule pins against it
//!   (warn-only; see [`contracts`]).
//! * Topic baking — JSON Schema / WIT-record schemas inlined into
//!   `meta.json` at install time.
//! * Lifecycle hooks — running the capsule's WASM `install` / `upgrade`
//!   export in a one-shot wasmtime instance.
//! * Archive unpacking — `.capsule` tar.gz with traversal/symlink
//!   defense.
//!
//! What this crate does **not** do:
//!
//! * Interactive env prompts. The library never reads stdin or writes
//!   to stderr; it returns an [`InstallOutput`] flag saying "this
//!   capsule has unset `[env]` fields, here's the env file path". The
//!   CLI prompts on that signal; the kernel-side handler ignores it
//!   (the dashboard collects env via a separate gateway route).
//! * Source resolution. `gh:`, `github:`, build-from-
//!   source, .capsule download — all of that lives in the CLI. By the
//!   time we get called the source is a path on disk.
//! * Import-conflict reporting. Both [`validate_imports`] and
//!   [`check_export_conflicts`] return diagnostic structs the caller
//!   can render. The library does not print.
//! * Distro lock regeneration. That's a CLI concern post-install.
//!
//! The split exists so the kernel can install capsules without
//! linking the CLI binary into the daemon, while keeping a single
//! implementation of "what an install actually does" — important
//! because most of the security posture (path-traversal defense in
//! archive unpack, atomic meta writes, lifecycle rollback) lives in
//! the file/copy/lifecycle layer.

#![deny(unsafe_code)]
#![deny(clippy::all)]
#![deny(unreachable_pub)]
// The install machinery is anyhow-based: every `Result<_, anyhow::Error>`
// already carries a precise root cause. A separate `# Errors` doc
// listing would just paraphrase what `with_context(...)` already
// records. Match the posture astrid-gateway uses for the same reason.
#![allow(clippy::missing_errors_doc)]
// Same logic for `# Panics` — install-path expects carry their
// rationale inline.
#![allow(clippy::missing_panics_doc)]
// `must_use_candidate` on pure-data accessors is noise here; the
// caller of `validate_imports` / `check_export_conflicts` always
// consumes the returned Vec.
#![allow(clippy::must_use_candidate)]

pub mod archive;
pub mod contracts;
pub mod copy;
pub mod github_source;
pub mod lifecycle;
pub mod local;
pub mod manifest_check;
pub mod meta;
pub mod paths;
pub mod principal_introspection;
pub mod wasm;
pub mod wit;

pub use archive::{unpack_and_install, unpack_and_install_for_principal};
pub use contracts::{
    CONTRACTS_WIT_BASENAME, ContractsSkew, canonical_contracts_b3, canonical_contracts_path,
    contracts_pin, contracts_skew, mismatching_contracts, seed_canonical_contracts_if_absent,
    short_hash,
};
pub use copy::copy_capsule_dir;
pub use local::{
    InstallOptions, InstallOutput, InstallPhase, install_from_local_path,
    install_from_local_path_for_principal,
};
pub use manifest_check::{ExportConflict, MissingImport, check_export_conflicts, validate_imports};
pub use meta::{
    CapsuleLocation, CapsuleMeta, InstalledCapsule, read_meta, scan_installed_capsules,
    scan_installed_capsules_in_home_for, write_meta,
};
pub use paths::{
    resolve_env_path, resolve_env_path_for, resolve_target_dir, resolve_target_dir_for,
    restore_env_from_backup, restore_env_from_backup_for,
};
pub use principal_introspection::materialize_principal_introspection;
pub use wit::{content_address_wit, materialize_wit_mirror};
