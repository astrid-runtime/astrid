//! Compatibility fixtures for persisted state shapes we intentionally support.
//!
//! These tests keep old on-disk examples in `e2e/fixtures/compat` so migration
//! coverage does not depend only on inline strings in unit tests.

use std::path::{Path, PathBuf};

use astrid_core::profile::{
    DEFAULT_MAX_CPU_FUEL_PER_SEC, DeviceScope, PrincipalProfile, ProfileError,
};
use astrid_kernel::pair_token::PairTokenStore;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("e2e/fixtures/compat")
        .join(name)
}

#[test]
fn legacy_profile_missing_cpu_fuel_uses_current_default() {
    let profile =
        PrincipalProfile::load_from_path(&fixture("legacy-profile-missing-cpu-fuel.toml"))
            .expect("legacy quota profile fixture loads");

    assert_eq!(profile.quotas.max_memory_bytes, 1_048_576);
    assert_eq!(
        profile.quotas.max_cpu_fuel_per_sec,
        DEFAULT_MAX_CPU_FUEL_PER_SEC
    );
}

#[test]
fn legacy_profile_bare_device_keys_load_as_full_scope() {
    let profile =
        PrincipalProfile::load_from_path(&fixture("legacy-profile-bare-device-keys.toml"))
            .expect("legacy bare-key profile fixture loads");

    assert_eq!(profile.auth.public_keys.len(), 2);
    for device in &profile.auth.public_keys {
        assert_eq!(device.scope, DeviceScope::Full);
    }
}

#[test]
fn future_profile_version_fails_with_controlled_error() {
    let err = PrincipalProfile::load_from_path(&fixture("future-profile-version.toml"))
        .expect_err("future profile fixture must be rejected");

    match err {
        ProfileError::Invalid(msg) => {
            assert!(msg.contains("profile_version"), "unexpected error: {msg}");
        },
        other => panic!("future profile must fail as Invalid, got {other:?}"),
    }
}

#[test]
fn legacy_pair_token_without_scope_loads_as_full_scope() {
    let loaded = PairTokenStore::new(fixture("legacy-pair-token-without-scope.toml"))
        .load()
        .expect("legacy pair-token fixture loads");

    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].principal.as_str(), "compat-user");
    assert_eq!(loaded[0].scope, DeviceScope::Full);
}

#[test]
fn legacy_sha_pair_token_is_invalidated_in_a_working_copy() {
    let dir = tempfile::tempdir().expect("compat tempdir");
    let path = dir.path().join("pair-tokens.toml");
    std::fs::copy(fixture("legacy-sha-pair-token.toml"), &path)
        .expect("copy legacy pair-token fixture");

    let loaded = PairTokenStore::new(path.clone())
        .load()
        .expect("legacy SHA pair-token store migrates");
    assert!(loaded.is_empty());

    let rewritten = std::fs::read_to_string(path).expect("read migrated store");
    assert!(rewritten.contains("schema_version = 1"));
    assert!(!rewritten.contains("[[pair_token]]"));
}
