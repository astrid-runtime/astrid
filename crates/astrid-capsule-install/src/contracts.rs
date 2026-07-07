//! Contracts-skew detection and canonical-contracts retention.
//!
//! Every SDK-built capsule vendors `astrid-contracts.wit` — the shared
//! data-shape records exchanged over the bus — and records its BLAKE3
//! pin in `meta.json`'s `wit_files`. Those contracts carry **zero WIT
//! funcs**, so a capsule pinning a stale (or ahead-of-daemon) snapshot
//! never fails at component link time; it fails silently at runtime the
//! moment a record shape moves. This module surfaces that skew.
//!
//! The "daemon canonical" is the named copy at the top of `wit/`
//! ([`canonical_contracts_path`]), kept out of the content-addressed
//! `wit/store/` so the `wit gc` sweep never prunes it. The **daemon owns
//! it**: at boot, [`refresh_canonical_contracts`] rewrites it from the
//! daemon's own system fleet (the [`install_principal`](crate::paths::install_principal)'s
//! retained contracts), so the baseline always tracks the running daemon —
//! an already-installed fleet gets skew visibility with no install required
//! and no dependence on which capsule happens to install first.
//! [`seed_canonical_contracts_if_absent`] is a first-writer-wins bootstrap
//! fallback for CLI-only flows where no daemon has ever booted; the daemon's
//! boot refresh is authoritative and supersedes it.
//!
//! Everything here is **warn-only**. Side-loading an ahead-of-daemon dev
//! build is legitimate, so skew is a signal, never a failure: install and
//! every read path succeed regardless. When no canonical exists (fresh
//! home, daemon never booted) the checks degrade silently — nothing to
//! compare means no warning and no error.

use std::collections::HashMap;
use std::hash::BuildHasher;
use std::path::{Path, PathBuf};

use anyhow::Context;
use astrid_core::dirs::AstridHome;

use crate::meta::{InstalledCapsule, read_meta};

/// Basename of the shared data-shape contracts WIT file every SDK-built
/// capsule vendors and the daemon links against.
pub const CONTRACTS_WIT_BASENAME: &str = "astrid-contracts.wit";

/// Number of leading hex chars shown for a BLAKE3 pin in human output.
const SHORT_HASH_LEN: usize = 12;

/// The display-friendly prefix of a BLAKE3 hex hash (first 12 chars), used
/// wherever a contracts pin is surfaced to an operator so the three CLI
/// touchpoints render identically. Short strings are returned whole.
#[must_use]
pub fn short_hash(hash: &str) -> &str {
    hash.get(..SHORT_HASH_LEN).unwrap_or(hash)
}

/// Path to the daemon's canonical `astrid-contracts.wit` copy.
///
/// Lives at the top of `wit/` (NOT the content-addressed `wit/store/`),
/// so `wit gc` never mistakes it for a prunable blob. May be absent on a
/// fresh home whose daemon has never installed a capsule.
#[must_use]
pub fn canonical_contracts_path(home: &AstridHome) -> PathBuf {
    home.wit_dir().join(CONTRACTS_WIT_BASENAME)
}

/// The capsule's pinned `astrid-contracts.wit` BLAKE3 hex, if it vendors
/// one.
///
/// `wit_files` keys are paths relative to the capsule's `wit/` source
/// (e.g. `deps/astrid-contracts/astrid-contracts.wit`); we match on the
/// basename so the nested layout doesn't matter. Should two entries ever
/// share the basename, the lexicographically-smallest relative path wins —
/// picking the first match from raw `HashMap` iteration would be
/// nondeterministic and could flip skew classification between runs.
#[must_use]
pub fn contracts_pin<S: BuildHasher>(wit_files: &HashMap<String, String, S>) -> Option<&String> {
    wit_files
        .iter()
        .filter(|(rel, _)| {
            Path::new(rel.as_str()).file_name().and_then(|n| n.to_str())
                == Some(CONTRACTS_WIT_BASENAME)
        })
        .min_by(|a, b| a.0.cmp(b.0))
        .map(|(_, hash)| hash)
}

/// BLAKE3 hex of the daemon canonical `astrid-contracts.wit`, or `None`
/// when the canonical file is absent or unreadable.
///
/// Absent canonical is a normal state (fresh home, daemon never booted) —
/// the caller degrades silently rather than treating it as an error.
#[must_use]
pub fn canonical_contracts_b3(home: &AstridHome) -> Option<String> {
    let bytes = std::fs::read(canonical_contracts_path(home)).ok()?;
    Some(blake3::hash(&bytes).to_hex().to_string())
}

/// Where a capsule's pinned `astrid-contracts.wit` sits relative to the
/// daemon canonical.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractsSkew {
    /// The capsule vendors no `astrid-contracts.wit` — nothing to compare.
    NotPinned,
    /// The capsule pins contracts, but no canonical exists to compare
    /// against (fresh home / daemon never booted).
    NoCanonical {
        /// The capsule's contracts pin.
        pin: String,
    },
    /// The capsule's pin matches the daemon canonical.
    Match {
        /// The (agreeing) contracts pin.
        pin: String,
    },
    /// The capsule's pin differs from the daemon canonical.
    Mismatch {
        /// The capsule's contracts pin.
        pin: String,
        /// The daemon canonical's BLAKE3 hex.
        canonical: String,
    },
}

impl ContractsSkew {
    /// The capsule's contracts pin, if it vendors one.
    #[must_use]
    pub fn pin(&self) -> Option<&str> {
        match self {
            Self::NotPinned => None,
            Self::NoCanonical { pin } | Self::Match { pin } | Self::Mismatch { pin, .. } => {
                Some(pin)
            },
        }
    }

    /// True only when a canonical exists AND the capsule's pin differs
    /// from it. `NotPinned` / `NoCanonical` / `Match` are all false.
    #[must_use]
    pub fn is_mismatch(&self) -> bool {
        matches!(self, Self::Mismatch { .. })
    }
}

/// Compare a capsule's `wit_files` pins against the daemon canonical.
#[must_use]
pub fn contracts_skew<S: BuildHasher>(
    home: &AstridHome,
    wit_files: &HashMap<String, String, S>,
) -> ContractsSkew {
    let Some(pin) = contracts_pin(wit_files) else {
        return ContractsSkew::NotPinned;
    };
    match canonical_contracts_b3(home) {
        None => ContractsSkew::NoCanonical { pin: pin.clone() },
        Some(canonical) if canonical == *pin => ContractsSkew::Match { pin: pin.clone() },
        Some(canonical) => ContractsSkew::Mismatch {
            pin: pin.clone(),
            canonical,
        },
    }
}

/// Names of installed capsules whose `astrid-contracts.wit` pin differs
/// from the daemon canonical, sorted and de-duplicated.
///
/// Returns empty when the canonical is absent (nothing to compare) — the
/// `astrid capsule list` summary warning is suppressed in that case.
#[must_use]
pub fn mismatching_contracts(home: &AstridHome, capsules: &[InstalledCapsule]) -> Vec<String> {
    let Some(canonical) = canonical_contracts_b3(home) else {
        return Vec::new();
    };
    let mut names: Vec<String> = capsules
        .iter()
        .filter_map(|c| {
            let pin = contracts_pin(&c.meta.as_ref()?.wit_files)?;
            (*pin != canonical).then(|| c.name.clone())
        })
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Seed the daemon canonical `astrid-contracts.wit` from a freshly
/// installed capsule's pinned blob, but only when the canonical is absent.
///
/// This is a **bootstrap fallback** for CLI-only flows where no daemon has
/// ever booted: it gives skew checks a baseline on the very first install.
/// When a daemon runs it is authoritative — [`refresh_canonical_contracts`]
/// rewrites the canonical from the daemon's own system fleet at every boot,
/// superseding whatever this seeded. Seeding is first-writer-wins and never
/// overwrites, so a running daemon's baseline is never clobbered by a later
/// side-loaded install (that install warns via [`contracts_skew`] instead).
///
/// Best-effort: the caller logs any failure and proceeds; retention of
/// the canonical must never break an otherwise-successful install.
pub fn seed_canonical_contracts_if_absent<S: BuildHasher>(
    home: &AstridHome,
    wit_files: &HashMap<String, String, S>,
) -> anyhow::Result<()> {
    let Some(pin) = contracts_pin(wit_files) else {
        return Ok(());
    };
    // Defense in depth: `pin` builds the `wit/store/<pin>.wit` lookup path
    // below. The install caller passes a freshly content-addressed pin, but
    // validate the BLAKE3-hex shape at the boundary so no caller can traverse
    // out of the store (mirrors `daemon_fleet_contracts_pin`).
    if !is_blake3_pin(pin) {
        anyhow::bail!("refusing to seed canonical from a non-content-address contracts pin");
    }

    let canonical = canonical_contracts_path(home);
    if canonical.exists() {
        return Ok(());
    }

    let blob = home.wit_store_dir().join(format!("{pin}.wit"));
    let content = std::fs::read(&blob)
        .with_context(|| format!("failed to read contracts blob {}", blob.display()))?;

    // Create-if-absent (atomic), not write-or-replace: the `exists()` fast path
    // above is a cheap common-case skip, but two installs racing that check
    // must not clobber each other's canonical. `create_canonical_if_absent`
    // returning `Ok(false)` means a racing installer won — first-writer-wins
    // holds either way, so both outcomes are `Ok`.
    create_canonical_if_absent(&canonical, &content)
        .map(|_created| ())
        .with_context(|| format!("failed to write canonical {}", canonical.display()))
}

/// Rewrite the daemon canonical `astrid-contracts.wit` from the daemon's
/// own system fleet — the daemon-authoritative baseline refresh run once at
/// boot (issue #1165).
///
/// Source: [`daemon_fleet_contracts_pin`] dereferenced from the retained
/// content-addressed store (`wit/store/<pin>.wit`) — the same bytes the
/// installer wrote when it provisioned that fleet's per-principal
/// `home://wit/` copies. The canonical is taken from the store, never from a
/// per-principal `home/<principal>/wit/astrid-contracts.wit` copy: that
/// mirror is last-writer-wins across all of a principal's installs, so
/// sourcing from it would reintroduce the install-order dependence this
/// refresh exists to remove.
///
/// Refresh semantics — daemon-authoritative:
/// - canonical absent -> write it;
/// - present but differing bytes -> overwrite (a fleet/daemon upgrade
///   legitimately moves the baseline; skew is measured versus the RUNNING
///   daemon);
/// - byte-identical -> no-op (the file's mtime is left untouched);
/// - no retained system-fleet contracts (fresh home, or only pre-retention
///   installs) -> no-op `Ok(())`.
///
/// Best-effort: the caller (daemon boot) logs any error and continues — a
/// canonical write failure only degrades warn-only skew reporting, it must
/// never break boot.
pub fn refresh_canonical_contracts(home: &AstridHome) -> anyhow::Result<()> {
    let Some(pin) = daemon_fleet_contracts_pin(home) else {
        return Ok(());
    };
    let blob = home.wit_store_dir().join(format!("{pin}.wit"));
    let content = std::fs::read(&blob)
        .with_context(|| format!("failed to read contracts blob {}", blob.display()))?;

    let canonical = canonical_contracts_path(home);
    // Identical -> no-op: don't churn the mtime (or race a concurrent reader)
    // rewriting the same bytes.
    if std::fs::read(&canonical).is_ok_and(|existing| existing == content) {
        return Ok(());
    }

    write_canonical_atomic(&canonical, &content)
        .with_context(|| format!("failed to write canonical {}", canonical.display()))
}

/// True when `pin` is a well-formed BLAKE3 hex digest (exactly 64 lowercase
/// hex chars) — the shape every real contracts pin has, since pins are
/// `blake3::hash(..).to_hex()` outputs. Because pins are read back from
/// untrusted `meta.json`, any other value (one containing `/`, `\0`, `.`, …)
/// is malformed and must never reach a `wit/store/<pin>.wit` path join.
fn is_blake3_pin(pin: &str) -> bool {
    pin.len() == 64 && pin.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The contracts pin that the plurality of the daemon's own system fleet
/// agrees on, or `None` when that fleet vendors no retained contracts.
///
/// "System fleet" = the capsules installed under the daemon's own
/// [`install_principal`](crate::paths::install_principal) (the default /
/// system principal the daemon runs as). Only pins whose blob is retained in
/// the content-addressed store (`wit/store/<pin>.wit`) are eligible — a
/// pre-retention install left no bytes to write the canonical from. The
/// plurality (not last-writer, not first-install) is what makes the boot
/// baseline order-independent: a lone side-loaded capsule on a different pin
/// cannot flip the baseline away from the majority fleet. Ties break to the
/// lexicographically-smallest pin so the result is deterministic across runs.
///
/// Reads only the injected `home` — never the process environment or a
/// workspace `.astrid/` (unlike [`scan_installed_capsules`](crate::scan_installed_capsules)) —
/// so it is safe on the fail-closed daemon boot path.
fn daemon_fleet_contracts_pin(home: &AstridHome) -> Option<String> {
    let principal = crate::paths::install_principal();
    let capsules_dir = home.principal_home(&principal).capsules_dir();
    let store = home.wit_store_dir();

    let mut counts: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    // A missing dir (fresh home / fleet never installed) is the normal no-op
    // path -> `None`. Per-entry errors below are surfaced (debug) and skipped
    // rather than silently dropped, so one unreadable entry can't abort the
    // baseline scan.
    for entry in std::fs::read_dir(&capsules_dir).ok()? {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                tracing::debug!(
                    dir = %capsules_dir.display(),
                    error = %e,
                    "skipping unreadable entry during contracts baseline scan"
                );
                continue;
            },
        };
        if !entry.file_type().is_ok_and(|ft| ft.is_dir()) {
            continue;
        }
        let Some(meta) = read_meta(&entry.path()) else {
            continue;
        };
        let Some(pin) = contracts_pin(&meta.wit_files) else {
            continue;
        };
        // `pin` is read back from untrusted on-disk `meta.json`. A genuine
        // contracts pin is a BLAKE3 hex digest; reject anything else — notably
        // a path-traversal sequence like `../../../../etc/passwd` — BEFORE it
        // is used to build the `wit/store/<pin>.wit` lookup path below, so a
        // tampered `meta.json` can't dereference a file outside the store into
        // the canonical.
        if !is_blake3_pin(pin) {
            tracing::warn!(
                capsule_dir = %entry.path().display(),
                "ignoring non-content-address contracts pin in meta.json (possible tampering)"
            );
            continue;
        }
        // Only a retained blob can source the canonical write.
        if store.join(format!("{pin}.wit")).is_file() {
            let count = counts.entry(pin.clone()).or_insert(0);
            *count = count.saturating_add(1);
        }
    }

    // Plurality. `BTreeMap` yields pins in ascending order and we replace only
    // on a STRICTLY greater count, so a count tie keeps the smallest pin.
    let mut best: Option<(String, usize)> = None;
    for (pin, n) in counts {
        if best.as_ref().is_none_or(|(_, best_n)| n > *best_n) {
            best = Some((pin, n));
        }
    }
    best.map(|(pin, _)| pin)
}

/// Write `content` to a UUID-named sibling temp of `canonical`, creating
/// parent dirs, and return the temp path for the caller to place or drop.
///
/// A fully-written temp is the shared prerequisite for both placement
/// primitives below (overwrite via rename, create-if-absent via hard link).
/// The temp is cleaned up on a write failure so nothing leaks into `wit/`.
/// Sibling tokio tasks in the daemon share a pid, so the temp name is
/// UUID-based rather than pid-based to avoid a collision race.
fn write_canonical_temp(canonical: &Path, content: &[u8]) -> std::io::Result<PathBuf> {
    if let Some(parent) = canonical.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = canonical.with_file_name(format!(
        "{CONTRACTS_WIT_BASENAME}.tmp.{}",
        uuid::Uuid::new_v4().simple()
    ));
    if let Err(e) = std::fs::write(&tmp, content) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(tmp)
}

/// Atomically **replace** the canonical with `content` (overwrite). The rename
/// swaps the destination atomically on unix, so a concurrent reader never
/// observes a half-written or absent file. Used by the daemon-authoritative
/// boot refresh, which legitimately moves the baseline.
fn write_canonical_atomic(canonical: &Path, content: &[u8]) -> std::io::Result<()> {
    let tmp = write_canonical_temp(canonical, content)?;
    if let Err(e) = std::fs::rename(&tmp, canonical) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// Atomically **create** the canonical with `content` only if it does not
/// already exist (first-writer-wins); returns `Ok(false)` when it already
/// existed.
///
/// `hard_link` is the create-if-absent primitive: it fails with
/// `AlreadyExists` when the destination is present, so a second installer
/// racing the same seed cannot clobber the first writer — unlike `rename`,
/// which silently replaces the destination on unix. The temp is always
/// dropped afterwards (the link, if made, is the durable copy).
fn create_canonical_if_absent(canonical: &Path, content: &[u8]) -> std::io::Result<bool> {
    let tmp = write_canonical_temp(canonical, content)?;
    let linked = std::fs::hard_link(&tmp, canonical);
    let _ = std::fs::remove_file(&tmp);
    match linked {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meta::{CapsuleLocation, CapsuleMeta};

    fn wit_files(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    fn write_canonical(home: &AstridHome, bytes: &[u8]) -> String {
        std::fs::create_dir_all(home.wit_dir()).unwrap();
        std::fs::write(canonical_contracts_path(home), bytes).unwrap();
        blake3::hash(bytes).to_hex().to_string()
    }

    fn installed(name: &str, wit: &[(&str, &str)]) -> InstalledCapsule {
        InstalledCapsule {
            name: name.to_string(),
            meta: Some(CapsuleMeta {
                wit_files: wit_files(wit),
                ..Default::default()
            }),
            location: CapsuleLocation::User,
        }
    }

    /// Write `bytes` into the content-addressed WIT store and return its pin.
    fn store_contracts_blob(home: &AstridHome, bytes: &[u8]) -> String {
        let hash = blake3::hash(bytes).to_hex().to_string();
        std::fs::create_dir_all(home.wit_store_dir()).unwrap();
        std::fs::write(home.wit_store_dir().join(format!("{hash}.wit")), bytes).unwrap();
        hash
    }

    /// Install a fake capsule into the daemon's own system fleet (the
    /// install-principal's `capsules/`), recording `pin` as its
    /// `astrid-contracts.wit` hash in `meta.json`.
    fn install_fleet_capsule(home: &AstridHome, name: &str, pin: &str) {
        let principal = crate::paths::install_principal();
        let dir = home.principal_home(&principal).capsules_dir().join(name);
        std::fs::create_dir_all(&dir).unwrap();
        let meta = CapsuleMeta {
            wit_files: wit_files(&[("deps/astrid-contracts/astrid-contracts.wit", pin)]),
            ..Default::default()
        };
        crate::meta::write_meta(&dir, &meta).unwrap();
    }

    #[test]
    fn pin_matches_on_basename_regardless_of_nesting() {
        let files = wit_files(&[
            ("deps/astrid-contracts/astrid-contracts.wit", "abc123"),
            ("capsule.wit", "deadbeef"),
        ]);
        assert_eq!(contracts_pin(&files).map(String::as_str), Some("abc123"));
    }

    #[test]
    fn pin_absent_when_no_contracts_vendored() {
        let files = wit_files(&[("capsule.wit", "deadbeef")]);
        assert!(contracts_pin(&files).is_none());
    }

    #[test]
    fn pin_is_deterministic_under_basename_collision() {
        // Two entries share the astrid-contracts.wit basename under
        // different dirs. The lexicographically-smallest relative path must
        // win, so the result never depends on HashMap iteration order.
        let files = wit_files(&[
            ("deps/astrid-contracts/astrid-contracts.wit", "bbb"),
            ("astrid-contracts.wit", "aaa"),
        ]);
        // "astrid-contracts.wit" < "deps/..." lexicographically -> "aaa".
        assert_eq!(contracts_pin(&files).map(String::as_str), Some("aaa"));
    }

    #[test]
    fn skew_not_pinned_when_capsule_has_no_contracts() {
        let tmp = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(tmp.path());
        let files = wit_files(&[("capsule.wit", "deadbeef")]);
        assert_eq!(contracts_skew(&home, &files), ContractsSkew::NotPinned);
    }

    #[test]
    fn skew_degrades_silently_when_canonical_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(tmp.path());
        let files = wit_files(&[("astrid-contracts.wit", "abc123")]);
        let skew = contracts_skew(&home, &files);
        assert!(!skew.is_mismatch(), "absent canonical must not flag skew");
        assert!(matches!(skew, ContractsSkew::NoCanonical { .. }));
    }

    #[test]
    fn skew_matches_when_pin_equals_canonical() {
        let tmp = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(tmp.path());
        let canon = write_canonical(&home, b"package astrid:contracts;\n");
        let files = wit_files(&[("deps/astrid-contracts/astrid-contracts.wit", &canon)]);
        let skew = contracts_skew(&home, &files);
        assert!(!skew.is_mismatch());
        assert!(matches!(skew, ContractsSkew::Match { .. }));
    }

    #[test]
    fn skew_flags_mismatch_and_not_matching_ones() {
        let tmp = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(tmp.path());
        let canon = write_canonical(&home, b"package astrid:contracts;\n");

        let matching = wit_files(&[("astrid-contracts.wit", &canon)]);
        assert!(!contracts_skew(&home, &matching).is_mismatch());

        let drifted = wit_files(&[("astrid-contracts.wit", "0000000000feedface")]);
        let skew = contracts_skew(&home, &drifted);
        assert!(skew.is_mismatch(), "differing pin must flag skew");
        match skew {
            ContractsSkew::Mismatch { pin, canonical } => {
                assert_eq!(pin, "0000000000feedface");
                assert_eq!(canonical, canon);
            },
            other => panic!("expected Mismatch, got {other:?}"),
        }
    }

    #[test]
    fn mismatching_contracts_names_only_drifted_capsules() {
        let tmp = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(tmp.path());
        let canon = write_canonical(&home, b"package astrid:contracts;\n");

        let capsules = vec![
            installed("aligned-a", &[("astrid-contracts.wit", &canon)]),
            installed("drifted", &[("astrid-contracts.wit", "1111beefcafe2222")]),
            installed("aligned-b", &[("astrid-contracts.wit", &canon)]),
            installed("no-contracts", &[("capsule.wit", "9999")]),
        ];

        assert_eq!(
            mismatching_contracts(&home, &capsules),
            vec!["drifted".to_string()],
        );
    }

    #[test]
    fn mismatching_contracts_empty_when_canonical_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(tmp.path());
        let capsules = vec![installed("anything", &[("astrid-contracts.wit", "abc")])];
        assert!(mismatching_contracts(&home, &capsules).is_empty());
    }

    #[test]
    fn seed_writes_canonical_first_writer_wins_and_never_overwrites() {
        let tmp = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(tmp.path());

        // Store the first capsule's contracts blob, then seed.
        let first = b"package astrid:contracts;\ninterface v1 {}\n";
        let first_hash = blake3::hash(first).to_hex().to_string();
        std::fs::create_dir_all(home.wit_store_dir()).unwrap();
        std::fs::write(
            home.wit_store_dir().join(format!("{first_hash}.wit")),
            first,
        )
        .unwrap();
        let files_a = wit_files(&[("astrid-contracts.wit", &first_hash)]);
        seed_canonical_contracts_if_absent(&home, &files_a).unwrap();

        let canonical = canonical_contracts_path(&home);
        assert_eq!(std::fs::read(&canonical).unwrap(), first);

        // A second capsule with different contracts must NOT overwrite it.
        let second = b"package astrid:contracts;\ninterface v2 {}\n";
        let second_hash = blake3::hash(second).to_hex().to_string();
        std::fs::write(
            home.wit_store_dir().join(format!("{second_hash}.wit")),
            second,
        )
        .unwrap();
        let files_b = wit_files(&[("astrid-contracts.wit", &second_hash)]);
        seed_canonical_contracts_if_absent(&home, &files_b).unwrap();

        assert_eq!(
            std::fs::read(&canonical).unwrap(),
            first,
            "canonical must stay first-writer-wins"
        );
        // ...and the second capsule now reads as skewed against it.
        assert!(contracts_skew(&home, &files_b).is_mismatch());
    }

    #[test]
    fn seed_is_noop_when_capsule_vendors_no_contracts() {
        let tmp = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(tmp.path());
        let files = wit_files(&[("capsule.wit", "deadbeef")]);
        seed_canonical_contracts_if_absent(&home, &files).unwrap();
        assert!(!canonical_contracts_path(&home).exists());
    }

    #[test]
    fn seed_rejects_non_content_address_pin() {
        // Defense-in-depth: a pin that isn't a BLAKE3 digest must be refused at
        // the boundary before it can build a store lookup path, even if the
        // traversal target exists.
        let tmp = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(tmp.path());
        std::fs::create_dir_all(home.wit_store_dir()).unwrap();
        std::fs::write(home.wit_dir().join("evil.wit"), b"stolen contents\n").unwrap();
        let files = wit_files(&[("astrid-contracts.wit", "../evil")]);
        assert!(seed_canonical_contracts_if_absent(&home, &files).is_err());
        assert!(!canonical_contracts_path(&home).exists());
    }

    #[test]
    fn create_canonical_if_absent_is_first_writer_wins_under_race() {
        // Directly exercise the atomic create-if-absent primitive that backs
        // the seed path: an already-present canonical must NOT be clobbered even
        // when the caller reaches the write. The `exists()` fast-path in
        // `seed_canonical_contracts_if_absent` is only an optimization; this
        // closes the check-then-write race window on unix, where `rename` would
        // otherwise silently replace the destination.
        let tmp = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(tmp.path());
        let first = b"package astrid:contracts;\ninterface v1 {}\n";
        write_canonical(&home, first);

        let canonical = canonical_contracts_path(&home);
        let created = create_canonical_if_absent(&canonical, b"second writer bytes\n").unwrap();
        assert!(!created, "an existing canonical must report not-created");
        assert_eq!(
            std::fs::read(&canonical).unwrap(),
            first,
            "first-writer-wins: the existing canonical must be untouched"
        );
    }

    #[test]
    fn boot_refresh_seeds_canonical_when_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(tmp.path());
        let bytes = b"package astrid:contracts;\ninterface v1 {}\n";
        let pin = store_contracts_blob(&home, bytes);
        install_fleet_capsule(&home, "alpha", &pin);

        assert!(!canonical_contracts_path(&home).exists());
        refresh_canonical_contracts(&home).unwrap();
        assert_eq!(
            std::fs::read(canonical_contracts_path(&home)).unwrap(),
            bytes,
            "boot must seed the canonical from the daemon's own fleet"
        );
    }

    #[test]
    fn boot_refresh_overwrites_stale_canonical_to_fleet_majority() {
        // The existing-fleet upgrade / inverted-baseline scenario from #1165:
        // a stale canonical (e.g. an earlier first-writer-wins seed from a lone
        // side-load) must be corrected to the pin the fleet MAJORITY agrees on,
        // regardless of install order.
        let tmp = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(tmp.path());

        let healthy = b"package astrid:contracts;\ninterface v2 {}\n";
        let sideload = b"package astrid:contracts;\ninterface dev {}\n";
        let healthy_pin = store_contracts_blob(&home, healthy);
        let sideload_pin = store_contracts_blob(&home, sideload);

        // Canonical currently points at the lone side-load pin (the bug: the
        // one drifted capsule defined the baseline, inverting the noise).
        let canon = write_canonical(&home, sideload);
        assert_eq!(canon, sideload_pin);

        // Fleet: three healthy capsules on `healthy_pin`, one side-load on
        // `sideload_pin`. Majority = healthy.
        install_fleet_capsule(&home, "reg-a", &healthy_pin);
        install_fleet_capsule(&home, "reg-b", &healthy_pin);
        install_fleet_capsule(&home, "reg-c", &healthy_pin);
        install_fleet_capsule(&home, "dev-x", &sideload_pin);

        refresh_canonical_contracts(&home).unwrap();

        assert_eq!(
            std::fs::read(canonical_contracts_path(&home)).unwrap(),
            healthy,
            "boot must move the baseline to the fleet majority"
        );
        // ...and now the healthy capsules read clean while the side-load warns.
        let healthy_files = wit_files(&[("astrid-contracts.wit", &healthy_pin)]);
        assert!(!contracts_skew(&home, &healthy_files).is_mismatch());
        let sideload_files = wit_files(&[("astrid-contracts.wit", &sideload_pin)]);
        assert!(contracts_skew(&home, &sideload_files).is_mismatch());
    }

    #[test]
    fn boot_refresh_tie_breaks_deterministically_to_smallest_pin() {
        // Two pins tie on count; the lexicographically-smallest pin wins so the
        // baseline is stable across runs (independent of directory read order).
        let tmp = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(tmp.path());
        let a = b"aaaa contracts\n";
        let b = b"bbbb contracts\n";
        let a_pin = store_contracts_blob(&home, a);
        let b_pin = store_contracts_blob(&home, b);
        let (small_bytes, small_pin): (&[u8], &String) = if a_pin < b_pin {
            (a, &a_pin)
        } else {
            (b, &b_pin)
        };
        install_fleet_capsule(&home, "one", &a_pin);
        install_fleet_capsule(&home, "two", &b_pin);

        refresh_canonical_contracts(&home).unwrap();

        assert_eq!(
            std::fs::read(canonical_contracts_path(&home))
                .unwrap()
                .as_slice(),
            small_bytes,
            "tie must resolve to the lexicographically-smallest pin"
        );
        assert_eq!(
            canonical_contracts_b3(&home).as_deref(),
            Some(small_pin.as_str())
        );
    }

    #[test]
    fn boot_refresh_is_noop_when_identical() {
        let tmp = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(tmp.path());
        let bytes = b"package astrid:contracts;\ninterface v1 {}\n";
        let pin = store_contracts_blob(&home, bytes);
        install_fleet_capsule(&home, "alpha", &pin);

        // Canonical already equals the fleet pin.
        write_canonical(&home, bytes);
        let canonical = canonical_contracts_path(&home);
        let mtime_before = std::fs::metadata(&canonical).unwrap().modified().unwrap();

        // Sleep past the filesystem mtime resolution so a rewrite WOULD be
        // observable; the identical-check must skip the write and leave the
        // mtime untouched.
        std::thread::sleep(std::time::Duration::from_millis(25));
        refresh_canonical_contracts(&home).unwrap();

        assert_eq!(std::fs::read(&canonical).unwrap(), bytes);
        assert_eq!(
            std::fs::metadata(&canonical).unwrap().modified().unwrap(),
            mtime_before,
            "identical bytes must not rewrite the canonical"
        );
    }

    #[test]
    fn boot_refresh_noop_when_fleet_has_no_retained_contracts() {
        let tmp = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(tmp.path());
        // Fleet capsule pins a valid (well-formed) contracts hash, but the blob
        // was never retained (a pre-store install) — nothing to source from.
        let unretained = blake3::hash(b"unretained pin").to_hex().to_string();
        install_fleet_capsule(&home, "legacy", &unretained);
        refresh_canonical_contracts(&home).unwrap();
        assert!(
            !canonical_contracts_path(&home).exists(),
            "no retained fleet contracts => no canonical written"
        );
    }

    #[test]
    fn boot_refresh_rejects_path_traversal_pin_even_if_target_exists() {
        // `pin` comes from untrusted `meta.json`. A tampered pin with a
        // traversal sequence must be rejected before it is dereferenced, even
        // when the traversal resolves to a real file: otherwise the daemon
        // would read an arbitrary `.wit` outside the store and write it into
        // the canonical.
        let tmp = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(tmp.path());
        std::fs::create_dir_all(home.wit_store_dir()).unwrap();
        // Plant the traversal target: store/../evil.wit resolves to wit/evil.wit.
        std::fs::write(home.wit_dir().join("evil.wit"), b"stolen contents\n").unwrap();
        assert!(
            home.wit_store_dir().join("../evil.wit").is_file(),
            "precondition: the traversal path resolves to the planted file"
        );

        install_fleet_capsule(&home, "evil-cap", "../evil");
        refresh_canonical_contracts(&home).unwrap();

        assert!(
            !canonical_contracts_path(&home).exists(),
            "a path-traversal pin must be rejected, never dereferenced into the canonical"
        );
    }

    #[test]
    fn boot_refresh_noop_on_fresh_home() {
        let tmp = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(tmp.path());
        // No fleet at all: the install-principal's capsules dir doesn't exist.
        refresh_canonical_contracts(&home).unwrap();
        assert!(!canonical_contracts_path(&home).exists());
    }

    #[test]
    fn boot_refresh_surfaces_write_failure_without_panicking() {
        // A canonical that cannot be written (here: its path is already a
        // directory, so the atomic rename can't replace it) must surface as an
        // `Err`. The daemon boot swallows that Err (warn + continue), so boot
        // never fails — this asserts the function returns Err, not panics.
        let tmp = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(tmp.path());
        let bytes = b"package astrid:contracts;\ninterface v1 {}\n";
        let pin = store_contracts_blob(&home, bytes);
        install_fleet_capsule(&home, "alpha", &pin);

        std::fs::create_dir_all(canonical_contracts_path(&home)).unwrap();

        assert!(
            refresh_canonical_contracts(&home).is_err(),
            "an unwritable canonical must surface as Err"
        );
    }
}
