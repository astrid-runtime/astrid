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
//! `wit/store/` so the `wit gc` sweep never prunes it. It is seeded
//! first-writer-wins by [`seed_canonical_contracts_if_absent`] on the
//! first install that vendors contracts, and never overwritten
//! thereafter — so it stays a stable baseline that later installs are
//! compared against.
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

use crate::meta::InstalledCapsule;

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
/// First-writer-wins: the first capsule install on a home defines the
/// baseline later installs are compared against. The canonical is
/// **never overwritten** — a later side-loaded capsule pinning a
/// different snapshot warns (via [`contracts_skew`]) rather than
/// clobbering the reference, so the baseline stays stable.
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
    let canonical = canonical_contracts_path(home);
    if canonical.exists() {
        return Ok(());
    }

    let blob = home.wit_store_dir().join(format!("{pin}.wit"));
    let content = std::fs::read(&blob)
        .with_context(|| format!("failed to read contracts blob {}", blob.display()))?;

    if let Some(parent) = canonical.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    // Atomic temp-and-rename so a concurrent reader never sees a
    // half-written canonical. UUID temp name — sibling tokio tasks in the
    // daemon share a pid and would race on a pid-based name.
    let tmp = canonical.with_file_name(format!(
        "{CONTRACTS_WIT_BASENAME}.tmp.{}",
        uuid::Uuid::new_v4().simple()
    ));
    if let Err(e) = std::fs::write(&tmp, &content) {
        // Clean up the partial temp so a failed write doesn't leak an orphan
        // into wit/ (mirrors the rename-failure path below).
        let _ = std::fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("failed to write canonical temp {}", tmp.display()));
    }
    match std::fs::rename(&tmp, &canonical) {
        Ok(()) => Ok(()),
        // A racing install already created the canonical (rename-over-
        // existing errors on some platforms); first-writer-wins holds.
        // Drop our temp and treat it as done.
        Err(_) if canonical.exists() => {
            let _ = std::fs::remove_file(&tmp);
            Ok(())
        },
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e).with_context(|| format!("failed to rename canonical to {}", canonical.display()))
        },
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
}
