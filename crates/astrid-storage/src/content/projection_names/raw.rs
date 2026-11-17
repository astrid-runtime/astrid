//! Admit raw host paths without silently applying the escaped-name planner.

use std::collections::BTreeMap;
use std::ops::ControlFlow;

use super::{ContentName, ProjectionNamePolicy, planner::comparison_key};

/// File versus directory role of one projection spelling prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RawProjectionRole {
    File,
    Directory,
}

/// One raw projection alias discovered under a comparison key function.
///
/// `first_prefix` / `second_prefix` are the concrete spellings that collided
/// (directory prefixes or terminal paths). Callers that consult the filesystem
/// must query the parent of these prefixes, not the parent of the full source
/// name, so a case-insensitive ancestor cannot be masked by a sensitive leaf.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RawProjectionCollision<'a> {
    pub first: &'a ContentName,
    pub first_prefix: &'a str,
    pub second: &'a ContentName,
    pub second_prefix: &'a str,
}

/// Projection spelling must match confinement's slash-separated form.
///
/// `ContentName` stays an opaque durable catalog key (backslash and `:` remain
/// pack-readable). Raw restoration rejects non-canonical host spellings before
/// the writer so `Path::new(raw)` cannot diverge from
/// `normalize_relative_path` / confinement: `\\` is a separator alias on some
/// hosts, and on Windows `:` introduces ADS / stream syntax
/// (`file::$DATA` ≡ `file`).
#[must_use]
pub(crate) fn raw_projection_spelling_is_canonical(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.contains(&b'\\') {
        return false;
    }
    // Windows host projection only: keep ContentName able to store `:`.
    #[cfg(windows)]
    if bytes.contains(&b':') {
        return false;
    }
    true
}

/// Visit each raw projection alias under `policy`, stopping on [`ControlFlow::Break`].
///
/// Prefixes are borrowed from the already-canonical source spelling. Callers
/// must reject non-canonical host spellings before invoking this walk.
pub(crate) fn visit_raw_projection_collisions<'a>(
    policy: ProjectionNamePolicy,
    names: impl IntoIterator<Item = &'a ContentName>,
    visit: impl FnMut(RawProjectionCollision<'a>) -> ControlFlow<()>,
) {
    visit_raw_projection_collisions_with_key(names, |value| comparison_key(policy, value), visit);
}

fn raw_terminal_spelling(raw: &str) -> &str {
    raw.strip_suffix('/').unwrap_or(raw)
}

fn raw_full_spellings(raw: &str) -> impl Iterator<Item = (&str, RawProjectionRole)> {
    let directories = raw
        .match_indices('/')
        .map(|(end, _)| (&raw[..end], RawProjectionRole::Directory));
    let terminal = (!raw.ends_with('/')).then_some((raw, RawProjectionRole::File));
    directories.chain(terminal)
}

/// Visit each raw projection alias using an arbitrary prefix key function.
///
/// `K: Ord` lets callers supply Windows NT UTF-16 upcase keys (`Vec<u16>`) or
/// the planner's `Vec<u8>` policy keys without changing the walk or collision
/// record shape.
pub(crate) fn visit_raw_projection_collisions_with_key<'a, K>(
    names: impl IntoIterator<Item = &'a ContentName>,
    mut key_for: impl FnMut(&str) -> K,
    mut visit: impl FnMut(RawProjectionCollision<'a>) -> ControlFlow<()>,
) where
    K: Ord,
{
    struct Spelling<'a> {
        source: &'a ContentName,
        prefix: &'a str,
        role: RawProjectionRole,
    }

    let mut seen: BTreeMap<K, Spelling<'a>> = BTreeMap::new();
    for source in names {
        for (prefix, role) in raw_full_spellings(source.as_str()) {
            let key = key_for(prefix);
            match seen.entry(key) {
                std::collections::btree_map::Entry::Vacant(slot) => {
                    slot.insert(Spelling {
                        source,
                        prefix,
                        role,
                    });
                },
                std::collections::btree_map::Entry::Occupied(slot) => {
                    let previous = slot.get();
                    if previous.prefix != prefix || previous.role != role {
                        let collision = RawProjectionCollision {
                            first: previous.source,
                            first_prefix: previous.prefix,
                            second: source,
                            second_prefix: prefix,
                        };
                        if visit(collision).is_break() {
                            return;
                        }
                    }
                },
            }
        }
    }
}

/// Compare protected sentinel terminals to full entry paths.
///
/// Builds a map of **only** the ~O(1) reserved terminals (no ancestor dirs, no
/// entry insertions). Each entry prefix is a map lookup: any hit is a conflict,
/// including identical leaf spelling. Peer entry aliases remain on the separate
/// full walk that runs first so seeds cannot shadow them.
pub(crate) fn visit_raw_protected_authority_collisions_with_key<'a, K>(
    seeds: impl IntoIterator<Item = &'a ContentName>,
    entries: impl IntoIterator<Item = &'a ContentName>,
    mut key_for: impl FnMut(&str) -> K,
    mut visit: impl FnMut(RawProjectionCollision<'a>) -> ControlFlow<()>,
) where
    K: Ord,
{
    // Sentinel terminals only. Reserved authorities do not need seed↔seed checks.
    let mut sentinels: BTreeMap<K, (&'a ContentName, &'a str)> = BTreeMap::new();
    for seed in seeds {
        let prefix = raw_terminal_spelling(seed.as_str());
        sentinels.entry(key_for(prefix)).or_insert((seed, prefix));
    }

    for entry in entries {
        for (prefix, _role) in raw_full_spellings(entry.as_str()) {
            let key = key_for(prefix);
            let Some(&(seed, seed_prefix)) = sentinels.get(&key) else {
                continue;
            };
            let collision = RawProjectionCollision {
                first: seed,
                first_prefix: seed_prefix,
                second: entry,
                second_prefix: prefix,
            };
            if visit(collision).is_break() {
                return;
            }
        }
    }
}

pub(crate) fn visit_raw_protected_authority_collisions<'a>(
    policy: ProjectionNamePolicy,
    seeds: impl IntoIterator<Item = &'a ContentName>,
    entries: impl IntoIterator<Item = &'a ContentName>,
    visit: impl FnMut(RawProjectionCollision<'a>) -> ControlFlow<()>,
) {
    visit_raw_protected_authority_collisions_with_key(
        seeds,
        entries,
        |value| comparison_key(policy, value),
        visit,
    );
}

pub(crate) fn find_raw_protected_authority_collision<'a>(
    policy: ProjectionNamePolicy,
    seeds: impl IntoIterator<Item = &'a ContentName>,
    entries: impl IntoIterator<Item = &'a ContentName>,
) -> Option<RawProjectionCollision<'a>> {
    let mut found = None;
    visit_raw_protected_authority_collisions(policy, seeds, entries, |collision| {
        found = Some(collision);
        ControlFlow::Break(())
    });
    found
}

/// Find the first namespace alias, including directory prefixes and file/dir conflicts.
pub(crate) fn find_raw_projection_collision<'a>(
    policy: ProjectionNamePolicy,
    names: impl IntoIterator<Item = &'a ContentName>,
) -> Option<RawProjectionCollision<'a>> {
    let mut found = None;
    visit_raw_projection_collisions(policy, names, |collision| {
        found = Some(collision);
        ControlFlow::Break(())
    });
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collision(policy: ProjectionNamePolicy, paths: &[&str]) -> bool {
        let names = paths
            .iter()
            .map(|name| ContentName::new(*name).unwrap())
            .collect::<Vec<_>>();
        find_raw_projection_collision(policy, &names).is_some()
    }

    fn has_key_collision<K: Ord>(paths: &[&str], key_for: impl FnMut(&str) -> K) -> bool {
        let names = paths
            .iter()
            .map(|name| ContentName::new(*name).unwrap())
            .collect::<Vec<_>>();
        let mut found = false;
        visit_raw_projection_collisions_with_key(&names, key_for, |_| {
            found = true;
            ControlFlow::Break(())
        });
        found
    }

    #[test]
    fn raw_names_reuse_target_equivalence_without_remapping() {
        let exact = ProjectionNamePolicy::posix_exact_v1();
        let folded = ProjectionNamePolicy::windows_caseless_v1();
        assert!(!collision(exact, &["config.toml", "CONFIG.TOML"]));
        assert!(collision(folded, &["config.toml", "CONFIG.TOML"]));
        assert!(collision(folded, &["profiles/first", "PROFILES/second"]));
        assert!(!collision(folded, &["profiles/first", "profiles/second"]));
        assert!(collision(exact, &["profiles", "profiles/second"]));
        assert!(collision(exact, &["profiles", "profiles/"]));
        assert!(!collision(exact, &["profiles/", "profiles/second"]));
        let canonical = ProjectionNamePolicy::unicode_canonical_v1();
        assert!(collision(
            canonical,
            &["caf\u{e9}/first", "cafe\u{301}/second"]
        ));
        assert!(!collision(
            exact,
            &["caf\u{e9}/first", "cafe\u{301}/second"]
        ));
    }

    #[test]
    fn directory_prefix_collision_preserves_prefix_identity() {
        let folded = ProjectionNamePolicy::windows_caseless_v1();
        let names = [
            ContentName::new("profiles/a").unwrap(),
            ContentName::new("PROFILES/b").unwrap(),
        ];
        let collision = find_raw_projection_collision(folded, &names).unwrap();
        assert_eq!(collision.first_prefix, "profiles");
        assert_eq!(collision.second_prefix, "PROFILES");
    }

    #[test]
    fn noncanonical_backslash_spelling_is_an_admission_gate() {
        assert!(raw_projection_spelling_is_canonical("dir/file"));
        assert!(!raw_projection_spelling_is_canonical("dir\\file"));
    }

    #[cfg(windows)]
    #[test]
    fn noncanonical_colon_spelling_is_an_admission_gate_on_windows() {
        assert!(raw_projection_spelling_is_canonical("dir/file"));
        assert!(!raw_projection_spelling_is_canonical("dir/file::$DATA"));
        assert!(!raw_projection_spelling_is_canonical("dir/file:stream"));
        // Opaque catalog construction still accepts `:`; only host admission gates it.
        assert!(ContentName::new("dir/file::$DATA").is_ok());
        assert!(ContentName::new("dir/file:stream").is_ok());
    }

    #[cfg(not(windows))]
    #[test]
    fn colon_remains_pack_readable_outside_windows_admission_gate() {
        assert!(raw_projection_spelling_is_canonical("dir/file::$DATA"));
        assert!(ContentName::new("dir/file::$DATA").is_ok());
    }

    #[test]
    fn custom_utf16_key_controls_collisions_without_policy_variant() {
        // Test the generic visitor's caller-selected key, not a simulated NT
        // table. Native Windows tests verify the real OS mapping separately.
        let ascii_key = |value: &str| {
            value
                .to_ascii_uppercase()
                .encode_utf16()
                .collect::<Vec<_>>()
        };
        assert!(has_key_collision(&["File", "FILE"], ascii_key));
        assert!(!has_key_collision(&["\u{00df}.toml", "SS.toml"], ascii_key));
        assert!(collision(
            ProjectionNamePolicy::windows_caseless_v1(),
            &["\u{00df}.toml", "SS.toml"]
        ));
    }

    #[test]
    fn protected_authority_ignores_ancestor_directory_aliases() {
        let seed_sock = ContentName::new("run/system.sock").unwrap();
        let seed_legacy = ContentName::new("var/astrid.volume").unwrap();
        let seed_store = ContentName::new("var/principal-store").unwrap();
        let seeds = [&seed_sock, &seed_legacy, &seed_store];

        let capsule = ContentName::new("RUN/capsules/example.wasm").unwrap();
        let unrelated = ContentName::new("VAR/unrelated-file").unwrap();
        let sock_alias = ContentName::new("RUN/SYSTEM.SOCK").unwrap();
        let store_child = ContentName::new("VAR/PRINCIPAL-STORE/x").unwrap();

        let folded = ProjectionNamePolicy::windows_caseless_v1();
        assert!(
            find_raw_protected_authority_collision(folded, seeds, [&capsule]).is_none(),
            "RUN/capsules must not collide with run/system.sock authority"
        );
        assert!(
            find_raw_protected_authority_collision(folded, seeds, [&unrelated]).is_none(),
            "VAR/unrelated must not collide with var/astrid.volume authority"
        );
        assert!(
            find_raw_protected_authority_collision(folded, seeds, [&sock_alias]).is_some(),
            "RUN/SYSTEM.SOCK must collide with run/system.sock authority"
        );
        assert!(
            find_raw_protected_authority_collision(folded, seeds, [&store_child]).is_some(),
            "VAR/PRINCIPAL-STORE/x must collide with var/principal-store authority"
        );
        let exact_sock = ContentName::new("run/system.sock").unwrap();
        assert!(
            find_raw_protected_authority_collision(folded, seeds, [&exact_sock]).is_some(),
            "exact protected leaf spelling must conflict with its seed authority"
        );

        // Full peer walk among entries still catches directory aliases.
        let peers = [
            ContentName::new("profiles/a").unwrap(),
            ContentName::new("PROFILES/b").unwrap(),
        ];
        assert!(find_raw_projection_collision(folded, peers.iter()).is_some());
    }
}
