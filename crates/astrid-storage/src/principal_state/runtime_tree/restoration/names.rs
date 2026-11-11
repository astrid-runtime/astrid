//! Reject raw target aliases before intent or host namespace mutation.

#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
use std::collections::HashMap;
#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
use std::ops::ControlFlow;
#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
use std::path::{Path, PathBuf};

use super::{AstridHome, ContentEntry, ContentName, StorageResult, tree_error};
use crate::content::{
    ProjectionNamePolicy, RawProjectionCollision, find_raw_projection_collision,
    find_raw_protected_authority_collision, raw_projection_spelling_is_canonical,
};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::content::{visit_raw_projection_collisions, visit_raw_protected_authority_collisions};
#[cfg(windows)]
use crate::content::{
    visit_raw_projection_collisions_with_key, visit_raw_protected_authority_collisions_with_key,
};
use crate::error::StorageError;

/// Exclusion spellings re-seeded into projection admission.
///
/// Byte-exact `is_excluded` drops canonical spellings from the catalog walk.
/// Seeds reintroduce those authorities so caseless / NT keys still reject
/// impostors before the first host mutation. Opaque `ContentName` values remain
/// pack-readable.
///
/// `ACTIVE_PROJECTION_NAME` is the durable catalog receipt path; a host file may
/// or may not exist yet. Seeding it prevents restore from materializing any
/// alias of that reserved relative path.
///
/// Seeds use **terminal authority only** via
/// [`visit_raw_protected_authority_collisions`]: `run/system.sock` does not claim
/// ancestor `run/`, so `run/capsules/**` stays admissible under caseless keys.
/// Bare `run/` is never seeded. Entry↔entry directory aliases stay on a separate
/// full-prefix walk that runs first so seeds cannot shadow peer collisions.
fn protected_sentinel_names(home: &AstridHome) -> Vec<ContentName> {
    let mut names = Vec::new();
    let mut push = |name: &str| {
        names.push(ContentName::new(name).expect("protected exclusion sentinel"));
    };

    push(super::super::CANONICAL_VOLUME);
    push(super::super::MIGRATING_VOLUME);
    push(super::super::LEGACY_VAR_VOLUME);
    for name in super::super::HOST_EXECUTABLES {
        push(name);
    }

    push(super::super::SOCKET_PATH);
    push(super::super::ACTIVE_PROJECTION_NAME);
    push(super::super::VOLUME_PATH_PREFIX);
    push(super::super::DIRECTORY_STORE_PREFIX);
    for name in super::super::TRANSACTION_STAGING_PATHS {
        push(name);
    }

    for file_name in [
        AstridHome::TOKEN_FILE_NAME,
        AstridHome::READY_FILE_NAME,
        AstridHome::PID_FILE_NAME,
    ] {
        push(&format!("{}/{file_name}", super::super::TRANSIENT_PREFIX));
    }
    let deferred_path = home.deferred_db_path();
    let deferred_leaf = deferred_path
        .file_name()
        .and_then(|name| name.to_str())
        .expect("deferred_db_path file name");
    push(&format!(
        "{}/{deferred_leaf}",
        super::super::TRANSIENT_PREFIX
    ));

    names
}

/// Mirror the excluded transient subtree using the target's actual name rules.
///
/// The capsules exception is resolved in its own parent: a caseless root does
/// not imply that `run` itself is caseless. Queries reuse the admission cache
/// and only occur for candidate aliases of the transient prefix.
#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
fn reject_excluded_run_aliases_on_caseless_host<K>(
    home: &AstridHome,
    entries: &[ContentEntry],
    mut key_for: impl FnMut(&str) -> K,
    label: &str,
) -> StorageResult<()>
where
    K: PartialEq,
{
    let run_key = key_for(super::super::TRANSIENT_PREFIX);
    let capsules_key = key_for("capsules");
    let mut cache = HashMap::<PathBuf, bool>::new();
    for entry in entries {
        let name = entry.name().as_str();
        let mut parts = name.split('/');
        let Some(first) = parts.next() else { continue };
        if key_for(first) != run_key {
            continue;
        }
        if first != super::super::TRANSIENT_PREFIX
            && directory_is_case_sensitive_cached(home.root(), first, &mut cache)?
        {
            // A distinct root entry cannot reach the excluded transient tree.
            continue;
        }
        let capsules_allowed = match parts.next() {
            Some("capsules") => true,
            Some(second) if key_for(second) == capsules_key => {
                let end = first.len().strict_add(1).strict_add(second.len());
                !directory_is_case_sensitive_cached(home.root(), &name[..end], &mut cache)?
            },
            _ => false,
        };
        if !capsules_allowed {
            return Err(tree_error(
                home.root(),
                format!(
                    "projection namespace collision between excluded run path and {name} under {label}"
                ),
            ));
        }
    }
    Ok(())
}

fn noncanonical_spelling_message(name: &str) -> String {
    #[cfg(windows)]
    {
        format!("projection name is not canonical host spelling (contains '\\' or ':'): {name}")
    }
    #[cfg(not(windows))]
    {
        format!("projection name is not canonical host spelling (contains '\\'): {name}")
    }
}

pub(super) fn validate(home: &AstridHome, entries: &[ContentEntry]) -> StorageResult<()> {
    for entry in entries {
        let name = entry.name().as_str();
        if !raw_projection_spelling_is_canonical(name) {
            return Err(tree_error(home.root(), noncanonical_spelling_message(name)));
        }
    }

    let sentinels = protected_sentinel_names(home);

    // Exact structural: peers first (full prefixes), then protected authority.
    let exact = ProjectionNamePolicy::posix_exact_v1();
    if let Some(collision) =
        find_raw_projection_collision(exact, entries.iter().map(ContentEntry::name))
    {
        return Err(collision_error(home, exact, &collision));
    }
    if let Some(collision) = find_raw_protected_authority_collision(
        exact,
        &sentinels,
        entries.iter().map(ContentEntry::name),
    ) {
        return Err(collision_error(home, exact, &collision));
    }

    // Host-aware run/**∖capsules exclusion aliases (independent of peer/sentinel
    // folded collisions so a lone RUN/principals impostor cannot skip the check).
    cfg_select! {
        windows => {
            use astrid_core::platform_fs::name_semantics::windows_nt_utf16_upcase_key;
            reject_excluded_run_aliases_on_caseless_host(
                home,
                entries,
                windows_nt_utf16_upcase_key,
                "windows-nt-utf16-upcase",
            )?;
        },
        any(target_os = "linux", target_os = "macos") => {
            let policy = ProjectionNamePolicy::unicode_canonical_caseless_v1();
            reject_excluded_run_aliases_on_caseless_host(
                home,
                entries,
                |value| crate::content::projection_name_comparison_key(policy, value),
                &policy.identifier(),
            )?;
        },
        _ => {},
    }

    let selected = cfg_select! {
        windows => windows_policy(home, &sentinels, entries)?,
        target_os = "macos" => macos_policy(home, &sentinels, entries)?,
        target_os = "linux" => linux_policy(home, &sentinels, entries)?,
        _ => Some(ProjectionNamePolicy::unicode_canonical_caseless_v1()),
    };
    let Some(policy) = selected else {
        return Ok(());
    };
    if let Some(collision) =
        find_raw_projection_collision(policy, entries.iter().map(ContentEntry::name))
    {
        return Err(collision_error(home, policy, &collision));
    }
    if let Some(collision) = find_raw_protected_authority_collision(
        policy,
        &sentinels,
        entries.iter().map(ContentEntry::name),
    ) {
        return Err(collision_error(home, policy, &collision));
    }
    Ok(())
}

fn collision_error(
    home: &AstridHome,
    policy: ProjectionNamePolicy,
    collision: &RawProjectionCollision<'_>,
) -> StorageError {
    collision_error_under(home, &policy.identifier(), collision)
}

fn collision_error_under(
    home: &AstridHome,
    under: &str,
    collision: &RawProjectionCollision<'_>,
) -> StorageError {
    tree_error(
        home.root(),
        format!(
            "projection namespace collision between {} and {} under {}",
            collision.first.as_str(),
            collision.second.as_str(),
            under
        ),
    )
}

#[cfg(target_os = "macos")]
fn macos_policy(
    home: &AstridHome,
    sentinels: &[ContentName],
    entries: &[ContentEntry],
) -> StorageResult<Option<ProjectionNamePolicy>> {
    let folded = ProjectionNamePolicy::unicode_canonical_caseless_v1();
    if !platform_has_folded_collision(folded, sentinels, entries) {
        return Ok(None);
    }
    reject_host_unrepresentable_collisions(
        home,
        sentinels,
        entries,
        folded,
        ProjectionNamePolicy::unicode_canonical_v1(),
    )?;
    Ok(Some(ProjectionNamePolicy::unicode_canonical_v1()))
}

#[cfg(windows)]
fn windows_policy(
    home: &AstridHome,
    sentinels: &[ContentName],
    entries: &[ContentEntry],
) -> StorageResult<Option<ProjectionNamePolicy>> {
    use astrid_core::platform_fs::name_semantics::windows_nt_utf16_upcase_key;

    // Admission uses the process NT ordinal UTF-16 upcase table
    // (`RtlUpcaseUnicodeChar`). Unicode default casefold both misses host
    // merges (Latin I vs dotless ı) and invents non-host merges (ß vs SS), so
    // it is not the Windows alias detector. On-disk NTFS `$UpCase` on older or
    // custom volumes can still differ from this user-mode table.
    const WINDOWS_NT_UPCASE: &str = "windows-nt-utf16-upcase";
    if !platform_has_key_collision(sentinels, entries, windows_nt_utf16_upcase_key) {
        return Ok(None);
    }
    reject_host_unrepresentable_collisions_with_key(
        home,
        sentinels,
        entries,
        windows_nt_utf16_upcase_key,
        WINDOWS_NT_UPCASE,
        ProjectionNamePolicy::posix_exact_v1(),
    )?;
    Ok(Some(ProjectionNamePolicy::posix_exact_v1()))
}

#[cfg(target_os = "linux")]
fn linux_policy(
    home: &AstridHome,
    sentinels: &[ContentName],
    entries: &[ContentEntry],
) -> StorageResult<Option<ProjectionNamePolicy>> {
    let folded = ProjectionNamePolicy::unicode_canonical_caseless_v1();
    // Fast path: no peer or protected-authority aliases under the conservative
    // table means byte-exact is safe without filesystem I/O.
    if !platform_has_folded_collision(folded, sentinels, entries) {
        return Ok(Some(ProjectionNamePolicy::posix_exact_v1()));
    }
    reject_host_unrepresentable_collisions(
        home,
        sentinels,
        entries,
        folded,
        ProjectionNamePolicy::posix_exact_v1(),
    )?;
    Ok(Some(ProjectionNamePolicy::posix_exact_v1()))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn platform_has_folded_collision(
    folded: ProjectionNamePolicy,
    sentinels: &[ContentName],
    entries: &[ContentEntry],
) -> bool {
    find_raw_projection_collision(folded, entries.iter().map(ContentEntry::name)).is_some()
        || find_raw_protected_authority_collision(
            folded,
            sentinels,
            entries.iter().map(ContentEntry::name),
        )
        .is_some()
}

#[cfg(windows)]
fn platform_has_key_collision<K: Ord>(
    sentinels: &[ContentName],
    entries: &[ContentEntry],
    mut key_for: impl FnMut(&str) -> K,
) -> bool {
    use std::ops::ControlFlow;

    let mut found = false;
    crate::content::visit_raw_projection_collisions_with_key(
        entries.iter().map(ContentEntry::name),
        &mut key_for,
        |_| {
            found = true;
            ControlFlow::Break(())
        },
    );
    if found {
        return true;
    }
    visit_raw_protected_authority_collisions_with_key(
        sentinels,
        entries.iter().map(ContentEntry::name),
        &mut key_for,
        |_| {
            found = true;
            ControlFlow::Break(())
        },
    );
    found
}

/// Reject every folded alias the host would actually merge.
///
/// Peer entry walk runs first (full prefixes). Protected-authority walk runs
/// second (seed terminals only vs entry full paths). Same literal prefix with a
/// role conflict always rejects. Distinct prefixes that share a comparison key
/// query the nearest existing parent of each colliding prefix. Queries are
/// cached for this admission pass only. Query errors fail closed.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn reject_host_unrepresentable_collisions(
    home: &AstridHome,
    sentinels: &[ContentName],
    entries: &[ContentEntry],
    folded: ProjectionNamePolicy,
    exact: ProjectionNamePolicy,
) -> StorageResult<()> {
    let label = folded.identifier();
    let mut cache = HashMap::<PathBuf, bool>::new();
    let mut failure = None::<StorageError>;
    // Peers first — do not let seed presence shadow entry↔entry collisions.
    visit_raw_projection_collisions(
        folded,
        entries.iter().map(ContentEntry::name),
        |collision| {
            consider_host_collision(home, &collision, &label, exact, &mut cache, &mut failure)
        },
    );
    if failure.is_none() {
        visit_raw_protected_authority_collisions(
            folded,
            sentinels,
            entries.iter().map(ContentEntry::name),
            |collision| {
                consider_host_collision(home, &collision, &label, exact, &mut cache, &mut failure)
            },
        );
    }
    match failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

#[cfg(windows)]
fn reject_host_unrepresentable_collisions_with_key<K>(
    home: &AstridHome,
    sentinels: &[ContentName],
    entries: &[ContentEntry],
    mut key_for: impl FnMut(&str) -> K,
    folded_label: &str,
    exact: ProjectionNamePolicy,
) -> StorageResult<()>
where
    K: Ord,
{
    use std::ops::ControlFlow;

    let mut cache = HashMap::<PathBuf, bool>::new();
    let mut failure = None::<StorageError>;
    crate::content::visit_raw_projection_collisions_with_key(
        entries.iter().map(ContentEntry::name),
        &mut key_for,
        |collision| {
            consider_host_collision(
                home,
                &collision,
                folded_label,
                exact,
                &mut cache,
                &mut failure,
            )
        },
    );
    if failure.is_none() {
        visit_raw_protected_authority_collisions_with_key(
            sentinels,
            entries.iter().map(ContentEntry::name),
            &mut key_for,
            |collision| {
                consider_host_collision(
                    home,
                    &collision,
                    folded_label,
                    exact,
                    &mut cache,
                    &mut failure,
                )
            },
        );
    }
    match failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
fn consider_host_collision(
    home: &AstridHome,
    collision: &RawProjectionCollision<'_>,
    folded_label: &str,
    exact: ProjectionNamePolicy,
    cache: &mut HashMap<PathBuf, bool>,
    failure: &mut Option<StorageError>,
) -> ControlFlow<()> {
    if failure.is_some() {
        return ControlFlow::Break(());
    }
    if collision.first_prefix == collision.second_prefix {
        // File/directory conflict on one spelling: always unrepresentable.
        *failure = Some(collision_error(home, exact, collision));
        return ControlFlow::Break(());
    }
    for prefix in [collision.first_prefix, collision.second_prefix] {
        match directory_is_case_sensitive_cached(home.root(), prefix, cache) {
            Ok(true) => {},
            Ok(false) => {
                *failure = Some(collision_error_under(home, folded_label, collision));
                return ControlFlow::Break(());
            },
            Err(error) => {
                *failure = Some(error);
                return ControlFlow::Break(());
            },
        }
    }
    ControlFlow::Continue(())
}

#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
fn directory_is_case_sensitive_cached(
    root: &Path,
    prefix: &str,
    cache: &mut HashMap<PathBuf, bool>,
) -> StorageResult<bool> {
    let parent = nearest_existing_parent(root, prefix).map_err(|error| {
        tree_error(
            root,
            format!("query target namespace parent for {prefix}: {error}"),
        )
    })?;
    if let Some(hit) = cache.get(&parent) {
        return Ok(*hit);
    }
    let case_sensitive =
        astrid_core::platform_fs::directory_is_case_sensitive(&parent).map_err(|error| {
            tree_error(
                &parent,
                format!("query target namespace for {prefix}: {error}"),
            )
        })?;
    cache.insert(parent, case_sensitive);
    Ok(case_sensitive)
}

/// Walk from the colliding prefix's immediate parent up to `root`, returning
/// the nearest existing real directory. New children inherit Linux
/// `FS_CASEFOLD_FL` from that ancestor. Symlinks and open failures other than
/// `NotFound` fail closed.
#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
fn nearest_existing_parent(root: &Path, prefix: &str) -> std::io::Result<PathBuf> {
    let relative = prefix.strip_suffix('/').unwrap_or(prefix);
    let mut candidate = if relative.is_empty() {
        root.to_path_buf()
    } else {
        root.join(relative).parent().unwrap_or(root).to_path_buf()
    };
    loop {
        if !candidate.starts_with(root) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "projection parent escaped runtime root",
            ));
        }
        match std::fs::symlink_metadata(&candidate) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "projection parent is a symbolic link",
                    ));
                }
                if metadata.is_dir() {
                    return Ok(candidate);
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotADirectory,
                    "projection parent exists and is not a directory",
                ));
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if candidate == root {
                    return Err(error);
                }
                candidate = candidate
                    .parent()
                    .filter(|parent| parent.starts_with(root))
                    .unwrap_or(root)
                    .to_path_buf();
            },
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::{
        ProjectionNamePolicy, find_raw_projection_collision, find_raw_protected_authority_collision,
    };
    use astrid_core::dirs::AstridHome;

    fn sentinel_set(home: &AstridHome) -> std::collections::BTreeSet<String> {
        protected_sentinel_names(home)
            .into_iter()
            .map(|name| name.as_str().to_owned())
            .collect()
    }

    #[test]
    fn protected_sentinels_reuse_constants_without_bare_run_prefix() {
        let root = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(root.path().join("home"));
        home.ensure().unwrap();
        let names = sentinel_set(&home);
        assert!(names.contains(super::super::super::SOCKET_PATH));
        assert!(names.contains(super::super::super::ACTIVE_PROJECTION_NAME));
        assert!(names.contains(super::super::super::VOLUME_PATH_PREFIX));
        assert!(names.contains(super::super::super::DIRECTORY_STORE_PREFIX));
        assert!(names.contains(super::super::super::LEGACY_VAR_VOLUME));
        assert!(!names.contains("run"));
        assert!(!names.contains("run/"));
        assert!(!names.iter().any(|name| name.starts_with("run/capsules")));
    }

    #[test]
    fn authority_seed_allows_unrelated_ancestor_siblings() {
        let root = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(root.path().join("home"));
        home.ensure().unwrap();
        let sentinels = protected_sentinel_names(&home);
        let folded = ProjectionNamePolicy::windows_caseless_v1();

        let capsule = ContentName::new("RUN/capsules/example.wasm").unwrap();
        let unrelated = ContentName::new("VAR/unrelated-file").unwrap();
        assert!(find_raw_protected_authority_collision(folded, &sentinels, [&capsule]).is_none());
        assert!(find_raw_protected_authority_collision(folded, &sentinels, [&unrelated]).is_none());

        let sock = ContentName::new("RUN/SYSTEM.SOCK").unwrap();
        let store = ContentName::new("VAR/PRINCIPAL-STORE/x").unwrap();
        let exact_sock = ContentName::new("run/system.sock").unwrap();
        assert!(find_raw_protected_authority_collision(folded, &sentinels, [&sock]).is_some());
        assert!(find_raw_protected_authority_collision(folded, &sentinels, [&store]).is_some());
        assert!(
            find_raw_protected_authority_collision(folded, &sentinels, [&exact_sock]).is_some()
        );
    }

    #[test]
    fn old_peer_only_guard_misses_receipt_alias_authority_seed_detects() {
        let impostor = ContentName::new("RUN/.ACTIVE-PROJECTION-V1.JSON").unwrap();
        let folded = ProjectionNamePolicy::windows_caseless_v1();
        assert!(find_raw_projection_collision(folded, [&impostor]).is_none());

        let root = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(root.path().join("home"));
        home.ensure().unwrap();
        let sentinels = protected_sentinel_names(&home);
        assert!(find_raw_protected_authority_collision(folded, &sentinels, [&impostor]).is_some());
    }
}
