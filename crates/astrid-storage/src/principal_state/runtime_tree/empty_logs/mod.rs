//! Omit only authenticated, wholly empty canonical principal-log groups.
//!
//! This changes host materialization, never catalog membership or history.
//! Callers hold bootstrap singleton custody before admitting guest writers.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use astrid_core::dirs::RetirementEntryKind;

use super::restoration::PreparedRestoration;
use super::{AstridHome, RuntimePrincipalStore, StateOwner, restoration, retirement, tree_error};
use crate::StorageResult;
use crate::content::{ContentEntry, ContentName};
use crate::engine::PrincipalProjectionEngine;
use crate::principal_state::NativePrincipalContentStore;
use crate::storage_model::RootState;

const PREFIX: &str = "log/principals/";

#[derive(Default)]
struct Group<'a> {
    rejected: bool,
    entries: Vec<&'a ContentEntry>,
}

pub(super) struct EmptyLogs {
    selected: Vec<PathBuf>,
    files: BTreeSet<ContentName>,
    directories: BTreeSet<PathBuf>,
}

impl EmptyLogs {
    /// Names must have passed restoration's complete collision/name validation.
    pub(super) fn authenticate(
        home: &AstridHome,
        content: &NativePrincipalContentStore,
        entries: &[ContentEntry],
    ) -> StorageResult<Self> {
        let mut groups = BTreeMap::<&str, Group<'_>>::new();
        for entry in entries {
            let Some((uid, remainder)) = group_name(entry.name().as_str()) else {
                continue;
            };
            let group = groups.entry(uid).or_default();
            if entry.logical_bytes() != 0 || !canonical_log(remainder) {
                group.rejected = true;
            }
            group.entries.push(entry);
        }
        let mut result = Self {
            selected: Vec::new(),
            files: BTreeSet::new(),
            directories: BTreeSet::new(),
        };
        let mut verified = BTreeSet::new();
        for (uid, group) in groups {
            if group.rejected || group.entries.is_empty() {
                continue;
            }
            let scope = PathBuf::from(format!("{PREFIX}{uid}"));
            for entry in group.entries {
                // Empty files share canonical identities; verify each immutable
                // descriptor once within this captured, quiescent inventory.
                if verified.insert(entry.file()) {
                    authenticate_empty(home, content, entry)?;
                }
                let path = Path::new(entry.name().as_str());
                for parent in path.ancestors().skip(1) {
                    if !parent.starts_with(&scope) {
                        break;
                    }
                    result.directories.insert(parent.to_path_buf());
                }
                result.files.insert(entry.name().clone());
            }
            result.selected.push(scope);
        }
        Ok(result)
    }

    fn authorize(&self, relative: &Path, kind: RetirementEntryKind) -> std::io::Result<()> {
        let admitted = match kind {
            RetirementEntryKind::File => {
                #[cfg(windows)]
                let name = relative.to_str().map(super::normalize_relative_path);
                #[cfg(not(windows))]
                let name = relative.to_str().map(str::to_owned);
                name.and_then(|name| ContentName::new(name).ok())
                    .is_some_and(|name| self.files.contains(&name))
            },
            RetirementEntryKind::Directory => self.directories.contains(relative),
        };
        if admitted {
            Ok(())
        } else {
            Err(std::io::Error::other(format!(
                "empty-log cleanup contains unauthenticated {kind:?}: {}",
                relative.display()
            )))
        }
    }

    pub(super) fn omits(&self, entry: &ContentEntry) -> bool {
        self.files.contains(entry.name())
    }

    /// Publish durable recovery authority before any selected host unlink.
    /// A partial failure retains the complete RETIRING inventory for retry.
    pub(super) fn retire<'a>(
        &self,
        home: &'a AstridHome,
        store: &'a RuntimePrincipalStore,
        entries: &[ContentEntry],
        expected: RootState,
        prepared: &mut Option<PreparedRestoration<'a>>,
    ) -> StorageResult<()> {
        if self.selected.is_empty() {
            return Ok(());
        }
        require_root(home, store, expected)?;
        // Refresh even an existing restoration intent through an exact-root
        // CAS. This binds classification to the complete inventory published
        // here; its staging scope is preserved for interrupted recovery.
        *prepared = Some(restoration::record_inventory_intent(
            home, store, entries, expected,
        )?);
        let expected = current_root(home, store)?;
        let captured = retirement::prepare_empty_projection(home, store, &self.selected)?;
        require_root(home, store, expected)?;
        captured.retire_empty_subtrees(&self.selected, |relative, kind| {
            self.authorize(relative, kind)
        })?;
        require_root(home, store, expected)
    }
}

/// Surviving ACTIVE publication does not run restoration. Apply the same
/// omission there after latest host bytes are admitted, before guest writers.
pub(super) fn cleanup_current(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
) -> StorageResult<()> {
    // Installed staging marks the end of the exclusive bootstrap window.
    // Never turn a live facade's unadmitted native journal into RETIRING
    // authority, nor remove files while its users can still acquire writers.
    if store.staging.get().is_some() {
        return Ok(());
    }
    let root = current_root(home, store)?;
    let entries = restoration::projection_entries(home, &store.content())?;
    let empty = EmptyLogs::authenticate(home, &store.content(), &entries)?;
    empty.retire(home, store, &entries, root, &mut None)
}

pub(super) fn current_root(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
) -> StorageResult<RootState> {
    store
        .engine
        .current_root(&StateOwner::System)
        .map_err(|error| tree_error(home.root(), error))?
        .ok_or_else(|| tree_error(home.root(), "empty-log projection has no System root"))
}

fn require_root(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
    expected: RootState,
) -> StorageResult<()> {
    if current_root(home, store)? != expected {
        return Err(tree_error(
            home.root(),
            "empty-log projection catalog changed",
        ));
    }
    store.require_volume_binding(home)
}

fn authenticate_empty(
    home: &AstridHome,
    content: &NativePrincipalContentStore,
    entry: &ContentEntry,
) -> StorageResult<()> {
    let handle = content
        .open_read(&StateOwner::System, entry.name())
        .map_err(|error| tree_error(home.root(), error))?
        .ok_or_else(|| tree_error(home.root(), "empty-log content disappeared"))?;
    let descriptor = handle.descriptor();
    if descriptor.file() != entry.file() || descriptor.logical_bytes() != 0 {
        return Err(tree_error(
            home.root(),
            "empty-log descriptor disagrees with catalog",
        ));
    }
    let bytes = handle
        .read()
        .map_err(|error| tree_error(home.root(), error))?;
    if !bytes.is_empty() {
        return Err(tree_error(home.root(), "empty-log content is not empty"));
    }
    Ok(())
}

fn group_name(name: &str) -> Option<(&str, &str)> {
    let remainder = name.strip_prefix(PREFIX)?;
    let (uid, rest) = remainder.split_once('/').unwrap_or((remainder, ""));
    (uid.len() == 64
        && uid
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    .then_some((uid, rest))
}

fn canonical_log(remainder: &str) -> bool {
    let Some((capsule, file)) = remainder.split_once('/') else {
        return false;
    };
    if capsule.is_empty() || matches!(capsule, "." | "..") || capsule.contains('\\') {
        return false;
    }
    let Some(date) = file.strip_suffix(".log") else {
        return false;
    };
    if date.len() != 10
        || date.bytes().enumerate().any(|(index, byte)| {
            if matches!(index, 4 | 7) {
                byte != b'-'
            } else {
                !byte.is_ascii_digit()
            }
        })
    {
        return false;
    }
    chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d").is_ok()
}

#[cfg(all(test, any(unix, windows)))]
mod tests;
