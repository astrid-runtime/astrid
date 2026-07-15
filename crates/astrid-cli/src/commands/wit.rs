//! Admin commands for the content-addressed WIT store.
//!
//! The WIT store at `~/.astrid/wit/store/{blake3}.wit` is append-only
//! from the installer's perspective — `astrid capsule install` writes
//! blobs but `astrid capsule remove` never deletes them. This preserves
//! replay: historic capsule states can be reconstructed as long as their
//! WIT blobs still exist. The store is a dedicated subdirectory so the
//! sweep never touches the daemon's canonical named copies at the top of
//! `wit/` (e.g. `wit/astrid-contracts.wit`).
//!
//! These admin commands let an operator explicitly prune unreferenced blobs
//! when they're certain no pending replays need the content.
//!
//! # Security
//!
//! - GC is admin-only (no automatic sweeps on uninstall)
//! - Dry-run by default; `--force` required to actually delete
//! - Mark set is derived from every `meta.json` found under every principal's
//!   capsules directory plus workspace-level capsules
//! - A blob is deleted only if no currently installed capsule references
//!   its hash via `wit_files`

use std::collections::HashSet;
use std::path::Path;

use anyhow::Context;
use astrid_core::dirs::AstridHome;
use colored::Colorize;

use super::capsule::meta::{CapsuleMeta, read_meta};
use crate::theme::Theme;

/// Garbage-collect unreferenced WIT blobs from the content store.
///
/// With `force = false` (default), reports orphans without deleting.
/// With `force = true`, deletes unreferenced blobs and reports the count.
pub(crate) fn gc(force: bool) -> anyhow::Result<()> {
    let home = AstridHome::resolve().context("failed to resolve Astrid home")?;
    let wit_store = home.wit_store_dir();

    if !wit_store.is_dir() {
        println!(
            "{}",
            Theme::info(&format!(
                "WIT store does not exist: {}",
                wit_store.display()
            ))
        );
        return Ok(());
    }

    // Build the mark set: every WIT hash referenced by any installed capsule.
    let marks = collect_marks(&home, crate::workspace_layout::current())?;

    // Scan the store and identify orphans.
    let mut orphans = Vec::new();
    let mut total_blobs = 0_usize;
    let mut total_bytes = 0_u64;
    let mut orphan_bytes = 0_u64;

    for entry in std::fs::read_dir(&wit_store)
        .with_context(|| format!("failed to read WIT store: {}", wit_store.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("wit") {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        // Skip temp files left by concurrent installs (format: `{hash}.tmp.{pid}`)
        if stem.contains(".tmp.") {
            continue;
        }

        total_blobs = total_blobs.saturating_add(1);
        if let Ok(meta) = std::fs::metadata(&path) {
            total_bytes = total_bytes.saturating_add(meta.len());
        }

        if !marks.contains(stem) {
            if let Ok(meta) = std::fs::metadata(&path) {
                orphan_bytes = orphan_bytes.saturating_add(meta.len());
            }
            orphans.push(path);
        }
    }

    println!("{}", Theme::header("WIT content store"));
    println!("  Location: {}", wit_store.display());
    println!("  Total blobs: {total_blobs}");
    println!(
        "  Referenced: {}",
        total_blobs.saturating_sub(orphans.len())
    );
    println!("  Orphaned:   {}", orphans.len());
    println!("  Total size: {total_bytes} bytes ({orphan_bytes} reclaimable)");

    if orphans.is_empty() {
        println!("{}", Theme::success("Nothing to do — no orphaned blobs."));
        return Ok(());
    }

    if !force {
        println!();
        println!("{}", Theme::header("Orphaned blobs (dry run):"));
        for path in &orphans {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                println!("  {}", name.yellow());
            }
        }
        println!();
        println!(
            "{}",
            Theme::info("Run with --force to actually delete these blobs.")
        );
        return Ok(());
    }

    println!();
    println!("{}", Theme::warning("Deleting orphaned blobs..."));
    let mut deleted = 0_usize;
    for path in &orphans {
        match std::fs::remove_file(path) {
            Ok(()) => deleted = deleted.saturating_add(1),
            Err(e) => {
                eprintln!(
                    "{}",
                    Theme::warning(&format!("Failed to delete {}: {e}", path.display()))
                );
            },
        }
    }

    println!(
        "{} Deleted {deleted} blob(s), reclaimed {orphan_bytes} bytes",
        Theme::success("OK")
    );
    Ok(())
}

/// Collect the set of hashes referenced by every installed capsule's
/// `meta.json` across all principals and the workspace.
fn collect_marks(
    home: &AstridHome,
    workspace_layout: &astrid_core::dirs::WorkspaceLayout,
) -> anyhow::Result<HashSet<String>> {
    let workspace_root = std::env::current_dir().ok();
    collect_marks_in_workspace(home, workspace_root.as_deref(), workspace_layout)
}

fn collect_marks_in_workspace(
    home: &AstridHome,
    workspace_root: Option<&Path>,
    workspace_layout: &astrid_core::dirs::WorkspaceLayout,
) -> anyhow::Result<HashSet<String>> {
    let mut marks = HashSet::new();

    // Walk every principal home under ~/.astrid/home/
    let home_root = home.home_dir();
    if home_root.is_dir() {
        for entry in std::fs::read_dir(&home_root)
            .with_context(|| format!("failed to read {}", home_root.display()))?
        {
            let Ok(entry) = entry else {
                continue;
            };
            let principal_root = entry.path();
            if !principal_root.is_dir() {
                continue;
            }
            // Each principal home's capsules directory
            let capsules_dir = principal_root.join(".local").join("capsules");
            if capsules_dir.is_dir() {
                collect_from_capsules_dir(&capsules_dir, &mut marks);
            }
        }
    }

    // Workspace-level capsules (if running from a workspace)
    if let Some(workspace_root) = workspace_root {
        let workspace = workspace_layout
            .resolve(workspace_root)
            .with_context(|| format!("unsafe workspace at {}", workspace_root.display()))?;
        let ws_caps = workspace.verify_tree("capsules")?;
        if ws_caps.is_dir() {
            collect_from_capsules_dir(&ws_caps, &mut marks);
        }
        workspace.verify_tree("capsules")?;
    }

    Ok(marks)
}

/// For every capsule subdirectory under `dir`, load `meta.json` and add its
/// `wit_files` hash values to `marks`.
fn collect_from_capsules_dir(dir: &Path, marks: &mut HashSet<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let capsule_dir = entry.path();
        if !capsule_dir.is_dir() {
            continue;
        }
        if let Some(meta) = read_meta(&capsule_dir) {
            add_meta_marks(&meta, marks);
        }
    }
}

/// Add every hash from a capsule's `wit_files` map to `marks`.
fn add_meta_marks(meta: &CapsuleMeta, marks: &mut HashSet<String>) {
    for hash in meta.wit_files.values() {
        marks.insert(hash.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wit_gc_marks_only_the_injected_workspace_root() {
        let home_dir = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(home_dir.path());
        let workspace = tempfile::tempdir().unwrap();
        let default_capsule = workspace.path().join(".astrid/capsules/default");
        let alternate_capsule = workspace
            .path()
            .join(".alternate-runtime/capsules/alternate");
        std::fs::create_dir_all(&default_capsule).unwrap();
        std::fs::create_dir_all(&alternate_capsule).unwrap();

        let mut default_meta = CapsuleMeta::default();
        default_meta
            .wit_files
            .insert("default.wit".into(), "default-hash".into());
        super::super::capsule::meta::write_meta(&default_capsule, &default_meta).unwrap();
        let mut alternate_meta = CapsuleMeta::default();
        alternate_meta
            .wit_files
            .insert("alternate.wit".into(), "alternate-hash".into());
        super::super::capsule::meta::write_meta(&alternate_capsule, &alternate_meta).unwrap();

        let layout = astrid_core::dirs::WorkspaceLayout::new(".alternate-runtime").unwrap();
        let marks = collect_marks_in_workspace(&home, Some(workspace.path()), &layout).unwrap();

        assert!(marks.contains("alternate-hash"));
        assert!(!marks.contains("default-hash"));
    }

    #[cfg(unix)]
    #[test]
    fn wit_gc_rejects_symlinked_workspace_meta() {
        use std::os::unix::fs::symlink;

        let home_dir = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(home_dir.path());
        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let capsule = workspace.path().join(".astrid/capsules/example");
        std::fs::create_dir_all(&capsule).unwrap();
        let outside_meta = outside.path().join("meta.json");
        std::fs::write(&outside_meta, r#"{"wit_files":{"x":"outside-hash"}}"#).unwrap();
        symlink(outside_meta, capsule.join("meta.json")).unwrap();

        assert!(
            collect_marks_in_workspace(
                &home,
                Some(workspace.path()),
                &astrid_core::dirs::WorkspaceLayout::default(),
            )
            .is_err()
        );
    }
}
