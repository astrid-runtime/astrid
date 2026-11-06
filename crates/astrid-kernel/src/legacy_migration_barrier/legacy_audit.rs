//! Layout-1 audit import, verified retirement, and non-default leftovers.
//!
//! 0.10.4 created empty audit directories for every principal. Only `default`
//! has an importer. Empty non-default trees are retired; non-empty ones are
//! quarantined with their bytes preserved.

use super::{Arc, AuditLog, preflight_legacy_audit_sources};

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use astrid_core::dirs::AstridHome;
use astrid_core::principal::PrincipalId;

use super::source::{SourceCount, SourceIdentity};
use super::{path_exists, retire_empty_directory};

const QUARANTINE_DIR: &str = "unbound-legacy-audit";

/// Retire an empty leftover audit tree, or quarantine a non-empty one.
pub(super) fn handle_non_default_audit_source(
    home: &AstridHome,
    alias: &PrincipalId,
    source: Option<&SourceIdentity>,
) -> io::Result<()> {
    let Some(source) = source else {
        return Ok(());
    };
    if !source.present {
        return Ok(());
    }
    let path = home.principal_home(alias).audit_dir();
    if source.entries == SourceCount::ZERO {
        if path_exists(&path)? {
            retire_empty_directory(&path)?;
        }
        return Ok(());
    }
    if !path_exists(&path)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "legacy audit source for {alias} was inventoried but is missing: {}",
                path.display()
            ),
        ));
    }
    quarantine_audit_tree(home, alias, &path)
}

fn quarantine_audit_tree(home: &AstridHome, alias: &PrincipalId, source: &Path) -> io::Result<()> {
    let quarantine_root = home.migrations_dir().join(QUARANTINE_DIR);
    astrid_core::platform_fs::ensure_private_directory(&quarantine_root)?;
    let destination = unique_destination(&quarantine_root, alias.as_str())?;
    fs::rename(source, &destination).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "quarantine {} to {}: {error}",
                source.display(),
                destination.display()
            ),
        )
    })?;
    super::sync_parent(source)?;
    super::sync_parent(&destination)?;
    tracing::warn!(
        principal = %alias,
        destination = %destination.display(),
        "quarantined non-default layout-1 audit tree; bytes preserved"
    );
    Ok(())
}

fn unique_destination(root: &Path, name: &str) -> io::Result<PathBuf> {
    for index in 0_u32..1024 {
        let candidate = if index == 0 {
            root.join(name)
        } else {
            root.join(format!("{name}-{index}"))
        };
        match fs::symlink_metadata(&candidate) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(candidate),
            Ok(_) => {},
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::other(
        "exhausted unique names for quarantined legacy audit tree",
    ))
}

pub(super) async fn migrate_legacy_audit(
    home: &AstridHome,
    audit: &Arc<AuditLog>,
) -> io::Result<()> {
    let default_audit = home.principal_home(&PrincipalId::default()).audit_dir();
    if preflight_legacy_audit_sources(home, &default_audit)? {
        audit
            .import_legacy_audit(&default_audit, "astrid-system-audit-v1")
            .await
            .map_err(|error| io::Error::other(format!("legacy audit migration failed: {error}")))?;
        // Revalidate other layout-1 sources before the audit owner authorizes
        // retirement of this captured source generation.
        if !preflight_legacy_audit_sources(home, &default_audit)? {
            return Err(io::Error::other(
                "legacy audit source disappeared before digest-bound retirement",
            ));
        }
    }
    // A missing original can still have an authorized, partially deleted
    // stage. The audit MOVE receipt is the sole authority to resume it.
    audit
        .retire_legacy_audit(
            &default_audit,
            home.migrations_dir(),
            "astrid-system-audit-v1",
        )
        .await
        .map_err(|error| io::Error::other(format!("legacy audit retirement failed: {error}")))?;
    Ok(())
}

#[cfg(test)]
mod tests;
