//! Layout-1 handling of non-default `.local/audit` leftovers.
//!
//! 0.10.4 created empty audit directories for every principal. Only `default`
//! has an importer. Empty non-default trees are retired; non-empty ones are
//! quarantined with their bytes preserved.

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
