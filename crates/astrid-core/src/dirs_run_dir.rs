//! Validated resolution of the disposable runtime directory.

use std::io;
use std::path::{Component, Path, PathBuf};

use super::AstridHome;

const VARIABLE: &str = "ASTRID_RUN_DIR";

pub(super) fn configured_path(home: &AstridHome) -> io::Result<PathBuf> {
    resolved(home).map(|path| path.unwrap_or_else(|| home.root().join("run")))
}

pub(super) fn validate(home: &AstridHome) -> io::Result<()> {
    resolved(home).map(drop)
}

fn resolved(home: &AstridHome) -> io::Result<Option<PathBuf>> {
    let Some(raw) = std::env::var_os(VARIABLE) else {
        return Ok(None);
    };
    let path = PathBuf::from(raw);
    if path.as_os_str().is_empty() {
        return Err(invalid("must not be empty"));
    }
    if !path.is_absolute() {
        return Err(invalid("must be an absolute path"));
    }
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(invalid("must not contain '.' or '..' path components"));
    }

    match std::fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{VARIABLE} is redirected: {}", path.display()),
            ));
        },
        Ok(metadata) if !metadata.is_dir() => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{VARIABLE} is not a real directory: {}", path.display()),
            ));
        },
        Ok(_) => {},
        Err(error) if error.kind() == io::ErrorKind::NotFound => {},
        Err(error) => return Err(error),
    }
    crate::platform_fs::verify_no_redirects(&path)?;

    let physical_run = physical_path(&path)?;
    let physical_root = physical_path(home.root())?;
    if paths_are_related(&physical_run, &physical_root)
        || directories_are_aliases(&physical_run, &physical_root)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{VARIABLE} overlaps the Astrid durable root: {} overlaps {}",
                path.display(),
                home.root().display()
            ),
        ));
    }
    Ok(Some(physical_run))
}

fn invalid(detail: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, format!("{VARIABLE} {detail}"))
}

fn physical_path(path: &Path) -> io::Result<PathBuf> {
    if let Ok(physical) = std::fs::canonicalize(path) {
        return Ok(physical);
    }
    let mut missing = Vec::new();
    let mut existing_parent = path;
    while matches!(
        std::fs::symlink_metadata(existing_parent),
        Err(error) if error.kind() == io::ErrorKind::NotFound
    ) {
        let Some(name) = existing_parent.file_name() else {
            break;
        };
        missing.push(name.to_os_string());
        existing_parent = existing_parent.parent().expect("parent checked above");
    }
    let mut physical = std::fs::canonicalize(existing_parent)?;
    for name in missing.into_iter().rev() {
        physical.push(name);
    }
    if let Some(name) = path.file_name()
        && physical.file_name() != Some(name)
    {
        physical.push(name);
    }
    Ok(physical)
}

fn paths_are_related(run: &Path, root: &Path) -> bool {
    run == root || run.starts_with(root) || root.starts_with(run)
}

#[test]
fn related_runtime_paths_are_rejected_in_both_directions() {
    let root = Path::new("/tmp/astrid-root");
    let inside = Path::new("/tmp/astrid-root/run");
    let outside = Path::new("/tmp/astrid-outside");
    let sibling_prefix = Path::new("/tmp/astrid-root-parent");

    assert!(paths_are_related(root, root));
    assert!(paths_are_related(inside, root));
    assert!(paths_are_related(root, inside));
    assert!(paths_are_related(root, Path::new("/")));
    assert!(!paths_are_related(inside, outside));
    assert!(!paths_are_related(root, sibling_prefix));
}

#[cfg(unix)]
fn directories_are_aliases(run: &Path, root: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;

    match (
        std::fs::symlink_metadata(run),
        std::fs::symlink_metadata(root),
    ) {
        (Ok(run), Ok(root)) => run.dev() == root.dev() && run.ino() == root.ino(),
        _ => false,
    }
}

#[cfg(not(unix))]
fn directories_are_aliases(_run: &Path, _root: &Path) -> bool {
    false
}
