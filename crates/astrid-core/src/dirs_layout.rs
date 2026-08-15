//! Versioned Astrid-home layout migration and fleet-served paths.

use std::collections::BTreeSet;
#[cfg(unix)]
use std::fs::{File, OpenOptions};
use std::io;
#[cfg(unix)]
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::FleetUid;

use super::{AstridHome, LAYOUT_VERSION, LEGACY_LAYOUT_VERSION};

const LAYOUT_MIGRATION_INTENT: &str = "layout-v1-to-v2.intent";
const LAYOUT_MIGRATION_RECEIPT: &str = "layout-v1-to-v2.complete";

impl AstridHome {
    /// Path to the canonical layout-version sentinel (`etc/layout-version`).
    #[must_use]
    pub fn layout_version_path(&self) -> PathBuf {
        self.etc_dir().join("layout-version")
    }

    /// Durable layout-migration records (`var/migrations/`).
    #[must_use]
    pub fn migrations_dir(&self) -> PathBuf {
        self.var_dir().join("migrations")
    }

    /// Fleet-owned served-data root (`srv/`).
    #[must_use]
    pub fn srv_dir(&self) -> PathBuf {
        self.root().join("srv")
    }

    /// All fleet served-data roots (`srv/fleets/`).
    #[must_use]
    pub fn fleets_dir(&self) -> PathBuf {
        self.srv_dir().join("fleets")
    }

    /// One fleet's canonical served-data root (`srv/fleets/{fleet_uid}/`).
    #[must_use]
    pub fn fleet_dir(&self, fleet_uid: FleetUid) -> PathBuf {
        self.fleets_dir().join(fleet_uid.to_string())
    }

    /// One fleet's durable common-file projection root.
    #[must_use]
    pub fn fleet_shared_dir(&self, fleet_uid: FleetUid) -> PathBuf {
        self.fleet_dir(fleet_uid).join("shared")
    }

    /// One fleet's admitted workspace-attachment root.
    #[must_use]
    pub fn fleet_workspaces_dir(&self, fleet_uid: FleetUid) -> PathBuf {
        self.fleet_dir(fleet_uid).join("workspaces")
    }

    /// Commit layout version two after store and ownership migration succeeds.
    ///
    /// The caller must hold the daemon singleton lock and must have completed
    /// the principal-store migration. This method first records an intent,
    /// creates every fleet root, makes the released legacy database read-only
    /// on Unix, writes a completion receipt, and replaces the layout sentinel
    /// last. Re-entry is idempotent.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown source layout, redirected legacy state,
    /// directory creation, durability, or permission failures.
    pub fn complete_layout_v2<I>(&self, fleet_uids: I) -> io::Result<()>
    where
        I: IntoIterator<Item = FleetUid>,
    {
        let fleets = fleet_uids.into_iter().collect::<BTreeSet<_>>();
        match self.layout_version()?.as_deref() {
            Some(LAYOUT_VERSION) => {
                self.ensure_layout_v2_dirs()?;
                return self.ensure_fleet_dirs(&fleets);
            },
            Some(LEGACY_LAYOUT_VERSION) => {},
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "cannot migrate an Astrid home without a layout-version sentinel",
                ));
            },
            Some(other) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unsupported Astrid home layout version {other:?}"),
                ));
            },
        }

        Self::ensure_private_dir(&self.migrations_dir())?;
        let record = migration_record(&fleets);
        atomic_write(
            &self.migrations_dir().join(LAYOUT_MIGRATION_INTENT),
            &record,
        )?;
        self.ensure_layout_v2_dirs()?;
        self.ensure_fleet_dirs(&fleets)?;
        protect_legacy_source(&self.state_db_path())?;
        atomic_write(
            &self.migrations_dir().join(LAYOUT_MIGRATION_RECEIPT),
            &record,
        )?;
        self.write_layout_version(LAYOUT_VERSION)
    }

    /// Read the exact admitted layout version, or `None` when uninitialized.
    ///
    /// # Errors
    ///
    /// Returns an error when the sentinel cannot be read as UTF-8 text.
    pub fn layout_version(&self) -> io::Result<Option<String>> {
        match std::fs::read_to_string(self.layout_version_path()) {
            Ok(version) => Ok(Some(version.trim().to_owned())),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub(super) fn write_layout_version(&self, version: &str) -> io::Result<()> {
        atomic_write(&self.layout_version_path(), version.as_bytes())
    }

    pub(super) fn ensure_layout_v2_dirs(&self) -> io::Result<()> {
        for path in [
            self.content_staging_path(),
            self.migrations_dir(),
            self.cow_dir(),
            self.srv_dir(),
            self.fleets_dir(),
        ] {
            Self::ensure_private_dir(&path)?;
        }
        Ok(())
    }

    fn ensure_fleet_dirs(&self, fleets: &BTreeSet<FleetUid>) -> io::Result<()> {
        for fleet in fleets {
            Self::ensure_private_dir(&self.fleet_shared_dir(*fleet))?;
            Self::ensure_private_dir(&self.fleet_workspaces_dir(*fleet))?;
        }
        Ok(())
    }

    fn ensure_private_dir(path: &Path) -> io::Result<()> {
        crate::platform_fs::ensure_private_directory(path)
    }
}

fn migration_record(fleets: &BTreeSet<FleetUid>) -> Vec<u8> {
    let mut record =
        String::from("migration=astrid-home-layout\nfrom=1\nto=2\nlegacy-source=var/state.db\n");
    for fleet in fleets {
        record.push_str("fleet=");
        record.push_str(&fleet.to_string());
        record.push('\n');
    }
    record.into_bytes()
}

fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    #[cfg(windows)]
    {
        crate::platform_fs::atomic_write_private_file(path, bytes)
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        let parent = path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "layout record has no parent")
        })?;
        std::fs::create_dir_all(parent)?;
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "layout record has no file name",
                )
            })?;
        let staged = parent.join(format!(".{name}.next"));
        match std::fs::symlink_metadata(&staged) {
            Ok(metadata) if metadata.file_type().is_file() => std::fs::remove_file(&staged)?,
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("layout staging path is redirected: {}", staged.display()),
                ));
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => {},
            Err(error) => return Err(error),
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&staged)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        crate::platform_fs::rename_with_write_through(&staged, path)?;
        File::open(parent)?.sync_all()
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, bytes);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "durable layout records are unsupported on this operating system",
        ))
    }
}

#[cfg(unix)]
fn protect_legacy_source(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("legacy state source is redirected: {}", path.display()),
        ));
    }
    if metadata.is_dir() {
        for entry in std::fs::read_dir(path)? {
            protect_legacy_source(&entry?.path())?;
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o500))
    } else if metadata.is_file() {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400))
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "legacy state source contains a special file: {}",
                path.display()
            ),
        ))
    }
}

#[cfg(not(unix))]
fn protect_legacy_source(_path: &Path) -> io::Result<()> {
    Ok(())
}
