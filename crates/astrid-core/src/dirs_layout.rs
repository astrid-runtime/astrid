//! Versioned Astrid-home layout migration.

use std::fs::File;
#[cfg(unix)]
use std::fs::OpenOptions;
use std::io;
use std::io::Read as _;
#[cfg(unix)]
use std::io::Write;
use std::path::{Path, PathBuf};

use super::{AstridHome, LAYOUT_VERSION, LEGACY_LAYOUT_VERSION};

#[path = "dirs_layout_records.rs"]
mod records;
#[path = "dirs_layout_retirement.rs"]
mod retirement;
use records::{
    LayoutMigrationReceiptV1, LayoutMigrationRecordV1, LayoutRetirementV1,
    admit_or_write_canonical, inventory_regular_file, inventory_tree, read_canonical_record,
    verify_receipt_destination_authority, verify_receipt_destination_is_live_path,
};

#[cfg(test)]
pub(super) fn decode_layout_receipt_path_for_test(
    bytes: Vec<u8>,
) -> io::Result<std::ffi::OsString> {
    records::encoded_bytes_to_os_string(bytes)
}
use retirement::{
    retire_legacy_source_tree as retire_legacy_source_tree_impl,
    validate_legacy_retirement_candidate,
};

const LAYOUT_MIGRATION_INTENT: &str = "layout-v1-to-v2.intent";
const LAYOUT_MIGRATION_RECEIPT: &str = "layout-v1-to-v2.complete";
const LAYOUT_MIGRATION_RETIREMENT: &str = "layout-v1-to-v2.retiring";
const LAYOUT_MIGRATION_SCHEMA: u32 = 1;
#[cfg(not(target_family = "wasm"))]
const LAYOUT_MIGRATION_HEADROOM_BYTES: u64 = 64 * 1024 * 1024;

/// Storage-format and executable identity committed into a layout migration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LayoutMigrationTarget {
    store_format: String,
    binary_identity: String,
}

impl LayoutMigrationTarget {
    /// Construct a non-empty migration target identity.
    ///
    /// # Errors
    ///
    /// Returns an error when either durable identity is empty or contains
    /// control characters that would make operator rendering ambiguous.
    pub fn new(
        store_format: impl Into<String>,
        binary_identity: impl Into<String>,
    ) -> io::Result<Self> {
        let target = Self {
            store_format: store_format.into(),
            binary_identity: binary_identity.into(),
        };
        for (label, value) in [
            ("store format", target.store_format.as_str()),
            ("binary identity", target.binary_identity.as_str()),
        ] {
            if value.is_empty() || value.chars().any(char::is_control) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("layout migration {label} must be non-empty printable text"),
                ));
            }
        }
        Ok(target)
    }

    /// Bind a migration to the exact executable bytes performing the cutover.
    ///
    /// # Errors
    ///
    /// Returns an error when the current executable cannot be resolved or read,
    /// or when the supplied store-format identity is invalid.
    pub fn for_current_executable(store_format: impl Into<String>) -> io::Result<Self> {
        let executable = std::env::current_exe()?;
        let mut file = File::open(&executable)?;
        let mut hasher = blake3::Hasher::new_derive_key("astrid layout migration binary v1");
        let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        Self::new(
            store_format,
            format!("blake3-derive-key-v1:{}", hasher.finalize().to_hex()),
        )
    }

    pub(super) fn store_format(&self) -> String {
        self.store_format.clone()
    }

    pub(super) fn binary_identity(&self) -> String {
        self.binary_identity.clone()
    }
}

impl AstridHome {
    /// Retired directory-backed principal-store upgrade source.
    #[must_use]
    pub fn principal_store_path(&self) -> PathBuf {
        self.var_dir().join("principal-store")
    }

    /// Canonical Astrid-owned durable media.
    #[must_use]
    pub fn storage_volume_path(&self) -> PathBuf {
        self.root().join("astrid.volume")
    }

    /// Released pre-root-volume paths accepted only during one-time promotion.
    ///
    /// New stores never use this path. Storage opening moves a regular file
    /// found here to [`Self::storage_volume_path`] before serving the home.
    #[must_use]
    pub fn legacy_storage_volume_path(&self) -> PathBuf {
        self.var_dir().join("astrid.volume")
    }

    /// Older hosted-volume path accepted only as a migration input.
    #[must_use]
    pub fn retired_root_storage_volume_path(&self) -> PathBuf {
        self.root().join("volume")
    }

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

    /// Persist the content-bound layout migration intent before opening stores.
    ///
    /// The caller must hold the daemon singleton lock. Re-entry accepts only
    /// the exact same source inventory, destination format, physical roots, and
    /// executable identity.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported layouts, redirected paths, invalid
    /// source content, or a prior intent for a different transaction.
    pub fn begin_layout_v2_migration(&self, target: &LayoutMigrationTarget) -> io::Result<()> {
        match self.layout_version()?.as_deref() {
            Some(LAYOUT_VERSION) => return Ok(()),
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
        reject_automatic_windows_layout_one()?;
        self.preflight_layout_v2_paths()?;
        for path in [
            self.storage_volume_path(),
            self.legacy_storage_volume_path(),
            self.retired_root_storage_volume_path(),
        ] {
            if std::fs::symlink_metadata(&path).is_ok() {
                inventory_regular_file(&path)?;
            }
        }
        let intent = LayoutMigrationRecordV1::capture(self, target)?;
        ensure_migration_capacity(&self.var_dir(), intent.material.source.bytes)?;
        Self::ensure_private_dir(&self.migrations_dir())?;
        admit_or_write_canonical(
            &self.migrations_dir().join(LAYOUT_MIGRATION_INTENT),
            &intent,
            true,
        )
    }

    /// Commit layout version two after store and ownership migration succeeds.
    ///
    /// The caller must hold the daemon singleton lock and must have completed
    /// the principal-store migration. This method first records an intent,
    /// writes a completion receipt, replaces the layout sentinel, and only
    /// then removes the verified legacy state database. The kernel invokes
    /// this only after its global component ledger is durable. The released
    /// `CoW` tree is retired separately against that ledger's exact source
    /// identity.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown source layout, redirected legacy state,
    /// directory creation, durability, or permission failures.
    pub fn complete_layout_v2(&self, target: &LayoutMigrationTarget) -> io::Result<()> {
        match self.layout_version()?.as_deref() {
            Some(LAYOUT_VERSION) => {
                self.ensure_layout_v2_dirs()?;
                return self.retire_verified_legacy_source();
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

        reject_automatic_windows_layout_one()?;

        self.preflight_layout_v2_paths()?;
        let intent = LayoutMigrationRecordV1::capture(self, target)?;
        admit_or_write_canonical(
            &self.migrations_dir().join(LAYOUT_MIGRATION_INTENT),
            &intent,
            false,
        )?;
        self.ensure_layout_v2_dirs()?;
        let retirement = LayoutRetirementV1 {
            schema: LAYOUT_MIGRATION_SCHEMA,
            transaction_id: intent.transaction_id.clone(),
            source: inventory_tree(&self.state_db_path())?,
        };
        admit_or_write_canonical(
            &self.migrations_dir().join(LAYOUT_MIGRATION_RETIREMENT),
            &retirement,
            true,
        )?;
        let receipt = LayoutMigrationReceiptV1 {
            schema: LAYOUT_MIGRATION_SCHEMA,
            transaction_id: intent.transaction_id.clone(),
            intent,
            destination: inventory_regular_file(&self.storage_volume_path())?,
        };
        admit_or_write_canonical(
            &self.migrations_dir().join(LAYOUT_MIGRATION_RECEIPT),
            &receipt,
            true,
        )?;
        self.write_layout_version(LAYOUT_VERSION)?;
        self.retire_verified_legacy_source()
    }

    /// Read the exact admitted layout version, or `None` when uninitialized.
    ///
    /// # Errors
    ///
    /// Returns an error when the sentinel cannot be read as UTF-8 text.
    pub fn layout_version(&self) -> io::Result<Option<String>> {
        match std::fs::read_to_string(self.layout_version_path()) {
            Ok(version) => Ok(Some(version)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub(super) fn write_layout_version(&self, version: &str) -> io::Result<()> {
        atomic_write(&self.layout_version_path(), version.as_bytes())
    }

    pub(super) fn ensure_layout_v2_dirs(&self) -> io::Result<()> {
        for path in [self.content_staging_path(), self.migrations_dir()] {
            Self::ensure_private_dir(&path)?;
        }
        Ok(())
    }

    /// Validate released directory-backed sources without retiring them.
    ///
    /// `AstridHome::ensure` runs before the kernel's singleton-owned global
    /// migration barrier. It can therefore establish the no-follow,
    /// same-device, mount, and special-entry boundary, but source deletion is
    /// reserved for [`Self::complete_layout_v2`] after the barrier has
    /// published every component receipt.
    pub(super) fn validate_layout_v2_legacy_sources(&self) -> io::Result<()> {
        for path in [self.state_db_path(), self.cow_dir()] {
            validate_legacy_retirement_candidate(&path)?;
        }
        Ok(())
    }

    fn preflight_layout_v2_paths(&self) -> io::Result<()> {
        let paths = [
            self.root().to_path_buf(),
            self.var_dir(),
            self.migrations_dir(),
            self.principal_store_path(),
            self.content_staging_path(),
            // `cow/` was part of the pre-volume workspace implementation. It
            // is checked here so a redirected legacy tree fails before an
            // upgrade intent is admitted, but it is never created by layout
            // v2.
            self.cow_dir(),
            self.state_db_path(),
        ];
        for path in paths {
            verify_existing_ancestor(&path)?;
        }
        validate_legacy_retirement_candidate(&self.cow_dir())?;
        Ok(())
    }

    pub(super) fn retire_verified_legacy_source(&self) -> io::Result<()> {
        let receipt_path = self.migrations_dir().join(LAYOUT_MIGRATION_RECEIPT);
        let intent_path = self.migrations_dir().join(LAYOUT_MIGRATION_INTENT);
        match std::fs::symlink_metadata(&receipt_path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if path_entry_present(&self.state_db_path())?
                    || path_entry_present(&self.cow_dir())?
                    || path_entry_present(&intent_path)?
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "layout-two home contains legacy state without a completion receipt",
                    ));
                }
                return Ok(());
            },
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "layout migration receipt is redirected or not a regular file: {}",
                        receipt_path.display()
                    ),
                ));
            },
            Ok(_) => {},
            Err(error) => return Err(error),
        }

        let receipt: LayoutMigrationReceiptV1 = read_canonical_record(&receipt_path)?;
        let intent: LayoutMigrationRecordV1 = read_canonical_record(&intent_path)?;
        let retirement_path = self.migrations_dir().join(LAYOUT_MIGRATION_RETIREMENT);
        let retirement: Option<LayoutRetirementV1> = match read_canonical_record(&retirement_path) {
            Ok(retirement) => Some(retirement),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        if receipt.schema != LAYOUT_MIGRATION_SCHEMA
            || receipt.transaction_id != intent.transaction_id
            || retirement.as_ref().is_some_and(|retirement| {
                retirement.schema != LAYOUT_MIGRATION_SCHEMA
                    || retirement.transaction_id != intent.transaction_id
            })
            || receipt.intent != intent
            || !intent.has_recomputable_identity()
            || receipt.destination.physical_path_hex != intent.material.target_physical_path_hex
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "layout migration receipt does not match its intent or destination: {}",
                    receipt_path.display()
                ),
            ));
        }
        verify_receipt_destination_authority(&receipt.destination)?;

        match std::fs::symlink_metadata(self.state_db_path()) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
            Ok(_) => {
                let source = inventory_tree(&self.state_db_path())?;
                let expected = retirement.map_or_else(
                    || receipt.intent.material.source.clone(),
                    |retirement| retirement.source,
                );
                if source == expected {
                    // The volume is live mutable state. An exact surviving
                    // retirement source proves this is the receipt's
                    // interrupted retirement; post-cutover volume writes are
                    // legitimate.
                    retire_legacy_source_tree(&self.state_db_path())
                } else {
                    // A clean stop packs the live volume, so its cutover byte
                    // identity is intentionally gone. Bind this restart to the
                    // receipt's canonical destination path and its regular,
                    // no-follow filesystem authority instead; the receipt itself
                    // is restored only from the authenticated volume projection.
                    verify_receipt_destination_is_live_path(
                        &receipt.destination,
                        &self.storage_volume_path(),
                    )?;
                    retire_legacy_source_tree(&self.state_db_path())
                }
            },
        }
    }

    fn ensure_private_dir(path: &Path) -> io::Result<()> {
        crate::platform_fs::ensure_private_directory(path)
    }
}

fn verify_existing_ancestor(path: &Path) -> io::Result<()> {
    let mut candidate = path;
    loop {
        match std::fs::symlink_metadata(candidate) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "layout path is redirected or not a directory: {}",
                        candidate.display()
                    ),
                ));
            },
            Ok(_) => return crate::platform_fs::verify_no_redirects(candidate),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                candidate = candidate.parent().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "layout path has no existing directory ancestor: {}",
                            path.display()
                        ),
                    )
                })?;
            },
            Err(error) => return Err(error),
        }
    }
}

fn path_entry_present(path: &Path) -> io::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

#[cfg(windows)]
fn reject_automatic_windows_layout_one() -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "automatic migration of unreleased Windows layout-one homes is unsupported; use the explicit developer importer",
    ))
}

#[cfg(not(windows))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the cross-platform migration gate has one fallible signature"
)]
fn reject_automatic_windows_layout_one() -> io::Result<()> {
    Ok(())
}

#[cfg(not(target_family = "wasm"))]
fn ensure_migration_capacity(target: &Path, source_bytes: u64) -> io::Result<()> {
    let available = fs2::available_space(target)?;
    ensure_available_migration_capacity(available, source_bytes)
}

#[cfg(not(target_family = "wasm"))]
fn ensure_available_migration_capacity(available: u64, source_bytes: u64) -> io::Result<()> {
    let required = source_bytes
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(LAYOUT_MIGRATION_HEADROOM_BYTES))
        .ok_or_else(|| io::Error::other("layout migration capacity requirement overflow"))?;
    if available < required {
        return Err(io::Error::new(
            io::ErrorKind::StorageFull,
            format!(
                "insufficient free space for layout migration: need {required} bytes, have {available} bytes"
            ),
        ));
    }
    Ok(())
}

#[cfg(target_family = "wasm")]
fn ensure_migration_capacity(_target: &Path, _source_bytes: u64) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "layout migration capacity probing is unavailable in a WebAssembly guest",
    ))
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

/// Validate and retire a legacy directory tree without following redirects.
///
/// The complete tree is checked for symlinks, special entries, filesystem
/// boundaries, and active mounts before bottom-up deletion. Directory fsyncs
/// make successful removal durable on hosted Unix filesystems.
///
/// # Errors
///
/// Returns an I/O error and leaves the tree untouched when validation finds a
/// redirect, special entry, filesystem boundary, or active mount.
pub fn retire_legacy_source_tree(path: &Path) -> io::Result<()> {
    retire_legacy_source_tree_impl(path)
}

#[cfg(all(test, not(target_family = "wasm")))]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    use retirement::is_active_mountpoint;

    #[test]
    fn migration_capacity_refuses_one_byte_below_the_required_boundary() {
        let source_bytes = 4096_u64;
        let required = source_bytes
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(LAYOUT_MIGRATION_HEADROOM_BYTES))
            .unwrap();
        let insufficient = required.checked_sub(1).unwrap();

        let error = ensure_available_migration_capacity(insufficient, source_bytes).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::StorageFull);
        assert!(
            error
                .to_string()
                .contains(&format!("need {required} bytes"))
        );
        assert!(
            error
                .to_string()
                .contains(&format!("have {insufficient} bytes"))
        );
        ensure_available_migration_capacity(required, source_bytes).unwrap();
    }

    #[test]
    fn migration_capacity_rejects_an_overflowing_requirement() {
        let error = ensure_available_migration_capacity(u64::MAX, u64::MAX).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(error.to_string().contains("requirement overflow"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn legacy_retirement_rejects_an_active_mount_boundary() {
        let mountpoint = Path::new("/proc");
        if !is_active_mountpoint(mountpoint).expect("read Linux mount table") {
            // Some minimal test containers do not mount procfs. There is no
            // safe local mount fixture without CAP_SYS_ADMIN, so leave this
            // boundary test inert in that environment.
            return;
        }

        let error = retire_legacy_source_tree(mountpoint).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("active mount"), "{error}");
    }
}
