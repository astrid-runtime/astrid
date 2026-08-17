//! Versioned Astrid-home layout migration.

use std::fs::{File, OpenOptions};
use std::io;
use std::io::Read as _;
#[cfg(unix)]
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::{AstridHome, LAYOUT_VERSION, LEGACY_LAYOUT_VERSION};

#[path = "dirs_layout_retirement.rs"]
mod retirement;
use retirement::{
    delete_legacy_tree, legacy_tree_device, sync_directory, validate_legacy_retirement_candidate,
    validate_legacy_tree,
};

const LAYOUT_MIGRATION_INTENT: &str = "layout-v1-to-v2.intent";
const LAYOUT_MIGRATION_RECEIPT: &str = "layout-v1-to-v2.complete";
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
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct LayoutTreeIdentityV1 {
    path_encoding: String,
    physical_path_hex: String,
    inventory_algorithm: String,
    inventory_digest: String,
    entries: u64,
    bytes: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct LayoutMigrationMaterialV1 {
    migration: String,
    from_layout: String,
    to_layout: String,
    source: LayoutTreeIdentityV1,
    target_path_encoding: String,
    target_physical_path_hex: String,
    target_store_format: String,
    binary_identity: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct LayoutMigrationRecordV1 {
    schema: u32,
    transaction_id: String,
    material: LayoutMigrationMaterialV1,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct LayoutMigrationReceiptV1 {
    schema: u32,
    transaction_id: String,
    intent: LayoutMigrationRecordV1,
    destination: LayoutTreeIdentityV1,
}

impl AstridHome {
    /// Retired directory-backed principal-store upgrade source.
    #[must_use]
    pub fn principal_store_path(&self) -> PathBuf {
        self.var_dir().join("principal-store")
    }

    /// Hosted Astrid volume; bare metal implements the same path-free contract.
    #[must_use]
    pub fn storage_volume_path(&self) -> PathBuf {
        self.var_dir().join("astrid.volume")
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
        if std::fs::symlink_metadata(self.storage_volume_path()).is_ok() {
            inventory_regular_file(&self.storage_volume_path())?;
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
        if receipt.schema != LAYOUT_MIGRATION_SCHEMA
            || receipt.transaction_id != intent.transaction_id
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

        match std::fs::symlink_metadata(self.state_db_path()) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
            Ok(_) => {
                // The destination identity proves that a still-present legacy
                // source is retired only against the exact cutover result.
                // Once that source is gone, the volume is live mutable state;
                // comparing it with the historical receipt would reject every
                // legitimate post-migration write on the next startup.
                let destination = inventory_regular_file(&self.storage_volume_path())?;
                if receipt.destination != destination {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "layout migration receipt does not match its destination: {}",
                            receipt_path.display()
                        ),
                    ));
                }
                let source = inventory_tree(&self.state_db_path())?;
                if source != receipt.intent.material.source {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "surviving legacy state differs from the verified migration source: {}",
                            self.state_db_path().display()
                        ),
                    ));
                }
                retire_legacy_source_tree(&self.state_db_path())
            },
        }
    }

    fn ensure_private_dir(path: &Path) -> io::Result<()> {
        crate::platform_fs::ensure_private_directory(path)
    }
}

fn read_canonical_record<T>(path: &Path) -> io::Result<T>
where
    T: DeserializeOwned + PartialEq + Serialize,
{
    let actual = std::fs::read(path)?;
    let parsed: T = serde_json::from_slice(&actual).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "invalid layout migration record {}: {error}",
                path.display()
            ),
        )
    })?;
    let mut expected = serde_json::to_vec(&parsed).map_err(io::Error::other)?;
    expected.push(b'\n');
    if actual != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "layout migration record is not canonical: {}",
                path.display()
            ),
        ));
    }
    Ok(parsed)
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

impl LayoutMigrationRecordV1 {
    fn has_recomputable_identity(&self) -> bool {
        self.schema == LAYOUT_MIGRATION_SCHEMA
            && self.transaction_id == layout_transaction_id(&self.material).unwrap_or_default()
            && self.material.migration == "astrid-home-layout"
            && self.material.from_layout == LEGACY_LAYOUT_VERSION
            && self.material.to_layout == LAYOUT_VERSION
            && self.material.source.path_encoding == "os-str-encoded-bytes-v1"
            && self.material.source.inventory_algorithm == "blake3-derive-key-v1"
            && self.material.target_path_encoding == "os-str-encoded-bytes-v1"
    }

    fn capture(home: &AstridHome, target: &LayoutMigrationTarget) -> io::Result<Self> {
        let material = LayoutMigrationMaterialV1 {
            migration: "astrid-home-layout".to_owned(),
            from_layout: LEGACY_LAYOUT_VERSION.to_owned(),
            to_layout: LAYOUT_VERSION.to_owned(),
            source: inventory_tree(&home.state_db_path())?,
            target_path_encoding: "os-str-encoded-bytes-v1".to_owned(),
            target_physical_path_hex: physical_path_hex(&home.storage_volume_path())?,
            target_store_format: target.store_format.clone(),
            binary_identity: target.binary_identity.clone(),
        };
        Ok(Self {
            schema: LAYOUT_MIGRATION_SCHEMA,
            transaction_id: layout_transaction_id(&material)?,
            material,
        })
    }
}

fn layout_transaction_id(material: &LayoutMigrationMaterialV1) -> io::Result<String> {
    let material_bytes = serde_json::to_vec(material).map_err(io::Error::other)?;
    Ok(hex::encode(blake3::derive_key(
        "astrid home layout migration transaction v1",
        &material_bytes,
    )))
}

fn admit_or_write_canonical<T>(path: &Path, expected: &T, allow_create: bool) -> io::Result<()>
where
    T: DeserializeOwned + PartialEq + Serialize,
{
    let mut expected_bytes = serde_json::to_vec(expected).map_err(io::Error::other)?;
    expected_bytes.push(b'\n');
    match std::fs::read(path) {
        Ok(actual) => {
            let parsed: T = serde_json::from_slice(&actual).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "invalid layout migration record {}: {error}",
                        path.display()
                    ),
                )
            })?;
            if parsed != *expected || actual != expected_bytes {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "layout migration record does not match this transaction: {}",
                        path.display()
                    ),
                ));
            }
            Ok(())
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound && allow_create => {
            atomic_write(path, &expected_bytes)
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("layout migration intent is missing: {}", path.display()),
        )),
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

fn inventory_tree(path: &Path) -> io::Result<LayoutTreeIdentityV1> {
    let mut hasher = blake3::Hasher::new_derive_key("astrid layout source inventory v1");
    let mut entries = 0_u64;
    let mut bytes = 0_u64;
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            hasher.update(b"absent");
        },
        Err(error) => return Err(error),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "layout migration source is redirected or not a directory: {}",
                    path.display()
                ),
            ));
        },
        Ok(_) => {
            crate::platform_fs::verify_no_redirects(path)?;
            inventory_directory(path, path, &mut hasher, &mut entries, &mut bytes)?;
        },
    }
    Ok(LayoutTreeIdentityV1 {
        path_encoding: "os-str-encoded-bytes-v1".to_owned(),
        physical_path_hex: physical_path_hex(path)?,
        inventory_algorithm: "blake3-derive-key-v1".to_owned(),
        inventory_digest: hasher.finalize().to_hex().to_string(),
        entries,
        bytes,
    })
}

fn inventory_regular_file(path: &Path) -> io::Result<LayoutTreeIdentityV1> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "layout migration destination is redirected or not a regular file: {}",
                path.display()
            ),
        ));
    }
    crate::platform_fs::verify_no_redirects(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let mut file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "layout migration destination changed type: {}",
                path.display()
            ),
        ));
    }
    let mut hasher = blake3::Hasher::new_derive_key("astrid layout destination inventory v1");
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    let mut bytes = 0_u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        bytes = bytes
            .checked_add(read as u64)
            .ok_or_else(|| io::Error::other("layout destination length overflow"))?;
        hasher.update(&buffer[..read]);
    }
    if bytes != metadata.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "layout migration destination changed while inventoried: {}",
                path.display()
            ),
        ));
    }
    Ok(LayoutTreeIdentityV1 {
        path_encoding: "os-str-encoded-bytes-v1".to_owned(),
        physical_path_hex: physical_path_hex(path)?,
        inventory_algorithm: "blake3-derive-key-v1".to_owned(),
        inventory_digest: hasher.finalize().to_hex().to_string(),
        entries: 1,
        bytes,
    })
}

fn inventory_directory(
    root: &Path,
    directory: &Path,
    hasher: &mut blake3::Hasher,
    entries: &mut u64,
    bytes: &mut u64,
) -> io::Result<()> {
    let mut children = std::fs::read_dir(directory)?.collect::<Result<Vec<_>, _>>()?;
    children.sort_by_key(std::fs::DirEntry::file_name);
    for child in children {
        let child_path = child.path();
        let relative = child_path.strip_prefix(root).map_err(io::Error::other)?;
        let relative_bytes = relative.as_os_str().as_encoded_bytes();
        let metadata = std::fs::symlink_metadata(&child_path)?;
        if metadata.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "layout migration source contains a redirect: {}",
                    child_path.display()
                ),
            ));
        }
        validate_legacy_surrealkv_entry(relative, metadata.is_dir(), metadata.is_file())?;
        *entries = entries
            .checked_add(1)
            .ok_or_else(|| io::Error::other("layout inventory entry count overflow"))?;
        hash_inventory_field(hasher, b"path", relative_bytes);
        if metadata.is_dir() {
            hasher.update(b"directory");
            inventory_directory(root, &child_path, hasher, entries, bytes)?;
        } else if metadata.is_file() {
            hasher.update(b"file");
            hasher.update(&metadata.len().to_le_bytes());
            let mut options = OpenOptions::new();
            options.read(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;

                options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt as _;
                use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

                options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
            }
            let mut file = options.open(&child_path)?;
            if !file.metadata()?.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "layout migration source changed type: {}",
                        child_path.display()
                    ),
                ));
            }
            let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
            let mut file_bytes = 0_u64;
            loop {
                let read = file.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                *bytes = bytes
                    .checked_add(read as u64)
                    .ok_or_else(|| io::Error::other("layout inventory byte count overflow"))?;
                file_bytes = file_bytes
                    .checked_add(read as u64)
                    .ok_or_else(|| io::Error::other("layout inventory file length overflow"))?;
                hasher.update(&buffer[..read]);
            }
            if file_bytes != metadata.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "layout migration source changed while inventoried: {}",
                        child_path.display()
                    ),
                ));
            }
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "layout migration source contains a special file: {}",
                    child_path.display()
                ),
            ));
        }
    }
    Ok(())
}

fn validate_legacy_surrealkv_entry(
    relative: &Path,
    is_directory: bool,
    is_file: bool,
) -> io::Result<()> {
    let components: Vec<_> = relative.components().collect();
    let valid = match components.as_slice() {
        [entry] if entry.as_os_str() == "LOCK" => is_file,
        [entry]
            if matches!(
                entry.as_os_str().to_str(),
                Some("manifest" | "wal" | "sstables" | "vlog" | "versioned_index")
            ) =>
        {
            is_directory
        },
        [directory, name] if directory.as_os_str() == "manifest" && is_file => {
            is_numbered_legacy_file(name.as_os_str(), b".manifest")
        },
        [directory, name] if directory.as_os_str() == "wal" && is_file => {
            is_numbered_legacy_file(name.as_os_str(), b".wal")
        },
        [directory, name] if directory.as_os_str() == "sstables" && is_file => {
            is_numbered_legacy_file(name.as_os_str(), b".sst")
        },
        [directory, name] if directory.as_os_str() == "vlog" && is_file => {
            is_numbered_legacy_file(name.as_os_str(), b".vlog")
        },
        [directory, name]
            if directory.as_os_str() == "versioned_index" && name.as_os_str() == "index.bpt" =>
        {
            is_file
        },
        _ => false,
    };
    if !valid {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "unexpected entry in released legacy SurrealKV source: {}",
                relative.display()
            ),
        ));
    }
    Ok(())
}

fn is_numbered_legacy_file(name: &std::ffi::OsStr, extension: &[u8]) -> bool {
    let bytes = name.as_encoded_bytes();
    bytes.split_at_checked(20).is_some_and(|(digits, suffix)| {
        digits.iter().all(u8::is_ascii_digit) && suffix == extension
    })
}

fn hash_inventory_field(hasher: &mut blake3::Hasher, label: &[u8], value: &[u8]) {
    hasher.update(&(label.len() as u64).to_le_bytes());
    hasher.update(label);
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
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

fn physical_path_hex(path: &Path) -> io::Result<String> {
    let absolute = if path.exists() {
        std::fs::canonicalize(path)?
    } else {
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::other("layout path has no parent"))?;
        let name = path
            .file_name()
            .ok_or_else(|| io::Error::other("layout path has no name"))?;
        std::fs::canonicalize(parent)?.join(name)
    };
    Ok(hex::encode(absolute.as_os_str().as_encoded_bytes()))
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
    if !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("legacy state source is not a directory: {}", path.display()),
        ));
    }

    // Validate the complete tree before removing anything. In particular,
    // `remove_dir_all` is intentionally not used: it can walk into a mount
    // boundary and its path-based recursion has no type check for special
    // entries. A failed validation leaves every legacy byte available for a
    // later operator repair or an idempotent restart.
    let root_device = legacy_tree_device(&metadata);
    validate_legacy_tree(path, root_device)?;
    delete_legacy_tree(path, root_device)?;
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("legacy state source has no parent"))?;
    sync_directory(parent)
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
